"""Legal-request document renderer (v0.13.1).

Generates draft MLAT requests, FinCEN 314(b) information-sharing
requests, and grand jury subpoena boilerplate from a case's
existing freeze_brief.json.

These are **drafts only**. Recupero has no subpoena authority — the
AUSA / DOJ-OIA / compliance officer must place the final document
on their letterhead and review every line before transmission. The
templates exist to compress what's currently a 2-4 hour drafting
exercise into a 30-second generate-and-edit cycle.

What goes where
---------------

  * **MLAT** — used when funds land at a VASP in a country with
    which the U.S. has a Mutual Legal Assistance Treaty. Sent via
    DOJ-OIA.

  * **FinCEN 314(b)** — used when funds land at a U.S.-based VASP
    that is 314(b)-registered. Sent VASP-to-VASP for AML/CTF
    information sharing.

  * **Grand jury subpoena** — used when funds land at any
    U.S.-based VASP under active federal investigation. Sent
    under AUSA letterhead on Rule 17(c) authority.

Operator workflow
-----------------

After ``recupero emit-brief CASE_ID`` produces freeze_brief.json::

    recupero legal-requests CASE_ID --type mlat
    recupero legal-requests CASE_ID --type 314b
    recupero legal-requests CASE_ID --type subpoena

Each command writes ``legal_requests/<type>_<exchange>.html`` next
to the brief; the operator emails the HTML (or PDF-renders it) to
the appropriate counsel.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"

LEGAL_REQUEST_TYPES = ("mlat", "314b", "subpoena", "exchange-subpoena")


@dataclass(frozen=True)
class LegalRequestRender:
    """Result of rendering one legal-request document."""
    request_type: str        # 'mlat' | '314b' | 'subpoena'
    exchange_name: str       # e.g. 'Binance', 'Coinbase'
    output_path: Path
    html_size_bytes: int


def render_legal_request(
    brief: dict[str, Any],
    *,
    request_type: str,
    output_dir: Path,
    exchange_filter: str | None = None,
) -> list[LegalRequestRender]:
    """Render a legal-request document for each exchange in the brief
    that received funds (or just the one matching ``exchange_filter``).

    The brief is the v0.10+ freeze_brief.json shape — produced by
    ``recupero emit-brief``. We extract:
      * Victim info (VICTIM_NAME, VICTIM_JURISDICTION)
      * Total loss (TOTAL_LOSS_USD)
      * Per-exchange info from EXCHANGES + FREEZABLE
      * Tx evidence from CROSS_CHAIN_HANDOFFS + DEX_SWAPS + DESTINATIONS

    Returns one LegalRequestRender per file written.
    """
    if request_type not in LEGAL_REQUEST_TYPES:
        raise ValueError(
            f"request_type must be one of {LEGAL_REQUEST_TYPES!r}, "
            f"got {request_type!r}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    # v0.14.11: exchange-subpoena requests come from freeze_asks'
    # onward_cex_flows, not from brief.EXCHANGES. They're per-exchange
    # consolidated records requests citing the documented theft trail
    # from freeze-target → CEX deposit address. Different rendering
    # path entirely.
    if request_type == "exchange-subpoena":
        return _render_exchange_subpoena_requests(
            brief, output_dir=output_dir, exchange_filter=exchange_filter,
        )

    template_file = {
        "mlat": "mlat_request.html.j2",
        "314b": "fincen_314b_request.html.j2",
        "subpoena": "subpoena_request.html.j2",
    }[request_type]

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template(template_file)

    base_ctx = _build_base_context(brief)
    targets = _enumerate_exchange_targets(brief, exchange_filter=exchange_filter)

    out: list[LegalRequestRender] = []
    for target in targets:
        ctx = {**base_ctx, "perpetrator": target}
        html = template.render(**ctx)
        # Filename: <type>_<exchange-safe>.html
        safe_exchange = target["exchange_name"].lower().replace(" ", "_")
        out_path = output_dir / f"{request_type}_{safe_exchange}.html"
        out_path.write_text(html, encoding="utf-8")
        log.info(
            "rendered legal request: %s (%d bytes)",
            out_path, out_path.stat().st_size,
        )
        out.append(LegalRequestRender(
            request_type=request_type,
            exchange_name=target["exchange_name"],
            output_path=out_path,
            html_size_bytes=out_path.stat().st_size,
        ))
    return out


def _build_base_context(brief: dict[str, Any]) -> dict[str, Any]:
    """Pull the shared (non-perpetrator-specific) context out of the
    brief. Used as the base for each template render."""
    now_iso = datetime.now(UTC).isoformat(timespec="seconds")
    incident_date = brief.get("INCIDENT_DATE") or ""
    return {
        "case_id": brief.get("CASE_ID") or "(case-id missing)",
        "generated_at": now_iso.replace("+00:00", "Z"),
        "incident_date": incident_date,
        "incident_type": brief.get("INCIDENT_TYPE") or "the underlying incident",
        "total_loss_usd": brief.get("TOTAL_LOSS_USD") or "$0.00",
        "victim": {
            "name": brief.get("VICTIM_NAME") or "[victim name]",
            "jurisdiction": brief.get("VICTIM_JURISDICTION") or "[jurisdiction]",
        },
        "investigator": {
            "name": brief.get("INVESTIGATOR_NAME") or "[investigator name]",
            "organization": brief.get("INVESTIGATOR_ENTITY_FULL")
                or brief.get("INVESTIGATOR_ENTITY") or "Recupero",
            "email": brief.get("INVESTIGATOR_EMAIL") or "[investigator email]",
            "fincen_314b_id": brief.get("FINCEN_314B_ID") or None,
        },
        # Tx evidence: pull from DESTINATIONS (the structured per-dest
        # record carries tx_hash + amount). DESTINATIONS in v0.10+
        # includes every destination address with totals.
        "tx_evidence": _build_tx_evidence_list(brief),
        # v0.14.11: IC3 case ID surfaces in the exchange-subpoena
        # template as the LE reference. Pre-filled from intake.
        "ic3_case_id": brief.get("IC3_CASE_ID") or None,
    }


def _build_tx_evidence_list(brief: dict[str, Any]) -> list[dict[str, str]]:
    """Build the tx_evidence list from a brief.

    Pulls from CROSS_CHAIN_HANDOFFS (which has tx_hash + tx_explorer_url
    + block_time) and DESTINATIONS (top destination addresses).
    Falls back to an empty list if the brief is pre-v0.10.
    """
    out: list[dict[str, str]] = []
    for handoff in (brief.get("CROSS_CHAIN_HANDOFFS") or []):
        if not isinstance(handoff, dict):
            continue
        out.append({
            "tx_hash": str(handoff.get("tx_hash") or ""),
            "block_time": str(handoff.get("block_time") or ""),
            "amount_usd": str(
                handoff.get("amount_usd") or handoff.get("amount_decimal") or ""
            ),
            "explorer_url": str(handoff.get("tx_explorer_url") or ""),
        })
    for swap in (brief.get("DEX_SWAPS") or []):
        if not isinstance(swap, dict):
            continue
        out.append({
            "tx_hash": str(swap.get("tx_hash") or ""),
            "block_time": str(swap.get("block_time") or ""),
            "amount_usd": str(swap.get("input_amount_usd") or ""),
            "explorer_url": str(swap.get("explorer_url") or ""),
        })
    return out


def _enumerate_exchange_targets(
    brief: dict[str, Any],
    *,
    exchange_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Build one perpetrator-context dict per exchange that received
    funds in this case.

    Reads from brief.EXCHANGES (one entry per exchange with
    address + total_received_usd). Filters by ``exchange_filter`` if
    provided (case-insensitive substring match).
    """
    exchanges = brief.get("EXCHANGES") or []
    targets: list[dict[str, Any]] = []
    for ex in exchanges:
        if not isinstance(ex, dict):
            continue
        exchange_name = (
            ex.get("exchange") or ex.get("exchange_name") or "(unknown exchange)"
        )
        if exchange_filter and exchange_filter.lower() not in str(exchange_name).lower():
            continue
        targets.append({
            "exchange_name": exchange_name,
            "exchange_legal_name": ex.get("exchange_legal_name") or exchange_name,
            "exchange_address": ex.get("exchange_address") or "",
            "registered_agent": ex.get("registered_agent") or "",
            "deposit_address": ex.get("address") or "",
            "total_received_usd": (
                ex.get("total_received_usd")
                or ex.get("usd")
                or "$0.00"
            ),
            # Free-form country — operator should override if known.
            "destination_country": ex.get("country") or "[destination country]",
        })
    # Defensive default — if EXCHANGES is empty but the operator still
    # wants to draft, render one empty target so the file exists.
    if not targets and not exchange_filter:
        targets.append({
            "exchange_name": "[exchange name]",
            "exchange_legal_name": "[exchange legal name]",
            "exchange_address": "[exchange address]",
            "registered_agent": "",
            "deposit_address": "[deposit address]",
            "total_received_usd": "$0.00",
            "destination_country": "[destination country]",
        })
    return targets


def load_brief(case_dir: Path) -> dict[str, Any]:
    """Load freeze_brief.json from a case directory.

    Logs a warning when the brief's SCHEMA_VERSION is stale or
    missing — stale briefs lack evidence_mode fields and would render
    incorrect "currently held" language for historical-receipt cases.
    """
    brief_path = case_dir / "freeze_brief.json"
    if not brief_path.exists():
        raise FileNotFoundError(
            f"freeze_brief.json not found at {brief_path}. Run "
            f"`recupero emit-brief CASE_ID` first."
        )
    brief = json.loads(brief_path.read_text(encoding="utf-8-sig"))
    from recupero.reports.brief import check_brief_schema_version
    warning = check_brief_schema_version(brief)
    if warning:
        log.warning(
            "freeze_brief.json at %s is stale: %s",
            brief_path, warning,
        )
    return brief


def load_freeze_asks(case_dir: Path) -> dict[str, Any]:
    """Load freeze_asks.json from a case directory.

    Used by the exchange-subpoena renderer to access ``onward_cex_flows``.
    Returns an empty-shape dict if the file is missing OR malformed —
    a partial write must not crash the entire rendering path with a
    cryptic JSONDecodeError.
    """
    empty = {"by_issuer": {}, "exchange_deposits": [], "onward_cex_flows": []}
    p = case_dir / "freeze_asks.json"
    if not p.exists():
        return empty
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "freeze_asks.json at %s is malformed (%s) — returning "
            "empty shape; downstream consumers should treat the "
            "case as having no onward CEX flows.",
            p, exc,
        )
        return empty


# ---- Exchange-subpoena rendering (v0.14.11) ---- #


# Per-exchange compliance contact lookup. Used when the
# onward_cex_flows don't carry a compliance email directly.
_EXCHANGE_COMPLIANCE_CONTACTS: dict[str, dict[str, str]] = {
    "Binance": {
        "legal_name": "Binance Holdings Ltd.",
        "compliance_email": "compliance@binance.com",
    },
    "Coinbase": {
        "legal_name": "Coinbase, Inc.",
        "compliance_email": "compliance@coinbase.com",
    },
    "Kraken": {
        "legal_name": "Payward, Inc. (d/b/a Kraken)",
        "compliance_email": "compliance@kraken.com",
    },
    "Bybit": {
        "legal_name": "Bybit Fintech Ltd.",
        "compliance_email": "compliance@bybit.com",
    },
    "OKX": {
        "legal_name": "OKX (Aux Cayes FinTech Co., Ltd.)",
        "compliance_email": "compliance@okx.com",
    },
    "Crypto.com": {
        "legal_name": "Foris DAX MT Limited (Crypto.com)",
        "compliance_email": "compliance@crypto.com",
    },
    "Gemini": {
        "legal_name": "Gemini Trust Company, LLC",
        "compliance_email": "compliance@gemini.com",
    },
    "Bitfinex": {
        "legal_name": "iFinex Inc. (Bitfinex)",
        "compliance_email": "compliance@bitfinex.com",
    },
    "KuCoin": {
        "legal_name": "KuCoin (Mek Global Limited)",
        "compliance_email": "compliance@kucoin.com",
    },
    "Gate.io": {
        "legal_name": "Gate Technology Inc.",
        "compliance_email": "compliance@gate.io",
    },
    "Huobi": {
        "legal_name": "Huobi Global (HTX)",
        "compliance_email": "compliance@htx.com",
    },
}


def _resolve_exchange_metadata(exchange_name: str) -> dict[str, str]:
    """Look up exchange compliance contact info. Falls back to
    placeholder values that the operator can edit before sending.

    Lookup is case-insensitive + space-insensitive: ``"crypto.com"``,
    ``"BINANCE"``, ``"Binance"`` all resolve to the same entry.
    Original casing is preserved for display.
    """
    # Exact match first.
    meta = _EXCHANGE_COMPLIANCE_CONTACTS.get(exchange_name)
    if meta is None:
        target = exchange_name.strip().lower()
        for known_name, known_meta in _EXCHANGE_COMPLIANCE_CONTACTS.items():
            if known_name.strip().lower() == target:
                meta = known_meta
                break
    meta = meta or {}
    return {
        "name": exchange_name,
        "legal_name": meta.get("legal_name", exchange_name),
        "compliance_email": meta.get(
            "compliance_email",
            f"[TODO: compliance email for {exchange_name}]",
        ),
    }


def _render_exchange_subpoena_requests(
    brief: dict[str, Any],
    *,
    output_dir: Path,
    exchange_filter: str | None = None,
) -> list[LegalRequestRender]:
    """Render one consolidated exchange-subpoena request per CEX
    that received funds from a freeze-target address.

    Reads onward_cex_flows from the case's freeze_asks.json (v0.14.10
    schema). If freeze_asks.json isn't co-located with the brief
    (atypical), surfaces an empty list — the operator should run
    list-freeze-targets first.
    """
    # The freeze_asks live next to the brief in the case dir. The
    # caller passes the brief dict but we need the freeze_asks. The
    # convention is to invoke this from a known case_dir; in the
    # CLI path that's preserved. For the pure-function entry, we
    # accept freeze_asks directly through brief['_freeze_asks'] as
    # an injection seam used by tests.
    freeze_asks = brief.get("_freeze_asks")
    if freeze_asks is None:
        case_dir = brief.get("_case_dir")
        if case_dir is not None:
            freeze_asks = load_freeze_asks(Path(case_dir))
        else:
            freeze_asks = {}

    flows = freeze_asks.get("onward_cex_flows", []) or []
    if exchange_filter:
        flows = [
            f for f in flows
            if exchange_filter.lower() in (f.get("exchange") or "").lower()
        ]
    if not flows:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)

    # Group flows by exchange so each CEX gets one consolidated
    # request (vs one letter per deposit address).
    by_exchange: dict[str, list[dict]] = {}
    for f in flows:
        ex = f.get("exchange") or "(unknown exchange)"
        by_exchange.setdefault(ex, []).append(f)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("exchange_subpoena_request.html.j2")

    base_ctx = _build_base_context(brief)
    renders: list[LegalRequestRender] = []

    for exchange_name, exchange_flows in by_exchange.items():
        # Sum total flow USD for the cover-page banner.
        total_usd = sum(
            float(str(f.get("flow_usd_value", "0")).replace("$", "").replace(",", ""))
            for f in exchange_flows
        )
        total_usd_str = f"${total_usd:,.2f}"

        # Distinct token symbols touched, for narrative.
        symbols = sorted({f.get("token_symbol", "") for f in exchange_flows if f.get("token_symbol")})
        if not symbols:
            token_summary = "the relevant token"
        elif len(symbols) == 1:
            token_summary = symbols[0]
        else:
            token_summary = ", ".join(symbols[:-1]) + " and " + symbols[-1]

        exchange_meta = _resolve_exchange_metadata(exchange_name)

        ctx = {
            **base_ctx,
            "exchange": exchange_meta,
            "flows": exchange_flows,
            "total_flow_usd": total_usd_str,
            "token_summary": token_summary,
            "le_engaged": bool(base_ctx.get("ic3_case_id")),
            "le_reference": base_ctx.get("ic3_case_id"),
        }

        html = template.render(**ctx)
        safe_exchange = exchange_name.lower().replace(" ", "_").replace(".", "")
        out_path = output_dir / f"exchange_subpoena_{safe_exchange}.html"
        out_path.write_text(html, encoding="utf-8")
        renders.append(LegalRequestRender(
            request_type="exchange-subpoena",
            exchange_name=exchange_name,
            output_path=out_path,
            html_size_bytes=out_path.stat().st_size,
        ))
    return renders


__all__ = (
    "LegalRequestRender",
    "LEGAL_REQUEST_TYPES",
    "render_legal_request",
    "load_brief",
    "load_freeze_asks",
)
