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
from decimal import Decimal
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero._common import atomic_write_text, resolve_render_time
from recupero.reports._money import format_usd_cents, parse_usd


def _parse_usd_string(s: Any) -> Decimal:
    """Parse '$47,840.12' -> Decimal('47840.12'). Returns Decimal('0') on
    failure. Strict parse (non-finite / negative -> 0); canonical
    implementation lives in :mod:`recupero.reports._money`."""
    return parse_usd(s)


def usd(v: Decimal) -> str:
    """Format a USD amount like '$47,840.00' or '$47,840.12'. Always shows
    cents (this differs from ``emit_brief.usd`` which trims round numbers).
    Canonical implementation lives in :mod:`recupero.reports._money`."""
    return format_usd_cents(v)

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"

LEGAL_REQUEST_TYPES = ("mlat", "314b", "subpoena", "exchange-subpoena", "exchange-freeze")


def _safe_filename_segment(name: str | None, *, fallback: str = "unknown") -> str:
    """Sanitize an attacker-controlled string into a safe filename segment.

    Z4 hardening: brief.EXCHANGES[*].exchange + freeze_asks
    .onward_cex_flows[*].exchange come from token-label provenance, which
    ultimately sources external data. Without sanitation, a malicious
    label like ``../../etc/passwd`` would let the renderer write outside
    the operator's chosen output_dir.

    The sanitizer:
      * Replaces path separators (``/``, ``\\``) with ``_``
      * Strips ``..`` segments and leading/trailing dots
      * Drops NUL bytes and other C0/C1 controls
      * Drops Unicode bidi-override controls
      * Restricts the surviving character set to alnum + ``-_``
      * Caps length to 64 chars
      * Returns ``fallback`` when the result would be empty
    """
    if not isinstance(name, str):
        name = str(name) if name is not None else ""
    # Strip path-traversal segments + separators outright. Doing this
    # BEFORE the char-restriction pass means a literal ".." is dropped
    # even though dots survive the char restriction.
    cleaned = name.replace("\\", "_").replace("/", "_")
    # Remove every ".." sequence iteratively (handles "...." → empty).
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "")
    # Strip NUL + controls + bidi overrides + reduce to alnum/_/-
    out_chars: list[str] = []
    for ch in cleaned:
        cp = ord(ch)
        if cp == 0:
            continue
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            continue
        if cp in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
                  0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            continue
        if ch.isalnum() or ch in "-_":
            out_chars.append(ch)
        elif ch == " ":
            out_chars.append("_")
        # Everything else (including `.`) is dropped.
    safe = "".join(out_chars).strip("._-")
    # v0.30.4 (Jacob hypothesis flake): lowercase BEFORE the 64-char cap.
    # Turkish dotted-I U+0130 lowercases to "i̇" (Latin i + combining
    # diacritical mark) — 2 codepoints instead of 1. Pre-v0.30.4 we
    # truncated to 64 chars FIRST, then lowercased, so an input of
    # exactly 64 dotted-I characters expanded to 65 after the lowercase.
    # The Hypothesis adversarial fuzzer found this corner case
    # (test_safe_filename_segment_caps_at_64). Swapping the order makes
    # the cap an actual cap: lowercase first, THEN truncate.
    safe = safe.lower()
    safe = safe[:64]
    if not safe:
        return fallback
    return safe


def _safe_total_usd(values: list[Any]) -> float:
    """Sum ``flow_usd_value`` entries, defensively skipping NaN/Inf.

    Z4 Bug 3: a poisoned ``flow_usd_value="Infinity"`` propagated into
    the cover-page banner ``f"${total_usd:,.2f}"`` as the literal text
    ``$inf``. Same shape for ``"NaN"`` → ``$nan``. Both are legal-
    document quality bugs.
    """
    import math
    total = 0.0
    for raw in values:
        try:
            cleaned = str(raw).replace("$", "").replace(",", "").strip()
            if not cleaned:
                continue
            v = float(cleaned)
        except (TypeError, ValueError):
            continue
        if math.isnan(v) or math.isinf(v):
            continue
        if v < 0:
            continue
        total += v
    return total


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

    # v0.35: time-critical asset-FREEZE request (vs the records subpoena above).
    # Same onward_cex_flows evidence, but addressed via the VERIFIED-aware
    # exchange-freeze contact resolver and framed as an immediate-hold ask.
    if request_type == "exchange-freeze":
        return _render_exchange_freeze_requests(
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
    # XSS defense-in-depth filters.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template(template_file)

    base_ctx = _build_base_context(brief)
    targets = _enumerate_exchange_targets(brief, exchange_filter=exchange_filter)

    out: list[LegalRequestRender] = []
    for target in targets:
        ctx = {**base_ctx, "perpetrator": target}
        html = template.render(**ctx)
        # Filename: <type>_<exchange-safe>.html
        # Z4 Bug 1: an attacker-controlled exchange name (sourced from
        # token labels) could carry path-traversal segments. Sanitize
        # via _safe_filename_segment so the file lands inside output_dir.
        safe_exchange = _safe_filename_segment(target["exchange_name"])
        out_path = output_dir / f"{request_type}_{safe_exchange}.html"
        atomic_write_text(out_path, html)
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
    now_iso = resolve_render_time().isoformat(timespec="seconds")
    incident_date = brief.get("INCIDENT_DATE") or ""
    # v0.32.1 (output-audit MEDIUM): sanitize free-text victim fields so a
    # work-marker placeholder sentinel (the unconfirmed-state kind, or
    # "(unset)", …) cannot typeset verbatim into an MLAT / 18 USC §3512 /
    # 314(b) / subpoena draft. The LE-handoff path already runs this; the
    # legal-request path did not. Reuse the canonical brief sanitizer
    # (lazy import — brief imports legal_requests lazily, so no cycle).
    from recupero.reports.brief import _sanitize_placeholder
    return {
        "case_id": brief.get("CASE_ID") or "(case-id missing)",
        "generated_at": now_iso.replace("+00:00", "Z"),
        "incident_date": incident_date,
        # v0.32.1 (output-audit LOW, sibling of the victim-field fix above):
        # incident_type + the investigator name/organization are free-text
        # intake fields that also typeset verbatim into the MLAT / §3512 /
        # 314(b) / subpoena drafts — run them through the SAME placeholder
        # sanitizer so an unconfirmed-state sentinel can't leak into a
        # signed legal request.
        "incident_type": _sanitize_placeholder(brief.get("INCIDENT_TYPE"))
            or "the underlying incident",
        "total_loss_usd": brief.get("TOTAL_LOSS_USD") or "$0.00",
        "victim": {
            "name": _sanitize_placeholder(brief.get("VICTIM_NAME")) or "[victim name]",
            "jurisdiction": _sanitize_placeholder(brief.get("VICTIM_JURISDICTION")) or "[jurisdiction]",
        },
        "investigator": {
            "name": _sanitize_placeholder(brief.get("INVESTIGATOR_NAME"))
                or "[investigator name]",
            "organization": _sanitize_placeholder(
                brief.get("INVESTIGATOR_ENTITY_FULL")
                or brief.get("INVESTIGATOR_ENTITY")
            ) or "Recupero",
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

    Reads from brief.EXCHANGES. v0.41-audit C1: the producer
    (emit_brief._extract_exchanges) emits one entry per exchange shaped
    ``{"exchange": name, "deposits": [{"address", "usd", "date", ...}]}``
    — there is NO flat ``ex["address"]`` / ``ex["total_received_usd"]``
    / ``ex["country"]`` key. Reading those non-existent keys made every
    MLAT / 314(b) / subpoena render a blank deposit address and
    ``$0.00`` regardless of how much actually landed at the exchange.

    We now walk ``ex["deposits"]``: sum the per-deposit USD into the
    target total and collect the FULL deposit-address list (court-facing
    — full addresses, never truncated). Filters by ``exchange_filter``
    if provided (case-insensitive substring match).
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
        # Walk the per-deposit list (the real producer shape). Sum USD
        # per deposit and collect full deposit addresses. Fall back to a
        # legacy flat ``ex["address"]`` / ``ex["total_received_usd"]``
        # shape only if no deposits list is present (back-compat with any
        # hand-rolled brief).
        deposits = ex.get("deposits")
        deposit_addresses: list[str] = []
        total_usd_dec = Decimal("0")
        if isinstance(deposits, list) and deposits:
            for d in deposits:
                if not isinstance(d, dict):
                    continue
                addr = str(d.get("address") or "").strip()
                if addr and addr not in deposit_addresses:
                    deposit_addresses.append(addr)
                total_usd_dec += _parse_usd_string(d.get("usd"))
            total_received_usd = usd(total_usd_dec)
        else:
            legacy_addr = str(ex.get("address") or "").strip()
            if legacy_addr:
                deposit_addresses.append(legacy_addr)
            total_received_usd = (
                ex.get("total_received_usd") or ex.get("usd") or "$0.00"
            )
        targets.append({
            "exchange_name": exchange_name,
            "exchange_legal_name": ex.get("exchange_legal_name") or exchange_name,
            "exchange_address": ex.get("exchange_address") or "",
            "registered_agent": ex.get("registered_agent") or "",
            # FULL addresses (court-facing). Newline-joined for the
            # single-string ``deposit_address`` consumers; the list form
            # is the canonical multi-address surface for templates.
            "deposit_address": "\n".join(deposit_addresses) or "",
            "deposit_addresses": deposit_addresses,
            "total_received_usd": total_received_usd,
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
            "deposit_addresses": ["[deposit address]"],
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
    # v0.20.0 (round-13 chain-coverage research): high-volume exchanges
    # added per the prioritized industry-named-destination list. Each
    # entry tagged with its HQ jurisdiction so the LE handoff can
    # route per-country freeze requests correctly.
    "HTX": {
        # HTX is the post-rebrand identity of Huobi Global. Keeping
        # both entries so legacy "Huobi" labels still resolve.
        "legal_name": "Huobi Global Ltd. (d/b/a HTX)",
        "compliance_email": "compliance@htx.com",
    },
    "Bitget": {
        "legal_name": "Bitget Limited",
        "compliance_email": "compliance@bitget.com",
    },
    "WhiteBIT": {
        "legal_name": "WB Services FZE (WhiteBIT)",
        "compliance_email": "compliance@whitebit.com",
    },
    "Upbit": {
        "legal_name": "Dunamu Inc. (Upbit)",
        "compliance_email": "compliance@upbit.com",
    },
    "Bithumb": {
        "legal_name": "Bithumb Korea Co., Ltd.",
        "compliance_email": "compliance@bithumb.com",
    },
    "Bitstamp": {
        "legal_name": "Bitstamp Limited",
        "compliance_email": "compliance@bitstamp.net",
    },
    "Robinhood": {
        "legal_name": "Robinhood Crypto, LLC",
        "compliance_email": "legal-investigations@robinhood.com",
    },
    "Robinhood Crypto": {
        "legal_name": "Robinhood Crypto, LLC",
        "compliance_email": "legal-investigations@robinhood.com",
    },
    "Cash App": {
        "legal_name": "Block, Inc. (Cash App)",
        "compliance_email": "cashapp.legalprocess@block.xyz",
    },
    "BingX": {
        "legal_name": "BingX Technology Limited",
        "compliance_email": "compliance@bingx.com",
    },
    "Phemex": {
        "legal_name": "Phemex Pte. Ltd.",
        "compliance_email": "compliance@phemex.com",
    },
    "LBank": {
        "legal_name": "LBank Exchange",
        "compliance_email": "compliance@lbank.com",
    },
    "Bitkub": {
        "legal_name": "Bitkub Online Co., Ltd.",
        "compliance_email": "compliance@bitkub.com",
    },
    "Independent Reserve": {
        "legal_name": "Independent Reserve Pty Ltd",
        "compliance_email": "compliance@independentreserve.com",
    },
    "BTC Markets": {
        "legal_name": "BTC Markets Pty Ltd",
        "compliance_email": "compliance@btcmarkets.net",
    },
    "CoinJar": {
        "legal_name": "CoinJar Pty Ltd",
        "compliance_email": "compliance@coinjar.com",
    },
    "WazirX": {
        "legal_name": "Zanmai Labs Pvt. Ltd. (WazirX)",
        "compliance_email": "compliance@wazirx.com",
    },
    "CoinDCX": {
        "legal_name": "Neblio Technologies Pvt. Ltd. (CoinDCX)",
        "compliance_email": "compliance@coindcx.com",
    },
    "Mercado Bitcoin": {
        "legal_name": "Mercado Bitcoin Serviços Digitais Ltda.",
        "compliance_email": "compliance@mercadobitcoin.com.br",
    },
    "Bitvavo": {
        "legal_name": "Bitvavo B.V.",
        "compliance_email": "compliance@bitvavo.com",
    },
    "Bitso": {
        "legal_name": "Bitso B.V.",
        "compliance_email": "compliance@bitso.com",
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
        freeze_asks = load_freeze_asks(Path(case_dir)) if case_dir is not None else {}

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
    # XSS defense-in-depth filters.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template("exchange_subpoena_request.html.j2")

    base_ctx = _build_base_context(brief)
    renders: list[LegalRequestRender] = []

    for exchange_name, exchange_flows in by_exchange.items():
        # Z4 Bug 3 (per-row): sanitize flow_usd_value on each flow so
        # the template's ``{{ flow.flow_usd_value }}`` cell can't leak
        # ``Infinity`` / ``NaN`` strings into the legal document body.
        import math
        sanitized_flows: list[dict] = []
        for f in exchange_flows:
            row = dict(f)
            raw = row.get("flow_usd_value", "0")
            try:
                cleaned = str(raw).replace("$", "").replace(",", "").strip()
                v = float(cleaned) if cleaned else 0.0
                if math.isnan(v) or math.isinf(v) or v < 0:
                    row["flow_usd_value"] = "$0.00"
                elif not str(raw).startswith("$"):
                    row["flow_usd_value"] = f"${v:,.2f}"
            except (TypeError, ValueError):
                row["flow_usd_value"] = "$0.00"
            sanitized_flows.append(row)
        exchange_flows = sanitized_flows

        # Sum total flow USD for the cover-page banner.
        # Z4 Bug 3: defend against Inf/NaN in flow_usd_value (price-
        # oracle glitch) — these would render as "$inf"/"$nan" in the
        # grand-jury subpoena cover page.
        total_usd = _safe_total_usd(
            [f.get("flow_usd_value", "0") for f in exchange_flows]
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
        # Z4 Bug 2: attacker-controlled exchange string can be
        # ``../evil`` etc — sanitize via _safe_filename_segment.
        safe_exchange = _safe_filename_segment(exchange_name)
        out_path = output_dir / f"exchange_subpoena_{safe_exchange}.html"
        atomic_write_text(out_path, html)
        renders.append(LegalRequestRender(
            request_type="exchange-subpoena",
            exchange_name=exchange_name,
            output_path=out_path,
            html_size_bytes=out_path.stat().st_size,
        ))
    return renders


def _render_exchange_freeze_requests(
    brief: dict[str, Any],
    *,
    output_dir: Path,
    exchange_filter: str | None = None,
) -> list[LegalRequestRender]:
    """Render one TIME-CRITICAL asset-freeze request per CEX that received
    funds from a freeze-target address. Same onward_cex_flows evidence as the
    subpoena, but addressed via the VERIFIED-aware exchange-freeze contact
    resolver (LE portal / freeze capability / verified flag) and framed as an
    immediate-hold ask. An unverified/unknown contact still renders, with a
    prominent "confirm channel before sending" banner."""
    import math

    freeze_asks = brief.get("_freeze_asks")
    if freeze_asks is None:
        case_dir = brief.get("_case_dir")
        freeze_asks = load_freeze_asks(Path(case_dir)) if case_dir is not None else {}

    flows = freeze_asks.get("onward_cex_flows", []) or []
    if exchange_filter:
        flows = [
            f for f in flows
            if exchange_filter.lower() in (f.get("exchange") or "").lower()
        ]
    if not flows:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)

    by_exchange: dict[str, list[dict]] = {}
    for f in flows:
        ex = f.get("exchange") or "(unknown exchange)"
        by_exchange.setdefault(ex, []).append(f)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template("exchange_freeze_request.html.j2")

    # Lazy import avoids any reports<->freeze import cycle.
    from recupero.freeze.exchange_contacts import resolve_exchange_freeze_contact

    base_ctx = _build_base_context(brief)
    renders: list[LegalRequestRender] = []

    for exchange_name, exchange_flows in by_exchange.items():
        # Sanitize flow_usd_value (Inf/NaN/negative) so the legal document
        # body can't typeset "$inf"/"$nan" — mirrors the subpoena renderer.
        sanitized: list[dict] = []
        for f in exchange_flows:
            row = dict(f)
            raw = row.get("flow_usd_value", "0")
            try:
                cleaned = str(raw).replace("$", "").replace(",", "").strip()
                v = float(cleaned) if cleaned else 0.0
                if math.isnan(v) or math.isinf(v) or v < 0:
                    row["flow_usd_value"] = "$0.00"
                elif not str(raw).startswith("$"):
                    row["flow_usd_value"] = f"${v:,.2f}"
            except (TypeError, ValueError):
                row["flow_usd_value"] = "$0.00"
            sanitized.append(row)
        exchange_flows = sanitized

        total_usd = _safe_total_usd(
            [f.get("flow_usd_value", "0") for f in exchange_flows]
        )
        symbols = sorted({f.get("token_symbol", "") for f in exchange_flows if f.get("token_symbol")})
        if not symbols:
            token_summary = "the relevant token"
        elif len(symbols) == 1:
            token_summary = symbols[0]
        else:
            token_summary = ", ".join(symbols[:-1]) + " and " + symbols[-1]

        contact = resolve_exchange_freeze_contact(exchange_name)
        if contact is not None:
            exchange_ctx = {
                "name": contact.name,
                "legal_name": contact.legal_name,
                "compliance_email": contact.compliance_email,
                "le_portal_url": contact.le_portal_url,
                "freeze_capability": contact.freeze_capability,
                "freeze_request_channel": contact.freeze_request_channel,
                "verified": contact.verified,
                "source": contact.source,
            }
        else:
            # Unknown exchange — render with a clearly-unverified placeholder.
            exchange_ctx = {
                "name": exchange_name, "legal_name": exchange_name,
                "compliance_email": None, "le_portal_url": None,
                "freeze_capability": "unknown", "freeze_request_channel": None,
                "verified": False, "source": None,
            }

        ctx = {
            **base_ctx,
            "exchange": exchange_ctx,
            "flows": exchange_flows,
            "total_flow_usd": f"${total_usd:,.2f}",
            "token_summary": token_summary,
            "le_engaged": bool(base_ctx.get("ic3_case_id")),
            "le_reference": base_ctx.get("ic3_case_id"),
        }

        html = template.render(**ctx)
        safe_exchange = _safe_filename_segment(exchange_name)
        out_path = output_dir / f"exchange_freeze_{safe_exchange}.html"
        atomic_write_text(out_path, html)
        renders.append(LegalRequestRender(
            request_type="exchange-freeze",
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
