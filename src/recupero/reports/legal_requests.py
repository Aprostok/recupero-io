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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"

LEGAL_REQUEST_TYPES = ("mlat", "314b", "subpoena")


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
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
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
    """Load freeze_brief.json from a case directory."""
    brief_path = case_dir / "freeze_brief.json"
    if not brief_path.exists():
        raise FileNotFoundError(
            f"freeze_brief.json not found at {brief_path}. Run "
            f"`recupero emit-brief CASE_ID` first."
        )
    return json.loads(brief_path.read_text(encoding="utf-8-sig"))


__all__ = (
    "LegalRequestRender",
    "LEGAL_REQUEST_TYPES",
    "render_legal_request",
    "load_brief",
)
