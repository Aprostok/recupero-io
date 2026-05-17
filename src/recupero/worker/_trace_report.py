"""Internal-facing trace-report HTML — the data-only summary the
admin UI's wallet-trace detail page surfaces as the primary artifact.

Emitted on EVERY investigation, regardless of case_id, skip flags,
or FREEZABLE count. The trace report is what an investigator looks
at first — clean forensic worksheet, no narrative prose, no
customer-facing salutations, no "Dear Compliance Team". It lives
alongside whatever customer-facing freeze letters get produced for
the same investigation; wallet-trace investigations (case_id=NULL,
skip_freeze_briefs=True) ship ONLY this artifact.

Sections (per Jacob's spec):
  1. Trace summary    — stats: transfers, depth, total USD, destinations
  2. Destinations     — every destination wallet with current holdings
  3. Freeze potential — only destinations holding freezable assets,
                        with HIGH/MEDIUM/LOW/NOT FREEZABLE taxonomy
  4. Flow viz pointer — attachment reference to flow_<hash>.svg

Filename: ``trace_report_<short-hash>.html`` — matches the existing
short-hash convention for ``flow_*.svg`` and ``freeze_request_*.html``.
Stored in ``case_dir/briefs/`` (same investigation folder as the
customer-facing letters).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero import __version__
from recupero.models import Case

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent.parent / "reports" / "templates"


# Chain explorer prefixes (mirrors brief.py + _flow_diagram.py).
_ADDRESS_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
}


def render_trace_report(
    *,
    case: Case,
    freeze_brief: dict[str, Any],
    briefs_dir: Path,
    flow_filename: str | None = None,
    investigation_id: str | None = None,
    label: str | None = None,
) -> Path | None:
    """Render the internal trace_report HTML to ``briefs_dir`` and
    return its path. Returns ``None`` on template-render failure.

    Best-effort: a Jinja crash logs a warning and returns None so
    the caller's building_package stage doesn't fail just because
    the internal report had a glitch.
    """
    try:
        briefs_dir.mkdir(parents=True, exist_ok=True)
        report_id = uuid4().hex[:8]
        report_path = briefs_dir / f"trace_report_{report_id}.html"

        ctx = _build_context(
            case=case,
            freeze_brief=freeze_brief,
            flow_filename=flow_filename,
            investigation_id=investigation_id or case.case_id,
            label=label,
        )

        env = Environment(
            loader=FileSystemLoader(_TEMPLATES_DIR),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        html = env.get_template("trace_report.html.j2").render(**ctx)
        report_path.write_text(html, encoding="utf-8")
        return report_path
    except Exception as exc:  # noqa: BLE001
        log.warning("trace report render failed: %s", exc)
        return None


# ----- context builder ----- #


def _build_context(
    *,
    case: Case,
    freeze_brief: dict[str, Any],
    flow_filename: str | None,
    investigation_id: str,
    label: str | None,
) -> dict[str, Any]:
    chain_str = case.chain.value
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    wallet_addr = case.seed_address

    stats = _compute_stats(case)
    # v0.7.4: lift the gross-perpetrator-holdings figure from
    # the freeze_brief onto the stats dict so the trace_report
    # template can lead with it. Falls back to None when
    # freeze_brief is missing the field (older briefs, or
    # cases that didn't run through emit_brief).
    stats["total_perpetrator_holdings_usd"] = (
        freeze_brief.get("TOTAL_PERPETRATOR_HOLDINGS_USD") or None
    )
    destinations = _build_destinations_table(case)
    freezable_rows = _build_freezable_table(freeze_brief, chain_str)

    # v0.8.1 / 0.9.x — surface the new sections into the trace
    # report template so the rendered PDF / HTML carries them.
    # Pass through verbatim from freeze_brief; the template
    # renders empty-state messages when sections are empty.
    cross_chain_handoffs = freeze_brief.get("CROSS_CHAIN_HANDOFFS") or []
    entity_clusters = freeze_brief.get("ENTITY_CLUSTERS") or None
    risk_assessment = freeze_brief.get("RISK_ASSESSMENT") or None

    return {
        "investigation_id": str(investigation_id),
        "label": label,
        "wallet_address": wallet_addr,
        "wallet_explorer_url": _explorer_url(wallet_addr, chain_str),
        "chain": chain_str,
        "generated_at": now,
        "software_version": __version__,
        "stats": stats,
        "destinations": destinations,
        "freezable_rows": freezable_rows,
        # v0.8.1 / v0.9.x sections
        "cross_chain_handoffs": cross_chain_handoffs,
        "entity_clusters": entity_clusters,
        "risk_assessment": risk_assessment,
        "flow_filename": flow_filename,
    }


def _compute_stats(case: Case) -> dict[str, Any]:
    transfers = case.transfers or []
    max_depth = max((t.hop_depth for t in transfers), default=0)
    total_usd = Decimal(0)
    destinations: set[str] = set()
    for t in transfers:
        if t.usd_value_at_tx:
            total_usd += t.usd_value_at_tx
        destinations.add(t.to_address.lower())
    # Drop the seed itself from the destinations count if it appears.
    destinations.discard((case.seed_address or "").lower())
    return {
        "total_transfers":     len(transfers),
        "max_depth_reached":   max_depth,
        "total_flow_usd":      _fmt_usd(total_usd),
        "destinations_count":  len(destinations),
        "trace_started_at":    (
            case.trace_started_at.strftime("%Y-%m-%d %H:%M:%S")
            if case.trace_started_at else "—"
        ),
        "trace_completed_at":  (
            case.trace_completed_at.strftime("%Y-%m-%d %H:%M:%S")
            if case.trace_completed_at else "—"
        ),
    }


def _build_destinations_table(case: Case) -> list[dict[str, Any]]:
    """One row per distinct destination address. Aggregates totals
    when an address appears in multiple transfers."""
    chain_str = case.chain.value
    seed = (case.seed_address or "").lower()
    by_addr: dict[str, dict[str, Any]] = {}
    for t in case.transfers or []:
        addr = t.to_address
        key = addr.lower()
        if key == seed:
            continue
        entry = by_addr.get(key)
        if entry is None:
            label = t.counterparty.label
            entry = {
                "address": addr,
                "address_short": _short_addr(addr),
                "explorer_url": _explorer_url(addr, chain_str),
                "role": (
                    label.category.value.replace("_", " ").title()
                    if label else "Wallet"
                ),
                "label": label.name if label else None,
                "symbol": t.token.symbol,
                "balance_human": _fmt_decimal(t.amount_decimal),
                "usd_value_human": _fmt_usd(t.usd_value_at_tx),
                "_usd": t.usd_value_at_tx or Decimal(0),
            }
            by_addr[key] = entry
        else:
            # Same address re-appears — keep the highest-USD transfer's
            # representation (typically the most relevant flow).
            if (t.usd_value_at_tx or Decimal(0)) > entry["_usd"]:
                entry["symbol"] = t.token.symbol
                entry["balance_human"] = _fmt_decimal(t.amount_decimal)
                entry["usd_value_human"] = _fmt_usd(t.usd_value_at_tx)
                entry["_usd"] = t.usd_value_at_tx or Decimal(0)
    rows = list(by_addr.values())
    rows.sort(key=lambda r: r["_usd"], reverse=True)
    for r in rows:
        r.pop("_usd", None)
    return rows


def _build_freezable_table(
    freeze_brief: dict[str, Any], chain_str: str,
) -> list[dict[str, Any]]:
    """Flatten FREEZABLE issuers × their holdings into a single
    table the template renders directly. One row per (issuer, holding).

    Capability taxonomy (from emit_brief.py): HIGH / MEDIUM / LOW.
    Holdings flagged ``status='UNRECOVERABLE'`` get the "NOT FREEZABLE"
    label for the operator — the issuer technically issues the token
    but has no power over a staking-contract holding.
    """
    rows: list[dict[str, Any]] = []
    for entry in freeze_brief.get("FREEZABLE") or []:
        issuer = entry.get("issuer") or "—"
        symbol = entry.get("token") or "—"
        issuer_capability = (entry.get("freeze_capability") or "").upper()
        for h in entry.get("holdings") or []:
            address = h.get("address") or ""
            status = (h.get("status") or "").upper()
            if status == "UNRECOVERABLE":
                capability = "NOT FREEZABLE"
                cap_class = "none"
            elif issuer_capability == "HIGH":
                capability = "HIGH"
                cap_class = "high"
            elif issuer_capability == "MEDIUM":
                capability = "MEDIUM"
                cap_class = "medium"
            else:
                capability = "LOW"
                cap_class = "low"
            rows.append({
                "address": address,
                "address_short": _short_addr(address),
                "explorer_url": _explorer_url(address, chain_str),
                "symbol": symbol,
                "amount": h.get("amount") or "—",
                "usd": h.get("usd") or "—",
                "issuer": issuer,
                "capability": capability,
                "capability_class": cap_class,
            })
    # Sort highest-USD first within the table — operator wants to see
    # the biggest freezable holdings at top.
    def _usd_key(r: dict[str, Any]) -> float:
        raw = (r["usd"] or "").replace("$", "").replace(",", "")
        try:
            return float(raw)
        except (ValueError, TypeError):
            return 0.0
    rows.sort(key=_usd_key, reverse=True)
    return rows


# ----- helpers ----- #


def _explorer_url(address: str, chain: str) -> str:
    if not address:
        return ""
    prefix = _ADDRESS_EXPLORER_BY_CHAIN.get(
        chain, "https://etherscan.io/address/",
    )
    return f"{prefix}{address}"


def _short_addr(addr: str) -> str:
    if not addr or len(addr) < 12:
        return addr or ""
    return f"{addr[:6]}…{addr[-4:]}"


def _fmt_usd(v: Decimal | None) -> str:
    if v is None:
        return "$0"
    try:
        return f"${v:,.2f}"
    except (TypeError, ValueError):
        return "$0"


def _fmt_decimal(v: Decimal | None) -> str:
    if v is None:
        return "—"
    try:
        s = f"{v:.6f}".rstrip("0").rstrip(".")
        return s or "0"
    except (TypeError, ValueError):
        return "—"


__all__ = ("render_trace_report",)
