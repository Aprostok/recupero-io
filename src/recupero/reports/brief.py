"""Brief generator.

Reads one or more case.json files, a victim.json, and renders both:
  * Maple Finance compliance freeze request
  * Law enforcement handoff package

The two HTML files are written to data/cases/<primary_case>/briefs/.

Design notes:
  - The "primary case" is the victim's case (depth=1 from the victim).
  - "Linked cases" are subsequent depth-N traces that show forwarding hops.
  - We identify the "stolen asset" automatically: the largest USD-value
    transfer in the primary case is treated as the theft event.
  - The "current holder" is the destination of the LAST transfer in the
    forwarding chain that involved the stolen asset.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero import __version__
from recupero.models import Case, Transfer
from recupero.reports.victim import VictimInfo

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass
class InvestigatorInfo:
    name: str
    organization: str
    email: str
    phone: str | None = None


@dataclass
class IssuerInfo:
    """The entity that issued the stolen token. Used to address the freeze brief.

    For tokenized RWAs, the issuer is the entity with protocol-level control over
    the wrapper token (mint/burn) — i.e. the only party that can implement a
    technical freeze. For pure DeFi assets without an issuer, leave name empty
    and the brief skips the freeze-request section.
    """
    name: str                              # e.g. "Midas Software GmbH"
    short_name: str                        # e.g. "Midas" — used in filenames and prose
    contact_email: str                     # e.g. "team@midas.app"
    jurisdiction: str | None = None        # e.g. "Germany (EU)"
    regulatory_framework: str | None = None  # e.g. "MiCA, GDPR, BaFin oversight"
    secondary_party: str | None = None     # e.g. "Maple Finance" — copied on brief
    secondary_role: str | None = None      # e.g. "underlying strategy manager"
    asset_description: str | None = None   # one-line technical description of asset
    kyc_required: bool = False             # was KYC required to acquire the asset originally?
    kyc_minimum: str | None = None         # e.g. "$125,000 USD"


# Sensible default for the Zigha case (Midas-issued msyrupUSDp)
MIDAS_ISSUER = IssuerInfo(
    name="Midas Software GmbH",
    short_name="Midas",
    contact_email="team@midas.app",
    jurisdiction="Germany (European Union)",
    regulatory_framework="EU Markets in Crypto-Assets Regulation (MiCA), General Data Protection Regulation (GDPR), German federal financial supervision (BaFin)",
    secondary_party="Maple Finance",
    secondary_role="underlying yield strategy manager",
    asset_description="Midas-issued ERC-20 wrapper token representing a pre-deposit position in Maple Finance's syrupUSDT institutional credit strategy on the Plasma blockchain",
    kyc_required=True,
    kyc_minimum="USD 125,000",
)


@dataclass
class BriefBundle:
    """Both rendered briefs + their disk paths."""
    maple_html: str
    le_html: str
    maple_path: Path
    le_path: Path
    manifest_path: Path
    brief_id: str


def generate_briefs(
    *,
    primary_case: Case,
    linked_cases: list[Case],
    victim: VictimInfo,
    investigator: InvestigatorInfo,
    case_dir: Path,
    issuer: IssuerInfo = MIDAS_ISSUER,
    asset_type: str = "ERC-20 yield-bearing wrapper token",
    asset_usd_value_current: str | None = None,
    outbound_count_of_stolen_asset: int = 0,
    flow_svg: str | None = None,
) -> BriefBundle:
    """Render both briefs and write them to disk."""
    # Identify the theft event: the largest USD transfer in the primary case
    theft_transfer = _find_theft_transfer(primary_case)
    if theft_transfer is None:
        raise ValueError(
            f"No transfers in case {primary_case.case_id} could be identified as the theft event."
        )

    # Build the forwarding chain across linked cases
    hops = _build_hops(theft_transfer, linked_cases)

    # Determine current holder: last hop's destination, or theft_transfer's destination if no hops
    if hops:
        current_holder_addr = hops[-1].to_address
    else:
        current_holder_addr = theft_transfer.to_address

    # Identify wallets across all cases for the LE summary table
    identified_wallets = _build_identified_wallets(primary_case, linked_cases, victim, current_holder_addr)

    # Common context
    now = datetime.now(timezone.utc)
    brief_id = f"BRIEF-{now.strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"

    ctx: dict[str, Any] = {
        "case_id": primary_case.case_id,
        "brief_id": brief_id,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "verified_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "trace_started_at": (
            primary_case.trace_started_at.strftime("%Y-%m-%d %H:%M:%S")
            if primary_case.trace_started_at else "—"
        ),
        "software_version": __version__,
        "victim": victim.model_dump(),
        "investigator": investigator.__dict__,
        "asset": {
            "symbol": theft_transfer.token.symbol,
            "contract": theft_transfer.token.contract or "(native)",
            "issuer": issuer.name,
            "issuer_short": issuer.short_name,
            "type": asset_type,
            "description": issuer.asset_description or asset_type,
            "amount_human": _fmt_decimal(theft_transfer.amount_decimal),
            "usd_value_at_theft": _fmt_usd(theft_transfer.usd_value_at_tx),
            "usd_value_current": asset_usd_value_current,
        },
        "issuer": {
            "name": issuer.name,
            "short_name": issuer.short_name,
            "contact_email": issuer.contact_email,
            "jurisdiction": issuer.jurisdiction,
            "regulatory_framework": issuer.regulatory_framework,
            "secondary_party": issuer.secondary_party,
            "secondary_role": issuer.secondary_role,
            "kyc_required": issuer.kyc_required,
            "kyc_minimum": issuer.kyc_minimum,
        },
        "theft_event": {
            "tx_hash": theft_transfer.tx_hash,
            "block_number": theft_transfer.block_number,
            "timestamp_human": theft_transfer.block_time.strftime("%Y-%m-%d %H:%M:%S"),
            "from_address": theft_transfer.from_address,
            "to_address": theft_transfer.to_address,
            "explorer_url": theft_transfer.explorer_url,
        },
        "hops": [
            {
                "tx_hash": h.tx_hash,
                "timestamp_human": h.block_time.strftime("%Y-%m-%d %H:%M:%S"),
                "from_address": h.from_address,
                "to_address": h.to_address,
                "amount_human": _fmt_decimal(h.amount_decimal),
                "symbol": h.token.symbol,
                "explorer_url": h.explorer_url,
            }
            for h in hops
        ],
        "current_holder": {
            "address": current_holder_addr,
            "explorer_url": f"https://etherscan.io/address/{current_holder_addr}",
        },
        "outbound_count_of_stolen_asset": outbound_count_of_stolen_asset,
        "identified_wallets": identified_wallets,
        # Inline-SVG flow diagram. Templates render via {{ flow_svg|safe }};
        # absence is rendered as nothing rather than an error so the
        # legacy CLI flow continues to work without the worker's
        # diagram pipeline attached.
        "flow_svg": flow_svg or "",
    }

    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    issuer_template = "issuer_freeze_request.html.j2"
    # Backward-compat: if old "maple.html.j2" still exists, prefer the new one
    try:
        env.get_template(issuer_template)
    except Exception:
        issuer_template = "maple.html.j2"

    maple_html = env.get_template(issuer_template).render(**ctx)
    le_html = env.get_template("le.html.j2").render(**ctx)

    briefs_dir = case_dir / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)
    issuer_slug = (issuer.short_name or "issuer").lower().replace(" ", "_")
    maple_path = briefs_dir / f"freeze_request_{issuer_slug}_{brief_id}.html"
    # Include the issuer slug in the LE handoff filename too — the LE
    # template references issuer.name / issuer.short_name extensively
    # (preservation requests, KYC framing, secondary-party language),
    # so multi-issuer cases produce DIFFERENT le_handoff content per
    # call. Without the slug, generate_briefs called N times would
    # silently overwrite the previous LE handoff with the last issuer's
    # version. Per-issuer filename preserves all of them.
    le_path = briefs_dir / f"le_handoff_{issuer_slug}_{brief_id}.html"
    maple_path.write_text(maple_html, encoding="utf-8")
    le_path.write_text(le_html, encoding="utf-8")

    manifest = {
        "brief_id": brief_id,
        "generated_at": now.isoformat(),
        "primary_case": primary_case.case_id,
        "linked_cases": [c.case_id for c in linked_cases],
        "theft_tx": theft_transfer.tx_hash,
        "current_holder": current_holder_addr,
        "victim_name": victim.name,
        "investigator": investigator.__dict__,
        "issuer": issuer.name,
        "software_version": __version__,
        "outputs": {
            "issuer_freeze_request": str(maple_path),
            "le_handoff": str(le_path),
        },
    }
    manifest_path = briefs_dir / f"manifest_{brief_id}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    log.info("wrote issuer freeze request: %s", maple_path)
    log.info("wrote LE handoff: %s", le_path)

    return BriefBundle(
        maple_html=maple_html,
        le_html=le_html,
        maple_path=maple_path,
        le_path=le_path,
        manifest_path=manifest_path,
        brief_id=brief_id,
    )


# ---------- internals ----------


def _find_theft_transfer(case: Case) -> Transfer | None:
    """The theft event is the highest-USD transfer in the case."""
    candidates = [t for t in case.transfers if t.usd_value_at_tx is not None]
    if not candidates:
        # No USD info — fall back to highest amount_decimal (less reliable)
        return max(case.transfers, key=lambda t: t.amount_decimal, default=None)
    return max(candidates, key=lambda t: t.usd_value_at_tx)


def _build_hops(theft: Transfer, linked_cases: list[Case]) -> list[Transfer]:
    """Find subsequent transfers of the stolen asset across linked cases.

    Walks forward: the theft's destination becomes the next 'from'. We look
    for transfers of the same TOKEN (by contract+chain) from that address in
    any linked case. If found, the chain continues — the new transfer's
    destination becomes the next 'from', and so on.
    """
    chain: list[Transfer] = []
    current = theft.to_address.lower()
    target_token_contract = (theft.token.contract or "").lower()
    target_chain = theft.token.chain

    # Build a quick index: {(from_addr_lower, token_contract_lower) -> list[Transfer]}
    index: dict[tuple[str, str], list[Transfer]] = {}
    for c in linked_cases:
        for t in c.transfers:
            if t.token.chain != target_chain:
                continue
            key = (t.from_address.lower(), (t.token.contract or "").lower())
            index.setdefault(key, []).append(t)

    visited: set[str] = {current}
    while True:
        candidates = index.get((current, target_token_contract), [])
        if not candidates:
            break
        # Pick the earliest forwarding tx (by block) — that's the natural chain
        candidates.sort(key=lambda t: t.block_number)
        next_hop = candidates[0]
        chain.append(next_hop)
        next_addr = next_hop.to_address.lower()
        if next_addr in visited:
            log.warning("hop chain loop detected at %s — breaking", next_addr)
            break
        visited.add(next_addr)
        current = next_addr

    return chain


def _build_identified_wallets(
    primary: Case,
    linked: list[Case],
    victim: VictimInfo,
    current_holder: str,
) -> list[dict[str, Any]]:
    """Collect every distinct address mentioned across all cases, with role + label."""
    seen: dict[str, dict[str, Any]] = {}

    def _add(addr: str, role: str, type_str: str, notes: str, row_class: str = ""):
        key = addr.lower()
        if key in seen:
            # Don't downgrade — first observation wins for role/notes
            return
        seen[key] = {
            "address": addr, "role": role, "type": type_str,
            "notes": notes, "row_class": row_class,
        }

    _add(victim.wallet_address, "Victim", "EOA", "Source of stolen funds", "victim-row")

    for c in [primary, *linked]:
        for t in c.transfers:
            if t.from_address.lower() == victim.wallet_address.lower():
                continue  # victim already added
            cp_label = t.counterparty.label
            if t.to_address.lower() == current_holder.lower():
                role = "Current holder of stolen position"
                row_class = "perp-row"
            elif cp_label and cp_label.category.value == "perpetrator":
                role = f"Perpetrator wallet ({cp_label.name})"
                row_class = "perp-row"
            elif cp_label:
                role = cp_label.name
                row_class = ""
            else:
                role = "Unlabeled (under investigation)"
                row_class = ""
            type_str = "Contract" if t.counterparty.is_contract else "EOA"
            notes_parts = []
            if cp_label:
                notes_parts.append(f"Category: {cp_label.category.value}")
                if cp_label.notes:
                    notes_parts.append(cp_label.notes)
            notes = " · ".join(notes_parts) or "—"
            _add(t.to_address, role, type_str, notes, row_class)

    # Sort: victim, perpetrators, then everyone else
    def _sort_key(w: dict[str, Any]) -> tuple[int, str]:
        if "victim" in w["row_class"]: return (0, w["address"])
        if "perp" in w["row_class"]: return (1, w["address"])
        return (2, w["address"])

    return sorted(seen.values(), key=_sort_key)


def _fmt_decimal(d: Decimal | None) -> str:
    if d is None:
        return "—"
    if d == d.to_integral_value():
        return f"{int(d):,}"
    return f"{d:,.6f}".rstrip("0").rstrip(".")


def _fmt_usd(d: Decimal | None) -> str:
    if d is None:
        return "(unknown)"
    return f"{d:,.2f}"
