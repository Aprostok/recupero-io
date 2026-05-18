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
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero import __version__
from recupero.models import Case, Chain, Transfer
from recupero.reports.victim import VictimInfo

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


# Chain → address-page explorer URL prefix.
#
# We mirror the prefix table that lives in worker/_flow_diagram.py
# rather than importing it: brief.py runs from the standalone CLI too,
# which doesn't carry the worker module. Keeping these in sync is
# manual but stable — block explorers don't rebrand often.
_ADDRESS_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
}


def _address_explorer_url(address: str, chain: Chain | str | None) -> str:
    """Build a click-through URL for ``address`` on the appropriate
    chain explorer. Falls back to Etherscan when chain is unknown."""
    if not address:
        return ""
    chain_str = chain.value if isinstance(chain, Chain) else (chain or "ethereum")
    prefix = _ADDRESS_EXPLORER_BY_CHAIN.get(chain_str,
                                            "https://etherscan.io/address/")
    return f"{prefix}{address}"


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
    flow_filename: str | None = None,
    issuer_freezable: dict | None = None,
) -> BriefBundle:
    """Render both briefs and write them to disk.

    ``issuer_freezable`` (added 2026-05-15 in response to the
    operator-quality review on case e917ffc5) is the per-issuer
    FREEZABLE entry from ``freeze_brief.json``. When provided, the
    template renders an issuer-specific "current location + ask"
    that lists each holding (status FREEZABLE or INVESTIGATE) the
    issuer actually controls, instead of generically asking every
    issuer to freeze the original ETH at the first hop.

    Shape (matches freeze_brief.json):

      {
        "issuer": "Circle",
        "token": "USDC",
        "total_usd": "$7,097.58",
        "total_suspected_usd": "$1,037,451.35",
        "freeze_capability": "HIGH",
        "holdings": [
          {"address": "0xABC...",
           "amount": "1066.27 USDC",
           "usd": "$1,066.27",
           "status": "FREEZABLE"},
          ...
        ],
        ...
      }

    When None (the legacy/wallet-trace path), the template falls
    back to single-asset/single-holder rendering using
    ``theft_transfer`` as the source. Backward-compatible for any
    caller that hasn't yet been updated to pass per-issuer data.
    """
    # Identify the theft event(s). _find_theft_events returns the full
    # drain cluster (primary event first, then any others within the
    # 7-day window). For real-world cases drained across multiple
    # transactions, this surfaces the full timeline in the LE handoff
    # while keeping the freeze letter focused on the primary event.
    theft_events = _find_theft_events(primary_case)
    if not theft_events:
        raise ValueError(
            f"No transfers in case {primary_case.case_id} could be identified as the theft event."
        )
    theft_transfer = theft_events[0]  # primary (headline) event

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
    now = datetime.now(UTC)
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
        # Address URLs are computed per-row so every raw address shown
        # in the letter is a click-through link in the rendered PDF.
        # WeasyPrint converts <a href=".."> annotations into PDF link
        # rectangles, so compliance reviewers can jump straight from
        # the document to the on-chain record.
        "theft_event": {
            "tx_hash": theft_transfer.tx_hash,
            "block_number": theft_transfer.block_number,
            "timestamp_human": theft_transfer.block_time.strftime("%Y-%m-%d %H:%M:%S"),
            "from_address": theft_transfer.from_address,
            "to_address": theft_transfer.to_address,
            "explorer_url": theft_transfer.explorer_url,
            "from_explorer_url": _address_explorer_url(
                theft_transfer.from_address, theft_transfer.chain
            ),
            "to_explorer_url": _address_explorer_url(
                theft_transfer.to_address, theft_transfer.chain
            ),
        },
        # Full theft-event cluster, sorted by block_time ascending for
        # chronological rendering in section 3 of the LE handoff.
        # The primary event is at index 0 unless block_time orders it
        # later; templates that want strictly chronological should sort.
        # ``theft_event_count`` and ``theft_event_total_usd`` are
        # convenience aggregates for prose generation.
        "theft_events": [
            {
                "tx_hash": t.tx_hash,
                "block_number": t.block_number,
                "timestamp_human": t.block_time.strftime("%Y-%m-%d %H:%M:%S"),
                "from_address": t.from_address,
                "to_address": t.to_address,
                "amount_human": _fmt_decimal(t.amount_decimal),
                "symbol": t.token.symbol,
                "usd_value": _fmt_usd(t.usd_value_at_tx),
                "explorer_url": t.explorer_url,
                "from_explorer_url": _address_explorer_url(t.from_address, t.chain),
                "to_explorer_url": _address_explorer_url(t.to_address, t.chain),
                "is_primary": t.transfer_id == theft_transfer.transfer_id,
            }
            for t in sorted(theft_events, key=lambda x: x.block_time)
        ],
        "theft_event_count": len(theft_events),
        "theft_event_total_usd": _fmt_usd(
            sum(
                (t.usd_value_at_tx for t in theft_events
                 if t.usd_value_at_tx is not None),
                start=Decimal(0),
            )
        ),
        "hops": [
            {
                "tx_hash": h.tx_hash,
                "timestamp_human": h.block_time.strftime("%Y-%m-%d %H:%M:%S"),
                "from_address": h.from_address,
                "to_address": h.to_address,
                "amount_human": _fmt_decimal(h.amount_decimal),
                "symbol": h.token.symbol,
                "explorer_url": h.explorer_url,
                "from_explorer_url": _address_explorer_url(h.from_address, h.chain),
                "to_explorer_url": _address_explorer_url(h.to_address, h.chain),
            }
            for h in hops
        ],
        "current_holder": {
            "address": current_holder_addr,
            "explorer_url": _address_explorer_url(
                current_holder_addr, primary_case.chain
            ),
        },
        # Asset contract address: clickable token-contract page when
        # the contract is known (None for native ETH / BTC).
        "asset_contract_explorer_url": (
            _address_explorer_url(theft_transfer.token.contract,
                                  theft_transfer.chain)
            if theft_transfer.token.contract else None
        ),
        # Victim wallet — first interaction many compliance reviewers
        # will want is to verify the seed wallet on chain.
        "victim_wallet_explorer_url": _address_explorer_url(
            victim.wallet_address, primary_case.chain
        ),
        "outbound_count_of_stolen_asset": outbound_count_of_stolen_asset,
        "identified_wallets": identified_wallets,
        # Fund-flow diagram lives in briefs/flow_<hash>.svg as a
        # standalone artifact. Letters reference it via attachment-
        # pointer in section 3 (no inline embed — the inline version
        # was unreadable when recipients re-printed the letter to
        # PDF). Templates guard with ``{% if flow_filename %}``.
        "flow_filename": flow_filename,
        # Per-issuer freezable holdings — see docstring above.
        # Pre-rendered for the template via ``_build_issuer_freezable_ctx``
        # so the template doesn't have to know about freeze_brief.json
        # internals or compute explorer URLs.
        "issuer_freezable": _build_issuer_freezable_ctx(
            issuer_freezable, primary_case.chain,
        ),
        # Law-enforcement filing-route recommendation. Only the LE
        # template uses this; the issuer freeze letter ignores the
        # ``le_routing`` context key. Built from victim's state +
        # country + (approximate) total loss so the LE handoff names
        # specific filing channels (IC3 + state AG + escalation tiers).
        "le_routing": _build_le_routing_ctx(
            victim, theft_transfer.usd_value_at_tx,
        ),
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
    """The primary theft event — the highest-USD transfer in the
    drain cluster. Backward-compat wrapper around
    ``_find_theft_events``; returns the first (largest-by-USD) item.

    Most letter sections render this single transfer as the headline
    "Theft Event". Section 3 of the LE handoff additionally renders
    the full cluster from ``_find_theft_events`` when the drain
    spans multiple transactions.
    """
    events = _find_theft_events(case)
    return events[0] if events else None


def _find_theft_events(
    case: Case,
    *,
    time_window_hours: int = 168,
) -> list[Transfer]:
    """Find every transfer that looks like part of the drain.

    Real victims are often drained across multiple transactions —
    e.g., a phishing attack that approves a token's spender contract
    and then drains $X in piece-meal trades over hours, or a wallet
    that's slowly emptied as the perpetrator avoids triggering
    exchange-side monitoring thresholds. Before this function, the
    brief rendered ONE event (the biggest), implying a single
    theft; the letter prose said "$X was stolen on day Y", missing
    the actual story of "$X was stolen across N transactions on
    days Y through Y+3".

    Algorithm
    ---------

    1. Identify the largest-USD transfer in the case (the primary
       theft event). Same logic as the legacy single-event picker.
    2. Cluster around it: include every other transfer with
       ``block_time`` within ``time_window_hours`` of the primary
       event's block_time. The default window (168 hours / 7 days)
       is conservative — most drain campaigns wrap in under a week.
    3. Return the cluster ordered by block_time ascending (so the
       template can render them chronologically).

    Notes
    -----
    * Only outbound transfers from the seed (victim) address count
      as theft events. Internal-to-internal transfers (e.g., the
      perpetrator moving funds around) are part of the
      ``hops`` chain, not the theft events.
    * Returns the primary event first in the returned list (which
      may not be chronologically first), so callers reading
      ``events[0]`` get the headline. The chronological ordering is
      via ``sorted(events, key=block_time)`` if needed for the
      timeline render.
    * Empty list if no transfers at all in the case (wallet trace
      that returned nothing).

    Returns
    -------
    A list ordered with the primary event first, then all other
    events in the cluster sorted by block_time ascending. Empty
    list if no transfers in the case.
    """
    if not case.transfers:
        return []

    seed_lower = case.seed_address.lower()

    # Outbound transfers from the victim
    outbound = [
        t for t in case.transfers
        if t.from_address.lower() == seed_lower
    ]
    if not outbound:
        # Fallback: any transfer in the case (preserves legacy
        # behavior for cases where the seed_address normalization
        # diverges or the case has no direct-from-seed transfers).
        outbound = list(case.transfers)

    # Primary event: highest-USD with sensible fallback
    priced = [t for t in outbound if t.usd_value_at_tx is not None]
    if priced:
        primary = max(priced, key=lambda t: t.usd_value_at_tx)
    else:
        primary = max(outbound, key=lambda t: t.amount_decimal, default=None)
    if primary is None:
        return []

    # Cluster around the primary event's block_time
    from datetime import timedelta
    window = timedelta(hours=time_window_hours)
    primary_time = primary.block_time

    cluster = [
        t for t in outbound
        if abs(t.block_time - primary_time) <= window
        and t.transfer_id != primary.transfer_id
    ]

    # Sort cluster by block_time ascending; prepend primary so
    # callers reading [0] get the headline event consistently
    cluster.sort(key=lambda t: t.block_time)
    return [primary] + cluster


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

    # Each identified wallet carries an ``explorer_url`` so the
    # rendered table makes every address a click-through to its
    # on-chain page. We default the chain to the primary case's chain;
    # multi-chain support is a follow-up (would need per-row chain
    # tracking on the underlying transfers).
    primary_chain = primary.chain

    def _add(addr: str, role: str, type_str: str, notes: str, row_class: str = ""):
        key = addr.lower()
        if key in seen:
            # Don't downgrade — first observation wins for role/notes
            return
        seen[key] = {
            "address": addr, "role": role, "type": type_str,
            "notes": notes, "row_class": row_class,
            "explorer_url": _address_explorer_url(addr, primary_chain),
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


def _build_issuer_freezable_ctx(
    raw: dict | None, chain: Chain | str,
) -> dict | None:
    """Convert a freeze_brief.json FREEZABLE entry into the template-
    friendly shape the issuer_freeze_request template expects.

    Returns None if ``raw`` is None — the template falls back to the
    single-asset/single-holder rendering path in that case (legacy
    callers or wallet-trace runs that skip freeze letters entirely).

    Output shape:

      {
        "token":                "USDC",
        "freeze_capability":    "HIGH",
        "total_usd_freezable":  "$7,097.58",
        "total_usd_suspected":  "$1,037,451.35",
        "holdings": [
          {"address": "...",
           "address_short": "0xABC…1234",
           "explorer_url": "https://etherscan.io/...",
           "amount": "1066.27 USDC",
           "usd": "$1,066.27",
           "status": "FREEZABLE"},
          ...
        ],
        "freezable_holdings":   [...only status=FREEZABLE...],
        "investigate_holdings": [...only status=INVESTIGATE...],
        "has_freezable":        True,
        "has_investigate":      True,
        "freezable_count":      2,
        "investigate_count":    4,
        "total_count":          6,
      }

    The template uses these to drive Sections 4 + 5 of the letter,
    which under the old behavior listed a single "current_holder"
    holding the original theft asset (e.g., 130 ETH at the first
    hop). With per-issuer holdings threaded through, each issuer
    gets a letter asking for a hold on the SPECIFIC stablecoin
    addresses that issuer actually controls.
    """
    if not raw:
        return None
    holdings_in = raw.get("holdings") or []
    holdings_out: list[dict] = []
    n_historical = 0
    n_current = 0
    for h in holdings_in:
        addr = h.get("address", "")
        # v0.16.2 (audit fix #1): propagate evidence_type + observed_at
        # per-row so the issuer freeze letter template's section-4
        # Evidence column renders the right "current"/"historical" pill.
        # Pre-fix these were dropped here, making the v0.16.1 template
        # branches dead code — every letter fell through the {% else %}
        # clause and said "currently held" regardless of evidence type.
        ev_type = h.get("evidence_type", "current_balance")
        if ev_type == "historical_inflow":
            n_historical += 1
        else:
            n_current += 1
        holdings_out.append({
            "address": addr,
            "address_short": _short_addr(addr),
            "explorer_url": _address_explorer_url(addr, chain),
            "amount": h.get("amount", "—"),
            "usd": h.get("usd", "—"),
            "status": h.get("status", "INVESTIGATE"),
            "evidence_type": ev_type,
            "observed_at": h.get("observed_at"),
        })

    freezable = [h for h in holdings_out if h["status"] == "FREEZABLE"]
    investigate = [h for h in holdings_out if h["status"] == "INVESTIGATE"]

    # v0.16.2 (audit fix #1 cont.): aggregate evidence_mode. If raw
    # carries an explicit evidence_mode (set by emit_brief._extract_
    # freezable), prefer that; otherwise derive from the per-row counts
    # so this still works for skip_editorial fallback callers that
    # didn't populate the aggregate.
    explicit_mode = raw.get("evidence_mode")
    if explicit_mode in ("current_balance_only", "historical_only", "mixed"):
        evidence_mode = explicit_mode
    elif n_historical > 0 and n_current > 0:
        evidence_mode = "mixed"
    elif n_historical > 0:
        evidence_mode = "historical_only"
    else:
        evidence_mode = "current_balance_only"

    return {
        "token": raw.get("token") or "—",
        "freeze_capability": raw.get("freeze_capability") or "UNKNOWN",
        "total_usd_freezable": raw.get("total_usd") or "$0",
        "total_usd_suspected": raw.get("total_suspected_usd") or "$0",
        "holdings": holdings_out,
        "freezable_holdings": freezable,
        "investigate_holdings": investigate,
        "has_freezable": bool(freezable),
        "has_investigate": bool(investigate),
        "freezable_count": len(freezable),
        "investigate_count": len(investigate),
        "total_count": len(holdings_out),
        # v0.16.2: drive the issuer-letter evidence_mode branches.
        # Pre-fix these keys were absent, making the v0.16.1 template
        # template branches inert.
        "evidence_mode": evidence_mode,
        "historical_count": n_historical,
        "current_balance_count": n_current,
        "earliest_observed": raw.get("earliest_observed"),
    }


def _short_addr(addr: str) -> str:
    """Truncate hex addresses for inline display: 0xABCDEF…1234."""
    if not addr or len(addr) < 12:
        return addr or ""
    return f"{addr[:8]}…{addr[-4:]}"


def _build_le_routing_ctx(
    victim: VictimInfo,
    estimated_loss_usd: Decimal | None,
) -> dict[str, Any]:
    """Translate the structured LERoutingPlan into a template-friendly
    dict. The LE template iterates ``primary_routes``, ``state_routes``,
    and ``escalation_routes`` to generate the "Suggested Filing Routes"
    section.

    Loss-tier escalation thresholds are evaluated against
    ``estimated_loss_usd`` — which is the originally-stolen-asset's
    USD value at theft, as a reasonable approximation for routing
    decisions. This is NOT the freezable-USD total (which depends on
    the freeze_brief), because the routing decision needs to reflect
    the SCALE of the crime, not just the partial-recovery amount.
    """
    from recupero.worker._le_routing import recommend_le_routes

    plan = recommend_le_routes(
        state=victim.state,
        country=victim.country or victim.citizenship,
        total_loss_usd=estimated_loss_usd,
    )

    def _route_dict(route) -> dict[str, Any]:
        return {
            "name": route.name,
            "jurisdiction": route.jurisdiction,
            "url": route.url,
            "phone": route.phone,
            "email": route.email,
            "description": route.description,
            "expected_response": route.expected_response,
        }

    return {
        "has_routes": bool(
            plan.primary_routes or plan.state_routes or plan.escalation_routes
        ),
        "primary_routes":     [_route_dict(r) for r in plan.primary_routes],
        "state_routes":       [_route_dict(r) for r in plan.state_routes],
        "escalation_routes":  [_route_dict(r) for r in plan.escalation_routes],
        "notes":              list(plan.notes),
    }
