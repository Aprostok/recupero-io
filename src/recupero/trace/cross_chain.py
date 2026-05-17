"""Cross-chain handoff detection (v0.8.1).

When a perpetrator-controlled address bridges funds to another
chain, the trace today can't follow the money past the bridge
contract — different RPC endpoint, different address space, no
unified state. But we CAN detect the handoff and surface it as
an investigation item the operator (or a government analyst)
can pick up manually.

This module:

  1. ``identify_cross_chain_handoffs(case)`` — scan a completed
     case for transfers whose ``to_address`` matches a known
     bridge contract in ``labels/seeds/bridges.json``. Returns
     one ``CrossChainHandoff`` per detected transfer with the
     bridge name, the source-side tx hash, and (when available)
     the destination chain inferred from the bridge's
     ``supports_to_chains`` metadata.

  2. ``ingest_bridge_seeds()`` — loads the bridges.json file and
     returns a dict[(chain, address)] → BridgeInfo. Used by the
     detector + by downstream label-aware analyzers.

The brief integration (in emit_brief.py) renders these as a new
``CROSS_CHAIN_HANDOFFS`` section the AI editorial picks up.
Each entry is structured + investigator-actionable: bridge name,
tx hash + explorer URL, source-chain amount in USD, destination-
chain candidate addresses (when we can parse the bridge's
calldata; otherwise null + a follow-up URL pointing at the
bridge's own explorer).

Government use-case framing:
  An FBI / IRS-CI analyst tracing stolen crypto needs to know
  "did the perpetrator move funds off this chain, and if so to
  where can I subpoena next?" The cross_chain_handoffs section
  gives them a structured handoff list they can hand to their
  cross-chain analyst (or to Chainalysis Reactor if they have a
  subscription). Without it, multi-chain cases bottleneck at
  the bridge contract.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.models import Address, Case, Chain, Transfer

log = logging.getLogger(__name__)


# Path to the bridges seed file. Lives next to the existing
# labels seed data so operators have one place to look for
# label / bridge / mixer / etc. updates.
_BRIDGES_SEED_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "bridges.json"
)


@dataclass(frozen=True)
class BridgeInfo:
    """Metadata about a known cross-chain bridge contract.

    ``supports_to_chains`` is a heuristic about which destination
    chains the bridge typically routes to. Used to populate the
    ``destination_chain_candidates`` field on a CrossChainHandoff
    even when we can't parse the actual calldata.
    """
    chain: Chain                  # source chain where the bridge contract lives
    address: str                  # lowercased contract address
    name: str                     # display name ("Wormhole: Token Bridge")
    protocol: str                 # protocol family ("Wormhole", "Stargate")
    confidence: str               # "high" | "medium" | "low"
    follow_up_url: str | None     # bridge's own explorer / refund portal
    supports_to_chains: tuple[str, ...]


@dataclass(frozen=True)
class CrossChainHandoff:
    """One detected handoff event. Surfaced in the brief.

    The shape is investigator-actionable: every field a
    downstream analyst needs to follow up is structured, not
    buried in prose. ``destination_chain_candidates`` is a tuple
    of chain identifiers the bridge typically routes to —
    operators can prioritize the ones with the most volume.
    """
    source_address: Address       # the perpetrator-controlled address that sent
    source_chain: Chain
    source_tx_hash: str
    source_explorer_url: str
    bridge_name: str
    bridge_protocol: str
    bridge_address: str
    amount_decimal: Decimal
    amount_usd: Decimal | None
    token_symbol: str
    block_time_iso: str
    follow_up_url: str | None
    destination_chain_candidates: tuple[str, ...]


def ingest_bridge_seeds(path: Path | None = None) -> dict[tuple[Chain, str], BridgeInfo]:
    """Load bridges.json + return ``{(chain, lowercased_address): BridgeInfo}``.

    Defensive against:
      * the v0.8.1 schema (flat array) — existing format
      * the original chain-aware schema if introduced later
      * malformed entries (skip + log warning)

    Operators can supply a custom path for testing / overrides.
    """
    src = path or _BRIDGES_SEED_PATH
    try:
        raw = json.loads(src.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001
        log.warning("bridges seed load failed (%s); cross-chain detection disabled", exc)
        return {}

    out: dict[tuple[Chain, str], BridgeInfo] = {}
    # Two shapes supported: flat array (current) or wrapped
    # object with "bridges" key (future schema bump).
    entries = raw if isinstance(raw, list) else raw.get("bridges", [])

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Skip section-marker dicts that don't have an address.
        addr = entry.get("address")
        if not isinstance(addr, str) or not addr.strip():
            continue
        # Default chain is ethereum (existing seed file is Ethereum-only).
        chain_str = (entry.get("chain") or "ethereum").lower()
        try:
            chain = Chain(chain_str)
        except (ValueError, KeyError):
            log.debug("bridges: skipping entry with unknown chain %s", chain_str)
            continue
        # supports_to_chains may be absent from v0.8.1's flat format.
        # Fall back to a generic "follow up via the bridge's explorer"
        # framing when missing.
        supports_raw = entry.get("supports_to_chains") or []
        supports = tuple(s.lower() for s in supports_raw if isinstance(s, str))

        info = BridgeInfo(
            chain=chain,
            address=addr.lower(),
            name=entry.get("name", "(unknown bridge)"),
            protocol=entry.get("protocol", entry.get("name", "(unknown)")),
            confidence=entry.get("confidence", "medium"),
            follow_up_url=entry.get("follow_up_url"),
            supports_to_chains=supports,
        )
        out[(chain, addr.lower())] = info

    log.debug("ingested %d bridge entries from %s", len(out), src)
    return out


def identify_cross_chain_handoffs(
    case: Case,
    bridge_db: dict[tuple[Chain, str], BridgeInfo] | None = None,
) -> list[CrossChainHandoff]:
    """Scan ``case.transfers`` for transfers that landed at a
    known bridge contract.

    Returns one ``CrossChainHandoff`` per detected transfer,
    sorted by ``amount_usd`` descending (largest first — investigator
    workflow priority).

    Defensive: returns ``[]`` if the bridge db can't be loaded.
    Never raises — failure to detect handoffs is a brief-quality
    issue, not a pipeline failure.
    """
    db = bridge_db if bridge_db is not None else ingest_bridge_seeds()
    if not db:
        return []

    handoffs: list[CrossChainHandoff] = []
    seen_keys: set[tuple[str, str]] = set()  # de-dup on (tx, bridge_addr)

    for t in case.transfers:
        bridge_addr = t.to_address.lower()
        key = (t.chain, bridge_addr)
        info = db.get(key)
        if info is None:
            continue

        dedup_key = (t.tx_hash, bridge_addr)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        handoffs.append(CrossChainHandoff(
            source_address=t.from_address,
            source_chain=t.chain,
            source_tx_hash=t.tx_hash,
            source_explorer_url=t.explorer_url,
            bridge_name=info.name,
            bridge_protocol=info.protocol,
            bridge_address=info.address,
            amount_decimal=t.amount_decimal,
            amount_usd=t.usd_value_at_tx,
            token_symbol=t.token.symbol,
            block_time_iso=t.block_time.isoformat().replace("+00:00", "Z"),
            follow_up_url=info.follow_up_url,
            destination_chain_candidates=info.supports_to_chains,
        ))

    handoffs.sort(
        key=lambda h: h.amount_usd if h.amount_usd is not None else Decimal("0"),
        reverse=True,
    )
    return handoffs


def handoffs_to_brief_section(
    handoffs: list[CrossChainHandoff],
) -> list[dict[str, Any]]:
    """Serialize handoffs into the dict shape the brief consumes.

    Each entry is investigator-actionable JSON suitable for both
    the editorial AI's prompt and the brief template. The
    structure is deliberately verbose — government analysts
    prefer explicit fields over compact representations.
    """
    out: list[dict[str, Any]] = []
    for h in handoffs:
        out.append({
            "source_chain": h.source_chain.value,
            "source_address": h.source_address,
            "tx_hash": h.source_tx_hash,
            "tx_explorer_url": h.source_explorer_url,
            "bridge_name": h.bridge_name,
            "bridge_protocol": h.bridge_protocol,
            "bridge_address": h.bridge_address,
            "amount_decimal": str(h.amount_decimal),
            "amount_usd": (
                f"${h.amount_usd:,.2f}" if h.amount_usd is not None else None
            ),
            "token_symbol": h.token_symbol,
            "block_time": h.block_time_iso,
            "follow_up_url": h.follow_up_url,
            "destination_chain_candidates": list(h.destination_chain_candidates),
            "investigator_note": _build_investigator_note(h),
        })
    return out


def _build_investigator_note(h: CrossChainHandoff) -> str:
    """One-line action item for a government / operator analyst.

    Reads like 'Bridged $X via <bridge> to candidate chains
    [<chains>]. Follow up at <follow_up_url> or query the
    destination chain for transfers received at this perpetrator's
    address near <block_time>.'
    """
    amount_str = (
        f"${h.amount_usd:,.2f} {h.token_symbol}"
        if h.amount_usd is not None
        else f"{h.amount_decimal} {h.token_symbol}"
    )
    chains_str = (
        ", ".join(h.destination_chain_candidates)
        if h.destination_chain_candidates
        else "(unknown — see bridge explorer)"
    )
    parts = [
        f"Bridged {amount_str} via {h.bridge_name} (source-chain "
        f"tx: {h.source_tx_hash[:14]}…).",
        f"Destination chain candidates: {chains_str}.",
    ]
    if h.follow_up_url:
        parts.append(f"Bridge's own tracking: {h.follow_up_url}.")
    parts.append(
        "Investigator: query the destination chain(s) for the "
        "perpetrator's known addresses at "
        f"{h.block_time_iso} ± a few blocks."
    )
    return " ".join(parts)


__all__ = (
    "BridgeInfo",
    "CrossChainHandoff",
    "ingest_bridge_seeds",
    "identify_cross_chain_handoffs",
    "handoffs_to_brief_section",
)
