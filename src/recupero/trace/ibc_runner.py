"""IBC continuation-out leads (roadmap-v4 Tier-2 #8).

Activates ``ibc_decode`` over a finished Cosmos-zone trace: for each traced
wallet, fetch its outbound txs and decode every ICS-20 ``send_packet`` —
surfacing where funds LEFT the zone (destination chain + receiver + denom +
amount), the hop the BFS previously died at. The headline case: an
Osmosis → Noble USDC exit is Circle-freezable, so it is flagged as an
actionable freeze target.

Forensic posture: the decoded hop is a protocol FACT (the packet is on-chain),
so the "funds left to this receiver on the counterparty zone" claim is HIGH
confidence — the IBC analogue of a confirmed bridge send. The destination
CHAIN NAME is resolved from a pinned, verified channel registry (unknown
channels surface the hop with dest_chain=None, never guessed). Amounts are RAW
micro-units, never priced here. Leads are for review, never a followed
destination, and the recoverable total is unchanged.

Gated by ``RECUPERO_IBC_LEADS`` (default off) — one tx-by-sender LCD fetch per
traced wallet.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

from recupero.trace.ibc_decode import parse_ibc_sends
from recupero.trace.nft_runner import traced_wallets

log = logging.getLogger(__name__)

_MAX_WALLETS = 25
_MAX_LEADS_PER_WALLET = 50


def ibc_leads_enabled() -> bool:
    """Opt-in gate (RECUPERO_IBC_LEADS). Default off — one tx-by-sender LCD
    fetch per traced wallet."""
    return (os.environ.get("RECUPERO_IBC_LEADS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _resolve_zone_name(address: str) -> str | None:
    """The Cosmos zone name ("osmosis", "cosmos-hub", …) for a bech32 address,
    or None if the prefix isn't a known zone. Lazy import to keep the trace
    layer free of a hard cosmos-client dependency."""
    try:
        from recupero.chains.cosmos.client import resolve_zone
    except Exception:  # noqa: BLE001
        return None
    zi = resolve_zone(address)
    return zi.zone if zi is not None else None


def _normalize_tx_responses(raw: Any) -> list[dict[str, Any]]:
    """Coerce a client's tx-by-sender result to a flat list of tx_response
    dicts (handles both ``{"tx_responses": [...]}`` and a bare list)."""
    if isinstance(raw, dict):
        items = raw.get("tx_responses") or raw.get("txs") or []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    return [t for t in items if isinstance(t, dict)]


def run_ibc_leads(
    *,
    transfers: Iterable[Any],
    client: Any,
    force: bool = False,
) -> list[dict[str, Any]]:
    """For each traced Cosmos wallet, decode its outbound ICS-20 sends into
    continuation leads. ``client`` must expose
    ``fetch_all_txs_by_sender(address) -> {tx_responses|list}``. Opt-in:
    ``[]`` unless ``force`` or ``RECUPERO_IBC_LEADS``. Best-effort per wallet."""
    if not (force or ibc_leads_enabled()):
        return []
    fetch = getattr(client, "fetch_all_txs_by_sender", None)
    if not callable(fetch):
        return []
    leads: list[dict[str, Any]] = []
    for wallet in traced_wallets(transfers, max_wallets=_MAX_WALLETS):
        zone = _resolve_zone_name(wallet)
        if zone is None:
            continue  # not a recognized Cosmos zone → skip (never guess)
        try:
            raw = fetch(wallet)
        except Exception as exc:  # noqa: BLE001 — best-effort per wallet
            log.warning("ibc-leads: tx fetch failed wallet=%s: %s", wallet, exc)
            continue
        sends: list[Any] = []
        for tr in _normalize_tx_responses(raw):
            sends.extend(parse_ibc_sends(tr, src_zone=zone))
        # Defense-in-depth: only sends actually initiated by this wallet.
        sends = [s for s in sends if s.sender == wallet][:_MAX_LEADS_PER_WALLET]
        for s in sends:
            leads.append({
                "src_zone": s.src_zone,
                "dest_chain": s.dest_chain,         # None when channel unpinned
                "sender": s.sender,
                "receiver": s.receiver,
                "denom": s.denom,
                "base_denom": s.base_denom,
                "amount_raw": s.amount_raw,
                "src_channel": s.src_channel,
                "dst_channel": s.dst_channel,
                "sequence": s.sequence,
                "pair_id": list(s.pair_id),
                "is_circle_usdc": s.is_circle_usdc,
                "freezable_issuer": "Circle (USDC)" if s.is_circle_usdc else None,
                "tx_hash": s.tx_hash,
                "confidence": "high",   # the IBC packet is an on-chain protocol fact
                "basis": (
                    "ICS-20 send_packet: the traced wallet sent this denom OUT "
                    "of the zone via IBC to the receiver on the counterparty "
                    "chain. (src_channel, dst_channel, sequence) is the "
                    "protocol-native cross-chain id — confirmable end-to-end "
                    "against the destination zone's recv_packet."
                    + (" Base denom is Circle USDC — freezable at the issuer."
                       if s.is_circle_usdc else "")
                ),
            })
        if sends:
            log.info("ibc-leads: wallet %s (%s) — %d outbound IBC send(s)",
                     wallet, zone, len(sends))
    return leads


def leads_to_json(leads: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialize run_ibc_leads output to the ibc_leads.json artifact."""
    return {
        "kind": "recupero_ibc_leads",
        "disclaimer": (
            "IBC (ICS-20) continuation-out leads. Each is an on-chain "
            "send_packet — the funds provably LEFT the zone to the named "
            "receiver on the counterparty chain (HIGH confidence; the "
            "(src_channel, dst_channel, sequence) tuple confirms it end-to-end "
            "against the destination zone's recv_packet). The destination "
            "CHAIN NAME comes from a pinned, verified channel registry "
            "(unknown channels surface dest_chain=null, never guessed). "
            "Osmosis/Noble USDC exits are flagged Circle-freezable. Amounts "
            "are RAW micro-units, never priced here; leads are for review, "
            "never a followed destination, and the recoverable total is "
            "unchanged."
        ),
        "lead_count": len(leads),
        "leads": leads,
    }


__all__ = (
    "ibc_leads_enabled",
    "run_ibc_leads",
    "leads_to_json",
)
