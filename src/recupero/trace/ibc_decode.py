"""IBC (ICS-20) cross-chain transfer decoder (roadmap-v4 Tier-2 #8).

The gap this closes: the BFS reaches + follows funds ON a Cosmos zone, but
dies at the first IBC hop OUT of the zone — so an Osmosis → Noble USDC route
(Circle-freezable) or Osmosis → Cosmos Hub hop simply vanished from the trace.

Every ICS-20 transfer emits a Tendermint ``send_packet`` event (outbound, on
the source zone) and a matching ``recv_packet`` on the destination zone. Both
carry the protocol-native cross-chain identity:

  ``packet_src_channel`` / ``packet_dst_channel`` / ``packet_sequence`` /
  ``packet_src_port`` / ``packet_dst_port``

and a ``packet_data`` JSON blob ``{sender, receiver, denom, amount}``. The
``(src_channel, dst_channel, sequence)`` tuple is identical on both zones —
so it is the IBC analogue of a bridge order-id, the only place an IBC edge may
legitimately be confirmed at HIGH confidence (protocol identity, not
inference). This module extracts that from a tx's events.

The event attribute shape, the ``packet_data`` keys, and the Osmosis channel
mappings below are LIVE-VERIFIED (2026-06) against real Osmosis LCD txs — e.g.
send_packet src_channel-750 -> dst_channel-1 seq 1222175 carrying
``transfer/channel-750/uusdc`` from ``osmo1...`` to ``noble1...`` (a real
Circle-freezable USDC exit).

Forensic posture: the decoded hop (sender/receiver/denom/amount/channels) is a
protocol FACT. The destination CHAIN NAME comes from a pinned channel registry
(channels can be reconfigured) — known channel = high, unknown = the hop is
still surfaced with ``dest_chain=None`` and the raw dst_channel. Nothing is
fabricated; malformed events are skipped.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Pinned (source-zone, source-channel) -> destination chain. Every entry
# LIVE-VERIFIED (2026-06) against a real send/recv packet on Osmosis LCD.
# Channels CAN be reconfigured by governance — re-verify periodically; an
# unknown channel degrades safely to dest_chain=None (hop still surfaced).
IBC_CHANNEL_REGISTRY: dict[tuple[str, str], str] = {
    ("osmosis", "channel-0"): "cosmoshub",   # Osmosis -> Cosmos Hub (verified)
    ("osmosis", "channel-750"): "noble",     # Osmosis -> Noble (USDC) (verified)
}

# Denoms whose base unit is a Circle-issued, freezable stablecoin. Surfaced so
# an Osmosis/Noble USDC IBC exit is flagged as an actionable freeze target
# (Circle can freeze USDC at the issuer level).
_CIRCLE_USDC_BASE_DENOMS = frozenset({"uusdc"})

# ICS-20 denom trace: zero or more leading "port/channel/" hops then the base
# denom, e.g. "transfer/channel-750/uusdc" -> base "uusdc".
_IBC_DENOM_HOP_RE = re.compile(r"^(?:[a-z0-9.\-]+/channel-\d+/)+")


@dataclass(frozen=True)
class IBCSend:
    """One outbound ICS-20 transfer leaving a zone (a ``send_packet``).

    ``dest_chain`` is the registry-resolved counterparty zone (None when the
    channel isn't pinned). ``pair_id`` = (src_channel, dst_channel, sequence) is
    the protocol-native cross-chain identity, identical on the dest zone's
    ``recv_packet`` — usable to confirm the hop end-to-end at HIGH confidence."""
    sender: str
    receiver: str
    denom: str               # full ICS-20 path as emitted
    base_denom: str          # path stripped
    amount_raw: str          # integer micro-units, verbatim
    src_port: str
    src_channel: str
    dst_port: str
    dst_channel: str
    sequence: str
    src_zone: str | None
    dest_chain: str | None
    is_circle_usdc: bool
    tx_hash: str

    @property
    def pair_id(self) -> tuple[str, str, str]:
        return (self.src_channel, self.dst_channel, self.sequence)


def strip_ibc_denom(denom: str) -> str:
    """Return the base denom of an ICS-20 denom trace (strip leading
    ``port/channel-N/`` hops). ``transfer/channel-750/uusdc`` -> ``uusdc``;
    a bare ``uosmo`` is returned unchanged."""
    if not isinstance(denom, str) or not denom:
        return ""
    return _IBC_DENOM_HOP_RE.sub("", denom)


def _attrs(event: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for a in event.get("attributes") or []:
        k = a.get("key")
        v = a.get("value")
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out


def parse_ibc_sends(
    tx_response: dict[str, Any], *, src_zone: str | None = None
) -> list[IBCSend]:
    """Extract outbound ICS-20 transfers (``send_packet`` events) from one LCD
    ``tx_response``. Malformed packets are skipped, never repaired. ``src_zone``
    (the queried wallet's zone, e.g. "osmosis") drives channel->chain lookup."""
    if not isinstance(tx_response, dict):
        return []
    txh = str(tx_response.get("txhash") or tx_response.get("txHash") or "")
    out: list[IBCSend] = []
    for ev in tx_response.get("events") or []:
        if not isinstance(ev, dict) or ev.get("type") != "send_packet":
            continue
        at = _attrs(ev)
        if at.get("packet_src_port") != "transfer":
            continue  # only ICS-20 fungible-token transfers
        raw = at.get("packet_data")
        if not raw:
            continue
        try:
            pd = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if not isinstance(pd, dict):
            continue
        sender = str(pd.get("sender") or "")
        receiver = str(pd.get("receiver") or "")
        denom = str(pd.get("denom") or "")
        amount = str(pd.get("amount") or "")
        if not (sender and receiver and denom and amount):
            continue
        # Raw micro-unit integer; skip non-numeric and zero-value (no-op/spam).
        if not amount.isdigit() or int(amount) == 0:
            continue
        src_channel = at.get("packet_src_channel") or ""
        dst_channel = at.get("packet_dst_channel") or ""
        base = strip_ibc_denom(denom)
        dest_chain = None
        if src_zone:
            dest_chain = IBC_CHANNEL_REGISTRY.get((src_zone, src_channel))
        out.append(IBCSend(
            sender=sender,
            receiver=receiver,
            denom=denom,
            base_denom=base,
            amount_raw=amount,
            src_port=at.get("packet_src_port") or "transfer",
            src_channel=src_channel,
            dst_port=at.get("packet_dst_port") or "transfer",
            dst_channel=dst_channel,
            sequence=at.get("packet_sequence") or "",
            src_zone=src_zone,
            dest_chain=dest_chain,
            is_circle_usdc=base in _CIRCLE_USDC_BASE_DENOMS,
            tx_hash=txh,
        ))
    return out


__all__ = (
    "IBC_CHANNEL_REGISTRY",
    "IBCSend",
    "strip_ibc_denom",
    "parse_ibc_sends",
)
