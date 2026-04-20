"""Trace traversal policies.

A policy answers two questions per transfer:
  1. Should we *include* this transfer in the case? (filter — dust, spoof, etc.)
  2. Should we *follow* this transfer to its destination as a new seed? (recursion)

The recursion answer is where the tool decides when to stop chasing money. Without
aggressive stop conditions a deep trace would explode — a single theft case has
fan-out of 10-50 counterparties per hop, so depth 3 unbounded is 125K+ transfers.

The default policy stops at:
  - labeled exchanges (off-ramp reached — terminal for the trace)
  - labeled mixers (funds obfuscated — flag and stop)
  - labeled bridges (cross-chain — we can't follow without a cross-chain adapter)
  - contract addresses (DeFi pools, routers, aggregators — usually not
    interesting to the theft narrative, and would explode the trace)
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from recupero.models import LabelCategory, Transfer


@dataclass
class TracePolicy:
    """Default policy."""

    max_depth: int = 1
    dust_threshold_usd: Decimal = Decimal("50")
    stop_at_exchange: bool = True
    stop_at_mixer: bool = True
    stop_at_bridge: bool = True
    # Whether to stop at destinations that are contract addresses. Defaults
    # True because most unlabeled contracts are DeFi routers / aggregators /
    # pools whose internal flow is not useful for theft tracing, and following
    # them explodes the trace. Override to False for specific investigations
    # where contract-internal flow matters (e.g., tracing through a vault).
    stop_at_contract: bool = True

    def should_include(self, transfer: Transfer) -> bool:
        """Filter: should this transfer appear in the case at all?"""
        if (
            transfer.usd_value_at_tx is not None
            and transfer.usd_value_at_tx < self.dust_threshold_usd
        ):
            return False
        return True

    def should_traverse(self, transfer: Transfer) -> bool:
        """Recursion: should we follow this transfer's destination as a new seed?

        Does NOT check is_contract — that requires an adapter call. The caller
        (tracer) does that check separately and passes its result via the
        destination_is_contract keyword if applicable.
        """
        if transfer.hop_depth + 1 >= self.max_depth:
            return False
        if transfer.counterparty.label is None:
            return True  # unlabeled — still investigate
        cat = transfer.counterparty.label.category
        if self.stop_at_exchange and cat in (
            LabelCategory.exchange_deposit,
            LabelCategory.exchange_hot_wallet,
        ):
            return False
        if self.stop_at_mixer and cat == LabelCategory.mixer:
            return False
        if self.stop_at_bridge and cat == LabelCategory.bridge:
            return False
        return True

    def should_traverse_address(self, *, is_contract: bool) -> bool:
        """Secondary check — applied per destination, independent of the
        transfer label. Returns True if the address is OK to traverse;
        False if it should be treated as terminal.
        """
        if self.stop_at_contract and is_contract:
            return False
        return True
