"""Trace traversal policies.

Phase 1 only honors the dust threshold (handled in the tracer directly), but the
policy interface exists from day one so Phase 2's recursive tracer plugs in
without restructuring.

A policy answers two questions per transfer:
  1. Should we *include* this transfer in the case? (filter)
  2. Should we *follow* this transfer to its destination as a new seed? (recursion)

Phase 1 always answers (2) "no" because depth is fixed at 1.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from recupero.models import LabelCategory, Transfer


@dataclass
class TracePolicy:
    """Default policy. Phase 1 sets max_depth=1; recursion never happens."""

    max_depth: int = 1
    dust_threshold_usd: Decimal = Decimal("50")
    stop_at_exchange: bool = True
    stop_at_mixer: bool = True

    def should_include(self, transfer: Transfer) -> bool:
        """Filter: should this transfer appear in the case at all?"""
        if (
            transfer.usd_value_at_tx is not None
            and transfer.usd_value_at_tx < self.dust_threshold_usd
        ):
            return False
        return True

    def should_traverse(self, transfer: Transfer) -> bool:
        """Recursion: should we follow this transfer's destination as a new seed?"""
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
            return False  # mixer terminates trace; flag instead
        return True
