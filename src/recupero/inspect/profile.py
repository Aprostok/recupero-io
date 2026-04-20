"""Pydantic model for an address profile."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict

from recupero.models import Address, Chain, Label


class CounterpartyStat(BaseModel):
    """One row in the 'top counterparties' table."""

    model_config = ConfigDict(extra="forbid")

    address: Address
    tx_count: int                      # how many txs we saw between us and them in the inspection window
    label: Label | None = None         # if known to our label store
    is_contract: bool | None = None    # filled if cheap to determine; None if not checked


class AddressProfile(BaseModel):
    """Quick on-chain profile of an address.

    All fields are best-effort. If a chain query fails or returns no data,
    the corresponding field is None — never raise, never guess.
    """

    model_config = ConfigDict(extra="forbid")

    address: Address
    chain: Chain

    # What is it?
    is_contract: bool
    contract_name: str | None = None        # if verified contract, e.g. "AggregationRouterV6"
    contract_proxy: bool = False            # is it a proxy?
    existing_label: Label | None = None     # match in our label store

    # When/how active?
    first_seen_block: int | None = None
    first_seen_at: datetime | None = None
    last_seen_block: int | None = None
    last_seen_at: datetime | None = None
    observed_tx_count: int = 0              # what we counted in the inspection window
    observed_tx_count_capped: bool = False  # True if we hit the API page cap (real count >= observed)

    # Current state
    eth_balance_wei: int | None = None
    eth_balance: Decimal | None = None      # wei / 1e18

    # Counterparty analysis (top 5 by tx count in the inspection window)
    top_counterparties: list[CounterpartyStat] = []

    # Best-guess identity (heuristic, low confidence — UI should label as such)
    likely_identity: str | None = None
    likely_identity_reason: str | None = None  # short prose explanation

    # Provenance
    inspected_at: datetime
    explorer_url: str
    inspection_window_size: int             # how many txs we pulled (1000 default, 10000 deep)
