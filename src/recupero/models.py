"""Recupero data models.

The single source of truth for what a Case, Transfer, Counterparty, etc. look like.
Everything serialized to disk (case.json, evidence receipts, CSV) is derived from these.

Design rules:
  * Use Pydantic v2 with extra="forbid" everywhere.
  * Money values are Decimal, not float. Raw chain amounts are str (preserves precision).
  * Datetimes are always UTC, ISO-8601 with Z suffix on serialization.
  * Address validation is per-chain; never accept raw strings outside Address.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# -- pin schema version. Bump on any breaking change to case.json layout. --
SCHEMA_VERSION = "1.0"


# ----- Enums ----- #


class Chain(str, Enum):
    ethereum = "ethereum"
    # Phase 3+
    solana = "solana"
    # Later
    bitcoin = "bitcoin"
    arbitrum = "arbitrum"
    base = "base"
    bsc = "bsc"
    polygon = "polygon"


class LabelCategory(str, Enum):
    exchange_deposit = "exchange_deposit"
    exchange_hot_wallet = "exchange_hot_wallet"
    bridge = "bridge"
    mixer = "mixer"
    defi_protocol = "defi_protocol"
    staking = "staking"
    victim = "victim"
    perpetrator = "perpetrator"
    unknown = "unknown"


# ----- Address (per-chain validated) ----- #
# We use a string type with a validator. For Ethereum, normalize to checksum.
# For Solana later, base58-validate. The validator dispatches on chain context,
# but since we don't always have chain at parse time, accept either; chain-aware
# normalization is enforced in the adapter on construction.


Address = Annotated[str, Field(description="Chain-specific address. EVM: checksum hex.")]


# ----- Token reference ----- #


class TokenRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain: Chain
    contract: Address | None = None  # None => native asset (ETH on mainnet)
    symbol: str
    decimals: int
    coingecko_id: str | None = None


# ----- Labels & counterparties ----- #


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: Address
    name: str
    category: LabelCategory
    exchange: str | None = None
    source: str  # provenance: where this label came from
    confidence: Literal["high", "medium", "low"] = "medium"
    notes: str | None = None
    added_at: datetime


class Counterparty(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: Address
    label: Label | None = None
    is_contract: bool = False
    first_seen_at: datetime | None = None


# ----- Transfer ----- #


class Transfer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Identity
    transfer_id: str
    chain: Chain
    tx_hash: str
    block_number: int
    block_time: datetime
    log_index: int | None = None

    # Movement
    from_address: Address
    to_address: Address
    counterparty: Counterparty
    token: TokenRef
    amount_raw: str  # integer in smallest unit, as string
    amount_decimal: Decimal

    # Valuation
    usd_value_at_tx: Decimal | None = None
    pricing_source: str | None = None
    pricing_error: str | None = None

    # Trace metadata
    hop_depth: int = 0
    parent_transfer_id: str | None = None

    # Provenance
    fetched_at: datetime
    explorer_url: str

    @field_validator("amount_raw")
    @classmethod
    def _amount_raw_is_int_string(cls, v: str) -> str:
        # Must parse as a non-negative integer
        if not v.lstrip("-").isdigit():
            raise ValueError(f"amount_raw must be an integer string, got {v!r}")
        return v


# ----- Aggregations ----- #


class ExchangeEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: Address
    exchange: str
    label_name: str
    transfer_ids: list[str]
    total_received_usd: Decimal | None = None
    first_deposit_at: datetime
    last_deposit_at: datetime


# ----- Case ----- #


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    case_id: str
    seed_address: Address
    chain: Chain
    incident_time: datetime

    transfers: list[Transfer] = Field(default_factory=list)
    exchange_endpoints: list[ExchangeEndpoint] = Field(default_factory=list)
    unlabeled_counterparties: list[Address] = Field(default_factory=list)
    total_usd_out: Decimal | None = None

    # Run metadata (mirrored to manifest.json for easy access)
    config_used: dict[str, Any] = Field(default_factory=dict)
    software_version: str = ""
    trace_started_at: datetime
    trace_completed_at: datetime | None = None


# ----- Evidence receipts (written separately, not embedded in Case) ----- #


class EvidenceReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain: Chain
    tx_hash: str
    block_number: int
    block_time: datetime
    raw_transaction: dict[str, Any]
    raw_receipt: dict[str, Any]
    raw_block_header: dict[str, Any]
    fetched_at: datetime
    fetched_from: str  # e.g. "etherscan.io/v2/api"
    explorer_url: str
