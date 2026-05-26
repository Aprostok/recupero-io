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
    # v0.12.0: Tron mainnet (TRX + TRC-20). Critical for USDT
    # laundering cases — ~half of all USDT volume lives on Tron.
    tron = "tron"
    # Later
    bitcoin = "bitcoin"
    arbitrum = "arbitrum"
    base = "base"
    bsc = "bsc"
    polygon = "polygon"
    # v0.20.0 (round-13 type-MED-8): Hyperliquid was treated as the
    # raw string "hyperliquid" throughout the codebase (explorer maps,
    # adapter routing, watch_tick) but was missing from the Chain enum.
    # Pydantic models carrying `chain: Chain` would reject a hyperliquid
    # case row; the in-flight code-paths handled it via str comparisons
    # only. Adding the enum member closes the type-system gap.
    #
    # NB: Hyperliquid uses EVM-format addresses but isn't an EVM chain —
    # the scraper at `chains/hyperliquid/scraper.py` deliberately sets
    # `Case.chain = Chain.ethereum` (now upgradable to `Chain.hyperliquid`)
    # for downstream brief / freeze pipelines that haven't been wired
    # for the chain.
    hyperliquid = "hyperliquid"
    # v0.20.0 (round-13 chain-coverage research): additional EVM
    # chains. Each reuses the existing `chains/evm/adapter.py` via a
    # chainid wire-up in `worker/watch_tick._CHAIN_ID_BY_NAME` (so
    # the watch-tick + monitor-tick + trace paths all light up
    # without a new adapter). Etherscan API V2 multichain supports
    # all seven via the `chainid` query parameter.
    #
    # Priority per industry theft-volume reports (Chainalysis 2024-2025,
    # TRM Insights, PeckShield monthly):
    #   * optimism, avalanche      → CRIT (top-10 stolen-fund destinations)
    #   * linea, blast, zksync     → HIGH (active 2025 drainer destinations)
    #   * scroll, mantle           → MED (smaller but recurring)
    optimism = "optimism"
    avalanche = "avalanche"
    linea = "linea"
    blast = "blast"
    zksync = "zksync"
    scroll = "scroll"
    mantle = "mantle"
    # v0.29.0 (label-DB completeness audit): chains where the bridge
    # ingestor needs to recognize destinations even though we don't
    # yet have a full EVM adapter for them. The bridges.json now
    # carries Stargate / Wormhole / Hop pool routers on these
    # chains, and ingest_bridge_seeds would silently drop entries
    # whose chain value wasn't in the enum.
    #
    # No adapter coverage yet — these are "destination-only" chains:
    # if a Zigha-shape trace bridges OUT to fantom/celo/gnosis, we
    # surface the handoff (operator pursues via the destination
    # block explorer) but don't auto-continue the BFS. The Chain
    # enum membership is what makes the destination labelable.
    # Add the matching adapter in a later release if these become
    # frequent.
    fantom = "fantom"
    celo = "celo"
    gnosis = "gnosis"
    moonbeam = "moonbeam"
    metis = "metis"
    kava = "kava"


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
        """`amount_raw` must be a NON-NEGATIVE integer string.

        Pre-v0.16.7 the check was `v.lstrip("-").isdigit()`, which accepted
        strings like "-1234" — there is no on-chain native negative transfer,
        and a leading `-` is a smoking-gun for a parser bug (signed-int
        overflow misread, off-by-one in raw-bytes decoding). Permitting it
        meant downstream Decimal math silently SUBTRACTED from totals.
        Surfaced in the round-9 forensic audit.
        """
        if not v.isdigit():
            raise ValueError(
                f"amount_raw must be a non-negative integer string, got {v!r}"
            )
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
    # Forward-compatible: reads from older or newer pipelines ignore
    # fields they don't know about rather than raising. The inner
    # types (Transfer / Counterparty / TokenRef / Label) keep
    # extra="forbid" because their shapes are stable contracts —
    # we WANT to crash if those drift. Only the top-level Case
    # container evolves across pipeline versions; this `ignore`
    # lets a v0.13.x reader open a v0.16.x case (and vice versa)
    # without parse errors.
    model_config = ConfigDict(extra="ignore")

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
