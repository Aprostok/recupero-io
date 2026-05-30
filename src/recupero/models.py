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
    # v0.29.0 added as label-only destination chains.
    # v0.31.0 PROMOTED to full adapter coverage: all 6 now route
    # through the EVM adapter via Etherscan V2 multichain (chainIDs
    # wired in `worker/watch_tick._CHAIN_ID_BY_NAME`). The BFS
    # auto-continues onto these chains when a bridge handoff resolves
    # there, instead of stopping at the bridge contract on the source
    # chain. Verified chainIDs: fantom 250, celo 42220, gnosis 100,
    # moonbeam 1284, metis 1088, kava 2222 (Etherscan V2 multichain).
    fantom = "fantom"
    celo = "celo"
    gnosis = "gnosis"
    moonbeam = "moonbeam"
    metis = "metis"
    kava = "kava"
    # v0.32.1 W5 (round-2 adversary Route 1' close-out): additional
    # rollup-canonical L2 destination chains. Each has a labeled
    # canonical bridge in bridges.json + a decoder dispatch in
    # bridge_calldata.py. Without these enum members the cross-chain
    # BFS continuation in tracer.py would fail to instantiate the
    # destination adapter and silently produce no continuation.
    #
    # NB: polygon_zkevm, opbnb, manta are LABEL-only destinations for
    # now (no full adapter via watch_tick). The Chain enum entry is
    # what bridges.json needs to be loaded WITHOUT being silently
    # dropped by the validator.
    polygon_zkevm = "polygon_zkevm"
    opbnb = "opbnb"
    manta = "manta"
    # v0.32.1+ (Cap-C): Cosmos / IBC chains. Minimal read-only
    # coverage via Mintscan / LCD endpoints. The enum entry is
    # shared by Cosmos Hub, Osmosis, Injective, etc. — the
    # CosmosAdapter dispatches per-zone via the address bech32
    # prefix (``cosmos1...``, ``osmo1...``, ``inj1...``).
    #
    # NOT YET wired into ChainAdapter.for_chain — the BFS does not
    # call into Cosmos until wave-7 integration. The enum entry
    # exists so Case / Transfer records can carry the chain
    # identifier without a Pydantic rejection.
    cosmos = "cosmos"


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
    # v0.32.1 (forensic-audit): decimals must be in [0, 255]. A NEGATIVE
    # value is a smoking-gun for a malformed RPC/label response, and it is
    # the exponent that scales raw on-chain integers into human amounts
    # (amount = raw / 10**decimals) — a negative would INFLATE the amount
    # by orders of magnitude, corrupting every USD figure derived from it.
    # The EVM/Tron adapters already clamp to [0, 255] at source; this is
    # the model-boundary backstop so a value reaching TokenRef any other
    # way (a hand-built seed, a future adapter) can't smuggle a negative
    # exponent into the loss math. 255 mirrors the adapter clamp ceiling
    # so it never rejects an adapter-produced value.
    decimals: int = Field(ge=0, le=255)
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
    # v0.31.2 (Gap #5 — point-in-time labels): optional validity window.
    # `added_at` alone gives "labeled forever after added_at" semantics;
    # populating these narrows that to "labeled only between
    # [valid_from, valid_until]". Default None preserves the original
    # forever-after-added_at behavior so existing seed files keep
    # working unchanged.
    #
    # Forensically: an address that was an "exchange deposit" today
    # may not have been one six months ago when the theft happened,
    # so a brief grounded in today's labels can mislabel historical
    # state. The trace-time lookup can now pass a point_in_time and
    # the store will skip labels whose window doesn't cover it.
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @field_validator("valid_until")
    @classmethod
    def _check_validity_window(
        cls, v: datetime | None, info: Any
    ) -> datetime | None:
        # Reject forensically-broken rows where the window closes before
        # it opens. A seed author writing valid_from=2024-12-31 +
        # valid_until=2024-01-01 has almost certainly swapped the dates,
        # and silently accepting it would produce a label that never
        # matches any point_in_time lookup.
        if v is None:
            return v
        valid_from = info.data.get("valid_from")
        if valid_from is not None and v < valid_from:
            raise ValueError(
                f"valid_until ({v.isoformat()}) must be >= valid_from "
                f"({valid_from.isoformat()}); the window cannot close "
                "before it opens"
            )
        return v


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

    @field_validator("amount_decimal", "usd_value_at_tx")
    @classmethod
    def _money_is_finite_nonnegative(cls, v: Decimal | None) -> Decimal | None:
        """`amount_decimal` and `usd_value_at_tx` must be finite and >= 0.

        Mirrors the `amount_raw` guard at the model boundary (the round-9
        audit closed the raw-string path; this closes the Decimal path that
        the rest of the pipeline actually does arithmetic on). Two failure
        modes this stops:

          * NEGATIVE — there is no on-chain negative transfer value; a
            leading `-` is a smoking-gun for a parser bug (signed-int
            overflow misread, off-by-one in raw-bytes decoding). Permitting
            it meant downstream Decimal sums silently SUBTRACTED from the
            loss total — a legally-consequential under-count.
          * NON-FINITE (NaN/Inf) — a price-feed or RPC glitch that, once it
            enters a Decimal column, poisons every aggregate it touches
            (total drained, per-asset, per-issuer recovery math) and renders
            "NaN"/"inf" into LE-facing deliverables. We have defense-in-depth
            downstream, but rejecting at construction is the real fix and
            makes the long-standing test-helper assumption (that the model
            rejects non-finite Decimals) finally true.

        `usd_value_at_tx` is optional, so `None` passes through untouched.
        """
        if v is None:
            return v
        if not v.is_finite():
            raise ValueError(
                f"monetary value must be a finite Decimal, got {v!r}"
            )
        if v < 0:
            raise ValueError(
                f"monetary value must be non-negative, got {v!r}"
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
    # v0.32.1 (trace-depth #2): behavioral classifications of UNLABELED
    # endpoints that a broader-activity diversity probe judged to be likely
    # exchange/service infrastructure (a subpoena lead the label DB missed).
    # Populated during the trace ONLY when RECUPERO_ENDPOINT_DIVERSITY_PROBE
    # is enabled; each entry is the EndpointClassification.as_dict() shape and
    # carries confidence "low"/"medium" (a behavioral inference, never proof).
    # Kept separate from exchange_endpoints so an inferred lead is never
    # conflated with a label-DB-confirmed endpoint.
    inferred_infrastructure_endpoints: list[dict[str, Any]] = Field(
        default_factory=list
    )

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
