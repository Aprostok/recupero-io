# Data Model

Everything Recupero produces is a serialization of these objects. Implement them as Pydantic v2 models in `src/recupero/models.py`. Keep them strict — `extra="forbid"` on every model — so unexpected fields surface as bugs, not silent data corruption.

## Core models

### `Chain`
String enum:
- `ethereum`
- `solana` (Phase 3)
- `bitcoin` (later)
- `arbitrum` / `base` / `bsc` / `polygon` (later)

### `Address`
A typed wrapper around a string. For Ethereum, validates as a checksummed 20-byte hex address using `eth_utils.to_checksum_address`. For Solana later, validates as base58. The validator is per-chain.

Use `Address` everywhere instead of raw `str` so a Solana address never accidentally gets passed to Ethereum code.

### `TokenRef`
Identifies a specific asset on a specific chain.
```python
class TokenRef(BaseModel):
    chain: Chain
    contract: Address | None            # None for native asset (ETH on mainnet, SOL on Solana)
    symbol: str                          # "ETH", "USDT", etc. — display only
    decimals: int                        # 18 for ETH, 6 for USDT, etc.
    coingecko_id: str | None             # "ethereum", "tether", etc. — None if unmappable
```

### `LabelCategory`
String enum used to sort counterparties by what they mean to the investigation:
- `exchange_deposit` — CEX deposit address (FREEZE TARGET)
- `exchange_hot_wallet` — CEX hot wallet (LE may still act)
- `bridge` — cross-chain bridge contract
- `mixer` — Tornado Cash, etc.
- `defi_protocol` — Uniswap router, 1inch, etc.
- `staking` — staking contract
- `victim` — known victim wallet (for cross-case work)
- `perpetrator` — confirmed bad actor (cross-case)
- `unknown` — no match

### `Label`
```python
class Label(BaseModel):
    address: Address
    name: str                            # "MEXC Deposit", "DeBridge: Gate", etc.
    category: LabelCategory
    exchange: str | None                 # "MEXC", "Binance", etc. — for exchange_* categories
    source: str                          # "local_seed:cex_deposits.json", "etherscan_tag", "user:josh"
    confidence: Literal["high", "medium", "low"]
    notes: str | None
    added_at: datetime
```

### `Counterparty`
The "to" side of a transfer.
```python
class Counterparty(BaseModel):
    address: Address
    label: Label | None                  # None means unlabeled (still surfaces, flagged for review)
    is_contract: bool                    # determined from chain — contracts behave differently
    first_seen_at: datetime | None       # in this case
```

### `Transfer`
The atomic unit. One value-moving event on chain.
```python
class Transfer(BaseModel):
    # Identity
    transfer_id: str                     # synthetic: f"{chain}:{tx_hash}:{log_index_or_0}"
    chain: Chain
    tx_hash: str
    block_number: int
    block_time: datetime                 # UTC
    log_index: int | None                # None for native transfers; set for ERC-20 Transfer events

    # Movement
    from_address: Address
    to_address: Address
    counterparty: Counterparty           # mirrors to_address with label resolution
    token: TokenRef
    amount_raw: str                      # integer in token's smallest unit, as string (avoids float)
    amount_decimal: Decimal              # human-readable (amount_raw / 10**decimals)

    # Valuation
    usd_value_at_tx: Decimal | None      # null if no price available
    pricing_source: str | None           # "coingecko:ethereum:2025-01-15", etc.
    pricing_error: str | None            # set if usd_value_at_tx is null

    # Trace metadata
    hop_depth: int                       # 0 = direct from seed; 1 = hop 1; ...
    parent_transfer_id: str | None       # which transfer brought funds in (Phase 2+)

    # Provenance
    fetched_at: datetime                 # when WE fetched this from chain
    explorer_url: str                    # https://etherscan.io/tx/0x...
```

`amount_raw` is a string, not an int, because some chains have values exceeding 2^53 and we don't want JSON serialization to lose precision. `Decimal` for `amount_decimal` and `usd_value_at_tx` for the same reason — never floats for money.

### `Case`
The whole case in one object.
```python
class Case(BaseModel):
    case_id: str
    seed_address: Address
    chain: Chain
    incident_time: datetime              # UTC

    transfers: list[Transfer]

    # Aggregated views — computed, but stored for convenience
    exchange_endpoints: list[ExchangeEndpoint]   # computed from transfers
    unlabeled_counterparties: list[Address]      # for investigator review
    total_usd_out: Decimal | None

    # Run metadata (also written separately to manifest.json)
    config_used: dict
    software_version: str
    trace_started_at: datetime
    trace_completed_at: datetime
```

### `ExchangeEndpoint`
The freeze targets. Computed from transfers but materialized for fast lookup.
```python
class ExchangeEndpoint(BaseModel):
    address: Address
    exchange: str                        # "MEXC"
    label_name: str                      # "MEXC Deposit"
    transfer_ids: list[str]              # which transfers landed here
    total_received_usd: Decimal | None
    first_deposit_at: datetime
    last_deposit_at: datetime
```

### `EvidenceReceipt`
What gets written to `tx_evidence/<tx_hash>.json`. Not stored in `case.json` (too bulky); referenced by `tx_hash`.
```python
class EvidenceReceipt(BaseModel):
    chain: Chain
    tx_hash: str
    block_number: int
    block_time: datetime
    raw_transaction: dict                # exactly what the chain returned
    raw_receipt: dict
    raw_block_header: dict
    fetched_at: datetime                 # chain-of-custody
    fetched_from: str                    # "etherscan.io/v2/api"
    explorer_url: str
```

## On serialization

- Use `orjson` for performance and consistent decimal/datetime handling.
- Datetimes are always UTC, ISO-8601 with `Z` suffix.
- Decimals serialize as strings to preserve precision.
- Pydantic models all have `model_config = ConfigDict(extra="forbid", frozen=False)`.

## On versioning

`case.json` includes `schema_version: "1.0"` at the top level. When we change the schema, bump and write a migration. Don't edit existing case files in place.
