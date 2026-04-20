# Trace Algorithm (Phase 1)

Pseudocode that the implementation in `src/recupero/trace/tracer.py` should follow. Phase 1 is single-hop; the structure here anticipates Phase 2's recursion so we don't have to rewrite.

## Entry point

```python
def run_trace(
    chain: Chain,
    seed_address: Address,
    incident_time: datetime,
    case_id: str,
    config: TraceConfig,
) -> Case:
    adapter = ChainAdapter.for_chain(chain, config)
    label_store = LabelStore.load(config)
    price_client = PriceClient(config)

    case = Case(
        case_id=case_id,
        seed_address=seed_address,
        chain=chain,
        incident_time=incident_time,
        transfers=[],
        exchange_endpoints=[],
        unlabeled_counterparties=[],
        total_usd_out=None,
        config_used=config.model_dump(),
        software_version=__version__,
        trace_started_at=utcnow(),
        trace_completed_at=None,  # set at end
    )

    # Phase 1: single hop only. Phase 2 will replace with recursion.
    transfers = trace_one_hop(
        adapter=adapter,
        label_store=label_store,
        price_client=price_client,
        from_address=seed_address,
        incident_time=incident_time,
        config=config,
        hop_depth=0,
        parent_transfer_id=None,
    )
    case.transfers = transfers

    case.exchange_endpoints = compute_exchange_endpoints(transfers)
    case.unlabeled_counterparties = collect_unlabeled(transfers)
    case.total_usd_out = sum_usd(transfers)
    case.trace_completed_at = utcnow()

    return case
```

## One-hop traversal

```python
def trace_one_hop(
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: PriceClient,
    from_address: Address,
    incident_time: datetime,
    config: TraceConfig,
    hop_depth: int,
    parent_transfer_id: str | None,
) -> list[Transfer]:
    start_time = incident_time - timedelta(minutes=config.trace.incident_buffer_minutes)
    start_block = adapter.block_at_or_before(start_time)

    raw_outflows = []
    raw_outflows.extend(adapter.fetch_native_outflows(from_address, start_block))
    raw_outflows.extend(adapter.fetch_erc20_outflows(from_address, start_block))

    # Cap to avoid runaway on chatty addresses
    raw_outflows = raw_outflows[: config.trace.max_transfers_per_address]

    transfers: list[Transfer] = []
    for raw in raw_outflows:
        transfer = build_transfer(raw, hop_depth, parent_transfer_id)

        # Pricing
        price_result = price_client.price_at(transfer.token, transfer.block_time)
        transfer.usd_value_at_tx = price_result.usd_value
        transfer.pricing_source = price_result.source
        transfer.pricing_error = price_result.error

        # Dust filter (post-pricing — we need USD value to filter)
        if (
            transfer.usd_value_at_tx is not None
            and transfer.usd_value_at_tx < config.trace.dust_threshold_usd
        ):
            log.debug("skipping dust transfer", tx_hash=transfer.tx_hash, usd=transfer.usd_value_at_tx)
            continue

        # Label resolution
        label = label_store.lookup(transfer.to_address, chain=adapter.chain)
        is_contract = adapter.is_contract(transfer.to_address)
        transfer.counterparty = Counterparty(
            address=transfer.to_address,
            label=label,
            is_contract=is_contract,
            first_seen_at=transfer.block_time,
        )

        transfers.append(transfer)

        # Write evidence receipt to disk immediately so partial failures still
        # leave us with the artifacts we did fetch.
        write_evidence_receipt(adapter, transfer)

    return transfers
```

## Building a Transfer from raw chain data

```python
def build_transfer(raw, hop_depth, parent_transfer_id) -> Transfer:
    # raw is a normalized dict produced by the chain adapter
    # — adapter handles the differences between native and ERC-20
    return Transfer(
        transfer_id=f"{raw['chain']}:{raw['tx_hash']}:{raw.get('log_index') or 0}",
        chain=raw["chain"],
        tx_hash=raw["tx_hash"],
        block_number=raw["block_number"],
        block_time=raw["block_time"],
        log_index=raw.get("log_index"),
        from_address=raw["from"],
        to_address=raw["to"],
        counterparty=Counterparty(address=raw["to"], label=None, is_contract=False, first_seen_at=None),
        token=raw["token"],
        amount_raw=str(raw["amount_raw"]),
        amount_decimal=Decimal(raw["amount_raw"]) / Decimal(10 ** raw["token"].decimals),
        usd_value_at_tx=None,        # filled by pricing step
        pricing_source=None,
        pricing_error=None,
        hop_depth=hop_depth,
        parent_transfer_id=parent_transfer_id,
        fetched_at=utcnow(),
        explorer_url=raw["explorer_url"],
    )
```

## Computing exchange endpoints

```python
def compute_exchange_endpoints(transfers: list[Transfer]) -> list[ExchangeEndpoint]:
    by_address: dict[Address, list[Transfer]] = defaultdict(list)
    for t in transfers:
        if t.counterparty.label and t.counterparty.label.category == LabelCategory.exchange_deposit:
            by_address[t.to_address].append(t)

    endpoints = []
    for address, ts in by_address.items():
        label = ts[0].counterparty.label
        endpoints.append(ExchangeEndpoint(
            address=address,
            exchange=label.exchange,
            label_name=label.name,
            transfer_ids=[t.transfer_id for t in ts],
            total_received_usd=sum_usd(ts),
            first_deposit_at=min(t.block_time for t in ts),
            last_deposit_at=max(t.block_time for t in ts),
        ))
    # Sort by USD desc — biggest freeze targets first
    endpoints.sort(key=lambda e: e.total_received_usd or Decimal(0), reverse=True)
    return endpoints
```

## Phase 2 hook (do NOT implement in Phase 1, but design for it)

When we add multi-hop, `trace_one_hop` will be called recursively. The recursion needs:
- A `visited: set[Address]` to prevent cycles
- A `policy.should_traverse(transfer) -> bool` returning False on exchange/mixer/dust/depth-exceeded
- A `policy.next_seeds(transfer) -> list[Address]` — usually `[transfer.to_address]` but bridge-aware later

Sketch the policy interface in `src/recupero/trace/policies.py` even in Phase 1. Single method signature, default implementation that says "yes traverse, depth limit only" — Phase 2 swaps in the real policy without touching the tracer.

## Logging

Every meaningful step writes a structured log line at INFO level. At minimum:
- Trace started: case_id, seed, chain, incident_time, config summary
- Each fetch: address, kind (native/erc20), block range, num_results
- Each transfer kept: tx_hash, to, amount, usd, label
- Each transfer skipped: tx_hash, reason (dust/no_price/etc.)
- Trace completed: total transfers, total USD, num exchange endpoints, duration

Logs go to `data/cases/<case_id>/logs/trace.log` AND stdout (rich-formatted).

## Error handling

- Network failures on Etherscan: retry with exponential backoff via `tenacity` (max 5 retries, 1s→32s).
- Rate limit (HTTP 429): wait per `Retry-After` header, then retry.
- Permanent errors (404 on a tx, malformed response): log loudly, write a `pricing_error`-style placeholder, continue. Never silently drop.
- Pricing failures: do not abort the trace. Mark `usd_value_at_tx=None` and continue.

The principle: **partial output is more useful than no output.** A trace that fetched 80% of transfers is still actionable. Always write what we have to disk before raising.
