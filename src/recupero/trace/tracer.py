"""Trace orchestrator.

Implements the algorithm described in docs/TRACE_ALGORITHM.md. Phase 1: single hop.
Phase 2 will add recursion, cycle detection, and policy-driven traversal — leave
the structure friendly to that.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from eth_utils import to_checksum_address

from recupero import __version__
from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.labels.store import LabelStore
from recupero.models import (
    Address,
    Case,
    Chain,
    Counterparty,
    ExchangeEndpoint,
    LabelCategory,
    Transfer,
)
from recupero.pricing.coingecko import CoinGeckoClient
from recupero.trace.evidence import write_evidence_receipt
from recupero.trace.policies import TracePolicy

log = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC)


_EVM_CHAINS: frozenset[Chain] = frozenset({
    Chain.ethereum,
    Chain.arbitrum,
    Chain.bsc,
    Chain.base,
    Chain.polygon,
})


def _is_evm_chain(chain: Chain) -> bool:
    """True if the chain uses EVM hex addresses (case-insensitive)."""
    return chain in _EVM_CHAINS


def _normalize_address(chain: Chain, address: Address) -> Address:
    """Normalize per-chain. EVM chains use checksum; Solana/Tron/Bitcoin pass through."""
    if _is_evm_chain(chain):
        return to_checksum_address(address)
    return address


def _address_visited_key(chain: Chain, address: Address) -> str:
    """Stable key for the BFS `visited` set and per-address caches.

    EVM addresses are case-insensitive — lowercased for dedup. Solana,
    Tron, and Bitcoin are base58/base58check, which IS case-sensitive;
    lowercasing those mangles the address (e.g. two distinct Solana
    mints whose lowercase forms collide get merged, and a mixed-case
    address pasted by an operator never matches the canonical form
    returned by Helius/TronGrid).

    v0.16.6 and earlier used `address.lower()` everywhere — this was
    the CRITICAL forensic-correctness bug surfaced in the round-9
    audit: every non-EVM trace silently de-duped against the wrong
    keys, occasionally dropping legitimate destinations.
    """
    if _is_evm_chain(chain):
        return address.lower()
    return address  # preserve case for base58 chains


def run_trace(
    *,
    chain: Chain,
    seed_address: Address,
    incident_time: datetime,
    case_id: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    case_dir: Path,
) -> Case:
    """End-to-end trace. Writes evidence receipts as it goes; caller writes case.json.

    When ``config.trace.max_depth`` > 1 this performs a BFS recursive trace:
    for each transfer returned from the seed, if the destination is eligible
    per the policy (labeled-exchange/mixer/bridge check, contract check, dust
    threshold, depth limit), the destination is enqueued as a new seed and
    re-traced. Cycle detection via a visited-addresses set.
    """
    if incident_time.tzinfo is None:
        incident_time = incident_time.replace(tzinfo=UTC)
    seed_address = _normalize_address(chain, seed_address)

    adapter = ChainAdapter.for_chain(chain, (config, env))
    label_store = LabelStore.load(config)
    cache_dir = Path(config.storage.data_dir) / "prices_cache"
    price_client = CoinGeckoClient(config, env, cache_dir)
    policy = TracePolicy(
        max_depth=config.trace.max_depth,
        dust_threshold_usd=Decimal(str(config.trace.dust_threshold_usd)),
        stop_at_exchange=config.trace.stop_at_exchange,
    )
    # Override stop_at_contract / stop_at_bridge / service_wallet threshold
    # from config if set there; otherwise keep the policy defaults.
    if hasattr(config.trace, "stop_at_contract"):
        policy.stop_at_contract = config.trace.stop_at_contract
    if hasattr(config.trace, "stop_at_bridge"):
        policy.stop_at_bridge = config.trace.stop_at_bridge
    if hasattr(config.trace, "service_wallet_outflow_threshold"):
        policy.service_wallet_outflow_threshold = (
            config.trace.service_wallet_outflow_threshold
        )

    started = utcnow()
    log.info(
        "trace start case=%s chain=%s seed=%s incident=%s max_depth=%d",
        case_id, chain.value, seed_address, incident_time.isoformat(), policy.max_depth,
    )

    case = Case(
        case_id=case_id,
        seed_address=seed_address,
        chain=chain,
        incident_time=incident_time,
        config_used=config.model_dump(),
        software_version=__version__,
        trace_started_at=started,
    )

    # --- Recursive BFS driver (wave-based, optionally parallel) ---
    # We process BFS one depth-wave at a time. Within a wave, addresses
    # are independent (no shared state mutated by their _trace_one_hop
    # calls beyond thread-safe rate-limiter / cache hits), so we fan
    # them out to a ThreadPoolExecutor. Between waves, the main thread
    # serially aggregates results and decides the next wave's contents,
    # so visited / is_contract_cache mutations don't need locks.
    #
    # Concurrency is configurable via RECUPERO_TRACE_CONCURRENCY (default 5).
    # The EtherscanClient + CoinGeckoClient rate-limiters globally cap
    # actual throughput, so higher thread counts give diminishing returns
    # once the rate limit is the bottleneck. 5 is conservative and lets
    # network latency be hidden behind in-flight requests.
    trace_concurrency = max(1, int(os.environ.get("RECUPERO_TRACE_CONCURRENCY", "5")))

    all_transfers: list[Transfer] = []
    # Chain-aware key: EVM lowercases, base58 (Solana/Tron/Bitcoin) preserves
    # case. See _address_visited_key for why this matters.
    visited: set[str] = {_address_visited_key(chain, seed_address)}  # includes queued-but-not-yet-processed
    is_contract_cache: dict[str, bool] = {}
    current_wave: list[tuple[Address, int]] = [(seed_address, 0)]
    addresses_processed = 0
    wave_number = 0

    while current_wave:
        wave_number += 1
        wave_size = len(current_wave)
        log.info(
            "wave #%d: %d address(es) at depth %d",
            wave_number, wave_size, current_wave[0][1],
        )
        next_wave: list[tuple[Address, int]] = []

        # --- Process current wave (parallel or serial) ---
        # Returns list of (from_address, depth, transfers, is_service_wallet).
        # Errors from a single address don't fail the wave — the worker
        # function catches and returns ([], False) so the rest of the
        # wave's work isn't wasted.
        wave_results = _process_wave(
            current_wave,
            adapter=adapter,
            label_store=label_store,
            price_client=price_client,
            policy=policy,
            incident_time=incident_time,
            config=config,
            evidence_dir=case_dir / "tx_evidence",
            concurrency=trace_concurrency,
        )

        # --- Aggregate results + build next wave (single-threaded) ---
        for from_addr, depth, hop_transfers, is_service_wallet in wave_results:
            addresses_processed += 1
            all_transfers.extend(hop_transfers)

            if depth + 1 >= policy.max_depth:
                continue

            # Service-wallet cap: keep the transfers we observed (audit
            # trail) but don't queue downstream. Without this, a single
            # 500-outflow OTC desk / unlabeled exchange explodes BFS at
            # the next depth.
            if is_service_wallet:
                log.info(
                    "service-wallet skip: not queueing %d destinations from %s",
                    len(hop_transfers), from_addr,
                )
                continue

            for transfer in hop_transfers:
                if not policy.should_traverse(transfer):
                    continue
                dest = transfer.to_address
                dest_key = _address_visited_key(chain, dest)
                if dest_key in visited:
                    continue

                # Contract check: one RPC per unique address, cached.
                # Done here (single-threaded between waves) so we don't
                # need to lock is_contract_cache.
                if policy.stop_at_contract:
                    if dest_key not in is_contract_cache:
                        try:
                            is_contract_cache[dest_key] = adapter.is_contract(dest)
                        except Exception as e:  # noqa: BLE001
                            log.debug("is_contract check failed for %s: %s", dest, e)
                            # Be conservative: if we can't check, assume contract (skip)
                            is_contract_cache[dest_key] = True
                    if is_contract_cache[dest_key]:
                        continue

                next_wave.append((dest, depth + 1))
                visited.add(dest_key)

        current_wave = next_wave

    case.transfers = all_transfers
    case.exchange_endpoints = _compute_exchange_endpoints(all_transfers)
    case.unlabeled_counterparties = _collect_unlabeled(all_transfers)
    case.total_usd_out = _sum_usd(all_transfers)
    case.trace_completed_at = utcnow()

    log.info(
        "primary trace complete case=%s addresses_traced=%d transfers=%d total_usd=%s endpoints=%d duration=%.1fs",
        case_id,
        addresses_processed,
        len(case.transfers),
        case.total_usd_out,
        len(case.exchange_endpoints),
        (case.trace_completed_at - started).total_seconds(),
    )

    # v0.16.9 (round-9 forensic CRIT): BFS continuation past DEX routers
    # and same-chain bridge destinations.
    #
    # Pre-v0.16.9 the primary BFS halted at every contract (DEX routers
    # are contracts) and every bridge label, even when `detect_dex_swaps`
    # and `identify_cross_chain_handoffs` could resolve the next-hop
    # recipient at high confidence. Operators saw "trace terminated at
    # 1inch router" without any continuation to where the swapped output
    # actually went — the exact gap TRM Labs / Chainalysis don't have.
    #
    # The continuation runs a SHALLOW (depth=1) BFS pass from each
    # high-confidence post-trace recipient that isn't already in the
    # visited set. Same-chain only; cross-chain bridge destinations
    # are still surfaced via the post-trace report (multi-chain BFS
    # state is a larger refactor for v0.16.10).
    _continue_past_dex_and_bridges(
        case=case,
        chain=chain,
        adapter=adapter,
        label_store=label_store,
        price_client=price_client,
        policy=policy,
        incident_time=incident_time,
        config=config,
        evidence_dir=case_dir / "tx_evidence",
        visited=visited,
        is_contract_cache=is_contract_cache,
        trace_concurrency=trace_concurrency,
    )

    # Cleanup
    price_client.close()
    return case


def _continue_past_dex_and_bridges(
    *,
    case: Case,
    chain: Chain,
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: CoinGeckoClient,
    policy: TracePolicy,
    incident_time: datetime,
    config: RecuperoConfig,
    evidence_dir: Path,
    visited: set[str],
    is_contract_cache: dict[str, bool],
    trace_concurrency: int,
) -> None:
    """Inject DEX-swap output recipients and same-chain bridge
    destinations into a follow-up shallow BFS pass. Mutates ``case``
    in place to extend ``transfers`` with anything the continuation
    finds.

    Safety:
      * Only fires when the original max_depth left room for one more
        hop (i.e., max_depth >= 2). For depth-1 traces the caller
        explicitly asked for a single hop; we honor that.
      * Skips destinations that are already visited (no work duplicated).
      * Caps the number of continuation seeds at 25 per pass so a
        whale wallet with many swaps doesn't explode the trace budget.
    """
    if policy.max_depth < 2:
        return

    # Lazy imports — these modules pull large label DBs that take
    # tens of ms to load; only pay that cost when continuation is
    # actually possible.
    from recupero.trace.cross_chain import identify_cross_chain_handoffs
    from recupero.trace.dex_swaps import detect_dex_swaps

    continuation_seeds: list[tuple[Address, int, str]] = []
    # (address, depth_hint, provenance_tag)

    # --- DEX swap output recipients ---
    try:
        swaps = detect_dex_swaps(case)
    except Exception as exc:  # noqa: BLE001
        log.warning("dex-swap detection failed; skipping continuation: %s", exc)
        swaps = []
    for swap in swaps:
        if swap.confidence != "high":
            continue
        if not swap.output_recipient:
            continue
        # The output recipient on a DEX swap is on the SAME chain as
        # the swap itself. Safe to queue without multi-chain state.
        recipient = swap.output_recipient
        recipient_key = _address_visited_key(chain, recipient)
        if recipient_key in visited:
            continue
        # Don't continue if the recipient is itself a router (swap
        # output going back into another aggregator). The next pass
        # will re-detect and we'd loop forever otherwise.
        # depth_hint=1 puts the continuation at depth 1 from the
        # original swap — under max_depth=2 that's the last hop.
        continuation_seeds.append((recipient, 1, "dex_swap_output"))
        visited.add(recipient_key)

    # --- Same-chain bridge destinations ---
    try:
        handoffs = identify_cross_chain_handoffs(case)
    except Exception as exc:  # noqa: BLE001
        log.warning("bridge-handoff detection failed; skipping: %s", exc)
        handoffs = []
    for handoff in handoffs:
        dest_addr = getattr(handoff, "destination_address", None)
        dest_chain = getattr(handoff, "destination_chain", None)
        confidence = getattr(handoff, "confidence", "low")
        if confidence != "high" or not dest_addr:
            continue
        # ONLY continue when destination is the same chain. Cross-
        # chain hops need a separate adapter and multi-chain trace
        # state — surface them in the handoffs report but don't
        # mid-trace BFS across chains.
        if dest_chain and dest_chain != chain.value:
            log.info(
                "cross-chain bridge handoff dest=%s on %s (current %s); "
                "surfacing in handoffs report — multi-chain BFS deferred",
                dest_addr, dest_chain, chain.value,
            )
            continue
        dest_key = _address_visited_key(chain, dest_addr)
        if dest_key in visited:
            continue
        continuation_seeds.append((dest_addr, 1, "bridge_handoff"))
        visited.add(dest_key)

    if not continuation_seeds:
        return

    # Cap to bound the additional fetch budget. Real cases rarely
    # produce more than ~10 continuation seeds; the cap exists to
    # protect against a pathological tx-fan-out that detect_dex_swaps
    # over-reports.
    max_continuation = int(os.environ.get(
        "RECUPERO_MAX_CONTINUATION_SEEDS", "25",
    ))
    if len(continuation_seeds) > max_continuation:
        log.warning(
            "continuation seeds capped at %d (had %d) — "
            "RECUPERO_MAX_CONTINUATION_SEEDS to raise",
            max_continuation, len(continuation_seeds),
        )
        continuation_seeds = continuation_seeds[:max_continuation]

    log.info(
        "BFS continuation: %d additional seeds (DEX outputs + same-chain "
        "bridge destinations) at depth 1",
        len(continuation_seeds),
    )

    # Run a single wave of `_process_wave` from the continuation seeds.
    # depth_hint=1 means the resulting transfers carry hop_depth=1,
    # consistent with how the primary BFS would have labeled them.
    cont_wave: list[tuple[Address, int]] = [
        (addr, depth) for (addr, depth, _provenance) in continuation_seeds
    ]
    cont_results = _process_wave(
        cont_wave,
        adapter=adapter,
        label_store=label_store,
        price_client=price_client,
        policy=policy,
        incident_time=incident_time,
        config=config,
        evidence_dir=evidence_dir,
        concurrency=trace_concurrency,
    )

    new_transfers: list[Transfer] = []
    for _from_addr, _depth, hop_transfers, _is_service in cont_results:
        new_transfers.extend(hop_transfers)

    if new_transfers:
        case.transfers = list(case.transfers) + new_transfers
        case.exchange_endpoints = _compute_exchange_endpoints(case.transfers)
        case.unlabeled_counterparties = _collect_unlabeled(case.transfers)
        case.total_usd_out = _sum_usd(case.transfers)
        log.info(
            "BFS continuation added %d transfers from %d new seeds",
            len(new_transfers), len(continuation_seeds),
        )


def _process_wave(
    wave: list[tuple[Address, int]],
    *,
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: CoinGeckoClient,
    policy: TracePolicy,
    incident_time: datetime,
    config: RecuperoConfig,
    evidence_dir: Path,
    concurrency: int,
) -> list[tuple[Address, int, list[Transfer], bool]]:
    """Run ``_trace_one_hop`` on every address in the wave, returning the
    aggregated results. Internal errors per-address are caught and
    surfaced as empty transfer lists (so a single bad address doesn't
    discard the wave's other work).

    Wave parallelism uses ``ThreadPoolExecutor``. The rate-limiters in
    EtherscanClient and CoinGeckoClient have internal locks, so multiple
    threads sharing the clients are safe — global throughput is capped
    at the per-key rate regardless of thread count. Higher concurrency
    just hides per-call latency behind concurrent in-flight requests.
    """
    if not wave:
        return []

    def _one(addr: Address, depth: int) -> tuple[Address, int, list[Transfer], bool]:
        try:
            transfers, is_service_wallet = _trace_one_hop(
                adapter=adapter,
                label_store=label_store,
                price_client=price_client,
                policy=policy,
                from_address=addr,
                incident_time=incident_time,
                config=config,
                hop_depth=depth,
                parent_transfer_id=None,
                evidence_dir=evidence_dir,
            )
            return (addr, depth, transfers, is_service_wallet)
        except Exception as e:  # noqa: BLE001
            log.warning(
                "trace hop failed for %s (depth=%d): %s — continuing",
                addr, depth, e,
            )
            return (addr, depth, [], False)

    # Single-threaded path for trivial waves or when concurrency is off.
    # Preserves test determinism + avoids ThreadPoolExecutor overhead
    # for tiny cases.
    if concurrency <= 1 or len(wave) == 1:
        return [_one(addr, depth) for addr, depth in wave]

    results: list[tuple[Address, int, list[Transfer], bool]] = []
    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="trace"
    ) as pool:
        futures = {pool.submit(_one, addr, depth): (addr, depth) for addr, depth in wave}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                # _one catches its own exceptions and returns a result tuple;
                # this is the belt-and-suspenders catch for anything that
                # escaped (e.g., a future cancelled exception).
                addr, depth = futures[fut]
                log.warning("trace wave worker crashed for %s: %s", addr, e)
                results.append((addr, depth, [], False))
    return results


def _trace_one_hop(
    *,
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: CoinGeckoClient,
    policy: TracePolicy,
    from_address: Address,
    incident_time: datetime,
    config: RecuperoConfig,
    hop_depth: int,
    parent_transfer_id: str | None,
    evidence_dir: Path,
) -> tuple[list[Transfer], bool]:
    """Fetch + label + price all outflows from one address.

    Returns ``(transfers, is_service_wallet)``. When ``is_service_wallet``
    is True, the address has more outflows than
    ``policy.service_wallet_outflow_threshold`` — caller should keep the
    transfers but stop BFS traversal at this address.
    """
    start_time = incident_time - timedelta(minutes=config.trace.incident_buffer_minutes)
    start_block = adapter.block_at_or_before(start_time)
    log.info(
        "fetching outflows from=%s start_block=%d (start_time=%s)",
        from_address, start_block, start_time.isoformat(),
    )

    raw_outflows: list[dict[str, Any]] = []
    raw_outflows.extend(adapter.fetch_native_outflows(from_address, start_block))
    raw_outflows.extend(adapter.fetch_erc20_outflows(from_address, start_block))

    log.info("fetched %d raw outflows", len(raw_outflows))

    # Service-wallet detection: a wallet emitting more outflows than the
    # threshold is almost certainly an unlabeled exchange / OTC desk /
    # token distributor. Caller stops BFS at this address.
    is_service_wallet = (
        len(raw_outflows) > policy.service_wallet_outflow_threshold
    )
    if is_service_wallet:
        log.warning(
            "service-wallet detected: %s emits %d outflows "
            "(threshold=%d) — including transfers but not traversing children",
            from_address, len(raw_outflows),
            policy.service_wallet_outflow_threshold,
        )

    # Cap to avoid runaway on chatty addresses
    if len(raw_outflows) > config.trace.max_transfers_per_address:
        log.warning(
            "capping outflows from %d to %d for address %s",
            len(raw_outflows), config.trace.max_transfers_per_address, from_address,
        )
        raw_outflows = raw_outflows[: config.trace.max_transfers_per_address]

    transfers: list[Transfer] = []
    for raw in raw_outflows:
        # Drop debug-only fields before transfer construction
        raw.pop("_native_source", None)

        # Build initial Transfer with placeholder counterparty (filled below)
        transfer = _build_transfer(raw, hop_depth=hop_depth, parent_transfer_id=parent_transfer_id)

        # Pricing — price_at returns per-unit USD price; transfer value = price × amount
        result = price_client.price_at(transfer.token, transfer.block_time)
        usd_value: Decimal | None = None
        pricing_error = result.error
        if result.usd_value is not None:
            usd_value = (result.usd_value * transfer.amount_decimal).quantize(Decimal("0.01"))
            # Defense-in-depth sanity check: any single transfer claiming more
            # than $100M is almost certainly a pricing bug (spoofed token with
            # wrong decimals, etc). Reject the price rather than poison the total.
            from recupero.pricing.coingecko import _PER_TRANSFER_USD_SANITY_CEILING
            if abs(usd_value) > _PER_TRANSFER_USD_SANITY_CEILING:
                log.warning(
                    "rejecting suspicious USD value usd=%s symbol=%s amount=%s — likely spoofed token or bad decimals",
                    usd_value, transfer.token.symbol, transfer.amount_decimal,
                )
                pricing_error = (
                    f"sanity_ceiling_exceeded: computed_usd={usd_value} "
                    f"(symbol={transfer.token.symbol}, amount={transfer.amount_decimal}) "
                    "— rejected as likely spoofed-token / bad-decimals artifact"
                )
                usd_value = None
        transfer = transfer.model_copy(update={
            "usd_value_at_tx": usd_value,
            "pricing_source": result.source,
            "pricing_error": pricing_error,
        })

        # Dust filter (after pricing)
        if not policy.should_include(transfer):
            log.debug("skipping (dust) tx=%s usd=%s", transfer.tx_hash, transfer.usd_value_at_tx)
            continue

        # Label resolution
        label = label_store.lookup(transfer.to_address, chain=adapter.chain)
        try:
            is_contract = adapter.is_contract(transfer.to_address)
        except Exception as e:  # noqa: BLE001
            log.warning("is_contract check failed for %s: %s", transfer.to_address, e)
            is_contract = False

        counterparty = Counterparty(
            address=transfer.to_address,
            label=label,
            is_contract=is_contract,
            first_seen_at=transfer.block_time,
        )
        transfer = transfer.model_copy(update={"counterparty": counterparty})
        transfers.append(transfer)

        # Persist evidence receipt immediately (partial output > no output)
        try:
            write_evidence_receipt(adapter, transfer.tx_hash, evidence_dir)
        except Exception as e:  # noqa: BLE001
            log.warning("evidence receipt failed tx=%s: %s", transfer.tx_hash, e)

        log.info(
            "kept tx=%s to=%s amount=%s %s usd=%s label=%s",
            transfer.tx_hash[:12] + "...",
            transfer.to_address[:10] + "...",
            transfer.amount_decimal,
            transfer.token.symbol,
            transfer.usd_value_at_tx,
            (label.name if label else "UNLABELED"),
        )

    return transfers, is_service_wallet


def _build_transfer(raw: dict, *, hop_depth: int, parent_transfer_id: str | None) -> Transfer:
    log_idx = raw.get("log_index")
    transfer_id = f"{raw['chain'].value}:{raw['tx_hash']}:{log_idx if log_idx is not None else 0}"
    amount_raw_int = raw["amount_raw"]
    decimals = raw["token"].decimals
    amount_decimal = Decimal(amount_raw_int) / Decimal(10**decimals)

    # Placeholder counterparty — replaced after labeling
    placeholder_cp = Counterparty(
        address=raw["to"],
        label=None,
        is_contract=False,
        first_seen_at=None,
    )

    return Transfer(
        transfer_id=transfer_id,
        chain=raw["chain"],
        tx_hash=raw["tx_hash"],
        block_number=raw["block_number"],
        block_time=raw["block_time"],
        log_index=log_idx,
        from_address=raw["from"],
        to_address=raw["to"],
        counterparty=placeholder_cp,
        token=raw["token"],
        amount_raw=str(amount_raw_int),
        amount_decimal=amount_decimal,
        usd_value_at_tx=None,
        pricing_source=None,
        pricing_error=None,
        hop_depth=hop_depth,
        parent_transfer_id=parent_transfer_id,
        fetched_at=utcnow(),
        explorer_url=raw["explorer_url"],
    )


def _compute_exchange_endpoints(transfers: list[Transfer]) -> list[ExchangeEndpoint]:
    by_addr: dict[str, list[Transfer]] = defaultdict(list)
    for t in transfers:
        if (
            t.counterparty.label is not None
            and t.counterparty.label.category
            in (LabelCategory.exchange_deposit, LabelCategory.exchange_hot_wallet)
        ):
            by_addr[t.to_address].append(t)

    endpoints: list[ExchangeEndpoint] = []
    for address, ts in by_addr.items():
        label = ts[0].counterparty.label
        assert label is not None
        endpoints.append(
            ExchangeEndpoint(
                address=address,
                exchange=label.exchange or "Unknown",
                label_name=label.name,
                transfer_ids=[t.transfer_id for t in ts],
                total_received_usd=_sum_usd(ts),
                first_deposit_at=min(t.block_time for t in ts),
                last_deposit_at=max(t.block_time for t in ts),
            )
        )
    endpoints.sort(key=lambda e: e.total_received_usd or Decimal(0), reverse=True)
    return endpoints


def _collect_unlabeled(transfers: list[Transfer]) -> list[Address]:
    seen: set[str] = set()
    out: list[Address] = []
    for t in transfers:
        if t.counterparty.label is None and t.to_address not in seen:
            seen.add(t.to_address)
            out.append(t.to_address)
    return out


def _sum_usd(transfers: list[Transfer]) -> Decimal | None:
    vals = [t.usd_value_at_tx for t in transfers if t.usd_value_at_tx is not None]
    if not vals:
        return None
    return sum(vals, start=Decimal(0))
