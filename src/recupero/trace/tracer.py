"""Trace orchestrator.

Implements the algorithm described in docs/TRACE_ALGORITHM.md. Phase 1: single hop.
Phase 2 will add recursion, cycle detection, and policy-driven traversal — leave
the structure friendly to that.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
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
    return datetime.now(timezone.utc)


def _normalize_address(chain: Chain, address: Address) -> Address:
    """Normalize per-chain. EVM chains use checksum; Solana/others pass through."""
    if chain in (Chain.ethereum, Chain.arbitrum, Chain.bsc, Chain.base, Chain.polygon):
        return to_checksum_address(address)
    return address


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
        incident_time = incident_time.replace(tzinfo=timezone.utc)
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

    # --- Recursive BFS driver ---
    # We maintain:
    #   - visited: addresses we've already traced-from (cycle detection)
    #   - queued: addresses currently in the queue (avoid dupes before visiting)
    #   - is_contract_cache: per-chain address → bool (to avoid repeat RPCs)
    all_transfers: list[Transfer] = []
    visited: set[str] = set()
    queued: set[str] = set()
    is_contract_cache: dict[str, bool] = {}
    queue: deque[tuple[Address, int]] = deque([(seed_address, 0)])
    queued.add(seed_address.lower())

    addresses_processed = 0

    while queue:
        current_address, current_depth = queue.popleft()
        addr_key = current_address.lower()
        queued.discard(addr_key)
        if addr_key in visited:
            continue
        visited.add(addr_key)
        addresses_processed += 1

        log.info(
            "tracing #%d address=%s depth=%d visited=%d queued=%d",
            addresses_processed, current_address, current_depth, len(visited), len(queue),
        )

        # Fetch outflows for this address. Errors at this stage shouldn't
        # abort the whole trace — log and move on.
        try:
            hop_transfers, is_service_wallet = _trace_one_hop(
                adapter=adapter,
                label_store=label_store,
                price_client=price_client,
                policy=policy,
                from_address=current_address,
                incident_time=incident_time,
                config=config,
                hop_depth=current_depth,
                parent_transfer_id=None,
                evidence_dir=case_dir / "tx_evidence",
            )
        except Exception as e:  # noqa: BLE001
            log.warning(
                "trace hop failed for %s (depth=%d): %s — continuing",
                current_address, current_depth, e,
            )
            continue

        all_transfers.extend(hop_transfers)

        # Decide which destinations to enqueue for the next hop
        if current_depth + 1 >= policy.max_depth:
            continue

        # Service-wallet cap: keep the transfers we observed (audit trail)
        # but don't queue downstream. Without this, a single 500-outflow
        # OTC desk / unlabeled exchange explodes BFS at the next depth.
        if is_service_wallet:
            log.info(
                "service-wallet skip: not queueing %d destinations from %s",
                len(hop_transfers), current_address,
            )
            continue

        for transfer in hop_transfers:
            if not policy.should_traverse(transfer):
                continue
            dest = transfer.to_address
            dest_key = dest.lower()
            if dest_key in visited or dest_key in queued:
                continue

            # Contract check: one RPC per unique address, cached
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

            queue.append((dest, current_depth + 1))
            queued.add(dest_key)

    case.transfers = all_transfers
    case.exchange_endpoints = _compute_exchange_endpoints(all_transfers)
    case.unlabeled_counterparties = _collect_unlabeled(all_transfers)
    case.total_usd_out = _sum_usd(all_transfers)
    case.trace_completed_at = utcnow()

    log.info(
        "trace complete case=%s addresses_traced=%d transfers=%d total_usd=%s endpoints=%d duration=%.1fs",
        case_id,
        addresses_processed,
        len(case.transfers),
        case.total_usd_out,
        len(case.exchange_endpoints),
        (case.trace_completed_at - started).total_seconds(),
    )

    # Cleanup
    price_client.close()
    return case


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
