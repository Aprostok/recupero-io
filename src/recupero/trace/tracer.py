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
from recupero.pricing.coingecko import CoinGeckoClient, PriceResult
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

    # v0.16.11 (round-9 worker-resilience ARCH): cooperative-cancel
    # timeout. Hard ceiling on wall-clock time the BFS can spend.
    # When the deadline hits between waves, we exit gracefully with
    # whatever transfers we've collected so far rather than running
    # past the worker's stale-claim threshold (5 min) and letting
    # the reaper kill us mid-stage.
    #
    # Default 540s (9 min) — comfortably under the 600s reaper window
    # so the worker has time to write the partial case + emit the
    # brief before any reaper-induced state churn.
    try:
        trace_deadline_sec = int(os.environ.get("RECUPERO_TRACE_TIMEOUT_SEC", "540"))
    except (TypeError, ValueError):
        trace_deadline_sec = 540
    trace_deadline = started + timedelta(seconds=trace_deadline_sec)
    timeout_hit = False

    # v0.16.11 (round-9 worker ARCH): max-transfers fail-fast gate.
    # A whale-wallet trace can produce 100k+ transfers and OOM the
    # worker's 8GB Railway instance because the entire case is held
    # in memory. We cap total transfers at a configurable ceiling and
    # exit gracefully (same partial-trace banner as the deadline path)
    # before OOM hits. Default 50k — comfortably above any real theft
    # case but well below the OOM boundary.
    try:
        max_transfers = int(os.environ.get("RECUPERO_MAX_TRANSFERS_PER_CASE", "50000"))
    except (TypeError, ValueError):
        max_transfers = 50000
    transfer_cap_hit = False

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
        # v0.16.11: cooperative deadline check between waves. We don't
        # interrupt in-flight wave work (would abandon per-tx evidence
        # writes mid-flight), but we DO refuse to start a new wave once
        # the deadline has elapsed. Logs a WARNING so the brief carries
        # an explicit "partial trace" provenance marker.
        if utcnow() >= trace_deadline:
            timeout_hit = True
            log.warning(
                "trace deadline hit (%ds) after %d wave(s); "
                "exiting with %d transfer(s) so far. "
                "Raise RECUPERO_TRACE_TIMEOUT_SEC for whale-wallet traces.",
                trace_deadline_sec, wave_number, len(all_transfers),
            )
            break
        # v0.16.11: transfer-cap check. OOM defense.
        if len(all_transfers) >= max_transfers:
            transfer_cap_hit = True
            log.warning(
                "trace transfer cap hit (%d) after %d wave(s); "
                "exiting with partial result. "
                "Raise RECUPERO_MAX_TRANSFERS_PER_CASE for whale-wallet traces.",
                max_transfers, wave_number,
            )
            break
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

    # v0.16.11: surface the partial-trace marker on the case so the
    # brief generator can render a "trace incomplete — deadline hit"
    # banner. Stored under config_used so it persists into case.json
    # without needing a new Case model field.
    if timeout_hit:
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "partial_deadline_hit",
            "trace_deadline_sec": trace_deadline_sec,
            "trace_waves_completed": wave_number,
        }
    elif transfer_cap_hit:
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "partial_transfer_cap_hit",
            "trace_transfer_cap": max_transfers,
            "trace_waves_completed": wave_number,
        }
    else:
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "complete",
        }

    log.info(
        "primary trace complete case=%s addresses_traced=%d transfers=%d total_usd=%s endpoints=%d duration=%.1fs status=%s",
        case_id,
        addresses_processed,
        len(case.transfers),
        case.total_usd_out,
        len(case.exchange_endpoints),
        (case.trace_completed_at - started).total_seconds(),
        case.config_used.get("trace_status", "complete"),
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
    # v0.17.4 (round-10 audit CRIT): wrap continuation + cleanup in
    # try/finally so price_client (and any dst-chain adapters opened
    # by the continuation pass) are released even on exception.
    # Pre-v0.17.4 a continuation-pass crash leaked httpx clients
    # for the lifetime of the worker process; over hours of activity
    # the OS file-descriptor limit hit and the process wedged.
    try:
        _continue_past_dex_and_bridges(
            case=case,
            chain=chain,
            adapter=adapter,
            label_store=label_store,
            price_client=price_client,
            policy=policy,
            incident_time=incident_time,
            config=config,
            env=env,
            evidence_dir=case_dir / "tx_evidence",
            visited=visited,
            is_contract_cache=is_contract_cache,
            trace_concurrency=trace_concurrency,
        )
    finally:
        try:
            price_client.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            adapter.close()
        except Exception:  # noqa: BLE001
            pass
    return case


def _continue_past_dex_and_bridges(
    *,
    case: Case,
    chain: Chain,
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: CoinGeckoClient,
    policy: TracePolicy,
    env: RecuperoEnv,
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

    # --- Bridge handoffs (same-chain + cross-chain) ---
    #
    # v0.16.13 (round-9 forensic ARCH): cross-chain BFS state.
    # When cross-chain continuation is enabled AND the bridge handoff
    # carries a decoded destination_chain that we have an adapter for,
    # we run a shallow (depth=1) BFS on the destination chain using a
    # freshly-instantiated adapter. The resulting transfers are
    # tagged with the destination chain (each Transfer carries its
    # own `chain` field) and merged into the case.
    #
    # v0.28.0 (Jacob Zigha review item 2, step 2.3): default flipped
    # from OFF to ON. The original off-by-default decision was a
    # v0.17.x conservative-default for cost/scope reasons. Three
    # things changed:
    #   * v0.17.4 added cross-chain seed dedup + per-case cap so the
    #     expansion is bounded
    #   * v0.27.2 made the trace coverage gap visible in shipping
    #     artifacts (1 of 7 Zigha destinations found)
    #   * v0.28.0 expanded bridges.json with Arbitrum/L2 entries so
    #     handoffs actually get DETECTED on the source side
    # Net: the env var is now opt-OUT, set
    # RECUPERO_CROSS_CHAIN_CONTINUATION=0 (or "no"/"false"/"off")
    # to disable. Default behavior chases bridge handoffs across
    # chains.
    #
    # The handoffs report ALWAYS surfaces the decoded destination
    # (regardless of the env var), so operators retain the manual-
    # pursue option for any handoff the BFS doesn't auto-follow.
    try:
        # Pass the source-chain adapter so handoff decoding can fetch
        # tx receipts + decode bridge calldata.
        handoffs = identify_cross_chain_handoffs(case, adapter=adapter)
    except Exception as exc:  # noqa: BLE001
        log.warning("bridge-handoff detection failed; skipping: %s", exc)
        handoffs = []

    # v0.28.0: default ON. To disable, set the env var to one of
    # the recognized opt-out values. An empty / unset env var falls
    # through to the ON default.
    _cross_chain_env = os.environ.get(
        "RECUPERO_CROSS_CHAIN_CONTINUATION", "",
    ).strip().lower()
    if _cross_chain_env in ("0", "false", "no", "off"):
        cross_chain_continue = False
    else:
        # Anything else (including unset / "1" / "true") → ON.
        cross_chain_continue = True

    # Track cross-chain seeds separately because they need their OWN
    # adapter (different chain) — they don't share the source-chain
    # adapter's wave loop. Shape: list[(chain, address, depth_hint)].
    cross_chain_seeds: list[tuple[Chain, Address, int]] = []
    # v0.17.4 (round-10 audit HIGH): dedup cross-chain seeds so the
    # same destination doesn't get traced twice. Keyed on (chain, addr).
    cross_chain_visited: set[tuple[str, str]] = set()

    for handoff in handoffs:
        # Same-chain destination from decoded calldata.
        decoded_chain_str = handoff.decoded_destination_chain
        decoded_addr = handoff.decoded_destination_address
        decoded_conf = handoff.decoded_confidence
        if decoded_conf != "high" or not decoded_addr:
            continue
        if decoded_chain_str and decoded_chain_str == chain.value:
            # Same chain — use the existing continuation seed list.
            dest_key = _address_visited_key(chain, decoded_addr)
            if dest_key in visited:
                continue
            # v0.17.4 (round-10 audit MED): apply the same stop_at_contract
            # gate as the primary BFS. Without it, a bridge handoff to a
            # router contract gets traced and the router's outflows
            # explode the budget on the next pass.
            if policy.stop_at_contract:
                try:
                    if adapter.is_contract(decoded_addr):
                        log.info(
                            "skipping same-chain bridge dest %s on %s — "
                            "is_contract=True",
                            decoded_addr, chain.value,
                        )
                        visited.add(dest_key)
                        continue
                except Exception:  # noqa: BLE001
                    pass  # treat as EOA on lookup failure
            continuation_seeds.append((decoded_addr, 1, "bridge_handoff_samechain"))
            visited.add(dest_key)
        elif cross_chain_continue and decoded_chain_str:
            # Cross-chain — only if env var allows AND we have an
            # adapter for the destination chain.
            try:
                dest_chain = Chain(decoded_chain_str)
            except (ValueError, KeyError):
                # v0.17.4 (round-10 audit HIGH): log at WARNING (was
                # INFO). Decoded destinations to chains not in our
                # Chain enum (avalanche / optimism / linea / zksync)
                # are detected but silently dropped — they belong on
                # the v0.17.x chain-expansion roadmap.
                log.warning(
                    "cross-chain handoff decoded to chain %r — not in "
                    "Chain enum, BFS continuation skipped. Brief "
                    "candidate list still surfaces it.",
                    decoded_chain_str,
                )
                continue
            # v0.17.4 (round-10 audit HIGH): dedup cross-chain seeds.
            xkey = (dest_chain.value, _address_visited_key(dest_chain, decoded_addr))
            if xkey in cross_chain_visited:
                continue
            cross_chain_visited.add(xkey)
            cross_chain_seeds.append((dest_chain, decoded_addr, 1))

    if not continuation_seeds and not cross_chain_seeds:
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

    # v0.16.13: cross-chain continuation pass. Each destination chain
    # needs its own adapter — group seeds by chain, instantiate one
    # adapter per chain, run a shallow wave. Bounded to prevent
    # quota explosion: at most RECUPERO_MAX_CROSS_CHAIN_SEEDS (default 10)
    # across all destination chains.
    if cross_chain_seeds:
        max_xchain = int(os.environ.get(
            "RECUPERO_MAX_CROSS_CHAIN_SEEDS", "10",
        ))
        if len(cross_chain_seeds) > max_xchain:
            log.warning(
                "cross-chain seeds capped at %d (had %d)",
                max_xchain, len(cross_chain_seeds),
            )
            cross_chain_seeds = cross_chain_seeds[:max_xchain]
        # Group by destination chain.
        by_chain: dict[Chain, list[tuple[Address, int]]] = {}
        for (dst_chain, dst_addr, depth_hint) in cross_chain_seeds:
            by_chain.setdefault(dst_chain, []).append((dst_addr, depth_hint))

        log.info(
            "cross-chain BFS continuation: %d seed(s) across %d chain(s)",
            len(cross_chain_seeds), len(by_chain),
        )

        for dst_chain, dst_seeds in by_chain.items():
            try:
                dst_adapter = ChainAdapter.for_chain(dst_chain, (config, env))
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "cross-chain continuation: failed to instantiate %s adapter: %s",
                    dst_chain.value, exc,
                )
                continue
            # v0.17.4 (round-10 audit CRIT): try/finally so the
            # destination-chain adapter's httpx client is released
            # even when the wave raises. Pre-v0.17.4 each cross-chain
            # continuation leaked one or more httpx clients per
            # investigation — FD exhaustion over hours of operation.
            try:
                try:
                    xchain_results = _process_wave(
                        dst_seeds,
                        adapter=dst_adapter,
                        label_store=label_store,
                        price_client=price_client,
                        policy=policy,
                        incident_time=incident_time,
                        config=config,
                        evidence_dir=evidence_dir,
                        concurrency=trace_concurrency,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "cross-chain continuation on %s failed: %s — skipping",
                        dst_chain.value, exc,
                    )
                    continue
                for _from_addr, _depth, hop_transfers, _is_service in xchain_results:
                    new_transfers.extend(hop_transfers)
            finally:
                try:
                    dst_adapter.close()
                except Exception:  # noqa: BLE001
                    pass

    if new_transfers:
        case.transfers = list(case.transfers) + new_transfers
        case.exchange_endpoints = _compute_exchange_endpoints(case.transfers)
        case.unlabeled_counterparties = _collect_unlabeled(case.transfers)
        case.total_usd_out = _sum_usd(case.transfers)
        log.info(
            "BFS continuation added %d transfers (same-chain seeds: %d, "
            "cross-chain seeds: %d)",
            len(new_transfers), len(continuation_seeds), len(cross_chain_seeds),
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

    # RIGOR-Jacob A: thread ``max_transfers_per_address`` into the
    # fetch layer with a 1.5x safety margin so an asymmetric split
    # (e.g., 1500 native + 5 token) doesn't truncate one leg below
    # the configured ceiling. ``max_transfers_per_address <= 0``
    # disables the cap — pass None so adapters walk to the natural
    # end of pagination.
    _cap = config.trace.max_transfers_per_address
    fetch_cap: int | None
    if _cap and _cap > 0:
        fetch_cap = int(_cap * 1.5)
    else:
        fetch_cap = None

    def _fetch_with_cap(
        fetch_fn: Any, from_addr: Address, sb: int, cap: int | None,
    ) -> list[dict[str, Any]]:
        """Call an adapter fetch_* method, threading max_results if
        the method accepts it. Falls back to a positional-only call
        for older adapters (e.g., test fakes) that don't take the
        kwarg, preserving backward compatibility."""
        try:
            return fetch_fn(from_addr, sb, max_results=cap)
        except TypeError:
            # Adapter doesn't accept max_results — old interface.
            return fetch_fn(from_addr, sb)

    raw_outflows: list[dict[str, Any]] = []
    raw_outflows.extend(
        _fetch_with_cap(
            adapter.fetch_native_outflows, from_address, start_block, fetch_cap,
        )
    )
    raw_outflows.extend(
        _fetch_with_cap(
            adapter.fetch_erc20_outflows, from_address, start_block, fetch_cap,
        )
    )

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
        # Wave-2 adversarial hardening: reject non-finite prices /
        # amounts at the per-hop boundary BEFORE any arithmetic. The
        # CoinGecko client filters at fetch, but a mocked / new /
        # compromised pricing provider could leak Decimal('NaN') —
        # `(NaN * amount).quantize(...)` raises InvalidOperation, the
        # exception is swallowed by _process_wave's bare-except, and
        # the ENTIRE hop's transfers are silently dropped. Treat
        # non-finite as "no price" so the existing unpriced-transfer
        # path (which still emits the audit-trail row with usd=None)
        # is taken instead.
        if result.usd_value is not None and (
            not result.usd_value.is_finite()
            or not transfer.amount_decimal.is_finite()
        ):
            pricing_error = (
                f"non_finite_price_or_amount: price={result.usd_value} "
                f"amount={transfer.amount_decimal} "
                f"(symbol={transfer.token.symbol}) — rejected"
            )
            result = PriceResult(
                usd_value=None, source=result.source, error=pricing_error,
            )
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
    # v0.18.3 (round-11 trace-HIGH-001): canonical-key the aggregation
    # dict. Pre-v0.18.3 used raw `t.to_address` directly — for Solana
    # / Tron / Bitcoin a counterparty address arriving from different
    # adapters with mixed-case OR an operator-pasted label match in
    # different case would split into two distinct ExchangeEndpoint
    # rows for the SAME logical address (totals halved, deposit
    # windows split). Now: key by canonical form, preserve the
    # first-seen original-case form for display.
    from recupero._common import canonical_address_key as _ck
    by_addr: dict[str, list[Transfer]] = defaultdict(list)
    display_addr: dict[str, str] = {}  # canonical → first-seen original case
    for t in transfers:
        if (
            t.counterparty.label is not None
            and t.counterparty.label.category
            in (LabelCategory.exchange_deposit, LabelCategory.exchange_hot_wallet)
        ):
            key = _ck(t.to_address)
            by_addr[key].append(t)
            display_addr.setdefault(key, t.to_address)

    endpoints: list[ExchangeEndpoint] = []
    for key, ts in by_addr.items():
        address = display_addr.get(key, key)
        label = ts[0].counterparty.label
        # v0.17.3 (round-10 audit MED): explicit narrowing — the filter
        # above only kept transfers where label is not None, but `assert`
        # is stripped under `python -O`. An unreachable-state crash here
        # would mean the filter regressed; surface it via RuntimeError
        # rather than the silent AttributeError we'd hit later.
        if label is None:
            log.warning(
                "exchange endpoint aggregation: filtered transfer carries "
                "None label for address=%s — skipping", address,
            )
            continue
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
