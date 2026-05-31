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
from recupero.labels.store import (
    LabelStore,
    lookup_pit_safe,  # v0.31.4
)
from recupero.models import (
    Address,
    Case,
    Chain,
    Counterparty,
    ExchangeEndpoint,
    LabelCategory,
    Transfer,
)
from recupero.observability.api_budget import (
    BudgetExceededError,
    CaseBudget,
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


def _attach_budget_to_adapter(adapter: ChainAdapter, budget: CaseBudget) -> None:
    """Best-effort propagation of the per-case API budget to whichever
    HTTP client the adapter holds.

    Different adapters expose different attribute names — EVM /
    Solana / Tron all bind a ``self.client``; the Bitcoin adapter
    binds a ``self.esplora``. We walk the small known surface and
    attach the budget where we find it. Unknown shapes are silently
    skipped (budget tracking is best-effort — never crash the trace
    over a missing attribute).
    """
    for attr in ("client", "esplora", "fallback_client"):
        sub = getattr(adapter, attr, None)
        if sub is None:
            continue
        try:
            sub.budget = budget
        except Exception:  # noqa: BLE001 — defensive, never raise out
            log.debug(
                "budget attach skipped for adapter=%s attr=%s",
                type(adapter).__name__, attr,
            )


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


# v0.34 (operator-requested coverage-honesty): per-case accumulator of
# points where the trace TRUNCATED coverage — currently the per-address
# fetch cap slicing a chatty/poisoned address's outflows. Cleared at the
# start of every ``run_trace`` (mirrors the BTC co-spend / CoinJoin
# registries below) so sequential in-process runs never bleed. Surfaced in
# ``case.config_used["coverage"]`` so a reduced-parameter trace can NEVER be
# silently rendered as "complete" in an LE deliverable.
_COVERAGE_TRUNCATIONS: list[dict[str, Any]] = []


def _clear_coverage_truncations() -> None:
    _COVERAGE_TRUNCATIONS.clear()


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

    # v0.32.1 (forensic-audit CRIT): reset the process-lifetime Bitcoin
    # co-spend input registry + synthetic-CoinJoin registry at the START
    # of every case. These are module-level globals populated during a
    # trace; a worker that processes case B after case A in the SAME
    # process would otherwise inherit case A's BTC input sets, causing
    # the H1 common-input clustering heuristic to FALSE-MERGE addresses
    # across unrelated victims — and making two sequential in-process
    # runs differ from a clean-process run (nondeterminism). The clears
    # are cheap no-ops for non-Bitcoin cases.
    from recupero.chains.bitcoin.adapter import (
        clear_synthetic_coinjoin_registry as _clear_btc_coinjoin,
    )
    from recupero.chains.bitcoin.inputs_registry import (
        clear_for_case as _clear_btc_inputs,
    )
    _clear_btc_inputs()
    _clear_btc_coinjoin()
    _clear_coverage_truncations()

    # v0.32 — per-case API budget. One CaseBudget per case, propagated
    # to every chain + pricing client. When the cap trips, BFS catches
    # the BudgetExceededError, marks the case partial_budget_hit, and
    # exits gracefully — same shape as the deadline-timeout path.
    case_budget = CaseBudget.from_env(case_id=case_id)

    adapter = ChainAdapter.for_chain(chain, (config, env))
    # Best-effort budget propagation. The adapter holds an HTTP client
    # constructed during ChainAdapter.for_chain; we attach the budget
    # to that nested client AFTER construction so we don't have to
    # plumb the budget through every adapter ctor signature.
    _attach_budget_to_adapter(adapter, case_budget)
    label_store = LabelStore.load(config)
    cache_dir = Path(config.storage.data_dir) / "prices_cache"
    price_client = CoinGeckoClient(config, env, cache_dir, budget=case_budget)

    # v0.31.0 — env-var overrides for the two BFS knobs operators most
    # often want to tune per-case. Both fall back to the config-yaml
    # defaults (TraceParams.max_depth=4, dust_threshold_usd=10) so the
    # behavior is unchanged when the env vars are absent.
    #   * RECUPERO_TRACE_MAX_HOPS — bump for deep-laundering cases
    #     (Zigha-shape paths can run 4-6 hops via consolidation hubs;
    #     APT-style chains can reach 30-50 hops). v0.32.1+ "industry-best
    #     mode": hard ceiling raised to 64 so we can reach destinations
    #     Reactor caps at ~12. Operators on quota-constrained API plans
    #     can lower RECUPERO_TRACE_MAX_HOPS_HARD_CEILING to match their
    #     funded API budget.
    #   * RECUPERO_TRACE_DUST_USD — lower for sub-cent dust-attack
    #     studies, raise for whale-volume cases where $10 noise gets
    #     too much attention.
    # Both are clamped to safe ranges: max_hops ∈ [1, HARD_CEILING]
    # (default 64), dust ∈ [0, 1e6].
    cfg_max_depth = config.trace.max_depth
    # v0.32.1+ "industry-best mode": the hard ceiling was 8 hops, which
    # is below what real laundering operators use (Lazarus / DPRK routes
    # typically span 10-20 hops; complex APT routes can hit 50+). The
    # ceiling is now operator-controllable via
    # ``RECUPERO_TRACE_MAX_HOPS_HARD_CEILING`` (default 64) so a $50M
    # case can drive a deep trace without artificial truncation. The
    # config default still pins the BFS to a sensible 6-hop start; ops
    # bump RECUPERO_TRACE_MAX_HOPS per case.
    try:
        hard_ceiling = int(
            os.environ.get("RECUPERO_TRACE_MAX_HOPS_HARD_CEILING", "64")
        )
    except (TypeError, ValueError):
        hard_ceiling = 64
    hard_ceiling = max(1, hard_ceiling)
    try:
        env_max_hops = int(os.environ.get("RECUPERO_TRACE_MAX_HOPS", str(cfg_max_depth)))
        cfg_max_depth = max(1, min(hard_ceiling, env_max_hops))
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_TRACE_MAX_HOPS=%r is not an int; falling back to config (%d)",
            os.environ.get("RECUPERO_TRACE_MAX_HOPS"), config.trace.max_depth,
        )

    # v0.32.1 W4 (round-2 CRIT-NEW-2 wire-up): adaptive depth. Pre-W4
    # this was dead-code; tracer.py clamped to ``min(8, env_max_hops)``
    # regardless of case severity. With adaptive_depth wired, a $50M
    # theft case is allowed to descend to depth 12 (severity bump +
    # budget headroom), while a $50K case stays shallow. Falls back to
    # the env+config-driven ceiling on any error — never break the
    # trace over a depth-policy module.
    if os.environ.get("RECUPERO_ADAPTIVE_DEPTH", "").strip().lower() in (
        "1", "true", "yes", "on",
    ):
        try:
            from recupero.trace.adaptive_depth import compute_max_depth
            budget_snap = case_budget.snapshot() if case_budget else {}
            # v0.32.1 (Phase-2 fix): read the CORRECT snapshot key. The
            # snapshot exposes ``remaining_usd`` (a stringified Decimal, or
            # the literal "unbounded" when budget tracking is DISABLED — the
            # industry-best default). The pre-fix code read a non-existent
            # ``budget_remaining_usd`` key, so it ALWAYS got 0.0 → the
            # adaptive pass treated every case as budget-starved and the
            # severity bumps never applied. Map unbounded / missing /
            # tracking-disabled → None so compute_max_depth takes its
            # DEEPEST (unbounded) path; a real enabled remaining is parsed.
            _rem_raw = budget_snap.get("remaining_usd")
            budget_remaining: float | None
            if (
                _rem_raw is None
                or _rem_raw == "unbounded"
                or not budget_snap.get("enabled", False)
            ):
                budget_remaining = None  # unbounded → deepest
            else:
                try:
                    budget_remaining = float(_rem_raw)
                except (TypeError, ValueError):
                    budget_remaining = None
            case_meta: dict[str, Any] = {}
            # The Case model doesn't carry theft_amount_usd until after
            # trace completes (operator inputs it on intake, scrapers
            # surface it). Best-effort: read from config_used if the
            # caller populated it, or from env override.
            theft_env = os.environ.get("RECUPERO_CASE_THEFT_USD")
            if theft_env is not None:
                try:
                    case_meta["theft_amount_usd"] = float(theft_env)
                except (TypeError, ValueError):
                    pass
            adaptive = compute_max_depth(
                case_metadata=case_meta or None,
                api_budget_remaining_usd=budget_remaining,
            )
            # Use the adaptive value as the ceiling unless the operator
            # has explicitly capped it lower via the env var. v0.32.1+
            # industry-best mode: adaptive_depth's HARD_CEILING is 64
            # so deep-laundering chains can be followed. The hard
            # ceiling here matches the RECUPERO_TRACE_MAX_HOPS_HARD_CEILING
            # env override so operators can lower the cap if needed.
            cfg_max_depth = max(1, min(hard_ceiling, adaptive, cfg_max_depth)) if (
                "RECUPERO_TRACE_MAX_HOPS" in os.environ
            ) else max(1, min(hard_ceiling, adaptive))
            log.info(
                "adaptive depth: case_meta=%s budget=$%s → max_depth=%d",
                case_meta, budget_remaining, cfg_max_depth,
            )
        except Exception as exc:  # noqa: BLE001 — never break trace
            log.debug(
                "adaptive_depth compute failed (%s); falling back to %d",
                exc, cfg_max_depth,
            )

    cfg_dust = config.trace.dust_threshold_usd
    try:
        env_dust_raw = os.environ.get("RECUPERO_TRACE_DUST_USD")
        if env_dust_raw is not None:
            env_dust = float(env_dust_raw)
            # Reject NaN / ±Inf / negative — these would silently break
            # the filter (NaN comparison is always False, so EVERY
            # transfer would slip the dust gate; -inf would clamp to 0
            # via max(0, -inf) and silently disable the filter while
            # masking the operator misconfig).
            import math as _m
            if not _m.isfinite(env_dust) or env_dust < 0:
                raise ValueError("non-finite or negative")
            cfg_dust = min(1_000_000.0, env_dust)
    except (TypeError, ValueError) as exc:
        log.warning(
            "RECUPERO_TRACE_DUST_USD=%r rejected (%s); falling back to config ($%s)",
            os.environ.get("RECUPERO_TRACE_DUST_USD"), exc, config.trace.dust_threshold_usd,
        )

    policy = TracePolicy(
        max_depth=cfg_max_depth,
        dust_threshold_usd=Decimal(str(cfg_dust)),
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
    # v0.32.1 W8 (round-2 wire-up): per-case contract_detection cache.
    # Keyed by ``f"{chain}:{address.lower()}"`` (see
    # contract_detection._cache_key). Distinct from is_contract_cache
    # (which uses chain-aware dest_key) so contract_detection.is_contract
    # can manage its own retry + non-cache-on-failure invariant without
    # interfering with the legacy cache shape.
    _contract_check_cache: dict[str, bool] = {}
    current_wave: list[tuple[Address, int]] = [(seed_address, 0)]
    addresses_processed = 0
    wave_number = 0
    # v0.32 — track whether the BFS exited due to the per-case API
    # budget cap. Same graceful-degradation shape as deadline_hit /
    # transfer_cap_hit. Records into case.config_used so the brief
    # can render the "trace incomplete — budget exhausted" banner.
    budget_hit = False
    budget_hit_provider: str | None = None

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
        try:
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
        except BudgetExceededError as exc:
            # v0.32 — per-case API budget tripped mid-wave. Same
            # graceful-degradation contract as deadline_hit: bail out
            # of the BFS, record the marker, and let the brief
            # render a "trace incomplete — budget exhausted" banner.
            budget_hit = True
            budget_hit_provider = exc.provider
            log.warning(
                "trace API budget hit ($%s spent / $%s budget) after "
                "%d wave(s) on provider=%s; exiting partial.",
                exc.spent_usd, exc.budget_usd, wave_number, exc.provider,
            )
            break

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
                #
                # v0.32.1 W8 (round-2 wire-up): route through
                # ``contract_detection.is_contract`` so transient RPC
                # failures don't poison the cache as "is_contract=True"
                # forever. Pre-W8 a single rate-limit hit on the
                # is_contract probe would make BFS skip that address
                # permanently for the rest of the worker's lifetime.
                # The contract_detection helper:
                #   * retries once on Exception (transient),
                #   * returns (None, reason) on twice-failed RPC and
                #     leaves the cache UNTOUCHED — letting later passes
                #     re-resolve cleanly,
                #   * caches verified True/False with a chain-aware key.
                # We mirror into the legacy ``is_contract_cache`` (keyed
                # by dest_key) so other code paths that read it
                # (continuation pass, tracer:1157) keep working.
                if policy.stop_at_contract:
                    if dest_key not in is_contract_cache:
                        try:
                            from recupero.trace.contract_detection import (
                                is_contract as _is_contract_safe,
                            )
                            result_bool, _reason = _is_contract_safe(
                                dest, chain.value, adapter, _contract_check_cache,
                            )
                            if result_bool is None:
                                # RPC failed twice; fall back to the
                                # conservative "assume contract" gate to
                                # avoid expanding into an unverifiable
                                # destination. NB: we DO NOT cache None
                                # so a later pass can re-resolve.
                                log.debug(
                                    "is_contract uncertain for %s (%s); "
                                    "treating as contract for this hop",
                                    dest, _reason,
                                )
                                is_contract_cache[dest_key] = True
                            else:
                                is_contract_cache[dest_key] = result_bool
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
    elif budget_hit:
        # v0.32 — per-case API budget exhausted. Surface the marker
        # AND the per-provider breakdown so the brief shows the
        # operator exactly where the dollars went.
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "partial_budget_hit",
            "trace_budget_provider": budget_hit_provider,
            "trace_waves_completed": wave_number,
        }
    else:
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "complete",
        }

    # v0.32 — always surface the per-case API budget snapshot under
    # case.config_used["api_budget"]. This is the breakdown the brief
    # and the audit trail will render, regardless of whether the cap
    # was hit. When the budget is disabled (RECUPERO_API_BUDGET_USD_PER_CASE=0)
    # the snapshot still lands but enabled=False makes the brief
    # renderer skip the section.
    case.config_used = {
        **(case.config_used or {}),
        "api_budget": case_budget.snapshot(),
    }

    # v0.34 (operator-requested coverage-honesty): a trace that ran with
    # reduced parameters — a per-address fetch cap that truncated an
    # address, and/or address-poisoning that inflated the transfer graph —
    # may have DROPPED a real onward hop. An LE deliverable must never imply
    # completeness in that case. Detect poisoning (best-effort; never breaks
    # a trace) + read the per-address cap truncations recorded during the
    # wave loop, and surface a loud notice recommending a recall-complete
    # re-run. ``coverage.complete`` is True ONLY when the trace finished
    # cleanly AND nothing reduced coverage.
    try:
        from recupero.trace.address_poisoning import detect_poisoning_attempts
        _poison_events = detect_poisoning_attempts(all_transfers, seed_address)
    except Exception as _pe:  # noqa: BLE001
        log.debug("poisoning detection failed (non-fatal): %s", _pe)
        _poison_events = []
    _cap_truncations = list(_COVERAGE_TRUNCATIONS)
    try:
        _resolved_addr_cap = int(os.environ.get(
            "RECUPERO_MAX_TRANSFERS_PER_ADDRESS",
            str(config.trace.max_transfers_per_address),
        ))
    except (TypeError, ValueError):
        _resolved_addr_cap = config.trace.max_transfers_per_address
    _coverage_reduced = bool(_cap_truncations) or bool(_poison_events)
    # v0.34 (coverage-honesty hardening): a trace that fetched ZERO transfers
    # is NEVER "complete" — it is almost always an API key/access failure
    # (invalid or rate-limited key returning NOTOK), a wrong seed/incident
    # time, or a dead RPC — NOT a genuinely empty wallet. Previously such a
    # run wrote trace_status="complete" + coverage.complete=True (no cap, no
    # poisoning, no timeout), silently presenting an utterly empty trace as a
    # finished one. That is the exact silent-incompleteness this notice exists
    # to prevent, so an empty result must flip complete=False with a loud,
    # distinct recommendation.
    _no_data = not all_transfers
    if _no_data:
        _recommendation = (
            "Trace fetched ZERO transfers. This is almost always an API "
            "key/access failure (invalid or rate-limited key returning NOTOK), "
            "a wrong seed address / incident time, or a dead RPC endpoint — "
            "NOT a genuinely empty wallet. The result is NOT usable; fix API "
            "access (verify ETHERSCAN_API_KEY + tier) and re-run before relying "
            "on this case."
        )
    elif _coverage_reduced:
        _recommendation = (
            "Coverage may be INCOMPLETE: address-poisoning and/or a "
            "per-address fetch cap was in effect, so funds split below "
            "the dust floor, sent beyond the fetch cap, or routed past "
            "the depth limit can be missed. Before relying on "
            "completeness for asset recovery, re-run recall-complete "
            "(e.g. --max-depth 8 --dust-threshold-usd 50 with "
            "RECUPERO_MAX_TRANSFERS_PER_ADDRESS=0), ideally on a paid "
            "API tier."
        )
    else:
        _recommendation = ""
    case.config_used = {
        **(case.config_used or {}),
        "coverage": {
            "complete": (
                case.config_used.get("trace_status") == "complete"
                and not _coverage_reduced
                and not _no_data
            ),
            "no_data": _no_data,
            "poisoning_detected": bool(_poison_events),
            "poisoning_event_count": len(_poison_events),
            "per_address_cap_truncations": _cap_truncations,
            "reduced_parameters": {
                "max_depth": int(cfg_max_depth),
                "dust_threshold_usd": float(config.trace.dust_threshold_usd),
                "max_transfers_per_address": int(_resolved_addr_cap),
            },
            "recommendation": _recommendation,
        },
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
    except BudgetExceededError as exc:
        # v0.32 — budget tripped during the DEX/bridge continuation
        # pass. Mark partial and let cleanup run via the finally block.
        log.warning(
            "trace API budget hit during continuation pass ($%s / $%s, "
            "provider=%s); exiting partial.",
            exc.spent_usd, exc.budget_usd, exc.provider,
        )
        case.config_used = {
            **(case.config_used or {}),
            "trace_status": "partial_budget_hit",
            "trace_budget_provider": exc.provider,
            "api_budget": case_budget.snapshot(),
        }
    finally:
        # v0.32.1 W7 (round-2 CRIT-NEW-1 wire-up): pre-fetch drainer
        # contract outflows BEFORE the adapter closes. Stores the
        # resulting findings on case.config_used["drainer_findings_w7"]
        # so emit_brief can consume them. Best-effort: any failure
        # here logs and continues — the brief still gets a chance to
        # run drainer detection at render time (without the W7
        # prefetch path).
        if os.environ.get("RECUPERO_DRAINER_W7_PREFETCH", "1").strip().lower() in (
            "1", "true", "yes", "on",
        ):
            try:
                from recupero.trace.drainer_detection import detect_drainer_pattern
                # Lazy-load high_risk_db; many cases don't trip signal-1
                # and the W7 path is signal-2-only.
                _w7_findings = detect_drainer_pattern(
                    case, high_risk_db=None, adapter=adapter,
                )
                # Surface a tiny snapshot on config_used so emit_brief can
                # detect that prefetch ran. The full findings object is
                # rebuilt at brief time from case.transfers + the now-cached
                # contract outflows that prefetch wrote into the adapter's
                # internal caches (where present).
                case.config_used = {
                    **(case.config_used or {}),
                    "drainer_w7_prefetch": {
                        "ran": True,
                        "events_found": len(_w7_findings.events),
                        "signals_found": len(_w7_findings.signals),
                    },
                }
            except Exception as exc:  # noqa: BLE001 — never break trace cleanup
                log.debug("drainer W7 prefetch failed: %s", exc)
        try:
            price_client.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            adapter.close()
        except Exception:  # noqa: BLE001
            pass

    # v0.31.2 — dust-attack pattern filter (off by default).
    #
    # A perpetrator sending many sub-cent transfers to many distinct
    # destinations from a single source address pollutes Section 5 of
    # the brief with innocent-looking noise, burying the real path.
    # When RECUPERO_DUST_ATTACK_FILTER=1, we identify those destination
    # addresses and remove them from `unlabeled_counterparties` so the
    # brief renderer doesn't include them in Section 5. The transfers
    # themselves stay in `case.transfers` for the audit trail.
    #
    # OFF by default to avoid changing existing case-rendering tests.
    # Operators turn it on per-case via the env var.
    _apply_dust_attack_filter(case)

    return case


def _ordered_lockmint_candidates(
    decoded_chain: str | None,
    candidates: tuple[str, ...] | list[str],
) -> list[str]:
    """Order the destination chains to try for lock-and-mint matching.

    When a decoder named the destination chain (e.g. the Orbiter amount-suffix
    decoder sets ``handoff.decoded_destination_chain``), it is AUTHORITATIVE
    about where the funds went, so it goes FIRST — the caller then stops on a
    match there. A multi-chain bridge's candidate list can coincidentally
    amount+time-match on several chains; leading with the decoded chain cuts
    both latency and that false-positive surface. With no decoded chain the
    original candidate order is preserved exactly. De-duplicated; empties
    dropped.
    """
    decoded = (decoded_chain or "").strip()
    out: list[str] = [decoded] if decoded else []
    for c in candidates:
        if c and c != decoded and c not in out:
            out.append(c)
    return out


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
    # adapter's wave loop. Shape: list[(chain, address, depth_hint,
    # source_bridge_block_time)]. The trailing block_time enables the
    # v0.31.0 cross-chain time-window filter (drop dst transfers
    # outside [source_bridge_time, +window] hours).
    cross_chain_seeds: list[tuple[Chain, Address, int, datetime]] = []
    # v0.17.4 (round-10 audit HIGH): dedup cross-chain seeds so the
    # same destination doesn't get traced twice. Keyed on (chain, addr).
    cross_chain_visited: set[tuple[str, str]] = set()

    # v0.31.0 — Configurable cross-chain time window. Default 24h
    # past the source bridge tx; 0 disables the filter (legacy
    # behavior). Clamped to [0, 720] hours (30d max — bridge handoffs
    # can hop in seconds or hours, never months in real cases).
    try:
        xchain_window_h = float(os.environ.get(
            "RECUPERO_CROSSCHAIN_WINDOW_HOURS", "24",
        ))
        # Reject NaN / ±Inf. v0.31.1: the earlier check only rejected
        # +Infinity (and NaN via self-inequality); -Infinity would slip
        # through, then `max(0, -inf) = 0` silently disabled the filter
        # and masked the operator misconfig. Use math.isfinite to catch
        # both infinities + NaN in one call.
        import math as _m
        if not _m.isfinite(xchain_window_h):
            raise ValueError("non-finite")
        xchain_window_h = max(0.0, min(720.0, xchain_window_h))
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_CROSSCHAIN_WINDOW_HOURS=%r rejected; using default 24h",
            os.environ.get("RECUPERO_CROSSCHAIN_WINDOW_HOURS"),
        )
        xchain_window_h = 24.0

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
            # v0.31.0: stash the source-chain bridge tx block_time so the
            # post-wave filter can drop dst transfers that fall outside
            # RECUPERO_CROSSCHAIN_WINDOW_HOURS of the handoff. Parsed
            # from handoff.block_time_iso ('Z'-terminated UTC ISO). On
            # any parse failure we fall back to the case incident_time
            # (forensically safe — case-wide window applies).
            try:
                src_iso = handoff.block_time_iso.replace("Z", "+00:00")
                src_block_time = datetime.fromisoformat(src_iso)
                if src_block_time.tzinfo is None:
                    src_block_time = src_block_time.replace(tzinfo=UTC)
            except (TypeError, ValueError, AttributeError):
                src_block_time = incident_time
            cross_chain_seeds.append((dest_chain, decoded_addr, 1, src_block_time))

    # v0.32.1 (trace-depth #1 wiring): lock-and-mint cross-chain matching.
    # OPT-IN via RECUPERO_LOCKMINT_MATCH because it is the more INFERENTIAL,
    # more EXPENSIVE tier. For handoffs where calldata decode yielded NO
    # destination (Celer pool / Orbiter / legacy Multichain — the recipient
    # is not in the source calldata), fetch the perpetrator address's
    # INBOUND transfers on each candidate destination chain and correlate by
    # amount+time (same-address lock-and-mint heuristic). A confirmed match
    # (confidence medium/low — a cross-chain correlation, NEVER proof) adds a
    # continuation seed so the BFS follows the trail onto the destination
    # chain. Default OFF so existing prod traces are byte-for-byte unchanged
    # unless an operator opts into the deeper matching for a specific case.
    _lockmint_on = os.environ.get(
        "RECUPERO_LOCKMINT_MATCH", "",
    ).strip().lower() in ("1", "true", "yes", "on")
    if _lockmint_on and cross_chain_continue and handoffs:
        from recupero.trace.cross_chain import (
            bridge_address_on_chain,
            ingest_bridge_seeds,
            match_lockmint_destination,
            match_pool_bridge_disbursement,
        )
        # Loaded once for the disbursement fallback (Wave #3): locate a pool/
        # swap bridge's DESTINATION-side contract to follow its outflows.
        _lm_bridge_db = ingest_bridge_seeds()
        for handoff in handoffs:
            if handoff.decoded_destination_address:
                continue  # calldata already produced a destination
            # Wave F: lead with the decoder-named chain (authoritative) and
            # stop on a match there — see _ordered_lockmint_candidates.
            for cand_str in _ordered_lockmint_candidates(
                handoff.decoded_destination_chain,
                handoff.destination_chain_candidates,
            ):
                try:
                    cand_chain = Chain(cand_str)
                except (ValueError, KeyError):
                    continue  # chain not in our enum / no adapter
                xkey = (
                    cand_chain.value,
                    _address_visited_key(cand_chain, handoff.source_address),
                )
                if xkey in cross_chain_visited:
                    continue
                try:
                    lm_adapter = ChainAdapter.for_chain(cand_chain, (config, env))
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "lock-mint: failed to instantiate %s adapter: %s",
                        cand_chain.value, exc,
                    )
                    continue
                try:
                    match = match_lockmint_destination(
                        handoff, dst_adapter=lm_adapter,
                        window_hours=xchain_window_h or 24.0,
                    )
                    if match is None:
                        # Wave #3: pool / native-swap bridges (Allbridge,
                        # Celer, THORChain) disburse to a DIFFERENT recipient
                        # than the sender, so same-address matching finds
                        # nothing. Follow the DESTINATION bridge contract's
                        # outflows instead (strict amount+time-only → "low").
                        # Reuses lm_adapter while it is still open.
                        _dst_bridge = bridge_address_on_chain(
                            _lm_bridge_db, handoff.bridge_protocol, cand_chain,
                        )
                        if _dst_bridge:
                            match = match_pool_bridge_disbursement(
                                handoff, dst_adapter=lm_adapter,
                                dst_bridge_address=_dst_bridge,
                                window_hours=xchain_window_h or 24.0,
                            )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "lock-mint match failed on %s: %s", cand_chain.value, exc,
                    )
                    match = None
                finally:
                    try:  # noqa: SIM105
                        lm_adapter.close()
                    except Exception:  # noqa: BLE001
                        pass
                if match is None:
                    continue
                cross_chain_visited.add(xkey)
                try:
                    src_bt = datetime.fromisoformat(
                        handoff.block_time_iso.replace("Z", "+00:00")
                    )
                    if src_bt.tzinfo is None:
                        src_bt = src_bt.replace(tzinfo=UTC)
                except (TypeError, ValueError, AttributeError):
                    src_bt = incident_time
                cross_chain_seeds.append(
                    (cand_chain, match.candidate.address, 1, src_bt)
                )
                log.info(
                    "lock-mint match: handoff %s → %s on %s (confidence=%s, "
                    "%.2f%% amount / %.1fh) — continuing BFS as a cross-chain "
                    "CORRELATION lead, not proof",
                    handoff.source_tx_hash[:14], match.candidate.address,
                    cand_chain.value, match.confidence, match.amount_diff_pct,
                    match.delay_seconds / 3600.0,
                )

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
        # Group by destination chain. Also retain the per-chain
        # source-bridge block_times so the post-wave window filter can
        # gate on the earliest handoff timestamp for the chain (a
        # single chain might be the destination of multiple bridges
        # at different times — take the earliest to maximize coverage).
        by_chain: dict[Chain, list[tuple[Address, int]]] = {}
        earliest_src_time_by_chain: dict[Chain, datetime] = {}
        for (dst_chain, dst_addr, depth_hint, src_time) in cross_chain_seeds:
            by_chain.setdefault(dst_chain, []).append((dst_addr, depth_hint))
            cur = earliest_src_time_by_chain.get(dst_chain)
            if cur is None or src_time < cur:
                earliest_src_time_by_chain[dst_chain] = src_time

        log.info(
            "cross-chain BFS continuation: %d seed(s) across %d chain(s) "
            "(window=%.1fh)",
            len(cross_chain_seeds), len(by_chain), xchain_window_h,
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
                # v0.32.1 JACOB_TRACE_AUDIT_v032 CRIT-3 close-out: use the
                # earliest bridge-handoff time INTO this destination chain
                # as the per-dst-chain incident anchor. Previously we
                # passed the source-chain incident_time which caused
                # _process_wave to apply incident_buffer_minutes WINDOW
                # before the SRC theft (a window that excludes legitimate
                # post-bridge outflows once the bridge takes more than a
                # few hours to settle). Falling back to source incident
                # time only if the dst_chain has no entry (defensive —
                # shouldn't happen because by_chain population is from
                # the same loop).
                dst_anchor_time = earliest_src_time_by_chain.get(
                    dst_chain, incident_time,
                )
                try:
                    xchain_results = _process_wave(
                        dst_seeds,
                        adapter=dst_adapter,
                        label_store=label_store,
                        price_client=price_client,
                        policy=policy,
                        incident_time=dst_anchor_time,
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
                # v0.31.0: per-chain time-window filter. When
                # xchain_window_h > 0 we drop destination-chain
                # transfers that fall outside [src_bridge_time,
                # src_bridge_time + window]. window=0 disables the
                # filter (legacy behavior). 'src_bridge_time' is the
                # earliest handoff into this destination chain so
                # later seeds with later source times are still
                # covered.
                src_time = earliest_src_time_by_chain.get(dst_chain)
                if xchain_window_h > 0 and src_time is not None:
                    window_end = src_time + timedelta(hours=xchain_window_h)
                    dropped = 0
                    for _from_addr, _depth, hop_transfers, _is_service in xchain_results:
                        for tx in hop_transfers:
                            if src_time <= tx.block_time <= window_end:
                                new_transfers.append(tx)
                            else:
                                dropped += 1
                    if dropped:
                        log.info(
                            "cross-chain window filter (%.1fh) dropped %d "
                            "out-of-range transfers on %s",
                            xchain_window_h, dropped, dst_chain.value,
                        )
                else:
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

    # v0.32.1 (trace-depth #2 wiring): behavioral endpoint diversity probe.
    # OPT-IN via RECUPERO_ENDPOINT_DIVERSITY_PROBE because it is the more
    # inferential, more EXPENSIVE tier (it fetches the broader in/out activity
    # of the top unlabeled terminal endpoints). Recognizes UNLABELED exchange
    # / service infrastructure (a subpoena lead the label DB missed) from
    # counterparty diversity — capped low/medium confidence, never proof, and
    # NEVER flags a low/asymmetric-diversity address (so a perpetrator's own
    # consolidation hub is not mislabeled as a CEX). Runs on the source-chain
    # adapter only; recorded onto the case for the brief's subpoena section.
    _div_probe_on = os.environ.get(
        "RECUPERO_ENDPOINT_DIVERSITY_PROBE", "",
    ).strip().lower() in ("1", "true", "yes", "on")
    if _div_probe_on:
        try:
            from recupero.trace.endpoint_classifier import (
                infer_infrastructure_endpoints,
            )
            probe_start_block = adapter.block_at_or_before(incident_time)
            infra = infer_infrastructure_endpoints(
                case, adapter=adapter, start_block=probe_start_block,
            )
            if infra:
                case.inferred_infrastructure_endpoints = (
                    list(case.inferred_infrastructure_endpoints) + infra
                )
                log.info(
                    "endpoint-diversity probe: %d unlabeled endpoint(s) "
                    "classified as likely exchange/service infrastructure "
                    "(behavioral correlation, not proof)",
                    len(infra),
                )
        except Exception as exc:  # noqa: BLE001 — probe is best-effort
            log.warning("endpoint-diversity probe failed (non-fatal): %s", exc)


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
    #
    # v0.32.1+ industry-best mode: env var
    # ``RECUPERO_MAX_TRANSFERS_PER_ADDRESS`` overrides the config value
    # per-case. Set to 0 to disable the cap entirely (the BFS still
    # terminates on max_depth + deadline + per-case transfer-cap gates).
    # Default config moved from 500 → 50000 so whale-wallet activity
    # histories are followed in full.
    _cap = config.trace.max_transfers_per_address
    _env_cap_raw = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
    if _env_cap_raw is not None:
        try:
            _cap = int(_env_cap_raw)
        except (TypeError, ValueError):
            log.warning(
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS=%r is not an int; "
                "falling back to config (%d)",
                _env_cap_raw, config.trace.max_transfers_per_address,
            )
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

    # Cap to avoid runaway on chatty addresses. ``_cap`` honors the
    # ``RECUPERO_MAX_TRANSFERS_PER_ADDRESS`` env-var override resolved
    # above; ``_cap <= 0`` disables the slice (industry-best mode).
    if _cap and _cap > 0 and len(raw_outflows) > _cap:
        log.warning(
            "capping outflows from %d to %d for address %s",
            len(raw_outflows), _cap, from_address,
        )
        # v0.34 coverage-honesty: record the truncation so the case carries
        # a "coverage incomplete" notice — dropping the tail of a chatty /
        # poisoned address can hide a real onward hop.
        _COVERAGE_TRUNCATIONS.append({
            "address": from_address,
            "kind": "per_address_fetch_cap",
            "raw_outflows": len(raw_outflows),
            "kept": _cap,
            "dropped": len(raw_outflows) - _cap,
            "hop_depth": hop_depth,
        })
        raw_outflows = raw_outflows[:_cap]

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
        # v0.31.4 (Gap 1a — point-in-time labels): pass incident_time so
        # the label as it stood AT THE TIME OF THEFT is applied, not the
        # label-DB's current state. Critical for older cases — a "this is
        # a known mixer" claim in court has to mean "was a known mixer
        # then," not "is one now."
        label = lookup_pit_safe(label_store, transfer.to_address,
            chain=adapter.chain,
            point_in_time=incident_time,)
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
    # v0.32.1 (chain-audit cycle-2): clamp the decimals exponent at this
    # COMMON sink for every chain adapter. token.decimals is sourced from
    # attacker-influenceable RPC / explorer responses; an unclamped huge
    # value makes 10**decimals build a multi-gigabyte integer before this
    # divide, DoS-ing the BFS hop (OverflowError / unbounded memory). Real
    # tokens never exceed ~24 decimals; u8 (255) is the on-chain ceiling.
    # Adapters also clamp at their own boundary — this is the backstop so
    # no single adapter (or a future one) can blow up the tracer.
    try:
        decimals = max(0, min(int(raw["token"].decimals), 255))
    except (TypeError, ValueError):
        decimals = 0
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
    # v0.32.1 (forensic-audit LOW): dedup on the CANONICAL address key,
    # not the raw string. EIP-55 checksum case is a UI convention — the
    # same EVM address can arrive both checksummed and lower-cased across
    # transfers, and a raw-string set would then list it TWICE in the
    # brief's unlabeled-counterparty list. canonical_address_key lower-
    # cases EVM and preserves case-sensitive base58 (Solana/Tron/BTC), so
    # this collapses casing variants without corrupting non-EVM addresses.
    # The first-seen RAW address is preserved in the output for display.
    from recupero._common import canonical_address_key as _ck
    seen: set[str] = set()
    out: list[Address] = []
    for t in transfers:
        if t.counterparty.label is not None:
            continue
        key = _ck(t.to_address) or t.to_address
        if key not in seen:
            seen.add(key)
            out.append(t.to_address)
    return out


def _apply_dust_attack_filter(case: Case) -> None:
    """v0.31.2 — filter dust-shower destinations from the brief's
    counterparty list.

    ON by default since v0.31.4 (Gap 4). Identifies destination
    addresses that participate in a fan-out shower (>=10 distinct
    sub-$1 destinations from a single source) and removes them from
    `case.unlabeled_counterparties`. The transfers themselves stay
    in `case.transfers` for the audit trail.

    Pre-v0.31.4 this was OFF-by-default to keep existing
    case-rendering tests deterministic. Honest-gaps audit flagged
    this: the filter is the right behavior for production. Tests
    that need the legacy (unfiltered) shape set
    RECUPERO_DUST_ATTACK_FILTER=0 explicitly.

    Env vars (all NaN/Inf-rejecting, clamped to safe ranges):
      * RECUPERO_DUST_ATTACK_FILTER       — set to "0/false/no/off"
                                            to disable (default ON).
      * RECUPERO_DUST_ATTACK_THRESHOLD_USD — default 1.00, clamped [0,100].
      * RECUPERO_DUST_ATTACK_MIN_FANOUT   — default 10, clamped [3,1000].
    """
    flag = os.environ.get("RECUPERO_DUST_ATTACK_FILTER", "").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return
    # Anything else — including unset / "" / "1" / "true" — enables.

    # Threshold env-var parsing — mirror RECUPERO_TRACE_DUST_USD's
    # NaN/Inf-rejecting pattern from v0.31.1.
    threshold_usd = Decimal("1.00")
    raw_thr = os.environ.get("RECUPERO_DUST_ATTACK_THRESHOLD_USD")
    if raw_thr is not None:
        try:
            env_thr = float(raw_thr)
            import math as _m
            if not _m.isfinite(env_thr) or env_thr < 0:
                raise ValueError("non-finite or negative")
            # Clamp to [0, 100] — anything above $100 starts catching
            # legitimate small payments, anything negative is nonsense.
            clamped = max(0.0, min(100.0, env_thr))
            threshold_usd = Decimal(str(clamped))
        except (TypeError, ValueError) as exc:
            log.warning(
                "RECUPERO_DUST_ATTACK_THRESHOLD_USD=%r rejected (%s); "
                "falling back to default $1.00",
                raw_thr, exc,
            )

    # Min-fanout env-var parsing.
    min_fanout = 10
    raw_fan = os.environ.get("RECUPERO_DUST_ATTACK_MIN_FANOUT")
    if raw_fan is not None:
        try:
            env_fan = int(raw_fan)
            # Clamp to [3, 1000]. Below 3 fires on legitimate change-back
            # patterns; above 1000 misses real attacks that stayed
            # modestly sized to evade detection.
            min_fanout = max(3, min(1000, env_fan))
        except (TypeError, ValueError):
            log.warning(
                "RECUPERO_DUST_ATTACK_MIN_FANOUT=%r is not an int; "
                "falling back to default 10",
                raw_fan,
            )

    # Lazy import — keep the dust-attack module out of the hot path
    # when the filter is off (which is the default).
    from recupero.trace.dust_attack import identify_dust_attack_destinations

    # v0.32.1 W1 (round-2 adversary M-5 wire-up): pass case_id so the
    # min_fanout threshold is per-case randomized under HMAC. Without
    # the case_id the function falls back to the fixed default (BC for
    # tests + ad-hoc analysis scripts).
    flagged = identify_dust_attack_destinations(
        case.transfers,
        dust_threshold_usd=threshold_usd,
        min_fanout=min_fanout,
        case_id=case.case_id,
    )
    if not flagged:
        return

    before = len(case.unlabeled_counterparties)
    case.unlabeled_counterparties = [
        a for a in case.unlabeled_counterparties if a not in flagged
    ]
    log.info(
        "dust-attack filter removed %d counterparties from brief "
        "(threshold=$%s, min_fanout=%d; %d -> %d)",
        before - len(case.unlabeled_counterparties),
        threshold_usd, min_fanout, before, len(case.unlabeled_counterparties),
    )


def _sum_usd(transfers: list[Transfer]) -> Decimal | None:
    vals = [t.usd_value_at_tx for t in transfers if t.usd_value_at_tx is not None]
    if not vals:
        return None
    return sum(vals, start=Decimal(0))
