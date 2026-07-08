"""Trace orchestrator.

Implements the algorithm described in docs/TRACE_ALGORITHM.md. Phase 1: single hop.
Phase 2 will add recursion, cycle detection, and policy-driven traversal — leave
the structure friendly to that.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as _futures_wait
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
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
from recupero.trace.address_poisoning import prune_airdrop_spam
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

# v0.34 (operator-requested "elite recall"): per-case accumulator of poison
# edges dropped BEFORE pricing (currently zero-value transfers — the canonical
# address-poisoning primitive). This is NOISE removal, not coverage reduction:
# a zero-value edge moves no funds, so dropping it never hides a real onward
# hop and does NOT flip coverage.complete. Surfaced as an INFORMATIONAL
# ``coverage.poison_edges_pruned`` count for the audit trail. Cleared at the
# start of every ``run_trace`` like the other module-level registries.
_POISON_PRUNED: list[dict[str, Any]] = []

# #253 (real Ronin trace): per-case accumulator of airdrop-spam token edges
# dropped at the wave-aggregation seam (address-poisoning *token* broadcasters —
# a single unpriceable contract spoofing thousands of tiny Transfers from a
# famous address; "Dream Cash"/CASH was 5,980 of 6,000 of the Ronin exploiter's
# sampled rows). NOISE removal, not coverage reduction: these are not transfers
# the address made, so dropping them never hides a real onward hop. Surfaced as
# an INFORMATIONAL ``coverage.airdrop_spam_pruned`` count. Cleared per run.
_SPAM_PRUNED: list[dict[str, Any]] = []


def _clear_coverage_truncations() -> None:
    _COVERAGE_TRUNCATIONS.clear()
    _POISON_PRUNED.clear()
    _SPAM_PRUNED.clear()


def run_trace(
    *,
    chain: Chain,
    seed_address: Address,
    incident_time: datetime,
    case_id: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    case_dir: Path,
    value_trace: bool | None = None,
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
    # v0.34 (operator-requested "elite recall"): per-run override of the
    # service-wallet outflow threshold. A wallet emitting more than this many
    # outflows is treated as a service/distributor and BFS traversal STOPS
    # there (its transfers are kept, but its children are not followed). The
    # default (200) deliberately halts at exchange hot wallets / token
    # distributors, but it also halts at a high-throughput DeFi aggregator /
    # pool that sits ON the laundering path — silently missing everything past
    # it. Raise this (e.g. 25000) for a deep recall-complete run so the trace
    # crosses the aggregator while still stopping at true mega-services.
    # Process env (not .env), mirroring the other RECUPERO_* trace knobs;
    # clamped to >= 1; bad/blank/non-positive values keep the resolved default.
    _sw_env = os.environ.get("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD")
    if _sw_env is not None and _sw_env.strip():
        try:
            _sw_val = int(_sw_env)
        except (TypeError, ValueError):
            log.warning(
                "RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD=%r is not an int; "
                "keeping %d", _sw_env, policy.service_wallet_outflow_threshold,
            )
        else:
            if _sw_val >= 1:
                policy.service_wallet_outflow_threshold = _sw_val
            else:
                log.warning(
                    "RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD=%r must be >= 1; "
                    "keeping %d", _sw_env,
                    policy.service_wallet_outflow_threshold,
                )

    # #253 (real Ronin trace) — airdrop-spam token filter. A famous/sanctioned
    # seed is flooded with unpriceable spam-token Transfers spoofing `from` (the
    # Ronin exploiter: 99% of recorded transfers were one "CASH" broadcaster).
    # They bypass the zero-value poison prune (non-zero amount) AND the USD dust
    # filter (usd=None can't be compared to a $ threshold), so they bloat the
    # case + starve the trace budget. Default ON; RECUPERO_SPAM_TOKEN_FILTER=0
    # disables it; RECUPERO_SPAM_TOKEN_MIN_TRANSFERS tunes the per-contract
    # broadcaster threshold (an unpriceable ERC-20 appearing >= this many times
    # from one address is spam). Dropping is forensically correct (these aren't
    # transfers the address made) and preserves the follow-largest-unpriced-leg
    # doctrine — a real unpriced leg appears a handful of times, far below it.
    _spam_filter_enabled = (
        os.environ.get("RECUPERO_SPAM_TOKEN_FILTER", "1").strip().lower()
        not in ("0", "false", "no", "off")
    )
    _spam_min_count = 25
    _spam_env = os.environ.get("RECUPERO_SPAM_TOKEN_MIN_TRANSFERS")
    if _spam_env is not None and _spam_env.strip():
        try:
            _spam_min_count = max(2, int(_spam_env))
        except (TypeError, ValueError):
            log.warning(
                "RECUPERO_SPAM_TOKEN_MIN_TRANSFERS=%r is not an int; keeping %d",
                _spam_env, _spam_min_count,
            )

    # v0.34.5 — "never fully skip the money path." A high-fan-out node used to be
    # SKIPPED entirely (no recursion) to avoid BFS explosion — but that dead-ends
    # the trace at the SEED itself when the seed is a perpetrator splitter (the
    # Lazarus/Ronin generalization case: 8827 outflows > threshold → depth-0
    # dead-end, never reaching the laundering downstream). Fix: follow the TOP-N
    # outflows BY VALUE instead of skipping. The seed (the investigation subject —
    # every outflow is theft dispersal) gets a generous N; deeper high-fan-out
    # nodes get a tighter N so branching stays finite (visited-set +
    # stop_at_exchange + max_depth + per-case budget bound the rest). Children
    # gain an inbound reference via _consider_enqueue, so they trace
    # value-DIRECTED from there. Set either to 0 to restore the legacy skip.
    def _topn_env(name: str, default: int) -> int:
        v = os.environ.get(name)
        if v is not None and v.strip():
            try:
                return max(0, int(v))
            except (TypeError, ValueError):
                log.warning("%s=%r is not an int; keeping %d", name, v, default)
        return default
    _seed_follow_topn = _topn_env("RECUPERO_SEED_FOLLOW_TOPN", 50)
    _sw_follow_topn = _topn_env("RECUPERO_SERVICE_WALLET_FOLLOW_TOPN", 8)

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
    # Self-imposed deadline so the worker writes a partial case + emits the
    # brief gracefully rather than running unbounded. The worker's background
    # heartbeat thread keeps the claimed row fresh throughout the trace (the
    # legacy 540s default already exceeds the 300s stale window and relies on
    # that heartbeat), so a longer deadline is safe.
    # v0.37.5 (deep-reach cleanup, Tier 1): the default is now deep-reach-aware
    # — 1800s (30 min) under the deep-reach default, 540s (9 min) on the legacy
    # shallow path. Deep + cross-chain + multi-bridge tracing legitimately needs
    # more wall-clock; without the higher ceiling a deep multi-chain trace would
    # stamp itself incomplete (the very under-coverage deep-reach fixes). An
    # explicit RECUPERO_TRACE_TIMEOUT_SEC always wins.
    if "RECUPERO_TRACE_TIMEOUT_SEC" in os.environ:
        try:
            trace_deadline_sec = int(os.environ["RECUPERO_TRACE_TIMEOUT_SEC"])
        except (TypeError, ValueError):
            trace_deadline_sec = 540
    else:
        trace_deadline_sec = 1800 if _deep_reach_enabled() else 540
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

    # v0.34 (operator-requested "elite recall"): value-directed tracing. When
    # RECUPERO_VALUE_TRACE is on, a high-fan-out node (service wallet /
    # aggregator / pool) is not a dead end: we value-match the inbound funds
    # against the node's outflows and follow ONLY the edge(s) whose amount
    # (same-asset) or USD value (across a swap) match. ``inbound_by_key`` maps
    # an address-key to ALL edges that delivered funds there — a node commonly
    # receives our funds via several transfers (e.g. ETH dust + a large token
    # leg), and value-matching must reference the LARGEST (our actual funds),
    # not whichever edge happened to be seen first. ``value_matched``
    # accumulates the per-hop provenance (confidence calibrated — never "high").
    # v0.35.4 — RECUPERO_DEEP_REACH master switch. One knob to turn on the whole
    # deep-reach recipe (value-trace + split-follow + labeled-terminals +
    # dormancy-aware window) for cold-case "go as deep as possible" tracing,
    # instead of remembering 4 separate env vars. It only fills in knobs that are
    # NOT individually set — an explicit per-knob env var (or the value_trace
    # arg) always wins, so you can deep-reach but pin one knob off. Default OFF
    # ⇒ every existing trace (incl. Zigha 4/4) is byte-identical.
    def _truthy(name: str) -> bool:
        return os.environ.get(name, "0").strip().lower() in ("1", "true", "yes", "on")

    # v0.37.0: deep-reach is the DEFAULT (resolved by the module-level
    # _deep_reach_enabled so run_trace + the bridge oracle agree). Opt out
    # with RECUPERO_DEEP_REACH=0. Per-knob env vars below still win when set.
    _deep_reach = _deep_reach_enabled()

    # Explicit ``value_trace`` arg wins (used by the multi-chain perpetrator
    # pivot to force directed tracing on a re-trace); else the env var if set;
    # else the deep-reach default.
    _value_trace_enabled = (
        value_trace if value_trace is not None
        else (_truthy("RECUPERO_VALUE_TRACE")
              if "RECUPERO_VALUE_TRACE" in os.environ else _deep_reach)
    )
    # v0.34.6: recover a 1:N same-asset SPLIT/peel when no 1:1 hop matched (low
    # confidence). Individually opt-in; also on under deep-reach.
    _follow_splits = (
        _truthy("RECUPERO_VALUE_TRACE_FOLLOW_SPLITS")
        if "RECUPERO_VALUE_TRACE_FOLLOW_SPLITS" in os.environ else _deep_reach
    )
    # v0.34.7: STOP-AND-FLAG at a labeled mixer/exchange/bridge terminal (record,
    # don't chase) — TRM/Chainalysis mixer handling. Opt-in; on under deep-reach.
    _label_terminals_enabled = (
        _truthy("RECUPERO_VALUE_TRACE_LABELED_TERMINALS")
        if "RECUPERO_VALUE_TRACE_LABELED_TERMINALS" in os.environ else _deep_reach
    )
    # v0.35.2: dormancy-aware value-match window. Default 72h (conservative);
    # deep-reach defaults it to 0 (lower-bound-only — match a dormant onward hop
    # moved weeks/months later). An explicit env value always wins.
    if "RECUPERO_VALUE_TRACE_WINDOW_HOURS" in os.environ:
        _value_window_hours = _topn_env("RECUPERO_VALUE_TRACE_WINDOW_HOURS", 72)
    else:
        _value_window_hours = 0 if _deep_reach else 72
    inbound_by_key: dict[str, list[Transfer]] = {}
    value_matched: list[dict[str, Any]] = []
    # v0.34.7: labeled terminals recorded at directed dead-ends (mixer/exchange/
    # bridge endpoints the traced funds reached). Audit-trail provenance.
    value_labeled_terminals: list[dict[str, Any]] = []
    # v0.34.1 coverage-honesty: directed (value-trace) nodes that MOVED funds
    # onward (had outflows) but where we followed NOTHING — a potential
    # incompleteness (an onward hop we couldn't match: below tolerance, an
    # unpriced cross-asset conversion, etc.). Distinct from a true resting
    # terminal (no outflows). Feeds coverage.complete=False + a recommendation.
    _value_dead_ends: list[dict[str, Any]] = []

    # v0.34: the per-transfer enqueue decision, factored out so the normal
    # breadth-first path AND the value-matched service-wallet path share the
    # exact same visited / contract / should_traverse gating. Returns True iff
    # ``transfer``'s destination was newly enqueued. Closes over the loop-local
    # ``next_wave`` (resolved at call time) plus the stable per-case caches.
    def _consider_enqueue(transfer: Transfer, parent_depth: int) -> bool:
        dest = transfer.to_address
        dest_key = _address_visited_key(chain, dest)
        # Record EVERY value-bearing edge to ``dest`` BEFORE any gate (traverse
        # or visited) so value-matching at dest references the LARGEST inbound
        # (our funds), decoupled from the traverse decision — a node funded by
        # several edges (e.g. ETH dust THEN a large token leg) must match against
        # the largest, and a larger inbound arriving on a non-traversable edge
        # must still inform the match rather than being dropped before recording.
        inbound_by_key.setdefault(dest_key, []).append(transfer)
        if not policy.should_traverse(transfer):
            return False
        if dest_key in visited:
            return False
        # Contract check: one RPC per unique address, cached. Single-threaded
        # between waves, so is_contract_cache needs no lock. Routed through
        # contract_detection.is_contract so a transient RPC failure doesn't
        # poison the cache as is_contract=True forever (returns None on
        # twice-failed RPC, leaving the cache untouched for a later re-resolve).
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
                        log.debug(
                            "is_contract uncertain for %s (%s); treating as "
                            "contract for this hop", dest, _reason,
                        )
                        is_contract_cache[dest_key] = True
                    else:
                        is_contract_cache[dest_key] = result_bool
                except Exception as e:  # noqa: BLE001
                    log.debug("is_contract check failed for %s: %s", dest, e)
                    is_contract_cache[dest_key] = True
            if is_contract_cache[dest_key]:
                return False
        next_wave.append((dest, parent_depth + 1))
        visited.add(dest_key)
        # (inbound edge already recorded above, before the visited guard.)
        return True

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
                value_trace=_value_trace_enabled,
                deadline=trace_deadline,
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

            # #253: drop address-poisoning airdrop-spam token edges BEFORE they
            # are recorded / value-matched / enqueued. A single unpriceable spam
            # contract can spoof thousands of tiny Transfers from a famous seed
            # (Ronin: 99% of rows were one "CASH" broadcaster); leaving them in
            # bloats the case, burns the per-case transfer cap, and floods the
            # next wave with junk recipients before the real path is reached.
            # These are not transfers the address made, so this is noise removal,
            # not coverage loss; a real unpriced stolen leg appears too few times
            # to trip the per-contract threshold (follow-unpriced doctrine intact).
            if _spam_filter_enabled and hop_transfers:
                hop_transfers, _spam_dropped = prune_airdrop_spam(
                    hop_transfers, min_count=_spam_min_count,
                )
                if _spam_dropped:
                    _SPAM_PRUNED.append(
                        {"address": from_addr, "depth": depth,
                         "pruned": len(_spam_dropped)}
                    )
                    log.info(
                        "airdrop-spam: pruned %d unpriced spam-token edge(s) from "
                        "%s (depth %d)", len(_spam_dropped), from_addr, depth,
                    )

            # v0.34 value-directed tracing ("follow the money"). When
            # RECUPERO_VALUE_TRACE is on, EVERY non-origin node (one reached via
            # a known inbound edge) follows ONLY the outflow(s) whose value
            # matches the funds that arrived — not all of them. This is what
            # bounds the trace to the laundering PATH (<=K onward hops per node)
            # instead of exploding the whole graph: an uncapped breadth-first
            # follow-everything fans out combinatorially over depth, but a
            # directed value-trace stays narrow. The seed (depth 0, no inbound)
            # still follows all of its outflows — every post-incident outflow
            # from the victim is suspect. At max depth we record but don't
            # recurse. Confidence is calibrated in value_matching (never "high").
            # Reference the LARGEST-USD inbound to this node — that is our
            # traced funds (a node often also receives ETH-dust / poison edges;
            # matching against those would miss the real onward hop). Unpriced
            # inbounds sort as 0 so a priced leg always wins when present.
            _inbounds = inbound_by_key.get(
                _address_visited_key(chain, from_addr)
            ) or []
            # v0.34.1: trace the largest priced leg AND the largest UNPRICED leg
            # (an exact same-asset match must be followed even when the asset has
            # no price — e.g. the stolen funds arrived as unpriced msyrupUSDp).
            _traced_inbounds = _select_traced_inbounds(
                _inbounds, policy.dust_threshold_usd,
            )
            directed = (
                _value_trace_enabled
                and bool(_traced_inbounds)
                and depth + 1 < policy.max_depth
            )

            if directed:
                # Keep ONLY the matched money-path hop(s) on the case — not the
                # node's full (possibly commingled) outflow set. Match each
                # traced inbound leg; dedup the followed hops (the priced + the
                # unpriced leg can land on the same outflow).
                followed = 0
                matched_transfers: list[Transfer] = []
                _seen_hops: set[tuple[str, str]] = set()
                for _inb in _traced_inbounds:
                    _f, _matched = _value_match_and_enqueue(
                        inbound_transfer=_inb,
                        node_outflows=hop_transfers,
                        parent_depth=depth,
                        node_addr=from_addr,
                        enqueue_fn=_consider_enqueue,
                        provenance_sink=value_matched,
                        follow_splits=_follow_splits,
                        window_hours=_value_window_hours,
                    )
                    followed += _f
                    for _mt in _matched:
                        _hk = (_mt.tx_hash, (_mt.to_address or "").lower())
                        if _hk in _seen_hops:
                            continue
                        _seen_hops.add(_hk)
                        matched_transfers.append(_mt)
                # v0.34.7 (opt-in): STOP-AND-FLAG at a labeled terminal. Same-
                # asset outflows landing at a labeled mixer/exchange/bridge are
                # the traced money's end state — KEEP them (real, label-enriched
                # → the brief classifies UNRECOVERABLE/EXCHANGE/etc. with no extra
                # work) but do NOT traverse (a mixer is the end; an exchange is a
                # subpoena target; a bridge is a separate cross-chain handoff).
                # This is what carries the Ronin trace to "→ Tornado Cash →
                # UNRECOVERABLE" instead of chasing ~216 identical pool deposits.
                _term_records: list[dict[str, Any]] = []
                _term_kept: list[Transfer] = []
                if _label_terminals_enabled:
                    _term_records, _term_tx = _detect_labeled_terminals(
                        inbound=_traced_inbounds[0],
                        node_outflows=hop_transfers,
                        node_addr=from_addr,
                        depth=depth,
                    )
                    if _term_records:
                        value_labeled_terminals.extend(_term_records)
                        _matched_ids = {mt.transfer_id for mt in matched_transfers}
                        for _tt in _term_tx:
                            if (
                                _tt.transfer_id not in _matched_ids
                                and policy.should_include(_tt)
                            ):
                                _term_kept.append(_tt)
                                _matched_ids.add(_tt.transfer_id)
                        log.info(
                            "labeled-terminal: node %s (depth=%d) → %d terminal(s): %s",
                            from_addr, depth, len(_term_records),
                            ", ".join(
                                f"{r['label_name']} [{r['status']}] "
                                f"{r['tx_count']}tx {r['agg_amount']} {r['token'] or ''}"
                                for r in _term_records
                            ),
                        )
                # Coverage honesty: this node FORWARDED THE SAME ASSET it
                # received but we followed NOTHING — a real incompleteness (the
                # asset moved onward and our matcher missed it: a split past
                # tolerance, a conversion, a poison-obscured hop). A true resting
                # terminal (no same-asset outflow) is NOT flagged — that's where
                # the funds legitimately sit. A node whose same-asset outflow went
                # to a LABELED terminal is NOT a dead-end — we resolved its end
                # state (recorded above), so don't double-flag it.
                if (
                    followed == 0
                    and not _term_records
                    and hop_transfers
                    and _node_forwarded_inbound_asset(_traced_inbounds[0], hop_transfers)
                ):
                    _ib0 = _traced_inbounds[0]
                    _itok = getattr(_ib0, "token", None)
                    _value_dead_ends.append({
                        "address": from_addr,
                        "depth": depth,
                        "inbound_token": (
                            (getattr(_itok, "symbol", None) or "").upper() or None
                            if _itok else None
                        ),
                        "inbound_amount": str(_ib0.amount_decimal or ""),
                        "inbound_unpriced": _ib0.usd_value_at_tx is None,
                        "node_outflow_count": len(hop_transfers),
                    })
                all_transfers.extend(matched_transfers)
                all_transfers.extend(_term_kept)
                # Finalize: write evidence for the matched hop(s). (The
                # service-wallet lightweight pass skipped per-outflow evidence;
                # the full path already wrote it — re-writing is an idempotent
                # file write.)
                for _mt in matched_transfers:
                    try:
                        write_evidence_receipt(
                            adapter, _mt.tx_hash, case_dir / "tx_evidence",
                        )
                    except Exception as _ev_exc:  # noqa: BLE001
                        log.warning(
                            "evidence receipt failed for matched hop tx=%s: %s",
                            _mt.tx_hash, _ev_exc,
                        )
                log.info(
                    "value-trace %s (depth=%d): %d outflow(s) -> %d matched "
                    "onward hop(s) followed",
                    from_addr, depth, len(hop_transfers), followed,
                )
                continue

            # Non-directed: the seed (no inbound), at/near max depth, or
            # value-trace OFF. Keep the full outflow set for the audit trail —
            # but dust-filter it. A node built under the lightweight pass SKIPS
            # the per-outflow dust filter (it's applied later only to matched
            # hops); a terminal-depth lightweight node is non-directed, so
            # without this it would extend its sub-dust / poison edges into the
            # case. ``should_include`` is idempotent for full-path transfers
            # (they already passed it in _trace_one_hop), so this only filters
            # the lightweight-built set. (v0.34 audit fix — coverage hygiene.)
            all_transfers.extend(
                t for t in hop_transfers if policy.should_include(t)
            )

            if depth + 1 >= policy.max_depth:
                continue

            # High-fan-out ("service-wallet") node. We must NOT queue ALL its
            # outflows (a genuine exchange has 100k+ to unrelated users → BFS
            # explosion) — but we must NEVER fully skip it either: the SEED is the
            # investigation subject (its every outflow is theft dispersal) and a
            # mid-route splitter is the laundering path. v0.34.5: FOLLOW THE MONEY
            # — enqueue the top-N outflows by value (USD desc, then raw amount).
            # Bounded N keeps branching finite; children become value-DIRECTED via
            # _consider_enqueue's inbound_by_key recording, so the deep recursion
            # then runs through the directed (value-matched) branch above. N=0
            # restores the legacy skip.
            #
            # GATED ON value-trace: this top-N follow is only sound under
            # "follow the money" mode, where the enqueued children become
            # value-directed (bounded). Under value-trace OFF (legacy
            # breadth-first), the children would themselves be non-directed and
            # fan out combinatorially — so a service wallet stays a dead end,
            # byte-identical to pre-v0.34.5 behavior (the seed, with no inbound,
            # is non-directed under value-trace too — which is exactly the
            # Lazarus/Ronin dead-end this fix targets).
            if is_service_wallet:
                follow_n = (
                    (_seed_follow_topn if depth == 0 else _sw_follow_topn)
                    if _value_trace_enabled else 0
                )
                if follow_n <= 0:
                    log.info(
                        "service-wallet skip (follow_topn=0): not queueing %d "
                        "destinations from %s", len(hop_transfers), from_addr,
                    )
                    continue
                ranked = sorted(
                    hop_transfers,
                    key=lambda t: (
                        float(t.usd_value_at_tx) if t.usd_value_at_tx is not None
                        else 0.0,
                        float(t.amount_decimal or 0),
                    ),
                    reverse=True,
                )
                enq = sum(
                    1 for transfer in ranked[:follow_n]
                    if _consider_enqueue(transfer, depth)
                )
                log.info(
                    "service-wallet %s (depth=%d): high fan-out (%d outflows) — "
                    "following top-%d by value (%d queued for deeper trace)",
                    from_addr, depth, len(hop_transfers), follow_n, enq,
                )
                continue

            for transfer in hop_transfers:
                _consider_enqueue(transfer, depth)

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

    # v0.34 coverage-honesty (operator-requested): the coverage computation —
    # poisoning detection, per-address cap truncations, no-data, and the
    # ``coverage.complete`` flag — runs AFTER the DEX/bridge continuation pass
    # (see the block just before ``_apply_dust_attack_filter`` below), NOT
    # here. Computing it here (pre-continuation) silently dropped (a) cap
    # truncations from the continuation pass — the deep, chatty aggregator/pool
    # addresses are typically only reached there, never in the primary BFS — and
    # (b) the final ``trace_status`` (e.g. ``partial_budget_hit`` the
    # continuation pass can set), so a truncated trace was stamped ``complete``.

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

    # v0.34 (operator-requested coverage-honesty): a trace that ran with
    # reduced parameters — a per-address fetch cap that truncated an
    # address, and/or address-poisoning that inflated the transfer graph —
    # may have DROPPED a real onward hop. An LE deliverable must never imply
    # completeness in that case. Detect poisoning (best-effort; never breaks
    # a trace) + read the per-address cap truncations recorded during the
    # wave loop AND the DEX/bridge continuation pass, and surface a loud
    # notice recommending a recall-complete re-run. ``coverage.complete`` is
    # True ONLY when the trace finished cleanly AND nothing reduced coverage.
    #
    # This runs AFTER ``_continue_past_dex_and_bridges`` (above) on purpose:
    #   (a) the continuation pass is where the deep, chatty aggregator/pool
    #       addresses are typically reached, so it is where the per-address
    #       fetch cap usually fires — capturing truncations before it ran
    #       silently reported zero and stamped a capped trace ``complete``;
    #   (b) the continuation pass can downgrade ``trace_status`` (e.g.
    #       ``partial_budget_hit``), and ``complete`` must reflect that final
    #       status.
    # It reads ``case.transfers`` (the FULL post-continuation graph — the
    # continuation rebinds it), not the primary-only ``all_transfers``.
    try:
        from recupero.trace.address_poisoning import detect_poisoning_attempts
        _poison_events = detect_poisoning_attempts(case.transfers, seed_address)
    except Exception as _pe:  # noqa: BLE001
        log.debug("poisoning detection failed (non-fatal): %s", _pe)
        _poison_events = []
    _cap_truncations = list(_COVERAGE_TRUNCATIONS)
    _poison_pruned = list(_POISON_PRUNED)
    try:
        _resolved_addr_cap = int(os.environ.get(
            "RECUPERO_MAX_TRANSFERS_PER_ADDRESS",
            str(config.trace.max_transfers_per_address),
        ))
    except (TypeError, ValueError):
        _resolved_addr_cap = config.trace.max_transfers_per_address
    _coverage_reduced = (
        bool(_cap_truncations) or bool(_poison_events) or bool(_value_dead_ends)
    )
    # v0.34 (coverage-honesty hardening): a trace that fetched ZERO transfers
    # is NEVER "complete" — it is almost always an API key/access failure
    # (invalid or rate-limited key returning NOTOK), a wrong seed/incident
    # time, or a dead RPC — NOT a genuinely empty wallet. Previously such a
    # run wrote trace_status="complete" + coverage.complete=True (no cap, no
    # poisoning, no timeout), silently presenting an utterly empty trace as a
    # finished one. That is the exact silent-incompleteness this notice exists
    # to prevent, so an empty result must flip complete=False with a loud,
    # distinct recommendation.
    _no_data = not case.transfers
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
        _dead_end_note = (
            (f" Additionally, {len(_value_dead_ends)} node(s) FORWARDED the "
             "traced asset onward but no onward hop could be matched (a split "
             "past tolerance, an asset conversion, or a poison-obscured hop) — "
             "the trail continues beyond what is recorded at: "
             + ", ".join(
                 f"{d['address']}"
                 f"{' [' + d['inbound_token'] + ']' if d.get('inbound_token') else ''}"
                 for d in _value_dead_ends[:5]
             )
             + ("…" if len(_value_dead_ends) > 5 else "") + ".")
            if _value_dead_ends else ""
        )
        _recommendation = (
            "Coverage may be INCOMPLETE: address-poisoning, a per-address fetch "
            "cap, and/or an unmatched onward hop was in effect, so funds split "
            "below the dust floor, sent beyond the fetch cap, routed past the "
            "depth limit, or moved through a conversion the matcher could not "
            "follow can be missed. Before relying on completeness for asset "
            "recovery, re-run recall-complete (e.g. --max-depth 8 "
            "--dust-threshold-usd 50 with RECUPERO_MAX_TRANSFERS_PER_ADDRESS=0), "
            "ideally on a paid API tier." + _dead_end_note
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
            # Informational: zero-value poison edges dropped pre-pricing. This
            # is NOISE removal (a zero-value edge moves no funds), so it does
            # NOT feed ``_coverage_reduced`` / flip ``complete`` — unlike the
            # fetch-cap truncations above, which can hide a real onward hop.
            "poison_edges_pruned": sum(p.get("pruned", 0) for p in _poison_pruned),
            "poison_pruned_addresses": len(_poison_pruned),
            # #253: airdrop-spam token edges dropped at wave aggregation. Like
            # poison_edges_pruned this is NOISE removal (spoofed broadcasts the
            # address never made), so it does NOT flip ``complete``.
            "airdrop_spam_pruned": sum(p.get("pruned", 0) for p in _SPAM_PRUNED),
            "airdrop_spam_pruned_addresses": len(_SPAM_PRUNED),
            # Value-directed onward hops followed through high-fan-out nodes
            # (RECUPERO_VALUE_TRACE). Each carries calibrated confidence
            # (medium/low — never high) + the match basis, so the deliverable
            # can present them as INFERENCE leads, not asserted identity.
            "value_matched_hops": list(value_matched),
            # v0.34.1: nodes that forwarded the traced asset onward but where no
            # onward hop could be matched (a real incompleteness — the trail
            # continues beyond what's recorded). Flips complete=False.
            "value_dead_ends": list(_value_dead_ends),
            # v0.34.7: labeled terminals the traced funds reached (mixer/
            # exchange/bridge) — the money's resolved end state, stop-and-
            # flagged (recorded) rather than chased deposit-by-deposit.
            "labeled_terminals": list(value_labeled_terminals),
            "reduced_parameters": {
                "max_depth": int(cfg_max_depth),
                "dust_threshold_usd": float(config.trace.dust_threshold_usd),
                "max_transfers_per_address": int(_resolved_addr_cap),
            },
            "recommendation": _recommendation,
        },
    }

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


def _tx_within_window(
    tx: Transfer,
    src_time: datetime | None,
    window_end: datetime | None,
) -> bool:
    """True if ``tx`` is an in-scope onward hop of bridged funds.

    LOWER bound (always, when ``src_time`` is known): the hop must occur AT OR
    AFTER the bridge handoff — pre-bridge activity on a (possibly reused)
    destination address is not the onward movement of these funds.

    UPPER bound (only when ``window_end`` is set): the hop must be within the
    operator-configured settlement window. **By default there is NO upper
    bound** — laundering parks funds and moves them LATER, so a dormant
    destination funded days/weeks after the bridge MUST still be followed
    (v0.34.4: the prior 24h cap silently dropped the dormant DAI holders in the
    Zigha case — ~$16.9M of traced-but-recoverable-later funds). We rely on
    value-direction + the high-confidence handoff gate to stay on the laundered
    money rather than a time cap. ``src_time is None`` disables the filter.
    """
    if src_time is None:
        return True
    if tx.block_time < src_time:
        return False
    if window_end is None:
        return True
    return tx.block_time <= window_end


def _collect_swap_output_seeds(
    transfers: list[Transfer],
    *,
    chain: Chain,
    adapter: ChainAdapter,
    visited: set[str],
    dex_router_db: dict[str, dict] | None = None,
) -> list[Address]:
    """Resolve DEX-aggregator (0x / Matcha settler-style) swap OUTPUT recipients
    among ``transfers`` and return the NEW ones to follow on ``chain``.

    Shared by the source-chain continuation AND the cross-chain destination
    continuation so a token->DAI swap is followed regardless of which chain it
    happened on. ``adapter`` MUST be the adapter for ``chain``: a settler swap
    whose output isn't already present in ``transfers`` is recovered from the
    swap tx's RECEIPT LOGS via that adapter (``detect_dex_swaps(..., adapter=
    adapter)``) — the destination chain's settler payout is invisible to the
    source-chain adapter, which is exactly why this must run per-chain.

    Only HIGH-confidence in-trace outputs and log-resolved (``output_source ==
    'receipt_logs'``) outputs are returned — never a low/medium in-trace guess.
    A DEX swap output is paid on the swap's OWN chain, so every returned
    recipient is a same-chain seed. Marks each returned recipient in ``visited``
    so the caller won't re-enqueue it.
    """
    from recupero.trace.dex_swaps import detect_dex_swaps

    if not transfers:
        return []
    # detect_dex_swaps reads only ``.transfers`` — a lightweight view keeps this
    # reusable for the destination-chain pass (whose transfers aren't a Case).
    view = SimpleNamespace(transfers=list(transfers))
    try:
        swaps = detect_dex_swaps(view, dex_router_db, adapter=adapter)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "dex-swap detection failed on %s; skipping continuation: %s",
            chain.value, exc,
        )
        return []

    seeds: list[Address] = []
    for swap in swaps:
        # Follow HIGH-confidence in-trace swap outputs AND log-resolved outputs
        # (medium, but structurally certain — the Transfer event is on-chain).
        # The latter is what crosses a 0x token->DAI swap that would otherwise
        # dead-end at the settler.
        if swap.confidence != "high" and (
            getattr(swap, "output_source", "in_trace") != "receipt_logs"
        ):
            continue
        if not swap.output_recipient:
            continue
        recipient = swap.output_recipient
        recipient_key = _address_visited_key(chain, recipient)
        if recipient_key in visited:
            continue
        seeds.append(recipient)
        visited.add(recipient_key)
    return seeds


def _collect_onward_value_seeds(
    transfers: list[Transfer],
    *,
    chain: Chain,
    adapter: ChainAdapter,
    policy: TracePolicy,
    visited: set[str],
    src_time: datetime | None,
    window_end: datetime | None,
) -> list[Address]:
    """v0.37.1 (deep cross-chain #1): return the NEW value-bearing onward
    recipients to follow on ``chain`` among ``transfers`` — generic onward
    hops, not just DEX-swap outputs.

    This is what makes the cross-chain destination trace go DEEP: the first
    cross-chain wave captures the bridge receiver's direct outflows (one hop);
    a plain ``receiver -> wallet -> ... -> exchange`` trail on the destination
    chain would otherwise dead-end after that hop because the dest-continuation
    loop only chased swap outputs. This collector follows the generic onward
    movement to the configured wave depth.

    Explosion-safe — gated identically to the primary BFS enqueue
    (``_consider_enqueue``):
      * ``policy.should_traverse`` (dust threshold + labeled mixer/exchange/
        bridge STOP + same-asset/value gating the policy already applies),
      * cross-chain time window (drop hops outside [src_bridge, +window]),
      * ``stop_at_contract`` (don't recurse into a router/pool contract),
      * visited-set dedup.
    The CALLER additionally excludes transfers whose SOURCE node was a
    high-fan-out service wallet (``is_service``) so a commingling node on the
    destination chain doesn't fan the trace out — same dead-end-a-service-
    wallet rule the primary BFS uses. Bounded further by the per-case transfer
    cap + API budget + ``RECUPERO_DEST_CONTINUATION_WAVES`` already in force.
    """
    seeds: list[Address] = []
    for tx in transfers:
        if not _tx_within_window(tx, src_time, window_end):
            continue
        if not policy.should_traverse(tx):
            continue
        dest = tx.to_address
        dest_key = _address_visited_key(chain, dest)
        if dest_key in visited:
            continue
        if policy.stop_at_contract:
            try:
                if adapter.is_contract(dest):
                    visited.add(dest_key)
                    continue
            except Exception:  # noqa: BLE001
                pass  # treat as EOA on lookup failure
        seeds.append(dest)
        visited.add(dest_key)
    return seeds


def _confirm_bridge_handoffs(
    handoffs: list[Any],
    *,
    src_adapter: ChainAdapter,
    config: RecuperoConfig,
    env: RecuperoEnv,
    window_hours: float,
    incident_time: datetime,
) -> list[tuple[Any, Any, datetime]]:
    """Cryptographically CONFIRM each cross-chain handoff's destination via the
    bridge-pairing oracle — the protocol's own order/message id matched on BOTH
    chains (``bridge_pairings.confirm_bridge_destination``). This is the only
    cross-chain edge basis that is genuine proof (vs the heuristic calldata
    decode / amount-time correlation). Best-effort; never raises.

    Returns ``(handoff, ConfirmedDestination, src_block_time)`` per confirmed
    handoff. Opt-in caller-gated (``RECUPERO_BRIDGE_CONFIRM``) — it fetches the
    source receipt and queries the destination chain's logs.
    """
    from recupero.trace.bridge_pairings import (
        confirm_bridge_destination,
        get_pair_spec,
        identify_source,
    )

    out: list[tuple[Any, Any, datetime]] = []
    seen_order_ids: set[str] = set()
    for h in handoffs:
        protocol = getattr(h, "bridge_protocol", None)
        if get_pair_spec(protocol) is None:
            continue
        try:
            ev = src_adapter.fetch_evidence_receipt(h.source_tx_hash)
            src_receipt = getattr(ev, "raw_receipt", None)
            ev_block_time = getattr(ev, "block_time", None)
        except Exception as exc:  # noqa: BLE001
            log.debug("bridge-confirm: source receipt fetch failed: %s", exc)
            continue
        # protocol id + destination chain from the source event (robust to
        # periphery entrypoints); fall back to the calldata-decoded dest chain.
        ident = identify_source(src_receipt)
        order_id = ident[1] if ident else None
        dest_chain_str = (
            (ident[2] if ident else None)
            or getattr(h, "decoded_destination_chain", None)
        )
        if not dest_chain_str:
            continue
        try:
            dest_chain = Chain(dest_chain_str)
        except (ValueError, KeyError):
            continue
        try:
            src_iso = (h.block_time_iso or "").replace("Z", "+00:00")
            sbt = datetime.fromisoformat(src_iso)
            if sbt.tzinfo is None:
                sbt = sbt.replace(tzinfo=UTC)
        except (TypeError, ValueError, AttributeError):
            sbt = ev_block_time or incident_time
        try:
            dst_adapter = ChainAdapter.for_chain(dest_chain, (config, env))
        except Exception as exc:  # noqa: BLE001
            log.warning("bridge-confirm: dst adapter for %s failed: %s", dest_chain_str, exc)
            continue
        src_chain_val = (
            h.source_chain.value if getattr(h, "source_chain", None) else None
        )
        try:
            confirmed = confirm_bridge_destination(
                protocol=protocol,
                destination_chain=dest_chain_str,
                source_receipt=src_receipt,
                dst_adapter=dst_adapter,
                src_block_time=sbt,
                source_chain=src_chain_val,
                window_hours=window_hours or 24.0,
                order_id=order_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("bridge-confirm failed for %s: %s", protocol, exc)
            confirmed = None
        finally:
            try:  # noqa: SIM105
                dst_adapter.close()
            except Exception:  # noqa: BLE001
                pass
        if confirmed and confirmed.order_id not in seen_order_ids:
            seen_order_ids.add(confirmed.order_id)
            out.append((h, confirmed, sbt))
    return out


def _deep_reach_enabled() -> bool:
    """v0.37.0: DEEP REACH IS THE DEFAULT.

    Recupero goes deep on every trace — value-directed tracing through
    aggregators/service wallets, 1:N split/peel following, dormancy-aware
    (no-upper-cap) value window, stop-and-flag at labeled mixer/exchange/
    bridge terminals, and cryptographic cross-chain bridge confirmation.
    "Halfway" tracing (dead-ending at the first service wallet, never
    crossing a bridge) aimed freeze letters at the first hop instead of
    where the money rests. Opt OUT with ``RECUPERO_DEEP_REACH=0`` (e.g.
    fixture-build / deterministic R&D runs), or pin an individual knob.

    Centralized here so ``run_trace`` and ``_bridge_confirm_enabled``
    resolve the default identically.
    """
    return os.environ.get("RECUPERO_DEEP_REACH", "1").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _bridge_confirm_enabled() -> bool:
    """Resolve whether the cryptographic cross-chain bridge-pairing oracle
    runs for this trace.

    The oracle is part of the deep-reach recipe. ``RECUPERO_BRIDGE_CONFIRM``
    is honored when explicitly set (an explicit value — including ``0`` —
    always wins, so an operator can deep-reach with the oracle pinned off
    for a cheaper same-chain-only pass). When it is NOT set, it inherits the
    deep-reach default (v0.37.0: ON), so the standard production trace
    confirms + follows cross-chain destinations cryptographically.
    """
    if "RECUPERO_BRIDGE_CONFIRM" in os.environ:
        return os.environ.get("RECUPERO_BRIDGE_CONFIRM", "0").strip().lower() in (
            "1", "true", "yes", "on",
        )
    return _deep_reach_enabled()


def _crosschain_max_bridge_hops() -> int:
    """How many CONSECUTIVE bridge crossings the cross-chain continuation
    follows (deep cross-chain #2 — A->bridge->B->bridge->C).

    ``RECUPERO_CROSSCHAIN_MAX_BRIDGE_HOPS`` wins when set (clamped >= 1). When
    unset: 4 under the deep-reach default, 1 (legacy single crossing) when
    deep-reach is opted out. A bad explicit value falls back to the
    deep-reach-derived default. Always >= 1.
    """
    raw = os.environ.get("RECUPERO_CROSSCHAIN_MAX_BRIDGE_HOPS")
    if raw is not None:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            pass
    return 4 if _deep_reach_enabled() else 1


def _dex_swap_max_rounds() -> int:
    """How many ITERATIVE DEX-swap continuation rounds to follow (roadmap #8 —
    A swaps USDT->WBTC, the WBTC recipient swaps WBTC->ETH, ...). The legacy
    same-chain continuation collected swap-output recipients ONCE, so a chain of
    3+ swaps dead-ended after the first. Each round re-collects swap-output seeds
    from the prior round's new transfers and follows them — mirroring the
    cross-chain multi-bridge recursion (``_crosschain_max_bridge_hops``).

    ``RECUPERO_DEX_SWAP_MAX_ROUNDS`` wins when set, clamped to [1, 8]. DEFAULT 1
    = the legacy single-pass behaviour (BYTE-IDENTICAL to pre-#8 traces). Raise
    it to follow multi-swap chains; bounded by the per-round continuation-seed
    cap + the ``visited`` dedup so it can't explode the budget or loop.
    """
    raw = os.environ.get("RECUPERO_DEX_SWAP_MAX_ROUNDS")
    if raw is not None:
        try:
            return max(1, min(8, int(raw)))
        except (TypeError, ValueError):
            pass
    return 1


def _continue_dex_swap_chain(
    prev_new_transfers: list[Transfer],
    *,
    chain: Chain,
    adapter: ChainAdapter,
    label_store: LabelStore,
    price_client: CoinGeckoClient,
    policy: TracePolicy,
    incident_time: datetime,
    config: RecuperoConfig,
    evidence_dir: Path,
    visited: set[str],
    trace_concurrency: int,
    max_rounds: int,
) -> list[Transfer]:
    """Iteratively follow a chain of same-chain DEX swaps (roadmap #8).

    Round 1 (the swap-output recipients of the ORIGINAL trace) is run by the
    caller; this picks up from there. Each subsequent round re-collects
    swap-output seeds from the PREVIOUS round's new transfers (via
    ``_collect_swap_output_seeds``, which dedups through ``visited``), runs one
    shallow ``_process_wave``, and feeds its new transfers into the next round —
    until no fresh swap output is found or ``max_rounds`` is reached. Returns the
    transfers discovered in rounds 2..N (empty when ``max_rounds <= 1``).
    """
    extra: list[Transfer] = []
    frontier = prev_new_transfers
    rounds_left = max_rounds - 1  # round 1 already performed by the caller
    max_cont = int(os.environ.get("RECUPERO_MAX_CONTINUATION_SEEDS", "25"))
    while rounds_left > 0 and frontier:
        rounds_left -= 1
        seeds = _collect_swap_output_seeds(
            frontier, chain=chain, adapter=adapter, visited=visited,
        )
        if not seeds:
            break
        # No silent caps: mirror the primary continuation path — dropping swap-
        # output seeds here means later legs of a multi-hop DEX chain (e.g.
        # USDT→WBTC→ETH) go unfollowed, so WARN when the cap bites (the INFO
        # line below reports only how many were FOLLOWED, not dropped).
        if len(seeds) > max_cont:
            log.warning(
                "dex-swap-chain: continuation seeds capped at %d (had %d) on "
                "%s — RECUPERO_MAX_CONTINUATION_SEEDS to raise; later swap legs "
                "may go unfollowed.",
                max_cont, len(seeds), chain.value,
            )
        wave = [(addr, 1) for addr in seeds[:max_cont]]
        log.info(
            "dex-swap-chain: following %d further swap output(s) on %s "
            "(round, %d left)", len(wave), chain.value, rounds_left,
        )
        results = _process_wave(
            wave,
            adapter=adapter,
            label_store=label_store,
            price_client=price_client,
            policy=policy,
            incident_time=incident_time,
            config=config,
            evidence_dir=evidence_dir,
            concurrency=trace_concurrency,
        )
        round_new: list[Transfer] = []
        for _from_addr, _depth, hop_transfers, _is_service in results:
            round_new.extend(hop_transfers)
        if not round_new:
            break
        extra.extend(round_new)
        frontier = round_new
    return extra


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

    continuation_seeds: list[tuple[Address, int, str]] = []
    # (address, depth_hint, provenance_tag)

    # --- DEX swap output recipients ---
    # v0.34: pass the adapter so a settler-style swap (0x / Matcha) whose output
    # isn't in case.transfers gets recovered from the swap tx's receipt logs.
    # Factored into _collect_swap_output_seeds so the SAME settler-output
    # resolution runs on the cross-chain DESTINATION wave below (with the
    # destination adapter) — see the dest-chain continuation in the
    # cross_chain_seeds loop. depth_hint=1 puts each recipient at the last hop
    # under max_depth>=2.
    for recipient in _collect_swap_output_seeds(
        case.transfers, chain=chain, adapter=adapter, visited=visited,
    ):
        continuation_seeds.append((recipient, 1, "dex_swap_output"))

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

    # v0.34.4 — Cross-chain UPPER window cap. DEFAULT 0 = NO upper cap
    # (lower-bound-only: keep every onward hop at/after the bridge handoff).
    # This is the dormancy-aware default: laundered funds are parked and moved
    # LATER, so a fixed upper cap structurally drops the dormant destinations we
    # most need to track (the Zigha ~$16.9M DAI miss). Set a positive value only
    # if an operator wants to bound trace size for cost control; the lower bound
    # (hop must be after the bridge) always applies. Clamped to [0, 8760] hours
    # (1y) when set.
    try:
        xchain_window_h = float(os.environ.get(
            "RECUPERO_CROSSCHAIN_WINDOW_HOURS", "0",
        ))
        # Reject NaN / ±Inf. v0.31.1: the earlier check only rejected
        # +Infinity (and NaN via self-inequality); -Infinity would slip
        # through, then `max(0, -inf) = 0` silently disabled the filter
        # and masked the operator misconfig. Use math.isfinite to catch
        # both infinities + NaN in one call.
        import math as _m
        if not _m.isfinite(xchain_window_h):
            raise ValueError("non-finite")
        xchain_window_h = max(0.0, min(8760.0, xchain_window_h))
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_CROSSCHAIN_WINDOW_HOURS=%r rejected; using default "
            "(no upper cap, lower-bound-only)",
            os.environ.get("RECUPERO_CROSSCHAIN_WINDOW_HOURS"),
        )
        xchain_window_h = 0.0

    for handoff in handoffs:
        # Same-chain destination from decoded calldata.
        decoded_chain_str = handoff.decoded_destination_chain
        decoded_addr = handoff.decoded_destination_address
        decoded_conf = handoff.decoded_confidence
        # v0.36: a FULL calldata decode (chain+address) is now labelled
        # 'medium' (TRM-parity: decoded intent, not observed receipt — never
        # 'high'). It is still followed: continuation is gated on a usable
        # decoded address + confidence in {high, medium}, so demoting the label
        # costs no reach. 'low' (partial/garbage) is still skipped, and the
        # `not decoded_addr` guard still drops address-less decodes.
        if decoded_conf not in ("high", "medium") or not decoded_addr:
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

    # v0.34: CRYPTOGRAPHIC bridge-destination confirmation (opt-in).
    # The handoff loop above seeds a destination only from the heuristic
    # calldata decode (receiverDst). This pass instead asks the bridge-pairing
    # ORACLE to confirm the destination by the protocol's own cross-chain id
    # matched on BOTH chains — the only cross-chain basis that is genuine proof.
    # A confirmed destination is PREFERRED (it carries the real fill recipient
    # and is recorded for the Phase-2 validator + brief); it is added as a
    # continuation seed (deduped against the heuristic seeds). Gated by
    # RECUPERO_BRIDGE_CONFIRM (it makes live destination-chain log queries),
    # default OFF — consistent with RECUPERO_LOCKMINT_MATCH, so prod traces are
    # byte-for-byte unchanged unless an operator opts in.
    # v0.36.0 (forensic-trace wiring): bridge-confirm is part of the
    # deep-reach recipe — see _bridge_confirm_enabled(). RECUPERO_DEEP_REACH=1
    # is the single knob that turns on the full forensic depth and now also
    # enables the cryptographic cross-chain oracle here; an explicit
    # RECUPERO_BRIDGE_CONFIRM always wins. Neither set ⇒ OFF ⇒ byte-identical.
    _bridge_confirm_on = _bridge_confirm_enabled()
    if _bridge_confirm_on and cross_chain_continue and handoffs:
        try:
            _confs = _confirm_bridge_handoffs(
                handoffs,
                src_adapter=adapter,
                config=config,
                env=env,
                window_hours=xchain_window_h,
                incident_time=incident_time,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("bridge-confirm pass failed: %s", exc)
            _confs = []
        _conf_records: list[dict[str, Any]] = []
        for (h, c, sbt) in _confs:
            _conf_records.append({
                "protocol": c.protocol,
                "order_id": c.order_id,
                "source_chain": (
                    h.source_chain.value if getattr(h, "source_chain", None) else None
                ),
                "source_tx": getattr(h, "source_tx_hash", None),
                "dst_chain": c.dst_chain,
                "dst_tx": c.dst_tx,
                "recipient": c.recipient,
                "raw_amount": str(c.raw_amount) if c.raw_amount is not None else None,
                "src_raw_amount": (
                    str(c.src_raw_amount) if c.src_raw_amount is not None else None
                ),
                "same_asset": c.same_asset,
                "confidence": c.confidence,
                "basis": c.basis,
            })
            # Seed the cryptographically-confirmed recipient on the dest chain
            # (deduped against the heuristic cross_chain_seeds via the same
            # cross_chain_visited set). No recipient -> recorded but not seeded.
            if not c.recipient:
                continue
            try:
                _dchain = Chain(c.dst_chain)
            except (ValueError, KeyError):
                continue
            _xkey = (_dchain.value, _address_visited_key(_dchain, c.recipient))
            if _xkey in cross_chain_visited:
                continue
            cross_chain_visited.add(_xkey)
            cross_chain_seeds.append((_dchain, c.recipient, 1, sbt))
        if _conf_records:
            case.config_used = {
                **(case.config_used or {}),
                "bridge_confirmations": _conf_records,
            }
            log.info(
                "bridge-confirm: %d cryptographically-confirmed cross-chain "
                "destination(s)", len(_conf_records),
            )
            # Phase 2 self-audit: every confirmed edge must carry its proof and
            # (same-asset only) conserve value. Log any violation — the trace
            # never asserts a high cross-chain edge it can't back up.
            try:
                from recupero.validators.cross_chain_integrity import (
                    validate_bridge_confirmations,
                )
                for _v in validate_bridge_confirmations(_conf_records):
                    log.warning(
                        "bridge-confirm self-audit [%s/%s]: %s",
                        _v.check, _v.severity, _v.detail,
                    )
            except Exception as exc:  # noqa: BLE001
                log.debug("bridge-confirm self-audit skipped: %s", exc)

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
    # v0.37.0: lock-and-mint matching is part of the deep-reach recipe so
    # "go deep" also covers POOL bridges (Celer/Orbiter/THORChain/Allbridge)
    # whose recipient is NOT in the source calldata and which the
    # cryptographic order-id oracle therefore cannot pair. Inherits the
    # deep-reach default unless RECUPERO_LOCKMINT_MATCH is explicitly set
    # (explicit value — incl. 0 — always wins). The matches are confidence-
    # calibrated medium/low (a cross-chain correlation, never proof) and the
    # brief classifies them as INVESTIGATE leads, never freeze targets — so
    # this widens coverage without ever billing an inferred edge as freezable.
    if "RECUPERO_LOCKMINT_MATCH" in os.environ:
        _lockmint_on = os.environ.get(
            "RECUPERO_LOCKMINT_MATCH", "0",
        ).strip().lower() in ("1", "true", "yes", "on")
    else:
        _lockmint_on = _deep_reach_enabled()
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

    # roadmap #8: iterative multi-swap-chain continuation. The pass above
    # followed the FIRST swap's output recipients; this follows a CHAIN of
    # further swaps (USDT->WBTC->ETH->...) by re-collecting swap-output seeds
    # from each round's new transfers. Opt-in via RECUPERO_DEX_SWAP_MAX_ROUNDS
    # (default 1 ⇒ this block is a no-op ⇒ byte-identical to pre-#8 traces).
    _swap_rounds = _dex_swap_max_rounds()
    if _swap_rounds > 1 and new_transfers:
        new_transfers.extend(_continue_dex_swap_chain(
            new_transfers, chain=chain, adapter=adapter, label_store=label_store,
            price_client=price_client, policy=policy, incident_time=incident_time,
            config=config, evidence_dir=evidence_dir, visited=visited,
            trace_concurrency=trace_concurrency, max_rounds=_swap_rounds,
        ))

    # v0.16.13: cross-chain continuation pass. Each destination chain
    # needs its own adapter — group seeds by chain, instantiate one
    # adapter per chain, run a shallow wave. Bounded to prevent
    # quota explosion: at most RECUPERO_MAX_CROSS_CHAIN_SEEDS (default 10)
    # across all destination chains.
    # v0.37.1 (deep cross-chain #2): multi-bridge recursion — follow a chain of
    # CONSECUTIVE bridge crossings (A -> bridge -> B -> bridge -> C), not just
    # the first. Bounded by RECUPERO_CROSSCHAIN_MAX_BRIDGE_HOPS rounds (default 4
    # under the deep-reach default; 1 = legacy single crossing when deep-reach is
    # off and the var is unset). Each round re-detects bridges among the prior
    # round's destination-chain transfers and seeds the next; cross_chain_visited
    # dedup + the per-case transfer cap / budget / deadline bound the total work.
    _max_bridge_hops = _crosschain_max_bridge_hops()
    _bridge_round = 0
    while cross_chain_seeds and _bridge_round < _max_bridge_hops:
        _bridge_round += 1
        # Seeds for the NEXT bridge round, collected from this round's
        # destination-chain transfers (a second bridge crossing).
        _next_round_seeds: list[tuple[Chain, Address, int, datetime]] = []
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
                window_end = (
                    src_time + timedelta(hours=xchain_window_h)
                    if (xchain_window_h > 0 and src_time is not None)
                    else None
                )
                chain_new: list[Transfer] = []
                # v0.37.1 (deep cross-chain #1): onward frontier excludes
                # transfers out of a high-fan-out service-wallet source so a
                # commingling node on the destination chain does not fan the
                # trace out (same dead-end rule the primary BFS applies). Swap-
                # output detection still sees ALL of chain_new (a settler swap
                # output IS the money even though the settler is high-fan-out).
                onward_new: list[Transfer] = []
                dropped = 0
                for _from_addr, _depth, hop_transfers, _is_service in xchain_results:
                    for tx in hop_transfers:
                        if _tx_within_window(tx, src_time, window_end):
                            chain_new.append(tx)
                            if not _is_service:
                                onward_new.append(tx)
                        else:
                            dropped += 1
                if dropped:
                    log.info(
                        "cross-chain window filter (%.1fh) dropped %d "
                        "out-of-range transfers on %s",
                        xchain_window_h, dropped, dst_chain.value,
                    )
                new_transfers.extend(chain_new)
                # v0.37.1 (#2): accumulate every transfer discovered on THIS
                # destination chain this round so we can re-detect a second
                # bridge among them after the dest-chain continuation completes.
                _chain_all: list[Transfer] = list(chain_new)

                # v0.34 (compose bridge -> swap -> onward): the cross-chain wave
                # above is a SINGLE shallow hop. It captures the destination
                # receiver's direct outflows (e.g. the deposit INTO a 0x /
                # Matcha settler) but NOT the settler's token->DAI payout — that
                # is paid from the settler's own balance and is recoverable only
                # from the swap tx RECEIPT LOGS using the DESTINATION chain's
                # adapter. Without this pass the trace dead-ends at the settler
                # on the destination chain (the exact Zigha gap: Arbitrum hub ->
                # DeBridge -> Ethereum receiver -> 0x swap -> DAI). Run up to
                # RECUPERO_DEST_CONTINUATION_WAVES extra waves on dst_adapter,
                # each resolving swap outputs among the prior wave's transfers
                # and following them one hop deeper. Bounded to this ONE
                # destination chain (no further cross-chain recursion) and to
                # the per-case transfer budget + visited set already in force.
                # v0.37.1 (deep cross-chain #1): each dest wave now follows BOTH
                # swap outputs AND generic value-bearing onward hops, so a plain
                # receiver -> wallet -> ... -> exchange trail on the destination
                # chain is chased to depth (not only token->DAI swaps). Under the
                # deep-reach default the wave budget is raised so the trail is
                # followed deep; an explicit RECUPERO_DEST_CONTINUATION_WAVES
                # always wins (and =0 disables the dest continuation entirely).
                if "RECUPERO_DEST_CONTINUATION_WAVES" in os.environ:
                    try:
                        _dest_waves = int(os.environ["RECUPERO_DEST_CONTINUATION_WAVES"])
                    except (TypeError, ValueError):
                        _dest_waves = 2
                else:
                    _dest_waves = 8 if _deep_reach_enabled() else 2
                _frontier = chain_new            # swap-output detection: all
                _onward_frontier = onward_new    # generic onward: service-safe
                for _wi in range(max(0, _dest_waves)):
                    if not _frontier and not _onward_frontier:
                        break
                    _dseeds: list[Address] = []
                    _seen_seed: set[str] = set()
                    for _s in _collect_swap_output_seeds(
                        _frontier, chain=dst_chain, adapter=dst_adapter,
                        visited=visited,
                    ) + _collect_onward_value_seeds(
                        _onward_frontier, chain=dst_chain, adapter=dst_adapter,
                        policy=policy, visited=visited,
                        src_time=src_time, window_end=window_end,
                    ):
                        _sk = _address_visited_key(dst_chain, _s)
                        if _sk not in _seen_seed:
                            _seen_seed.add(_sk)
                            _dseeds.append(_s)
                    if not _dseeds:
                        break
                    log.info(
                        "dest-chain continuation on %s: %d onward/swap seed(s) "
                        "(wave %d/%d) — composing bridge->onward",
                        dst_chain.value, len(_dseeds), _wi + 1, _dest_waves,
                    )
                    try:
                        _dres = _process_wave(
                            [(_a, 1) for _a in _dseeds],
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
                            "dest-chain continuation wave on %s failed: %s",
                            dst_chain.value, exc,
                        )
                        break
                    _next_frontier: list[Transfer] = []
                    _next_onward: list[Transfer] = []
                    for _fa, _fd, _hts, _isvc in _dres:
                        for tx in _hts:
                            if not _tx_within_window(tx, src_time, window_end):
                                continue
                            new_transfers.append(tx)
                            _chain_all.append(tx)
                            _next_frontier.append(tx)
                            # Don't fan out from a high-fan-out service wallet
                            # reached on the destination chain.
                            if not _isvc:
                                _next_onward.append(tx)
                    _frontier = _next_frontier
                    _onward_frontier = _next_onward

                # v0.37.1 (deep cross-chain #2): re-detect a SECOND bridge among
                # this chain's transfers and seed the next round (while the dst
                # adapter is still open). Conservative: only HIGH-confidence
                # calldata-decoded destinations seed onward (same gate as round
                # 0's heuristic path); deduped via cross_chain_visited so a chain
                # is never re-traced. Bounded by _max_bridge_hops.
                if _bridge_round < _max_bridge_hops and _chain_all:
                    try:
                        from recupero.trace.cross_chain import (
                            identify_cross_chain_handoffs,
                        )
                        _view = SimpleNamespace(transfers=list(_chain_all))
                        _h2 = identify_cross_chain_handoffs(_view, adapter=dst_adapter)
                    except Exception as exc:  # noqa: BLE001
                        log.warning(
                            "multi-bridge detection on %s failed: %s",
                            dst_chain.value, exc,
                        )
                        _h2 = []
                    for _hh in _h2:
                        if (
                            # v0.36: full calldata decode is 'medium' now (never
                            # 'high'); still followed when chain+address present.
                            getattr(_hh, "decoded_confidence", None)
                            not in ("high", "medium")
                            or not getattr(_hh, "decoded_destination_address", None)
                            or not getattr(_hh, "decoded_destination_chain", None)
                        ):
                            continue
                        try:
                            _ndc = Chain(_hh.decoded_destination_chain)
                        except (ValueError, KeyError):
                            continue
                        _nk = (
                            _ndc.value,
                            _address_visited_key(_ndc, _hh.decoded_destination_address),
                        )
                        if _nk in cross_chain_visited:
                            continue
                        cross_chain_visited.add(_nk)
                        try:
                            _src_iso = (_hh.block_time_iso or "").replace("Z", "+00:00")
                            _nbt = datetime.fromisoformat(_src_iso)
                            if _nbt.tzinfo is None:
                                _nbt = _nbt.replace(tzinfo=UTC)
                        except (TypeError, ValueError, AttributeError):
                            _nbt = dst_anchor_time
                        _next_round_seeds.append(
                            (_ndc, _hh.decoded_destination_address, 1, _nbt),
                        )
            finally:
                try:
                    dst_adapter.close()
                except Exception:  # noqa: BLE001
                    pass

        # v0.37.1 (#2): advance to the next bridge round. The while-loop
        # re-groups these seeds by chain and processes them; an empty list
        # (no further bridge detected) terminates the recursion, as does
        # hitting _max_bridge_hops.
        if _next_round_seeds:
            log.info(
                "multi-bridge recursion: %d onward bridge destination(s) "
                "detected (round %d/%d)",
                len(_next_round_seeds), _bridge_round, _max_bridge_hops,
            )
        cross_chain_seeds = _next_round_seeds

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


def _select_traced_inbound(
    inbounds: list[Transfer], dust_threshold_usd: Decimal
) -> Transfer | None:
    """Pick the inbound edge representing the TRACED funds among several edges
    into a node (v0.34 audit fix).

    Prefer the largest PRICED inbound ABOVE the dust threshold (our funds, when
    priceable). If every priced inbound is dust, fall back to the largest
    UNPRICED inbound by token amount — so a tiny priced poison/dust edge can't
    displace the real (often unpriced — e.g. an illiquid/new token, or a leg
    built under the lightweight ``skip_contract_api`` pass) laundering leg and
    send the matcher chasing the wrong amount, missing the real onward hop.
    Previously ``max(usd_value or 0)`` let a $5 priced dust beat the unpriced
    real funds (which sorted as 0).
    """
    if not inbounds:
        return None
    meaningful = [
        t for t in inbounds
        if t.usd_value_at_tx is not None
        and t.usd_value_at_tx.is_finite()
        and t.usd_value_at_tx > dust_threshold_usd
    ]
    if meaningful:
        return max(meaningful, key=lambda t: t.usd_value_at_tx)
    unpriced = [t for t in inbounds if t.usd_value_at_tx is None]
    if unpriced:
        # real funds are often the unpriced leg; rank by token amount (best
        # available signal absent USD) rather than chasing priced dust.
        return max(unpriced, key=lambda t: t.amount_decimal or Decimal(0))
    # every inbound is priced-but-dust → take the largest priced one.
    return max(
        inbounds,
        key=lambda t: (
            t.usd_value_at_tx if t.usd_value_at_tx is not None else Decimal(0)
        ),
    )


def _select_traced_inbounds(
    inbounds: list[Transfer], dust_threshold_usd: Decimal
) -> list[Transfer]:
    """The inbound leg(s) to trace onward from a node (v0.34.1).

    Returns the primary (``_select_traced_inbound``) AND, when distinct, the
    largest UNPRICED inbound by token amount. Rationale: an EXACT same-asset
    onward match is the strongest signal the matcher has and must be followed
    even when the asset has no price — otherwise a hub that received the stolen
    funds as an unpriced token (e.g. Midas msyrupUSDp) while also receiving a
    tiny priced ETH-dust leg gets traced on the dust (priced legs win
    ``_select_traced_inbound``), the unpriced same-asset forward is never
    evaluated, and the trace dead-ends one hop short of the resting wallet.
    Following BOTH legs is bounded: same-asset matching only fires on an exact
    amount match, so this adds the real onward hop, not a fan-out.
    """
    from recupero.trace.value_matching import is_confusable_token_symbol

    if not inbounds:
        return []
    # Exclude homoglyph/impersonation-token inbounds (address-poisoning spam):
    # the tracer must not select a poison leg as the funds to follow. Legit
    # symbols are ASCII; a non-ASCII symbol is a mimic of a real asset.
    inbounds = [
        t for t in inbounds
        if not is_confusable_token_symbol(
            getattr(getattr(t, "token", None), "symbol", None)
        )
    ]
    if not inbounds:
        return []
    primary = _select_traced_inbound(inbounds, dust_threshold_usd)
    out: list[Transfer] = [primary] if primary is not None else []
    unpriced = [
        t for t in inbounds
        if t.usd_value_at_tx is None and (t.amount_decimal or Decimal(0)) > 0
    ]
    if unpriced:
        big_unpriced = max(unpriced, key=lambda t: t.amount_decimal or Decimal(0))
        if big_unpriced is not primary:
            out.append(big_unpriced)
    return out


def _node_forwarded_inbound_asset(
    inbound: Transfer, node_outflows: list[Transfer]
) -> bool:
    """True if the node emitted an outflow of the SAME on-chain asset it received
    on ``inbound`` (matched by contract when known, else symbol). Used to tell a
    real value-trace dead-end (the asset moved onward but no hop matched) from a
    legitimate resting terminal (no same-asset outflow — the funds sit here)."""
    itok = getattr(inbound, "token", None)
    if itok is None:
        return False
    ic = (getattr(itok, "contract", None) or "").lower()
    isym = (getattr(itok, "symbol", None) or "").upper()
    for t in node_outflows:
        tok = getattr(t, "token", None)
        if tok is None:
            continue
        c = (getattr(tok, "contract", None) or "").lower()
        s = (getattr(tok, "symbol", None) or "").upper()
        if ic and c:
            if c == ic:
                return True
        elif isym and s == isym:
            return True
    return False


# v0.34.7 — label-aware terminals. At a directed node, a same-asset outflow that
# lands at a LABELED mixer/exchange/bridge is the traced money's END STATE. We
# record it and stop — exactly how TRM/Chainalysis stop-and-flag at a mixer
# rather than chasing every pool deposit. Bounded + truthful: never fabricates
# (only real, already-label-enriched outflows), never traverses the terminal.
_TERMINAL_CATEGORIES = (
    LabelCategory.mixer,
    LabelCategory.exchange_deposit,
    LabelCategory.exchange_hot_wallet,
    LabelCategory.bridge,
)


def _terminal_status_for_category(category: LabelCategory) -> str:
    """Map a terminal label category to the holding status the brief uses."""
    if category == LabelCategory.mixer:
        return "UNRECOVERABLE"   # mixed → not traceable further (Tornado etc.)
    if category in (LabelCategory.exchange_deposit, LabelCategory.exchange_hot_wallet):
        return "EXCHANGE"        # subpoena to exchange compliance, not a freeze
    if category == LabelCategory.bridge:
        return "BRIDGE"          # cross-chain handoff (separate continuation)
    return "TRANSIT"


def _same_onchain_asset(a: Any, b: Any) -> bool:
    """Same on-chain asset? Contract identity when known; else native matched by
    symbol. Mirrors value_matching._same_token — a spoof token with a colliding
    symbol but a different contract is NOT treated as the same asset."""
    if b is None:
        return False
    ac = (getattr(a, "contract", None) or "").lower()
    bc = (getattr(b, "contract", None) or "").lower()
    if ac or bc:
        return bool(ac) and bool(bc) and ac == bc
    asym = (getattr(a, "symbol", None) or "").upper()
    bsym = (getattr(b, "symbol", None) or "").upper()
    return bool(asym) and asym == bsym


def _detect_labeled_terminals(
    *,
    inbound: Transfer,
    node_outflows: list[Transfer],
    node_addr: Address,
    depth: int,
) -> tuple[list[dict[str, Any]], list[Transfer]]:
    """Surface the node's SAME-ASSET outflows that land at a LABELED terminal
    (mixer / exchange / bridge). Returns ``(records, kept_transfers)``.

    ``kept_transfers`` are REAL, already-label-enriched outflows — re-recording
    them on the case lets the brief classify the destination
    (mixer→UNRECOVERABLE, exchange→EXCHANGE) from the existing label with no
    extra work. ``records`` is per-terminal audit provenance (node, terminal,
    label, status, aggregate amount/USD, tx count, sample tx hashes).

    Same-asset = same on-chain token as the inbound (contract identity), which
    ties the terminal to the funds being traced and defeats symbol-spoofing.
    The terminal is recorded, NEVER enqueued/traversed."""
    itok = getattr(inbound, "token", None)
    if itok is None:
        return [], []
    by_dest: dict[str, list[Transfer]] = {}
    for t in node_outflows:
        cp = getattr(t, "counterparty", None)
        label = getattr(cp, "label", None) if cp is not None else None
        if label is None or label.category not in _TERMINAL_CATEGORIES:
            continue
        if not _same_onchain_asset(itok, getattr(t, "token", None)):
            continue
        dest = (t.to_address or "").lower()
        if not dest:
            continue
        by_dest.setdefault(dest, []).append(t)

    records: list[dict[str, Any]] = []
    kept: list[Transfer] = []
    for _dest, txs in sorted(by_dest.items()):
        label = txs[0].counterparty.label
        agg_amt = sum(
            (Decimal(str(t.amount_decimal)) for t in txs if t.amount_decimal is not None),
            Decimal(0),
        )
        usd_vals = [
            Decimal(str(t.usd_value_at_tx))
            for t in txs if t.usd_value_at_tx is not None
        ]
        agg_usd = sum(usd_vals, Decimal(0)) if usd_vals else None
        records.append({
            "node": node_addr,
            "terminal_address": txs[0].to_address,
            "label_name": label.name,
            "label_category": label.category.value,
            "status": _terminal_status_for_category(label.category),
            "token": (getattr(itok, "symbol", None) or "").upper() or None,
            "tx_count": len(txs),
            "agg_amount": str(agg_amt),
            "agg_usd": float(agg_usd) if agg_usd is not None else None,
            "depth": depth,
            "sample_tx_hashes": [t.tx_hash for t in txs[:5]],
        })
        kept.extend(txs)
    return records, kept


def _value_match_and_enqueue(
    *,
    inbound_transfer: Any,
    node_outflows: list[Transfer],
    parent_depth: int,
    node_addr: Address,
    enqueue_fn: Any,
    provenance_sink: list[dict[str, Any]],
    follow_splits: bool = False,
    window_hours: int = 72,
) -> tuple[int, list[Transfer]]:
    """At a high-fan-out node, follow ONLY the outflow(s) whose value matches
    the inbound funds (v0.34 value-directed tracing).

    Builds a ``Leg`` for the inbound edge and for each outflow, ranks them with
    ``value_matching.match_onward_transfers`` (same-asset amount match, then
    USD-value match across a swap), and enqueues each match via ``enqueue_fn``
    (the BFS's shared per-transfer gate — so visited / contract / depth rules
    still apply). Records one provenance row per ACTUALLY-enqueued hop, carrying
    the calibrated confidence (never "high").

    Returns ``(followed_count, matched_transfers)`` where ``matched_transfers``
    are the Transfer objects that were enqueued — the caller records ONLY these
    on the case (the money path), not the node's full commingled outflow set,
    so a mixer/aggregator's thousands of unrelated outflows neither bloat the
    per-case transfer budget nor pollute the deliverable.
    """
    from recupero.trace.value_matching import (
        detect_same_asset_split,
        leg_from_transfer,
        match_onward_transfers,
    )

    inbound_leg = leg_from_transfer(inbound_transfer)
    if inbound_leg is None:
        return 0, []

    by_key: dict[tuple[str, str], Transfer] = {}
    cand_legs = []
    for t in node_outflows:
        leg = leg_from_transfer(t)
        if leg is None:
            continue
        by_key[(leg.tx_hash, leg.to_address.lower())] = t
        cand_legs.append(leg)

    matches = match_onward_transfers(
        inbound_leg, cand_legs, time_window_hours=window_hours,
    )
    # v0.34.6: when no 1:1 hop matched, optionally recover a 1:N same-asset
    # SPLIT/peel (the node forwarded the inbound funds as many smaller same-asset
    # sends summing to ~the inbound). Opt-in (RECUPERO_VALUE_TRACE_FOLLOW_SPLITS)
    # because it follows MULTIPLE onward edges from one node — bounded by the
    # detector's leg cap + the BFS visited/depth/budget gates. All split legs are
    # confidence="low" (a set inference). This is what carries the Lazarus/Ronin
    # trace past the consolidation wallets that peel into mixer-denomination
    # chunks instead of forwarding a single matching amount.
    if not matches and follow_splits:
        matches = detect_same_asset_split(
            inbound_leg, cand_legs, time_window_hours=window_hours,
        )
    followed = 0
    matched_transfers: list[Transfer] = []
    for m in matches:
        t = by_key.get((m.tx_hash, m.to_address.lower()))
        if t is None:
            continue
        if not enqueue_fn(t, parent_depth):
            # visited / contract / depth gate rejected it — don't claim a hop.
            continue
        matched_transfers.append(t)
        provenance_sink.append({
            "node": node_addr,
            "inbound_tx": inbound_leg.tx_hash,
            "matched_to": m.to_address,
            "matched_tx": m.tx_hash,
            "kind": m.kind,
            "confidence": m.confidence,
            "ambiguous": m.ambiguous,
            "basis": m.basis,
            "hop_depth": parent_depth + 1,
        })
        followed += 1
    return followed, matched_transfers


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
    value_trace: bool = False,
    deadline: datetime | None = None,
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

    ``deadline`` (v0.41.1, #253) bounds the wave to the trace's wall-clock
    budget. The between-wave deadline check (``run_trace``) only refuses to
    START a new wave — but a single wave over a large, expensive frontier (the
    real Lazarus/Ronin case: dozens of high-fan-out $-consolidation nodes
    against a rate-limited API) can itself run far past the budget, so the trace
    never returns. Here we stop collecting once the deadline elapses, cancel the
    not-yet-started nodes, and return the partial wave. The caller then trips
    ``timeout_hit`` and writes a partial-trace case (the existing graceful-
    degradation contract) instead of hanging forever.
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
                value_trace=value_trace,
            )
            return (addr, depth, transfers, is_service_wallet)
        except Exception as e:  # noqa: BLE001
            log.warning(
                "trace hop failed for %s (depth=%d): %s — continuing",
                addr, depth, e,
            )
            return (addr, depth, [], False)

    def _past_deadline() -> bool:
        return deadline is not None and utcnow() >= deadline

    # Single-threaded path for trivial waves or when concurrency is off.
    # Preserves test determinism + avoids ThreadPoolExecutor overhead
    # for tiny cases. The deadline is checked before each node so the
    # serial path is bounded too (a tiny-wave whale node can't run forever).
    if concurrency <= 1 or len(wave) == 1:
        serial: list[tuple[Address, int, list[Transfer], bool]] = []
        for addr, depth in wave:
            if _past_deadline():
                log.warning(
                    "trace wave deadline: skipping %d remaining node(s) (serial)",
                    len(wave) - len(serial),
                )
                break
            serial.append(_one(addr, depth))
        return serial

    results: list[tuple[Address, int, list[Transfer], bool]] = []
    pool = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="trace")
    try:
        futures = {pool.submit(_one, addr, depth): (addr, depth) for addr, depth in wave}
        # Bounded wait: return as soon as all nodes finish OR the trace
        # wall-clock deadline elapses, whichever comes first. ``timeout=None``
        # (no deadline) waits for all — identical to the old behavior.
        timeout = None
        if deadline is not None:
            timeout = max(0.0, (deadline - utcnow()).total_seconds())
        done, not_done = _futures_wait(set(futures), timeout=timeout)
        for fut in done:
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                # _one catches its own exceptions and returns a result tuple;
                # this is the belt-and-suspenders catch for anything that
                # escaped (e.g., a future cancelled exception).
                addr, depth = futures[fut]
                log.warning("trace wave worker crashed for %s: %s", addr, e)
                results.append((addr, depth, [], False))
        if not_done:
            # Deadline elapsed mid-wave: cancel the queued nodes (running ones
            # can't be interrupted — at most ``concurrency`` finish in the
            # background) and return the partial wave so the caller degrades
            # gracefully instead of blocking on the whole frontier.
            log.warning(
                "trace wave deadline: cancelling %d of %d node(s) still in flight",
                len(not_done), len(futures),
            )
            for fut in not_done:
                fut.cancel()
    finally:
        # wait=False so we don't block on the (≤concurrency) running nodes;
        # cancel_futures drops anything still queued.
        pool.shutdown(wait=False, cancel_futures=True)
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
    value_trace: bool = False,
) -> tuple[list[Transfer], bool]:
    """Fetch + label + price all outflows from one address.

    Returns ``(transfers, is_service_wallet)``. When ``is_service_wallet``
    is True, the address has more outflows than
    ``policy.service_wallet_outflow_threshold`` — caller should keep the
    transfers but stop BFS traversal at this address.

    v0.34 value-directed fast path: when ``value_trace`` is on AND this address
    is a high-fan-out service wallet, we build its (up to thousands of) outflows
    LIGHTWEIGHT — cheap price (no per-token CoinGecko contract-resolution API),
    label kept (in-memory), but SKIP the two per-outflow Etherscan RPCs
    (``is_contract`` + evidence-receipt fetch) and the dust filter. The caller
    value-matches these to pick the real onward hop(s) and FINALIZES only those
    few (writes their evidence). This turns an ~8k-RPC, multi-minute node into a
    sub-second one, so a deep endpoint behind an aggregator is reachable. For
    NON-service-wallet nodes (and whenever value_trace is off) the full,
    fully-evidenced path runs unchanged.
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

    # v0.34 (operator-requested "elite recall"): prune UNAMBIGUOUS poison edges
    # BEFORE pricing/following so the tracer can run UNCAPPED without drowning
    # in address-poisoning spam. Zero-value transfers move no funds and are the
    # canonical poisoning primitive; dropping them here (a) avoids a CoinGecko
    # contract-resolution call per throwaway poison token — the historical
    # multi-hour "freeze" — and (b) keeps the per-address fetch cap from ever
    # having to truncate a real onward hop. This is NOISE removal: it never
    # drops a value-bearing edge, so it does NOT reduce coverage. Runs BEFORE
    # the service-wallet check so that count reflects REAL edges, not poison.
    # Opt-out: RECUPERO_POISON_PRUNE in {0,false,no,off}.
    if os.environ.get("RECUPERO_POISON_PRUNE", "1").strip().lower() not in (
        "0", "false", "no", "off",
    ):
        from recupero.trace.poison_pruning import prune_poison_outflows
        _pre_prune = len(raw_outflows)
        raw_outflows, _pruned_edges = prune_poison_outflows(raw_outflows)
        if _pruned_edges:
            log.info(
                "poison-pruned %d zero-value outflow(s) from %s (%d -> %d kept)",
                len(_pruned_edges), from_address, _pre_prune, len(raw_outflows),
            )
            _POISON_PRUNED.append({
                "address": from_address,
                "kind": "zero_value_poison",
                "pruned": len(_pruned_edges),
                "raw_outflows": _pre_prune,
                "hop_depth": hop_depth,
            })

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

    # v0.34 value-directed fast path: build a high-fan-out node's outflows
    # cheaply (no per-token price API, no per-outflow is_contract / evidence
    # RPC, no dust filter) so the caller can value-match them and finalize only
    # the matched few. ``_lightweight`` gates the expensive ops in the loop.
    #
    # v0.34 perf (prune-before-enrich): the cheap build must engage for ANY
    # high-fan-out node under value-trace, not just those above the
    # service-wallet threshold. The full path does ~3 Etherscan RPCs per kept
    # outflow (per-token CoinGecko contract-resolution + per-dest is_contract +
    # per-tx evidence receipt); on a node with thousands of outflows that is the
    # multi-hour wall we hit when a 10k-outflow node sat just UNDER the
    # service-wallet bar. The wave aggregation value-matches the cheaply-built
    # set and FINALIZES the expensive ops (is_contract + evidence) for ONLY the
    # matched onward hop(s) (see run_trace ~643). Gate the count-based trigger on
    # hop_depth>=1 so the seed (depth 0, non-directed — every outflow is kept and
    # must stay fully evidenced) is never cheapened. The service-wallet branch is
    # preserved unchanged. Ceiling tunable via RECUPERO_VALUE_TRACE_ENRICH_CEILING
    # (default 50; <=0 disables the count trigger, leaving only the service-wallet
    # behavior).
    try:
        _enrich_ceiling = int(
            os.environ.get("RECUPERO_VALUE_TRACE_ENRICH_CEILING", "50")
        )
    except (TypeError, ValueError):
        _enrich_ceiling = 50
    _lightweight = value_trace and (
        is_service_wallet
        or (
            hop_depth >= 1
            and _enrich_ceiling > 0
            and len(raw_outflows) > _enrich_ceiling
        )
    )

    # Cap to avoid runaway on chatty addresses. ``_cap`` honors the
    # ``RECUPERO_MAX_TRANSFERS_PER_ADDRESS`` env-var override resolved
    # above; ``_cap <= 0`` disables the slice (industry-best mode).
    #
    # v0.34 audit fix (coverage): the slice is positional (``[:_cap]``) and
    # adapters fetch ASCENDING by block, so it keeps the EARLIEST outflows and
    # silently drops the tail — but the onward laundering hop occurs AFTER the
    # inflow, so the tail is exactly where the money path lives. The slice's only
    # purpose is to bound the EXPENSIVE per-outflow work; under ``_lightweight``
    # that work is already skipped (cheap build, value-matched to ≤K, finalized
    # only on the matched hop), so capping a lightweight node both is unnecessary
    # AND drops the money path. Skip the per-address slice when lightweight; the
    # per-CASE transfer cap still bounds total memory.
    if not _lightweight and _cap and _cap > 0 and len(raw_outflows) > _cap:
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

    # Per-hop dedup of blocking RPCs. A consolidation node fans thousands of
    # transfers into a handful of unique destination addresses / txs; without
    # this the loop below issued one is_contract RPC per transfer (not per
    # address) and one evidence fetch per transfer (not per tx). Both calls are
    # idempotent for a given key, so memoizing collapses N round-trips to K
    # unique — the single biggest network-I/O reduction on the hot path.
    _contract_cache: dict[str, bool] = {}
    _evidence_seen: set[str] = set()

    def _resolve_is_contract(addr: str) -> bool:
        cached = _contract_cache.get(addr)
        if cached is not None:
            return cached
        try:
            val = adapter.is_contract(addr)
        except Exception as e:  # noqa: BLE001
            log.warning("is_contract check failed for %s: %s", addr, e)
            val = False
        _contract_cache[addr] = val
        return val

    transfers: list[Transfer] = []
    for raw in raw_outflows:
        # Drop debug-only fields before transfer construction
        raw.pop("_native_source", None)

        # Build initial Transfer with placeholder counterparty (filled below)
        transfer = _build_transfer(raw, hop_depth=hop_depth, parent_transfer_id=parent_transfer_id)

        # Pricing — price_at returns per-unit USD price; transfer value = price × amount
        # Lightweight (value-trace service-wallet) pass skips the per-token
        # CoinGecko contract-resolution API so ranking thousands of outflows
        # stays cheap; real-rail tokens still price via hint/stablecoin/static map.
        if _lightweight:
            result = price_client.price_at(
                transfer.token, transfer.block_time, skip_contract_api=True,
            )
        else:
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

        # Dust filter (after pricing). SKIPPED in the lightweight pass so the
        # value-matcher sees every candidate (a sub-dust edge simply won't match
        # a high-value inbound); these transfers are transient — only the matched
        # few are kept by the caller.
        if not _lightweight and not policy.should_include(transfer):
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
        # is_contract is an Etherscan RPC per destination. In the lightweight
        # pass we defer it (placeholder False) — these are throwaway candidates;
        # only the value-matched onward hop(s) get a proper resolution when the
        # next wave fetches them.
        is_contract = False if _lightweight else _resolve_is_contract(transfer.to_address)

        counterparty = Counterparty(
            address=transfer.to_address,
            label=label,
            is_contract=is_contract,
            first_seen_at=transfer.block_time,
        )
        transfer = transfer.model_copy(update={"counterparty": counterparty})
        transfers.append(transfer)

        # Persist evidence receipt immediately (partial output > no output).
        # SKIPPED in the lightweight pass — it is a per-tx RPC fetch and the
        # dominant cost at a high-fan-out node. The caller writes evidence for
        # the value-matched onward hop(s) only (see _value_match_and_enqueue
        # finalize in run_trace).
        # One evidence fetch per unique tx, not per log-line transfer. The
        # receipt is keyed solely by tx_hash and is idempotent (same file), so
        # de-duplicating multiple transfers within one tx avoids redundant RPCs.
        if not _lightweight and transfer.tx_hash not in _evidence_seen:
            _evidence_seen.add(transfer.tx_hash)
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
