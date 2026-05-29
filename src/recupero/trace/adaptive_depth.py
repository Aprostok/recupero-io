"""Adaptive BFS depth ceiling (v0.32.1 trace gap C).

Reactor's BFS adapts depth to case severity + API budget. A $50k drain
gets a shallow trace (depth 6) because the recovery economics don't
warrant 1000+ RPC calls; a $50M drain warrants depth 12 even if it
exhausts most of the daily budget.

Recupero's tracer.py historically used a hardcoded depth=6. This
module lets the BFS pass case metadata + budget state in and pull
back a sensible ceiling. Pure / no side effects.

Tunable constants are intentionally module-level so a roll-forward
config file can override without code changes.

# TODO(wave-4-integration): wire `compute_max_depth` into
# trace.tracer entry point; pass case.theft_amount_usd and the
# rate-limiter budget state. Replace the hardcoded depth.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


# Tunable thresholds. Keep all dollar values in plain USD (not cents).
DEFAULT_MAX_DEPTH = 6

# Severity bumps: monotone increasing in theft amount.
SEVERITY_BUMP_TIER_1 = 1_000_000  # > $1M → depth 8
SEVERITY_BUMP_TIER_2 = 10_000_000  # > $10M → depth 10

# Budget headroom: large budget remaining → can afford deeper trace.
BUDGET_HEADROOM_BUMP = 100.0  # > $100 remaining → depth 12
# v0.32.1+ industry-best mode: budget starvation no longer collapses
# the trace to a shallow 4 hops. Recupero now ships budget-disabled by
# default, so a "starved" budget is the normal case. Keep the gate at
# 16 (a sensible safe floor) rather than 4 — operators who explicitly
# opt in to per-case budget tracking get the conservative behavior only
# when they've ALSO chosen to cap depth via RECUPERO_TRACE_MAX_HOPS.
BUDGET_STARVATION_CAP = 5.0  # < $5 remaining → floor at 16 (was 4)
BUDGET_STARVATION_FLOOR_DEPTH = 16  # was 4 in v0.32.0

# Hard ceiling — operators reach for this when they want to chase a
# 30-50 hop APT laundering chain end-to-end. v0.32.1+ industry-best
# mode raised the ceiling 16 → 64 so Recupero reaches destinations
# Reactor caps around 12. The frontier-size guard below still keeps
# combinatorial blow-up bounded; the depth ceiling alone never
# justifies stopping the trace.
HARD_CEILING = 64

# Frontier-size guard: if BFS frontier exceeds this at depth>=16,
# refuse to expand further. Prevents one popular CEX address from
# turning the trace into a graph of the entire ecosystem.
# v0.32.1+ industry-best mode: relaxed the guard so deep traces with
# legitimately bushy fanouts (CEX hot-wallet sprays, mixer post-pool
# disbursement) aren't artificially truncated. Was (depth>=8, size>10k);
# now (depth>=16, size>100k).
FRONTIER_REFUSE_AT_DEPTH = 16
FRONTIER_REFUSE_SIZE = 100_000


def _theft_amount(case_metadata: dict[str, Any] | None) -> float:
    """Extract the theft amount (USD) from case metadata, defensively.

    Looked-up keys in order: theft_amount_usd, total_loss_usd, loss_usd.
    Garbage / missing → 0.0 (no severity bump).
    """
    if not isinstance(case_metadata, dict):
        return 0.0
    for key in ("theft_amount_usd", "total_loss_usd", "loss_usd"):
        v = case_metadata.get(key)
        if v is None:
            continue
        try:
            f = float(v)
            if f != f or f in (float("inf"), float("-inf")):
                continue
            if f >= 0:
                return f
        except (ValueError, TypeError):
            continue
    return 0.0


def compute_max_depth(
    case_metadata: dict[str, Any] | None,
    api_budget_remaining_usd: float | None,
) -> int:
    """Decide the BFS max_depth for this trace.

    Logic (final depth is clipped to the hard ceiling):
      - UNBOUNDED budget (None / +inf — the default deployment ships
        budget tracking DISABLED, i.e. "budget doesn't matter, go
        deeper"): start from the industry-best floor (16) and stack the
        severity bumps ON TOP, so a $50M case is chased deeper (20) than
        a $50k one (16). This is the DEEPEST path — an uncapped
        deployment never loses hops.
      - Enabled budget < $5 (starved): floor at BUDGET_STARVATION_FLOOR_DEPTH
        (16) — even a tiny operator-set budget keeps the floor.
      - Enabled budget >= $5: base 6, +2 if theft > $1M, +2 more if
        theft > $10M, +2 if budget > $100 (operator opted into
        economization → shallower than the uncapped default, by design).
      - Never exceed HARD_CEILING (64 in industry-best mode).
    """
    theft = _theft_amount(case_metadata)

    # Coerce budget. None => UNBOUNDED (default disabled-budget deployment).
    # +inf is also unbounded. Garbage / NaN => 0.0 (treated as starved →
    # floor) so a poisoned value can never SHRINK the trace below the floor.
    if api_budget_remaining_usd is None:
        budget = float("inf")
    else:
        try:
            budget = float(api_budget_remaining_usd)
            if budget != budget:  # NaN
                budget = 0.0
        except (ValueError, TypeError):
            budget = 0.0

    # UNBOUNDED budget: the DEEPEST path. The budget never gates depth;
    # severity bumps stack on the industry-best floor (16 → 18 → 20).
    if budget == float("inf"):
        depth = BUDGET_STARVATION_FLOOR_DEPTH
        if theft > SEVERITY_BUMP_TIER_1:
            depth += 2
        if theft > SEVERITY_BUMP_TIER_2:
            depth += 2
        depth = min(HARD_CEILING, depth)
        log.debug(
            "compute_max_depth: UNBOUNDED budget, theft=$%s → depth=%d",
            theft, depth,
        )
        return depth

    # v0.32.1+ industry-best mode: a STARVED enabled budget no longer
    # collapses the trace to 4 — it floors at 16. An operator who set a
    # tiny per-case budget still shouldn't lose hops below the floor.
    if budget < BUDGET_STARVATION_CAP:
        log.debug(
            "compute_max_depth: budget %s < %s, flooring at %d",
            budget,
            BUDGET_STARVATION_CAP,
            BUDGET_STARVATION_FLOOR_DEPTH,
        )
        return BUDGET_STARVATION_FLOOR_DEPTH

    depth = DEFAULT_MAX_DEPTH

    if theft > SEVERITY_BUMP_TIER_1:
        depth += 2
    if theft > SEVERITY_BUMP_TIER_2:
        depth += 2
    if budget > BUDGET_HEADROOM_BUMP:
        depth += 2

    if depth > HARD_CEILING:
        depth = HARD_CEILING

    log.debug(
        "compute_max_depth: theft=$%s budget=$%s → depth=%d",
        theft,
        budget,
        depth,
    )
    return depth


def should_descend_further(
    current_depth: int,
    frontier_size: int,
    max_depth: int,
) -> bool:
    """Decide whether the BFS should descend to current_depth+1.

    Two stop conditions:
      - current_depth >= max_depth (always stop)
      - frontier_size > FRONTIER_REFUSE_SIZE AND
        current_depth >= FRONTIER_REFUSE_AT_DEPTH
        (combinatorial blow-up guard; explained at FRONTIER_REFUSE_*).
        Industry-best defaults: refuse when (depth>=16, size>100_000).
    """
    if not isinstance(current_depth, int) or current_depth < 0:
        return False
    if not isinstance(max_depth, int) or max_depth <= 0:
        return False
    if current_depth >= max_depth:
        return False
    if not isinstance(frontier_size, int) or frontier_size < 0:
        # Degenerate input — refuse rather than guess.
        return False
    if (
        current_depth >= FRONTIER_REFUSE_AT_DEPTH
        and frontier_size > FRONTIER_REFUSE_SIZE
    ):
        log.info(
            "should_descend_further: refusing expansion at depth=%d frontier=%d",
            current_depth,
            frontier_size,
        )
        return False
    return True
