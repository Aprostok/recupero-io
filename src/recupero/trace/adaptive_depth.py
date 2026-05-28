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
BUDGET_STARVATION_CAP = 5.0  # < $5 remaining → cap at 4

# Hard ceiling — even with infinite budget and a $1B theft, never
# descend deeper than this. Beyond depth 16 the frontier blows up
# combinatorially and the brief becomes unreadable.
HARD_CEILING = 16

# Frontier-size guard: if BFS frontier exceeds this at depth>=8,
# refuse to expand further. Prevents one popular CEX address from
# turning the trace into a graph of the entire ecosystem.
FRONTIER_REFUSE_AT_DEPTH = 8
FRONTIER_REFUSE_SIZE = 10_000


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

    Logic (each rule applies independently; final depth is clipped to
    the hard ceiling):
      - Base = 6.
      - +2 if theft > $1M.
      - +2 more if theft > $10M (so $10M+ caps at 10 from severity).
      - +2 if budget > $100 (so $10M+ with healthy budget can hit 12).
      - If budget < $5, hard cap at 4 (recovery starved).
      - Never exceed HARD_CEILING.
    """
    theft = _theft_amount(case_metadata)

    # Coerce budget input.
    try:
        budget = float(api_budget_remaining_usd) if api_budget_remaining_usd is not None else 0.0
        if budget != budget:  # NaN
            budget = 0.0
    except (ValueError, TypeError):
        budget = 0.0

    # Budget starvation: short-circuit before applying severity bumps.
    if budget < BUDGET_STARVATION_CAP:
        log.debug(
            "compute_max_depth: budget %s < %s, capping at 4",
            budget,
            BUDGET_STARVATION_CAP,
        )
        return 4

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
      - frontier_size > 10_000 AND current_depth >= 8
        (combinatorial blow-up guard; explained at FRONTIER_REFUSE_*)
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
