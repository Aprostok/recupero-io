"""Tests for adaptive BFS depth (v0.32.1 trace gap C).

v0.32.1+ industry-best mode bumped:
  * HARD_CEILING: 16 → 64 (Reactor caps ~12; we go deeper)
  * FRONTIER_REFUSE_AT_DEPTH: 8 → 16
  * FRONTIER_REFUSE_SIZE: 10_000 → 100_000
  * BUDGET_STARVATION_FLOOR_DEPTH: 4 → 16 (budget no longer gates depth)

Tests below assert the NEW industry-best values where they apply.
"""

from __future__ import annotations

from recupero.trace.adaptive_depth import (
    BUDGET_STARVATION_FLOOR_DEPTH,
    FRONTIER_REFUSE_AT_DEPTH,
    FRONTIER_REFUSE_SIZE,
    HARD_CEILING,
    compute_max_depth,
    should_descend_further,
)

# ---- compute_max_depth ---- #


def test_default_depth_no_metadata() -> None:
    """No metadata, $50 budget → base depth 6."""
    assert compute_max_depth(None, 50.0) == 6
    assert compute_max_depth({}, 50.0) == 6


def test_small_theft_no_bump() -> None:
    """$500k theft → still base depth (under $1M threshold)."""
    assert compute_max_depth({"theft_amount_usd": 500_000}, 50.0) == 6


def test_medium_theft_bumps_to_8() -> None:
    """$5M theft → depth 8."""
    assert compute_max_depth({"theft_amount_usd": 5_000_000}, 50.0) == 8


def test_large_theft_bumps_to_10() -> None:
    """$50M theft, moderate budget → depth 10 (severity bumps only)."""
    assert compute_max_depth({"theft_amount_usd": 50_000_000}, 50.0) == 10


def test_large_theft_with_headroom_hits_12() -> None:
    """$50M theft, $500 budget → depth 12 (all bumps apply)."""
    assert compute_max_depth({"theft_amount_usd": 50_000_000}, 500.0) == 12


def test_starvation_floor_industry_best() -> None:
    """v0.32.1+ industry-best mode: budget < $5 → floor at 16, not 4.

    With budget tracking disabled by default, "starved" is the normal
    case; previously this collapsed every trace to depth 4 which made
    the disabled-budget path actively worse than the budgeted path."""
    assert compute_max_depth(
        {"theft_amount_usd": 100_000_000}, 2.0,
    ) == BUDGET_STARVATION_FLOOR_DEPTH
    assert compute_max_depth(
        {"theft_amount_usd": 100_000_000}, 0.0,
    ) == BUDGET_STARVATION_FLOOR_DEPTH
    # The floor itself is 16 (the industry-best value).
    assert BUDGET_STARVATION_FLOOR_DEPTH == 16


def test_hard_ceiling_enforced() -> None:
    """Even with very-large theft + budget, never exceed HARD_CEILING.

    With base+severity+headroom maxing at 12, this test mainly locks
    in HARD_CEILING as an UPPER bound (the algorithm doesn't itself
    push to 64; that's the ceiling for operator-set RECUPERO_TRACE_MAX_HOPS).
    """
    result = compute_max_depth({"theft_amount_usd": 10_000_000_000}, 1_000_000.0)
    assert result <= HARD_CEILING
    assert result == 12  # severity (+4) + headroom (+2) on base 6
    # v0.32.1+ industry-best mode: HARD_CEILING raised from 16 to 64.
    assert HARD_CEILING == 64


def test_alternative_metadata_keys() -> None:
    """Falls back to total_loss_usd / loss_usd if theft_amount_usd absent."""
    assert compute_max_depth({"total_loss_usd": 5_000_000}, 50.0) == 8
    assert compute_max_depth({"loss_usd": 5_000_000}, 50.0) == 8


def test_garbage_metadata_no_crash() -> None:
    """Non-numeric values → fall back to defaults, no crash."""
    assert compute_max_depth({"theft_amount_usd": "lots"}, 50.0) == 6
    assert compute_max_depth({"theft_amount_usd": None}, 50.0) == 6


def test_garbage_budget_no_crash() -> None:
    """Garbage budget → treat as 0 (which triggers the starvation floor).

    v0.32.1+ industry-best mode: the floor is 16, not 4."""
    assert compute_max_depth(
        {"theft_amount_usd": 100_000}, "infinite",
    ) == BUDGET_STARVATION_FLOOR_DEPTH
    assert compute_max_depth(
        {"theft_amount_usd": 100_000}, float("nan"),
    ) == BUDGET_STARVATION_FLOOR_DEPTH


# ---- should_descend_further ---- #


def test_descend_at_shallow_depth() -> None:
    """Normal expansion at depth 3 with small frontier → True."""
    assert should_descend_further(3, 200, 8) is True


def test_stop_at_max_depth() -> None:
    """current == max → False."""
    assert should_descend_further(8, 200, 8) is False


def test_stop_past_max_depth() -> None:
    assert should_descend_further(10, 5, 8) is False


def test_frontier_explosion_at_industry_best_threshold() -> None:
    """v0.32.1+ industry-best mode: refuse only when
    frontier > 100k AND depth >= 16.

    The old (depth>=8, frontier>10k) gate was too aggressive — a CEX
    hot-wallet spray at depth 9 hits 12k frontier easily and the
    old gate truncated legitimately deep traces."""
    # Below the new threshold (depth<16): expansion allowed even with
    # a frontier that would have tripped the old gate.
    assert should_descend_further(8, 15_000, 32) is True
    assert should_descend_further(15, 50_000, 32) is True
    # At/past the new gate: refuse.
    assert should_descend_further(16, 150_000, 32) is False
    assert should_descend_further(20, 100_001, 32) is False


def test_large_frontier_at_industry_best_below_gate_still_ok() -> None:
    """Big frontier below depth 16 → still allowed (deep traces with
    legitimately bushy fanouts at depth 5-15 must continue)."""
    assert should_descend_further(5, 50_000, 32) is True
    assert should_descend_further(10, 99_000, 32) is True


def test_frontier_refuse_constants_industry_best() -> None:
    """Lock in the industry-best constants."""
    assert FRONTIER_REFUSE_AT_DEPTH == 16
    assert FRONTIER_REFUSE_SIZE == 100_000


def test_negative_inputs() -> None:
    """Negative depth or frontier → refuse (defensive)."""
    assert should_descend_further(-1, 100, 8) is False
    assert should_descend_further(3, -1, 8) is False
    assert should_descend_further(3, 100, 0) is False


# ---- v0.32.1 Phase-2: unbounded budget = deepest ("go deeper") ---- #


def test_unbounded_budget_none_is_deepest() -> None:
    """None budget = UNBOUNDED (the default disabled-budget deployment).
    Takes the DEEPEST path: the industry-best floor (16) with severity
    bumps stacked on top, so a high-value case is chased deeper than a
    small one. 'Budget doesn't matter, go deeper.'"""
    assert compute_max_depth(None, None) == BUDGET_STARVATION_FLOOR_DEPTH  # 16
    assert compute_max_depth({"theft_amount_usd": 500_000}, None) == 16  # < $1M
    assert compute_max_depth({"theft_amount_usd": 5_000_000}, None) == 18  # > $1M
    assert compute_max_depth({"theft_amount_usd": 50_000_000}, None) == 20  # > $10M


def test_unbounded_budget_inf_matches_none() -> None:
    """+inf is the same UNBOUNDED signal as None."""
    assert compute_max_depth({"theft_amount_usd": 50_000_000}, float("inf")) == 20
    assert compute_max_depth(None, float("inf")) == 16


def test_unbounded_high_value_deeper_than_enabled_budget() -> None:
    """An uncapped deployment chases a $50M case DEEPER (20) than the same
    case under an enabled, healthy budget (12) — enabling a budget is an
    opt-in to economization, by design. Pre-Phase-2 the adaptive wiring
    read the wrong snapshot key and flattened every case to the floor."""
    uncapped = compute_max_depth({"theft_amount_usd": 50_000_000}, None)
    enabled = compute_max_depth({"theft_amount_usd": 50_000_000}, 500.0)
    assert uncapped == 20
    assert enabled == 12
    assert uncapped > enabled


def test_unbounded_never_exceeds_hard_ceiling() -> None:
    """Even unbounded + astronomical theft stays clipped to HARD_CEILING."""
    assert compute_max_depth({"theft_amount_usd": 1e18}, None) <= HARD_CEILING
