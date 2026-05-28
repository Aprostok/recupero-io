"""Tests for adaptive BFS depth (v0.32.1 trace gap C)."""

from __future__ import annotations

from recupero.trace.adaptive_depth import (
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


def test_starvation_caps_at_4() -> None:
    """Budget < $5 → cap at 4 regardless of severity."""
    assert compute_max_depth({"theft_amount_usd": 100_000_000}, 2.0) == 4
    assert compute_max_depth({"theft_amount_usd": 100_000_000}, 0.0) == 4


def test_hard_ceiling_enforced() -> None:
    """Even with very-large theft + budget, never exceed HARD_CEILING."""
    result = compute_max_depth({"theft_amount_usd": 10_000_000_000}, 1_000_000.0)
    assert result <= HARD_CEILING
    assert result == 12  # severity (+4) + headroom (+2) on base 6


def test_alternative_metadata_keys() -> None:
    """Falls back to total_loss_usd / loss_usd if theft_amount_usd absent."""
    assert compute_max_depth({"total_loss_usd": 5_000_000}, 50.0) == 8
    assert compute_max_depth({"loss_usd": 5_000_000}, 50.0) == 8


def test_garbage_metadata_no_crash() -> None:
    """Non-numeric values → fall back to defaults, no crash."""
    assert compute_max_depth({"theft_amount_usd": "lots"}, 50.0) == 6
    assert compute_max_depth({"theft_amount_usd": None}, 50.0) == 6


def test_garbage_budget_no_crash() -> None:
    """Garbage budget → treat as 0 (which triggers starvation cap)."""
    assert compute_max_depth({"theft_amount_usd": 100_000}, "infinite") == 4
    assert compute_max_depth({"theft_amount_usd": 100_000}, float("nan")) == 4


# ---- should_descend_further ---- #


def test_descend_at_shallow_depth() -> None:
    """Normal expansion at depth 3 with small frontier → True."""
    assert should_descend_further(3, 200, 8) is True


def test_stop_at_max_depth() -> None:
    """current == max → False."""
    assert should_descend_further(8, 200, 8) is False


def test_stop_past_max_depth() -> None:
    assert should_descend_further(10, 5, 8) is False


def test_frontier_explosion_at_depth_8() -> None:
    """Frontier > 10k at depth 8 → refuse further descent."""
    assert should_descend_further(8, 15_000, 12) is False


def test_large_frontier_below_depth_8_still_ok() -> None:
    """Big frontier at depth 5 → still allowed (early hops naturally bushy)."""
    assert should_descend_further(5, 15_000, 12) is True


def test_negative_inputs() -> None:
    """Negative depth or frontier → refuse (defensive)."""
    assert should_descend_further(-1, 100, 8) is False
    assert should_descend_further(3, -1, 8) is False
    assert should_descend_further(3, 100, 0) is False
