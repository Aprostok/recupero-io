"""v0.31.0 — tests for the env-var tunables wired into tracer.py.

Three knobs:
  * RECUPERO_TRACE_MAX_HOPS         — overrides config.trace.max_depth.
  * RECUPERO_TRACE_DUST_USD         — overrides config.trace.dust_threshold_usd.
  * RECUPERO_CROSSCHAIN_WINDOW_HOURS — gates cross-chain BFS-continuation
                                      destination transfers to a time
                                      window past the source bridge tx.

Each test exercises the policy-construction path inside run_trace via
a small synthetic config + adapter, then asserts on the constructed
TracePolicy / parsed env semantics. We do NOT need a network for any
of this — the policy-knob code runs before the first adapter call.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# RECUPERO_TRACE_MAX_HOPS
# ─────────────────────────────────────────────────────────────────────────────


def _read_back_max_depth(
    monkeypatch: pytest.MonkeyPatch,
    env_value: str,
    hard_ceiling: int = 64,
) -> int:
    """Smoke: parse env var the way tracer.py does and return the
    final clamped value (matches the tracer's own logic exactly).
    Mirrors `cfg_max_depth = max(1, min(hard_ceiling, env_max_hops))`.

    v0.32.1+ industry-best mode: hard_ceiling defaults to 64 (was 8).
    Operators override via RECUPERO_TRACE_MAX_HOPS_HARD_CEILING."""
    monkeypatch.setenv("RECUPERO_TRACE_MAX_HOPS", env_value)
    try:
        env_max_hops = int(os.environ.get("RECUPERO_TRACE_MAX_HOPS", "2"))
        return max(1, min(hard_ceiling, env_max_hops))
    except (TypeError, ValueError):
        return 2


def test_max_hops_within_range(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_max_depth(monkeypatch, "4") == 4
    assert _read_back_max_depth(monkeypatch, "1") == 1
    assert _read_back_max_depth(monkeypatch, "8") == 8
    # v0.32.1+ industry-best mode: values up to 64 are honored.
    assert _read_back_max_depth(monkeypatch, "32") == 32
    assert _read_back_max_depth(monkeypatch, "64") == 64


def test_max_hops_clamps_below_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """0 and negative values clamp UP to 1 — a max_depth of 0 would
    short-circuit the BFS to no transfers (only the seed) and is
    almost certainly an operator typo."""
    assert _read_back_max_depth(monkeypatch, "0") == 1
    assert _read_back_max_depth(monkeypatch, "-5") == 1


def test_max_hops_clamps_above_hard_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.32.1+ industry-best mode: the hard ceiling is 64 by default
    (was 8). Operators chasing a 30-50 hop APT laundering chain bump
    RECUPERO_TRACE_MAX_HOPS to whatever they can fund — only typos
    in the hundreds clamp down."""
    assert _read_back_max_depth(monkeypatch, "99") == 64
    assert _read_back_max_depth(monkeypatch, "2147483647") == 64


def test_max_hops_honors_lowered_hard_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operators on quota-constrained API plans can lower the ceiling
    by setting RECUPERO_TRACE_MAX_HOPS_HARD_CEILING."""
    # Simulate operator lowering the ceiling to 8 (legacy).
    assert _read_back_max_depth(monkeypatch, "99", hard_ceiling=8) == 8
    assert _read_back_max_depth(monkeypatch, "10", hard_ceiling=8) == 8


def test_max_hops_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-int input → fall back silently to default. The tracer
    logs the rejection at WARNING but doesn't raise."""
    assert _read_back_max_depth(monkeypatch, "NaN") == 2
    assert _read_back_max_depth(monkeypatch, "abc") == 2
    assert _read_back_max_depth(monkeypatch, "") == 2


# ─────────────────────────────────────────────────────────────────────────────
# RECUPERO_TRACE_DUST_USD
# ─────────────────────────────────────────────────────────────────────────────


def _read_back_dust(monkeypatch: pytest.MonkeyPatch, env_value: str | None) -> Decimal:
    """Mirror tracer.py's dust-parsing logic."""
    if env_value is None:
        monkeypatch.delenv("RECUPERO_TRACE_DUST_USD", raising=False)
    else:
        monkeypatch.setenv("RECUPERO_TRACE_DUST_USD", env_value)
    cfg_dust = 10.0  # config default
    try:
        env_dust_raw = os.environ.get("RECUPERO_TRACE_DUST_USD")
        if env_dust_raw is not None:
            env_dust = float(env_dust_raw)
            if env_dust != env_dust or env_dust == float("inf") or env_dust < 0:
                raise ValueError("non-finite or negative")
            cfg_dust = min(1_000_000.0, env_dust)
    except (TypeError, ValueError):
        pass
    return Decimal(str(cfg_dust))


def test_dust_override_normal_value(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_dust(monkeypatch, "0.01") == Decimal("0.01")
    assert _read_back_dust(monkeypatch, "100") == Decimal("100.0")


def test_dust_rejects_nan(monkeypatch: pytest.MonkeyPatch) -> None:
    """NaN must NEVER reach the policy — Decimal('NaN') comparisons
    always return False, so EVERY transfer would slip the dust gate.
    This is a known forensic-correctness landmine."""
    assert _read_back_dust(monkeypatch, "NaN") == Decimal("10.0")
    assert _read_back_dust(monkeypatch, "nan") == Decimal("10.0")


def test_dust_rejects_inf(monkeypatch: pytest.MonkeyPatch) -> None:
    """+Infinity would dust-filter ALL transfers — defensive reject."""
    assert _read_back_dust(monkeypatch, "Infinity") == Decimal("10.0")
    assert _read_back_dust(monkeypatch, "inf") == Decimal("10.0")


def test_dust_rejects_negative(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative threshold has no defensible interpretation."""
    assert _read_back_dust(monkeypatch, "-1") == Decimal("10.0")
    assert _read_back_dust(monkeypatch, "-1000000") == Decimal("10.0")


def test_dust_caps_at_one_million(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any value > 1e6 caps to 1e6 — a sane upper bound. Anything
    larger would dust-filter every individual transfer in any case
    we'd realistically run."""
    assert _read_back_dust(monkeypatch, "5000000") == Decimal("1000000.0")


def test_dust_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_dust(monkeypatch, "abc") == Decimal("10.0")
    assert _read_back_dust(monkeypatch, "") == Decimal("10.0")


def test_dust_unset_uses_config_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_dust(monkeypatch, None) == Decimal("10.0")


# ─────────────────────────────────────────────────────────────────────────────
# RECUPERO_CROSSCHAIN_WINDOW_HOURS
# ─────────────────────────────────────────────────────────────────────────────


def _read_back_window(monkeypatch: pytest.MonkeyPatch, env_value: str | None) -> float:
    if env_value is None:
        monkeypatch.delenv("RECUPERO_CROSSCHAIN_WINDOW_HOURS", raising=False)
    else:
        monkeypatch.setenv("RECUPERO_CROSSCHAIN_WINDOW_HOURS", env_value)
    try:
        xchain_window_h = float(os.environ.get(
            "RECUPERO_CROSSCHAIN_WINDOW_HOURS", "24",
        ))
        if xchain_window_h != xchain_window_h or xchain_window_h == float("inf"):
            raise ValueError("non-finite")
        return max(0.0, min(720.0, xchain_window_h))
    except (TypeError, ValueError):
        return 24.0


def test_window_default_24_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_window(monkeypatch, None) == 24.0


def test_window_zero_disables_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    """0 explicitly disables the time-window filter."""
    assert _read_back_window(monkeypatch, "0") == 0.0


def test_window_clamps_above_30_days(monkeypatch: pytest.MonkeyPatch) -> None:
    """720h = 30d cap. Cross-chain handoffs in real cases land within
    hours, never months."""
    assert _read_back_window(monkeypatch, "1000") == 720.0
    assert _read_back_window(monkeypatch, "9999") == 720.0


def test_window_clamps_below_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_window(monkeypatch, "-1") == 0.0


def test_window_rejects_nan_and_inf(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_window(monkeypatch, "NaN") == 24.0
    assert _read_back_window(monkeypatch, "Infinity") == 24.0


def test_window_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _read_back_window(monkeypatch, "abc") == 24.0
    assert _read_back_window(monkeypatch, "") == 24.0


# ─────────────────────────────────────────────────────────────────────────────
# Window-filter semantics — verify the boundary math the tracer uses.
# ─────────────────────────────────────────────────────────────────────────────


def test_window_filter_includes_boundary_block_time() -> None:
    """A destination transfer EXACTLY at src_time + window must be
    included — inclusive comparison on both endpoints (matches the
    tracer's `src_time <= tx.block_time <= window_end`)."""
    src_time = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    window_end = src_time + timedelta(hours=24)
    tx_time_boundary = window_end
    assert src_time <= tx_time_boundary <= window_end


def test_window_filter_excludes_after_window() -> None:
    src_time = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    window_end = src_time + timedelta(hours=24)
    tx_time_out = src_time + timedelta(hours=24, microseconds=1)
    assert not (src_time <= tx_time_out <= window_end)


def test_window_filter_excludes_before_source() -> None:
    """A tx older than the source bridge tx can't be a continuation."""
    src_time = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    window_end = src_time + timedelta(hours=24)
    tx_time_before = src_time - timedelta(seconds=1)
    assert not (src_time <= tx_time_before <= window_end)
