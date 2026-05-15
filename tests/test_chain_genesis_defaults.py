"""Unit tests for chain-genesis timestamps + wallet-trace defaults.

Two concerns:

  1. ``_CHAIN_GENESIS_TIMESTAMPS`` locks each supported chain's
     genesis-block timestamp. These are calendar facts — earlier
     values cause each chain's block-by-timestamp explorer endpoint
     to return "no closest block found", which the tracer chokes on
     (the original empirical bug). Tests guard against accidental
     edits to these values.

  2. ``_default_incident_time_for`` resolves the *operational*
     default for wallet-trace runs that don't supply an
     incident_time. As of the 365-day-lookback change, this returns
     ``now - lookback_days`` UNLESS that would predate chain-genesis,
     in which case genesis wins. The previous chain-genesis-only
     behavior was technically correct but operationally too slow
     for active wallets (depth-2 traces from 2015 routinely
     exceeded the 5-minute reaper threshold).

The lookback default is 365 days, configurable per-call via the
``RECUPERO_WALLET_TRACE_LOOKBACK_DAYS`` env var. Per-row overrides
work too — when the operator sets ``Investigation.incident_time``
explicitly, the default doesn't apply at all.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from recupero.worker.pipeline import (
    _CHAIN_GENESIS_TIMESTAMPS,
    _FALLBACK_GENESIS,
    _default_incident_time_for,
)


# ---- canonical genesis timestamps locked ---- #


def test_ethereum_genesis_is_block_1() -> None:
    """Ethereum's getblocknobytime answers from block 1, not block 0.
    Verified empirically — block 0 timestamp returns "no closest block
    found" because block 0 has a null timestamp."""
    expected = datetime(2015, 7, 30, 15, 26, 13, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["ethereum"] == expected


def test_polygon_genesis() -> None:
    """Polygon (formerly Matic) mainnet genesis."""
    expected = datetime(2020, 5, 30, 6, 23, 35, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["polygon"] == expected


def test_bsc_genesis() -> None:
    """BNB Smart Chain genesis."""
    expected = datetime(2020, 8, 29, 3, 24, 14, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["bsc"] == expected


def test_arbitrum_genesis() -> None:
    """Arbitrum One genesis."""
    expected = datetime(2021, 8, 31, 22, 9, 39, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["arbitrum"] == expected


def test_base_genesis() -> None:
    """Base mainnet genesis."""
    expected = datetime(2023, 6, 15, 17, 0, 0, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["base"] == expected


def test_solana_genesis() -> None:
    """Solana mainnet-beta launch. Not used by run_trace (Solana has
    its own slot-based lookup), but locked for the fallback case if
    dispatch logic ever changes."""
    expected = datetime(2020, 3, 16, 14, 0, 0, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["solana"] == expected


def test_hyperliquid_launched() -> None:
    """Hyperliquid launch. Not used by run_trace — for completeness."""
    expected = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert _CHAIN_GENESIS_TIMESTAMPS["hyperliquid"] == expected


# ---- dispatch behavior (operational default) ---- #


@pytest.mark.parametrize(
    "chain",
    ["ethereum", "polygon", "bsc", "arbitrum", "base", "solana", "hyperliquid"],
)
def test_default_returns_one_year_lookback_for_recent_now(chain: str, monkeypatch) -> None:
    """For a 'now' that's well past every chain's genesis (the
    operational case), the default is ``now - 365 days``. Faster than
    chain-genesis on active wallets — that was the operational
    bottleneck the change addresses."""
    # Pin lookback to the default explicitly so the env var can't
    # change the test's expected math.
    monkeypatch.delenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", raising=False)
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for(chain, now=now)
    expected = now - timedelta(days=365)
    assert out == expected, (
        f"chain={chain}: expected lookback {expected.isoformat()}, "
        f"got {out.isoformat()}"
    )


def test_default_clamps_to_genesis_for_new_chain(monkeypatch) -> None:
    """When ``now - lookback`` predates chain genesis (e.g., the
    365-day lookback in mid-2024 would have predated Base's June
    2023 genesis by a few months), the chain's genesis timestamp
    wins. Prevents the trace start from falling into the explorer's
    "no closest block found" error path."""
    monkeypatch.delenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", raising=False)
    # Pick a 'now' close enough to Base's genesis that a 365-day
    # lookback predates it. Base genesis is 2023-06-15; pick now =
    # 2024-04-01 so candidate=2023-04-01 (before genesis).
    now = datetime(2024, 4, 1, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("base", now=now)
    assert out == _CHAIN_GENESIS_TIMESTAMPS["base"], (
        f"expected genesis clamp, got {out.isoformat()}"
    )


def test_env_var_override_lookback(monkeypatch) -> None:
    """RECUPERO_WALLET_TRACE_LOOKBACK_DAYS overrides the 365-day
    default. Set to a large value to effectively re-enable
    full-history tracing for an ops emergency."""
    monkeypatch.setenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", "30")
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("ethereum", now=now)
    assert out == now - timedelta(days=30)


def test_env_var_huge_value_falls_back_to_genesis(monkeypatch) -> None:
    """A pragmatically-infinite lookback (99999 days) is the operator
    escape hatch for "trace full history" — should fall back to the
    chain genesis after clamping."""
    monkeypatch.setenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", "99999")
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("ethereum", now=now)
    # 99999 days ago is well before Ethereum genesis → clamps.
    assert out == _CHAIN_GENESIS_TIMESTAMPS["ethereum"]


def test_env_var_invalid_falls_back_to_default(monkeypatch) -> None:
    """A garbled env var doesn't crash the worker — falls back to the
    365-day default."""
    monkeypatch.setenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", "not-a-number")
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("ethereum", now=now)
    assert out == now - timedelta(days=365)


def test_env_var_zero_or_negative_minimum_one_day(monkeypatch) -> None:
    """Defensive: zero or negative lookback would default to "now"
    or future, which would emit zero transfers. Clamp to 1 day minimum
    so a misconfigured env doesn't silently produce empty traces."""
    for bad_value in ["0", "-5"]:
        monkeypatch.setenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", bad_value)
        now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
        out = _default_incident_time_for("ethereum", now=now)
        assert out == now - timedelta(days=1), (
            f"lookback={bad_value!r}: expected 1-day clamp"
        )


def test_case_insensitive_lookup(monkeypatch) -> None:
    """Chain names are normalized to lowercase before genesis lookup so
    a capitalization mismatch in the DB doesn't blow up the trace."""
    monkeypatch.delenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", raising=False)
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out_upper = _default_incident_time_for("ETHEREUM", now=now)
    out_mixed = _default_incident_time_for("Polygon", now=now)
    # Both should resolve to the 365-day default (post-genesis on both chains)
    assert out_upper == now - timedelta(days=365)
    assert out_mixed == now - timedelta(days=365)


def test_unknown_chain_uses_fallback_genesis_as_floor(monkeypatch) -> None:
    """An unknown chain uses the Ethereum-block-1 fallback as its
    genesis floor. A new chain in the DB schema shouldn't wedge the
    worker — it'll just use a defensive earliest-known-good floor."""
    monkeypatch.delenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", raising=False)
    # 'now' well past Ethereum genesis — 365-day lookback wins.
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("hypothetical_new_chain_v2", now=now)
    assert out == now - timedelta(days=365)


def test_unknown_chain_clamps_to_eth_genesis_floor(monkeypatch) -> None:
    """If the lookback would predate even Ethereum genesis (huge env
    var), the unknown-chain path still floors at Ethereum block 1."""
    monkeypatch.setenv("RECUPERO_WALLET_TRACE_LOOKBACK_DAYS", "99999")
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = _default_incident_time_for("hypothetical_new_chain_v2", now=now)
    assert out == _FALLBACK_GENESIS
    assert out == _CHAIN_GENESIS_TIMESTAMPS["ethereum"]


def test_all_genesis_are_utc() -> None:
    """Every entry must have an explicit UTC tzinfo — naive datetimes
    cause silent drift when the tracer compares against block
    timestamps (which Etherscan returns as Unix epoch, no TZ)."""
    for chain, ts in _CHAIN_GENESIS_TIMESTAMPS.items():
        assert ts.tzinfo is not None, f"{chain}: genesis must be tz-aware"
        assert ts.utcoffset().total_seconds() == 0, (
            f"{chain}: genesis must be UTC, got offset {ts.utcoffset()}"
        )


def test_genesis_ordered_by_chain_launch_year() -> None:
    """Sanity: the older chains have older genesis timestamps. Catches
    typos like swapping two chains' values — Base launched in 2023, so
    it can't be earlier than BSC's 2020 genesis."""
    eth = _CHAIN_GENESIS_TIMESTAMPS["ethereum"]
    polygon = _CHAIN_GENESIS_TIMESTAMPS["polygon"]
    bsc = _CHAIN_GENESIS_TIMESTAMPS["bsc"]
    arbitrum = _CHAIN_GENESIS_TIMESTAMPS["arbitrum"]
    base = _CHAIN_GENESIS_TIMESTAMPS["base"]
    assert eth < polygon < bsc < arbitrum < base, (
        "chain genesis timestamps should be in launch-year order — "
        "if you intentionally re-ordered these, update this test"
    )
