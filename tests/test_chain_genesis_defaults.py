"""Unit tests for per-chain genesis-timestamp defaults.

The wallet-trace path uses these as the default trace-window start
when the investigation row has incident_time=NULL. The values matter
because each chain's block-by-timestamp explorer endpoint returns
"no closest block found" for timestamps before that chain's genesis,
and the tracer chokes on that error string.

These tests just lock in the per-chain values + the fallback path —
they're calendar facts, not behavior we'd ever want to change without
explicit intent.
"""

from __future__ import annotations

from datetime import datetime, timezone

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


# ---- dispatch behavior ---- #


@pytest.mark.parametrize(
    "chain",
    ["ethereum", "polygon", "bsc", "arbitrum", "base", "solana", "hyperliquid"],
)
def test_default_resolves_per_chain(chain: str) -> None:
    """Every supported chain has a per-chain default — no chain
    silently falls through to the generic fallback."""
    out = _default_incident_time_for(chain)
    assert out == _CHAIN_GENESIS_TIMESTAMPS[chain]


def test_case_insensitive_lookup() -> None:
    """Chain names are normalized to lowercase before lookup so a
    capitalization mismatch in the DB doesn't blow up the trace."""
    assert _default_incident_time_for("ETHEREUM") == _CHAIN_GENESIS_TIMESTAMPS["ethereum"]
    assert _default_incident_time_for("Polygon") == _CHAIN_GENESIS_TIMESTAMPS["polygon"]


def test_unknown_chain_falls_back_to_ethereum() -> None:
    """An unknown chain falls back to the Ethereum genesis rather than
    raising. A new chain in the DB schema shouldn't immediately wedge
    the worker — it'll just trace from "too early" and the chain
    adapter will clamp internally."""
    out = _default_incident_time_for("hypothetical_new_chain_v2")
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
