"""Unit tests for the pure helpers + dataclasses in worker/watch_tick.

The watch_tick module is a multi-chain RPC orchestrator with most of
its surface area I/O-bound. But it exposes a handful of pure helpers
(``_env_decimal``, ``_env_int``) and dataclasses (``MaterialChange``,
``WatchTickReport``) that benefit from coverage:

  * Bad env-var values fall through to defaults without crashing —
    the watch-tick service runs nightly and a config typo
    shouldn't take it offline.
  * The dataclass shapes are the contract the digest renderer binds
    to; locking them prevents accidental schema drift.

Tests run in <50ms total, zero network, zero DB.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from recupero.worker.watch_tick import (
    MaterialChange,
    WatchTickReport,
    _env_decimal,
    _env_int,
)

# ---- _env_decimal ---- #


def test_env_decimal_unset_returns_default(monkeypatch) -> None:
    """Missing env var → default. No crash, no warning needed."""
    monkeypatch.delenv("RECUPERO_TEST_DECIMAL", raising=False)
    assert _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0")) == Decimal("100.0")


def test_env_decimal_empty_string_returns_default(monkeypatch) -> None:
    """Empty string → default. Operators often set env vars to ""
    instead of unsetting them; that shouldn't crash."""
    monkeypatch.setenv("RECUPERO_TEST_DECIMAL", "")
    assert _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0")) == Decimal("100.0")


def test_env_decimal_whitespace_string_returns_default(monkeypatch) -> None:
    """Whitespace-only value → default. Same rationale as empty."""
    monkeypatch.setenv("RECUPERO_TEST_DECIMAL", "   ")
    assert _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0")) == Decimal("100.0")


def test_env_decimal_parses_valid_value(monkeypatch) -> None:
    """A real number string parses correctly."""
    monkeypatch.setenv("RECUPERO_TEST_DECIMAL", "2500.50")
    assert _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0")) == Decimal("2500.50")


def test_env_decimal_garbled_falls_back(monkeypatch, caplog) -> None:
    """Unparseable values fall back to default AND log a warning so
    the operator sees the typo. The watch-tick is nightly cron — a
    silent fallback to defaults would mask a config error."""
    import logging
    monkeypatch.setenv("RECUPERO_TEST_DECIMAL", "not-a-number")
    with caplog.at_level(logging.WARNING):
        out = _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0"))
    assert out == Decimal("100.0")
    # Verify the warning surfaces the bad value.
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("ignoring bad" in w.lower() or "not-a-number" in w for w in warnings)


def test_env_decimal_negative_value_parsed_as_is(monkeypatch) -> None:
    """Negative decimals parse cleanly — semantics is up to the
    caller, not the parser."""
    monkeypatch.setenv("RECUPERO_TEST_DECIMAL", "-50.25")
    assert _env_decimal("RECUPERO_TEST_DECIMAL", Decimal("100.0")) == Decimal("-50.25")


# ---- _env_int ---- #


def test_env_int_unset_returns_default(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_TEST_INT", raising=False)
    assert _env_int("RECUPERO_TEST_INT", 60) == 60


def test_env_int_parses_valid_value(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_TEST_INT", "120")
    assert _env_int("RECUPERO_TEST_INT", 60) == 120


def test_env_int_garbled_falls_back(monkeypatch) -> None:
    """Non-integer values fall back to default — matches
    _env_decimal's defensive contract."""
    monkeypatch.setenv("RECUPERO_TEST_INT", "120.5")
    assert _env_int("RECUPERO_TEST_INT", 60) == 60


def test_env_int_empty_string_returns_default(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_TEST_INT", "")
    assert _env_int("RECUPERO_TEST_INT", 60) == 60


def test_env_int_negative_value_parsed(monkeypatch) -> None:
    """Negative ints parse — semantics is up to the caller."""
    monkeypatch.setenv("RECUPERO_TEST_INT", "-5")
    assert _env_int("RECUPERO_TEST_INT", 60) == -5


# ---- MaterialChange shape ---- #


def test_material_change_required_fields() -> None:
    """The dataclass requires every field the digest renderer reads.
    A missing field would crash the digest at render time on prod."""
    mc = MaterialChange(
        watchlist_id=uuid4(),
        address="0x" + "a" * 40,
        chain="ethereum",
        role="suspect",
        label_name="Suspect wallet",
        is_freezeable=True,
        issuer="Circle",
        asset_symbol="USDC",
        prior_taken_at=datetime(2026, 5, 14, tzinfo=UTC),
        prior_usd=Decimal("10000"),
        prior_tx_count=5,
        new_taken_at=datetime(2026, 5, 15, tzinfo=UTC),
        new_usd=Decimal("9500"),
        new_tx_count=8,
        delta_usd=Decimal("-500"),
        tx_count_delta=3,
        reason="$500 outflow exceeded $100 threshold",
    )
    assert mc.is_freezeable is True
    assert mc.delta_usd == Decimal("-500")
    assert mc.reason.startswith("$500 outflow")


def test_material_change_nullable_fields() -> None:
    """label_name, issuer, asset_symbol, and prior_* fields are
    nullable — a wallet's first-ever snapshot has no prior, and
    unlabeled wallets have no name/issuer/symbol."""
    mc = MaterialChange(
        watchlist_id=uuid4(),
        address="0x" + "b" * 40,
        chain="solana",
        role="counterparty",
        label_name=None,
        is_freezeable=False,
        issuer=None,
        asset_symbol=None,
        prior_taken_at=None,
        prior_usd=None,
        prior_tx_count=None,
        new_taken_at=datetime(2026, 5, 15, tzinfo=UTC),
        new_usd=Decimal("250"),
        new_tx_count=1,
        delta_usd=None,
        tx_count_delta=None,
        reason="first observed snapshot",
    )
    assert mc.label_name is None
    assert mc.prior_usd is None


# ---- WatchTickReport shape ---- #


def test_watch_tick_report_default_lists_empty() -> None:
    """Errors and material_changes default to empty lists (not None)
    so the digest renderer can iterate without null-checking."""
    rpt = WatchTickReport(
        started_at=datetime(2026, 5, 15, tzinfo=UTC),
        finished_at=datetime(2026, 5, 15, 0, 5, tzinfo=UTC),
        candidates=100,
        snapshotted=95,
        skipped_cooldown=4,
        skipped_unsupported_chain=1,
    )
    assert rpt.errors == []
    assert rpt.material_changes == []


def test_watch_tick_report_default_lists_independent() -> None:
    """The empty-list defaults must be per-instance — a classic
    dataclass footgun is using ``field(default=[])`` instead of
    ``field(default_factory=list)``, which shares one list across
    every instance. Verify this isn't broken."""
    a = WatchTickReport(
        started_at=datetime(2026, 5, 15, tzinfo=UTC),
        finished_at=datetime(2026, 5, 15, 0, 5, tzinfo=UTC),
        candidates=1, snapshotted=1, skipped_cooldown=0,
        skipped_unsupported_chain=0,
    )
    b = WatchTickReport(
        started_at=datetime(2026, 5, 16, tzinfo=UTC),
        finished_at=datetime(2026, 5, 16, 0, 5, tzinfo=UTC),
        candidates=2, snapshotted=2, skipped_cooldown=0,
        skipped_unsupported_chain=0,
    )
    a.errors.append("error in a")
    assert b.errors == [], (
        "WatchTickReport.errors leaked across instances — switch to "
        "field(default_factory=list)"
    )


# ---- _fetch_eligible atomic-claim contract (race fix) ---- #


def test_fetch_eligible_uses_atomic_claim_not_bare_select() -> None:
    """v0.32.1 worker-resilience contract lock. watch-tick runs as an
    UNLEASED cron; pre-fix ``_fetch_eligible`` ran a bare SELECT and
    advanced ``last_snapshot_at`` only at the END (after the chain API
    call), so two overlapping ticks both claimed the same rows and both
    burned an RPC call + wrote a duplicate snapshot. The fix mirrors
    monitor_tick: an atomic ``UPDATE ... FROM (SELECT ... FOR UPDATE SKIP
    LOCKED) ... RETURNING`` that advances the claim mark as it selects.

    This is a source-level contract assertion (same shape as
    test_w2_w3_update_sql_carries_status_active_filter for monitor_tick)
    — it does not need a DB and guards against a regression that silently
    reverts to the racy bare SELECT.
    """
    import inspect

    from recupero.worker import watch_tick

    src = inspect.getsource(watch_tick._fetch_eligible)
    assert "FOR UPDATE SKIP LOCKED" in src, (
        "_fetch_eligible no longer carries FOR UPDATE SKIP LOCKED — the "
        "double-snapshot race has regressed to a bare SELECT"
    )
    # The claim must advance last_snapshot_at (the cooldown column doubles
    # as the claim mark) and RETURN the claimed rows.
    assert "SET last_snapshot_at = NOW()" in src
    assert "RETURNING" in src
    # Both the priority-aware and legacy-fallback paths must be claims.
    assert src.count("FOR UPDATE SKIP LOCKED") >= 2, (
        "both the priority and legacy-fallback queries must use the "
        "atomic claim, not just one"
    )
