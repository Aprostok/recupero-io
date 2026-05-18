"""Tests for v0.14.6 monitor-tick worker stage.

DB I/O is mocked at the psycopg level; activity-fetch is mocked
via the ``fetch_activities_fn`` testing seam so we exercise the
core orchestration logic without hitting any network.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.monitoring.poller import (
    ObservedActivity,
    Subscription,
)
from recupero.worker.monitor_tick import (
    MonitorTickResult,
    run_monitor_tick,
)


def _sub_row(
    *,
    sub_id=None,
    address="0xperp",
    trigger_type="any_movement",
    threshold_usd=None,
    last_observed_tx_hash=None,
):
    return {
        "id": sub_id or uuid4(),
        "address": address,
        "chain": "ethereum",
        "trigger_type": trigger_type,
        "threshold_usd": threshold_usd,
        "webhook_url": "https://hook.example/alert",
        "webhook_secret": None,
        "last_observed_tx_hash": last_observed_tx_hash,
        "last_polled_at": None,
    }


def _activity(
    *,
    tx_hash="0xnew",
    amount_usd=Decimal("1000"),
    direction="outflow",
    counterparty="0xexch",
):
    return ObservedActivity(
        tx_hash=tx_hash,
        block_time_iso="2026-05-17T12:00:00Z",
        amount_usd=amount_usd,
        direction=direction,
        counterparty=counterparty,
        counterparty_label=None,
        counterparty_is_ofac=False,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


# ---- Empty-state ---- #


def test_no_active_subscriptions_returns_zero_counts() -> None:
    """No active subs → no work → all counters zero, errors empty."""
    with patch("psycopg.connect") as mock_connect:
        # Mock the cursor.fetchall to return no subs.
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        result = run_monitor_tick(dsn="postgres://test")
    assert result.subscriptions_polled == 0
    assert result.alerts_fired == 0
    assert result.errors == []


def test_db_unavailable_records_error() -> None:
    """When the subscription fetch raises, the tick should record
    the error and return — not crash."""
    with patch("psycopg.connect") as mock_connect:
        mock_connect.side_effect = Exception("connection refused")
        result = run_monitor_tick(dsn="postgres://test")
    assert len(result.errors) >= 1
    assert "connection refused" in result.errors[0]


# ---- One-sub happy path ---- #


def test_first_poll_no_cursor_bookmarks_without_firing() -> None:
    """A brand-new subscription (no cursor) on its first tick should
    advance the cursor to the newest activity but NOT fire any
    alerts (matches evaluate_all_activities first-poll behavior)."""
    sub_row = _sub_row(last_observed_tx_hash=None)
    activities = [
        _activity(tx_hash="0xnewest"),
        _activity(tx_hash="0xmiddle"),
        _activity(tx_hash="0xoldest"),
    ]

    def _fake_fetch(_sub, _chain):
        return activities

    with patch("psycopg.connect") as mock_connect:
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [sub_row]
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        result = run_monitor_tick(
            dsn="postgres://test",
            fetch_activities_fn=_fake_fetch,
        )

    assert result.subscriptions_polled == 1
    assert result.activities_evaluated == 3
    assert result.alerts_fired == 0  # first-poll: no firing


def test_subsequent_poll_fires_on_new_activity() -> None:
    """A subscription with a cursor at 'middle' should fire alerts
    only for activities newer than 'middle'."""
    sub_row = _sub_row(
        last_observed_tx_hash="0xmiddle",
        trigger_type="any_movement",
    )
    activities = [
        _activity(tx_hash="0xnewest"),
        _activity(tx_hash="0xmiddle"),  # cursor
        _activity(tx_hash="0xoldest"),
    ]

    def _fake_fetch(_sub, _chain):
        return activities

    # Mock dispatch_alert to always succeed.
    fake_result = MagicMock()
    fake_result.succeeded = True

    with patch("psycopg.connect") as mock_connect:
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [sub_row]
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        with patch(
            "recupero.monitoring.dispatcher.dispatch_alert",
            return_value=fake_result,
        ), patch(
            "recupero.monitoring.dispatcher.record_alert_attempt",
            return_value=uuid4(),
        ):
            result = run_monitor_tick(
                dsn="postgres://test",
                fetch_activities_fn=_fake_fetch,
            )

    assert result.subscriptions_polled == 1
    assert result.alerts_fired == 1
    assert result.alerts_succeeded == 1
    assert result.alerts_failed == 0


def test_failed_dispatch_recorded_in_failed_count() -> None:
    sub_row = _sub_row(
        last_observed_tx_hash="0xmiddle",
        trigger_type="any_movement",
    )
    activities = [
        _activity(tx_hash="0xnew1"),
        _activity(tx_hash="0xmiddle"),  # cursor
    ]

    def _fake_fetch(_sub, _chain):
        return activities

    fake_result = MagicMock()
    fake_result.succeeded = False  # dispatch fails

    with patch("psycopg.connect") as mock_connect:
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [sub_row]
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        with patch(
            "recupero.monitoring.dispatcher.dispatch_alert",
            return_value=fake_result,
        ), patch(
            "recupero.monitoring.dispatcher.record_alert_attempt",
            return_value=uuid4(),
        ):
            result = run_monitor_tick(
                dsn="postgres://test",
                fetch_activities_fn=_fake_fetch,
            )

    assert result.alerts_fired == 1
    assert result.alerts_succeeded == 0
    assert result.alerts_failed == 1
    assert result.ok is False


# ---- Per-sub error isolation ---- #


def test_one_bad_sub_does_not_poison_others() -> None:
    """If processing sub-A raises, sub-B should still be processed."""
    good_sub = _sub_row(sub_id=uuid4())
    bad_sub = _sub_row(sub_id=uuid4())

    def _fake_fetch(sub, _chain):
        if sub.subscription_id == bad_sub["id"]:
            raise RuntimeError("fetch boom")
        return [_activity(tx_hash="0xnew")]

    with patch("psycopg.connect") as mock_connect:
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [good_sub, bad_sub]
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        result = run_monitor_tick(
            dsn="postgres://test",
            fetch_activities_fn=_fake_fetch,
        )

    # Good sub processed; bad sub recorded as error.
    assert result.subscriptions_polled == 1  # only good_sub
    assert len(result.errors) == 1
    assert "fetch boom" in result.errors[0]


# ---- MonitorTickResult.ok ---- #


def test_ok_true_when_all_alerts_succeed() -> None:
    r = MonitorTickResult(
        subscriptions_polled=3,
        activities_evaluated=10,
        alerts_fired=2,
        alerts_succeeded=2,
        alerts_failed=0,
        errors=[],
    )
    assert r.ok is True


def test_ok_false_when_any_alert_fails() -> None:
    r = MonitorTickResult(
        subscriptions_polled=3,
        activities_evaluated=10,
        alerts_fired=2,
        alerts_succeeded=1,
        alerts_failed=1,
        errors=[],
    )
    assert r.ok is False


def test_ok_true_when_no_alerts_needed() -> None:
    """No alerts fired (e.g., first-poll bookmark, no new activity)
    → ok=True even if there are subs."""
    r = MonitorTickResult(
        subscriptions_polled=5,
        activities_evaluated=15,
        alerts_fired=0,
        alerts_succeeded=0,
        alerts_failed=0,
        errors=[],
    )
    assert r.ok is True


# ---- CLI entry point ---- #


def test_main_returns_1_when_no_dsn() -> None:
    """`recupero-worker --monitor-tick` without SUPABASE_DB_URL set
    must exit 1 (cron alerts on non-zero)."""
    import os
    from recupero.worker.monitor_tick import main
    original = os.environ.pop("SUPABASE_DB_URL", None)
    try:
        rc = main()
        assert rc == 1
    finally:
        if original is not None:
            os.environ["SUPABASE_DB_URL"] = original
