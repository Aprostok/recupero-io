"""Tests for the engagement-state + emails-sent extensions to
``GET /investigations/<id>``.

The two helpers under test:

  * ``_build_engagement_summary(row)`` — pure-Python derivation
    of engagement status / days-remaining / needs-followup from
    the raw engagement_* columns. No I/O, deterministic.

  * ``_fetch_emails_summary(dsn, inv_id)`` — DB query that
    aggregates emails_sent into a UI-friendly shape. Uses
    mocked psycopg.connect for tests; the integration coverage
    lives in the live verification against the canary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

from recupero.worker.investigations_api import (
    _build_engagement_summary,
    _fetch_emails_summary,
)

# ---- _build_engagement_summary ---- #


def _row(**overrides) -> dict:
    """Sparse row template. Override the engagement_* fields per test."""
    base = {
        "engagement_started_at": None,
        "engagement_closed_at": None,
        "engagement_fee_paid_usd": None,
        "last_followup_sent_at": None,
    }
    base.update(overrides)
    return base


def test_engagement_not_engaged() -> None:
    """No engagement_started_at → 'not_engaged' + everything NULL."""
    summary = _build_engagement_summary(_row())
    assert summary["status"] == "not_engaged"
    assert summary["fee_paid_usd"] is None
    assert summary["started_at"] is None
    assert summary["days_since_start"] is None
    assert summary["days_remaining"] is None
    assert summary["needs_followup"] is False


def test_engagement_active_fresh() -> None:
    """engagement_started_at set + no closed, less than 30 days
    in → 'active' status."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=5),
        engagement_fee_paid_usd=Decimal("1500"),
    ))
    assert summary["status"] == "active"
    assert summary["days_since_start"] == 5
    assert summary["days_remaining"] == 25
    assert summary["fee_paid_usd"] == "1500"


def test_engagement_closed() -> None:
    """engagement_closed_at set → 'closed' regardless of how long ago."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=10),
        engagement_closed_at=now - timedelta(days=2),
    ))
    assert summary["status"] == "closed"
    assert summary["needs_followup"] is False


def test_engagement_expired_uncloseed_after_30_days() -> None:
    """Active engagement (no closed_at) past day 30 → 'expired'.
    The operator should run mark-closed on these — but the API
    surfaces the state so the UI can show a "needs closing" alert."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=35),
    ))
    assert summary["status"] == "expired"
    assert summary["days_since_start"] == 35
    assert summary["days_remaining"] == 0
    assert summary["needs_followup"] is False


def test_needs_followup_when_never_sent() -> None:
    """Active engagement with no last_followup_sent_at →
    needs_followup True. The daily cron will pick this up
    on its next run."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=1),
        last_followup_sent_at=None,
    ))
    assert summary["status"] == "active"
    assert summary["needs_followup"] is True


def test_needs_followup_when_stale() -> None:
    """Active engagement, last followup more than 6 days ago →
    needs_followup True (matches the cron's 6-day cadence)."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=15),
        last_followup_sent_at=now - timedelta(days=7),
    ))
    assert summary["status"] == "active"
    assert summary["needs_followup"] is True


def test_does_not_need_followup_when_recent() -> None:
    """Recently sent followup → needs_followup False."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=15),
        last_followup_sent_at=now - timedelta(days=3),
    ))
    assert summary["status"] == "active"
    assert summary["needs_followup"] is False


def test_closed_engagement_never_needs_followup() -> None:
    """Even if the followup is stale, a closed engagement should
    not flag needs_followup — the cron correctly excludes these."""
    now = datetime.now(UTC)
    summary = _build_engagement_summary(_row(
        engagement_started_at=now - timedelta(days=15),
        engagement_closed_at=now - timedelta(days=1),
        last_followup_sent_at=now - timedelta(days=20),
    ))
    assert summary["status"] == "closed"
    assert summary["needs_followup"] is False


def test_summary_shape_locked() -> None:
    """Lock the dict keys — the UI binds to this contract.
    Adding a key here is intentional (and the UI should be
    notified); removing one is a breaking change."""
    summary = _build_engagement_summary(_row())
    assert set(summary.keys()) == {
        "status",
        "fee_paid_usd",
        "started_at",
        "closed_at",
        "last_followup_at",
        "days_since_start",
        "days_remaining",
        "needs_followup",
    }


def test_naive_datetime_assumed_utc() -> None:
    """If the DB returns a naive datetime (shouldn't happen with
    timestamptz, but defensive), the helper treats it as UTC."""
    naive = datetime.now() - timedelta(days=3)  # NO tzinfo
    summary = _build_engagement_summary(_row(
        engagement_started_at=naive,
    ))
    assert summary["status"] == "active"
    # days_since_start may be off-by-one near midnight; just assert
    # it's a positive int in the expected ballpark
    assert summary["days_since_start"] in (2, 3, 4)


# ---- _fetch_emails_summary ---- #


def test_emails_summary_empty_log() -> None:
    """No emails sent → counts all zero + recent is empty list."""
    inv_id = str(uuid4())
    with patch("recupero.worker.investigations_api.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # Aggregate row: zero counts
        mock_cursor.fetchone.side_effect = [
            {"total": 0, "successful": 0, "failed": 0, "last_sent_at": None},
        ]
        # By-type query: empty
        # Recent query: empty
        mock_cursor.fetchall.side_effect = [[], []]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        summary = _fetch_emails_summary(dsn="fake-dsn", investigation_id=inv_id)

    assert summary == {
        "total": 0, "successful": 0, "failed": 0,
        "by_type": {}, "last_sent_at": None, "recent": [],
    }


def test_emails_summary_with_sends() -> None:
    """Mixed success + failure rows aggregate correctly."""
    inv_id = str(uuid4())
    now = datetime.now(UTC)
    with patch("recupero.worker.investigations_api.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            {"total": 5, "successful": 4, "failed": 1, "last_sent_at": now},
        ]
        mock_cursor.fetchall.side_effect = [
            # by_type query
            [
                {"email_type": "victim_summary", "n": 1},
                {"email_type": "freeze_letter", "n": 3},
            ],
            # recent query
            [
                {"sent_at": now, "to_address": "compliance@circle.com",
                 "email_type": "freeze_letter", "subject": "Circle Freeze",
                 "error_message": None},
            ],
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        summary = _fetch_emails_summary(dsn="fake-dsn", investigation_id=inv_id)

    assert summary["total"] == 5
    assert summary["successful"] == 4
    assert summary["failed"] == 1
    assert summary["by_type"] == {"victim_summary": 1, "freeze_letter": 3}
    assert len(summary["recent"]) == 1
    assert summary["recent"][0]["success"] is True
    assert summary["recent"][0]["to_address"] == "compliance@circle.com"


def test_emails_summary_db_error_returns_empty_shape() -> None:
    """If the DB query fails, return the empty shape — the UI's
    detail response must still be renderable. Matches the
    defensive pattern in _build_artifacts_map."""
    inv_id = str(uuid4())
    with patch("recupero.worker.investigations_api.psycopg.connect",
               side_effect=Exception("network blip")):
        summary = _fetch_emails_summary(dsn="fake-dsn", investigation_id=inv_id)

    assert summary["total"] == 0
    assert summary["by_type"] == {}
    assert summary["recent"] == []


def test_emails_summary_shape_locked() -> None:
    """Lock the response keys — same UI-contract reasoning as
    the engagement summary."""
    with patch("recupero.worker.investigations_api.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "total": 0, "successful": 0, "failed": 0, "last_sent_at": None,
        }
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        summary = _fetch_emails_summary(dsn="fake-dsn", investigation_id=str(uuid4()))
    assert set(summary.keys()) == {
        "total", "successful", "failed", "by_type",
        "last_sent_at", "recent",
    }
