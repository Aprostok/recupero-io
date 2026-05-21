"""Tests for the list-payments CLI command and the payments
dashboard widget.

The CLI runs a single SQL SELECT + manual table formatting; the
dashboard widget runs an aggregated COUNT query against the
same table. We test the SHAPE contracts (what fields exist,
what the empty fallback is) and the formatting helpers — the
DB layer is mocked, the live integration is exercised by the
canary verification at release time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

from recupero.ops.commands.list_payments import (
    _action_label,
    _fmt_datetime,
    _fmt_usd_cents,
    run,
)
from recupero.worker.dashboard_summary import (
    _empty_payments,
)

# ---- _fmt_usd_cents ---- #


def test_fmt_usd_cents_round_dollars() -> None:
    """$499 → '$499.00' (always two decimals). The engagement
    letter + the table both need consistent formatting."""
    assert _fmt_usd_cents(49900, "usd") == "$499.00"
    assert _fmt_usd_cents(1_000_000, "usd") == "$10,000.00"


def test_fmt_usd_cents_dollars_and_cents() -> None:
    """Fractional dollars formatted correctly."""
    assert _fmt_usd_cents(49950, "usd") == "$499.50"
    assert _fmt_usd_cents(1_234_567, "usd") == "$12,345.67"


def test_fmt_usd_cents_handles_none() -> None:
    """None amount → em-dash. Defensive against DB nulls."""
    assert _fmt_usd_cents(None, "usd") == "—"


def test_fmt_usd_cents_non_usd_shows_currency() -> None:
    """Non-USD currencies render with the ISO suffix instead of
    the dollar sign — defensive against future multi-currency
    Payment Links (Stripe supports a long list of currencies)."""
    out = _fmt_usd_cents(100000, "eur")
    assert "EUR" in out
    assert "$" not in out


# ---- _fmt_datetime ---- #


def test_fmt_datetime_aware() -> None:
    """A timezone-aware datetime renders in UTC."""
    dt = datetime(2026, 5, 17, 14, 32, 0, tzinfo=UTC)
    assert _fmt_datetime(dt) == "2026-05-17 14:32 UTC"


def test_fmt_datetime_naive_assumed_utc() -> None:
    """A naive datetime (shouldn't happen with timestamptz but
    defensive) is treated as UTC, not local time."""
    dt = datetime(2026, 5, 17, 14, 32, 0)
    assert _fmt_datetime(dt) == "2026-05-17 14:32 UTC"


def test_fmt_datetime_none() -> None:
    assert _fmt_datetime(None) == "—"


# ---- _action_label (notes → table label) ---- #


def test_action_label_truncates_notes_at_separators() -> None:
    """The dispatcher's notes field is operator-friendly prose:
    'engagement fee $10,000 recorded; follow-up cron will pick up'.
    The table column truncates at the first separator (semicolon
    here) so it stays readable."""
    label = _action_label(
        "engagement",
        "engagement fee $10,000.00 recorded; follow-up cron will pick up on next run",
    )
    assert label.startswith("engagement fee")
    assert ";" not in label
    assert "follow-up" not in label


def test_action_label_default_when_no_notes() -> None:
    """An empty notes field gets a sensible default per amount_type."""
    assert _action_label("diagnostic", "") == "diagnostic-paid"
    assert _action_label("engagement", "") == "engagement-paid"


def test_action_label_caps_at_30_chars() -> None:
    """Notes longer than 30 chars get truncated to fit the column."""
    notes = "x" * 200
    label = _action_label("unknown", notes)
    assert len(label) <= 30


# ---- _empty_payments dashboard shape ---- #


def test_empty_payments_shape_locked() -> None:
    """The UI binds against these keys. Adding one is intentional
    (and the UI should be notified); removing one is breaking."""
    out = _empty_payments()
    assert set(out.keys()) == {
        "count_24h",
        "paid_count_24h",
        "amount_paid_cents_24h",
        "refunded_count_24h",
        "disputed_count_24h",
        "count_7d",
        "paid_count_7d",
        "amount_paid_cents_7d",
        "needs_triage_count",
        "recent_refunds",
        "recent_disputes",
    }
    # Numeric counters start at 0; list fields start as empty lists.
    assert out["recent_refunds"] == []
    assert out["recent_disputes"] == []
    int_keys = (
        "count_24h", "paid_count_24h", "amount_paid_cents_24h",
        "refunded_count_24h", "disputed_count_24h",
        "count_7d", "paid_count_7d", "amount_paid_cents_7d",
        "needs_triage_count",
    )
    for k in int_keys:
        assert out[k] == 0, f"counter {k} should default to 0"


# ---- list-payments run() ---- #


def _mk_payment_row(**overrides):
    """Sparse row from public.payments + joined cases."""
    base = {
        "id": uuid4(),
        "received_at": datetime(2026, 5, 17, 14, 0, tzinfo=UTC),
        "processed_at": datetime(2026, 5, 17, 14, 0, 1, tzinfo=UTC),
        "amount_type": "diagnostic",
        "amount_cents": 49900,
        "currency": "usd",
        "status": "paid",
        "stripe_event_id": "evt_test_abc",
        "stripe_event_type": "checkout.session.completed",
        "notes": None,
        "case_id": uuid4(),
        "investigation_id": None,
        "case_number": "V-12345",
        "client_name": "Test Victim",
    }
    base.update(overrides)
    return base


def test_list_payments_rejects_bad_limit() -> None:
    """--limit out of range → exit 1 with a clear message."""
    assert run(limit=0, since="7d", case_id=None, dsn="fake") == 1
    assert run(limit=1001, since="7d", case_id=None, dsn="fake") == 1
    assert run(limit=-5, since="7d", case_id=None, dsn="fake") == 1


def test_list_payments_rejects_bad_since() -> None:
    """--since must be one of the documented strings."""
    assert run(limit=10, since="2w", case_id=None, dsn="fake") == 1


def test_list_payments_empty_db_prints_friendly_message(capsys) -> None:
    """No rows → friendly hint to widen the window. Don't print
    an empty table."""
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        rc = run(limit=10, since="7d", case_id=None, dsn="fake")

    captured = capsys.readouterr()
    assert rc == 0
    assert "No payments found" in captured.out
    # Hint about widening is only shown when no --case-id filter
    assert "--since all" in captured.out


def test_list_payments_renders_table(capsys) -> None:
    """Happy path: one diagnostic payment → table prints with the
    case number, amount, status, action label."""
    rows = [
        _mk_payment_row(
            amount_type="diagnostic", amount_cents=49900,
            case_number="V-99999",
            notes=(
                "diagnostic payment for case V-99999 "
                "($499.00); investigation abc-123 queued"
            ),
        ),
    ]
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = rows
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        rc = run(limit=10, since="7d", case_id=None, dsn="fake")

    captured = capsys.readouterr()
    assert rc == 0
    assert "V-99999" in captured.out
    assert "$499.00" in captured.out
    assert "diagnostic" in captured.out
    assert "paid" in captured.out
    # Notes wrap below
    assert "└─" in captured.out


def test_list_payments_handles_missing_case_number(capsys) -> None:
    """Stripe event with no matching case_id (operator-triage
    audit_only case) → case column shows em-dash, no crash."""
    rows = [
        _mk_payment_row(
            case_id=None, case_number=None, client_name=None,
            amount_type="unknown",
            notes="diagnostic payment without metadata.case_id",
        ),
    ]
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = rows
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        rc = run(limit=10, since="7d", case_id=None, dsn="fake")

    captured = capsys.readouterr()
    assert rc == 0
    assert "—" in captured.out  # case column placeholder
    assert "unknown" in captured.out


def test_list_payments_uses_interval_in_sql() -> None:
    """The SQL passed to psycopg should include a parameterized
    INTERVAL when --since is not 'all'. We check the call args
    rather than running real SQL."""
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        run(limit=10, since="7d", case_id=None, dsn="fake")

    sql, params = cur.execute.call_args.args
    assert "INTERVAL" in sql
    assert params["interval"] == "7 days"
    assert params["limit"] == 10


def test_list_payments_all_window_omits_since_filter() -> None:
    """--since all → no INTERVAL filter in the SQL. Used when
    operator wants the full history."""
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        run(limit=10, since="all", case_id=None, dsn="fake")

    sql, params = cur.execute.call_args.args
    assert "INTERVAL" not in sql
    assert "interval" not in params
    # case_id filter also absent
    assert "case_id" not in params


def test_list_payments_case_id_filter_appears_in_sql() -> None:
    """--case-id filter adds a WHERE clause + param."""
    case_uuid = uuid4()
    with patch(
        "recupero.ops.commands.list_payments.psycopg.connect"
    ) as mock_connect:
        cur = MagicMock()
        cur.fetchall.return_value = []
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn
        run(limit=10, since="all", case_id=case_uuid, dsn="fake")

    sql, params = cur.execute.call_args.args
    assert "p.case_id = %(case_id)s" in sql
    assert params["case_id"] == str(case_uuid)
