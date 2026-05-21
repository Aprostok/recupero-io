"""Tests for the recupero-ops CLI helpers.

Argument parsing + dispatch is tested with stubs for the actual
SQL / network calls — the command modules' core logic (idempotency
checks, confirmation prompts, dispatch plan building) is what
matters for the tests, not the underlying DB / Resend layers
(those are covered by the email module tests + integration
verification against the live DB).
"""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

# ---- _parse_uuid + _confirm ---- #


def test_parse_uuid_accepts_canonical_form() -> None:
    from recupero.ops.cli import _parse_uuid
    s = "e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c"
    u = _parse_uuid(s)
    assert isinstance(u, UUID)
    assert str(u) == s


def test_parse_uuid_rejects_garbage(capsys) -> None:
    from recupero.ops.cli import _parse_uuid
    with pytest.raises(SystemExit) as exc_info:
        _parse_uuid("not-a-uuid")
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "must be a UUID" in err


def test_confirm_assume_yes_short_circuits(monkeypatch) -> None:
    """RECUPERO_OPS_ASSUME_YES=1 returns True without prompting,
    so the ops commands are scriptable from CI / batch jobs."""
    from recupero.ops.cli import _confirm
    monkeypatch.setenv("RECUPERO_OPS_ASSUME_YES", "1")
    assert _confirm("anything", default=False) is True


def test_confirm_empty_input_uses_default(monkeypatch) -> None:
    """Pressing enter (empty input) returns the default value.
    Lets ops commands provide safe-defaults for their prompts."""
    from recupero.ops.cli import _confirm
    monkeypatch.delenv("RECUPERO_OPS_ASSUME_YES", raising=False)
    with patch("builtins.input", return_value=""):
        assert _confirm("OK?", default=False) is False
        assert _confirm("OK?", default=True) is True


def test_confirm_yes_returns_true(monkeypatch) -> None:
    from recupero.ops.cli import _confirm
    monkeypatch.delenv("RECUPERO_OPS_ASSUME_YES", raising=False)
    with patch("builtins.input", return_value="y"):
        assert _confirm("?", default=False) is True
    with patch("builtins.input", return_value="yes"):
        assert _confirm("?", default=False) is True


def test_confirm_no_returns_false(monkeypatch) -> None:
    from recupero.ops.cli import _confirm
    monkeypatch.delenv("RECUPERO_OPS_ASSUME_YES", raising=False)
    with patch("builtins.input", return_value="n"):
        assert _confirm("?", default=True) is False


def test_confirm_eof_returns_false(monkeypatch) -> None:
    """Ctrl-D / EOF should cancel (return False), not raise."""
    from recupero.ops.cli import _confirm
    monkeypatch.delenv("RECUPERO_OPS_ASSUME_YES", raising=False)
    with patch("builtins.input", side_effect=EOFError):
        assert _confirm("?", default=True) is False


# ---- mark-engaged command ---- #


def test_mark_engaged_missing_investigation_returns_1() -> None:
    from recupero.ops.commands import mark_engaged
    with patch("recupero.ops.commands.mark_engaged.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = mark_engaged.run(
            investigation_id=uuid4(), fee_usd=Decimal("1500"),
            dsn="fake-dsn",
        )
    assert result == 1


def test_mark_engaged_idempotent_on_already_active() -> None:
    """Running mark-engaged on an already-active engagement is a
    no-op (preserves the original start time)."""
    from datetime import datetime

    from recupero.ops.commands import mark_engaged
    with patch("recupero.ops.commands.mark_engaged.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # Row exists with engagement_started_at set + no closed
        mock_cursor.fetchone.return_value = {
            "id": uuid4(),
            "status": "complete",
            "engagement_started_at": datetime(2026, 1, 1, tzinfo=UTC),
            "engagement_closed_at": None,
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = mark_engaged.run(
            investigation_id=uuid4(), fee_usd=Decimal("1500"),
            dsn="fake-dsn",
        )
    assert result == 0
    # Should NOT have called UPDATE (only the SELECT)
    update_calls = [
        c for c in mock_cursor.execute.call_args_list
        if "UPDATE" in str(c)
    ]
    assert len(update_calls) == 0


# ---- mark-closed command ---- #


def test_mark_closed_errors_if_no_engagement() -> None:
    """Can't close what isn't open."""
    from recupero.ops.commands import mark_closed
    with patch("recupero.ops.commands.mark_closed.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "id": uuid4(),
            "engagement_started_at": None,
            "engagement_closed_at": None,
            "change_summary": None,
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = mark_closed.run(
            investigation_id=uuid4(),
            reason="test", dsn="fake-dsn",
        )
    assert result == 1


def test_mark_closed_idempotent_on_already_closed(capsys) -> None:
    """Running mark-closed on an already-closed engagement returns
    0 without modifying state."""
    from datetime import datetime

    from recupero.ops.commands import mark_closed
    with patch("recupero.ops.commands.mark_closed.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "id": uuid4(),
            "engagement_started_at": datetime(2026, 1, 1, tzinfo=UTC),
            "engagement_closed_at": datetime(2026, 2, 1, tzinfo=UTC),
            "change_summary": "prior",
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = mark_closed.run(
            investigation_id=uuid4(),
            reason="test", dsn="fake-dsn",
        )
    assert result == 0
    captured = capsys.readouterr()
    assert "already closed" in captured.out


# ---- send-freeze-letters: dispatch plan logic ---- #


def test_send_freeze_letters_no_investigation_returns_1() -> None:
    """Missing investigation → error exit."""
    from recupero.ops.commands import send_freeze_letters
    with patch.object(send_freeze_letters, "_fetch_investigation",
                      return_value=None):
        result = send_freeze_letters.run(
            investigation_id=uuid4(), issuer_filter=None,
            dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
        )
    assert result == 1


def test_send_freeze_letters_no_freeze_brief_returns_1() -> None:
    """Investigation exists but no freeze_brief in bucket → error."""
    from recupero.ops.commands import send_freeze_letters
    with patch.object(send_freeze_letters, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": uuid4(),
                                    "status": "complete"}):
        with patch.object(send_freeze_letters, "_fetch_freeze_brief_from_bucket",
                          return_value=None):
            result = send_freeze_letters.run(
                investigation_id=uuid4(), issuer_filter=None,
                dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
            )
    assert result == 1


def test_send_freeze_letters_wallet_trace_returns_1() -> None:
    """Wallet-trace investigations (case_id=NULL) have no freeze
    letters to send — error with explanatory message."""
    from recupero.ops.commands import send_freeze_letters
    with patch.object(send_freeze_letters, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": None,
                                    "status": "complete"}):
        result = send_freeze_letters.run(
            investigation_id=uuid4(), issuer_filter=None,
            dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
        )
    assert result == 1


def test_send_freeze_letters_empty_freezable_returns_0(capsys) -> None:
    """If FREEZABLE is empty (case-driven case but no recoverable
    funds), there's nothing to send — return 0 with a NOTE."""
    from recupero.ops.commands import send_freeze_letters
    with patch.object(send_freeze_letters, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": uuid4(),
                                    "status": "complete"}):
        with patch.object(send_freeze_letters, "_fetch_freeze_brief_from_bucket",
                          return_value={"FREEZABLE": []}):
            result = send_freeze_letters.run(
                investigation_id=uuid4(), issuer_filter=None,
                dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
            )
    assert result == 0
    captured = capsys.readouterr()
    assert "no FREEZABLE entries" in captured.out


def test_send_freeze_letters_issuer_filter_no_match_returns_1() -> None:
    """If --issuer is provided but no FREEZABLE entry matches, error."""
    from recupero.ops.commands import send_freeze_letters
    with patch.object(send_freeze_letters, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": uuid4(),
                                    "status": "complete"}):
        with patch.object(send_freeze_letters, "_fetch_freeze_brief_from_bucket",
                          return_value={"FREEZABLE": [
                              {"issuer": "Circle", "token": "USDC",
                               "contact_email": "c@circle.com",
                               "total_usd": "$1000"},
                          ]}):
            result = send_freeze_letters.run(
                investigation_id=uuid4(),
                issuer_filter="Tether",  # not in the brief
                dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
            )
    assert result == 1


# ---- followup-now command ---- #


def test_followup_now_requires_active_engagement() -> None:
    """followup-now errors if the investigation has no
    engagement_started_at (the cron eligibility requirement)."""
    from recupero.ops.commands import followup_now
    with patch("recupero.ops.commands.followup_now.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "investigation_id": uuid4(),
            "case_id": uuid4(),
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
            "engagement_started_at": None,  # NOT engaged
            "last_followup_sent_at": None,
            "freezable_issuers": None,
            "victim_email": "x@example.com",
            "victim_name": "X",
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = followup_now.run(
            investigation_id=uuid4(), dsn="fake-dsn",
            confirm=lambda *_a, **_kw: True,
        )
    assert result == 1


def test_followup_now_requires_victim_email() -> None:
    """Engaged investigation without cases.client_email can't be
    sent — error."""
    from datetime import datetime

    from recupero.ops.commands import followup_now
    with patch("recupero.ops.commands.followup_now.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "investigation_id": uuid4(),
            "case_id": uuid4(),
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
            "engagement_started_at": datetime(2026, 1, 1, tzinfo=UTC),
            "last_followup_sent_at": None,
            "freezable_issuers": None,
            "victim_email": None,  # missing
            "victim_name": "X",
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = followup_now.run(
            investigation_id=uuid4(), dsn="fake-dsn",
            confirm=lambda *_a, **_kw: True,
        )
    assert result == 1


def test_followup_now_user_cancels_returns_1(capsys) -> None:
    """If the operator types 'n' at the confirmation prompt, the
    command exits 1 without sending."""
    from datetime import datetime

    from recupero.ops.commands import followup_now
    with patch("recupero.ops.commands.followup_now.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {
            "investigation_id": uuid4(),
            "case_id": uuid4(),
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
            "engagement_started_at": datetime(2026, 1, 1, tzinfo=UTC),
            "last_followup_sent_at": None,
            "freezable_issuers": None,
            "victim_email": "x@example.com",
            "victim_name": "X",
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = followup_now.run(
            investigation_id=uuid4(), dsn="fake-dsn",
            confirm=lambda *_a, **_kw: False,  # user declines
        )
    assert result == 1
    assert "Cancelled" in capsys.readouterr().out


# ---- send-le-handoff command ---- #


def test_send_le_handoff_no_letter_in_bucket_returns_1() -> None:
    """If the bucket has no le_handoff_*.html for this investigation,
    error."""
    from recupero.ops.commands import send_le_handoff
    with patch.object(send_le_handoff, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": uuid4(),
                                    "status": "complete"}):
        with patch.object(send_le_handoff, "_list_bucket_briefs",
                          return_value=[]):
            result = send_le_handoff.run(
                investigation_id=uuid4(), to_email="le@fbi.gov",
                dsn="fake-dsn", confirm=lambda *_a, **_kw: True,
            )
    assert result == 1


def test_send_le_handoff_user_cancel_returns_1(capsys) -> None:
    """Operator declines at the confirmation → exit 1, no send."""
    from recupero.ops.commands import send_le_handoff
    with patch.object(send_le_handoff, "_fetch_investigation",
                      return_value={"id": uuid4(), "case_id": uuid4(),
                                    "status": "complete"}):
        with patch.object(send_le_handoff, "_list_bucket_briefs",
                          return_value=[{"name": "le_handoff_circle_BRIEF-20260515T120000-abc.html"}]):
            with patch.object(send_le_handoff, "_already_sent_to",
                              return_value=False):
                result = send_le_handoff.run(
                    investigation_id=uuid4(), to_email="le@fbi.gov",
                    dsn="fake-dsn", confirm=lambda *_a, **_kw: False,
                )
    assert result == 1
    assert "Cancelled" in capsys.readouterr().out


# ---- _find_latest_le_handoff ---- #


def test_find_latest_le_handoff_picks_most_recent_timestamp() -> None:
    """When multiple le_handoff files exist (from re-runs), pick
    the one with the latest BRIEF-<timestamp> suffix."""
    from recupero.ops.commands.send_le_handoff import _find_latest_le_handoff
    files = [
        {"name": "le_handoff_circle_BRIEF-20260514T120000-old.html"},
        {"name": "le_handoff_circle_BRIEF-20260515T130000-mid.html"},
        {"name": "le_handoff_circle_BRIEF-20260515T140000-new.html"},
        {"name": "freeze_request_circle_BRIEF-20260516T000000-x.html"},  # not LE
    ]
    latest = _find_latest_le_handoff(files)
    assert latest == "le_handoff_circle_BRIEF-20260515T140000-new.html"


def test_find_latest_le_handoff_none_when_no_match() -> None:
    """No le_handoff_*.html in the file list → None."""
    from recupero.ops.commands.send_le_handoff import _find_latest_le_handoff
    files = [
        {"name": "freeze_request_circle_BRIEF-x.html"},
        {"name": "trace_report_abc.html"},
    ]
    assert _find_latest_le_handoff(files) is None
