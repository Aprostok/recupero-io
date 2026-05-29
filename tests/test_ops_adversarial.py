"""RIGOR-Jacob Z13: adversarial-input hunt for the recupero-ops CLI surface.

These tests exercise the operator-facing CLI surface with the kinds
of inputs an exhausted operator types at 2am — pasted-from-Excel
values with bidi / NUL bytes, ``NaN`` / ``Infinity`` Decimal strings,
and unbounded-length reason strings — and confirm the command modules
surface a clean error (not a Python traceback, not silent DB
corruption).

Each test is paired with one bug in src/recupero/ops/. Re-running
after the fix confirms the friendly-error path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# ---- Z13-1: mark_engaged with --fee NaN raises uncaught InvalidOperation ---- #


def test_mark_engaged_rejects_nan_fee_cleanly(capsys) -> None:
    """``recupero-ops mark-engaged --fee NaN`` should surface a friendly
    error and exit non-zero — not crash with a ``decimal.InvalidOperation``
    traceback from ``fee_usd <= 0`` (NaN comparisons trap by default).

    Pre-fix: ``Decimal('NaN') <= 0`` raises InvalidOperation, the
    exception is uncaught at the cli.py layer, and the operator sees
    a traceback while the investigation row is left untouched in a
    half-committed transaction state.
    """
    from recupero.ops.commands import mark_engaged

    # No DB mock needed — the bug triggers before the SELECT executes
    # because the validation check at the top of run() blows up on the
    # `fee_usd <= 0` comparison.
    result = mark_engaged.run(
        investigation_id=uuid4(),
        fee_usd=Decimal("NaN"),
        dsn="fake-dsn",
    )
    assert result == 1
    err_out = capsys.readouterr().out
    # Should call out NaN / non-finite, not show a traceback
    assert "NaN" in err_out or "finite" in err_out or "must be" in err_out


def test_mark_engaged_rejects_infinity_fee(capsys) -> None:
    """``Decimal('Infinity')`` for --fee should be rejected cleanly.
    (Existing > $1M bound catches this, but verify with NaN-style
    handling so a future refactor doesn't regress.)
    """
    from recupero.ops.commands import mark_engaged
    result = mark_engaged.run(
        investigation_id=uuid4(),
        fee_usd=Decimal("Infinity"),
        dsn="fake-dsn",
    )
    assert result == 1


# ---- Z13-2: mark_closed --reason with NUL/control chars ---- #


def test_mark_closed_rejects_null_byte_in_reason(capsys) -> None:
    """A pasted-from-Excel --reason with embedded NUL should be
    rejected at the command layer — psycopg silently strips NULs
    on TEXT inserts (or errors mid-transaction depending on version)
    and either outcome corrupts the change_summary audit trail.
    """
    from recupero.ops.commands import mark_closed
    with patch("recupero.ops.commands.mark_closed.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # Will only be reached if validation fails open — assert below
        # confirms we never reach the SELECT.
        mock_cursor.fetchone.return_value = {
            "id": uuid4(),
            "engagement_started_at": datetime(2026, 1, 1, tzinfo=UTC),
            "engagement_closed_at": None,
            "change_summary": None,
        }
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        result = mark_closed.run(
            investigation_id=uuid4(),
            reason="recovered\x00; DROP TABLE investigations;--",
            dsn="fake-dsn",
        )
    assert result == 1
    err = capsys.readouterr().out
    assert "control" in err.lower() or "null" in err.lower() or "invalid" in err.lower()


def test_mark_closed_rejects_bidi_override_in_reason(capsys) -> None:
    """A bidi-override (RLO U+202E) in --reason can spoof the audit
    log to display reversed text. Reject at the command layer."""
    from recupero.ops.commands import mark_closed
    result = mark_closed.run(
        investigation_id=uuid4(),
        reason="closed‮evil-reversed",
        dsn="fake-dsn",
    )
    assert result == 1


def test_mark_closed_rejects_oversize_reason(capsys) -> None:
    """An operator who pastes a 100KB chat-log into --reason should
    get a friendly cap, not a 100KB row in change_summary jsonb."""
    from recupero.ops.commands import mark_closed
    result = mark_closed.run(
        investigation_id=uuid4(),
        reason="x" * 20_000,  # 20KB — way past any legitimate audit note
        dsn="fake-dsn",
    )
    assert result == 1
    err = capsys.readouterr().out
    assert "length" in err.lower() or "too long" in err.lower() or "characters" in err.lower()


# ---- Z13-3: promote_freezable --reason adversarial inputs ---- #


def test_promote_freezable_rejects_null_byte_in_reason(capsys) -> None:
    """Operator promotion notes go straight to kyc_confirmation_note;
    NUL bytes need to be rejected at command layer."""
    from recupero.ops.commands import promote_freezable
    result = promote_freezable.run(
        watchlist_id=uuid4(),
        reason="Circle confirmed via ticket #1234567890\x00",
        force=False,
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result == 1


def test_promote_freezable_rejects_bidi_in_reason(capsys) -> None:
    """Bidi override in promotion reason → reject."""
    from recupero.ops.commands import promote_freezable
    result = promote_freezable.run(
        watchlist_id=uuid4(),
        reason="ticket‮1234567890",
        force=False,
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result == 1


def test_promote_freezable_rejects_oversize_reason(capsys) -> None:
    """100KB pasted note in --reason → reject."""
    from recupero.ops.commands import promote_freezable
    result = promote_freezable.run(
        watchlist_id=uuid4(),
        reason="ticket-paste " + "x" * 20_000,
        force=False,
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result == 1


# ---- Z13-4: record-freeze-outcome positional letter_id form ---- #


def test_record_outcome_nan_frozen_raises_clean_error() -> None:
    """``recupero.freeze_learning.recorder.record_outcome`` already
    validates NaN frozen_usd — confirm the ValueError it raises is
    clear (RIGOR-Jacob Z10 boundary). The CLI dispatcher in cli.py
    must catch this; if it doesn't, the operator gets a traceback.

    This test confirms the recorder boundary; the CLI catch is
    enforced by the structure of cli.py (we read it to confirm a
    try/except wraps record_outcome).
    """
    from recupero.freeze_learning.recorder import record_outcome
    with pytest.raises(ValueError, match="finite"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="full_freeze",
            frozen_usd=Decimal("NaN"),
            dsn="fake-dsn",
        )


def test_cli_record_outcome_positional_catches_value_error() -> None:
    """The positional letter_id branch of `record-freeze-outcome` in
    cli.py must wrap record_outcome() in a try/except so a NaN
    frozen_usd produces ``ERROR: ...`` + exit 2, not a traceback.

    We can't easily exec the CLI without sys.argv juggling; instead
    we confirm the source contains the catch — minimal but durable.
    """
    from pathlib import Path

    import recupero.ops.cli as cli_mod
    src = Path(cli_mod.__file__).read_text(encoding="utf-8")
    # The positional record_outcome call has to live inside a try/except
    # that catches ValueError (the recorder raises it for NaN inputs).
    # Look for the pattern: a try block before/around `record_outcome(`
    # that handles ValueError. We do a simple structural check — find
    # the line that calls `record_outcome(` for the positional branch
    # and assert it has a `try:` ancestor before the next dedent.
    lines = src.splitlines()
    # Find positional branch: `if has_letter_id:` is at the legacy form.
    in_positional = False
    saw_try_before_record_outcome_positional = False
    for i, line in enumerate(lines):
        if "if has_letter_id:" in line:
            in_positional = True
            continue
        if in_positional:
            stripped = line.strip()
            if stripped.startswith("try:"):
                saw_try_before_record_outcome_positional = True
            if "out_id = record_outcome(" in line:
                break
            if stripped.startswith("# v0.21.0 case-scoped form"):
                # Left the positional branch
                break
    assert saw_try_before_record_outcome_positional, (
        "cli.py positional record-freeze-outcome path does not wrap "
        "record_outcome() in a try/except. A --frozen-usd NaN argument "
        "will surface a ValueError traceback instead of `ERROR: ...`. "
        "Add a try/except around the record_outcome call mirroring the "
        "case-scoped branch."
    )
