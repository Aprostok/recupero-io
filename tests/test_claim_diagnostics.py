"""Unit tests for the claim-failure diagnostic path in worker/main.

The original null-incident_time regression took 12+ hours to find
because the silent-catch in ``_try_claim`` swallowed the pydantic
``ValidationError`` with a one-line log message that didn't:

  * Include the full traceback (which would have named the offending
    column directly).
  * Mention that the row was now stuck in 'claimed' state.
  * Cool down between retries — the polling loop kept hammering
    `claim_one` every 2s, generating noise in logs without making
    progress.

These tests lock in the diagnostic improvements:

  * `_try_claim` uses log.exception (full traceback) not log.error.
  * `_try_claim` cools down after a claim failure so the same broken
    row can't generate a thousand log lines in 30 seconds.
  * On success, `_try_claim` returns the Investigation unchanged
    (no behavior change on the happy path).

These don't exercise claim_one's mark_failed self-recovery path —
that needs a real DB connection. Those are covered by manual
end-to-end verification (canary fa34bb56 ran the full path on
Railway).
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from recupero.worker.db import Investigation
from recupero.worker.main import _try_claim


def _make_fake_investigation() -> Investigation:
    """Build a minimal valid Investigation for happy-path tests."""
    from uuid import uuid4
    return Investigation.model_validate({
        "id": uuid4(),
        "status": "pending",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
    })


def test_happy_path_returns_investigation_unchanged() -> None:
    """When claim_one returns an Investigation, _try_claim passes it
    through verbatim. No cooldown, no extra logging."""
    fake_inv = _make_fake_investigation()
    db = MagicMock()
    db.claim_one.return_value = fake_inv

    result = _try_claim(db)

    assert result is fake_inv
    db.claim_one.assert_called_once()


def test_no_work_returns_none() -> None:
    """When claim_one returns None (no claimable rows), _try_claim
    returns None unchanged. No exception means no cooldown."""
    db = MagicMock()
    db.claim_one.return_value = None

    result = _try_claim(db)

    assert result is None
    db.claim_one.assert_called_once()


def test_exception_is_logged_with_traceback(caplog) -> None:
    """When claim_one raises, _try_claim logs at ERROR level WITH the
    full traceback. The original bug was invisible because the
    one-line log message didn't surface enough context."""
    db = MagicMock()
    db.claim_one.side_effect = ValueError("synthetic test failure")

    # Mock the shutdown event's wait so we don't actually sleep 30s.
    with patch("recupero.worker.main._shutdown") as mock_shutdown:
        mock_shutdown.wait = MagicMock(return_value=False)
        with caplog.at_level(logging.ERROR):
            result = _try_claim(db)

    assert result is None
    # log.exception emits ERROR-level records with exc_info set.
    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(error_records) >= 1, (
        "expected at least one ERROR log record on claim failure"
    )
    # At least one record should carry exception info (the full traceback).
    has_exc_info = any(r.exc_info is not None for r in error_records)
    assert has_exc_info, (
        "expected log.exception (with exc_info), got plain log.error. "
        "Without the traceback, pydantic ValidationErrors don't name "
        "the offending column — which was the root cause of the "
        "12-hour discovery delay for the incident_time bug."
    )


def test_exception_triggers_cooldown(caplog) -> None:
    """A claim failure should call _shutdown.wait() with the
    cooldown seconds before returning. Without this, the polling
    loop hits claim_one again within 2s and generates rapid-fire
    log spam from the same broken row."""
    db = MagicMock()
    db.claim_one.side_effect = ValueError("synthetic test failure")

    with patch("recupero.worker.main._shutdown") as mock_shutdown:
        mock_shutdown.wait = MagicMock(return_value=False)
        _try_claim(db)

    # Verify _shutdown.wait was called with a positive cooldown.
    assert mock_shutdown.wait.called, (
        "expected _try_claim to call _shutdown.wait() for cooldown"
    )
    cooldown_arg = mock_shutdown.wait.call_args[0][0]
    assert cooldown_arg > 0, (
        f"cooldown must be positive seconds, got {cooldown_arg}"
    )
    # Reasonable upper bound — 30s is the current default. Anything
    # north of 5 minutes would over-react to transient DB blips.
    assert cooldown_arg <= 300, (
        f"cooldown too long: {cooldown_arg}s would over-react to "
        f"transient claim failures"
    )


def test_cooldown_interrupted_by_shutdown() -> None:
    """If SIGTERM fires during the claim-failure cooldown,
    _shutdown.wait returns True and we should return None
    immediately without further work. This guarantees a clean
    Railway redeploy drains in <30s even if the worker hits a
    claim failure during the drain."""
    db = MagicMock()
    db.claim_one.side_effect = ValueError("synthetic test failure")

    with patch("recupero.worker.main._shutdown") as mock_shutdown:
        # wait() returns True when the event was set (shutdown signal).
        mock_shutdown.wait = MagicMock(return_value=True)
        result = _try_claim(db)

    assert result is None
    # Verify wait was called exactly once — no retry loop after
    # shutdown interruption.
    assert mock_shutdown.wait.call_count == 1
