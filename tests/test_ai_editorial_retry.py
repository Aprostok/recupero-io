"""Tests for the retry-with-backoff wrapper around the Anthropic
messages.create call in recupero.reports.ai_editorial.

The motivation: Jacob reported a sustained 529 overloaded_error
during smoke tests that killed a 25-minute pipeline cycle. The
wrapper absorbs those transient failures with explicit
10s / 30s / 60s exponential waits.

We don't exercise the real Anthropic client here — the SDK is
mocked. The contracts under test:

  * Transient errors get retried up to N times.
  * Each retry uses the spec'd wait sequence.
  * Non-transient errors are raised immediately (no retry).
  * Successful calls on a later attempt return the response cleanly.
  * The final exception after exhaustion is the ORIGINAL exception
    (not a wrapped RetryError), so the existing error-handling at
    the call site still works.

Patching strategy: replace `time.sleep` so the tests run fast.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from recupero.reports.ai_editorial import (
    _ANTHROPIC_RETRY_MAX_ATTEMPTS,
    _ANTHROPIC_RETRY_WAITS_SEC,
    _call_messages_with_retry,
)

# ---- Synthetic exception types (mirror anthropic SDK shape) ---- #


class _FakeAPIStatusError(Exception):
    """Stand-in for anthropic.APIStatusError. Exposes a status_code
    attribute so the retry helper's log line can format it."""
    def __init__(self, status_code: int, msg: str = "overloaded") -> None:
        super().__init__(msg)
        self.status_code = status_code


class _FakeBadRequestError(Exception):
    """Stand-in for anthropic.BadRequestError (400). Should NOT be
    retried — caller bug, no amount of waiting fixes it."""
    def __init__(self) -> None:
        super().__init__("bad request")
        self.status_code = 400


def _mk_client(side_effects):
    """Build a mock Anthropic client whose .messages.create raises or
    returns from `side_effects` in order."""
    client = MagicMock()
    client.messages.create.side_effect = side_effects
    return client


# ---- Tests ---- #


def test_retry_succeeds_on_first_attempt() -> None:
    """Happy path: no retry needed. The wrapper returns the response
    and doesn't sleep."""
    expected_resp = MagicMock(name="response")
    client = _mk_client([expected_resp])
    with patch("recupero.reports.ai_editorial.time.sleep") as sleep:
        out = _call_messages_with_retry(
            client=client, system_blocks=[], user_content_blocks=[],
            transient_excs=(_FakeAPIStatusError,),
        )
    assert out is expected_resp
    assert client.messages.create.call_count == 1
    sleep.assert_not_called()


def test_retry_absorbs_one_transient_failure() -> None:
    """529 once → wait 10s → call succeeds. The original error is
    swallowed because the retry recovered."""
    expected_resp = MagicMock(name="response")
    client = _mk_client([_FakeAPIStatusError(529), expected_resp])
    with patch("recupero.reports.ai_editorial.time.sleep") as sleep:
        out = _call_messages_with_retry(
            client=client, system_blocks=[], user_content_blocks=[],
            transient_excs=(_FakeAPIStatusError,),
        )
    assert out is expected_resp
    assert client.messages.create.call_count == 2
    # First wait should be 10s per the spec.
    sleep.assert_called_once_with(_ANTHROPIC_RETRY_WAITS_SEC[0])


def test_retry_uses_spec_wait_sequence() -> None:
    """Multiple failures → waits 10s, 30s, 60s in order before each
    retry. Locks Jacob's spec so a future tuning doesn't drift away
    from the documented behavior."""
    expected_resp = MagicMock(name="response")
    client = _mk_client([
        _FakeAPIStatusError(529),
        _FakeAPIStatusError(529),
        _FakeAPIStatusError(529),
        expected_resp,
    ])
    with patch("recupero.reports.ai_editorial.time.sleep") as sleep:
        out = _call_messages_with_retry(
            client=client, system_blocks=[], user_content_blocks=[],
            transient_excs=(_FakeAPIStatusError,),
        )
    assert out is expected_resp
    waits = [c.args[0] for c in sleep.call_args_list]
    assert waits == list(_ANTHROPIC_RETRY_WAITS_SEC)


def test_retry_exhaustion_reraises_original_exception() -> None:
    """All attempts fail → the ORIGINAL exception type bubbles up,
    NOT a RetryError or wrapper. Important: the existing
    call_anthropic_for_editorial's error message expects the raw
    exception (it formats `.status_code`)."""
    last_error = _FakeAPIStatusError(529, "still overloaded")
    client = _mk_client([
        _FakeAPIStatusError(529), _FakeAPIStatusError(529),
        _FakeAPIStatusError(529), last_error,
    ])
    with patch("recupero.reports.ai_editorial.time.sleep"):
        with pytest.raises(_FakeAPIStatusError) as exc_info:
            _call_messages_with_retry(
                client=client, system_blocks=[], user_content_blocks=[],
                transient_excs=(_FakeAPIStatusError,),
            )
    assert exc_info.value is last_error  # exact instance, not a wrapper


def test_retry_attempts_count_matches_constant() -> None:
    """Exhaustion → exactly _ANTHROPIC_RETRY_MAX_ATTEMPTS attempts.
    Locks the relationship between the wait sequence + total
    attempts so adding a wait doesn't silently change the budget."""
    failures = [_FakeAPIStatusError(529) for _ in range(_ANTHROPIC_RETRY_MAX_ATTEMPTS)]
    client = _mk_client(failures)
    with patch("recupero.reports.ai_editorial.time.sleep"), pytest.raises(_FakeAPIStatusError):
        _call_messages_with_retry(
            client=client, system_blocks=[], user_content_blocks=[],
            transient_excs=(_FakeAPIStatusError,),
        )
    assert client.messages.create.call_count == _ANTHROPIC_RETRY_MAX_ATTEMPTS


def test_retry_does_not_retry_non_transient_errors() -> None:
    """An exception NOT in the transient_excs tuple → no retry, no
    sleep. The wrapper's purpose is transient-failure absorption,
    not blanket retry-everything."""
    client = _mk_client([_FakeBadRequestError()])
    with patch("recupero.reports.ai_editorial.time.sleep") as sleep:
        with pytest.raises(_FakeBadRequestError):
            _call_messages_with_retry(
                client=client, system_blocks=[], user_content_blocks=[],
                transient_excs=(_FakeAPIStatusError,),  # only 5xx-ish in scope
            )
    assert client.messages.create.call_count == 1
    sleep.assert_not_called()


def test_retry_passes_through_call_args() -> None:
    """The wrapper should call messages.create with the model + max
    tokens + system + messages blocks intact. Catches any future
    refactor that accidentally drops a kwarg."""
    expected_resp = MagicMock(name="response")
    client = _mk_client([expected_resp])
    system_blocks = [{"type": "text", "text": "sysprompt"}]
    user_blocks = [{"type": "text", "text": "user prompt"}]
    with patch("recupero.reports.ai_editorial.time.sleep"):
        _call_messages_with_retry(
            client=client, system_blocks=system_blocks,
            user_content_blocks=user_blocks,
            transient_excs=(_FakeAPIStatusError,),
        )
    kwargs = client.messages.create.call_args.kwargs
    assert kwargs["system"] == system_blocks
    assert kwargs["messages"] == [{"role": "user", "content": user_blocks}]
    assert "model" in kwargs
    assert "max_tokens" in kwargs


def test_retry_with_short_wait_sequence_locks_attempts() -> None:
    """Inject a custom short wait sequence — useful for tests + ops
    overrides. Total attempts = len(wait_seq) + 1."""
    client = _mk_client([
        _FakeAPIStatusError(529),
        _FakeAPIStatusError(529),
        _FakeAPIStatusError(529),
    ])
    with patch("recupero.reports.ai_editorial.time.sleep") as sleep:
        with pytest.raises(_FakeAPIStatusError):
            _call_messages_with_retry(
                client=client, system_blocks=[], user_content_blocks=[],
                transient_excs=(_FakeAPIStatusError,),
                wait_seq_sec=(1, 2),  # 3 total attempts
            )
    assert client.messages.create.call_count == 3
    # Only 2 sleeps (one less than total attempts; no sleep after
    # the final failed attempt — we raise instead).
    assert [c.args[0] for c in sleep.call_args_list] == [1, 2]
