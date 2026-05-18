"""Tests for the retry-on-transient wrapper around Resend HTTP calls.

Same pattern as test_ai_editorial_retry — patch time.sleep, mock
urlopen, exercise the wait sequence + exhaustion + non-retriable
short-circuits.

Why a separate test file (not folded into test_email.py)? The
retry helper is a self-contained transport-layer concern; isolating
it makes the contract obvious and avoids dragging the
DB / template / audit-log machinery into these tests.
"""

from __future__ import annotations

import io
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from recupero.worker._email import (
    _RESEND_RETRY_WAITS_SEC,
    _resend_send_with_retry,
)


def _mk_req() -> urllib.request.Request:
    return urllib.request.Request("https://api.resend.com/emails", method="POST")


def _mk_ok_response(body: bytes = b'{"id":"msg_abc"}') -> MagicMock:
    """Mock the context-manager that urlopen returns."""
    resp = MagicMock()
    resp.read.return_value = body
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


def _mk_http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://api.resend.com/emails",
        code=code,
        msg="error",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body),
    )


# ---- Happy path ---- #


def test_send_succeeds_first_try() -> None:
    """Single successful urlopen → parsed JSON returned, no sleep."""
    with patch("recupero.worker._email.urllib.request.urlopen",
               return_value=_mk_ok_response(b'{"id":"msg_1"}')), \
         patch("recupero.worker._email.time.sleep") as sleep:
        out = _resend_send_with_retry(_mk_req())
    assert out == {"id": "msg_1"}
    sleep.assert_not_called()


# ---- Transient retries ---- #


def test_retry_absorbs_one_5xx() -> None:
    """First call hits 503 → wait 5s → second call succeeds. Audit
    row sees only the success (the 503 was absorbed silently)."""
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep") as sleep:
        urlopen.side_effect = [
            _mk_http_error(503),
            _mk_ok_response(b'{"id":"msg_after_retry"}'),
        ]
        out = _resend_send_with_retry(_mk_req())
    assert out == {"id": "msg_after_retry"}
    # v0.16.8: jitter ±25% on each backoff so concurrent retries
    # desynchronize. We assert the wait is within the jitter band,
    # not exactly equal to the base value.
    assert sleep.call_count == 1
    actual_wait = sleep.call_args_list[0].args[0]
    base = _RESEND_RETRY_WAITS_SEC[0]
    assert base * 0.75 <= actual_wait <= base * 1.25, (
        f"jittered wait {actual_wait} outside ±25% band of base {base}"
    )


def test_retry_uses_full_wait_sequence_then_raises() -> None:
    """All 4 attempts fail with 5xx → waits 5/15/30 seconds (±25% jitter)
    in order between retries → raises the LAST exception (so the
    audit row captures the actual final failure).

    v0.16.8: jitter ±25% added to each backoff. We assert the
    PROGRESSION (each wait greater than the prior) and bounded
    spread, not exact values.
    """
    last = _mk_http_error(503)
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep") as sleep:
        urlopen.side_effect = [_mk_http_error(503),
                               _mk_http_error(503),
                               _mk_http_error(503),
                               last]
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            _resend_send_with_retry(_mk_req())
    waits = [c.args[0] for c in sleep.call_args_list]
    assert len(waits) == len(_RESEND_RETRY_WAITS_SEC)
    for actual, base in zip(waits, _RESEND_RETRY_WAITS_SEC):
        assert base * 0.75 <= actual <= base * 1.25, (
            f"jittered wait {actual} outside ±25% band of base {base}"
        )
    assert exc_info.value is last


def test_retry_handles_urlerror_transient() -> None:
    """URLError (DNS/connect/socket failure) → retried."""
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep"):
        urlopen.side_effect = [
            urllib.error.URLError("connection refused"),
            _mk_ok_response(b'{"id":"msg_after_urlerr"}'),
        ]
        out = _resend_send_with_retry(_mk_req())
    assert out == {"id": "msg_after_urlerr"}


def test_retry_handles_timeout() -> None:
    """socket.timeout / TimeoutError → retried (these surface as
    a separate exception class from URLError in some Python
    versions)."""
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep"):
        urlopen.side_effect = [
            TimeoutError("read timed out"),
            _mk_ok_response(b'{"id":"msg_after_timeout"}'),
        ]
        out = _resend_send_with_retry(_mk_req())
    assert out == {"id": "msg_after_timeout"}


# ---- 4xx short-circuit ---- #


def test_4xx_raises_immediately_no_retry() -> None:
    """400 / 401 / 403 → caller bug; don't retry — re-raise so the
    audit row captures the real error. Saves ~50s of retries that
    would all fail the same way."""
    err = _mk_http_error(400, b'{"message":"invalid from address"}')
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep") as sleep:
        urlopen.side_effect = [err]
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            _resend_send_with_retry(_mk_req())
    assert exc_info.value is err
    urlopen.assert_called_once()
    sleep.assert_not_called()


def test_429_is_retried() -> None:
    """429 is the exception to the 4xx-no-retry rule — rate-limiting
    is exactly the kind of transient we want to absorb."""
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep"):
        urlopen.side_effect = [
            _mk_http_error(429),
            _mk_ok_response(b'{"id":"msg_after_429"}'),
        ]
        out = _resend_send_with_retry(_mk_req())
    assert out == {"id": "msg_after_429"}


def test_404_raises_immediately() -> None:
    """404 is a caller bug (wrong endpoint URL) — don't retry."""
    err = _mk_http_error(404)
    with patch("recupero.worker._email.urllib.request.urlopen") as urlopen, \
         patch("recupero.worker._email.time.sleep") as sleep:
        urlopen.side_effect = [err]
        with pytest.raises(urllib.error.HTTPError):
            _resend_send_with_retry(_mk_req())
    sleep.assert_not_called()
