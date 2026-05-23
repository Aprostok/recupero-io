"""Tests for the Resend email-sending primitive.

The network paths (actual Resend API calls) are mocked so the
tests run offline. The disable switch, from-header construction,
attachment encoding, error handling, and idempotency-check logic
are all unit-testable.

Audit-log writes are also unit-testable — they go to public.emails_sent
via psycopg. Tests stub the DB connection so we don't hit Supabase
in CI.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.worker._email import (
    EmailResult,
    _format_from_header,
    has_been_sent,
    send_email,
)

# ---- Disable switch + missing API key ---- #


def test_disable_email_env_var_skips_send(monkeypatch) -> None:
    """RECUPERO_DISABLE_EMAIL=1 short-circuits without touching the
    API or the DB. Returns a skipped EmailResult so callers can
    distinguish 'didn't send because configured off' from 'tried
    to send and failed'."""
    monkeypatch.setenv("RECUPERO_DISABLE_EMAIL", "1")
    result = send_email(
        to="victim@example.com",
        subject="Test",
        html="<p>body</p>",
        email_type="victim_summary",
    )
    assert result.success is False
    assert result.skipped is True
    assert "RECUPERO_DISABLE_EMAIL" in (result.error or "")


def test_missing_api_key_returns_failure(monkeypatch) -> None:
    """Without RESEND_API_KEY, send_email logs to audit and returns
    a failure result. Doesn't crash the caller."""
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    # Patch _log_to_audit so we don't try to write to a real DB
    with patch("recupero.worker._email._log_to_audit") as mock_log:
        result = send_email(
            to="victim@example.com", subject="Test",
            html="<p>body</p>", email_type="victim_summary",
        )
    assert result.success is False
    assert result.skipped is False
    assert "RESEND_API_KEY" in (result.error or "")
    # Audit log was attempted even for the failure
    mock_log.assert_called_once()


# ---- _format_from_header ---- #


def test_from_header_default(monkeypatch) -> None:
    """No env vars set → falls back to the canonical investigator-identity
    placeholder address (``compliance@recupero.io``), NOT the dev's
    address. v0.19.0 (round-11 arch follow-up): pre-v0.19.0 the
    fallback hard-coded ``alec@recupero.io``, so an unconfigured deploy
    routed every outbound message through the dev's mailbox; now the
    fallback flows from ``recupero._common.investigator_defaults``."""
    monkeypatch.delenv("RECUPERO_EMAIL_FROM", raising=False)
    monkeypatch.delenv("RECUPERO_EMAIL_FROM_NAME", raising=False)
    monkeypatch.delenv("RECUPERO_INVESTIGATOR_EMAIL", raising=False)
    assert _format_from_header(None, None) == (
        "Recupero Investigation Services <compliance@recupero.io>"
    )


def test_from_header_uses_investigator_email_when_set(monkeypatch) -> None:
    """v0.19.0: setting RECUPERO_INVESTIGATOR_EMAIL propagates to the
    From: fallback. Verifies the env-var path doesn't drift from
    investigator_defaults() over time."""
    monkeypatch.delenv("RECUPERO_EMAIL_FROM", raising=False)
    monkeypatch.delenv("RECUPERO_EMAIL_FROM_NAME", raising=False)
    monkeypatch.setenv("RECUPERO_INVESTIGATOR_EMAIL", "ops@example.com")
    assert _format_from_header(None, None) == (
        "Recupero Investigation Services <ops@example.com>"
    )


def test_from_header_env_override(monkeypatch) -> None:
    """RECUPERO_EMAIL_FROM and _FROM_NAME override the defaults."""
    monkeypatch.setenv("RECUPERO_EMAIL_FROM", "support@recupero.io")
    monkeypatch.setenv("RECUPERO_EMAIL_FROM_NAME", "Recupero Support")
    assert _format_from_header(None, None) == (
        "Recupero Support <support@recupero.io>"
    )


def test_from_header_explicit_override(monkeypatch) -> None:
    """Explicit args win over env vars."""
    monkeypatch.setenv("RECUPERO_EMAIL_FROM", "env@example.com")
    assert _format_from_header("explicit@example.com", "Explicit Sender") == (
        "Explicit Sender <explicit@example.com>"
    )


# ---- send_email: API call construction ---- #


def test_send_email_constructs_resend_request(monkeypatch) -> None:
    """Verify the POST request to Resend has the right URL, headers,
    and body shape. Most-important regression guard against future
    API-shape drift."""
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    monkeypatch.delenv("RECUPERO_EMAIL_FROM", raising=False)
    monkeypatch.delenv("RECUPERO_EMAIL_FROM_NAME", raising=False)

    # Mock urlopen to capture the request
    captured = {}
    def fake_urlopen(req, **_):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        class FakeResp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self):
                return json.dumps({"id": "msg_test_123"}).encode("utf-8")
        return FakeResp()

    with patch("recupero.worker._email.urllib.request.urlopen", fake_urlopen):
        with patch("recupero.worker._email._log_to_audit"):
            result = send_email(
                to="victim@example.com",
                subject="Test Subject",
                html="<p>hello</p>",
                email_type="victim_summary",
            )

    assert result.success is True
    assert result.message_id == "msg_test_123"
    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["method"] == "POST"
    # Authorization header — case-insensitive lookup
    auth_header = next(
        (v for k, v in captured["headers"].items() if k.lower() == "authorization"),
        None,
    )
    assert auth_header == "Bearer test-api-key"
    # Body shape
    body = captured["body"]
    assert body["to"] == ["victim@example.com"]
    assert body["subject"] == "Test Subject"
    assert body["html"] == "<p>hello</p>"
    assert "Recupero Investigation Services" in body["from"]


def test_send_email_with_attachments(monkeypatch) -> None:
    """Attachments are base64-encoded and included in the request
    body under the 'attachments' key."""
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)

    captured = {}
    def fake_urlopen(req, **_):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        class FakeResp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self):
                return json.dumps({"id": "msg_attach_456"}).encode("utf-8")
        return FakeResp()

    with TemporaryDirectory() as tmp:
        # Two fake attachment files
        f1 = Path(tmp) / "trace_report.pdf"
        f1.write_bytes(b"%PDF-1.7\nfake trace report")
        f2 = Path(tmp) / "flow.pdf"
        f2.write_bytes(b"%PDF-1.7\nfake flow diagram")

        with patch("recupero.worker._email.urllib.request.urlopen", fake_urlopen):
            with patch("recupero.worker._email._log_to_audit"):
                result = send_email(
                    to="victim@example.com", subject="With attachments",
                    html="<p>body</p>", email_type="victim_summary",
                    attachments=[f1, f2],
                )

    assert result.success is True
    body = captured["body"]
    assert "attachments" in body
    assert len(body["attachments"]) == 2
    names = {a["filename"] for a in body["attachments"]}
    assert names == {"trace_report.pdf", "flow.pdf"}
    # Verify base64 encoding round-trips
    for a in body["attachments"]:
        decoded = base64.b64decode(a["content"])
        assert decoded.startswith(b"%PDF-1.7")
    # Content-type set from extension
    types = {a["content_type"] for a in body["attachments"]}
    assert "application/pdf" in types


def test_send_email_handles_http_error(monkeypatch) -> None:
    """A 4xx/5xx from Resend → EmailResult.success=False, error
    contains the HTTP code + response body."""
    import urllib.error
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)

    def fake_urlopen_400(*_args, **_kwargs):
        # Simulate a 422 from Resend (invalid recipient)
        class FakeErr(urllib.error.HTTPError):
            def __init__(self):
                self.code = 422
                self.msg = "Unprocessable Entity"
            def read(self):
                return b'{"name":"validation_error","message":"Invalid email"}'
        raise FakeErr()

    with patch("recupero.worker._email.urllib.request.urlopen", fake_urlopen_400):
        with patch("recupero.worker._email._log_to_audit") as mock_log:
            # RIGOR-Wave6: a malformed recipient is now rejected at the
            # validator BEFORE the HTTP call (defense in depth). To
            # exercise the HTTP-422 branch the original test targeted,
            # supply a well-formed address — the mocked urlopen still
            # raises the 422 we're testing.
            result = send_email(
                to="recipient@example.com", subject="Test",
                html="<p>body</p>", email_type="victim_summary",
            )

    assert result.success is False
    assert result.skipped is False
    assert "HTTP 422" in (result.error or "")
    assert "Invalid email" in (result.error or "")
    # Audit was still logged (failure is auditable)
    mock_log.assert_called_once()


def test_send_email_handles_network_error(monkeypatch) -> None:
    """A network failure (DNS, connection refused, timeout) →
    EmailResult.success=False with URLError in the error."""
    import urllib.error
    monkeypatch.setenv("RESEND_API_KEY", "test-api-key")
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)

    def fake_urlopen_netfail(*_args, **_kwargs):
        raise urllib.error.URLError("Name resolution failed")

    with patch("recupero.worker._email.urllib.request.urlopen", fake_urlopen_netfail):
        with patch("recupero.worker._email._log_to_audit"):
            result = send_email(
                to="victim@example.com", subject="Test",
                html="<p>body</p>", email_type="victim_summary",
            )

    assert result.success is False
    assert "URLError" in (result.error or "")


# ---- has_been_sent (idempotency check) ---- #


def test_has_been_sent_returns_false_when_no_dsn(monkeypatch) -> None:
    """No DSN configured → idempotency check returns False so the
    caller proceeds with the send. Better to risk a duplicate
    than to skip silently."""
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    assert has_been_sent(
        investigation_id=uuid4(), email_type="victim_summary",
    ) is False


def test_has_been_sent_returns_true_on_match() -> None:
    """When a successful send row exists, returns True."""
    with patch("recupero.worker._email.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        assert has_been_sent(
            investigation_id=uuid4(), email_type="victim_summary",
            dsn="postgresql://test",
        ) is True


def test_has_been_sent_returns_false_on_no_match() -> None:
    """No matching row → False, caller should proceed."""
    with patch("recupero.worker._email.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn
        assert has_been_sent(
            investigation_id=uuid4(), email_type="victim_summary",
            dsn="postgresql://test",
        ) is False


def test_has_been_sent_fails_closed_on_db_error() -> None:
    """v0.19.2 (round-13 pipeline-HIGH-1): when the audit query fails
    (network blip, pooler 5xx, permissions) we now return True so the
    caller treats the send as "already done" and skips. Pre-v0.19.2
    we returned False ("not yet sent → go ahead"); but the victim-
    summary path mints a NEW Stripe payment link on every send, so a
    duplicate could mean a duplicate $10K engagement charge. Trading
    a delayed legitimate send (operator can force via ops CLI once
    the DB recovers) for an impossible duplicate charge is the right
    direction."""
    with patch("recupero.worker._email.psycopg.connect",
               side_effect=Exception("network down")):
        assert has_been_sent(
            investigation_id=uuid4(), email_type="victim_summary",
            dsn="postgresql://test",
        ) is True


# ---- EmailResult shape ---- #


def test_email_result_immutable() -> None:
    """EmailResult is frozen — callers shouldn't mutate the outcome
    after the send (it's a value object, not state)."""
    import dataclasses

    r = EmailResult(success=True, message_id="x", error=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.success = False  # type: ignore[misc]
