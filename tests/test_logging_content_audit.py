"""Logging-content audit (wave-6 follow-up).

Pins the invariant: a log line that interpolates a SENSITIVE value
(portal token, DSN password, raw HTTP body, full email address,
webhook secret, Bearer / API key) must not allow the sensitive
fingerprint to survive in caplog after the suspect callsite is
exercised.

The redaction infrastructure lives in two places:

* ``recupero.logging_setup._SecretRedactingFilter`` — the root-logger
  filter (covers DSN passwords, Bearer/api-key URLs, auth headers,
  sk-/ant- literal keys).
* Per-module mask helpers like
  ``recupero.worker._email._mask_email_for_log`` — used at the
  callsite for value classes the central filter can't safely target
  in-place (an arbitrary log line containing "alice@gmail.com" must
  NOT be redacted globally, because counterparty contact email is
  legitimate operator-facing context in some lines but PII-grade in
  others; the discriminator lives at the callsite).

Each test exercises a real callsite and asserts the sensitive
fingerprint does not appear anywhere in caplog's captured records.
"""

from __future__ import annotations

import io
import logging
import urllib.error
from unittest import mock

import pytest

from recupero.logging_setup import _redact
from recupero.worker._email import (
    EmailResult,
    _mask_email_for_log,
    send_email,
)


# ---------------------------------------------------------------- #
# Mask helper — unit-level
# ---------------------------------------------------------------- #


def test_mask_email_local_part_redacted() -> None:
    """The mask must NEVER reveal more than the leading char of the
    local-part. Full local-part survival is the bug we're guarding."""
    out = _mask_email_for_log("alice.victim+stripe@gmail.com")
    assert "alice.victim+stripe" not in out
    assert "alice" not in out
    assert out.startswith("a")
    assert out.endswith("@gmail.com")


def test_mask_email_handles_non_email_inputs() -> None:
    """A non-email string (or None) must not regex-confuse the mask
    into echoing the input verbatim."""
    assert _mask_email_for_log(None) == "<none>"
    assert _mask_email_for_log("not-an-email") == "***"
    assert _mask_email_for_log("") == "***"


# ---------------------------------------------------------------- #
# send_email — failure-path leak guards
# ---------------------------------------------------------------- #


def test_disable_email_path_does_not_log_full_recipient(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RECUPERO_DISABLE_EMAIL=1 is the dev/test short-circuit and
    runs on every CI job. Pre-fix it logged the FULL recipient
    address — a leaked dev log archive would contain hundreds of
    test-fixture victim emails (some of which mirror real victims
    when an operator re-runs an investigation locally)."""
    monkeypatch.setenv("RECUPERO_DISABLE_EMAIL", "1")
    caplog.set_level(logging.INFO, logger="recupero.worker._email")

    with mock.patch("recupero.worker._email._log_to_audit"):
        result = send_email(
            to="victim.alice.fullname@protonmail.com",
            subject="x",
            html="<p>x</p>",
            email_type="test",
        )
    assert result.skipped is True
    rendered = "\n".join(r.getMessage() for r in caplog.records)
    assert "victim.alice.fullname" not in rendered
    assert "protonmail.com" in rendered  # domain context preserved


def test_missing_resend_api_key_does_not_log_full_recipient(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When RESEND_API_KEY is unset, send_email logs a configuration
    warning. Pre-fix it interpolated the raw ``to`` address."""
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    caplog.set_level(logging.WARNING, logger="recupero.worker._email")

    with mock.patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="forensic.target.123@yahoo.com",
            subject="x",
            html="<p>x</p>",
            email_type="test",
            dsn=None,
        )
    rendered = "\n".join(r.getMessage() for r in caplog.records)
    assert "forensic.target.123" not in rendered


def test_resend_http_error_body_not_logged(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If Resend returns an HTTP error, the response body often echoes
    back fragments of the request (the recipient address, the subject
    line, sometimes a snippet of the html). The audit-DB row keeps the
    body for forensics, but the LOG line must NOT — log shipping ends
    up in SIEM archives that we can't unilaterally purge."""
    monkeypatch.setenv("RESEND_API_KEY", "rk_test_x" * 4)
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    caplog.set_level(logging.WARNING, logger="recupero.worker._email")

    err_body = (
        b'{"message":"Invalid recipient: confidential.case@'
        b'rich-victim-firm.com","webhook_secret":"whsec_LEAK_ME"}'
    )
    fake_http_err = urllib.error.HTTPError(
        url="https://api.resend.com/emails",
        code=422,
        msg="Unprocessable",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(err_body),
    )
    with mock.patch(
        "recupero.worker._email._resend_send_with_retry",
        side_effect=fake_http_err,
    ), mock.patch(
        "recupero.worker._email._log_to_audit",
    ):
        result = send_email(
            to="confidential.case@rich-victim-firm.com",
            subject="x",
            html="<p>x</p>",
            email_type="test",
            dsn=None,
        )
    assert result.success is False
    rendered = "\n".join(r.getMessage() for r in caplog.records)
    # The error body's secret fragments must not reach caplog.
    assert "confidential.case" not in rendered
    assert "whsec_LEAK_ME" not in rendered
    assert "Invalid recipient:" not in rendered
    # Status code IS expected (operator triage signal).
    assert "422" in rendered


def test_invalid_recipient_log_does_not_echo_address(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The address-validation rejection path used to log the
    attacker-supplied address verbatim. Two problems: (a) log
    injection if the attacker controls a CRLF in the address, (b)
    the address itself is sensitive. Both fixed: log line carries
    only email_type."""
    monkeypatch.delenv("RECUPERO_DISABLE_EMAIL", raising=False)
    caplog.set_level(logging.WARNING, logger="recupero.worker._email")
    with mock.patch("recupero.worker._email._log_to_audit"):
        send_email(
            to="this-is-not-a-valid-email-address",
            subject="x",
            html="<p>x</p>",
            email_type="freeze_letter",
            dsn=None,
        )
    rendered = "\n".join(r.getMessage() for r in caplog.records)
    assert "this-is-not-a-valid-email-address" not in rendered
    assert "freeze_letter" in rendered  # operator-triage context


# ---------------------------------------------------------------- #
# Central redaction — defense in depth
# ---------------------------------------------------------------- #


def test_dsn_password_in_exception_arg_redacted() -> None:
    """psycopg's OperationalError routinely embeds the full DSN with
    password in its str() form. Anyone calling ``log.exception(...)``
    or interpolating the exception into a log line would otherwise
    leak the DB password. The central redaction filter MUST catch
    this — it's the highest-impact leak vector."""
    msg = (
        "OperationalError: connection failed: "
        "postgresql://recupero:SuperSecretPw_2026@db.supabase.co:6543/postgres"
    )
    out = _redact(msg)
    assert "SuperSecretPw_2026" not in out
    assert "postgresql://recupero:***@" in out


def test_bearer_token_in_logged_request_redacted() -> None:
    """An httpx DEBUG line that dumps the request headers must not
    leak the Bearer token. This pattern bites every outbound API
    call — Resend, Stripe, Anthropic, Helius."""
    msg = (
        "request: POST https://api.resend.com/emails "
        "headers={'Authorization': 'Bearer re_live_LEAK_TOKEN_abc123'}"
    )
    out = _redact(msg)
    assert "re_live_LEAK_TOKEN_abc123" not in out


def test_anthropic_key_literal_redacted() -> None:
    """Defense-in-depth: even if a key escapes the header redaction
    by appearing in a free-form log line, the literal sk-ant- prefix
    pattern catches it."""
    msg = "WARN: API rejected — token sk-ant-api03-AAAAAAAAAAAAAAAAAAAA was invalid"
    out = _redact(msg)
    assert "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA" not in out


# ---------------------------------------------------------------- #
# repr() of objects holding sensitive fields
# ---------------------------------------------------------------- #


def test_email_result_repr_does_not_carry_recipient(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Some debug paths log ``EmailResult(...)`` via ``%r``. The
    dataclass intentionally does NOT include the recipient address
    in its fields — pinned here so a future refactor doesn't add it
    and silently leak the recipient through ``log.debug("%r", result)``."""
    result = EmailResult(success=True, message_id="msg_x", error=None)
    rendered = repr(result)
    assert "@" not in rendered
    assert "to=" not in rendered
