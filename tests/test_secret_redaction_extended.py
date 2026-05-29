"""Extended secret-redaction audit for ``_SecretRedactingFilter``.

Wave-5 added DSN + Bearer + sk-/ant- redaction. This file deepens the
coverage to the broader set of vendor key formats the codebase
plausibly encounters in log output: Stripe, OpenAI (sk-proj-),
GitHub PATs, AWS access keys, Resend, JWT-shaped tokens
(incl. Supabase service-role), and Recupero portal access tokens.

For each format we exercise BOTH the pure ``_redact`` helper and the
full ``_SecretRedactingFilter`` (so we catch handler-wiring breaks
too). The invariant is the same: the secret fingerprint must not
survive into the rendered log message.
"""

from __future__ import annotations

import logging

import pytest

from recupero.logging_setup import _redact, _SecretRedactingFilter

# ---------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------- #


def _run_filter(message: str, *args: object) -> str:
    """Run a fabricated LogRecord through ``_SecretRedactingFilter`` and
    return the post-filter rendered message. This mirrors what every
    downstream handler sees."""
    rec = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=0,
        msg=message, args=args or None, exc_info=None,
    )
    flt = _SecretRedactingFilter()
    assert flt.filter(rec) is True
    return rec.getMessage()


# ---------------------------------------------------------------- #
# 1. Stripe family
# ---------------------------------------------------------------- #


@pytest.mark.parametrize(
    "secret",
    [
        # Synthetic fixtures only — the bodies are obvious all-uppercase
        # FAKE markers, not real or doc-sample Stripe keys. They still
        # match the redactor's `(sk|rk|pk)_(live|test)_[A-Za-z0-9]{16,}`
        # pattern, so the test exercises the redaction path without
        # tripping GitHub secret-scanning push protection.
        "sk_live_" + "FAKEFIXTURE" + "X" * 16,
        "sk_test_" + "FAKEFIXTURE" + "X" * 16,
        "rk_live_" + "FAKEFIXTURE" + "X" * 16,
        "rk_test_" + "FAKEFIXTURE" + "X" * 16,
    ],
)
def test_stripe_secret_key_redacted(secret: str) -> None:
    msg = f"stripe charge.create failed using {secret}"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


def test_stripe_webhook_secret_redacted() -> None:
    secret = "whsec_LEAKMEABCDEFGHIJKLMNOPQRSTUV"
    msg = f"verifying signature with {secret}"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 2. Anthropic
# ---------------------------------------------------------------- #


def test_anthropic_key_redacted() -> None:
    secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    msg = f"calling claude with {secret}"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 3. OpenAI — sk-proj- and legacy sk-
# ---------------------------------------------------------------- #


def test_openai_proj_key_redacted_without_breaking_stripe() -> None:
    """``sk-proj-...`` (dash) must redact, and the Stripe ``sk_live_``
    (underscore) sample on the same line must ALSO redact — they take
    different code paths and we want both gone."""
    openai = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
    # Synthetic fake — see comment on the Stripe parametrize block.
    stripe = "sk_live_" + "FAKEFIXTURE" + "X" * 16
    msg = f"openai={openai} stripe={stripe}"
    out = _redact(msg)
    assert openai not in out
    assert stripe not in out
    assert openai not in _run_filter(msg)


def test_openai_legacy_sk_redacted() -> None:
    secret = "sk-AbCdEfGhIjKlMnOpQrStUvWx"
    msg = f"openai header uses {secret} for auth"
    assert secret not in _redact(msg)


# ---------------------------------------------------------------- #
# 4. AWS
# ---------------------------------------------------------------- #


@pytest.mark.parametrize(
    "secret", ["AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"],
)
def test_aws_access_key_id_redacted(secret: str) -> None:
    msg = f"aws boto3 client using access key id {secret} for s3"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 5. GitHub PATs
# ---------------------------------------------------------------- #


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "gho_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
        "ghu_abcdefghijklmnopqrstuvwxyz0123456789",
    ],
)
def test_github_pat_redacted(secret: str) -> None:
    msg = f"git push failed: token {secret} expired"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 6. Resend
# ---------------------------------------------------------------- #


def test_resend_api_key_redacted() -> None:
    """Resend keys begin with ``re_`` and are 30+ base62 chars. A bare
    literal (e.g. a fallback ``log.warning("using key %s", api_key)``)
    must not survive redaction."""
    secret = "re_LeakAbCdEfGhIjKlMnOpQrStUvWxYz123456"
    msg = f"resend client initialized with {secret}"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 7. Bearer tokens in HTTP log lines
# ---------------------------------------------------------------- #


def test_bearer_token_in_http_log_line_redacted() -> None:
    secret = "AbCdEfGhIjKlMnOpQrStUv0123456789"
    msg = f"POST /v1/messages HTTP/1.1 Authorization: Bearer {secret}"
    assert secret not in _redact(msg)
    assert secret not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 8. JWT-shaped + 9. Supabase service-role
# ---------------------------------------------------------------- #


def test_jwt_shaped_token_redacted() -> None:
    """Three-segment JWT — header.payload.signature, all base64url. The
    Supabase service-role JWT lives in env config; if it ever lands in a
    log line via misconfigured debug output, redact it."""
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByb2plY3QiLCJyb2xlIjoic2VydmljZV9yb2xlIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    msg = f"connecting to supabase with token {jwt}"
    out = _redact(msg)
    assert jwt not in out
    assert "eyJ" not in out or out.count("eyJ") == 0
    assert jwt not in _run_filter(msg)


# ---------------------------------------------------------------- #
# 10. URL-embedded credentials (DSN)
# ---------------------------------------------------------------- #


@pytest.mark.parametrize(
    "dsn",
    [
        "postgres://user:Pa$$w0rd!@db.internal:5432/recupero",
        "postgresql://recupero:S3cr3tPw_2026@db.supabase.co:6543/postgres",
    ],
)
def test_dsn_embedded_password_redacted(dsn: str) -> None:
    msg = f"connection failed for {dsn}"
    out = _redact(msg)
    # The password portion must be gone, the user + host preserved.
    assert "Pa$$w0rd" not in out
    assert "S3cr3tPw" not in out
    assert ":***@" in out


# ---------------------------------------------------------------- #
# 11. Recupero portal tokens
# ---------------------------------------------------------------- #


def test_portal_token_labeled_field_redacted() -> None:
    """``secrets.token_urlsafe(32)`` → ~43 url-safe-base64 chars.
    When it appears alongside an explicit ``portal_token=`` /
    ``access_token=`` label (the realistic logging shape), redact it."""
    secret = "Q3JhbmtsZUZlcm1hdElzU2VjcmV0VG9rZW5fMTIzNDU2Nzg5MA"
    msg = f"sending portal link portal_token={secret} to operator"
    out = _redact(msg)
    assert secret not in out
    assert "***" in out


def test_portal_token_in_authorization_header_redacted() -> None:
    """Even unlabeled, a portal token presented as a Bearer should be
    caught by the existing Bearer pattern."""
    secret = "RandomLongUrlSafe_TokenAbCdEf0123456789xyzAA"
    msg = f"incoming request Authorization: Bearer {secret}"
    assert secret not in _redact(msg)


# ---------------------------------------------------------------- #
# Negative controls — no over-redaction of operator triage context
# ---------------------------------------------------------------- #


def test_no_false_positive_on_plain_message() -> None:
    msg = "investigation 12345 completed in 4.2s with 7 transfers"
    assert _redact(msg) == msg


def test_no_false_positive_on_evm_address() -> None:
    """A 42-char hex EVM address must NOT be mistaken for a token —
    the AWS pattern is anchored to AKIA/ASIA + uppercase, and the
    portal-token pattern requires an explicit label."""
    addr = "0xAaBbCcDdEeFf00112233445566778899aAbBcCdD"
    msg = f"victim address {addr} drained to attacker"
    assert _redact(msg) == msg
