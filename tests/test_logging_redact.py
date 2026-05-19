"""Tests for the structured-log secret redaction (logging_setup._redact).

v0.16.7 (round-9 security HIGH) introduced redaction of Postgres DSN
passwords + Bearer tokens. v0.17.10 (round-10 security MED) extended
to Recupero-specific header shapes + literal Anthropic / OpenAI key
prefixes. These tests pin the redaction patterns so a regression
that re-introduces a secret into log output is caught immediately.
"""

from __future__ import annotations

from recupero.logging_setup import _redact


def test_postgres_dsn_password_redacted() -> None:
    """A psycopg failure that logs the DSN with the password inline
    must NOT leak the password to the log line."""
    msg = (
        "connection failed: could not translate host name "
        "'db.supabase.co' from postgresql://recupero:s3cr3t!_abc@db.supabase.co:6543/postgres"
    )
    out = _redact(msg)
    assert "s3cr3t!_abc" not in out
    assert "postgresql://recupero:***@" in out


def test_bearer_token_redacted() -> None:
    """Authorization: Bearer ... is the standard auth header shape and
    must never appear verbatim in log output."""
    msg = "outgoing httpx request: Authorization: Bearer abc123def456ghi789"
    out = _redact(msg)
    assert "abc123def456ghi789" not in out


def test_query_param_api_key_redacted() -> None:
    """?api_key=... in URL strings (httpx logs full URLs at DEBUG)
    must be redacted."""
    msg = "GET https://api.coingecko.com/v3/simple/price?api_key=secretvalue123&ids=ethereum"
    out = _redact(msg)
    assert "secretvalue123" not in out
    assert "ids=ethereum" in out  # non-secret query params preserved


def test_recupero_api_key_header_redacted() -> None:
    """v0.17.10: X-Recupero-API-Key header in a logged request dict
    must be redacted before it lands in the log."""
    msg = "request headers: {'X-Recupero-API-Key': 'rcp_live_abc123def456', 'host': 'api.recupero.io'}"
    out = _redact(msg)
    assert "rcp_live_abc123def456" not in out
    assert "host" in out  # other headers preserved


def test_helius_api_key_header_redacted() -> None:
    """v0.17.10: Helius-API-Key header redaction."""
    msg = "POST helius headers: helius-api-key: some_long_helius_key_abc123"
    out = _redact(msg)
    assert "some_long_helius_key_abc123" not in out


def test_anthropic_literal_key_redacted() -> None:
    """v0.17.10: bare 'sk-ant-...' literal in a log line (e.g. a
    typo of ANTHROPIC_API_KEY pasted into a print statement) must
    be redacted."""
    msg = "config loaded with anthropic key sk-ant-api03-abcdef1234567890XYZ"
    out = _redact(msg)
    assert "sk-ant-api03-abcdef1234567890XYZ" not in out
    assert "***" in out


def test_non_secret_text_passes_through() -> None:
    """Plain log messages should not be mangled by the redactor."""
    msg = "investigation 12345 completed in 4.2s with 7 transfers"
    out = _redact(msg)
    assert out == msg
