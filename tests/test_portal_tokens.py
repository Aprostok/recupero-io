"""Tests for the pure-Python helpers in recupero.portal.tokens.

We focus on:

  * generate_token's entropy/format guarantees (token length, URL-
    safety, uniqueness across calls).
  * public_portal_url's base-URL handling — getting this wrong
    means we email customers a broken link.

Database-touching paths (verify_token, revoke_token) are exercised
via mocked psycopg.connect, mirroring the test_engagement_api
pattern. The integration coverage lives in the live verification
against the canary.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from recupero.portal.tokens import (
    VerifiedToken,
    generate_token,
    public_portal_url,
    revoke_token,
    verify_token,
)


# ---- public_portal_url ---- #


def test_public_portal_url_uses_env_var(monkeypatch) -> None:
    """RECUPERO_PORTAL_BASE_URL → that's the host. Strips trailing
    slashes so 'https://portal.recupero.io/' and 'https://portal.recupero.io'
    produce the same URL."""
    monkeypatch.setenv("RECUPERO_PORTAL_BASE_URL", "https://portal.recupero.io/")
    url = public_portal_url(token="abc123")
    assert url == "https://portal.recupero.io/portal/abc123"


def test_public_portal_url_explicit_base_overrides_env(monkeypatch) -> None:
    """Explicit base_url kwarg wins. Used by tests + ops scripts that
    need to override the env-configured host."""
    monkeypatch.setenv("RECUPERO_PORTAL_BASE_URL", "https://prod.recupero.io")
    url = public_portal_url(token="abc", base_url="https://staging.recupero.io")
    assert url == "https://staging.recupero.io/portal/abc"


def test_public_portal_url_unset_env_falls_back_to_localhost(monkeypatch) -> None:
    """No env var, no explicit base → fall back to localhost. The CLI
    prints a WARN in this case so the operator notices."""
    monkeypatch.delenv("RECUPERO_PORTAL_BASE_URL", raising=False)
    url = public_portal_url(token="abc")
    assert url == "http://localhost:8080/portal/abc"


# ---- generate_token (mocked) ---- #


def test_generate_token_returns_url_safe_token() -> None:
    """token_urlsafe(32) yields ~43 base64url chars with no
    ambiguous characters. Required so the URL doesn't need
    URL-encoding when pasted into emails."""
    case_id = uuid4()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # cases-exists query → one row
        # insert returning id → a UUID
        new_token_id = uuid4()
        mock_cursor.fetchone.side_effect = [
            {"id": str(case_id)},
            {"id": str(new_token_id)},
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        token_id, token, expires_at = generate_token(
            case_id=case_id, dsn="fake-dsn", ttl_days=90,
        )

    assert token_id == new_token_id
    assert len(token) >= 40, "token should be ~43 chars from token_urlsafe(32)"
    # URL-safe alphabet: A-Z, a-z, 0-9, -, _
    assert all(c.isalnum() or c in "-_" for c in token)
    assert expires_at is not None
    # Expiry should be ~90 days out
    delta = expires_at - datetime.now(timezone.utc)
    assert timedelta(days=89) < delta <= timedelta(days=90)


def test_generate_token_ttl_none_means_never_expires() -> None:
    """ttl_days=None → expires_at is NULL in the DB. Reserved for
    enterprise / long-tail workflows; the CLI defaults to 90."""
    case_id = uuid4()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            {"id": str(case_id)}, {"id": str(uuid4())},
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        _, _, expires_at = generate_token(
            case_id=case_id, dsn="fake-dsn", ttl_days=None,
        )

    assert expires_at is None


def test_generate_token_rejects_unknown_case() -> None:
    """Pre-flight check: the cases-exists lookup returns None for a
    bogus case_id, so we raise ValueError instead of inserting an
    orphan token row."""
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None  # case doesn't exist
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        with pytest.raises(ValueError, match="not found"):
            generate_token(case_id=uuid4(), dsn="fake-dsn", ttl_days=90)


def test_generate_token_yields_unique_tokens_per_call() -> None:
    """Two consecutive generate_token calls should produce different
    token values. token_urlsafe is cryptographically random so
    collisions are astronomically unlikely, but we lock it here
    so a future "let's make this idempotent" patch doesn't
    silently break the security model."""
    case_id = uuid4()
    tokens_seen = []

    def _mock_factory():
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {"id": str(case_id)}, {"id": str(uuid4())},
        ]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        return conn

    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_connect.return_value.__enter__.side_effect = [
            _mock_factory() for _ in range(2)
        ]
        for _ in range(2):
            _, tok, _ = generate_token(case_id=case_id, dsn="x", ttl_days=90)
            tokens_seen.append(tok)

    assert tokens_seen[0] != tokens_seen[1]


# ---- verify_token (mocked) ---- #


def _mk_token_row(**overrides):
    """Helper: a sparse case_tokens-join-cases row template."""
    base = {
        "token_id": uuid4(),
        "case_id": uuid4(),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=30),
        "revoked_at": None,
        "label": None,
        "last_used_at": None,
        "case_number": "V-12345",
        "client_name": "Test Victim",
        "client_email": "victim@example.com",
        "case_status": "complete",
        "case_state": None,
        "estimated_value_usd": 50000,
    }
    base.update(overrides)
    return base


def _mk_inv_row(**overrides):
    base = {
        "id": uuid4(),
        "engagement_started_at": None,
        "engagement_closed_at": None,
        "engagement_fee_paid_usd": None,
    }
    base.update(overrides)
    return base


def test_verify_token_returns_none_for_short_input() -> None:
    """A request with token='abc' shouldn't even hit the DB — we
    reject ultra-short input as obviously bogus. The 20-char floor
    is conservative; real tokens are 43+ chars."""
    out = verify_token(token="abc", dsn="ignored")
    assert out is None


def test_verify_token_returns_none_for_unknown_token() -> None:
    """No matching row → return None. The handler renders the same
    'link unavailable' page as for revoked/expired tokens so the
    response doesn't leak whether the token ever existed."""
    long_bogus = secrets.token_urlsafe(32)
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        out = verify_token(token=long_bogus, dsn="fake-dsn")

    assert out is None


def test_verify_token_rejects_revoked_token() -> None:
    """revoked_at IS NOT NULL → return None even if expires_at
    hasn't been reached. Operator's kill switch."""
    long_token = secrets.token_urlsafe(32)
    row = _mk_token_row(revoked_at=datetime.now(timezone.utc))
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = row
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        out = verify_token(token=long_token, dsn="fake-dsn")

    assert out is None


def test_verify_token_rejects_expired_token() -> None:
    """expires_at < now → return None. Even if the operator never
    revoked it, the customer should re-request a fresh link."""
    long_token = secrets.token_urlsafe(32)
    row = _mk_token_row(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = row
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        out = verify_token(token=long_token, dsn="fake-dsn")

    assert out is None


def test_verify_token_returns_full_shape_on_match() -> None:
    """Happy path: valid token → returns a VerifiedToken with the
    case + latest-investigation fields the portal needs to render
    its landing page."""
    long_token = secrets.token_urlsafe(32)
    row = _mk_token_row(case_number="V-99999", client_name="Alex Victim")
    inv = _mk_inv_row()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # First fetchone() = token-join-case row.
        # The last_used_at bump may execute an UPDATE (no fetchone).
        # Second fetchone() = latest-investigation row.
        mock_cursor.fetchone.side_effect = [row, inv]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        out = verify_token(token=long_token, dsn="fake-dsn")

    assert isinstance(out, VerifiedToken)
    assert out.case_number == "V-99999"
    assert out.client_name == "Alex Victim"
    # No prior engagement → quoted_fee defaults to $1,500 (Tier-2 standard)
    assert out.quoted_fee_usd == 1500


def test_verify_token_handles_case_with_no_investigations() -> None:
    """Intake-only case (no investigation row yet) shouldn't crash —
    investigation_id comes back None and the portal handles it."""
    long_token = secrets.token_urlsafe(32)
    row = _mk_token_row()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        # token row, then no investigation
        mock_cursor.fetchone.side_effect = [row, None]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        out = verify_token(token=long_token, dsn="fake-dsn")

    assert out is not None
    assert out.investigation_id is None
    assert out.engagement_started_at is None


def test_verify_token_bumps_last_used_only_after_interval() -> None:
    """last_used_at bump skips if the previous bump was < 1 hour
    ago. This is just a write-amplification optimization but
    matters under traffic — every portal page load would
    otherwise rewrite the row."""
    long_token = secrets.token_urlsafe(32)
    fresh_bump = datetime.now(timezone.utc) - timedelta(minutes=5)
    row = _mk_token_row(last_used_at=fresh_bump)
    inv = _mk_inv_row()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [row, inv]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        verify_token(token=long_token, dsn="fake-dsn")

    # Check that no UPDATE last_used_at was issued. Iterate over
    # execute calls and assert none of them is the bump SQL.
    bumps = [
        c for c in mock_cursor.execute.call_args_list
        if "UPDATE public.case_tokens SET last_used_at" in c.args[0]
    ]
    assert bumps == [], "last_used_at should NOT have been bumped within the interval"


# ---- revoke_token (mocked) ---- #


def test_revoke_token_returns_true_on_success() -> None:
    """UPDATE returning the row → True. Idempotent — re-revoking
    a revoked token still returns True because the COALESCE
    leaves the original timestamp in place."""
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"id": str(uuid4())}
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        result = revoke_token(token_id=uuid4(), dsn="fake-dsn")

    assert result is True


def test_revoke_token_returns_false_on_unknown_id() -> None:
    """UPDATE returning no row → False. Caller can decide whether
    that's an error (typo) or expected (already-cleaned-up state)."""
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        result = revoke_token(token_id=uuid4(), dsn="fake-dsn")

    assert result is False
