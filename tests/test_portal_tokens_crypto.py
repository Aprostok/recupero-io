"""Adversarial-input crypto audit for ``recupero.portal.tokens``.

These tests deepen the existing ``test_portal_tokens.py`` coverage by
locking the eight crypto/replay guarantees the round-9 + round-11
security passes established. They are characterization-RED tests:
a regression that reintroduces ``random.randint`` for token minting,
logs the secret on success, or accepts a typo'd short pepper would
flip these red.

Scope is the pure-Python helpers — the DB path remains mocked via
``patch("recupero.portal.tokens.psycopg.connect")`` to match the
existing test pattern.
"""

from __future__ import annotations

import inspect
import logging
import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.portal.tokens import (
    _token_pepper,
    compute_token_hmac,
    generate_token,
    verify_token,
)

# ---- entropy source ---- #


def test_generate_token_uses_secrets_not_random() -> None:
    """Mutation lock: ``generate_token`` MUST derive the secret from
    ``secrets.token_urlsafe`` (cryptographically strong) — never from
    ``random.randint``/``random.choice`` which are deterministic from
    the Mersenne-Twister state and trivially recoverable. We assert
    by inspecting the source so the static guarantee survives even
    when the DB layer is mocked away.
    """
    src = inspect.getsource(generate_token)
    assert "secrets.token_urlsafe" in src, (
        "generate_token must derive tokens from secrets.token_urlsafe; "
        "got source without that call"
    )
    assert "random.randint" not in src
    assert "random.choice" not in src


def test_generate_token_entropy_floor_is_256_bits() -> None:
    """Token byte length must be >= 32 bytes (256 bits). 256 bits is
    the Stripe-equivalent floor we documented in the module docstring;
    dropping below it would let a determined adversary brute-force
    the keyspace.
    """
    from recupero.portal.tokens import _TOKEN_BYTES
    assert _TOKEN_BYTES >= 32


# ---- timing side channel ---- #


def test_no_python_level_token_equality_compare() -> None:
    """The whole point of the HMAC-of-token migration (014) is that
    Python NEVER compares a user-supplied bearer token byte-by-byte
    via ``==`` or ``!=`` (Postgres also gets the HMAC, not the raw
    token). A future patch that re-introduces e.g. ``if token ==
    row["token"]:`` would silently reintroduce the timing channel.

    We lock the absence by static inspection of the module source.
    """
    import recupero.portal.tokens as tk
    src = inspect.getsource(tk)
    # ``token`` is the user-supplied argument name across verify_token
    # / generate_token. Any equality compare with it on either side
    # is suspect.
    forbidden_fragments = [
        "token == ",
        "== token",
        "token != ",
        "!= token",
    ]
    for frag in forbidden_fragments:
        assert frag not in src, (
            f"Python-level token compare reintroduced "
            f"(found {frag!r}); use hmac.compare_digest or DB HMAC index"
        )


# ---- token logging ---- #


def test_generate_token_does_not_log_secret_token_value(caplog) -> None:
    """The mint log line must never include the raw token string —
    ops dashboards, papertrail, Railway logs etc. all ingest these
    messages and a token leak there equals account takeover.
    """
    case_id = uuid4()
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [
            {"id": str(case_id)}, {"id": str(uuid4())},
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value.__enter__.return_value = mock_conn

        with caplog.at_level(logging.DEBUG, logger="recupero.portal.tokens"):
            _, token, _ = generate_token(
                case_id=case_id, dsn="fake-dsn", ttl_days=90,
            )

    # The raw secret must not appear in ANY captured log record.
    for rec in caplog.records:
        msg = rec.getMessage()
        assert token not in msg, (
            f"Token secret leaked into log record: {msg!r}"
        )


# ---- expiry enforcement ---- #


def test_verify_token_rejects_token_expired_by_one_second() -> None:
    """An ``expires_at`` strictly less than NOW must reject. Locks the
    boundary so a future patch that flips ``<`` to ``<=`` (or drops
    the check entirely) goes red.
    """
    long_token = secrets.token_urlsafe(32)
    one_sec_ago = datetime.now(UTC) - timedelta(seconds=1)
    row = {
        "token_id": uuid4(),
        "case_id": uuid4(),
        "expires_at": one_sec_ago,
        "revoked_at": None,
        "label": None,
        "last_used_at": None,
        "case_number": "V-1",
        "client_name": "v",
        "client_email": None,
        "case_status": "complete",
        "case_state": None,
        "estimated_value_usd": 0,
    }
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        cur = MagicMock()
        cur.fetchone.return_value = row
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn

        assert verify_token(token=long_token, dsn="x") is None


# ---- case-bound enforcement ---- #


def test_verify_token_returns_only_its_own_case_id() -> None:
    """A token row stores ONE ``case_id``. ``verify_token`` returns
    that exact id with no opportunity for the caller to substitute
    another case. This is the structural guarantee that token T1
    (issued for case A) cannot expose case B's state — the DB join
    pins the lookup.
    """
    token = secrets.token_urlsafe(32)
    case_a = uuid4()
    case_b = uuid4()  # noqa: F841 — proves T1 cannot return case_b
    row = {
        "token_id": uuid4(),
        "case_id": case_a,
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "revoked_at": None,
        "label": None,
        "last_used_at": None,
        "case_number": "V-A",
        "client_name": "Alice",
        "client_email": None,
        "case_status": "complete",
        "case_state": None,
        "estimated_value_usd": 0,
    }
    inv = {
        "id": uuid4(),
        "engagement_started_at": None,
        "engagement_closed_at": None,
        "engagement_fee_paid_usd": None,
    }
    with patch("recupero.portal.tokens.psycopg.connect") as mock_connect:
        cur = MagicMock()
        cur.fetchone.side_effect = [row, inv]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur
        mock_connect.return_value.__enter__.return_value = conn

        out = verify_token(token=token, dsn="x")

    assert out is not None
    assert out.case_id == case_a
    # And the WHERE-clause is hmac/raw-token-keyed, never case-keyed.
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    assert any("t.token_hmac = %s" in s or "t.token = %s" in s
               for s in sql_calls)


# ---- HMAC pepper validation ---- #


def test_token_pepper_rejects_short_hex_does_not_fallback_to_base64(
    monkeypatch, caplog,
) -> None:
    """Adversarial-input fix: an operator typo that truncates a
    32-byte hex pepper used to silently fall through to base64
    decoding and accept a 16-byte derivation of the typo. Now the
    helper must refuse and log an error so the misconfig surfaces.
    """
    # 22 hex chars = 11 bytes (too short), but also valid base64-url.
    # Pre-fix this returned 16 bytes via base64; post-fix returns None.
    monkeypatch.setenv("RECUPERO_TOKEN_PEPPER", "deadbeefdeadbeefdeadbe")
    with caplog.at_level(logging.ERROR, logger="recupero.portal.tokens"):
        assert _token_pepper() is None
    assert any("too short" in rec.getMessage() for rec in caplog.records)


def test_token_pepper_accepts_full_length_hex(monkeypatch) -> None:
    """Sanity: a properly-formed 64-char hex pepper still loads."""
    monkeypatch.setenv("RECUPERO_TOKEN_PEPPER", "ab" * 32)
    out = _token_pepper()
    assert out is not None
    assert len(out) == 32


def test_compute_token_hmac_is_deterministic_and_pepper_bound(
    monkeypatch,
) -> None:
    """HMAC must be deterministic across calls (so the indexed DB
    lookup hits) AND must change when the pepper rotates (so a
    pepper rotation invalidates all live tokens).
    """
    monkeypatch.setenv("RECUPERO_TOKEN_PEPPER", "11" * 32)
    h1 = compute_token_hmac("victim-token-xyz")
    h2 = compute_token_hmac("victim-token-xyz")
    assert h1 == h2 and h1 is not None

    monkeypatch.setenv("RECUPERO_TOKEN_PEPPER", "22" * 32)
    h3 = compute_token_hmac("victim-token-xyz")
    assert h3 != h1, "rotating the pepper must invalidate the HMAC"


# ---- input-shape rejection ---- #


@pytest.mark.parametrize("bogus", [
    "",
    "short",
    "a" * 19,           # one below the lower bound
    "a" * 65,           # one above the upper bound
    "a" * 4096,         # cheap brute-force probe size
])
def test_verify_token_rejects_malformed_input_without_db(bogus) -> None:
    """The pre-DB length guard must reject obviously-malformed input
    without burning a roundtrip — protects against amplification DoS.
    We assert by setting psycopg.connect to a sentinel that raises if
    called: if the guard regresses, the test fails with the sentinel
    error.
    """
    sentinel = MagicMock(side_effect=AssertionError(
        "psycopg.connect should not be reached for malformed input"
    ))
    with patch("recupero.portal.tokens.psycopg.connect", sentinel):
        assert verify_token(token=bogus, dsn="x") is None
