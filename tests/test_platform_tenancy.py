"""Unit tests for the SaaS tenancy primitives (pure stdlib crypto + quota).

No database or network — these lock the security-critical pieces of the
multi-tenant layer: password hashing, API-key hashing, HS256 session tokens
(incl. tamper / expiry / alg-confusion rejection), and plan/quota policy.
"""

from __future__ import annotations

import pytest

from recupero.platform import tenancy

# ---- passwords ---- #

def test_password_roundtrip_and_wrong_password() -> None:
    h = tenancy.hash_password("correct horse battery staple")
    assert h.startswith("scrypt$")
    assert tenancy.verify_password("correct horse battery staple", h) is True
    assert tenancy.verify_password("wrong", h) is False


def test_password_hash_is_salted() -> None:
    assert tenancy.hash_password("same") != tenancy.hash_password("same")


def test_verify_password_malformed_is_false_not_raise() -> None:
    assert tenancy.verify_password("x", "not-a-valid-hash") is False
    assert tenancy.verify_password("x", "") is False


def test_empty_password_rejected() -> None:
    with pytest.raises(ValueError):
        tenancy.hash_password("")


# ---- API keys ---- #

def test_api_key_generation_and_verify() -> None:
    key = tenancy.generate_api_key()
    assert key.plaintext.startswith(tenancy.API_KEY_PREFIX)
    assert key.plaintext.endswith(key.last4)
    assert tenancy.hash_api_key(key.plaintext) == key.key_hash
    assert tenancy.verify_api_key(key.plaintext, key.key_hash) is True
    assert tenancy.verify_api_key("rk_live_tampered", key.key_hash) is False
    # plaintext itself is never derivable from what we store
    assert key.plaintext not in (key.key_hash, key.last4)


def test_api_keys_are_unique() -> None:
    assert tenancy.generate_api_key().plaintext != tenancy.generate_api_key().plaintext


# ---- session JWTs ---- #

_SECRET = "unit-test-secret-not-for-prod"


def test_jwt_roundtrip_claims() -> None:
    tok = tenancy.mint_jwt(secret=_SECRET, subject="u1", org_id="o1", role="owner",
                           ttl_seconds=3600, now=1_000_000, extra={"plan": "pro"})
    claims = tenancy.verify_jwt(tok, secret=_SECRET, now=1_000_100)
    assert claims["sub"] == "u1" and claims["org"] == "o1"
    assert claims["role"] == "owner" and claims["plan"] == "pro"


def test_jwt_expired_rejected() -> None:
    tok = tenancy.mint_jwt(secret=_SECRET, subject="u1", org_id="o1", role="member",
                           ttl_seconds=10, now=1_000_000)
    with pytest.raises(tenancy.TokenError):
        tenancy.verify_jwt(tok, secret=_SECRET, now=1_000_011)


def test_jwt_wrong_secret_rejected() -> None:
    tok = tenancy.mint_jwt(secret=_SECRET, subject="u1", org_id="o1", role="member", now=1_000_000)
    with pytest.raises(tenancy.TokenError):
        tenancy.verify_jwt(tok, secret="attacker-secret", now=1_000_010)


def test_jwt_tampered_payload_rejected() -> None:
    tok = tenancy.mint_jwt(secret=_SECRET, subject="u1", org_id="o1", role="member", now=1_000_000)
    header, payload, sig = tok.split(".")
    # swap in a different (validly-encoded) payload without re-signing
    forged_payload = tenancy._b64u_encode(b'{"sub":"u1","org":"o2","role":"owner","exp":9999999999}')
    with pytest.raises(tenancy.TokenError):
        tenancy.verify_jwt(f"{header}.{forged_payload}.{sig}", secret=_SECRET, now=1_000_010)


def test_jwt_alg_confusion_none_rejected() -> None:
    # An attacker-forged 'none'/other-alg header must be refused even if the rest parses.
    forged_header = tenancy._b64u_encode(b'{"alg":"none","typ":"JWT"}')
    payload = tenancy._b64u_encode(b'{"sub":"u1","org":"o1","role":"owner","exp":9999999999}')
    with pytest.raises(tenancy.TokenError):
        tenancy.verify_jwt(f"{forged_header}.{payload}.", secret=_SECRET, now=1_000_010)


# ---- plans + quota ---- #

def test_plan_lookup_defaults() -> None:
    assert tenancy.get_plan("pro").name == "pro"
    assert tenancy.get_plan(None).name == tenancy.DEFAULT_PLAN
    assert tenancy.get_plan("nonexistent").name == tenancy.DEFAULT_PLAN


def test_free_trace_quota_exhaustion() -> None:
    q0 = tenancy.check_trace_quota(plan_name="free", used_this_period=0)
    assert q0.allowed and q0.remaining == 5
    q_last = tenancy.check_trace_quota(plan_name="free", used_this_period=4)
    assert q_last.allowed and q_last.remaining == 1
    q_over = tenancy.check_trace_quota(plan_name="free", used_this_period=5)
    assert not q_over.allowed and q_over.remaining == 0


def test_enterprise_unlimited() -> None:
    q = tenancy.check_trace_quota(plan_name="enterprise", used_this_period=10_000)
    assert q.allowed and q.remaining == -1


def test_seat_quota() -> None:
    assert tenancy.check_seat_quota(plan_name="free", current_seats=2).allowed is False
    assert tenancy.check_seat_quota(plan_name="pro", current_seats=2).allowed is True
    assert tenancy.check_seat_quota(plan_name="enterprise", current_seats=9999).allowed is True
