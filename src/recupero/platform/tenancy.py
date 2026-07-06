"""Multi-tenant identity + billing primitives (the SaaS layer).

The recupero *engine* (tracer, freeze artifacts, chain adapters) and the
Postgres ``investigations`` job queue already exist and scale. This module adds
the missing product-layer primitives for a self-serve, multi-tenant SaaS:
password / API-key / session-token crypto, plan → quota policy, and usage
accounting — all pure functions over stdlib only, so they carry NO new runtime
dependency and are fully unit-testable without a database.

Security posture (minimal-but-correct; hardening notes inline):
  * Passwords: ``hashlib.scrypt`` with a per-user random salt (memory-hard).
    PROD: migrate to argon2id (add ``argon2-cffi``) — the stored format is
    versioned (``scrypt$…``) so a rehash-on-login upgrade is drop-in.
  * API keys: shown once (``rk_live_<token>``); only a SHA-256 hash + last-4 are
    stored, compared in constant time. A leaked DB never yields usable keys.
  * Session tokens: compact HS256 JWTs (stdlib hmac/base64url) with iat/exp and
    org/role claims. PROD: rotate the signing secret + move to asymmetric (ES256)
    so verifiers don't hold the signing key. The verify path already rejects
    alg-confusion (only HS256 accepted) and expired tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

# --------------------------------------------------------------------------- #
# base64url (no padding) — the JWT wire encoding
# --------------------------------------------------------------------------- #


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --------------------------------------------------------------------------- #
# Passwords — scrypt with a versioned, self-describing stored format
# --------------------------------------------------------------------------- #

_SCRYPT_N = 2**14  # CPU/memory cost (16384) — ~tens of ms, tune per box
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


@lru_cache(maxsize=1)
def _argon2_hasher() -> Any | None:
    """Return an argon2id ``PasswordHasher`` if ``argon2-cffi`` is installed, else
    None. Optional dependency — memoized (returns an object, so the
    lru_cache-side-effect audit doesn't flag it)."""
    try:
        from argon2 import PasswordHasher  # optional: pip install argon2-cffi
    except Exception:
        return None
    return PasswordHasher()


def _argon2_enabled() -> bool:
    """argon2id is used for NEW hashes only when explicitly opted in AND the
    library is present — so the default install stays dependency-free (scrypt)."""
    flag = (os.environ.get("RECUPERO_PASSWORD_ARGON2") or "").strip().lower()
    return flag in ("1", "true", "yes", "on") and _argon2_hasher() is not None


def hash_password(password: str) -> str:
    """Hash a password. Default: scrypt (self-describing ``scrypt$N$r$p$salt$dk``,
    no dependency). When ``RECUPERO_PASSWORD_ARGON2`` is enabled and argon2-cffi
    is installed, uses argon2id (``$argon2id$…``). ``verify_password`` reads both
    formats, so this is a safe drop-in with rehash-on-login (``needs_rehash``)."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if _argon2_enabled():
        return str(_argon2_hasher().hash(password))
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64u_encode(salt)}${_b64u_encode(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against a ``hash_password`` string (scrypt OR argon2).
    Never raises on a malformed stored value — returns False (an attacker can't
    probe via errors)."""
    if isinstance(stored, str) and stored.startswith("$argon2"):
        hasher = _argon2_hasher()
        if hasher is None:
            return False  # argon2 hash but library unavailable → fail closed
        try:
            return bool(hasher.verify(stored, password))
        except Exception:
            return False
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=_b64u_decode(salt_b64),
            n=int(n_s), r=int(r_s), p=int(p_s), dklen=len(_b64u_decode(dk_b64)),
        )
        return hmac.compare_digest(dk, _b64u_decode(dk_b64))
    except (ValueError, TypeError, AttributeError):
        return False


def needs_rehash(stored: str) -> bool:
    """True if ``stored`` should be re-hashed on the next successful login — i.e.
    argon2id is the configured target but the stored hash is still scrypt (or an
    argon2 hash whose parameters are now stale). Enables a zero-downtime upgrade."""
    if not isinstance(stored, str):
        return False
    if stored.startswith("$argon2"):
        hasher = _argon2_hasher()
        try:
            return bool(hasher and hasher.check_needs_rehash(stored))
        except Exception:
            return False
    # scrypt stored → rehash iff argon2id is now enabled.
    return _argon2_enabled()


# --------------------------------------------------------------------------- #
# API keys — plaintext shown once, only a hash + last4 persisted
# --------------------------------------------------------------------------- #

API_KEY_PREFIX = "rk_live_"


@dataclass(frozen=True)
class NewApiKey:
    plaintext: str   # returned to the caller ONCE, never stored
    key_hash: str    # sha256 hex — stored
    last4: str       # UI hint — stored


def generate_api_key() -> NewApiKey:
    token = secrets.token_urlsafe(32)
    plaintext = f"{API_KEY_PREFIX}{token}"
    return NewApiKey(
        plaintext=plaintext,
        key_hash=hash_api_key(plaintext),
        last4=token[-4:],
    )


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def verify_api_key(plaintext: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(plaintext), stored_hash or "")


# --------------------------------------------------------------------------- #
# Invite tokens — single-use org-invite links; only a hash is stored
# --------------------------------------------------------------------------- #

INVITE_TOKEN_TTL_SEC = 7 * 24 * 3600  # 7 days


def generate_invite_token() -> tuple[str, str]:
    """Return ``(plaintext, sha256_hash)``. The plaintext goes in the invite
    link (emailed once); only the hash is stored — same hash-only posture as API
    keys, so a leaked DB yields no usable invite links."""
    token = secrets.token_urlsafe(32)
    return token, hash_invite_token(token)


def hash_invite_token(plaintext: str) -> str:
    return hashlib.sha256((plaintext or "").encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Session tokens — minimal HS256 JWT (stdlib only)
# --------------------------------------------------------------------------- #


class TokenError(Exception):
    """Raised by ``verify_jwt`` on an invalid / expired / tampered token."""


def mint_jwt(
    *, secret: str, subject: str, org_id: str, role: str,
    ttl_seconds: int = 3600, now: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    if not secret:
        raise ValueError("empty signing secret")
    issued = int(now if now is not None else time.time())
    payload: dict[str, Any] = {
        "sub": subject, "org": org_id, "role": role,
        "iat": issued, "exp": issued + int(ttl_seconds),
    }
    if extra:
        payload.update(extra)
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64u_encode(sig)}"


def verify_jwt(token: str, *, secret: str, now: int | None = None) -> dict[str, Any]:
    """Return the validated claims or raise ``TokenError``. Rejects alg-confusion
    (only HS256), bad signatures, and expired tokens."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except (ValueError, AttributeError) as exc:
        raise TokenError("malformed token") from exc
    signing_input = f"{header_b64}.{payload_b64}"
    expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    try:
        given = _b64u_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise TokenError("bad signature encoding") from exc
    if not hmac.compare_digest(expected, given):
        raise TokenError("signature mismatch")
    try:
        header = json.loads(_b64u_decode(header_b64))
        claims = json.loads(_b64u_decode(payload_b64))
    except Exception as exc:  # noqa: BLE001
        raise TokenError("bad token body") from exc
    if header.get("alg") != "HS256":
        raise TokenError("unexpected alg")  # block alg-confusion / 'none'
    ts = int(now if now is not None else time.time())
    if int(claims.get("exp", 0)) < ts:
        raise TokenError("token expired")
    return claims


# --------------------------------------------------------------------------- #
# Plans + quota policy — pure, so billing rules are unit-testable
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Plan:
    name: str
    monthly_trace_quota: int    # -1 = unlimited
    rate_limit_per_min: int
    max_seats: int
    retention_days: int


PLANS: dict[str, Plan] = {
    "free":       Plan("free", monthly_trace_quota=5, rate_limit_per_min=30, max_seats=2, retention_days=30),
    "pro":        Plan("pro", monthly_trace_quota=500, rate_limit_per_min=120, max_seats=10, retention_days=365),
    "enterprise": Plan("enterprise", monthly_trace_quota=-1, rate_limit_per_min=600, max_seats=-1, retention_days=3650),
}
DEFAULT_PLAN = "free"


def get_plan(name: str | None) -> Plan:
    return PLANS.get((name or DEFAULT_PLAN).lower(), PLANS[DEFAULT_PLAN])


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    reason: str
    remaining: int  # -1 = unlimited


def check_trace_quota(*, plan_name: str | None, used_this_period: int) -> QuotaDecision:
    """Pure quota gate for a trace submission. ``used_this_period`` is the count
    of traces the org has run in the current billing window."""
    plan = get_plan(plan_name)
    if plan.monthly_trace_quota < 0:
        return QuotaDecision(True, "unlimited", -1)
    remaining = plan.monthly_trace_quota - max(0, int(used_this_period))
    if remaining <= 0:
        return QuotaDecision(
            False,
            f"monthly trace quota ({plan.monthly_trace_quota}) exhausted for plan '{plan.name}'",
            0,
        )
    return QuotaDecision(True, "ok", remaining)


def check_seat_quota(*, plan_name: str | None, current_seats: int) -> QuotaDecision:
    plan = get_plan(plan_name)
    if plan.max_seats < 0:
        return QuotaDecision(True, "unlimited", -1)
    remaining = plan.max_seats - max(0, int(current_seats))
    if remaining <= 0:
        return QuotaDecision(False, f"seat limit ({plan.max_seats}) reached", 0)
    return QuotaDecision(True, "ok", remaining)


__all__ = (
    "API_KEY_PREFIX", "NewApiKey", "Plan", "PLANS", "DEFAULT_PLAN", "QuotaDecision",
    "TokenError",
    "hash_password", "verify_password", "needs_rehash",
    "generate_api_key", "hash_api_key", "verify_api_key",
    "INVITE_TOKEN_TTL_SEC", "generate_invite_token", "hash_invite_token",
    "mint_jwt", "verify_jwt",
    "get_plan", "check_trace_quota", "check_seat_quota",
)
