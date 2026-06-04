"""API-key auth + per-key rate limiting (v0.15.1).

In-process token-bucket rate limiter. Suitable for single-instance
deployments; for multi-instance Recupero would need a Redis-backed
limiter. Not enabled in this v0.15.1.

API keys live in the RECUPERO_API_KEYS env var as a comma-separated
list of ``name:secret`` pairs. Lookup is O(n) — fine for the
< ~100-key range we'd actually deploy with.

Local development bypass: RECUPERO_API_AUTH_OPTIONAL=1 makes the
dependency pass through without a key. NEVER set in production.
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

log = logging.getLogger(__name__)


# Rate-limit defaults. Per API key, per process. Overridable per
# key via RECUPERO_API_RATE_LIMITS env var (key_name:rps,key2:rps2
# format).
_DEFAULT_RPS = 5.0
_DEFAULT_BURST = 20


@dataclass
class _Bucket:
    """Token bucket state for one API key."""
    tokens: float
    last_refill: float
    rps: float
    burst: int


# Global bucket map. Lock-guarded for thread safety since FastAPI
# may run multiple workers / async tasks concurrently.
_buckets: dict[str, _Bucket] = {}
_buckets_lock = threading.Lock()


# v0.18.2 (round-11 api-CRIT-002): cache the parsed key map at
# module-load so each request doesn't re-parse RECUPERO_API_KEYS
# from env. Cache invalidates when the env var changes (sha256
# fingerprint of the raw string), so operators can rotate keys via
# Railway redeploys without a process restart. Locked for thread
# safety since FastAPI may serve concurrent requests on multiple
# threads / async workers.
_keys_cache: dict[str, str] = {}
_keys_cache_fingerprint: str | None = None
_keys_cache_lock = threading.Lock()


def _load_api_keys() -> dict[str, str]:
    """Parse RECUPERO_API_KEYS env var into {secret: name} map.

    Format: 'name1:secret1,name2:secret2'. Whitespace stripped.
    Empty pairs silently skipped.

    v0.18.2 (round-11 api-CRIT-002): caches the parsed map keyed on
    a hash of the raw env value. Subsequent calls return the cache
    until the env var changes — Railway redeploys with a new
    RECUPERO_API_KEYS will produce a new fingerprint and reparse.
    """
    import hashlib
    raw = os.environ.get("RECUPERO_API_KEYS", "").strip()
    if not raw:
        return {}
    fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    with _keys_cache_lock:
        global _keys_cache_fingerprint
        if fingerprint == _keys_cache_fingerprint and _keys_cache:
            return dict(_keys_cache)
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, secret = pair.partition(":")
        name = name.strip()
        secret = secret.strip()
        if name and secret:
            out[secret] = name  # keyed by secret for O(1) lookup
    with _keys_cache_lock:
        _keys_cache.clear()
        _keys_cache.update(out)
        _keys_cache_fingerprint = fingerprint
    return out


def _find_api_key_constant_time(provided: str) -> str | None:
    """Match `provided` against configured secrets in constant time.

    v0.18.2 (round-11 sec-HIGH-004): pre-v0.18.2 the lookup was
    `dict.get(provided)` which uses Python's string-equality
    short-circuit — observable timing differences on short prefix
    mismatches enable a remote-timing side-channel attacker to
    learn the first 1-2 bytes of any valid API key over millions
    of probes. Now: iterate every configured secret with
    `hmac.compare_digest` and return the name only on full match.
    For <100 keys this is microseconds and reveals nothing.
    """
    keys = _load_api_keys()
    if not keys:
        return None
    # Probe every key; do NOT short-circuit on first match.
    matched: str | None = None
    for secret, name in keys.items():
        if hmac.compare_digest(secret, provided):
            matched = name
            # No break — keep iterating to maintain constant work.
    return matched


def _load_rate_limits() -> dict[str, float]:
    """Parse RECUPERO_API_RATE_LIMITS into {key_name: rps}. Unset → default."""
    raw = os.environ.get("RECUPERO_API_RATE_LIMITS", "").strip()
    if not raw:
        return {}
    out: dict[str, float] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, rps_str = pair.partition(":")
        try:
            out[name.strip()] = float(rps_str.strip())
        except ValueError:
            continue
    return out


# ─────────────────────────────────────────────────────────────────────────────
# v0.28.0 — Multi-tenant authorization for /v1/freeze-outcomes (S-1)
#
# The pre-v0.28 surface required only a valid API key to write into
# freeze_outcomes for ANY case/issuer. This was the most dangerous
# multi-tenant gap in the platform: a single leaked partner key
# corrupted cooperation priors + law-firm dashboards + leaked the
# existence of internal letters via a 201-vs-404 enumeration oracle.
#
# Two env vars now gate /v1/freeze-outcomes:
#
#   RECUPERO_API_KEY_ISSUERS
#     key_name:Issuer1|Issuer2,key2:Issuer3
#     Whitelist of issuer names each partner key is allowed to write
#     outcomes for. Per-key issuers are case-insensitive (matched
#     after .strip().lower()).
#
#   RECUPERO_API_KEY_ADMINS
#     key_name,key2
#     Comma-separated list of operator/admin key names that get
#     universal write access (no per-issuer restriction). Use this
#     for the ops team's own keys; never grant to a partner.
#
# Default behavior: a key that appears in NEITHER list is denied.
# This is deny-by-default — explicit allow-list required.
# ─────────────────────────────────────────────────────────────────────────────


def _load_api_key_issuers() -> dict[str, frozenset[str]]:
    """Parse RECUPERO_API_KEY_ISSUERS env var into
    ``{key_name: frozenset(issuer_lower)}`` map. Empty / unset → {}."""
    raw = os.environ.get("RECUPERO_API_KEY_ISSUERS", "").strip()
    if not raw:
        return {}
    out: dict[str, frozenset[str]] = {}
    # Format: "key_name:Issuer1|Issuer2,key2:Issuer3"
    # Comma separates pairs; colon splits name from pipe-list of
    # issuers; case-insensitive comparison.
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, issuers_str = pair.partition(":")
        name = name.strip()
        issuers = frozenset(
            i.strip().lower() for i in issuers_str.split("|")
            if i.strip()
        )
        if name and issuers:
            out[name] = issuers
    return out


def _load_api_key_admins() -> frozenset[str]:
    """Parse RECUPERO_API_KEY_ADMINS into a frozenset of key names
    that get universal write access. Empty / unset → empty set
    (deny-by-default)."""
    raw = os.environ.get("RECUPERO_API_KEY_ADMINS", "").strip()
    if not raw:
        return frozenset()
    return frozenset(
        n.strip() for n in raw.split(",") if n.strip()
    )


# ── RBAC roles (v0.38, enterprise non-data #2) ───────────────────────────────
# Three ordered roles. viewer < analyst < admin. Defaulting to ANALYST keeps
# every pre-RBAC key working exactly as before (additive, no access regression);
# operators downgrade to viewer or upgrade to admin explicitly. Admin keys
# (RECUPERO_API_KEY_ADMINS) are always role 'admin' regardless of the roles map.
_ROLE_ORDER: dict[str, int] = {"viewer": 0, "analyst": 1, "admin": 2}
_DEFAULT_ROLE = "analyst"


def _load_api_key_roles() -> dict[str, str]:
    """Parse RECUPERO_API_KEY_ROLES ("name:role,name2:role2") → {name: role}.
    Unknown role tokens are ignored (fall back to the default). Empty → {}."""
    raw = os.environ.get("RECUPERO_API_KEY_ROLES", "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, role = pair.partition(":")
        name = name.strip()
        role = role.strip().lower()
        if name and role in _ROLE_ORDER:
            out[name] = role
    return out


def role_for_key(api_key_name: str) -> str:
    """Resolve an API key NAME to its role. Admins win; then the explicit
    roles map; else the default (analyst). Optional-auth callers ('anonymous')
    resolve to 'admin' — the bypass is already prod-gated."""
    if _is_optional_auth():
        return "admin"
    if api_key_name in _load_api_key_admins():
        return "admin"
    return _load_api_key_roles().get(api_key_name, _DEFAULT_ROLE)


def require_role(min_role: str):
    """FastAPI dependency factory: authenticate (via require_api_key) THEN
    require the key's role be >= ``min_role``. Returns the key name. Raises 401
    (no/invalid key), 429 (rate limit), or 403 (role too low)."""
    min_rank = _ROLE_ORDER.get(min_role, 99)

    async def _dep(request: Request) -> str:
        key_name = await require_api_key(request)
        role = role_for_key(key_name)
        request.state.api_key_role = role
        if _ROLE_ORDER.get(role, -1) < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {role!r} is insufficient; requires {min_role!r} or higher",
            )
        return key_name

    return _dep


def is_authorized_to_record_outcome(
    *, api_key_name: str, issuer: str,
) -> bool:
    """v0.28.0 (S-1): return True when ``api_key_name`` is allowed to
    write a freeze_outcome for ``issuer``.

    Authorization sources:
      1. The key appears in RECUPERO_API_KEY_ADMINS → universal write.
      2. The key appears in RECUPERO_API_KEY_ISSUERS with the issuer
         in its allow-list → permitted.
      3. Optional-auth mode (``_is_optional_auth() == True``) → permit
         everything (the auth bypass is already gated against
         production by `_is_production_environment`).
      4. Otherwise → denied.
    """
    if _is_optional_auth():
        return True
    admins = _load_api_key_admins()
    if api_key_name in admins:
        return True
    issuers_map = _load_api_key_issuers()
    issuers_lc = issuers_map.get(api_key_name, frozenset())
    return issuer.strip().lower() in issuers_lc


def _is_production_environment() -> bool:
    """Best-effort detection of a production deploy.

    v0.17.6 (round-10 security CRIT): _is_optional_auth() previously
    relied on the operator never setting RECUPERO_API_AUTH_OPTIONAL=1
    in prod. Accidentally setting it (env-var copy-paste, stale
    .env file in a CI deploy) silently disabled API auth — every
    endpoint went public with no warning. This helper inspects
    common deploy markers so the bypass can REFUSE to engage when
    we're clearly running in prod.

    Detected markers (any one is enough):
      * RAILWAY_ENVIRONMENT=production (Railway PRD service)
      * ENVIRONMENT=production / ENV=production / NODE_ENV=production
      * RECUPERO_ENV=production
      * SENTRY_ENVIRONMENT=production
    """
    prod_markers = {
        "RAILWAY_ENVIRONMENT",
        "ENVIRONMENT",
        "ENV",
        "NODE_ENV",
        "RECUPERO_ENV",
        "SENTRY_ENVIRONMENT",
    }
    for var in prod_markers:
        val = (os.environ.get(var) or "").strip().lower()
        if val in ("production", "prod"):
            return True
    return False


#: Environment-marker values that POSITIVELY declare a local / dev / test
#: deploy. "staging" is deliberately EXCLUDED — staging is a real-ish
#: environment and must get the safe (production-like) behavior.
_DEV_ENV_VALUES = frozenset({"development", "dev", "local", "test", "testing"})


def _is_local_dev_environment() -> bool:
    """True only when an env marker POSITIVELY declares a local/dev/test
    deploy.

    Used for FAIL-CLOSED security defaults: a feature that relaxes a
    control "in dev" (e.g. trusting a client-settable header for rate-limit
    bucketing) must gate on THIS returning True, so an unmarked / ambiguous
    / production deploy gets the SAFE behavior by default.

    This is intentionally STRICTER than ``not _is_production_environment()``
    — the latter is True for an UNMARKED environment, which is exactly the
    ambiguous case we must NOT treat as dev (an operator who forgot to set
    a production marker must still get production-safe behavior). Same
    marker set as the prod detector, matched against dev values.
    """
    markers = (
        "RAILWAY_ENVIRONMENT",
        "ENVIRONMENT",
        "ENV",
        "NODE_ENV",
        "RECUPERO_ENV",
        "SENTRY_ENVIRONMENT",
    )
    for var in markers:
        val = (os.environ.get(var) or "").strip().lower()
        if val in _DEV_ENV_VALUES:
            return True
    return False


def _is_optional_auth() -> bool:
    """Local-dev bypass. Production-environment markers REFUSE the
    bypass and log a loud WARNING so accidental setting in prod
    can't go undetected.

    v0.17.6 (round-10 security CRIT): pre-v0.17.6 this was a pure
    env-var read. Now: if we detect production AND someone set the
    bypass anyway, we log+ignore. Optional-auth requires both
    RECUPERO_API_AUTH_OPTIONAL=1 AND no production marker.
    """
    requested = os.environ.get("RECUPERO_API_AUTH_OPTIONAL", "").strip() == "1"
    if not requested:
        return False
    if _is_production_environment():
        log.warning(
            "RECUPERO_API_AUTH_OPTIONAL=1 is set but a production "
            "environment marker (RAILWAY_ENVIRONMENT / ENVIRONMENT / "
            "etc.) was detected — REFUSING the auth bypass. Remove "
            "the env var or unset the production marker if this was "
            "intentional."
        )
        return False
    return True


async def require_api_key(request: Request) -> str:
    """FastAPI dependency: extracts + validates API key from the
    X-Recupero-API-Key header. Applies per-key rate limit.

    Returns the key NAME (not the secret — the secret never leaves
    the auth layer). Endpoints can attribute requests via the name
    for audit logs.

    Raises HTTP 401 on missing/invalid key, 429 on rate-limit
    violation.
    """
    if _is_optional_auth():
        request.state.api_key_name = "anonymous"
        return "anonymous"

    # v0.20.2 (adversarial-audit): do NOT .strip() the inbound header.
    # Stripping silently accepts " sk_xxx\t" as equivalent to "sk_xxx",
    # expanding the valid-key surface for every leaked secret and
    # defeating naive log-fingerprint / WAF diff detection. Treat the
    # header value as opaque bytes; compare exactly what the client
    # sent. We still treat a missing header OR a header that is empty
    # / whitespace-only as "no credential supplied" (401), so that a
    # client sending `X-Recupero-API-Key: ` does not slip through to
    # the constant-time match with an empty-string probe.
    key_secret = request.headers.get("X-Recupero-API-Key", "")
    if not key_secret or not key_secret.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Recupero-API-Key header",
        )
    # v0.18.2 (round-11 sec-HIGH-004): constant-time match.
    # See `_find_api_key_constant_time` for the timing-side-channel
    # rationale. Defense against a remote attacker who can sample
    # response-time variance to learn prefix bytes of valid keys.
    key_name = _find_api_key_constant_time(key_secret)
    if key_name is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if _check_rate_limit(key_name) is False:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for API key {key_name!r}",
        )

    # Stash the resolved actor for audit + RBAC (the secret never leaves here).
    request.state.api_key_name = key_name
    return key_name


def _check_rate_limit(key_name: str) -> bool:
    """Token-bucket check. Returns True if request allowed; False
    if rate-limited. Thread-safe."""
    rate_limits = _load_rate_limits()
    rps = rate_limits.get(key_name, _DEFAULT_RPS)
    burst = _DEFAULT_BURST
    now = time.monotonic()

    with _buckets_lock:
        bucket = _buckets.get(key_name)
        if bucket is None:
            bucket = _Bucket(
                tokens=float(burst),
                last_refill=now,
                rps=rps,
                burst=burst,
            )
            _buckets[key_name] = bucket
        # Refill since last check.
        elapsed = now - bucket.last_refill
        bucket.tokens = min(
            float(bucket.burst),
            bucket.tokens + elapsed * bucket.rps,
        )
        bucket.last_refill = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False


def reset_buckets_for_tests() -> None:
    """Clear rate-limit state. Tests call this between scenarios
    so the previous test's bucket state doesn't bleed into the
    next."""
    with _buckets_lock:
        _buckets.clear()


__all__ = (
    "require_api_key",
    "require_role",
    "role_for_key",
    "reset_buckets_for_tests",
)
