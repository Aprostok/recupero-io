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


def _load_api_keys() -> dict[str, str]:
    """Parse RECUPERO_API_KEYS env var into {name: secret} map.

    Format: 'name1:secret1,name2:secret2'. Whitespace stripped.
    Empty pairs silently skipped.
    """
    raw = os.environ.get("RECUPERO_API_KEYS", "").strip()
    if not raw:
        return {}
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
    return out


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


def _is_optional_auth() -> bool:
    """Local-dev bypass. NEVER set in production."""
    return os.environ.get("RECUPERO_API_AUTH_OPTIONAL", "").strip() == "1"


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
        return "anonymous"

    key_secret = request.headers.get("X-Recupero-API-Key", "").strip()
    if not key_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Recupero-API-Key header",
        )
    keys = _load_api_keys()
    key_name = keys.get(key_secret)
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
    "reset_buckets_for_tests",
)
