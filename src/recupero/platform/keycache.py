"""Optional Redis cache for API-key → principal resolution (auth hot path).

Machine clients present an org API key on EVERY request; resolving it hits
Postgres (hash lookup + a ``last_used_at`` write). When ``RECUPERO_REDIS_URL`` is
set this caches the POSITIVE resolution (org_id + plan) under the key hash for a
short TTL, saving that round-trip on repeat calls.

Correctness posture (security-sensitive — deliberately conservative):
  * only positive, active resolutions are cached — an invalid/unknown key ALWAYS
    re-checks the DB (no cache-driven lockout, no negative caching);
  * TTL is short (``RECUPERO_APIKEY_CACHE_TTL_SEC``, default 60) so a plan/status
    change propagates quickly on its own;
  * revocation calls ``invalidate()`` for immediate effect;
  * ANY Redis error (or missing package) falls back to the DB — the cache is
    best-effort and never an auth gate.
Unset ``RECUPERO_REDIS_URL`` ⇒ every op is a no-op (behaviour identical to no
cache), so this is inert in single-replica / local dev.
"""

from __future__ import annotations

import contextlib
import json
import os
from functools import lru_cache
from typing import Any

_PREFIX = "akc:"


def _ttl() -> int:
    try:
        return max(1, int(os.environ.get("RECUPERO_APIKEY_CACHE_TTL_SEC", "60")))
    except (TypeError, ValueError):
        return 60


@lru_cache(maxsize=1)
def _client() -> Any | None:
    """Process-wide Redis client, or None when unconfigured/unreachable. Memoized;
    call ``_client.cache_clear()`` in tests to re-read the environment."""
    url = os.environ.get("RECUPERO_REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis  # optional dependency — shared with platform.ratelimit

        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        return client
    except Exception:
        return None


def get(key_hash: str) -> dict[str, Any] | None:
    client = _client()
    if client is None:
        return None
    try:
        raw = client.get(_PREFIX + key_hash)
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def put(key_hash: str, value: dict[str, Any]) -> None:
    client = _client()
    if client is None:
        return
    with contextlib.suppress(Exception):
        client.setex(_PREFIX + key_hash, _ttl(), json.dumps(value))


def invalidate(key_hash: str) -> None:
    client = _client()
    if client is None:
        return
    with contextlib.suppress(Exception):
        client.delete(_PREFIX + key_hash)


__all__ = ("get", "put", "invalidate")
