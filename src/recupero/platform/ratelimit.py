"""Per-org rate limiting: a correct in-process default + an optional shared
Redis backend for multi-replica deployments.

The API enforces each org's plan rate limit (``tenancy.Plan.rate_limit_per_min``)
with a token bucket. In-process state is correct only for a SINGLE API replica —
each replica keeps its own bucket, so N replicas would allow ~N× the intended
rate. Set ``RECUPERO_REDIS_URL`` and the limiter switches to a SHARED Redis token
bucket (atomic via a Lua script), so the limit holds across every replica.

Design notes
------------
* The bucket state lives INSIDE the limiter instance (not a module-level dict),
  so this module has no module-level mutable hotspot to guard.
* The backend is chosen ONCE per process (``get_rate_limiter`` is memoized). If
  ``RECUPERO_REDIS_URL`` is set but the ``redis`` package is missing or the
  server is unreachable, the limiter FAILS OPEN to the in-process bucket — rate
  limiting is a best-effort guard, never a correctness gate, so degrading to a
  per-replica limit beats 500-ing the request.
* In-process uses a monotonic clock (immune to wall-clock jumps); Redis uses the
  wall clock (``time.time``) because the bucket is shared across processes whose
  monotonic clocks are unrelated.
"""

from __future__ import annotations

import os
import threading
import time
from functools import lru_cache
from typing import Any, Protocol


class RateLimiter(Protocol):
    """A token-bucket limiter. ``allow`` consumes one token for ``key`` and
    returns whether the request is under the per-minute rate."""

    def allow(self, key: str, rate_per_min: int) -> bool: ...


class InProcessRateLimiter:
    """Monotonic-clock token bucket held per-instance. Correct for a single
    replica; each replica keeps independent state."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)
        self._lock = threading.Lock()

    def allow(self, key: str, rate_per_min: int, *, now: float | None = None) -> bool:
        if rate_per_min <= 0:
            return True
        now = time.monotonic() if now is None else now
        capacity = float(rate_per_min)
        refill_per_sec = rate_per_min / 60.0
        with self._lock:
            tokens, last = self._buckets.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - last) * refill_per_sec)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True


# Atomic token bucket in a single round-trip. Reads (tokens, ts), refills by
# elapsed wall-clock time, consumes one token iff >= 1, writes back, and sets a
# TTL so idle keys evict themselves. Returns 1 (allowed) or 0 (limited).
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_sec = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  ts = now
end
tokens = math.min(capacity, tokens + (now - ts) * refill_per_sec)
local allowed = 0
if tokens >= 1.0 then
  tokens = tokens - 1.0
  allowed = 1
end
redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, ttl)
return allowed
"""


class RedisRateLimiter:
    """Shared token bucket backed by Redis (atomic via a server-side Lua
    script). Correct across any number of API replicas. On a Redis error the
    request FAILS OPEN to a local in-process bucket."""

    def __init__(self, client: Any, *, fallback: RateLimiter | None = None) -> None:
        self._redis = client
        self._script = client.register_script(_TOKEN_BUCKET_LUA)  # server SHA-cached
        self._fallback = fallback if fallback is not None else InProcessRateLimiter()

    def allow(self, key: str, rate_per_min: int, *, now: float | None = None) -> bool:
        if rate_per_min <= 0:
            return True
        now = time.time() if now is None else now  # WALL clock — shared across replicas
        capacity = float(rate_per_min)
        refill_per_sec = rate_per_min / 60.0
        # Evict idle keys after ~2× the full drain time (min 60s).
        ttl = max(60, int(capacity / refill_per_sec) * 2) if refill_per_sec else 60
        try:
            res = self._script(keys=[f"rl:{key}"], args=[capacity, refill_per_sec, now, ttl])
            return bool(int(res))
        except Exception:
            # Redis hiccup → best-effort local guard rather than a hard failure.
            return self._fallback.allow(key, rate_per_min)


@lru_cache(maxsize=1)
def get_rate_limiter() -> RateLimiter:
    """Return the process-wide limiter, chosen once from the environment.

    ``RECUPERO_REDIS_URL`` set + reachable → shared Redis limiter; otherwise the
    in-process default. Memoized; call ``get_rate_limiter.cache_clear()`` in
    tests to re-read the environment."""
    url = os.environ.get("RECUPERO_REDIS_URL", "").strip()
    if not url:
        return InProcessRateLimiter()
    try:
        import redis  # optional dependency — only needed for multi-replica

        client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        return RedisRateLimiter(client)
    except Exception:
        # redis package missing or server unreachable at boot → local fallback.
        return InProcessRateLimiter()


__all__ = (
    "RateLimiter",
    "InProcessRateLimiter",
    "RedisRateLimiter",
    "get_rate_limiter",
)
