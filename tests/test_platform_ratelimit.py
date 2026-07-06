"""Unit tests for the per-org rate limiter (in-process + Redis backends).

No live Redis: the Redis backend is exercised through a fake client that
implements ``register_script`` + a callable script, so we lock the delegation
path and the fail-open behavior without a server.
"""

from __future__ import annotations

from recupero.platform import ratelimit
from recupero.platform.ratelimit import (
    InProcessRateLimiter,
    RedisRateLimiter,
    get_rate_limiter,
)

# ---- in-process token bucket ---- #

def test_inprocess_allows_up_to_capacity_then_limits() -> None:
    rl = InProcessRateLimiter()
    # Freeze the clock: capacity=3, no refill within the burst.
    allowed = [rl.allow("org1", 3, now=100.0) for _ in range(3)]
    assert allowed == [True, True, True]
    assert rl.allow("org1", 3, now=100.0) is False  # bucket empty


def test_inprocess_refills_over_time() -> None:
    rl = InProcessRateLimiter()
    for _ in range(3):
        rl.allow("org1", 60, now=0.0)  # drain 3 of 60 (rate 60/min = 1/sec)
    # 60/min → 1 token/sec. Two seconds later, ≥1 token has refilled.
    assert rl.allow("org1", 60, now=2.0) is True


def test_inprocess_zero_rate_always_allows() -> None:
    rl = InProcessRateLimiter()
    assert all(rl.allow("org1", 0, now=t) for t in range(10))
    assert rl.allow("org1", -5, now=0.0) is True


def test_inprocess_isolates_keys() -> None:
    rl = InProcessRateLimiter()
    assert rl.allow("orgA", 1, now=0.0) is True
    assert rl.allow("orgA", 1, now=0.0) is False   # A drained
    assert rl.allow("orgB", 1, now=0.0) is True     # B independent


# ---- Redis backend (fake client) ---- #

class _FakeScript:
    """Simulates the Lua token bucket in Python, keyed by the passed KEYS[0]."""

    def __init__(self, store: dict):
        self._store = store

    def __call__(self, *, keys, args):
        key = keys[0]
        capacity, refill, now, _ttl = (float(a) for a in args)
        tokens, ts = self._store.get(key, (capacity, now))
        tokens = min(capacity, tokens + (now - ts) * refill)
        allowed = 0
        if tokens >= 1.0:
            tokens -= 1.0
            allowed = 1
        self._store[key] = (tokens, now)
        return allowed


class _FakeRedis:
    def __init__(self):
        self.store: dict = {}
        self.script = _FakeScript(self.store)

    def register_script(self, _lua: str):
        return self.script


class _BrokenRedis:
    def register_script(self, _lua: str):
        def _boom(*, keys, args):
            raise RuntimeError("redis down")
        return _boom


def test_redis_backend_limits_via_script() -> None:
    rl = RedisRateLimiter(_FakeRedis())
    allowed = [rl.allow("org1", 2, now=100.0) for _ in range(2)]
    assert allowed == [True, True]
    assert rl.allow("org1", 2, now=100.0) is False  # bucket empty (shared store)


def test_redis_backend_zero_rate_allows_without_touching_script() -> None:
    rl = RedisRateLimiter(_FakeRedis())
    assert rl.allow("org1", 0) is True


def test_redis_backend_fails_open_on_error() -> None:
    # Script raises → falls back to the in-process bucket (still enforces, never 500s).
    fallback = InProcessRateLimiter()
    rl = RedisRateLimiter(_BrokenRedis(), fallback=fallback)
    # First call fails open to the fallback (capacity 1) → allowed.
    assert rl.allow("org1", 1) is True
    # Fallback now empty for org1 → next call limited (proves fallback is real).
    assert rl.allow("org1", 1) is False


# ---- backend selection ---- #

def test_get_rate_limiter_defaults_to_inprocess(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_REDIS_URL", raising=False)
    get_rate_limiter.cache_clear()
    try:
        assert isinstance(get_rate_limiter(), InProcessRateLimiter)
    finally:
        get_rate_limiter.cache_clear()


def test_get_rate_limiter_unreachable_redis_fails_open(monkeypatch) -> None:
    # A URL that can't connect → limiter falls open to the in-process default
    # (redis import may succeed or fail; either way we must not raise).
    monkeypatch.setenv("RECUPERO_REDIS_URL", "redis://127.0.0.1:6390/0")
    get_rate_limiter.cache_clear()
    try:
        assert isinstance(get_rate_limiter(), InProcessRateLimiter)
    finally:
        get_rate_limiter.cache_clear()


def test_module_exports() -> None:
    assert set(ratelimit.__all__) >= {
        "RateLimiter", "InProcessRateLimiter", "RedisRateLimiter", "get_rate_limiter",
    }
