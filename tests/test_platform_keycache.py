"""Unit tests for the optional API-key resolution cache (platform/keycache.py)
and its wiring into the auth hot path.

No live Redis: the client picker is monkeypatched with a fake redis (or None).
"""

from __future__ import annotations

import json

from recupero.platform import deps, keycache, store, tenancy


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, bytes] = {}

    def get(self, k):
        return self.store.get(k)

    def setex(self, k, ttl, v):
        self.store[k] = v.encode() if isinstance(v, str) else v

    def delete(self, k):
        self.store.pop(k, None)


def _use_fake(monkeypatch):
    fake = _FakeRedis()
    keycache._client.cache_clear()
    monkeypatch.setattr(keycache, "_client", lambda: fake)
    return fake


def teardown_function():
    keycache._client.cache_clear()


# ---- no-redis: every op is a no-op ---- #

def test_no_redis_is_inert(monkeypatch):
    keycache._client.cache_clear()
    monkeypatch.setattr(keycache, "_client", lambda: None)
    assert keycache.get("h") is None
    keycache.put("h", {"org_id": "o"})   # no raise
    keycache.invalidate("h")             # no raise
    assert keycache.get("h") is None


# ---- with fake redis: round-trip + invalidate ---- #

def test_put_then_get_roundtrip(monkeypatch):
    fake = _use_fake(monkeypatch)
    keycache.put("h1", {"org_id": "org1", "plan": "pro"})
    assert keycache.get("h1") == {"org_id": "org1", "plan": "pro"}
    # stored under the namespaced key
    assert "akc:h1" in fake.store


def test_invalidate_drops_entry(monkeypatch):
    _use_fake(monkeypatch)
    keycache.put("h1", {"org_id": "org1", "plan": "pro"})
    keycache.invalidate("h1")
    assert keycache.get("h1") is None


def test_corrupt_cache_value_ignored(monkeypatch):
    fake = _use_fake(monkeypatch)
    fake.store["akc:h1"] = b"not json"
    assert keycache.get("h1") is None


# ---- store.revoke_api_key now returns the hash ---- #

class _RevCursor:
    def __init__(self, row):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        assert "RETURNING key_hash" in sql

    def fetchone(self):
        return self._row


class _RevConn:
    def __init__(self, row):
        self._c = _RevCursor(row)

    def cursor(self):
        return self._c


def test_revoke_returns_hash_or_none():
    assert store.revoke_api_key(_RevConn(("abc123",)), org_id="o", key_id="k") == "abc123"
    assert store.revoke_api_key(_RevConn(None), org_id="o", key_id="k") is None


# ---- deps hot path: a cache hit skips the DB resolve ---- #

def test_current_principal_cache_hit_skips_db(monkeypatch):
    _use_fake(monkeypatch)
    key = tenancy.API_KEY_PREFIX + "sometoken"
    keycache.put(tenancy.hash_api_key(key), {"org_id": "org1", "plan": "pro"})

    def _boom(*a, **k):
        raise AssertionError("resolve_api_key must NOT be called on a cache hit")

    monkeypatch.setattr(store, "resolve_api_key", _boom)
    ctx = deps.current_principal(authorization=None, x_api_key=key, conn=object())
    assert ctx.org_id == "org1" and ctx.plan == "pro" and ctx.role == "service"


def test_current_principal_cache_miss_populates(monkeypatch):
    fake = _use_fake(monkeypatch)
    key = tenancy.API_KEY_PREFIX + "freshtoken"
    resolved = store.OrgContext(org_id="org9", plan="enterprise", user_id=None, role="service")
    monkeypatch.setattr(store, "resolve_api_key", lambda conn, k: resolved)
    ctx = deps.current_principal(authorization=None, x_api_key=key, conn=object())
    assert ctx.org_id == "org9"
    # cache now populated for next time
    cached = json.loads(fake.store["akc:" + tenancy.hash_api_key(key)])
    assert cached == {"org_id": "org9", "plan": "enterprise"}
