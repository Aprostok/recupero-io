"""v0.35.17 (E2) — high-throughput screening cache.

Pins: the result LRU (hit/miss, EIP-55 canonical dedup, chain in the key, LRU
eviction), the load-once DB cache, and clear/reset semantics. The cache must be
a transparent perf layer — same verdict as an uncached call, never invented.
"""

from __future__ import annotations

import pytest

import recupero.screen.screen_cache as sc


class _FakeResult:
    def __init__(self, address: str, chain: str) -> None:
        self.address = address
        self.chain = chain
        self.risk_verdict = "clean"


@pytest.fixture(autouse=True)
def _reset_and_patch(monkeypatch):
    """Isolate the module-global caches + count DB loads / screen calls."""
    counts = {"db": 0, "screen": 0}

    def fake_db(*a, **k):
        counts["db"] += 1
        return {}

    def fake_screen(address, *, chain="ethereum", use_correlation_db=True,
                    high_risk_db=None):
        counts["screen"] += 1
        # The cache must call with correlation OFF + the cached db injected.
        assert use_correlation_db is False
        assert high_risk_db is not None
        return _FakeResult(address, chain)

    monkeypatch.setattr(sc, "load_high_risk_db", fake_db)
    monkeypatch.setattr(sc, "screen_address", fake_screen)
    sc.clear_screen_cache(reload_db=True)
    yield counts
    sc.clear_screen_cache(reload_db=True)


def test_hit_miss_and_db_loaded_once(_reset_and_patch):
    counts = _reset_and_patch
    a = "0x" + "a" * 40
    sc.cached_screen(a, chain="ethereum")          # miss
    sc.cached_screen(a, chain="ethereum")          # hit
    sc.cached_screen("0x" + "b" * 40, chain="ethereum")  # miss
    st = sc.cache_stats()
    assert st["hits"] == 1 and st["misses"] == 2 and st["size"] == 2
    assert counts["screen"] == 2          # the hit avoided a recompute
    assert counts["db"] == 1              # DB loaded once, reused
    assert st["db_loaded"] is True
    assert st["hit_rate"] == round(1 / 3, 4)


def test_eip55_canonical_dedup(_reset_and_patch):
    counts = _reset_and_patch
    mixed = "0x" + "Ab" * 20
    sc.cached_screen(mixed, chain="ethereum")        # miss
    sc.cached_screen(mixed.lower(), chain="ethereum")  # canonical → hit
    assert counts["screen"] == 1
    assert sc.cache_stats()["hits"] == 1


def test_chain_is_part_of_key(_reset_and_patch):
    counts = _reset_and_patch
    a = "0x" + "c" * 40
    sc.cached_screen(a, chain="ethereum")
    sc.cached_screen(a, chain="arbitrum")
    # Same address, different chain → two distinct cache entries.
    assert counts["screen"] == 2
    assert sc.cache_stats()["size"] == 2


def test_lru_eviction(monkeypatch, _reset_and_patch):
    monkeypatch.setattr(sc, "_MAX_RESULTS", 2)
    for i in range(3):
        sc.cached_screen("0x" + f"{i:040x}", chain="ethereum")
    assert sc.cache_stats()["size"] == 2   # oldest evicted


def test_clear_resets_stats_and_db(_reset_and_patch):
    counts = _reset_and_patch
    sc.cached_screen("0x" + "d" * 40, chain="ethereum")
    assert sc.cache_stats()["misses"] == 1
    sc.clear_screen_cache(reload_db=True)
    st = sc.cache_stats()
    assert st["hits"] == 0 and st["misses"] == 0 and st["size"] == 0
    assert st["db_loaded"] is False
    # Next screen reloads the DB.
    sc.cached_screen("0x" + "d" * 40, chain="ethereum")
    assert counts["db"] == 2   # initial load (fixture) + reload after clear


def test_result_is_passed_through(_reset_and_patch):
    a = "0x" + "e" * 40
    r = sc.cached_screen(a, chain="ethereum")
    assert isinstance(r, _FakeResult)
    assert r.address == a
