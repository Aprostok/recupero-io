"""Tests for the two price cache backends + factory.

PostgresPriceCache is tested via a fake psycopg layer (no live DB
required). The factory is tested by toggling environment + explicit
parameters.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from recupero.pricing.cache import (
    PostgresPriceCache,
    PriceCache,
    make_price_cache,
)

# ============================================================================
# PriceCache (file-system, original)
# ============================================================================


class TestFileCacheRoundTrip:
    def test_get_missing_returns_none(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        assert cache.get("coingecko:simple:ethereum:2026-05-10") is None

    def test_put_then_get_roundtrip(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        cache.put("k1", {"usd": "1234.56"})
        result = cache.get("k1")
        assert result == {"usd": "1234.56"}

    def test_put_decimal_serializes_safely(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        cache.put("k1", {"usd": Decimal("1234.56"), "error": None})
        result = cache.get("k1")
        # Decimal serialized as string
        assert result["usd"] == "1234.56"

    def test_path_chars_sanitized(self, tmp_path: Path) -> None:
        """v0.16.10 (round-9 forensic MEDIUM): keys hashed to fixed-
        length filenames to prevent the `a:b` / `a/b` collision the
        old replace-chars approach had. The exact filename is opaque
        SHA1 hex; we just assert one file is created + readable."""
        cache = PriceCache(tmp_path)
        key = "coingecko:simple:ethereum:2026-05-10"
        cache.put(key, {"usd": "1.00"})
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1
        # Filename is 16-char hex + .json suffix
        assert files[0].suffix == ".json"
        assert len(files[0].stem) == 16
        # Round-trip via the same key works
        result = cache.get(key)
        assert result == {"usd": "1.00"}

    def test_path_keys_with_collision_chars_dont_clash(
        self, tmp_path: Path,
    ) -> None:
        """Different keys → different files (the bug pre-v0.16.10 was
        `a:b` and `a/b` hashing to the same path)."""
        cache = PriceCache(tmp_path)
        cache.put("a:b", {"usd": "1.00"})
        cache.put("a/b", {"usd": "2.00"})
        assert cache.get("a:b") == {"usd": "1.00"}
        assert cache.get("a/b") == {"usd": "2.00"}

    def test_corrupted_file_treated_as_miss(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        # Put a deliberately broken JSON file
        bad = tmp_path / "coingecko_test_2026-05-10.json"
        bad.write_text("not valid json{")
        assert cache.get("coingecko:test:2026-05-10") is None


# ============================================================================
# PostgresPriceCache (via injected fake psycopg)
# ============================================================================


class _FakeCursor:
    def __init__(self, store: dict[str, tuple]) -> None:
        self.store = store
        self.last_result: tuple | None = None

    def execute(self, sql: str, params: tuple | None = None) -> None:
        sql_norm = " ".join(sql.split())
        if "SELECT usd_price" in sql_norm:
            (key,) = params
            self.last_result = self.store.get(key)
        elif "INSERT INTO public.pricing_cache" in sql_norm:
            key, usd, error = params
            # Match the production write semantics: usd_price stored as Decimal-ish
            self.store[key] = (Decimal(usd) if usd is not None else None, error)
        else:
            raise AssertionError(f"unexpected SQL: {sql_norm[:80]}")

    def fetchone(self) -> tuple | None:
        return self.last_result

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc) -> None:
        return None


class _FakeConn:
    def __init__(self, store: dict[str, tuple]) -> None:
        self.store = store

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self.store)

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc) -> None:
        return None


class _FakePsycopg:
    """Just enough of the psycopg module surface for PostgresPriceCache."""

    def __init__(self) -> None:
        self.store: dict[str, tuple] = {}

    def connect(self, dsn: str, **kwargs) -> _FakeConn:
        return _FakeConn(self.store)

    # mimic psycopg.errors.UndefinedTable
    class errors:  # noqa: N801
        class UndefinedTable(Exception):
            pass


@pytest.fixture
def fake_psycopg(monkeypatch):
    fp = _FakePsycopg()
    monkeypatch.setitem(__import__("sys").modules, "psycopg", fp)
    return fp


class TestPostgresCache:
    def test_init_requires_dsn(self) -> None:
        with pytest.raises(ValueError, match="dsn is required"):
            PostgresPriceCache("")

    def test_get_missing_returns_none(self, fake_psycopg) -> None:
        cache = PostgresPriceCache("postgresql://fake")
        assert cache.get("coingecko:simple:ethereum:2026-05-10") is None

    def test_put_then_get(self, fake_psycopg) -> None:
        cache = PostgresPriceCache("postgresql://fake")
        cache.put("k1", {"usd": "1234.56"})
        result = cache.get("k1")
        assert result == {"usd": "1234.56"}

    def test_put_none_price_is_cached_with_error(self, fake_psycopg) -> None:
        """A failed fetch should still be cached so we don't retry the same
        unavailable price on every nightly run."""
        cache = PostgresPriceCache("postgresql://fake")
        cache.put("k1", {"usd": None, "error": "no_coingecko_mapping"})
        result = cache.get("k1")
        assert result["usd"] is None
        assert result["error"] == "no_coingecko_mapping"

    def test_missing_table_returns_none_gracefully(self, fake_psycopg, caplog) -> None:
        """If migration hasn't been applied yet, the cache should silently
        degrade rather than crashing every CoinGecko lookup."""

        def _raise_undefined(*a, **k):
            raise fake_psycopg.errors.UndefinedTable("relation does not exist")

        fake_psycopg.connect = _raise_undefined  # type: ignore[method-assign]

        import logging
        caplog.set_level(logging.WARNING, logger="recupero.pricing.cache")
        cache = PostgresPriceCache("postgresql://fake")
        assert cache.get("k1") is None
        # Warning logged once
        assert "pricing_cache table not found" in caplog.text
        # Subsequent calls don't log a second time
        caplog.clear()
        assert cache.get("k2") is None
        assert "pricing_cache table not found" not in caplog.text

    def test_put_overwrites_existing_key(self, fake_psycopg) -> None:
        # Conflict path: same key, value updated, cached_at refreshed
        cache = PostgresPriceCache("postgresql://fake")
        cache.put("k1", {"usd": "1000.00"})
        cache.put("k1", {"usd": "1100.00"})
        result = cache.get("k1")
        assert result["usd"] == "1100.00"


# ============================================================================
# Factory
# ============================================================================


class TestFactory:
    def test_dsn_picked_when_provided(self, fake_psycopg) -> None:
        cache = make_price_cache(dsn="postgresql://fake")
        assert isinstance(cache, PostgresPriceCache)

    def test_cache_dir_picked_when_no_dsn(self, tmp_path: Path) -> None:
        cache = make_price_cache(dsn=None, cache_dir=tmp_path)
        assert isinstance(cache, PriceCache)

    def test_neither_raises(self) -> None:
        with pytest.raises(ValueError, match="requires either dsn or cache_dir"):
            make_price_cache(dsn=None, cache_dir=None)

    def test_dsn_wins_over_cache_dir(self, fake_psycopg, tmp_path: Path) -> None:
        # When both are provided, Postgres wins (worker production path)
        cache = make_price_cache(dsn="postgresql://fake", cache_dir=tmp_path)
        assert isinstance(cache, PostgresPriceCache)
