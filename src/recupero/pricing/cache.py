"""Price cache for the CoinGecko client.

Two implementations:

- ``PriceCache`` — file-system backed, one JSON file per (cache_key) tuple.
  The original implementation. Survives within a single investigation
  (per-tempdir) but disappears when the tempdir is cleaned up. Used by
  the CLI and any code path that doesn't pass a DB DSN.

- ``PostgresPriceCache`` — single ``public.pricing_cache`` table shared
  across all investigations and worker replicas. Used by the worker so
  Phase 2 nightly re-runs and any high-volume workload don't pay
  CoinGecko's 0.5 rps tax every run for tokens we've already priced.

Both implement the same minimal interface:
  - ``get(key: str) -> dict | None``
  - ``put(key: str, value: dict) -> None``

The value dict shape is owned by CoinGeckoClient — both implementations
treat it as opaque (key plus a {"usd": str|None, "error": str?} payload).

The factory ``make_price_cache(dsn=None, cache_dir=...)`` picks the
DB-backed one when a DSN is provided, falling back to the file-based
implementation otherwise. That keeps test paths and CLI usage working
without requiring a live DB.
"""

from __future__ import annotations

import json
import logging
import os
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from recupero._common import db_connect

log = logging.getLogger(__name__)


class PriceCacheLike(Protocol):
    """Duck-typed interface so callers can accept either backend."""

    def get(self, key: str) -> dict | None: ...
    def put(self, key: str, value: dict) -> None: ...


class PriceCache:
    """File-system backed cache. One JSON file per key under ``cache_dir``."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> dict | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            with path.open() as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("price cache miss (corrupted) %s: %s", path, e)
            return None
        # v0.16.10 (round-9 forensic MEDIUM): negative-price defense.
        # CoinGecko has been known to return absurd negatives during
        # outages on obscure tokens; refuse to surface them to the
        # consumer (they'd pollute USD totals).
        usd = data.get("usd")
        if usd is not None:
            try:
                if float(usd) < 0:
                    log.warning(
                        "price cache returned negative usd=%r for key=%s — discarding",
                        usd, key,
                    )
                    return None
            except (TypeError, ValueError):
                pass
        return data

    def put(self, key: str, value: dict) -> None:
        path = self._path_for(key)
        # Convert Decimals to strings for JSON safety
        value = self._json_safe(value)
        # v0.16.10 (round-9 forensic LOW): atomic write. Concurrent
        # dormant-detector threads pricing the same key could corrupt
        # the cache file with overlapping writes; the manifest then
        # parsed as truncated JSON and we'd refetch unnecessarily.
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            with tmp.open("w") as f:
                json.dump(value, f, indent=2)
            os.replace(tmp, path)
        except OSError as e:
            log.warning("failed to write price cache %s: %s", path, e)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass

    def _path_for(self, key: str) -> Path:
        # v0.16.10 (round-9 forensic MEDIUM): hash the key to a fixed
        # filename. Pre-v0.16.10 we just replaced `/` and `:` with `_`,
        # which collided when keys like `a:b` and `a/b` mapped to the
        # same path. SHA1 is fine here — we're not protecting against
        # collisions adversarially, just keeping distinct cache keys
        # in distinct files. The first 16 hex chars (64 bits) is more
        # than enough collision-resistance for our cache size.
        import hashlib
        h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        return self.cache_dir / f"{h}.json"

    @staticmethod
    def _json_safe(value: dict) -> dict:
        out = {}
        for k, v in value.items():
            if isinstance(v, Decimal):
                out[k] = str(v)
            else:
                out[k] = v
        return out


class PostgresPriceCache:
    """Postgres-backed price cache shared across investigations.

    Stores rows in ``public.pricing_cache`` (one row per cache_key).
    Apply ``migrations/003_pricing_cache.sql`` before using; the class
    falls back gracefully on missing-table errors so a misconfigured
    deployment downgrades to "no cache" rather than crashing every run.

    Thread-safe: each get/put opens its own short-lived connection.
    Designed for the transaction-pooler endpoint (port 6543) so
    concurrent dormant-detector workers can hit it without exhausting
    Postgres connection slots.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn:
            raise ValueError("dsn is required for PostgresPriceCache")
        self._dsn = dsn
        self._table_missing_warned = False

    def get(self, key: str) -> dict | None:
        import psycopg
        try:
            with db_connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT usd_price, error_msg FROM public.pricing_cache "
                    "WHERE cache_key = %s",
                    (key,),
                )
                row = cur.fetchone()
        except psycopg.errors.UndefinedTable:
            self._warn_table_missing()
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("price cache (pg) get failed for %s: %s", key, e)
            return None
        if row is None:
            return None
        usd, error = row
        out: dict = {}
        # Match the file-based cache's serialized shape so CoinGeckoClient
        # can treat both backends identically.
        if usd is not None:
            out["usd"] = str(usd)
        else:
            out["usd"] = None
            if error:
                out["error"] = error
        return out

    def put(self, key: str, value: dict) -> None:
        import psycopg
        usd = value.get("usd")
        # Coerce numeric strings to Decimal-friendly form for the column.
        # Numeric NULL when no price; we still store the row so callers
        # don't refetch a known-unavailable price for the same date.
        usd_param = None if usd in (None, "None", "") else str(usd)
        error_param = value.get("error")
        try:
            with db_connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """
                        INSERT INTO public.pricing_cache
                            (cache_key, usd_price, error_msg)
                        VALUES (%s, %s::numeric, %s)
                        ON CONFLICT (cache_key) DO UPDATE SET
                            usd_price = EXCLUDED.usd_price,
                            error_msg = EXCLUDED.error_msg,
                            cached_at = NOW()
                        """,
                    (key, usd_param, error_param),
                )
        except psycopg.errors.UndefinedTable:
            self._warn_table_missing()
        except Exception as e:  # noqa: BLE001
            log.warning("price cache (pg) put failed for %s: %s", key, e)

    def _warn_table_missing(self) -> None:
        if self._table_missing_warned:
            return
        self._table_missing_warned = True
        log.warning(
            "pricing_cache table not found — apply migrations/003_pricing_cache.sql. "
            "Running without persistent cache for this process."
        )


def make_price_cache(
    *,
    dsn: str | None = None,
    cache_dir: Path | None = None,
) -> PriceCacheLike:
    """Factory: return the best cache backend for the runtime.

    Order of preference:
      1. Postgres if DSN is provided (worker production path).
      2. File system if cache_dir is provided (CLI / tests / fallback).
      3. Raise — caller must supply at least one.
    """
    if dsn:
        return PostgresPriceCache(dsn)
    if cache_dir is not None:
        return PriceCache(cache_dir)
    raise ValueError("make_price_cache requires either dsn or cache_dir")
