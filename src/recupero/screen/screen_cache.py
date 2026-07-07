"""High-throughput screening cache (v0.35.17 — roadmap E2).

``screen_address`` re-loads the ENTIRE high-risk DB from disk on every call
(``load_high_risk_db()`` when no db is injected). Under the bulk-screening /
address-profile load that dominates latency. This adds two process-local caches
so a busy screening surface stays fast:

  1. **DB cache** — load the high-risk DB once, reuse it across calls.
  2. **Result LRU** — memoize the (canonical-address, chain) → ``ScreeningResult``
     for local-seed screening (correlation DB intentionally OFF for cached
     results: correlation is mutable per-case state and must not be frozen in a
     process-lifetime cache).

Both caches are cleared explicitly (``clear_screen_cache``) after a label
re-sync, so there is NO time-based staleness and NO hidden clock — deterministic
and testable. Cache stats (hits / misses / size / hit-rate) are exposed for the
ops/monitoring surface.

Forensic posture unchanged: this is purely a performance layer over the same
local-seed screener; verdicts/labels/confidence are byte-identical to an
uncached call. It never invents a result and never caches correlation history.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from recupero.screen.screener import screen_address
from recupero.trace.risk_scoring import load_high_risk_db

if TYPE_CHECKING:  # pragma: no cover
    from recupero.screen.screener import ScreeningResult
    from recupero.trace.risk_scoring import HighRiskEntry

log = logging.getLogger(__name__)

# Max distinct (chain, address) results retained. ~50k covers a heavy bulk
# session; beyond that the least-recently-used entries are evicted.
_MAX_RESULTS = 50_000

_lock = threading.Lock()
_high_risk_db: dict[str, HighRiskEntry] | None = None
# M5: stamp of the OFAC live CSV (mtime, size) captured when the DB cache was
# built. When another PROCESS re-syncs OFAC the CSV changes on disk; on the
# next access this process notices the changed stamp and auto-reloads — so a
# cross-process refresh invalidates the cache without an explicit clear call.
_ofac_csv_stamp: tuple[float, int] | None = None
_results: OrderedDict[tuple[str, str], ScreeningResult] = OrderedDict()
_hits = 0
_misses = 0


def _current_ofac_csv_stamp() -> tuple[float, int] | None:
    """(mtime, size) of the authoritative OFAC live CSV, or None if absent /
    unreadable. Never raises — a stat failure degrades to "no stamp" (the cache
    simply won't auto-invalidate on that source)."""
    try:
        from recupero.trace.ofac_sync import DEFAULT_OFAC_CSV_PATH
        st = DEFAULT_OFAC_CSV_PATH.stat()
        return (st.st_mtime, st.st_size)
    except Exception:  # noqa: BLE001
        return None


def get_cached_high_risk_db(*, force_reload: bool = False) -> dict[str, HighRiskEntry]:
    """Load the high-risk DB once and reuse it. ``force_reload`` re-reads disk
    (call after a label re-sync).

    M5: also auto-reloads when the OFAC live CSV's (mtime, size) has changed
    since the cache was built — so a sync performed by ANOTHER process is
    picked up here without an explicit ``clear_screen_cache`` call."""
    global _high_risk_db, _ofac_csv_stamp
    with _lock:
        stamp = _current_ofac_csv_stamp()
        stale = _high_risk_db is not None and stamp != _ofac_csv_stamp
        if _high_risk_db is None or force_reload or stale:
            _high_risk_db = load_high_risk_db()
            _ofac_csv_stamp = stamp
        return _high_risk_db


def cached_screen(address: str, *, chain: str = "ethereum") -> ScreeningResult:
    """Screen an address using the cached DB + result LRU (local-seed only).

    Equivalent to ``screen_address(address, chain=chain,
    use_correlation_db=False, high_risk_db=<cached>)`` but memoized by canonical
    (chain, address). For correlation-aware screening, call ``screen_address``
    directly (uncached) — correlation must not be frozen in cache.
    """
    from recupero._common import canonical_address_key as _ck
    key = ((chain or "ethereum").strip().lower(), _ck(str(address or "")))

    global _hits, _misses
    with _lock:
        hit = _results.get(key)
        if hit is not None:
            _results.move_to_end(key)
            _hits += 1
            return hit

    # Compute outside the lock (screen_address can be non-trivial); the DB is
    # already cached. A concurrent duplicate miss just recomputes harmlessly.
    db = get_cached_high_risk_db()
    result = screen_address(
        address, chain=chain, use_correlation_db=False, high_risk_db=db,
    )
    with _lock:
        _misses += 1
        _results[key] = result
        _results.move_to_end(key)
        while len(_results) > _MAX_RESULTS:
            _results.popitem(last=False)   # evict least-recently-used
    return result


def cache_stats() -> dict[str, Any]:
    """Hit/miss/size/hit-rate snapshot for the monitoring surface."""
    with _lock:
        total = _hits + _misses
        return {
            "hits": _hits,
            "misses": _misses,
            "size": len(_results),
            "max_size": _MAX_RESULTS,
            "db_loaded": _high_risk_db is not None,
            "hit_rate": round(_hits / total, 4) if total else 0.0,
        }


def clear_screen_cache(*, reload_db: bool = False) -> None:
    """Clear the result LRU + counters (call after a label re-sync). When
    ``reload_db`` is True the DB cache is dropped too so the next screen re-reads
    the refreshed seeds."""
    global _high_risk_db, _hits, _misses, _ofac_csv_stamp
    with _lock:
        _results.clear()
        _hits = 0
        _misses = 0
        if reload_db:
            _high_risk_db = None
            _ofac_csv_stamp = None


__all__ = (
    "get_cached_high_risk_db",
    "cached_screen",
    "cache_stats",
    "clear_screen_cache",
)
