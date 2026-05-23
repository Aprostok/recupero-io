"""Adversarial audit of recupero.pricing.cache.PriceCache.

Hunts: poisoned NaN/Infinity surviving re-read, filename traversal,
concurrent writes, TTL/staleness, size cap, JSON parse safety,
filesystem error handling leakage.
"""

from __future__ import annotations

import json
import math
import os
import pathlib
from pathlib import Path
from unittest import mock

import pytest

from recupero.pricing.cache import PriceCache


# ----------------------------------------------------------------------
# 1. Cache poisoning — NaN/Infinity surviving re-read
# ----------------------------------------------------------------------

class TestPoisonedNaNInfinity:
    def _poison(self, cache: PriceCache, key: str, payload: dict) -> Path:
        """Write a raw JSON file bypassing put() guards."""
        path = cache._path_for(key)
        # Python's json.dump permits NaN/Infinity by default (allow_nan=True).
        with path.open("w") as f:
            json.dump(payload, f)
        return path

    def test_poisoned_nan_usd_must_not_be_served(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        # Externally-written file with NaN — e.g. attacker, prior buggy version.
        self._poison(cache, "bitcoin:2026-05-22", {"usd": float("nan")})
        result = cache.get("bitcoin:2026-05-22")
        # NaN must NEVER be served — NaN poisons every downstream USD arithmetic.
        if result is not None:
            usd = result.get("usd")
            assert usd is None or (
                not (isinstance(usd, float) and math.isnan(usd))
            ), f"poisoned NaN was served: {result!r}"

    def test_poisoned_positive_infinity_must_not_be_served(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        self._poison(cache, "shitcoin:2026-05-22", {"usd": float("inf")})
        result = cache.get("shitcoin:2026-05-22")
        if result is not None:
            usd = result.get("usd")
            assert usd is None or (
                not (isinstance(usd, float) and math.isinf(usd))
            ), f"poisoned Infinity was served: {result!r}"

    def test_poisoned_string_infinity_must_not_be_served(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        # Even string "Infinity" — float("Infinity") parses as inf and slips past negative check.
        self._poison(cache, "k:2026-05-22", {"usd": "Infinity"})
        result = cache.get("k:2026-05-22")
        if result is not None:
            usd = result.get("usd")
            if usd is not None:
                try:
                    f = float(usd)
                    assert math.isfinite(f), (
                        f"poisoned string Infinity coerced to inf was served: {result!r}"
                    )
                except (TypeError, ValueError):
                    pass


# ----------------------------------------------------------------------
# 2. Cache filename traversal — ".." in cache key
# ----------------------------------------------------------------------

class TestFilenameTraversal:
    def test_dot_dot_in_key_does_not_escape_cache_dir(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache = PriceCache(cache_dir)
        evil_key = "../../../../etc/passwd"
        cache.put(evil_key, {"usd": "1.00"})
        # Anything written must live inside cache_dir.
        written = list(cache_dir.iterdir())
        assert written, "put() silently dropped the write"
        for p in written:
            assert cache_dir.resolve() in p.resolve().parents or p.parent.resolve() == cache_dir.resolve()


# ----------------------------------------------------------------------
# 3. TTL / staleness — a year-old poisoned cache shouldn't be served forever
# ----------------------------------------------------------------------

class TestStaleness:
    def test_year_old_cache_entry_is_refused_or_documented(self, tmp_path: Path) -> None:
        """Currently PriceCache has NO TTL. Document the gap by asserting
        on the documented contract: a 1-year-old file is still served.

        This test is intentionally a RED test for the missing TTL feature.
        If we add a TTL it should be enforced here.
        """
        cache = PriceCache(tmp_path)
        cache.put("eth:2025-05-22", {"usd": "1.00"})
        path = cache._path_for("eth:2025-05-22")
        # Backdate the file ~400 days.
        old = (path.stat().st_mtime - 400 * 86400)
        os.utime(path, (old, old))
        result = cache.get("eth:2025-05-22")
        # If TTL is implemented, it should refuse stale data.
        # Until then, document the behaviour — this is the gap.
        # We assert the safer behaviour: stale must NOT be served as fresh.
        assert result is None, (
            "stale cache entry (400 days old) was served without TTL check; "
            "poisoned ancient files persist indefinitely"
        )


# ----------------------------------------------------------------------
# 4. JSON parse safety — corrupted file must fail closed, not crash
# ----------------------------------------------------------------------

class TestCorruptedFileFailsClosed:
    def test_garbage_bytes_returns_none_not_crash(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        path = cache._path_for("k")
        path.write_bytes(b"\x00\x01\xff\xfe not json at all {{{")
        # Must NOT raise — must just return None.
        assert cache.get("k") is None

    def test_truncated_json_returns_none(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        path = cache._path_for("k")
        path.write_text('{"usd": "1.2')  # truncated
        assert cache.get("k") is None


# ----------------------------------------------------------------------
# 5. Filesystem error leakage — operator should not see raw paths/tracebacks
# ----------------------------------------------------------------------

class TestFilesystemErrorHandling:
    def test_read_oserror_returns_none_not_raise(
        self, tmp_path: Path,
    ) -> None:
        """Pre-fix: a file-open error (PermissionError, IsADirectoryError,
        DiskFullError, etc.) propagated out of PriceCache.get and crashed
        the caller. Source must swallow OSError → return None.

        We trigger the OSError WITHOUT monkey-patching Path.open globally
        (which proved test-order-dependent in the full suite when another
        test holds a Path.open mock that mistakenly survives teardown).
        Instead we create the cache "file" as a directory, so `path.open()`
        raises IsADirectoryError (a real OSError subclass) — exercising
        the exact except clause that defends the read path."""
        cache = PriceCache(tmp_path)
        path = cache._path_for("k")
        # Make the cache "file" a directory — open() raises IsADirectoryError.
        path.mkdir(parents=True, exist_ok=True)
        # Should swallow OSError, not propagate.
        assert cache.get("k") is None

    def test_put_oserror_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cache = PriceCache(tmp_path)
        real_open = pathlib.Path.open

        def _deny(self: pathlib.Path, *args: object, **kw: object):
            # Only deny writes inside the cache dir — leave everything
            # else (loggers, tempfile metadata reads) alone so test
            # teardown doesn't trip.
            try:
                self.relative_to(tmp_path)
            except ValueError:
                return real_open(self, *args, **kw)
            raise OSError("disk full")

        monkeypatch.setattr(pathlib.Path, "open", _deny)
        cache.put("k", {"usd": "1.0"})  # must not raise


# ----------------------------------------------------------------------
# 6. Negative price defense — already in code; regression guard
# ----------------------------------------------------------------------

class TestNegativePriceRejected:
    def test_negative_usd_not_served(self, tmp_path: Path) -> None:
        cache = PriceCache(tmp_path)
        path = cache._path_for("k")
        path.write_text(json.dumps({"usd": "-1.5"}))
        assert cache.get("k") is None
