"""Unit tests for the SupabaseCaseStore.delete_under() primitive.

Added with the building_package brief-cleanup change. The
``delete_under`` method removes every file under a given subpath
of the investigation's bucket prefix — used to wipe ``briefs/``
before each re-run so artifacts don't accumulate across resumes.

Tests cover:

  * The subpath argument is required (callers should use
    ``delete_all`` for the whole investigation, not ``delete_under("")``).
  * The full prefix passed to the underlying delete is correctly
    formed (storage_prefix + subpath + trailing slash).
  * Subpaths with/without leading/trailing slashes both normalize.

Network-touching paths (the actual DELETE batch) are exercised
end-to-end against the live bucket — see the manual smoke in
the building_package commit message.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from recupero.storage.supabase_case_store import SupabaseCaseStore


def _make_stub_store(investigation_id: str = "test-inv") -> SupabaseCaseStore:
    """Build a SupabaseCaseStore without actually opening any
    network connections — we stub out the httpx client + bypass
    the constructor's strict checks.

    The storage_prefix is computed from _investigation_id as
    ``investigations/<id>/``, matching the production layout."""
    store = SupabaseCaseStore.__new__(SupabaseCaseStore)
    store._storage_root = "https://test.supabase.co/storage/v1"
    store._bucket = "investigation-files"
    store._investigation_id = investigation_id
    store._pretty = False
    store._client = MagicMock()
    return store


def test_delete_under_requires_nonempty_subpath() -> None:
    """Empty subpath would wipe the entire investigation — callers
    must use ``delete_all`` for that explicitly."""
    store = _make_stub_store()
    with pytest.raises(ValueError, match="non-empty subpath"):
        store.delete_under("")


def test_delete_under_strips_slashes() -> None:
    """Subpath with leading/trailing slashes normalizes to the
    canonical form ``prefix + subpath + /``."""
    store = _make_stub_store("abc")
    captured: dict = {}

    def fake_delete_under_prefix(prefix: str) -> int:
        captured["prefix"] = prefix
        return 0

    store._delete_under_prefix = fake_delete_under_prefix  # type: ignore[method-assign]

    # All three variants should normalize identically.
    for variant in ("briefs", "/briefs", "briefs/", "/briefs/"):
        store.delete_under(variant)
        assert captured["prefix"] == "investigations/abc/briefs/", (
            f"variant {variant!r} normalized incorrectly: {captured['prefix']!r}"
        )


def test_delete_under_returns_count_from_inner_impl() -> None:
    """delete_under is a thin wrapper — the actual delete count
    comes from _delete_under_prefix."""
    store = _make_stub_store()
    store._delete_under_prefix = MagicMock(return_value=42)  # type: ignore[method-assign]
    assert store.delete_under("briefs") == 42


def test_delete_all_uses_storage_prefix() -> None:
    """delete_all delegates to _delete_under_prefix with the full
    storage_prefix (no subpath). Regression guard against an
    earlier version of the patch that hard-coded the prefix logic
    in two places."""
    store = _make_stub_store("xyz")
    captured: dict = {}

    def fake_delete_under_prefix(prefix: str) -> int:
        captured["prefix"] = prefix
        return 0

    store._delete_under_prefix = fake_delete_under_prefix  # type: ignore[method-assign]
    store.delete_all()
    assert captured["prefix"] == "investigations/xyz/"


def test_delete_under_does_not_touch_root_files() -> None:
    """The cleanup is scoped to the subpath. Root-level case.json,
    manifest.json etc. should NOT be deleted by delete_under('briefs').
    This is enforced by the prefix construction ('briefs/' has a
    trailing slash, so 'case.json' at the root never matches)."""
    store = _make_stub_store("abc")
    captured: dict = {}

    def fake_delete_under_prefix(prefix: str) -> int:
        captured["prefix"] = prefix
        return 0

    store._delete_under_prefix = fake_delete_under_prefix  # type: ignore[method-assign]
    store.delete_under("briefs")
    # Prefix ends with /briefs/ — files at investigations/abc/case.json
    # do NOT match this prefix.
    assert captured["prefix"].endswith("/briefs/")
    assert not captured["prefix"].endswith("/case.json")
