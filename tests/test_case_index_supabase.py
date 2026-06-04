"""Supabase-backed Case-Index console source (v0.36).

When RECUPERO_CASE_STORE=supabase (+ creds), the operator console lists and
browses real investigations from the Supabase Storage bucket instead of the
empty, ephemeral local store. These tests pin:

  * the SupabaseCaseStore browse primitives (artifact walk + sizes, top-level
    names, read_artifact + its traversal guard) via the stub-store pattern;
  * list_investigation_ids returns only folder UUIDs;
  * the env gate (off by default; needs the flag AND both creds);
  * the case_index_api routes delegate to the Supabase source when enabled,
    and the local path is untouched when it's not.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from recupero.api import _supabase_case_source as sbsrc
from recupero.storage.supabase_case_store import SupabaseCaseStore

_INV = "11111111-1111-1111-1111-111111111111"


def _stub_store(investigation_id: str = _INV) -> SupabaseCaseStore:
    store = SupabaseCaseStore.__new__(SupabaseCaseStore)
    store._storage_root = "https://t.supabase.co/storage/v1"
    store._bucket = "investigation-files"
    store._investigation_id = investigation_id
    store._pretty = False
    store._client = MagicMock()
    return store


# ----- store browse primitives ----- #

def test_list_artifacts_walks_with_sizes_and_relpaths(monkeypatch) -> None:
    store = _stub_store()
    pfx = store.storage_prefix

    def fake_list(prefix: str, limit: int = 1000):
        if prefix == pfx:
            return [
                {"name": "case.json", "id": "a", "metadata": {"size": 10}},
                {"name": "briefs", "id": None},  # folder
            ]
        if prefix == pfx + "briefs/":
            return [
                {"name": "le_handoff.html", "id": "b", "metadata": {"size": 200}},
            ]
        return []

    monkeypatch.setattr(store, "_list", fake_list)
    arts = dict(store.list_artifacts())
    # relpaths are prefix-relative; sizes come from metadata.size
    assert arts == {"case.json": 10, "briefs/le_handoff.html": 200}


def test_list_top_level_names_includes_folders(monkeypatch) -> None:
    store = _stub_store()
    monkeypatch.setattr(store, "_list", lambda prefix, limit=1000: [
        {"name": "case.json", "id": "a"},
        {"name": "freeze_brief.json", "id": "b"},
        {"name": "exhibit_pack", "id": None},
    ])
    names = set(store.list_top_level_names())
    assert names == {"case.json", "freeze_brief.json", "exhibit_pack"}


def test_read_artifact_rejects_traversal() -> None:
    store = _stub_store()
    for bad in ("../secrets", "a//b", "/abs", "x\x00y"):
        with pytest.raises(ValueError):
            store.read_artifact(bad)


def test_read_artifact_downloads_relative(monkeypatch) -> None:
    store = _stub_store()
    captured = {}

    def fake_dl(path: str) -> bytes:
        captured["path"] = path
        return b"<html>hi</html>"

    monkeypatch.setattr(store, "_download", fake_dl)
    out = store.read_artifact("briefs/le_handoff.html")
    assert out == b"<html>hi</html>"
    assert captured["path"] == store.storage_prefix + "briefs/le_handoff.html"


def test_list_investigation_ids_returns_folder_uuids(monkeypatch) -> None:
    from recupero.storage import supabase_case_store as mod

    captured = {}

    def fake_init(self, *a, **k):
        self._client = MagicMock()

    monkeypatch.setattr(SupabaseCaseStore, "__init__", fake_init)

    def fake_list(self, prefix, limit=1000):
        captured["prefix"] = prefix
        return [
            {"name": _INV, "id": None},               # folder = investigation
            {"name": "22222222-2222-2222-2222-222222222222/", "id": None},
            {"name": ".keep", "id": "file"},          # a file, not a folder
        ]

    monkeypatch.setattr(SupabaseCaseStore, "_list", fake_list)
    monkeypatch.setattr(SupabaseCaseStore, "close", lambda self: None)
    ids = mod.list_investigation_ids(MagicMock(), "https://u", "k")
    assert ids == [_INV, "22222222-2222-2222-2222-222222222222"]
    assert captured["prefix"] == "investigations/"


# ----- env gate ----- #

def test_enabled_off_by_default(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_CASE_STORE", raising=False)
    assert sbsrc.enabled() is False


def test_enabled_requires_flag_and_creds(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_CASE_STORE", "supabase")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    assert sbsrc.enabled() is False  # flag set but no creds
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "k")
    assert sbsrc.enabled() is True
    monkeypatch.setenv("RECUPERO_CASE_STORE", "local")
    assert sbsrc.enabled() is False  # explicit local wins


# ----- api delegation ----- #

def test_get_cases_uses_supabase_when_enabled(monkeypatch) -> None:
    from recupero.api import case_index_api as api

    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setattr(sbsrc, "enabled", lambda: True)
    monkeypatch.setattr(sbsrc, "list_cases", lambda: [
        {"case_id": _INV, "has_brief": True, "has_ai_triage": False,
         "has_exhibit_pack": True, "has_graph": False},
    ])
    out = api.get_cases(x_recupero_admin_key="secret")
    assert out["count"] == 1
    assert out["cases"][0]["case_id"] == _INV


def test_get_case_artifact_supabase_traversal_still_400(monkeypatch) -> None:
    from fastapi import HTTPException

    from recupero.api import case_index_api as api

    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setattr(sbsrc, "enabled", lambda: True)
    # Even with supabase enabled, a traversal path is rejected before any read.
    with pytest.raises(HTTPException) as ei:
        api.get_case_artifact(
            case_id=_INV, path="../../etc/passwd", x_recupero_admin_key="secret",
        )
    assert ei.value.status_code == 400


def test_get_case_artifact_supabase_serves_bytes(monkeypatch) -> None:
    from recupero.api import case_index_api as api

    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setattr(sbsrc, "enabled", lambda: True)
    monkeypatch.setattr(sbsrc, "read_artifact",
                        lambda case_id, rel: b"<html>brief</html>")
    resp = api.get_case_artifact(
        case_id=_INV, path="briefs/le_handoff_demo.html",
        x_recupero_admin_key="secret",
    )
    assert resp.status_code == 200
    assert b"brief" in resp.body
    assert resp.media_type == "text/html; charset=utf-8"
