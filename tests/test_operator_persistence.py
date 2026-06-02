"""Tests for operator graph annotations + saved views (Phase 3.9) and the
expansion result cache.

The DB layer is exercised through a fake ``db_connect`` (capturing SQL +
returning canned rows); the endpoints are tested with the store mocked.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest

from recupero.reports import graph_expand, operator_store

INV = "11111111-1111-1111-1111-111111111111"
NODE = "0x" + "a" * 40


class _FakeCursor:
    def __init__(self, rows): self._rows = rows; self.calls = []
    def execute(self, sql, params=None): self.calls.append((sql, params))
    def fetchall(self): return self._rows
    def fetchone(self): return self._rows[0] if self._rows else None
    def __enter__(self): return self
    def __exit__(self, *a): return False


class _FakeConn:
    def __init__(self, cur): self._cur = cur
    def cursor(self): return self._cur
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _fake_db(rows):
    cur = _FakeCursor(rows)
    @contextmanager
    def _cm(dsn, **kw):
        yield _FakeConn(cur)
    return _cm, cur


# ---- store ---- #


def test_get_annotations_maps_rows() -> None:
    cm, _ = _fake_db([(NODE, "watch this one"), ("0x" + "b" * 40, "peeling")])
    with patch("recupero.reports.operator_store.db_connect", cm):
        out = operator_store.get_annotations("dsn", INV)
    assert out == {NODE: "watch this one", "0x" + "b" * 40: "peeling"}


def test_upsert_annotation_deletes_on_empty() -> None:
    cm, cur = _fake_db([])
    with patch("recupero.reports.operator_store.db_connect", cm):
        operator_store.upsert_annotation("dsn", INV, NODE, "   ")
    assert "DELETE" in cur.calls[-1][0]


def test_upsert_annotation_inserts_on_conflict() -> None:
    cm, cur = _fake_db([])
    with patch("recupero.reports.operator_store.db_connect", cm):
        operator_store.upsert_annotation("dsn", INV, NODE, "real note")
    sql = cur.calls[-1][0]
    assert "INSERT INTO public.operator_graph_annotations" in sql
    assert "ON CONFLICT" in sql


def test_save_and_load_snapshot() -> None:
    cm, cur = _fake_db([({"layout": "flow", "minUsd": 0},)])
    with patch("recupero.reports.operator_store.db_connect", cm):
        operator_store.save_snapshot("dsn", INV, "view A", {"layout": "flow"})
        state = operator_store.load_snapshot("dsn", INV, "view A")
    assert "INSERT INTO public.operator_graph_snapshots" in cur.calls[0][0]
    assert state == {"layout": "flow", "minUsd": 0}


# ---- endpoints ---- #


@pytest.fixture(autouse=True)
def _admin(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "testkey123")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://x")


def _client():
    from fastapi.testclient import TestClient
    from recupero.api.app import app
    return TestClient(app)


_H = {"X-Recupero-Admin-Key": "testkey123"}


def test_annotations_endpoints_require_auth() -> None:
    c = _client()
    assert c.get(f"/v1/operator/graph/{INV}/annotations").status_code == 401
    assert c.put(f"/v1/operator/graph/{INV}/annotations", json={"node_id": NODE, "note": "x"}).status_code == 401


def test_annotations_get_degrades_to_empty_on_db_error() -> None:
    with patch("recupero.reports.operator_store.get_annotations", side_effect=RuntimeError("no table")):
        r = _client().get(f"/v1/operator/graph/{INV}/annotations", headers=_H)
    assert r.status_code == 200 and r.json()["annotations"] == {}


def test_annotation_put_ok_and_write_failure_503() -> None:
    c = _client()
    with patch("recupero.reports.operator_store.upsert_annotation", return_value=None):
        assert c.put(f"/v1/operator/graph/{INV}/annotations", json={"node_id": NODE, "note": "hi"}, headers=_H).status_code == 200
    with patch("recupero.reports.operator_store.upsert_annotation", side_effect=RuntimeError("no table")):
        assert c.put(f"/v1/operator/graph/{INV}/annotations", json={"node_id": NODE, "note": "hi"}, headers=_H).status_code == 503


def test_snapshot_save_list_load_roundtrip() -> None:
    c = _client()
    with patch("recupero.reports.operator_store.save_snapshot", return_value=None):
        assert c.put(f"/v1/operator/graph/{INV}/snapshots", json={"name": "A", "state": {"layout": "radial"}}, headers=_H).status_code == 200
    with patch("recupero.reports.operator_store.list_snapshots", return_value=[{"name": "A", "created_at": "2026-06-01T00:00:00Z"}]):
        r = c.get(f"/v1/operator/graph/{INV}/snapshots", headers=_H)
    assert r.json()["snapshots"][0]["name"] == "A"
    with patch("recupero.reports.operator_store.load_snapshot", return_value={"layout": "radial"}):
        r = c.get(f"/v1/operator/graph/{INV}/snapshots/A", headers=_H)
    assert r.status_code == 200 and r.json()["state"] == {"layout": "radial"}


def test_snapshot_load_404_when_absent() -> None:
    with patch("recupero.reports.operator_store.load_snapshot", return_value=None):
        r = _client().get(f"/v1/operator/graph/{INV}/snapshots/missing", headers=_H)
    assert r.status_code == 404


def test_bad_investigation_id_400() -> None:
    assert _client().get("/v1/operator/graph/not-a-uuid/annotations", headers=_H).status_code == 400


# ---- expansion cache ---- #


def test_expansion_cache_primitive_ttl() -> None:
    graph_expand.clear_expansion_cache()
    key = ("ethereum", "0xabc", "out", 40)
    graph_expand._cache_put(key, {"nodes": []}, now=100.0)
    assert graph_expand._cache_get(key, now=150.0) == {"nodes": []}   # within TTL
    assert graph_expand._cache_get(key, now=999.0) is None            # expired


def test_expand_address_caches_constructed_adapter_path() -> None:
    graph_expand.clear_expansion_cache()
    calls = {"n": 0}

    class _Fake:
        def fetch_native_outflows(self, a, sb): return []
        def fetch_erc20_outflows(self, a, sb): return []
        def fetch_native_inflows(self, a, sb, **k): return []
        def fetch_erc20_inflows(self, a, sb, **k): return []
        def close(self): pass

    def _for_chain(chain, config):
        calls["n"] += 1
        return _Fake()

    from recupero.models import Chain
    clock = [1000.0]
    with patch("recupero.chains.base.ChainAdapter.for_chain", _for_chain), \
         patch("recupero.config.load_config", return_value=({}, {})):
        graph_expand.expand_address(chain=Chain.ethereum, address="0xABC", direction="out", _clock=lambda: clock[0])
        graph_expand.expand_address(chain=Chain.ethereum, address="0xabc", direction="out", _clock=lambda: clock[0])
    assert calls["n"] == 1   # second call served from cache, adapter built once
