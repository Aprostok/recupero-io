"""Unit tests for the bespoke /v2 fund-flow graph endpoint (platform/router.py).

Two layers, no live DB / store:
* ``_build_graph_payload`` store dispatch (supabase vs local) with the case load
  + engine ``build_graph_data`` monkeypatched — locks that it reuses the engine's
  real graph producer and keys the two stores correctly;
* the ``trace_graph`` handler decision logic (org-scope 404, build-error mapping)
  by calling the handler directly (FastAPI ``Depends`` is bypassed on a direct
  call) with ``store.get_trace_status`` + ``_build_graph_payload`` monkeypatched.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import router, store

_PAYLOAD = {"nodes": [{"id": "0xabc"}], "edges": [], "meta": {"node_count": 1}}


def _principal() -> store.OrgContext:
    return store.OrgContext(org_id="org1", plan="pro", user_id="u1", role="owner")


# --------------------------------------------------------------------------- #
# _build_graph_payload — store dispatch
# --------------------------------------------------------------------------- #

def test_build_graph_payload_supabase_path(monkeypatch) -> None:
    import recupero.api._supabase_case_source as scs
    import recupero.reports.graph_ui as gui

    sentinel_case = object()
    monkeypatch.setattr(scs, "enabled", lambda: True)
    seen = {}

    def _read_case(case_id):
        seen["case_id"] = case_id
        return sentinel_case

    monkeypatch.setattr(scs, "read_case", _read_case)
    monkeypatch.setattr(gui, "build_graph_data", lambda case: _PAYLOAD if case is sentinel_case else None)

    out = router._build_graph_payload("inv-uuid-123", "CASE-ignored")
    assert out == _PAYLOAD
    # supabase keys the case by the investigation id, NOT the case_id.
    assert seen["case_id"] == "inv-uuid-123"


def test_build_graph_payload_local_path(monkeypatch) -> None:
    import recupero.api._supabase_case_source as scs
    import recupero.config as config
    import recupero.reports.graph_ui as gui
    import recupero.storage.case_store as cs

    sentinel_case = object()
    monkeypatch.setattr(scs, "enabled", lambda: False)
    monkeypatch.setattr(config, "load_config", lambda: (object(), object()))
    seen = {}

    class _FakeCaseStore:
        def __init__(self, cfg):
            pass

        def read_case(self, case_id):
            seen["case_id"] = case_id
            return sentinel_case

    monkeypatch.setattr(cs, "CaseStore", _FakeCaseStore)
    monkeypatch.setattr(gui, "build_graph_data", lambda case: _PAYLOAD if case is sentinel_case else None)

    out = router._build_graph_payload("inv-uuid-123", "CASE-777")
    assert out == _PAYLOAD
    # local store keys the case by the submitted case_id.
    assert seen["case_id"] == "CASE-777"


# --------------------------------------------------------------------------- #
# trace_graph handler — decision logic
# --------------------------------------------------------------------------- #

def test_trace_graph_returns_payload(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "CASE-1", "status": "complete"})
    monkeypatch.setattr(router, "_build_graph_payload", lambda inv, cid: _PAYLOAD)
    out = router.trace_graph("inv1", principal=_principal(), conn=object())
    assert out == _PAYLOAD


def test_trace_graph_404_when_trace_not_in_org(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: None)
    with pytest.raises(HTTPException) as ei:
        router.trace_graph("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_trace_graph_404_when_case_not_ready(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "CASE-1"})

    def _boom(inv, cid):
        raise OSError("case.json not found yet")

    monkeypatch.setattr(router, "_build_graph_payload", _boom)
    with pytest.raises(HTTPException) as ei:
        router.trace_graph("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_trace_graph_503_on_build_blowup(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_trace_status", lambda conn, org_id, investigation_id: {"case_id": "CASE-1"})

    def _boom(inv, cid):
        raise RuntimeError("aggregation exploded")

    monkeypatch.setattr(router, "_build_graph_payload", _boom)
    with pytest.raises(HTTPException) as ei:
        router.trace_graph("inv1", principal=_principal(), conn=object())
    assert ei.value.status_code == 503
