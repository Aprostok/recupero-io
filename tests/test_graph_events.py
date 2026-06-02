"""Tests for real-time graph events (Phase 4.13).

The in-process pub/sub, payload shaping, SSE frame format, and the
cross-process pg_notify publisher are unit-tested here. The SSE *endpoint*
streaming behaviour needs a running ASGI server + Postgres to exercise
end-to-end; we test its admin-gating via TestClient.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest

from recupero.reports import graph_events as ge

INV = "22222222-2222-2222-2222-222222222222"


def test_publish_reaches_subscribers_and_unsubscribe() -> None:
    q = ge.subscribe(INV)
    assert ge.subscriber_count(INV) == 1
    n = ge.publish(INV, {"type": "delta", "reason": "test", "nodes": [], "edges": []})
    assert n == 1
    ev = q.get_nowait()
    assert ev["reason"] == "test"
    ge.unsubscribe(INV, q)
    assert ge.subscriber_count(INV) == 0
    # No subscribers → publish delivers to nobody, doesn't raise.
    assert ge.publish(INV, {"type": "delta"}) == 0


def test_publish_isolated_per_investigation() -> None:
    qa = ge.subscribe("inv-a")
    qb = ge.subscribe("inv-b")
    ge.publish("inv-a", {"type": "delta", "reason": "a"})
    assert qa.qsize() == 1 and qb.qsize() == 0
    ge.unsubscribe("inv-a", qa)
    ge.unsubscribe("inv-b", qb)


def test_build_delta_event_shape() -> None:
    ev = ge.build_delta_event(reason="expand", nodes=[{"id": "x"}], edges=[{"source": "a", "target": "b"}])
    assert ev == {"type": "delta", "reason": "expand", "nodes": [{"id": "x"}], "edges": [{"source": "a", "target": "b"}]}


def test_sse_frame_format() -> None:
    frame = ge.sse_frame({"type": "delta", "reason": "x"})
    assert frame.startswith("data: ") and frame.endswith("\n\n")
    assert '"reason":"x"' in frame


def test_notify_pg_issues_pg_notify() -> None:
    captured = {}

    class _Cur:
        def execute(self, sql, params): captured["sql"] = sql; captured["params"] = params
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class _Conn:
        def cursor(self): return _Cur()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    @contextmanager
    def _cm(dsn, **kw):
        yield _Conn()

    with patch("recupero._common.db_connect", _cm):
        ok = ge.notify_pg("dsn", INV, {"type": "delta", "reason": "watch"})
    assert ok is True
    assert "pg_notify" in captured["sql"]
    assert captured["params"][0] == ge.PG_CHANNEL
    assert INV in captured["params"][1]


def test_notify_pg_rejects_oversized_payload() -> None:
    big = {"type": "delta", "nodes": [{"id": "x" * 100} for _ in range(200)]}
    # No DB touched because the size guard trips first.
    assert ge.notify_pg("dsn", INV, big) is False


# ---- SSE endpoint admin-gating ---- #


@pytest.fixture(autouse=True)
def _admin(monkeypatch):
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "testkey123")


def _client():
    from fastapi.testclient import TestClient
    from recupero.api.app import app
    return TestClient(app)


def test_stream_requires_admin_key() -> None:
    # No key (header or query) → 401.
    r = _client().get(f"/v1/operator/graph/{INV}/stream")
    assert r.status_code == 401


def test_stream_rejects_bad_uuid() -> None:
    r = _client().get("/v1/operator/graph/not-a-uuid/stream?key=testkey123")
    assert r.status_code == 400
