"""Tests for the /v2 live-trace-status Server-Sent Events endpoint.

Exercises the async handler + its generator directly (no ASGI server): JWT
query-param auth, status streaming until terminal, and the not-found path. The
per-tick DB read is monkeypatched so no DB or real sleep is involved.
"""

from __future__ import annotations

import pytest

from recupero.platform import deps, router, tenancy


@pytest.mark.asyncio
async def test_sse_rejects_bad_token(monkeypatch) -> None:
    monkeypatch.setattr(deps, "_jwt_secret", lambda: "secret")

    def _boom(token, *, secret, now=None):
        raise tenancy.TokenError("bad")

    monkeypatch.setattr(tenancy, "verify_jwt", _boom)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        await router.stream_trace_status("inv1", token="nope")
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_sse_streams_until_terminal(monkeypatch) -> None:
    monkeypatch.setattr(deps, "_jwt_secret", lambda: "secret")
    monkeypatch.setattr(tenancy, "verify_jwt", lambda token, *, secret, now=None: {"org": "org1"})
    monkeypatch.setattr(router, "_SSE_INTERVAL_SEC", 0)  # no real waiting
    seq = iter([{"status": "running"}, {"status": "running"}, {"status": "complete"}])
    monkeypatch.setattr(router, "_poll_trace_status", lambda org, inv: next(seq))

    resp = await router.stream_trace_status("inv1", token="t")
    assert resp.media_type == "text/event-stream"
    body = "".join([chunk async for chunk in resp.body_iterator])
    # status emitted on CHANGE only: one "running", one "complete", then stops.
    assert body.count("running") == 1
    assert "complete" in body
    assert '"investigation_id": "inv1"' in body


@pytest.mark.asyncio
async def test_sse_not_found_emits_error_event(monkeypatch) -> None:
    monkeypatch.setattr(deps, "_jwt_secret", lambda: "secret")
    monkeypatch.setattr(tenancy, "verify_jwt", lambda token, *, secret, now=None: {"org": "org1"})
    monkeypatch.setattr(router, "_poll_trace_status", lambda org, inv: None)

    resp = await router.stream_trace_status("missing", token="t")
    body = "".join([chunk async for chunk in resp.body_iterator])
    assert "event: error" in body and "trace not found" in body
