"""Unit tests for the structured /v2 request log (platform/reqlog.py) and the
auth dependency's request.state stash that feeds it.

No live server: the pure record builder + enable check are exercised directly,
and the deps stash is verified by calling current_principal with a fake request.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

from recupero.platform import deps, reqlog, tenancy


class _FakeRequest:
    """Only ``request.state`` is touched by current_principal."""

    def __init__(self) -> None:
        self.state = SimpleNamespace()


# ---- pure record builder ---- #

def test_build_log_record_shape_and_types() -> None:
    line = reqlog.build_log_record(
        method="POST", path="/v2/traces", status=202,
        duration_ms=12.3456, org_id="org1", plan="pro", role="service",
    )
    rec = json.loads(line)
    assert rec == {
        "event": "http_request",
        "method": "POST",
        "path": "/v2/traces",
        "status": 202,
        "duration_ms": 12.35,   # rounded to 2dp
        "org_id": "org1",
        "plan": "pro",
        "role": "service",
    }


def test_build_log_record_keys_sorted_and_compact() -> None:
    line = reqlog.build_log_record(
        method="GET", path="/v2/me", status=200,
        duration_ms=1.0, org_id="o", plan="free", role="member",
    )
    # sort_keys → deterministic order; no spaces after separators (compact).
    assert line.startswith('{"duration_ms"')
    assert ", " not in line and ": " not in line


def test_build_log_record_null_org_for_unauthenticated() -> None:
    rec = json.loads(reqlog.build_log_record(
        method="GET", path="/v2/me", status=401,
        duration_ms=0.5, org_id=None, plan=None, role=None,
    ))
    assert rec["org_id"] is None and rec["plan"] is None and rec["role"] is None
    assert rec["status"] == 401


def test_request_log_enabled_env(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_PLATFORM_REQUEST_LOG", raising=False)
    assert reqlog.request_log_enabled() is False
    monkeypatch.setenv("RECUPERO_PLATFORM_REQUEST_LOG", "1")
    assert reqlog.request_log_enabled() is True
    monkeypatch.setenv("RECUPERO_PLATFORM_REQUEST_LOG", "0")
    assert reqlog.request_log_enabled() is False


def test_emit_logs_at_info_on_named_logger(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="recupero.platform.request"):
        reqlog.emit('{"event":"http_request"}')
    assert any(
        r.name == "recupero.platform.request" and "http_request" in r.getMessage()
        for r in caplog.records
    )


# ---- deps stash: current_principal records the tenant on request.state ---- #

def test_current_principal_stashes_tenant_from_jwt(monkeypatch) -> None:
    secret = "reqlog-stash-secret"
    monkeypatch.setattr(deps, "_jwt_secret", lambda: secret)
    token = tenancy.mint_jwt(
        secret=secret, subject="u1", org_id="org42", role="admin",
        ttl_seconds=60, extra={"plan": "pro"},
    )
    req = _FakeRequest()
    ctx = deps.current_principal(
        request=req, authorization=f"Bearer {token}", x_api_key=None, conn=object(),
    )
    assert ctx.org_id == "org42"
    # the middleware reads exactly these off scope['state'] == request.state
    assert req.state.org_id == "org42"
    assert req.state.plan == "pro"
    assert req.state.role == "admin"


def test_stash_principal_is_best_effort_when_request_none() -> None:
    from recupero.platform import store
    ctx = store.OrgContext(org_id="o", plan="free", user_id=None, role="service")
    # request=None must not raise (telemetry never fails a request).
    assert deps._stash_principal(None, ctx) is ctx
