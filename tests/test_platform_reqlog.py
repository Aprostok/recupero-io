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


class _MembershipCursor:
    """Returns one (role, plan, status) row — current_principal now RE-VALIDATES a
    session JWT against public.memberships so a removed/demoted member loses
    access immediately instead of at token expiry (and role/plan come from the DB,
    not stale claims)."""

    def __init__(self, row=("admin", "pro", "active")):
        self._row = row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        pass

    def fetchone(self):
        return self._row


class _MembershipConn:
    def __init__(self, row=("admin", "pro", "active")):
        self._cur = _MembershipCursor(row)

    def cursor(self):
        return self._cur


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
        request=req, authorization=f"Bearer {token}", x_api_key=None,
        conn=_MembershipConn(("admin", "pro", "active")),
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


# --------------------------------------------------------------------------- #
# Session revocation (security regression).
#
# A JWT is a bearer of claims minted at LOGIN. Trusting them alone meant a removed
# or demoted member kept full org access until the token expired (default 1h) —
# and inside that window could mint an org API key that outlived their removal, so
# remove_member / set_member_role were only advisory.
# --------------------------------------------------------------------------- #


def _bearer(monkeypatch, secret="revocation-secret", role="admin", plan="free"):
    monkeypatch.setattr(deps, "_jwt_secret", lambda: secret)
    return tenancy.mint_jwt(
        secret=secret, subject="u1", org_id="org1", role=role,
        ttl_seconds=60, extra={"plan": plan},
    )


def test_removed_member_is_rejected_immediately(monkeypatch) -> None:
    """Membership row gone → 401, even though the JWT is still cryptographically
    valid and unexpired."""
    import pytest
    from fastapi import HTTPException
    token = _bearer(monkeypatch)
    with pytest.raises(HTTPException) as ei:
        deps.current_principal(
            request=_FakeRequest(), authorization=f"Bearer {token}",
            x_api_key=None, conn=_MembershipConn(None),
        )
    assert ei.value.status_code == 401


def test_inactive_org_is_rejected(monkeypatch) -> None:
    import pytest
    from fastapi import HTTPException
    token = _bearer(monkeypatch)
    with pytest.raises(HTTPException) as ei:
        deps.current_principal(
            request=_FakeRequest(), authorization=f"Bearer {token}",
            x_api_key=None, conn=_MembershipConn(("admin", "pro", "suspended")),
        )
    assert ei.value.status_code == 403


def test_role_and_plan_come_from_db_not_stale_claims(monkeypatch) -> None:
    """A demotion (owner→viewer) and a Stripe upgrade (free→pro) both take effect
    on the NEXT request, not at token expiry."""
    token = _bearer(monkeypatch, role="owner", plan="free")
    ctx = deps.current_principal(
        request=_FakeRequest(), authorization=f"Bearer {token}",
        x_api_key=None, conn=_MembershipConn(("viewer", "pro", "active")),
    )
    assert ctx.role == "viewer"   # demoted since the token was minted
    assert ctx.plan == "pro"      # upgraded since the token was minted


def test_db_failure_fails_closed(monkeypatch) -> None:
    """A verification error must NOT silently fall back to trusting the claims."""
    import pytest
    from fastapi import HTTPException

    class _BrokenConn:
        def cursor(self):
            raise RuntimeError("db down")

    token = _bearer(monkeypatch)
    with pytest.raises(HTTPException) as ei:
        deps.current_principal(
            request=_FakeRequest(), authorization=f"Bearer {token}",
            x_api_key=None, conn=_BrokenConn(),
        )
    assert ei.value.status_code == 401
