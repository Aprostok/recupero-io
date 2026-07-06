"""FastAPI dependencies for the multi-tenant SaaS layer.

Resolves the request principal from EITHER a Bearer session JWT (the customer web
app) OR an ``rk_live_`` org API key (programmatic clients), yielding an
``OrgContext``. Also provides a per-request psycopg connection and a lightweight
per-org token-bucket rate limiter (a correct in-process default; swap for a
Redis/edge limiter when you run >1 API replica — see PLATFORM_ARCHITECTURE.md).
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from typing import Any

from fastapi import Depends, Header, HTTPException, status

from recupero.platform import store, tenancy


def _jwt_secret() -> str:
    secret = os.environ.get("RECUPERO_PLATFORM_JWT_SECRET", "")
    if not secret:
        # Fail closed: never mint/verify against an empty secret in prod.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="platform auth not configured (RECUPERO_PLATFORM_JWT_SECRET unset)",
        )
    return secret


def _dsn() -> str:
    dsn = os.environ.get("RECUPERO_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database not configured",
        )
    return dsn


def db_conn() -> Iterator[Any]:
    """Yield a per-request psycopg connection (autocommit off; commit on clean
    exit, rollback on error). In prod this rides the Supabase transaction pooler
    / pgbouncer; a process-wide psycopg_pool is the drop-in upgrade."""
    import psycopg  # lazy — keeps the package import-light for unit tests

    conn = psycopg.connect(_dsn())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def current_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    conn: Any = Depends(db_conn),
) -> store.OrgContext:
    """Authenticate a request → OrgContext. Bearer JWT first (web sessions),
    then an org API key. 401 if neither resolves."""
    # 1) Bearer session token
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            claims = tenancy.verify_jwt(token, secret=_jwt_secret())
        except tenancy.TokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
        return store.OrgContext(
            org_id=str(claims.get("org")),
            plan=str(claims.get("plan", tenancy.DEFAULT_PLAN)),
            user_id=str(claims.get("sub")),
            role=str(claims.get("role", "member")),
        )
    # 2) Org API key
    if x_api_key and x_api_key.startswith(tenancy.API_KEY_PREFIX):
        ctx = store.resolve_api_key(conn, x_api_key)
        if ctx is not None:
            return ctx
        raise HTTPException(status_code=401, detail="invalid API key")
    raise HTTPException(
        status_code=401,
        detail="authentication required (Bearer token or X-API-Key)",
    )


def require_role(*roles: str):
    """Dependency factory gating an endpoint to specific membership roles."""
    allowed = set(roles)

    def _dep(principal: store.OrgContext = Depends(current_principal)) -> store.OrgContext:
        if principal.role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"role '{principal.role}' not permitted (need one of {sorted(allowed)})",
            )
        return principal

    return _dep


# --------------------------------------------------------------------------- #
# Per-org rate limiter (in-process token bucket — correct for a single replica)
# --------------------------------------------------------------------------- #

_buckets: dict[str, tuple[float, float]] = {}   # org_id -> (tokens, last_refill)
_bucket_lock = threading.Lock()


def _allow(org_id: str, rate_per_min: int, *, now: float | None = None) -> bool:
    if rate_per_min <= 0:
        return True
    now = time.monotonic() if now is None else now
    capacity = float(rate_per_min)
    refill_per_sec = rate_per_min / 60.0
    with _bucket_lock:
        tokens, last = _buckets.get(org_id, (capacity, now))
        tokens = min(capacity, tokens + (now - last) * refill_per_sec)
        if tokens < 1.0:
            _buckets[org_id] = (tokens, now)
            return False
        _buckets[org_id] = (tokens - 1.0, now)
        return True


def rate_limit(principal: store.OrgContext = Depends(current_principal)) -> store.OrgContext:
    """Enforce the org's plan rate limit. NOTE: in-process — for multiple API
    replicas move this to a shared Redis token bucket or the API gateway edge."""
    plan = tenancy.get_plan(principal.plan)
    if not _allow(principal.org_id, plan.rate_limit_per_min):
        raise HTTPException(
            status_code=429,
            detail=f"rate limit exceeded ({plan.rate_limit_per_min}/min for plan '{plan.name}')",
        )
    return principal


__all__ = ("db_conn", "current_principal", "require_role", "rate_limit")
