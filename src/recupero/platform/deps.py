"""FastAPI dependencies for the multi-tenant SaaS layer.

Resolves the request principal from EITHER a Bearer session JWT (the customer web
app) OR an ``rk_live_`` org API key (programmatic clients), yielding an
``OrgContext``. Also provides a per-request psycopg connection and a lightweight
per-org token-bucket rate limiter (a correct in-process default; swap for a
Redis/edge limiter when you run >1 API replica — see PLATFORM_ARCHITECTURE.md).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

from fastapi import Depends, Header, HTTPException, status

from recupero.platform import keycache, store, tenancy
from recupero.platform.ratelimit import get_rate_limiter


def _jwt_secret() -> str:
    secret = os.environ.get("RECUPERO_PLATFORM_JWT_SECRET", "")
    if not secret:
        # Fail closed: never mint/verify against an empty secret in prod.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="platform auth not configured (RECUPERO_PLATFORM_JWT_SECRET unset)",
        )
    return secret


def _max_body_bytes() -> int:
    try:
        return max(1024, int(os.environ.get("RECUPERO_MAX_REQUEST_BYTES", "262144")))
    except (TypeError, ValueError):
        return 262144


def max_request_body(content_length: str | None = Header(default=None)) -> None:
    """Reject oversized request bodies (413) as a cheap first-line DoS guard,
    applied as a router-level dependency to every /v2 route. Uses the
    Content-Length header (a chunked request without one bypasses this — the ASGI
    server's own limits are the backstop). Cap: ``RECUPERO_MAX_REQUEST_BYTES``
    (default 256 KiB — generous for JSON + Stripe webhooks)."""
    if content_length:
        try:
            declared = int(content_length)
        except (TypeError, ValueError):
            return
        limit = _max_body_bytes()
        if declared > limit:
            raise HTTPException(
                status_code=413,
                detail=f"request body too large (max {limit} bytes)",
            )


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
    # 2) Org API key. Check the optional short-TTL cache first (positive-only,
    # fails open to the DB); only active resolutions are ever cached.
    if x_api_key and x_api_key.startswith(tenancy.API_KEY_PREFIX):
        key_hash = tenancy.hash_api_key(x_api_key)
        cached = keycache.get(key_hash)
        if cached is not None:
            return store.OrgContext(
                org_id=str(cached["org_id"]), plan=str(cached.get("plan", tenancy.DEFAULT_PLAN)),
                user_id=None, role="service",
            )
        ctx = store.resolve_api_key(conn, x_api_key)
        if ctx is not None:
            keycache.put(key_hash, {"org_id": ctx.org_id, "plan": ctx.plan})
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
# Per-org rate limiter
# --------------------------------------------------------------------------- #


def rate_limit(principal: store.OrgContext = Depends(current_principal)) -> store.OrgContext:
    """Enforce the org's plan rate limit via the process-wide limiter (in-process
    token bucket by default; a shared Redis bucket when ``RECUPERO_REDIS_URL`` is
    set, so the limit holds across multiple API replicas — see
    ``platform.ratelimit``)."""
    plan = tenancy.get_plan(principal.plan)
    if not get_rate_limiter().allow(principal.org_id, plan.rate_limit_per_min):
        raise HTTPException(
            status_code=429,
            detail=f"rate limit exceeded ({plan.rate_limit_per_min}/min for plan '{plan.name}')",
        )
    return principal


__all__ = ("db_conn", "current_principal", "require_role", "rate_limit")
