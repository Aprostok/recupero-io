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
from contextlib import contextmanager
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

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
    / pgbouncer; a process-wide psycopg_pool is the drop-in upgrade.

    This is the TENANT connection: ``current_principal`` sets ``app.current_org``
    on it after auth, so RLS scopes every subsequent query to the caller's org.
    In prod it should be a restricted (NOBYPASSRLS, non-owner) role."""
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


def _auth_dsn() -> str:
    """DSN for PRE-auth / cross-tenant lookups (signup, login, API-key resolution)
    and the worker. These intentionally cross the org boundary, so in prod this is
    the service role WITH BYPASSRLS. Defaults to the tenant DSN for dev/back-compat
    (single-role deployments where RLS is not FORCED)."""
    return os.environ.get("RECUPERO_AUTH_DATABASE_URL") or _dsn()


@contextmanager
def _auth_conn_cm() -> Iterator[Any]:
    """Short-lived BYPASSRLS connection for a single cross-tenant lookup."""
    import psycopg

    conn = psycopg.connect(_auth_dsn())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def auth_db_conn() -> Iterator[Any]:
    """Request-scoped auth connection for routes that run BEFORE a principal exists
    (signup / login) and therefore must read/write across the org boundary."""
    with _auth_conn_cm() as conn:
        yield conn


def _set_current_org(conn: Any, org_id: str) -> None:
    """Bind the tenant to this connection so RLS scopes every subsequent query.
    Transaction-local (``is_local=true``) so a pooled/pgbouncer backend can never
    leak the setting into the next tenant's request."""
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.current_org', %s, true)", (org_id,))


def _stash_principal(request: Request | None, ctx: store.OrgContext) -> store.OrgContext:
    """Record the resolved tenant on ``request.state`` (which is ``scope['state']``)
    so downstream ASGI middleware — the opt-in structured request log (see
    ``platform.reqlog``) — can key a log line by org without re-parsing the token.
    Best-effort: telemetry must never fail a request. Returns ``ctx`` so callers
    can ``return _stash_principal(request, ctx)`` in one line."""
    if request is not None:
        try:
            request.state.org_id = ctx.org_id
            request.state.plan = ctx.plan
            request.state.role = ctx.role
        except Exception:  # noqa: BLE001
            pass
    return ctx


def _resolve_principal(
    authorization: str | None, x_api_key: str | None,
) -> store.OrgContext:
    """Authenticate → OrgContext (no tenant-conn side effects). Bearer JWT first
    (web sessions), then an org API key. 401 if neither resolves."""
    # 1) Bearer session token — self-contained, no DB read.
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
    # 2) Org API key. Positive-only short-TTL cache first (fails open to the DB).
    if x_api_key and x_api_key.startswith(tenancy.API_KEY_PREFIX):
        key_hash = tenancy.hash_api_key(x_api_key)
        cached = keycache.get(key_hash)
        if cached is not None:
            return store.OrgContext(
                org_id=str(cached["org_id"]), plan=str(cached.get("plan", tenancy.DEFAULT_PLAN)),
                user_id=None, role="service",
            )
        # Resolving a key hash → org is a CROSS-TENANT lookup, so it must run on
        # the BYPASSRLS auth connection (the tenant conn isn't org-scoped yet and
        # RLS would hide the row).
        with _auth_conn_cm() as auth_conn:
            ctx = store.resolve_api_key(auth_conn, x_api_key)
        if ctx is not None:
            keycache.put(key_hash, {"org_id": ctx.org_id, "plan": ctx.plan})
            return ctx
        raise HTTPException(status_code=401, detail="invalid API key")
    raise HTTPException(
        status_code=401,
        detail="authentication required (Bearer token or X-API-Key)",
    )


def current_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    conn: Any = Depends(db_conn),
) -> store.OrgContext:
    """Authenticate a request → OrgContext, then bind ``app.current_org`` on the
    tenant connection so RLS scopes every query the route makes. The resolved
    tenant is stashed on ``request.state`` for the structured request log."""
    ctx = _resolve_principal(authorization, x_api_key)
    _set_current_org(conn, ctx.org_id)
    return _stash_principal(request, ctx)


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


__all__ = (
    "db_conn", "auth_db_conn", "current_principal", "require_role", "rate_limit",
)
