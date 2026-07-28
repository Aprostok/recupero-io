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


def _revalidate_session(conn: Any, *, org_id: str, user_id: str) -> store.OrgContext:
    """Re-check a session JWT's membership + org status against the DB.

    A JWT is a bearer of claims minted at LOGIN. Trusting those claims alone means
    a removed or demoted member keeps full access until the token expires
    (``RECUPERO_PLATFORM_JWT_TTL_SEC``, default 1h) — and inside that window can
    mint an org API key that survives their removal indefinitely, so
    ``remove_member`` / ``set_member_role`` were only advisory.

    Re-reading the membership makes revocation immediate, and taking ``role`` +
    ``plan`` from the DB (not the claims) also removes the staleness where a
    Stripe upgrade left the rate limiter and entitlement gate on the old plan.

    Fails CLOSED: a DB error here yields 401 rather than silently trusting the
    token. Every authenticated endpoint already requires the DB, so this trades no
    real availability for a genuine security property.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT m.role, o.plan, o.status "
                "FROM public.memberships m "
                "JOIN public.organizations o ON o.id = m.org_id "
                "WHERE m.org_id = %s AND m.user_id = %s",
                (org_id, user_id),
            )
            row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001 — fail closed, never trust the claims
        raise HTTPException(
            status_code=401, detail="session could not be verified",
        ) from exc
    if row is None:
        # Membership gone (removed from the org, or the org was deleted).
        raise HTTPException(status_code=401, detail="session is no longer valid")
    role, plan, status = row[0], row[1], row[2]
    if status != "active":
        raise HTTPException(status_code=403, detail="organization inactive")
    return store.OrgContext(
        org_id=org_id,
        plan=str(plan or tenancy.DEFAULT_PLAN),
        user_id=user_id,
        role=str(role or "member"),
    )


def current_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    conn: Any = Depends(db_conn),
) -> store.OrgContext:
    """Authenticate a request → OrgContext. Bearer JWT first (web sessions),
    then an org API key. 401 if neither resolves. The resolved tenant is stashed
    on ``request.state`` for the structured request log."""
    # 1) Bearer session token
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            claims = tenancy.verify_jwt(token, secret=_jwt_secret())
        except tenancy.TokenError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
        return _stash_principal(
            request,
            _revalidate_session(
                conn,
                org_id=str(claims.get("org")),
                user_id=str(claims.get("sub")),
            ),
        )
    # 2) Org API key. Check the optional short-TTL cache first (positive-only,
    # fails open to the DB); only active resolutions are ever cached.
    if x_api_key and x_api_key.startswith(tenancy.API_KEY_PREFIX):
        key_hash = tenancy.hash_api_key(x_api_key)
        cached = keycache.get(key_hash)
        if cached is not None:
            return _stash_principal(request, store.OrgContext(
                org_id=str(cached["org_id"]), plan=str(cached.get("plan", tenancy.DEFAULT_PLAN)),
                user_id=None, role="service",
            ))
        ctx = store.resolve_api_key(conn, x_api_key)
        if ctx is not None:
            keycache.put(key_hash, {"org_id": ctx.org_id, "plan": ctx.plan})
            return _stash_principal(request, ctx)
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


def require_entitlement(*features: str):
    """Dependency factory gating an endpoint to orgs whose PLAN unlocks every one
    of ``features`` (see ``tenancy`` feature keys). This is the consumer product's
    server-side unlock gate — 402 Payment Required with an upsell message listing
    the missing feature(s) when the plan doesn't include them, so the web app can
    surface an "Upgrade to unlock" path. Uses the plan from the session principal
    (same source as ``rate_limit``), so it never adds a DB hit."""
    needed = tuple(features)

    def _dep(principal: store.OrgContext = Depends(current_principal)) -> store.OrgContext:
        have = tenancy.plan_features(principal.plan)
        missing = [f for f in needed if f not in have]
        if missing:
            raise HTTPException(
                status_code=402,
                detail=(
                    f"plan '{principal.plan}' does not include: {', '.join(missing)}. "
                    "Upgrade to unlock."
                ),
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


__all__ = ("db_conn", "current_principal", "require_role", "require_entitlement", "rate_limit")
