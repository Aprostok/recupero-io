"""Tenant data-access layer (psycopg, connection-injected).

Every function takes an open psycopg connection so the caller owns pooling +
transaction scope (matches the worker's pattern) and the module stays free of
global state — easy to test against a throwaway DB and safe under many workers.
All queries are parameterized (no string interpolation of user input) and every
tenant read is explicitly scoped by ``org_id``.

This module is imported lazily by the router so the package carries no hard
psycopg import at collection time (keeps the pure ``tenancy`` unit tests, and
the rest of the suite, dependency-light).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from recupero.platform import tenancy


@dataclass(frozen=True)
class OrgContext:
    """The authenticated tenant principal threaded through a request."""
    org_id: str
    plan: str
    user_id: str | None      # None for API-key (machine) principals
    role: str                # owner | admin | member | viewer | service


# --------------------------------------------------------------------------- #
# Users + orgs + membership
# --------------------------------------------------------------------------- #


def create_user(conn: Any, *, email: str, password: str, name: str | None) -> str:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.users (email, password_hash, name) "
            "VALUES (%s, %s, %s) RETURNING id::text",
            (email.strip().lower(), tenancy.hash_password(password), name),
        )
        return cur.fetchone()[0]


def get_user_by_email(conn: Any, email: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, email, password_hash, name FROM public.users "
            "WHERE email = %s",
            (email.strip().lower(),),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {"id": row[0], "email": row[1], "password_hash": row[2], "name": row[3]}


def create_organization(
    conn: Any, *, name: str, slug: str, owner_user_id: str, plan: str = "free",
) -> str:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.organizations (name, slug, plan) "
            "VALUES (%s, %s, %s) RETURNING id::text",
            (name, slug, plan),
        )
        org_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO public.memberships (org_id, user_id, role) "
            "VALUES (%s, %s, 'owner')",
            (org_id, owner_user_id),
        )
    return org_id


def get_org(conn: Any, org_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, name, slug, plan, status, trace_used_period, period_start "
            "FROM public.organizations WHERE id = %s",
            (org_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0], "name": row[1], "slug": row[2], "plan": row[3],
        "status": row[4], "trace_used_period": row[5], "period_start": row[6],
    }


def get_membership(conn: Any, *, org_id: str, user_id: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT role FROM public.memberships WHERE org_id = %s AND user_id = %s",
            (org_id, user_id),
        )
        row = cur.fetchone()
    return {"role": row[0]} if row else None


def count_seats(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.memberships WHERE org_id = %s", (org_id,))
        return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #


def create_api_key(
    conn: Any, *, org_id: str, name: str, created_by: str | None,
) -> tenancy.NewApiKey:
    key = tenancy.generate_api_key()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.org_api_keys (org_id, name, key_hash, last4, created_by) "
            "VALUES (%s, %s, %s, %s, %s)",
            (org_id, name, key.key_hash, key.last4, created_by),
        )
    return key


def resolve_api_key(conn: Any, plaintext: str) -> OrgContext | None:
    """Authenticate a plaintext API key → OrgContext, or None. Constant-time via
    a hash lookup; also records last_used_at."""
    key_hash = tenancy.hash_api_key(plaintext)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT k.org_id::text, o.plan, o.status "
            "FROM public.org_api_keys k JOIN public.organizations o ON o.id = k.org_id "
            "WHERE k.key_hash = %s AND k.revoked_at IS NULL",
            (key_hash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            "UPDATE public.org_api_keys SET last_used_at = now() WHERE key_hash = %s",
            (key_hash,),
        )
    org_id, plan, status = row
    if status != "active":
        return None
    return OrgContext(org_id=org_id, plan=plan, user_id=None, role="service")


def list_api_keys(conn: Any, org_id: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, name, last4, created_at, last_used_at, revoked_at "
            "FROM public.org_api_keys WHERE org_id = %s ORDER BY created_at DESC",
            (org_id,),
        )
        rows = cur.fetchall()
    return [
        {"id": r[0], "name": r[1], "last4": r[2], "created_at": r[3],
         "last_used_at": r[4], "revoked": r[5] is not None}
        for r in rows
    ]


def revoke_api_key(conn: Any, *, org_id: str, key_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.org_api_keys SET revoked_at = now() "
            "WHERE id = %s AND org_id = %s AND revoked_at IS NULL",
            (key_id, org_id),
        )
        return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Quota + usage
# --------------------------------------------------------------------------- #


def traces_used_this_period(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT coalesce(sum(quantity), 0) FROM public.usage_events "
            "WHERE org_id = %s AND kind = 'trace_submitted' "
            "AND created_at >= (SELECT period_start FROM public.organizations WHERE id = %s)",
            (org_id, org_id),
        )
        return int(cur.fetchone()[0])


def record_usage(
    conn: Any, *, org_id: str, kind: str, quantity: int = 1,
    investigation_id: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.usage_events (org_id, kind, quantity, investigation_id) "
            "VALUES (%s, %s, %s, %s)",
            (org_id, kind, quantity, investigation_id),
        )


# --------------------------------------------------------------------------- #
# Tenant-scoped job queue (reuses the existing `investigations` queue)
# --------------------------------------------------------------------------- #


def enqueue_trace(
    conn: Any, *, org_id: str, submitted_by: str | None,
    chain: str, seed_address: str, incident_time: str, case_id: str,
) -> str:
    """Insert a tenant-scoped job into the existing worker queue and meter it,
    atomically. Returns the new investigation id. The worker (multi-process,
    FOR UPDATE SKIP LOCKED) picks it up; nothing here runs the trace inline."""
    investigation_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.investigations "
            "(id, org_id, submitted_by, chain, seed_address, incident_time, case_id, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued')",
            (investigation_id, org_id, submitted_by, chain, seed_address,
             incident_time, case_id),
        )
        cur.execute(
            "INSERT INTO public.usage_events (org_id, kind, quantity, investigation_id) "
            "VALUES (%s, 'trace_submitted', 1, %s)",
            (org_id, investigation_id),
        )
    return investigation_id


def get_trace_status(conn: Any, *, org_id: str, investigation_id: str) -> dict[str, Any] | None:
    """Tenant-scoped status read — an org can ONLY see its own jobs."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, status, case_id, chain, seed_address, created_at, updated_at "
            "FROM public.investigations WHERE id = %s AND org_id = %s",
            (investigation_id, org_id),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "investigation_id": row[0], "status": row[1], "case_id": row[2],
        "chain": row[3], "seed_address": row[4],
        "created_at": row[5], "updated_at": row[6],
    }


def list_traces(conn: Any, *, org_id: str, limit: int = 50) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, status, case_id, chain, created_at "
            "FROM public.investigations WHERE org_id = %s "
            "ORDER BY created_at DESC LIMIT %s",
            (org_id, max(1, min(limit, 200))),
        )
        rows = cur.fetchall()
    return [
        {"investigation_id": r[0], "status": r[1], "case_id": r[2],
         "chain": r[3], "created_at": r[4]}
        for r in rows
    ]


__all__ = (
    "OrgContext",
    "create_user", "get_user_by_email",
    "create_organization", "get_org", "get_membership", "count_seats",
    "create_api_key", "resolve_api_key", "list_api_keys", "revoke_api_key",
    "traces_used_this_period", "record_usage",
    "enqueue_trace", "get_trace_status", "list_traces",
)
