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


def update_password_hash(conn: Any, *, user_id: str, password_hash: str) -> None:
    """Overwrite a user's stored password hash (used for rehash-on-login upgrade
    and password reset)."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.users SET password_hash = %s WHERE id = %s",
            (password_hash, user_id),
        )


def create_user_token(
    conn: Any, *, user_id: str, kind: str, token_hash: str, expires_at: Any,
) -> None:
    """Store a single-use email token (verification / password reset). Only the
    hash is persisted — the plaintext lives in the emailed link."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.user_tokens (user_id, kind, token_hash, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, kind, token_hash, expires_at),
        )


def consume_user_token(conn: Any, *, kind: str, token_hash: str) -> str | None:
    """Atomically consume a token: valid + unused + unexpired → mark used_at and
    return its user_id; otherwise None. Single UPDATE, so a token works once."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.user_tokens SET used_at = now() "
            "WHERE token_hash = %s AND kind = %s AND used_at IS NULL "
            "AND expires_at > now() RETURNING user_id::text",
            (token_hash, kind),
        )
        row = cur.fetchone()
    return row[0] if row else None


def set_email_verified(conn: Any, user_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.users SET email_verified_at = now() WHERE id = %s",
            (user_id,),
        )


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
            "SELECT id::text, name, slug, plan, status, trace_used_period, "
            "       period_start, stripe_customer_id, plan_renews_at "
            "FROM public.organizations WHERE id = %s",
            (org_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0], "name": row[1], "slug": row[2], "plan": row[3],
        "status": row[4], "trace_used_period": row[5], "period_start": row[6],
        "stripe_customer_id": row[7], "plan_renews_at": row[8],
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


def revoke_api_key(conn: Any, *, org_id: str, key_id: str) -> str | None:
    """Revoke a key; return its ``key_hash`` (so the caller can invalidate any
    cached resolution) or None if no matching live key was found."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.org_api_keys SET revoked_at = now() "
            "WHERE id = %s AND org_id = %s AND revoked_at IS NULL "
            "RETURNING key_hash",
            (key_id, org_id),
        )
        row = cur.fetchone()
        return row[0] if row else None


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
    idempotency_key: str | None = None,
) -> tuple[str, bool]:
    """Insert a tenant-scoped job into the existing worker queue and meter it,
    atomically. Returns ``(investigation_id, created)``. The worker (multi-
    process, FOR UPDATE SKIP LOCKED) picks it up; nothing here runs the trace
    inline.

    Idempotent: with an ``idempotency_key`` a client retry conflicts on the
    UNIQUE(org_id, idempotency_key) index → we REPLAY the original job id and
    do NOT enqueue or meter a second time (``created=False``)."""
    investigation_id = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.investigations "
            "(id, org_id, submitted_by, chain, seed_address, incident_time, "
            " case_id, status, idempotency_key) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', %s) "
            "ON CONFLICT (org_id, idempotency_key) WHERE idempotency_key IS NOT NULL "
            "DO NOTHING RETURNING id::text",
            (investigation_id, org_id, submitted_by, chain, seed_address,
             incident_time, case_id, idempotency_key),
        )
        row = cur.fetchone()
        if row is None:
            # Conflict: this (org, key) already enqueued — replay the original.
            cur.execute(
                "SELECT id::text FROM public.investigations "
                "WHERE org_id = %s AND idempotency_key = %s",
                (org_id, idempotency_key),
            )
            existing = cur.fetchone()
            return (existing[0] if existing else investigation_id, False)
        cur.execute(
            "INSERT INTO public.usage_events (org_id, kind, quantity, investigation_id) "
            "VALUES (%s, 'trace_submitted', 1, %s)",
            (org_id, row[0]),
        )
    return (row[0], True)


# --------------------------------------------------------------------------- #
# Billing (Stripe linkage + webhook-driven state)
# --------------------------------------------------------------------------- #


def link_stripe_customer(conn: Any, *, org_id: str, customer_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.organizations SET stripe_customer_id = %s, updated_at = now() "
            "WHERE id = %s",
            (customer_id, org_id),
        )


def org_id_by_stripe_customer(conn: Any, customer_id: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text FROM public.organizations WHERE stripe_customer_id = %s",
            (customer_id,),
        )
        row = cur.fetchone()
    return row[0] if row else None


def apply_billing_change(conn: Any, change: Any) -> bool:
    """Apply a ``billing.BillingChange`` to the org located by its Stripe
    customer id. Only non-None fields are written; ``reset_period`` zeroes the
    usage window. Returns False if no org matches (unknown customer)."""
    if not getattr(change, "customer_id", None):
        return False
    org_id = org_id_by_stripe_customer(conn, change.customer_id)
    if org_id is None:
        return False
    # STATIC SQL (no dynamic column list): each optional field is a CASE guarded
    # by a boolean "set_X" flag, so a field is written only when the change
    # carries it. Fully parameterized — no user/Stripe string is ever formatted
    # into the query text.
    renews = change.plan_renews_at
    params = {
        "org_id": org_id,
        "plan": change.plan, "set_plan": change.plan is not None,
        "status": change.status, "set_status": change.status is not None,
        "sub": change.stripe_subscription_id,
        "set_sub": change.stripe_subscription_id is not None,
        "price": change.stripe_price_id,
        "set_price": change.stripe_price_id is not None,
        "renews": int(renews) if renews is not None else None,
        "set_renews": renews is not None,
        "reset": bool(change.reset_period),
    }
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.organizations SET "
            "  plan = CASE WHEN %(set_plan)s THEN %(plan)s ELSE plan END, "
            "  status = CASE WHEN %(set_status)s THEN %(status)s ELSE status END, "
            "  stripe_subscription_id = CASE WHEN %(set_sub)s THEN %(sub)s "
            "      ELSE stripe_subscription_id END, "
            "  stripe_price_id = CASE WHEN %(set_price)s THEN %(price)s "
            "      ELSE stripe_price_id END, "
            "  plan_renews_at = CASE WHEN %(set_renews)s THEN to_timestamp(%(renews)s) "
            "      ELSE plan_renews_at END, "
            "  period_start = CASE WHEN %(reset)s THEN now() ELSE period_start END, "
            "  trace_used_period = CASE WHEN %(reset)s THEN 0 ELSE trace_used_period END, "
            "  updated_at = now() "
            "WHERE id = %(org_id)s",
            params,
        )
        return cur.rowcount > 0


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


# --------------------------------------------------------------------------- #
# Team: members + invites
# --------------------------------------------------------------------------- #


def add_membership(conn: Any, *, org_id: str, user_id: str, role: str) -> None:
    """Add (or re-role) a user in an org. Idempotent on (org_id, user_id)."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.memberships (org_id, user_id, role) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
            (org_id, user_id, role),
        )


def list_members(conn: Any, org_id: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT u.id::text, u.email, u.name, m.role, m.created_at "
            "FROM public.memberships m JOIN public.users u ON u.id = m.user_id "
            "WHERE m.org_id = %s ORDER BY m.created_at ASC",
            (org_id,),
        )
        rows = cur.fetchall()
    return [
        {"user_id": r[0], "email": r[1], "name": r[2], "role": r[3], "joined_at": r[4]}
        for r in rows
    ]


def count_owners(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM public.memberships WHERE org_id = %s AND role = 'owner'",
            (org_id,),
        )
        return int(cur.fetchone()[0])


def update_member_role(conn: Any, *, org_id: str, user_id: str, role: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.memberships SET role = %s WHERE org_id = %s AND user_id = %s",
            (role, org_id, user_id),
        )
        return cur.rowcount > 0


def remove_member(conn: Any, *, org_id: str, user_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM public.memberships WHERE org_id = %s AND user_id = %s",
            (org_id, user_id),
        )
        return cur.rowcount > 0


def count_pending_invites(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM public.org_invites "
            "WHERE org_id = %s AND accepted_at IS NULL",
            (org_id,),
        )
        return int(cur.fetchone()[0])


def create_invite(
    conn: Any, *, org_id: str, email: str, role: str, invited_by: str | None,
    token_hash: str, expires_at: Any,
) -> str:
    """Create (or replace) a pending invite for ``(org, email)``. A prior pending
    invite for the same email is cleared first so re-inviting rotates the token
    rather than colliding on the partial-unique index."""
    norm = email.strip().lower()
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM public.org_invites "
            "WHERE org_id = %s AND email = %s AND accepted_at IS NULL",
            (org_id, norm),
        )
        cur.execute(
            "INSERT INTO public.org_invites "
            "(org_id, email, role, token_hash, invited_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id::text",
            (org_id, norm, role, token_hash, invited_by, expires_at),
        )
        return cur.fetchone()[0]


def list_invites(conn: Any, org_id: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, email, role, created_at, expires_at "
            "FROM public.org_invites WHERE org_id = %s AND accepted_at IS NULL "
            "ORDER BY created_at DESC",
            (org_id,),
        )
        rows = cur.fetchall()
    return [
        {"id": r[0], "email": r[1], "role": r[2], "created_at": r[3], "expires_at": r[4]}
        for r in rows
    ]


def revoke_invite(conn: Any, *, org_id: str, invite_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM public.org_invites "
            "WHERE id = %s AND org_id = %s AND accepted_at IS NULL",
            (invite_id, org_id),
        )
        return cur.rowcount > 0


def get_invite_by_token(conn: Any, token_hash: str) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, org_id::text, email, role, expires_at, accepted_at "
            "FROM public.org_invites WHERE token_hash = %s",
            (token_hash,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0], "org_id": row[1], "email": row[2], "role": row[3],
        "expires_at": row[4], "accepted_at": row[5],
    }


def mark_invite_accepted(conn: Any, *, invite_id: str, user_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.org_invites SET accepted_at = now(), accepted_by = %s "
            "WHERE id = %s AND accepted_at IS NULL",
            (user_id, invite_id),
        )


__all__ = (
    "OrgContext",
    "create_user", "get_user_by_email",
    "create_organization", "get_org", "get_membership", "count_seats",
    "create_api_key", "resolve_api_key", "list_api_keys", "revoke_api_key",
    "traces_used_this_period", "record_usage",
    "enqueue_trace", "get_trace_status", "list_traces",
    "add_membership", "list_members", "count_owners", "update_member_role",
    "remove_member", "count_pending_invites", "create_invite", "list_invites",
    "revoke_invite", "get_invite_by_token", "mark_invite_accepted",
    "update_password_hash", "create_user_token", "consume_user_token",
    "set_email_verified",
)
