"""Multi-tenant SaaS API — mounted under ``/v2`` (the existing flat-key API stays
at ``/v1`` for back-compat). Self-serve signup/login, org API-key management, and
a tenant-scoped async trace-submission endpoint that enqueues onto the existing
worker queue (never runs the long trace inline).
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

from recupero.platform import billing, deps, store, tenancy

router = APIRouter(prefix="/v2", tags=["platform"])

_SLUG_RE = re.compile(r"[^a-z0-9-]+")
# Pragmatic email shape check (avoids the email-validator dependency that
# pydantic's EmailStr pulls in — the SaaS layer stays stdlib-light).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _slugify(name: str) -> str:
    base = _SLUG_RE.sub("-", (name or "org").strip().lower()).strip("-") or "org"
    return f"{base[:40]}-{uuid.uuid4().hex[:6]}"


def _session_ttl() -> int:
    try:
        return int(os.environ.get("RECUPERO_PLATFORM_JWT_TTL_SEC", "3600"))
    except (TypeError, ValueError):
        return 3600


def _as_utc(dt: datetime) -> datetime:
    """Treat a naive datetime as UTC (psycopg returns tz-aware timestamptz;
    this only guards a test/edge that hands us a naive value)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


# Roles an owner/admin may hand out. 'owner' is intentionally excluded from
# invites (ownership is granted at org creation or via an explicit role change).
_ASSIGNABLE_ROLES = ("admin", "member", "viewer")
_ALL_ROLES = ("owner", "admin", "member", "viewer")


# ---- request/response models ---- #


class SignupIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=10, max_length=256)
    org_name: str = Field(min_length=1, max_length=120)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not _EMAIL_RE.match(v or ""):
            raise ValueError("invalid email")
        return v.strip().lower()


class LoginIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not _EMAIL_RE.match(v or ""):
            raise ValueError("invalid email")
        return v.strip().lower()


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    org_id: str


class TraceIn(BaseModel):
    chain: str = Field(min_length=1, max_length=32)
    seed_address: str = Field(min_length=1, max_length=128)
    incident_time: str = Field(description="ISO-8601 UTC incident timestamp")
    case_id: str | None = Field(default=None, max_length=80)


# ---- auth ---- #


@router.post("/auth/signup", response_model=TokenOut, status_code=201)
def signup(body: SignupIn, conn: Any = Depends(deps.db_conn)) -> TokenOut:
    if store.get_user_by_email(conn, body.email):
        raise HTTPException(status_code=409, detail="email already registered")
    user_id = store.create_user(
        conn, email=body.email, password=body.password, name=None,
    )
    org_id = store.create_organization(
        conn, name=body.org_name, slug=_slugify(body.org_name),
        owner_user_id=user_id, plan=tenancy.DEFAULT_PLAN,
    )
    ttl = _session_ttl()
    token = tenancy.mint_jwt(
        secret=deps._jwt_secret(), subject=user_id, org_id=org_id,
        role="owner", ttl_seconds=ttl, extra={"plan": tenancy.DEFAULT_PLAN},
    )
    return TokenOut(access_token=token, expires_in=ttl, org_id=org_id)


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, conn: Any = Depends(deps.db_conn)) -> TokenOut:
    user = store.get_user_by_email(conn, body.email)
    # Constant-ish path: verify even on missing user to avoid a timing oracle.
    stored_hash = user["password_hash"] if user else "scrypt$1$1$1$AA$AA"
    if not tenancy.verify_password(body.password, stored_hash) or not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    membership = _primary_membership(conn, user["id"])
    if membership is None:
        raise HTTPException(status_code=403, detail="user has no organization")
    org_id, role = membership
    org = store.get_org(conn, org_id) or {}
    ttl = _session_ttl()
    token = tenancy.mint_jwt(
        secret=deps._jwt_secret(), subject=user["id"], org_id=org_id,
        role=role, ttl_seconds=ttl, extra={"plan": org.get("plan", tenancy.DEFAULT_PLAN)},
    )
    return TokenOut(access_token=token, expires_in=ttl, org_id=org_id)


def _primary_membership(conn: Any, user_id: str) -> tuple[str, str] | None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT org_id::text, role FROM public.memberships "
            "WHERE user_id = %s ORDER BY created_at ASC LIMIT 1",
            (user_id,),
        )
        row = cur.fetchone()
    return (row[0], row[1]) if row else None


@router.get("/me")
def me(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    org = store.get_org(conn, principal.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="organization not found")
    used = store.traces_used_this_period(conn, principal.org_id)
    quota = tenancy.check_trace_quota(plan_name=org["plan"], used_this_period=used)
    plan = tenancy.get_plan(org["plan"])
    return {
        "org_id": principal.org_id, "role": principal.role, "user_id": principal.user_id,
        "plan": org["plan"], "status": org["status"],
        "usage": {"traces_used": used, "traces_remaining": quota.remaining,
                  "rate_limit_per_min": plan.rate_limit_per_min},
    }


# ---- API keys (owner/admin only) ---- #


@router.post("/api-keys", status_code=201)
def create_key(
    name: str = Body(embed=True, min_length=1, max_length=80),
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    key = store.create_api_key(
        conn, org_id=principal.org_id, name=name, created_by=principal.user_id,
    )
    # plaintext is returned exactly ONCE
    return {"api_key": key.plaintext, "last4": key.last4,
            "warning": "store this now — it will not be shown again"}


@router.get("/api-keys")
def list_keys(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {"keys": store.list_api_keys(conn, principal.org_id)}


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_key(
    key_id: str,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> None:
    if not store.revoke_api_key(conn, org_id=principal.org_id, key_id=key_id):
        raise HTTPException(status_code=404, detail="key not found")


# ---- team: members + invites ---- #


class InviteIn(BaseModel):
    email: str = Field(max_length=254)
    role: str = Field(default="member")

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not _EMAIL_RE.match(v or ""):
            raise ValueError("invalid email")
        return v.strip().lower()

    @field_validator("role")
    @classmethod
    def _role_ok(cls, v: str) -> str:
        r = (v or "").strip().lower()
        if r not in _ASSIGNABLE_ROLES:
            raise ValueError(f"role must be one of {list(_ASSIGNABLE_ROLES)}")
        return r


class RoleIn(BaseModel):
    role: str


class AcceptInviteIn(BaseModel):
    token: str = Field(min_length=8, max_length=256)
    password: str | None = Field(default=None, max_length=256)
    name: str | None = Field(default=None, max_length=120)


@router.get("/members")
def list_org_members(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {"members": store.list_members(conn, principal.org_id)}


# NOTE: the literal `/members/invites*` routes are declared BEFORE the
# `/members/{user_id}` param routes so they are matched first.
@router.post("/members/invites", status_code=201)
def invite_member(
    body: InviteIn,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    org = store.get_org(conn, principal.org_id) or {}
    # Count seats already used PLUS pending invites so we can't over-commit.
    committed = store.count_seats(conn, principal.org_id) + store.count_pending_invites(
        conn, principal.org_id,
    )
    quota = tenancy.check_seat_quota(plan_name=org.get("plan"), current_seats=committed)
    if not quota.allowed:
        raise HTTPException(status_code=402, detail=quota.reason)  # seat limit reached
    token, token_hash = tenancy.generate_invite_token()
    expires = datetime.now(UTC) + timedelta(seconds=tenancy.INVITE_TOKEN_TTL_SEC)
    invite_id = store.create_invite(
        conn, org_id=principal.org_id, email=body.email, role=body.role,
        invited_by=principal.user_id, token_hash=token_hash, expires_at=expires,
    )
    base = os.environ.get("RECUPERO_APP_BASE_URL", "https://app.recupero.io")
    # The token is returned ONCE (email delivery is a separate, gated concern).
    return {
        "invite_id": invite_id, "email": body.email, "role": body.role,
        "invite_token": token, "accept_url": f"{base}/invite?token={token}",
        "expires_at": expires.isoformat(),
        "warning": "share this link with the invitee — the token is shown once",
    }


@router.get("/members/invites")
def list_member_invites(
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {"invites": store.list_invites(conn, principal.org_id)}


@router.delete("/members/invites/{invite_id}", status_code=204)
def revoke_member_invite(
    invite_id: str,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> None:
    if not store.revoke_invite(conn, org_id=principal.org_id, invite_id=invite_id):
        raise HTTPException(status_code=404, detail="invite not found")


@router.post("/members/invites/accept", response_model=TokenOut)
def accept_member_invite(
    body: AcceptInviteIn, conn: Any = Depends(deps.db_conn),
) -> TokenOut:
    """Public (no auth): the single-use token IS the proof the invitee received
    the emailed link. Adds an existing user to the org, or creates the account
    (password required) — then returns a session token so they're signed in."""
    invite = store.get_invite_by_token(conn, tenancy.hash_invite_token(body.token))
    if invite is None or invite["accepted_at"] is not None:
        raise HTTPException(status_code=404, detail="invite not found or already used")
    if invite["expires_at"] is not None and _as_utc(invite["expires_at"]) < datetime.now(UTC):
        raise HTTPException(status_code=410, detail="invite expired")

    org_id, email, role = invite["org_id"], invite["email"], invite["role"]
    user = store.get_user_by_email(conn, email)
    if user is None:
        if not body.password or len(body.password) < 10:
            raise HTTPException(status_code=422, detail="new account requires a password (10+ chars)")
        user_id = store.create_user(conn, email=email, password=body.password, name=body.name)
    else:
        user_id = user["id"]

    org = store.get_org(conn, org_id) or {}
    already_member = store.get_membership(conn, org_id=org_id, user_id=user_id) is not None
    if not already_member:
        seats = store.count_seats(conn, org_id)
        quota = tenancy.check_seat_quota(plan_name=org.get("plan"), current_seats=seats)
        if not quota.allowed:
            raise HTTPException(status_code=402, detail=quota.reason)

    store.add_membership(conn, org_id=org_id, user_id=user_id, role=role)
    store.mark_invite_accepted(conn, invite_id=invite["id"], user_id=user_id)
    ttl = _session_ttl()
    token = tenancy.mint_jwt(
        secret=deps._jwt_secret(), subject=user_id, org_id=org_id, role=role,
        ttl_seconds=ttl, extra={"plan": org.get("plan", tenancy.DEFAULT_PLAN)},
    )
    return TokenOut(access_token=token, expires_in=ttl, org_id=org_id)


@router.patch("/members/{user_id}")
def set_member_role(
    user_id: str, body: RoleIn,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    role = (body.role or "").strip().lower()
    if role not in _ALL_ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {list(_ALL_ROLES)}")
    target = store.get_membership(conn, org_id=principal.org_id, user_id=user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="member not found")
    # Never leave an org without an owner.
    if target["role"] == "owner" and role != "owner" and store.count_owners(conn, principal.org_id) <= 1:
        raise HTTPException(status_code=409, detail="cannot demote the last owner")
    store.update_member_role(conn, org_id=principal.org_id, user_id=user_id, role=role)
    return {"user_id": user_id, "role": role}


@router.delete("/members/{user_id}", status_code=204)
def remove_org_member(
    user_id: str,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> None:
    target = store.get_membership(conn, org_id=principal.org_id, user_id=user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="member not found")
    if target["role"] == "owner" and store.count_owners(conn, principal.org_id) <= 1:
        raise HTTPException(status_code=409, detail="cannot remove the last owner")
    store.remove_member(conn, org_id=principal.org_id, user_id=user_id)


# ---- traces (async, tenant-scoped, quota-gated) ---- #


@router.post("/traces", status_code=202)
def submit_trace(
    body: TraceIn,
    principal: store.OrgContext = Depends(deps.rate_limit),
    conn: Any = Depends(deps.db_conn),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    # validate incident_time up front (fail fast, before enqueue)
    try:
        datetime.fromisoformat(body.incident_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="incident_time must be ISO-8601") from exc

    org = store.get_org(conn, principal.org_id)
    if not org or org["status"] != "active":
        raise HTTPException(status_code=403, detail="organization inactive")

    used = store.traces_used_this_period(conn, principal.org_id)
    quota = tenancy.check_trace_quota(plan_name=org["plan"], used_this_period=used)
    if not quota.allowed:
        raise HTTPException(status_code=402, detail=quota.reason)  # 402 Payment Required

    case_id = body.case_id or f"CASE-{uuid.uuid4().hex[:12]}"
    # Idempotent: a retry with the same Idempotency-Key replays the original job
    # (no double-enqueue, no double-metering). ``created`` is False on replay.
    investigation_id, created = store.enqueue_trace(
        conn, org_id=principal.org_id, submitted_by=principal.user_id,
        chain=body.chain, seed_address=body.seed_address,
        incident_time=body.incident_time, case_id=case_id,
        idempotency_key=(idempotency_key or None),
    )
    return {
        "investigation_id": investigation_id,
        "status": "queued" if created else "already_submitted",
        "case_id": case_id,
        "idempotent_replay": not created,
        "poll": f"/v2/traces/{investigation_id}",
        "quota_remaining": (
            max(0, quota.remaining - 1) if (quota.remaining >= 0 and created)
            else quota.remaining
        ),
        "submitted_at": datetime.now(UTC).isoformat(),
    }


# ---- billing ---- #


@router.get("/billing/usage")
def billing_usage(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    org = store.get_org(conn, principal.org_id)
    if not org:
        raise HTTPException(status_code=404, detail="organization not found")
    used = store.traces_used_this_period(conn, principal.org_id)
    quota = tenancy.check_trace_quota(plan_name=org["plan"], used_this_period=used)
    plan = tenancy.get_plan(org["plan"])
    return {
        "plan": org["plan"], "status": org["status"],
        "period_start": org["period_start"], "plan_renews_at": org["plan_renews_at"],
        "traces_used": used, "traces_included": plan.monthly_trace_quota,
        "traces_remaining": quota.remaining,
        "rate_limit_per_min": plan.rate_limit_per_min,
        "seats": {"used": store.count_seats(conn, principal.org_id), "max": plan.max_seats},
        "billing_configured": bool(org["stripe_customer_id"]),
    }


@router.post("/billing/checkout", status_code=201)
def billing_checkout(
    plan: str = Body(embed=True),
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Create a Stripe Checkout Session for an upgrade. Requires Stripe to be
    configured (RECUPERO_STRIPE_SECRET_KEY + a price id for the plan); returns
    501 otherwise. The actual plan flip happens on the webhook, not here."""
    price_id = os.environ.get(f"RECUPERO_STRIPE_PRICE_{plan.upper()}")
    secret_key = os.environ.get("RECUPERO_STRIPE_SECRET_KEY")
    if not secret_key or not price_id:
        raise HTTPException(
            status_code=501,
            detail="billing not configured (set RECUPERO_STRIPE_SECRET_KEY + "
                   f"RECUPERO_STRIPE_PRICE_{plan.upper()})",
        )
    try:
        import stripe  # optional extra; only needed when billing is enabled
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise HTTPException(status_code=501, detail="stripe SDK not installed") from exc
    stripe.api_key = secret_key
    org = store.get_org(conn, principal.org_id) or {}
    customer_id = org.get("stripe_customer_id")
    if not customer_id:  # pragma: no cover - needs live Stripe
        customer = stripe.Customer.create(metadata={"org_id": principal.org_id})
        customer_id = customer["id"]
        store.link_stripe_customer(conn, org_id=principal.org_id, customer_id=customer_id)
    base = os.environ.get("RECUPERO_APP_BASE_URL", "https://app.recupero.io")
    session = stripe.checkout.Session.create(  # pragma: no cover - needs live Stripe
        mode="subscription", customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{base}/billing?status=success",
        cancel_url=f"{base}/billing?status=cancelled",
    )
    return {"checkout_url": session["url"]}


@router.post("/webhooks/stripe", include_in_schema=False)
def stripe_webhook(
    payload: bytes = Body(default=b""),
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Stripe webhook: verify the signature over the RAW body, map the event to a
    tenant state change, and apply it. Unhandled events are acked (200) so Stripe
    stops retrying. Never trusts the body without a valid signature.

    Sync handler taking the raw body via ``bytes = Body()`` (FastAPI passes the
    UNMODIFIED bytes Stripe signed) so blocking psycopg runs safely in the
    threadpool — no async event-loop blocking."""
    import json as _json

    secret = os.environ.get("RECUPERO_STRIPE_WEBHOOK_SECRET", "")
    try:
        billing.verify_stripe_signature(payload, stripe_signature, secret)
    except billing.StripeSignatureError as exc:
        raise HTTPException(status_code=400, detail=f"signature: {exc}") from exc
    try:
        event = _json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc
    change = billing.apply_webhook_event(event, price_to_plan=billing.price_plan_map())
    applied = store.apply_billing_change(conn, change) if change else False
    return {"received": True, "applied": applied, "type": event.get("type")}


@router.get("/traces/{investigation_id}")
def trace_status(
    investigation_id: str,
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    row = store.get_trace_status(
        conn, org_id=principal.org_id, investigation_id=investigation_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="trace not found")
    return row


@router.get("/traces")
def list_traces(
    limit: int = 50,
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {"traces": store.list_traces(conn, org_id=principal.org_id, limit=limit)}


__all__ = ("router",)
