"""Multi-tenant SaaS API — mounted under ``/v2`` (the existing flat-key API stays
at ``/v1`` for back-compat). Self-serve signup/login, org API-key management, and
a tenant-scoped async trace-submission endpoint that enqueues onto the existing
worker queue (never runs the long trace inline).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from recupero.observability import metrics as obs_metrics
from recupero.platform import (
    assistant,
    audit,
    billing,
    deps,
    emailer,
    keycache,
    objectstore,
    store,
    tenancy,
    walletguard,
)

log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v2", tags=["platform"],
    # Router-wide DoS guard: reject oversized bodies (413) before handlers run.
    dependencies=[Depends(deps.max_request_body)],
)

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
    audit.record(conn, org_id=org_id, actor=user_id, action="org.created",
                 target=org_id, target_kind="org", metadata={"email": body.email})
    obs_metrics.record_signup()
    return TokenOut(access_token=token, expires_in=ttl, org_id=org_id)


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, conn: Any = Depends(deps.db_conn)) -> TokenOut:
    user = store.get_user_by_email(conn, body.email)
    # Constant-ish path: verify even on missing user to avoid a timing oracle.
    stored_hash = user["password_hash"] if user else "scrypt$1$1$1$AA$AA"
    if not tenancy.verify_password(body.password, stored_hash) or not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    # Rehash-on-login: transparently upgrade an outdated hash (e.g. scrypt →
    # argon2id once enabled) now that we hold the plaintext + a valid match.
    if tenancy.needs_rehash(stored_hash):
        store.update_password_hash(
            conn, user_id=user["id"], password_hash=tenancy.hash_password(body.password),
        )
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
    audit.record(conn, org_id=org_id, actor=user["id"], action="auth.login",
                 target=user["id"], target_kind="user")
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


# ---- email verification + password reset (single-use tokens) ---- #

_PASSWORD_RESET_TTL_SEC = 3600  # 1 hour


class TokenIn(BaseModel):
    token: str = Field(min_length=8, max_length=256)


class ResetRequestIn(BaseModel):
    email: str = Field(max_length=254)

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not _EMAIL_RE.match(v or ""):
            raise ValueError("invalid email")
        return v.strip().lower()


class ResetConfirmIn(BaseModel):
    token: str = Field(min_length=8, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


@router.post("/auth/verify/request", status_code=201)
def request_email_verification(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Mint an email-verification link for the signed-in user. Authenticated, so
    returning the link here is safe (the user owns the session); production also
    emails it via the dispatcher."""
    if not principal.user_id:
        raise HTTPException(status_code=400, detail="API-key principals have no email to verify")
    token, token_hash = tenancy.generate_invite_token()
    expires = datetime.now(UTC) + timedelta(seconds=tenancy.INVITE_TOKEN_TTL_SEC)
    store.create_user_token(
        conn, user_id=principal.user_id, kind="verify_email",
        token_hash=token_hash, expires_at=expires,
    )
    base = os.environ.get("RECUPERO_APP_BASE_URL", "https://app.recupero.io")
    verify_url = f"{base}/verify?token={token}"
    # Best-effort email; the link is also returned (the caller owns the session).
    email = store.get_user_email(conn, principal.user_id)
    if email:
        emailer.send_link_email(to=email, kind="verify", url=verify_url)
    return {"verify_token": token, "verify_url": verify_url}


@router.post("/auth/verify/confirm")
def confirm_email_verification(
    body: TokenIn, conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Public: consume the emailed token → mark the email verified."""
    user_id = store.consume_user_token(
        conn, kind="verify_email", token_hash=tenancy.hash_invite_token(body.token),
    )
    if user_id is None:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    store.set_email_verified(conn, user_id)
    return {"verified": True}


@router.post("/auth/password/reset-request", status_code=202)
def request_password_reset(
    body: ResetRequestIn, conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Public: mint a reset token for the email IF it exists, then email it. The
    token is NEVER returned in the response (an unauthenticated caller must not
    be able to reset an account they can't read email for), and the response is
    ALWAYS 202 regardless of whether the email exists (no user enumeration)."""
    user = store.get_user_by_email(conn, body.email)
    if user is not None:
        token, token_hash = tenancy.generate_invite_token()
        expires = datetime.now(UTC) + timedelta(seconds=_PASSWORD_RESET_TTL_SEC)
        store.create_user_token(
            conn, user_id=user["id"], kind="password_reset",
            token_hash=token_hash, expires_at=expires,
        )
        # Email the reset link (best-effort). The token is delivered ONLY via
        # email — it is never returned in the response, so an unauthenticated
        # caller can't reset an account whose mailbox they don't control.
        base = os.environ.get("RECUPERO_APP_BASE_URL", "https://app.recupero.io")
        emailer.send_link_email(
            to=body.email, kind="password_reset", url=f"{base}/reset?token={token}",
        )
    return {"status": "sent"}


@router.post("/auth/password/reset-confirm")
def confirm_password_reset(
    body: ResetConfirmIn, conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Public: consume the emailed reset token → set the new password."""
    user_id = store.consume_user_token(
        conn, kind="password_reset", token_hash=tenancy.hash_invite_token(body.token),
    )
    if user_id is None:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    store.update_password_hash(
        conn, user_id=user_id, password_hash=tenancy.hash_password(body.new_password),
    )
    return {"reset": True}


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
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "api-key",
                 action="apikey.created", target=name, target_kind="api_key",
                 metadata={"last4": key.last4})
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
    revoked_hash = store.revoke_api_key(conn, org_id=principal.org_id, key_id=key_id)
    if revoked_hash is None:
        raise HTTPException(status_code=404, detail="key not found")
    # Drop any cached resolution so the revoked key stops authenticating at once.
    keycache.invalidate(revoked_hash)
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "api-key",
                 action="apikey.revoked", target=key_id, target_kind="api_key")


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


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    """Prometheus exposition for the API process (unauthenticated — restrict at
    the network layer; contains only aggregate counts, never secrets). The
    worker process exposes its own /metrics on the health port."""
    return PlainTextResponse(
        obs_metrics.metrics_endpoint_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/audit")
def list_audit(
    limit: int = 100,
    principal: store.OrgContext = Depends(deps.require_role("owner", "admin")),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Recent security-relevant events for THIS org (SOC 2 CC6/CC7)."""
    return {"events": audit.list_events(conn, org_id=principal.org_id, limit=limit)}


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
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "system",
                 action="member.invited", target=body.email, target_kind="invite",
                 metadata={"role": body.role})
    base = os.environ.get("RECUPERO_APP_BASE_URL", "https://app.recupero.io")
    accept_url = f"{base}/invite?token={token}"
    # Email the invitee the accept link (best-effort). The token is ALSO returned
    # once to the inviter (who owns the session) so a copy-paste flow works even
    # when email delivery isn't configured.
    emailer.send_link_email(to=body.email, kind="invite", url=accept_url)
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
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "system",
                 action="invite.revoked", target=invite_id, target_kind="invite")


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
    audit.record(conn, org_id=org_id, actor=user_id, action="invite.accepted",
                 target=email, target_kind="member", metadata={"role": role})
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
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "system",
                 action="member.role_changed", target=user_id, target_kind="member",
                 metadata={"role": role})
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
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "system",
                 action="member.removed", target=user_id, target_kind="member")


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

    obs_metrics.record_platform_request("submit_trace", org.get("plan", "unknown"))
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


# ---- live trace status (Server-Sent Events) ---- #

_SSE_INTERVAL_SEC = 3.0
_SSE_MAX_TICKS = 100  # ~5 min ceiling; the browser EventSource auto-reconnects
_TERMINAL_TRACE = ("complete", "failed")


def _poll_trace_status(org_id: str, investigation_id: str) -> dict[str, Any] | None:
    """One SSE tick's DB read — SYNC + short-lived (run via asyncio.to_thread so
    it never blocks the event loop). A fresh connection per poll means no DB
    connection is held for the stream's lifetime."""
    import psycopg

    dsn = os.environ.get("RECUPERO_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        return None
    with psycopg.connect(dsn) as conn:
        return store.get_trace_status(
            conn, org_id=org_id, investigation_id=investigation_id,
        )


@router.get("/traces/{investigation_id}/stream")
async def stream_trace_status(
    investigation_id: str, token: str,
) -> StreamingResponse:
    """Server-Sent Events live status for a trace. Auth is via a ``?token=`` query
    param (a `/v2` session JWT) because a browser ``EventSource`` cannot set the
    Authorization header. Emits the status on change every few seconds until a
    terminal status or a bounded tick ceiling; opens a fresh short-lived DB
    connection per tick OFF the event loop (``asyncio.to_thread``), so no
    connection is pinned for the stream and the loop never blocks."""
    try:
        claims = tenancy.verify_jwt(token, secret=deps._jwt_secret())
    except tenancy.TokenError as exc:
        raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
    org_id = str(claims.get("org"))

    async def _events() -> Any:
        import json as _json

        last: str | None = None
        for _ in range(_SSE_MAX_TICKS):
            row = await asyncio.to_thread(_poll_trace_status, org_id, investigation_id)
            if row is None:
                yield 'event: error\ndata: {"detail": "trace not found"}\n\n'
                return
            status = str(row.get("status"))
            if status != last:
                yield "data: " + _json.dumps(
                    {"status": status, "investigation_id": investigation_id},
                ) + "\n\n"
                last = status
            if status in _TERMINAL_TRACE:
                return
            await asyncio.sleep(_SSE_INTERVAL_SEC)

    return StreamingResponse(_events(), media_type="text/event-stream")


@router.get("/traces/{investigation_id}/artifacts/{name}")
def trace_artifact_url(
    investigation_id: str, name: str,
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Return a short-lived presigned download URL for one case artifact. The
    object key is server-built from the tenant's org id (no traversal), and the
    trace must belong to the caller's org. 501 when object storage is unset."""
    if not objectstore.is_safe_name(name):
        raise HTTPException(status_code=422, detail="invalid artifact name")
    row = store.get_trace_status(
        conn, org_id=principal.org_id, investigation_id=investigation_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="trace not found")
    signed = objectstore.presign_artifact(
        org_id=principal.org_id, investigation_id=investigation_id,
        name=name, now=datetime.now(UTC),
    )
    if signed is None:
        raise HTTPException(status_code=501, detail="artifact storage not configured")
    url, ttl = signed
    return {"artifact": name, "url": url, "expires_in": ttl}


# --------------------------------------------------------------------------- #
# Wallet Guard (WalletBlock) — proactive pre-send checks + address book + alerts
# --------------------------------------------------------------------------- #


class GuardCheckIn(BaseModel):
    address: str = Field(min_length=1, max_length=128)
    chain: str = Field(default="ethereum", min_length=1, max_length=32)


class WatchIn(BaseModel):
    address: str = Field(min_length=1, max_length=128)
    chain: str = Field(default="ethereum", min_length=1, max_length=32)
    label: str | None = Field(default=None, max_length=120)


# Roles allowed to mutate the guard (viewers get read-only).
_GUARD_WRITE = ("owner", "admin", "member")


def _require_uuid(value: str, kind: str) -> None:
    """Reject a malformed id path param with 404, rather than letting a non-UUID
    string reach the ``uuid`` column and surface as a psycopg 500."""
    try:
        uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"{kind} not found") from exc


def _maybe_raise_alert(
    conn: Any, *, org_id: str, chain: str, result: dict[str, Any],
    source: str, watched_address_id: str | None = None,
) -> str | None:
    """Create a wallet alert when a check screens sanctioned/high. Returns the
    alert id, or None when the verdict is below the alert threshold."""
    guard = result["guard"]
    if not guard.get("should_alert"):
        return None
    screening = result["screening"]
    labels = screening.get("labels") or []
    category = labels[0].get("category") if labels else None
    return walletguard.create_alert(
        conn, org_id=org_id, chain=chain, address=screening["address"],
        verdict=guard["verdict"], severity=guard["risk_score"],
        headline=guard["headline"], category=category,
        watched_address_id=watched_address_id, source=source,
    )


@router.post("/guard/check")
def guard_check(
    body: GuardCheckIn,
    principal: store.OrgContext = Depends(deps.rate_limit),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Pre-send counterparty check: 'is it safe to send here?'. Screens the
    address offline (<50ms) and returns a consumer-facing verdict; raises an
    alert (and meters the check) when the verdict is sanctioned/high."""
    try:
        result = walletguard.check_address(body.address, chain=body.chain)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid address: {exc}") from exc
    alert_id = _maybe_raise_alert(
        conn, org_id=principal.org_id, chain=body.chain, result=result,
        source="guard_check",
    )
    store.record_usage(conn, org_id=principal.org_id, kind="guard_check")
    return {**result, "alert_id": alert_id}


@router.get("/guard/addresses")
def list_guard_addresses(
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {"addresses": walletguard.list_watched_addresses(conn, principal.org_id)}


@router.post("/guard/addresses", status_code=201)
def add_guard_address(
    body: WatchIn,
    principal: store.OrgContext = Depends(deps.require_role(*_GUARD_WRITE)),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Add (or refresh) an address in the watchlist/address book. Screens on add
    so the stored verdict is populated, and raises an alert if it screens risky."""
    try:
        result = walletguard.check_address(body.address, chain=body.chain)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid address: {exc}") from exc
    guard = result["guard"]
    canonical = result["screening"]["address"]
    watched_id = walletguard.add_watched_address(
        conn, org_id=principal.org_id, chain=body.chain, address=canonical,
        label=body.label, created_by=principal.user_id,
        verdict=guard["verdict"], risk_score=guard["risk_score"],
    )
    alert_id = _maybe_raise_alert(
        conn, org_id=principal.org_id, chain=body.chain, result=result,
        source="watch_add", watched_address_id=watched_id,
    )
    audit.record(conn, org_id=principal.org_id, actor=principal.user_id or "system",
                 action="guard.address_added", target=canonical,
                 target_kind="watched_address", metadata={"verdict": guard["verdict"]})
    return {
        "id": watched_id, "address": canonical, "chain": body.chain,
        "label": body.label, "guard": guard, "alert_id": alert_id,
    }


@router.delete("/guard/addresses/{watched_id}", status_code=204)
def delete_guard_address(
    watched_id: str,
    principal: store.OrgContext = Depends(deps.require_role(*_GUARD_WRITE)),
    conn: Any = Depends(deps.db_conn),
) -> None:
    _require_uuid(watched_id, "watched address")
    if not walletguard.delete_watched_address(
        conn, org_id=principal.org_id, watched_id=watched_id,
    ):
        raise HTTPException(status_code=404, detail="watched address not found")


@router.get("/guard/alerts")
def list_guard_alerts(
    unacknowledged: bool = False, limit: int = 50,
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    return {
        "alerts": walletguard.list_alerts(
            conn, org_id=principal.org_id, only_unacked=unacknowledged, limit=limit,
        ),
        "unacknowledged": walletguard.count_unacked_alerts(conn, principal.org_id),
    }


@router.post("/guard/alerts/{alert_id}/ack")
def ack_guard_alert(
    alert_id: str,
    principal: store.OrgContext = Depends(deps.require_role(*_GUARD_WRITE)),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    _require_uuid(alert_id, "alert")
    if not walletguard.ack_alert(
        conn, org_id=principal.org_id, alert_id=alert_id, user_id=principal.user_id,
    ):
        raise HTTPException(status_code=404, detail="alert not found or already acknowledged")
    return {"alert_id": alert_id, "acknowledged": True}


# --------------------------------------------------------------------------- #
# AI Assistant ("Nikiwa") — grounded crypto-safety chat
# --------------------------------------------------------------------------- #


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=assistant.MAX_MSG_CHARS)


class ChatIn(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=assistant.MAX_TURNS)
    chain: str = Field(default="ethereum", min_length=1, max_length=32)


@router.post("/assistant/chat")
def assistant_chat(
    body: ChatIn,
    principal: store.OrgContext = Depends(deps.rate_limit),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Grounded crypto-safety chat. Opt-in (``RECUPERO_ASSISTANT_ENABLED``); 503
    when disabled or the model isn't configured (no API key)."""
    if not assistant.is_enabled():
        raise HTTPException(status_code=503, detail="assistant not enabled")
    payload = [{"role": m.role, "content": m.content} for m in body.messages]
    try:
        result = assistant.answer(payload, chain=body.chain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    store.record_usage(conn, org_id=principal.org_id, kind="assistant_chat")
    return result


# ---- fund-flow graph (JSON, for the web dashboard's D3 view) ---- #


def _build_graph_payload(investigation_id: str, case_id: str | None) -> dict[str, Any]:
    """Load the case and build the JSON fund-flow graph via the engine's
    ``reports.graph_ui.build_graph_data`` (the exact ``{nodes, edges, meta}`` the
    engine embeds in ``interactive_graph.html``). The case is read from the
    Supabase bucket when ``RECUPERO_CASE_STORE=supabase`` (keyed by the
    investigation UUID) else the local case store (keyed by ``case_id``).

    Raises ``OSError`` / ``ValueError`` when the case can't be read (trace still
    running, no artifacts yet, or a malformed id) — the caller maps these to 404.
    """
    from recupero.api import _supabase_case_source
    from recupero.reports.graph_ui import build_graph_data

    if _supabase_case_source.enabled():
        case = _supabase_case_source.read_case(investigation_id)
    else:
        from recupero.config import load_config
        from recupero.storage.case_store import CaseStore
        cfg, _ = load_config()
        case = CaseStore(cfg).read_case(case_id or investigation_id)
    return build_graph_data(case)


@router.get("/traces/{investigation_id}/graph")
def trace_graph(
    investigation_id: str,
    principal: store.OrgContext = Depends(deps.current_principal),
    conn: Any = Depends(deps.db_conn),
) -> dict[str, Any]:
    """Fund-flow graph for a trace as JSON (``{nodes, edges, meta}``) — the same
    data the engine embeds in ``interactive_graph.html``, served same-origin so
    the web dashboard can render it with D3 directly (no S3 CORS, no HTML iframe).
    The trace must belong to the caller's org; 404 until the case artifacts
    exist (i.e. the trace has completed)."""
    row = store.get_trace_status(
        conn, org_id=principal.org_id, investigation_id=investigation_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        return _build_graph_payload(investigation_id, row.get("case_id"))
    except (OSError, ValueError):
        # case.json not present yet (running / no artifacts) or a malformed id —
        # a single "not available" to the caller (no state leak).
        raise HTTPException(
            status_code=404, detail="graph not available for this trace yet",
        ) from None
    except Exception as exc:  # noqa: BLE001 — any build blowup → 503, never 500
        log.warning("graph build failed for %s: %s", investigation_id, exc)
        raise HTTPException(status_code=503, detail="graph unavailable") from None


__all__ = ("router",)
