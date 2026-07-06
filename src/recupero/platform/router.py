"""Multi-tenant SaaS API — mounted under ``/v2`` (the existing flat-key API stays
at ``/v1`` for back-compat). Self-serve signup/login, org API-key management, and
a tenant-scoped async trace-submission endpoint that enqueues onto the existing
worker queue (never runs the long trace inline).
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from recupero.platform import deps, store, tenancy

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


# ---- traces (async, tenant-scoped, quota-gated) ---- #


@router.post("/traces", status_code=202)
def submit_trace(
    body: TraceIn,
    principal: store.OrgContext = Depends(deps.rate_limit),
    conn: Any = Depends(deps.db_conn),
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
    investigation_id = store.enqueue_trace(
        conn, org_id=principal.org_id, submitted_by=principal.user_id,
        chain=body.chain, seed_address=body.seed_address,
        incident_time=body.incident_time, case_id=case_id,
    )
    return {
        "investigation_id": investigation_id, "status": "queued", "case_id": case_id,
        "poll": f"/v2/traces/{investigation_id}",
        "quota_remaining": max(0, quota.remaining - 1) if quota.remaining >= 0 else -1,
        "submitted_at": datetime.now(UTC).isoformat(),
    }


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
