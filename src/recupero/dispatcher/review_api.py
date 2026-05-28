"""FastAPI router for the reviewer queue API (v0.32 Tier-0 gap #1).

Endpoints (all gated by ``X-Recupero-Admin-Key``):

  * ``GET    /v1/reviews/queue``          — list awaiting_review rows
  * ``POST   /v1/reviews/{id}/approve``   — mark approved (requires reviewer_email)
  * ``POST   /v1/reviews/{id}/reject``    — mark rejected (requires review_notes)
  * ``POST   /v1/reviews/{id}/override``  — mark overridden_unreviewed
    (requires override_reason + override_acknowledged_legal_risk=true)

The dashboard UI for these endpoints is out of scope; this surface is
designed to be driven by a thin operator UI or curl from an SRE/IC.

Auth: the X-Recupero-Admin-Key header pattern is shared with the
worker's _health_server admin surface (RECUPERO_ADMIN_KEY env var).
If RECUPERO_ADMIN_KEY is unset, every admin endpoint returns 503 —
deny-by-default rather than accidentally-open.
"""

from __future__ import annotations

import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from recupero.dispatcher.review_gate import (
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_AWAITING,
    REVIEW_STATUS_OVERRIDDEN,
    REVIEW_STATUS_REJECTED,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/reviews", tags=["reviews"])


def _require_admin_auth(provided: str | None) -> None:
    """Constant-time match against ``RECUPERO_ADMIN_KEY``.

    Raises 503 when no admin key is configured (deny-by-default so
    a misconfigured deploy doesn't accidentally publish the queue),
    401 when the header is missing/invalid.
    """
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "review API disabled — set RECUPERO_ADMIN_KEY to "
                "enable"
            ),
        )
    if not provided or not provided.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing X-Recupero-Admin-Key",
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid X-Recupero-Admin-Key",
        )


def _dsn() -> str:
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="review API unavailable: DSN not configured",
        )
    return dsn


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────


class ApproveRequest(BaseModel):
    reviewer_email: str = Field(..., min_length=3, max_length=254)
    review_notes: str | None = Field(default=None, max_length=4000)

    @field_validator("reviewer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("reviewer_email must be a valid email")
        return v


class RejectRequest(BaseModel):
    reviewer_email: str = Field(..., min_length=3, max_length=254)
    review_notes: str = Field(..., min_length=1, max_length=4000)

    @field_validator("reviewer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("reviewer_email must be a valid email")
        return v


class OverrideRequest(BaseModel):
    reviewer_email: str = Field(..., min_length=3, max_length=254)
    override_reason: str = Field(..., min_length=1, max_length=4000)
    override_acknowledged_legal_risk: bool = Field(...)

    @field_validator("override_acknowledged_legal_risk")
    @classmethod
    def _must_acknowledge(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "override_acknowledged_legal_risk must be true to "
                "use the override path"
            )
        return v

    @field_validator("reviewer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("reviewer_email must be a valid email")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/queue", summary="List awaiting_review review rows")
def get_review_queue(
    x_recupero_admin_key: str | None = Header(default=None),
    limit: int = 100,
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    dsn = _dsn()

    # Defensive bound on limit so a misconfigured caller can't pull
    # an arbitrarily large queue.
    limit = max(1, min(int(limit or 100), 500))

    from recupero._common import db_connect
    rows: list[dict[str, Any]] = []
    try:
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, case_id, artifact_kind, artifact_path,
                       artifact_sha256, status, created_at_utc
                  FROM public.brief_reviews
                 WHERE status = %s
                 ORDER BY created_at_utc ASC
                 LIMIT %s
                """,
                (REVIEW_STATUS_AWAITING, limit),
            )
            for r in cur.fetchall():
                rows.append({
                    "id": r[0],
                    "case_id": str(r[1]),
                    "artifact_kind": r[2],
                    "artifact_path": r[3],
                    "artifact_sha256": r[4],
                    "status": r[5],
                    "created_at_utc": (
                        r[6].isoformat() if r[6] is not None else None
                    ),
                })
    except Exception as exc:  # noqa: BLE001
        log.warning("review queue DB lookup failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="review queue lookup failed",
        ) from None

    return {"reviews": rows, "count": len(rows)}


def _update_status(
    *,
    review_id: int,
    new_status: str,
    reviewer_email: str,
    review_notes: str | None = None,
    override_reason: str | None = None,
    override_acknowledged_legal_risk: bool | None = None,
) -> dict[str, Any]:
    """Run the SQL UPDATE for status transitions. Returns the new row
    state. Raises 404 if the id doesn't exist."""
    dsn = _dsn()
    from recupero._common import db_connect
    try:
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.brief_reviews
                   SET status = %s,
                       reviewer_email = %s,
                       review_completed_at_utc = NOW(),
                       review_notes = COALESCE(%s, review_notes),
                       override_reason = COALESCE(%s, override_reason),
                       override_acknowledged_legal_risk =
                           COALESCE(%s, override_acknowledged_legal_risk)
                 WHERE id = %s
             RETURNING id, case_id, artifact_kind, artifact_sha256,
                       status, reviewer_email, review_notes,
                       override_reason, override_acknowledged_legal_risk,
                       review_completed_at_utc
                """,
                (
                    new_status, reviewer_email, review_notes,
                    override_reason, override_acknowledged_legal_risk,
                    review_id,
                ),
            )
            row = cur.fetchone()
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("review status update failed (id=%s): %s",
                    review_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="review update failed",
        ) from None

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"review id {review_id} not found",
        )
    return {
        "id": row[0],
        "case_id": str(row[1]),
        "artifact_kind": row[2],
        "artifact_sha256": row[3],
        "status": row[4],
        "reviewer_email": row[5],
        "review_notes": row[6],
        "override_reason": row[7],
        "override_acknowledged_legal_risk": row[8],
        "review_completed_at_utc": (
            row[9].isoformat() if row[9] is not None else None
        ),
    }


@router.post("/{review_id}/approve",
             summary="Approve an awaiting_review row")
def approve_review(
    review_id: int,
    req: ApproveRequest,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    result = _update_status(
        review_id=review_id,
        new_status=REVIEW_STATUS_APPROVED,
        reviewer_email=req.reviewer_email,
        review_notes=req.review_notes,
    )
    log.info(
        "review APPROVED — id=%s reviewer=%s artifact=%s/%s",
        review_id, req.reviewer_email,
        result["artifact_kind"], result["artifact_sha256"][:8],
    )
    return result


@router.post("/{review_id}/reject",
             summary="Reject an awaiting_review row")
def reject_review(
    review_id: int,
    req: RejectRequest,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    result = _update_status(
        review_id=review_id,
        new_status=REVIEW_STATUS_REJECTED,
        reviewer_email=req.reviewer_email,
        review_notes=req.review_notes,
    )
    log.info(
        "review REJECTED — id=%s reviewer=%s artifact=%s/%s notes=%r",
        review_id, req.reviewer_email,
        result["artifact_kind"], result["artifact_sha256"][:8],
        req.review_notes[:120],
    )
    return result


@router.post("/{review_id}/override",
             summary="Override the gate (audited)")
def override_review(
    review_id: int,
    req: OverrideRequest,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    result = _update_status(
        review_id=review_id,
        new_status=REVIEW_STATUS_OVERRIDDEN,
        reviewer_email=req.reviewer_email,
        review_notes=None,
        override_reason=req.override_reason,
        override_acknowledged_legal_risk=req.override_acknowledged_legal_risk,
    )
    log.warning(
        "review OVERRIDDEN — id=%s reviewer=%s artifact=%s/%s reason=%r",
        review_id, req.reviewer_email,
        result["artifact_kind"], result["artifact_sha256"][:8],
        req.override_reason[:120],
    )
    return result


__all__ = ("router",)
