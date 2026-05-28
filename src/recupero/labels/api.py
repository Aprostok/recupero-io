"""FastAPI router for the label-candidate review API (v0.32).

Endpoints (all gated by ``X-Recupero-Admin-Key``):

  * ``GET    /v1/labels/candidates?status=pending_review`` — list candidates
  * ``POST   /v1/labels/candidates/{id}/promote``         — write to seed JSON
  * ``POST   /v1/labels/candidates/{id}/reject``          — requires reason

Auth: shared with the worker's review API. RECUPERO_ADMIN_KEY unset
→ every endpoint returns 503 (deny-by-default).

This is the operator-facing half of the two-stage auto-ingest
pipeline. The cron job (``recupero.labels.auto_ingest.run_daily_pull``)
writes candidates with ``status='pending_review'``; the operator
calls these endpoints to promote or reject. We do NOT auto-promote
— a tag-spammer would otherwise inject bogus "labels" into our
operator output.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from recupero.labels import auto_ingest

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/labels", tags=["labels"])


# ─────────────────────────────────────────────────────────────────────────────
# Auth (shared shape with dispatcher/review_api.py)
# ─────────────────────────────────────────────────────────────────────────────


def _require_admin_auth(provided: str | None) -> None:
    """Constant-time match against ``RECUPERO_ADMIN_KEY``.

    Raises 503 when no admin key is configured (deny-by-default), 401
    when the header is missing/invalid. Same shape as
    ``dispatcher.review_api._require_admin_auth`` — could share, but
    duplicating keeps the labels module standalone-importable.
    """
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "label-candidates API disabled — set RECUPERO_ADMIN_KEY "
                "to enable"
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


def _dsn_or_503() -> str:
    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="label-candidates API unavailable: DSN not configured",
        )
    return dsn


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────


class PromoteRequest(BaseModel):
    reviewer_email: str = Field(..., min_length=3, max_length=254)
    # Operator-set confidence at promotion time. The candidate row
    # always carries 'low'; the operator typically promotes to
    # 'medium' (upstream tag + sanity check) or 'high' (primary-source
    # verified). Required to be explicit — leaving it as 'low' should
    # be a deliberate choice, not a defaulted afterthought.
    confidence: str = Field(default="medium")

    @field_validator("reviewer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("reviewer_email must be a valid email")
        return v

    @field_validator("confidence")
    @classmethod
    def _validate_confidence(cls, v: str) -> str:
        if v not in ("low", "medium", "high"):
            raise ValueError(
                f"confidence {v!r} must be one of low/medium/high"
            )
        return v


class RejectRequest(BaseModel):
    reviewer_email: str = Field(..., min_length=3, max_length=254)
    reason: str = Field(..., min_length=1, max_length=4000)

    @field_validator("reviewer_email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("reviewer_email must be a valid email")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/candidates",
    summary="List label candidates (default: pending_review)",
)
def list_label_candidates(
    x_recupero_admin_key: str | None = Header(default=None),
    status_filter: str = "pending_review",
    limit: int = 100,
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    dsn = _dsn_or_503()
    if status_filter not in (
        "pending_review", "promoted", "rejected", "expired",
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown status {status_filter!r} (use pending_review / "
                "promoted / rejected / expired)"
            ),
        )
    # Defensive bound.
    limit = max(1, min(int(limit or 100), 500))
    try:
        rows = auto_ingest.list_candidates(
            status=status_filter, limit=limit, dsn=dsn,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("label candidates list failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="candidate query failed",
        ) from None
    return {"candidates": rows, "count": len(rows), "status": status_filter}


@router.post(
    "/candidates/{candidate_id}/promote",
    summary="Promote a candidate; appends to bridges.json / cex_deposits.json",
)
def promote_label_candidate(
    candidate_id: int,
    req: PromoteRequest,
    x_recupero_admin_key: str | None = Header(default=None),
    x_recupero_promote_confirm: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    _dsn_or_503()  # raises 503 if unset
    # v0.32.1 CRIT-1 close-out: require the operator to echo the
    # candidate-row SHA-256 in X-Recupero-Promote-Confirm. Mismatch /
    # missing → 400 (fail closed) before any field validation.
    if (
        x_recupero_promote_confirm is None
        or not x_recupero_promote_confirm.strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "missing X-Recupero-Promote-Confirm header — "
                "must echo the sha256 of the candidate row you viewed"
            ),
        )
    try:
        result = auto_ingest.promote_candidate(
            candidate_id=candidate_id,
            reviewer=req.reviewer_email,
            confidence=req.confidence,
            confirm_sha256=x_recupero_promote_confirm.strip().lower(),
        )
    except ValueError as exc:
        # 404 for "not found", 409 for "already promoted/rejected"
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=msg,
            ) from None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=msg,
        ) from None
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "promote_candidate failed (id=%s): %s",
            candidate_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="promote failed",
        ) from None
    log.info(
        "label PROMOTED — id=%s reviewer=%s category=%s confidence=%s",
        candidate_id, req.reviewer_email,
        result.get("proposed_category"), req.confidence,
    )
    return {
        "id": result["id"],
        "address": result["address"],
        "chain": result["chain"],
        "promoted_to": result.get("promoted_to"),
        "confidence": req.confidence,
        "status": "promoted",
    }


@router.post(
    "/candidates/{candidate_id}/reject",
    summary="Reject a candidate; reason is required",
)
def reject_label_candidate(
    candidate_id: int,
    req: RejectRequest,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    _dsn_or_503()
    try:
        result = auto_ingest.reject_candidate(
            candidate_id=candidate_id,
            reviewer=req.reviewer_email,
            reason=req.reason,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=msg,
            ) from None
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=msg,
        ) from None
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "reject_candidate failed (id=%s): %s",
            candidate_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="reject failed",
        ) from None
    log.info(
        "label REJECTED — id=%s reviewer=%s reason=%r",
        candidate_id, req.reviewer_email, req.reason[:120],
    )
    return {
        "id": result["id"],
        "address": result["address"],
        "chain": result["chain"],
        "status": "rejected",
        "reason": req.reason,
    }


__all__ = ("router",)
