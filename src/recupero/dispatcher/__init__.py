"""Recupero dispatcher module — gates every external-facing artifact
emission behind the mandatory human-review gate (v0.32 Tier-0 gap #1).

The hard rule: NO artifact (brief, freeze letter, LE handoff,
engagement letter, subpoena, recovery snapshot, cooperation dashboard)
leaves the system without a corresponding ``brief_reviews`` row that
either:

  * has ``status='human_reviewed_approved'``, OR
  * has ``status='overridden_unreviewed'`` with a documented
    ``override_reason`` (which writes a permanent audit row and
    logs a WARN).

Every other status — ``awaiting_review``, ``reviewer_assigned``,
``human_reviewed_rejected`` — REFUSES the emission.

The dispatcher's job is to be the LAST gate before any
``email_dispatch()``, ``webhook_dispatch()``, or ``bucket_upload()``
call for case artifacts.

Local-dev / test-runs without a DSN skip the gate (with a WARN log)
so the test suite + local iteration aren't blocked. The DSN-present
production path is the only one that enforces.
"""

from __future__ import annotations

from recupero.dispatcher.review_gate import (
    ARTIFACT_KINDS,
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_AWAITING,
    REVIEW_STATUS_OVERRIDDEN,
    REVIEW_STATUS_REJECTED,
    REVIEW_STATUS_REVIEWER_ASSIGNED,
    BriefNotReviewedError,
    classify_artifact_kind,
    compute_sha256,
    create_review_row,
    insert_review_rows_for_deliverables,
    require_review_approved,
)
from recupero.dispatcher.sla import (
    DEFAULT_SLA_HOURS,
    run_review_sla_job,
    scan_overdue_reviews,
)

__all__ = (
    "ARTIFACT_KINDS",
    "DEFAULT_SLA_HOURS",
    "REVIEW_STATUS_APPROVED",
    "REVIEW_STATUS_AWAITING",
    "REVIEW_STATUS_OVERRIDDEN",
    "REVIEW_STATUS_REJECTED",
    "REVIEW_STATUS_REVIEWER_ASSIGNED",
    "BriefNotReviewedError",
    "classify_artifact_kind",
    "compute_sha256",
    "create_review_row",
    "insert_review_rows_for_deliverables",
    "require_review_approved",
    "run_review_sla_job",
    "scan_overdue_reviews",
)
