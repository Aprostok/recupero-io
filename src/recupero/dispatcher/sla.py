"""24h SLA enforcement for the human-review queue (v0.32 Tier-0 gap #1).

A review row in status='awaiting_review' that's older than 24 hours
indicates the operator-on-call missed it. This module's
``scan_overdue_reviews`` returns the offending rows so the cron
scheduler can page on-call.

This is a separate module so the cron-side import surface stays
small (no FastAPI, no Pydantic) — keeps the cron container's
startup cost low.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from recupero.dispatcher.review_gate import REVIEW_STATUS_AWAITING

log = logging.getLogger(__name__)


# Default SLA. Operators that want to tune this can set
# RECUPERO_REVIEW_SLA_HOURS in the environment; missing/invalid
# fall back to 24h.
DEFAULT_SLA_HOURS = 24


def _resolve_sla_hours() -> int:
    raw = (os.environ.get("RECUPERO_REVIEW_SLA_HOURS", "") or "").strip()
    if not raw:
        return DEFAULT_SLA_HOURS
    try:
        h = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_SLA_HOURS
    if h < 1 or h > 24 * 30:
        # 1h-720h (30d) sanity envelope; outside that, ignore.
        return DEFAULT_SLA_HOURS
    return h


def scan_overdue_reviews(
    *,
    dsn: str | None = None,
    now: datetime | None = None,
    sla_hours: int | None = None,
) -> list[dict[str, Any]]:
    """Return brief_reviews rows still in status='awaiting_review'
    that were created more than ``sla_hours`` ago.

    Returns an empty list (and logs a warning) when no DSN is set —
    consistent with the rest of the dispatcher module's behavior in
    local dev.
    """
    dsn = dsn or (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        log.warning(
            "scan_overdue_reviews: SUPABASE_DB_URL unset — skipping "
            "(local dev / test mode)",
        )
        return []

    sla_hours = sla_hours or _resolve_sla_hours()
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=sla_hours)

    overdue: list[dict[str, Any]] = []
    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, case_id, artifact_kind, artifact_path,
                       artifact_sha256, created_at_utc
                  FROM public.brief_reviews
                 WHERE status = %s
                   AND created_at_utc < %s
                 ORDER BY created_at_utc ASC
                """,
                (REVIEW_STATUS_AWAITING, cutoff),
            )
            for r in cur.fetchall():
                overdue.append({
                    "id": r[0],
                    "case_id": str(r[1]),
                    "artifact_kind": r[2],
                    "artifact_path": r[3],
                    "artifact_sha256": r[4],
                    "created_at_utc": (
                        r[5].isoformat() if r[5] is not None else None
                    ),
                    "age_hours": (
                        (now - r[5]).total_seconds() / 3600.0
                        if r[5] is not None else None
                    ),
                })
    except Exception as exc:  # noqa: BLE001
        log.warning("scan_overdue_reviews: DB query failed: %s", exc)
        return []
    if overdue:
        log.warning(
            "review-SLA: %d row(s) overdue past %dh SLA",
            len(overdue), sla_hours,
        )
    return overdue


def run_review_sla_job(*, dsn: str | None = None) -> int:
    """Cron entrypoint. Scans for overdue rows + emits a structured
    report (to the operator-on-call channel via stderr + log). Returns
    the count of overdue rows for testing.

    The "page operator-on-call" delivery is intentionally minimal:
    a WARN log line per overdue row. Production deploys forward the
    cron container's stderr to PagerDuty / Slack via the existing
    log-shipping pipeline — we don't need a separate alerting
    integration here.
    """
    overdue = scan_overdue_reviews(dsn=dsn)
    for row in overdue:
        log.warning(
            "review-SLA: PAGE operator-on-call — review id=%s "
            "case=%s kind=%s sha=%s age_hours=%.1f",
            row["id"], row["case_id"], row["artifact_kind"],
            row["artifact_sha256"][:8],
            row.get("age_hours") or 0.0,
        )
    return len(overdue)


__all__ = (
    "DEFAULT_SLA_HOURS",
    "run_review_sla_job",
    "scan_overdue_reviews",
)
