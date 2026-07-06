"""Tenant maintenance: completion-metering + plan-based case retention.

Two idempotent operations, safe to run repeatedly from the cron scheduler
(``platform_maintenance`` job) or by hand. Both are connection-injected like the
rest of ``platform.store`` so the caller owns the transaction scope.

``reconcile_completed_traces``
    Append a ``trace_completed`` usage_event for every investigation the worker
    has finished (status = ``complete``) that does not already have one. This is
    deliberately DECOUPLED from the worker's hot path — no surgery in
    ``worker.db.mark_completed``. The metering is derived from the queue's own
    terminal state, so it is correct across worker restarts, backfills, and
    re-traces, and a double-run inserts nothing (the ``NOT EXISTS`` guard makes
    it idempotent). ``trace_submitted`` (metered at enqueue, drives quota) and
    ``trace_completed`` (metered here, drives billing/analytics of *delivered*
    work) are the two halves of the usage ledger.

``purge_expired_cases``
    Delete finished investigations older than the owning org's plan retention
    window (``tenancy.Plan.retention_days``). Every FK that points at
    ``investigations`` is ``ON DELETE SET NULL`` or ``ON DELETE CASCADE`` (see
    migrations 001/005/008/010/011/012/013/019), so the delete is referentially
    safe. Append-only ``usage_events`` are intentionally NOT deleted — billing
    history must outlive the case artifacts it describes. The legacy/system org
    is on the ``enterprise`` plan (3650-day window), so pre-tenancy rows are
    never purged in practice.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from recupero.platform import tenancy

# Worker terminal success state (see recupero.worker.db) — only completed jobs
# are metered as delivered work; 'failed' jobs are eligible for retention purge
# but are never metered as completed.
_COMPLETED = "complete"


def reconcile_completed_traces(conn: Any) -> int:
    """Meter every finished-but-unmetered trace. Idempotent. Returns rows added."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.usage_events (org_id, kind, quantity, investigation_id) "
            "SELECT i.org_id, 'trace_completed', 1, i.id "
            "FROM public.investigations i "
            "WHERE i.status = %s AND i.org_id IS NOT NULL "
            "AND NOT EXISTS ("
            "    SELECT 1 FROM public.usage_events u "
            "    WHERE u.investigation_id = i.id AND u.kind = 'trace_completed') "
            "RETURNING id",
            (_COMPLETED,),
        )
        return len(cur.fetchall())


def retention_cutoffs(now: datetime | None = None) -> dict[str, datetime]:
    """Pure policy: plan name → the timestamp before which finished cases are
    expired. Derived from ``tenancy.PLANS`` so the retention window lives in ONE
    place (the plan definition), not duplicated in SQL."""
    ref = now if now is not None else datetime.now(tz=UTC)
    return {
        name: ref - timedelta(days=plan.retention_days)
        for name, plan in tenancy.PLANS.items()
    }


def purge_expired_cases(conn: Any, *, now: datetime | None = None) -> int:
    """Delete finished investigations past their org plan's retention window.
    Returns rows deleted. One parameterized DELETE per plan (policy stays in
    Python; the SQL is static and fully parameterized)."""
    deleted = 0
    with conn.cursor() as cur:
        for plan_name, cutoff in retention_cutoffs(now).items():
            cur.execute(
                "DELETE FROM public.investigations i "
                "USING public.organizations o "
                "WHERE i.org_id = o.id AND o.plan = %s "
                "AND i.status IN ('complete', 'failed') "
                "AND i.created_at < %s",
                (plan_name, cutoff),
            )
            deleted += cur.rowcount
    return deleted


def run_maintenance(conn: Any, *, now: datetime | None = None) -> dict[str, int]:
    """Run both maintenance passes in the caller's transaction. Returns a
    ``{metered, purged}`` summary. The caller commits."""
    metered = reconcile_completed_traces(conn)
    purged = purge_expired_cases(conn, now=now)
    return {"metered": metered, "purged": purged}


__all__ = (
    "reconcile_completed_traces",
    "retention_cutoffs",
    "purge_expired_cases",
    "run_maintenance",
)
