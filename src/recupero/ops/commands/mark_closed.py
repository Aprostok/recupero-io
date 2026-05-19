"""recupero-ops mark-closed <inv_id> [--reason TEXT] — close engagement.

Operator runs this when an engagement reaches a terminal state:
funds recovered (success), victim withdrew, 30-day commitment
window elapsed, or the engagement was determined unworkable.

Stops the follow-up cron from sending further status emails for
this investigation. The engagement state is preserved (start time,
fees paid) for audit; only ``engagement_closed_at`` is added.

The reason is recorded in ``change_summary`` (appended, not
replaced) so the operator can re-open later and re-trace the
history.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def run(*, investigation_id: UUID, reason: str, dsn: str) -> int:
    """Close an active engagement. Returns 0 on success, 1 on
    errors / no-active-engagement."""
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, engagement_started_at, engagement_closed_at, "
            "       change_summary "
            "  FROM public.investigations WHERE id = %s",
            (str(investigation_id),),
        )
        row = cur.fetchone()
        if not row:
            print(f"ERROR: investigation {investigation_id} not found")
            return 1

        if not row["engagement_started_at"]:
            print(
                f"ERROR: investigation {investigation_id} has no active engagement. "
                "Use `recupero-ops mark-engaged` first."
            )
            return 1

        if row["engagement_closed_at"]:
            print(
                f"NOTE: engagement already closed "
                f"(closed_at={row['engagement_closed_at']}). No change."
            )
            return 0

        # change_summary is jsonb — append a structured event to
        # the existing array (or create a new array). The schema
        # accepts either an array or an object; arrays are
        # friendlier for audit-trail use (one event per close
        # action), so we use that convention.
        now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        new_event = {
            "ts": now_iso,
            "action": "engagement_closed",
            "reason": reason,
        }
        existing = row["change_summary"]
        if isinstance(existing, list):
            events = existing + [new_event]
        elif isinstance(existing, dict):
            # Existing single-event shape — promote to array
            events = [existing, new_event]
        else:
            events = [new_event]

        cur.execute(
            """
                UPDATE public.investigations
                   SET engagement_closed_at = NOW(),
                       change_summary = %s::jsonb
                 WHERE id = %s
                RETURNING engagement_closed_at
                """,
            (json.dumps(events), str(investigation_id)),
        )
        updated = cur.fetchone()

    print(
        f"OK — engagement closed for {investigation_id}\n"
        f"     closed_at: {updated['engagement_closed_at']}\n"
        f"     reason:    {reason}\n"
        f"     follow-up cron will no longer send status updates for this case."
    )
    return 0


__all__ = ("run",)
