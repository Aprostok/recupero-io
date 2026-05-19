"""recupero-ops mark-engaged <inv_id> [--fee 10000] — activate Tier-2.

Operator runs this when a victim signs the engagement letter and
pays the incremental engagement fee. Sets engagement_started_at
+ engagement_fee_paid_usd on the investigation row, which
activates the daily follow-up cron for this case.

Idempotent: running twice doesn't reset the start time (the
follow-up cron uses engagement_started_at as the t=0 anchor for
the 30-day commitment, so resetting it would extend the
commitment window).
"""

from __future__ import annotations

import logging
from decimal import Decimal
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def run(*, investigation_id: UUID, fee_usd: Decimal, dsn: str) -> int:
    """Mark an investigation as Tier-2 engaged. Returns 0 on success,
    1 on errors (missing investigation, etc.)."""
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, status, engagement_started_at, engagement_closed_at "
            "  FROM public.investigations WHERE id = %s",
            (str(investigation_id),),
        )
        row = cur.fetchone()
        if not row:
            print(f"ERROR: investigation {investigation_id} not found")
            return 1

        if row["engagement_started_at"] and not row["engagement_closed_at"]:
            print(
                f"NOTE: engagement already active "
                f"(started_at={row['engagement_started_at']}). "
                f"No change made — idempotent."
            )
            return 0

        if row["engagement_closed_at"]:
            print(
                f"NOTE: investigation has a closed engagement "
                f"(closed_at={row['engagement_closed_at']}). "
                "Re-opening by clearing engagement_closed_at + "
                "setting fresh engagement_started_at."
            )

        cur.execute(
            """
                UPDATE public.investigations
                   SET engagement_started_at = NOW(),
                       engagement_closed_at = NULL,
                       engagement_fee_paid_usd = %s,
                       last_followup_sent_at = NULL
                 WHERE id = %s
                RETURNING engagement_started_at, engagement_fee_paid_usd
                """,
            (fee_usd, str(investigation_id)),
        )
        updated = cur.fetchone()

    print(
        f"OK — engagement activated for {investigation_id}\n"
        f"     started_at: {updated['engagement_started_at']}\n"
        f"     fee paid:   ${updated['engagement_fee_paid_usd']}\n"
        f"     first follow-up will be sent on the next "
        f"`recupero-worker --send-followups` cron run."
    )
    return 0


__all__ = ("run",)
