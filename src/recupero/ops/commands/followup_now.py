"""recupero-ops followup-now <inv_id> — force-send a status email.

Bypasses the 6-day cadence check in the daily cron and sends a
follow-up status email to the victim immediately. Useful when:

  * Operator has material news to share (issuer responded, LE
    engaged, recovery occurred) and wants to inform the victim
    sooner than the next scheduled cadence
  * Operator just activated the engagement and wants to send the
    first weekly status right away rather than waiting for the
    next cron firing
  * Operator is testing the follow-up rendering for a specific case

Confirmation prompt before sending. Updates ``last_followup_sent_at``
on success so the next cadence calculation starts fresh from now.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def run(
    *,
    investigation_id: UUID,
    dsn: str,
    confirm: Callable[[str], bool],
) -> int:
    """Force-send a follow-up email. Returns 0 on success, 1 on
    errors / declined-by-operator."""
    # Build a FollowupCandidate from the row
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            """
                SELECT i.id            AS investigation_id,
                       i.case_id       AS case_id,
                       i.chain         AS chain,
                       i.seed_address  AS seed_address,
                       i.engagement_started_at,
                       i.last_followup_sent_at,
                       i.freezable_issuers,
                       c.client_email  AS victim_email,
                       c.client_name   AS victim_name
                  FROM public.investigations i
                  LEFT JOIN public.cases c ON c.id = i.case_id
                 WHERE i.id = %s
                """,
            (str(investigation_id),),
        )
        row = cur.fetchone()
        if not row:
            print(f"ERROR: investigation {investigation_id} not found")
            return 1

    if not row["engagement_started_at"]:
        print(
            f"ERROR: investigation {investigation_id} has no active engagement.\n"
            "Use `recupero-ops mark-engaged` first."
        )
        return 1

    if not row["victim_email"]:
        print(
            f"ERROR: investigation {investigation_id} has no victim email "
            "on file (cases.client_email is null). Cannot send."
        )
        return 1

    # Confirmation
    print("=" * 72)
    print(f"FOLLOW-UP NOW — Investigation {investigation_id}")
    print("=" * 72)
    print(f"  To:              {row['victim_email']}")
    print(f"  Victim name:     {row['victim_name']}")
    print(f"  Engagement started: {row['engagement_started_at']}")
    print(f"  Last followup:   {row['last_followup_sent_at'] or '(none yet)'}")
    print()
    if not confirm(
        "Send follow-up status email NOW (bypassing 6-day cadence)?",
        default=False,
    ):
        print("Cancelled.")
        return 1

    # Build the candidate + send via the existing follow-up path
    from recupero.worker._followup import FollowupCandidate, send_followup
    candidate = FollowupCandidate(
        investigation_id=row["investigation_id"],
        case_id=row["case_id"],
        victim_email=row["victim_email"],
        victim_name=row["victim_name"] or "Client",
        engagement_started_at=row["engagement_started_at"],
        last_followup_sent_at=row["last_followup_sent_at"],
        chain=row["chain"] or "ethereum",
        seed_address=row["seed_address"] or "",
        freezable_issuers=row["freezable_issuers"],
    )

    # If email is disabled (RECUPERO_DISABLE_EMAIL truthy), don't
    # treat the skipped send as a failure for the operator's exit
    # code. send_followup returns False on skip OR fail; we check
    # the env directly to distinguish. v0.19.1 (round-12 arch-HIGH-3):
    # canonical env_truthy honors "1" / "true" / "yes" / "on" so an
    # operator setting RECUPERO_DISABLE_EMAIL=true in their .env
    # doesn't trip an "OK but no send" log line on ops invocations.
    from recupero._common import env_truthy
    email_disabled = env_truthy("RECUPERO_DISABLE_EMAIL")

    ok = send_followup(candidate=candidate, dsn=dsn)
    if ok:
        print("OK — follow-up sent + last_followup_sent_at updated.")
        return 0
    if email_disabled:
        print(
            "SKIP — email disabled (RECUPERO_DISABLE_EMAIL=1). Would have "
            f"sent week-{(candidate.last_followup_sent_at or candidate.engagement_started_at).strftime('%U')} "
            f"status update to {candidate.victim_email}."
        )
        return 0
    print("FAIL — see logs for details.")
    return 1


__all__ = ("run",)
