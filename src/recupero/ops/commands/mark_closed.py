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

# RIGOR-2: tests patch `recupero.ops.commands.mark_closed.psycopg.connect`
# via unittest.mock.patch — module-level psycopg attribute IS the
# test-mock seam. F401 false-positive; do not remove.
import psycopg  # noqa: F401
from psycopg.rows import dict_row

from recupero._common import db_connect

log = logging.getLogger(__name__)


# Z13-2/3: Maximum acceptable length for a --reason audit note.
# An operator pasting a 100KB chat log into the field would otherwise
# write a 100KB row into the change_summary jsonb column.
_MAX_REASON_LEN = 4_000


def _validate_reason(reason: str) -> str | None:
    """Validate a --reason audit note.

    Returns an error message string when the reason is invalid, or
    ``None`` when it passes. Rejects:

      * NUL bytes (psycopg silently strips or errors mid-transaction)
      * C0 / C1 control characters
      * Unicode bidi-override controls (audit-log spoofing vector)
      * Oversized notes (> _MAX_REASON_LEN chars)
    """
    if not isinstance(reason, str):
        return "ERROR: --reason must be a string"
    if len(reason) > _MAX_REASON_LEN:
        return (
            f"ERROR: --reason too long: {len(reason)} characters "
            f"(max {_MAX_REASON_LEN}). Trim the audit note to a "
            "concise sentence; longer narrative belongs in the case "
            "directory's change-log, not in change_summary."
        )
    for ch in reason:
        cp = ord(ch)
        if cp == 0:
            return (
                "ERROR: --reason contains a null byte / control "
                "character — invalid audit-log content."
            )
        # C0 controls (allow \n, \r, \t for legitimate operator notes).
        if cp < 0x20 and ch not in ("\n", "\r", "\t"):
            return (
                "ERROR: --reason contains a control character "
                f"(codepoint {cp:#06x}) — invalid audit-log content."
            )
        if cp == 0x7F or 0x80 <= cp <= 0x9F:
            return (
                "ERROR: --reason contains a control character "
                f"(codepoint {cp:#06x}) — invalid audit-log content."
            )
        if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                  0x2066, 0x2067, 0x2068, 0x2069):
            return (
                "ERROR: --reason contains a Unicode bidi-override "
                f"control (codepoint {cp:#06x}) — invalid in audit logs."
            )
    return None


def run(*, investigation_id: UUID, reason: str, dsn: str) -> int:
    """Close an active engagement. Returns 0 on success, 1 on
    errors / no-active-engagement."""
    # Z13-2: validate --reason BEFORE touching the DB so a hostile
    # note doesn't open a transaction we then have to roll back.
    err = _validate_reason(reason)
    if err is not None:
        print(err)
        return 1

    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
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
