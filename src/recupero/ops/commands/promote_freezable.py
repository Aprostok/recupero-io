"""recupero-ops promote-freezable <watchlist_id> --reason "..."

Flip a watchlist row from INVESTIGATE to FREEZABLE, recording who
promoted it and why. Sets:

  * is_freezeable = TRUE
  * kyc_confirmed_at = NOW()
  * kyc_confirmed_by_operator = <operator identifier>
  * kyc_confirmation_note = <required free-form reason>

Typical trigger: an issuer's compliance team responds confirming
that they host the address ("yes, this is a Circle-controlled
USDC wallet, here is the KYC packet number..."). The operator
then runs:

    recupero-ops promote-freezable 9a8b7c6d-... \\
        --reason "Circle confirmed KYC on 2026-05-20 via ticket #123"

After promotion, the watchlist row is included in the FREEZABLE
list on the dashboard + becomes eligible for the next
``send-freeze-letters`` run on the parent investigation.

Idempotency: re-running on an already-freezeable row prints a
warning and does NOT overwrite the existing kyc_* columns —
that would lose the original promotion audit trail. Use
`--force` to overwrite (e.g., if the operator-name typo'd).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def run(
    *,
    watchlist_id: UUID,
    reason: str,
    force: bool,
    dsn: str,
    confirm: Callable[[str], bool],
) -> int:
    """Promote a watchlist row to FREEZABLE. Returns 0 on success."""
    operator = os.environ.get("RECUPERO_OPS_OPERATOR", "").strip() or "unknown"

    if len(reason.strip()) < 10:
        print(
            "ERROR: --reason must be at least 10 characters. The audit "
            "trail needs enough context to re-verify the promotion "
            "later (issuer ticket number, email thread, etc.)."
        )
        return 1

    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            """
                SELECT id, chain, address, status, is_freezeable,
                       issuer, last_balance_usd,
                       kyc_confirmed_at, kyc_confirmed_by_operator,
                       kyc_confirmation_note
                  FROM public.watchlist
                 WHERE id = %s
                """,
            (str(watchlist_id),),
        )
        row = cur.fetchone()
        if not row:
            print(f"ERROR: watchlist row {watchlist_id} not found")
            return 1

        if row["is_freezeable"]:
            if not force:
                print(
                    f"NOTE: watchlist {watchlist_id} is already FREEZABLE.\n"
                    f"      Original promotion:\n"
                    f"        at:    {row['kyc_confirmed_at']}\n"
                    f"        by:    {row['kyc_confirmed_by_operator']}\n"
                    f"        note:  {row['kyc_confirmation_note']}\n"
                    "      Pass --force to overwrite the audit columns."
                )
                return 0

        # Surface what we're about to do.
        print(
            f"About to promote watchlist row to FREEZABLE:\n"
            f"  chain:   {row['chain']}\n"
            f"  address: {row['address']}\n"
            f"  status:  {row['status']}\n"
            f"  issuer:  {row['issuer'] or '(unknown)'}\n"
            f"  balance: ${row['last_balance_usd'] or 0}\n"
            f"  reason:  {reason}\n"
            f"  by:      {operator}"
        )
        if not confirm("Promote to FREEZABLE?"):
            print("Aborted — no changes.")
            return 0

        cur.execute(
            """
                UPDATE public.watchlist
                   SET is_freezeable = TRUE,
                       kyc_confirmed_at = NOW(),
                       kyc_confirmed_by_operator = %s,
                       kyc_confirmation_note = %s
                 WHERE id = %s
                RETURNING kyc_confirmed_at
                """,
            (operator, reason, str(watchlist_id)),
        )
        updated = cur.fetchone()

    print(
        f"\nOK — watchlist {watchlist_id} promoted to FREEZABLE\n"
        f"     confirmed_at: {updated['kyc_confirmed_at']}\n"
        f"     by:           {operator}\n"
        f"\nNext step: run "
        f"`recupero-ops send-freeze-letters <investigation_id>` "
        f"to send the compliance request to this issuer."
    )
    return 0


__all__ = ("run",)
