"""recupero-ops list-payments [--limit 10] [--since 24h] [--case-id <uuid>]

Lists recent Stripe payment events from public.payments with
their workflow correlation (case_number, investigation_id) +
notes from the dispatcher. The operator's go-to command for
"did the webhook fire for case V-12345?" and "what did Stripe
report yesterday?"

Filters
-------

  --limit N
      Max rows to return (default 10). The table sorts by
      received_at DESC so this is "the N most recent payments."

  --since DURATION
      Only show payments received within the duration. Accepts
      '24h', '7d', '30d', '90d', or 'all'. Default '7d'.

  --case-id <uuid>
      Filter to one specific case. Useful when chasing down a
      specific customer's payment history.

Output shape (table form)
-------------------------

  RECEIVED              TYPE        AMOUNT       STATUS    CASE         ACTION
  2026-05-17 14:32 UTC  diagnostic  $499.00      paid      V-058868     investigation_created
  2026-05-17 14:35 UTC  engagement  $10,000.00   paid      V-058868     engagement_activated
  ...

The notes column (if non-empty) wraps below each row for
operator triage clarity.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

# RIGOR-2: tests patch `recupero.ops.commands.list_payments.psycopg.connect`
# via unittest.mock.patch — so `psycopg` MUST be a top-level module
# attribute even though we don't reference it by name directly (we
# use db_connect() from _common.py). Removing this import (ruff F401
# auto-fix did) breaks every test that mocks DB connections via this
# patch point. The pattern is intentional; not a real unused-import.
import psycopg  # noqa: F401
from psycopg.rows import dict_row

from recupero._common import db_connect

log = logging.getLogger(__name__)


# Map our --since strings to PostgreSQL interval expressions.
# 'all' skips the WHERE clause entirely.
_SINCE_TO_INTERVAL = {
    "24h": "1 day",
    "7d":  "7 days",
    "30d": "30 days",
    "90d": "90 days",
}


def run(
    *,
    limit: int,
    since: str,
    case_id: UUID | None,
    dsn: str,
) -> int:
    """Print the table + return 0 on success."""
    if limit <= 0 or limit > 1000:
        print(f"ERROR: --limit must be between 1 and 1000 (got {limit})")
        return 1

    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if since != "all":
        interval = _SINCE_TO_INTERVAL.get(since)
        if interval is None:
            print(
                f"ERROR: --since must be one of {list(_SINCE_TO_INTERVAL)} or 'all' "
                f"(got {since!r})"
            )
            return 1
        where_clauses.append(
            "p.received_at >= NOW() - INTERVAL %(interval)s"
        )
        params["interval"] = interval

    if case_id is not None:
        where_clauses.append("p.case_id = %(case_id)s")
        params["case_id"] = str(case_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT p.id, p.received_at, p.processed_at,
               p.amount_type, p.amount_cents, p.currency, p.status,
               p.stripe_event_id, p.stripe_event_type, p.notes,
               p.case_id, p.investigation_id,
               c.case_number, c.client_name
          FROM public.payments p
          LEFT JOIN public.cases c ON c.id = p.case_id
        {where_sql}
         ORDER BY p.received_at DESC
         LIMIT %(limit)s
    """
    params["limit"] = limit

    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    if not rows:
        scope = f"case {case_id}" if case_id else f"the last {since}"
        print(f"No payments found in {scope}.")
        if since != "all" and case_id is None:
            print("Pass --since all to look further back.")
        return 0

    _print_table(rows)
    print()
    print(f"Showing {len(rows)} payment(s).")
    if since != "all":
        print(f"Filter: --since {since}. Pass --since all to widen.")
    return 0


# ----- Helpers ----- #


def _print_table(rows: list[dict[str, Any]]) -> None:
    """Render the payments table. Manual formatting because
    we want monospace columns + wrapped notes per row, which is
    awkward with `rich` Table for this density."""
    header = (
        f"{'RECEIVED':<22} {'TYPE':<11} {'AMOUNT':>12} "
        f"{'STATUS':<10} {'CASE':<14} ACTION"
    )
    print()
    print(header)
    print("-" * len(header))
    for r in rows:
        received = _fmt_datetime(r["received_at"])
        amount_type = (r.get("amount_type") or "?")[:11]
        amount = _fmt_usd_cents(r["amount_cents"], r.get("currency", "usd"))
        status = (r.get("status") or "?")[:10]
        case_disp = (r.get("case_number") or "—")[:14]
        # The 'action' column reads from the notes field's leading
        # phrase: e.g., "engagement fee $10,000 recorded..." → "engagement fee"
        notes = (r.get("notes") or "").strip()
        action = _action_label(amount_type, notes)
        print(
            f"{received:<22} {amount_type:<11} {amount:>12} "
            f"{status:<10} {case_disp:<14} {action}"
        )
        if notes:
            # v0.18.9 (round-11 ops-MED-020): sanitize terminal escape
            # sequences. Pre-v0.18.9 a malicious Stripe-webhook metadata
            # payload could embed ANSI codes (\x1b[2J = clear screen)
            # into payments.notes — `recupero-ops list-payments` would
            # then wipe the operator's terminal mid-output. Now: strip
            # ESC (\x1b), CR/LF, and other control chars before printing.
            import re as _re_sanitize
            safe_notes = _re_sanitize.sub(
                r"[\x00-\x08\x0b-\x1f\x7f]", "?", notes,
            ).replace("\r", " ").replace("\n", " ")
            print(f"  └─ {safe_notes[:160]}")


def _action_label(amount_type: str, notes: str) -> str:
    """Compress notes → short action label for the table column.

    The notes field is operator-friendly prose but too long for a
    table cell. We pluck the first phrase before the first em-dash
    or semicolon and cap at 30 chars.
    """
    if not notes:
        if amount_type == "diagnostic":
            return "diagnostic-paid"
        if amount_type == "engagement":
            return "engagement-paid"
        return ""
    # Trim at first sentence boundary
    for sep in (";", " — ", "."):
        if sep in notes:
            notes = notes.split(sep, 1)[0]
            break
    return notes[:30].strip()


def _fmt_datetime(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _fmt_usd_cents(cents: int | None, currency: str) -> str:
    if cents is None:
        return "—"
    if currency.lower() != "usd":
        return f"{cents/100:,.2f} {currency.upper()}"
    return f"${cents/100:,.2f}"


__all__ = ("run",)
