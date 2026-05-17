"""recupero-ops status <inv_id> — print full investigation state.

Single-shot read-only command that shows the operator everything
they'd otherwise piece together from multiple SQL queries:

  * Investigation row metadata (status, chain, seed, timing, error)
  * Engagement state (started/closed, fee paid, last followup)
  * Emails sent for this investigation (audit log)
  * Artifact inventory from the bucket
  * Summary stats from case.json (transfers, addresses, total flow)

Output is plain text with section headers. Use ``--log-level DEBUG``
on the cli for the full row + extra detail.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row


def run(*, investigation_id: UUID, dsn: str) -> int:
    """Print investigation state to stdout. Returns 0 on success,
    1 if the investigation is not found."""
    inv = _fetch_investigation(investigation_id=investigation_id, dsn=dsn)
    if inv is None:
        print(f"ERROR: investigation {investigation_id} not found",
              file=sys.stderr)
        return 1

    case = _fetch_case(case_id=inv["case_id"], dsn=dsn) if inv["case_id"] else None
    emails = _fetch_emails(investigation_id=investigation_id, dsn=dsn)

    _print_investigation_section(inv, case)
    print()
    _print_engagement_section(inv)
    print()
    _print_emails_section(emails)
    print()
    _print_artifacts_section(investigation_id=investigation_id)

    return 0


# ----- section printers ----- #


def _print_investigation_section(inv: dict, case: dict | None) -> None:
    print("=" * 72)
    print(f"INVESTIGATION  {inv['id']}")
    print("=" * 72)
    print(f"  Status:           {inv['status']}")
    print(f"  Chain:            {inv['chain']}")
    print(f"  Seed address:     {inv['seed_address']}")
    print(f"  Max depth:        {inv['max_depth']}")
    print(f"  Skip editorial:   {inv['skip_editorial']}")
    print(f"  Skip freeze:      {inv['skip_freeze_briefs']}")
    print(f"  Triggered by:     {inv['triggered_by']}")
    print(f"  Triggered at:     {_fmt(inv['triggered_at'])}")
    print(f"  Completed at:     {_fmt(inv['completed_at'])}")
    if inv["failed_at"]:
        print(f"  FAILED at:        {_fmt(inv['failed_at'])}")
        print(f"  Error stage:      {inv['error_stage']}")
        print(f"  Error message:    {(inv['error_message'] or '')[:200]}")
    print(f"  Total loss USD:   ${inv['total_loss_usd']}")
    print(f"  Recoverable USD:  ${inv['max_recoverable_usd']}")
    print(f"  API costs USD:    ${inv['api_costs_usd']}")
    print(f"  Freezable issuers: {inv['freezable_issuers']}")

    if case:
        print()
        print(f"  Linked case:      {case['case_number']} ({case['client_name']})")
        print(f"  Case status:      {case['status']}")
        print(f"  Client email:     {case['client_email']}")
        print(f"  Country:          {case['country']}")


def _print_engagement_section(inv: dict) -> None:
    print("=" * 72)
    print("ENGAGEMENT")
    print("=" * 72)
    if not inv.get("engagement_started_at"):
        print("  Status:           NOT ENGAGED (diagnostic only)")
        print("  To activate Tier 2: `recupero-ops mark-engaged <id> [--fee 10000]`")
        return

    print(f"  Status:           {'CLOSED' if inv.get('engagement_closed_at') else 'ACTIVE'}")
    print(f"  Started at:       {_fmt(inv['engagement_started_at'])}")
    if inv.get("engagement_closed_at"):
        print(f"  Closed at:        {_fmt(inv['engagement_closed_at'])}")
    print(f"  Fee paid (USD):   ${inv.get('engagement_fee_paid_usd')}")
    print(f"  Last follow-up:   {_fmt(inv.get('last_followup_sent_at'))}")

    # Days metric only relevant for active engagements
    if not inv.get("engagement_closed_at"):
        started = inv["engagement_started_at"]
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_in = (now - started).days
        days_remaining = max(0, 30 - days_in)
        print(f"  Days into engagement: {days_in}")
        print(f"  Days remaining in 30-day window: {days_remaining}")


def _print_emails_section(emails: list[dict]) -> None:
    print("=" * 72)
    print(f"EMAILS SENT  ({len(emails)} total)")
    print("=" * 72)
    if not emails:
        print("  (no emails sent for this investigation yet)")
        return
    for e in emails:
        status = "OK" if not e["error_message"] else "FAILED"
        print(f"  [{_fmt_short(e['sent_at'])}] "
              f"{e['email_type']:18s} "
              f"-> {e['to_address']:35s} "
              f"[{status}]")
        if e["error_message"]:
            print(f"      error: {e['error_message'][:150]}")
        if e["attachments"]:
            print(f"      attached: {', '.join(e['attachments'][:5])}")


def _print_artifacts_section(*, investigation_id: UUID) -> None:
    print("=" * 72)
    print("ARTIFACTS")
    print("=" * 72)
    try:
        # Lazy import + use the existing investigations_api helper
        import os
        from recupero.worker.investigations_api import get_investigation_detail
        d = get_investigation_detail(
            dsn=os.environ.get("SUPABASE_DB_URL", ""),
            supabase_url=os.environ.get("SUPABASE_URL", "").rstrip("/"),
            service_role_key=os.environ.get("SUPABASE_SERVICE_ROLE_KEY", ""),
            investigation_id=investigation_id,
        )
        if not d:
            print("  (investigation not found by API)")
            return
        art = d["artifacts"]
        if art.get("trace_report", {}).get("html"):
            print(f"  trace_report.html: {art['trace_report']['html']['name']}")
        if art.get("trace_report", {}).get("pdf"):
            print(f"  trace_report.pdf:  {art['trace_report']['pdf']['name']}")
        if art.get("flow_diagram", {}).get("svg"):
            print(f"  flow.svg:          {art['flow_diagram']['svg']['name']}")
        if art.get("flow_diagram", {}).get("pdf"):
            print(f"  flow.pdf:          {art['flow_diagram']['pdf']['name']}")
        raw_keys = sorted(art.get("raw", {}).keys())
        if raw_keys:
            print(f"  raw bundle:        {', '.join(raw_keys)}")
        freeze_letters = art.get("freeze_letters") or []
        print(f"  freeze_letters:    {len(freeze_letters)} ({', '.join(f.get('issuer_slug','?').split()[0] for f in freeze_letters)})")
        summary = d.get("summary") or {}
        if summary:
            print()
            print(f"  Summary:           {summary.get('transfers', 0)} transfers, "
                  f"{summary.get('addresses_traced', 0)} addresses, "
                  f"total_usd_out=${summary.get('total_usd_out')}")
    except Exception as e:  # noqa: BLE001
        print(f"  (artifact listing failed: {e})")


# ----- queries ----- #


def _fetch_investigation(*, investigation_id: UUID, dsn: str) -> dict | None:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM public.investigations WHERE id = %s",
                        (str(investigation_id),))
            return cur.fetchone()


def _fetch_case(*, case_id: UUID, dsn: str) -> dict | None:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT case_number, client_name, client_email, status, country "
                "  FROM public.cases WHERE id = %s",
                (str(case_id),),
            )
            return cur.fetchone()


def _fetch_emails(*, investigation_id: UUID, dsn: str) -> list[dict]:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sent_at, email_type, to_address, subject,
                       message_id, error_message, attachments
                  FROM public.emails_sent
                 WHERE investigation_id = %s
                 ORDER BY sent_at ASC
                """,
                (str(investigation_id),),
            )
            return list(cur.fetchall())


def _fmt(dt: Any) -> str:
    if dt is None:
        return "—"
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(dt)


def _fmt_short(dt: Any) -> str:
    if dt is None:
        return "—"
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M")
    return str(dt)


__all__ = ("run",)
