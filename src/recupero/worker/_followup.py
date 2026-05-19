"""Weekly follow-up status emails for Tier-2 engagements.

The Tier-2 engagement letter commits to "weekly status reports in
writing for 30 days from the engagement date". This module is
what fulfills that commitment automatically — a daily cron entry
that finds eligible engagements and sends each one's victim a
short status email.

Eligibility (computed by ``find_followups_due``):
  * engagement_started_at IS NOT NULL  (operator has marked
    engagement active)
  * engagement_closed_at IS NULL       (engagement still open)
  * engagement_started_at < NOW() - INTERVAL '30 days' is FALSE
    (still within the 30-day commitment window)
  * last_followup_sent_at IS NULL OR < NOW() - INTERVAL '6 days'
    (we haven't sent in the last 6 days — 6 not 7 so the cadence
    doesn't drift later in the day each week)

For each eligible row, the cron:
  1. Renders a follow-up HTML from the template using
     case + investigation + emails_sent audit log data
  2. Sends it via worker/_email.send_email (with idempotency check
     skipped for this type since followups are intentionally
     time-windowed instead of one-shot)
  3. Updates investigations.last_followup_sent_at on success

The cron is wired into the existing worker CLI via a new
``--send-followups`` flag.

Operator note
-------------

Engagement activation is currently a manual SQL update by the
operator:

    UPDATE investigations
       SET engagement_started_at = NOW(),
           engagement_fee_paid_usd = 10000
     WHERE id = '<inv_id>';

Once Jacob's admin UI surfaces this control, the workflow becomes
a button click. For now, the SQL approach is fine for the first
N engagements.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from jinja2 import Environment, FileSystemLoader, select_autoescape
from psycopg.rows import dict_row

log = logging.getLogger(__name__)

# Templates live with the other letter templates.
_TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent / "reports" / "templates"
)

# Commitment window: 30 days from engagement_started_at
_ENGAGEMENT_WINDOW_DAYS = 30
# Cadence: send every 6 days (slightly under 7 so the time-of-day
# doesn't drift later week-over-week)
_FOLLOWUP_CADENCE_DAYS = 6


@dataclass
class FollowupCandidate:
    """One engagement row that's due for a follow-up email."""
    investigation_id: UUID
    case_id: UUID | None
    victim_email: str
    victim_name: str
    engagement_started_at: datetime
    last_followup_sent_at: datetime | None
    chain: str
    seed_address: str
    freezable_issuers: list[str] | None


def find_followups_due(*, dsn: str) -> list[FollowupCandidate]:
    """Query the DB for engagements that need a follow-up email
    sent now. Returns a list of FollowupCandidate, possibly empty.
    """
    sql = """
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
         WHERE i.engagement_started_at IS NOT NULL
           AND i.engagement_closed_at IS NULL
           AND i.engagement_started_at > NOW() - make_interval(days => %(window)s)
           AND (i.last_followup_sent_at IS NULL
                OR i.last_followup_sent_at < NOW() - make_interval(days => %(cadence)s))
           AND c.client_email IS NOT NULL
         ORDER BY i.last_followup_sent_at ASC NULLS FIRST
    """
    out: list[FollowupCandidate] = []
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            sql,
            {"window": _ENGAGEMENT_WINDOW_DAYS,
             "cadence": _FOLLOWUP_CADENCE_DAYS},
        )
        for r in cur.fetchall():
            out.append(FollowupCandidate(
                investigation_id=r["investigation_id"],
                case_id=r["case_id"],
                victim_email=r["victim_email"] or "",
                victim_name=r["victim_name"] or "Client",
                engagement_started_at=r["engagement_started_at"],
                last_followup_sent_at=r["last_followup_sent_at"],
                chain=r["chain"] or "ethereum",
                seed_address=r["seed_address"] or "",
                freezable_issuers=r["freezable_issuers"],
            ))
    return out


def send_followup(
    *,
    candidate: FollowupCandidate,
    dsn: str,
    investigator_name: str | None = None,
    investigator_email: str | None = None,
) -> bool:
    """Render + send one follow-up email. Updates
    ``last_followup_sent_at`` on success. Returns True on success,
    False on render failure / send failure.

    v0.19.0: ``investigator_name`` / ``investigator_email`` default to
    ``None``; if unset they're resolved at call-time via
    ``recupero._common.investigator_defaults()``. Pre-v0.19.0 the
    defaults hard-coded "Alec Prostok" / "alec@recupero.io" — so an
    operator running Recupero under a different identity needed an
    extra step to override per call, and an unconfigured deploy
    signed the dev's name on every follow-up.
    """
    from recupero._common import investigator_defaults
    from recupero.worker._email import send_email

    if investigator_name is None or investigator_email is None:
        _inv = investigator_defaults()
        if investigator_name is None:
            investigator_name = _inv["INVESTIGATOR_NAME"]
        if investigator_email is None:
            investigator_email = _inv["INVESTIGATOR_EMAIL"]

    now = datetime.now(UTC)
    days_since = (now - candidate.engagement_started_at).days
    days_remaining = max(0, _ENGAGEMENT_WINDOW_DAYS - days_since)
    week_number = max(1, (days_since // 7) + 1)

    # Pull recent actions from the emails_sent audit log
    actions = _fetch_recent_actions(dsn, candidate.investigation_id)

    # Build status prose
    status_summary = _build_status_summary(
        candidate=candidate,
        recent_actions=actions,
        days_since=days_since,
    )

    next_steps = _build_next_steps(
        candidate=candidate,
        recent_actions=actions,
    )

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.3.x"

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    try:
        html = env.get_template("followup_status.html.j2").render(
            case_id=str(candidate.investigation_id),
            victim={"name": candidate.victim_name},
            investigator={"name": investigator_name,
                          "email": investigator_email},
            week_number=week_number,
            days_since_engagement=days_since,
            days_remaining=days_remaining,
            engagement_started_human=candidate.engagement_started_at.strftime("%Y-%m-%d"),
            engagement_closes_human=(
                candidate.engagement_started_at + timedelta(days=_ENGAGEMENT_WINDOW_DAYS)
            ).strftime("%Y-%m-%d"),
            status_summary_paragraph=status_summary,
            recent_actions=actions,
            compliance_responses=[],  # Operator-input via future admin UI
            next_steps=next_steps,
            generated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("followup render failed for inv=%s: %s",
                    candidate.investigation_id, exc)
        return False

    subject = (
        f"Recupero Recovery Update (Week {week_number}) — Case "
        f"{str(candidate.investigation_id)[:8]}"
    )
    preview = f"{days_remaining} days remaining in active engagement; status summary inside."

    result = send_email(
        to=candidate.victim_email,
        subject=subject,
        html=html,
        investigation_id=candidate.investigation_id,
        email_type=f"followup_w{week_number}",
        preview_text=preview,
        sent_by="worker:followup-cron",
        dsn=dsn,
    )

    if result.success:
        # Stamp last_followup_sent_at
        try:
            with psycopg.connect(dsn, autocommit=True,
                                 connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE public.investigations "
                    "   SET last_followup_sent_at = NOW() "
                    " WHERE id = %s",
                    (str(candidate.investigation_id),),
                )
            log.info(
                "sent followup-w%d to=%s inv=%s message_id=%s",
                week_number, candidate.victim_email,
                candidate.investigation_id, result.message_id,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("followup stamp failed for inv=%s: %s",
                        candidate.investigation_id, e)
        return True

    if result.skipped:
        log.info(
            "followup skipped (RECUPERO_DISABLE_EMAIL=1): inv=%s",
            candidate.investigation_id,
        )
        return False

    log.warning(
        "followup send FAILED to=%s inv=%s err=%s",
        candidate.victim_email, candidate.investigation_id, result.error,
    )
    return False


def run_followup_cron(*, dsn: str) -> dict[str, Any]:
    """Top-level entry point for the daily cron. Finds eligible
    engagements and sends followups for each.

    Returns a dict suitable for logging at INFO level:
      {"candidates": N, "sent": K, "failed": F,
       "skipped_no_email": S, "skipped_disabled": D}

    The two skipped counters distinguish:
      * skipped_no_email — case has no victim email on file (operator
        error, worth flagging)
      * skipped_disabled — RECUPERO_DISABLE_EMAIL=1 was set (intended
        no-op for local dev / dry-runs, NOT a failure)

    The cron caller uses ``failed`` to set the process exit code;
    skipped-disabled does not count as failed.
    """
    # v0.19.1 (round-12 arch-HIGH-3): canonical env_truthy so
    # ``RECUPERO_DISABLE_EMAIL=true`` (the natural shell-savvy form)
    # is honored consistently across the trace pipeline and followup
    # cron. Pre-v0.19.1 followup only accepted "1" while _email.py
    # accepted "true" — partial-mode silently sent followups while
    # the rest of the pipeline went quiet.
    from recupero._common import env_truthy
    email_disabled = env_truthy("RECUPERO_DISABLE_EMAIL")
    candidates = find_followups_due(dsn=dsn)
    sent = 0
    failed = 0
    skipped_no_email = 0
    skipped_disabled = 0

    for c in candidates:
        if not c.victim_email:
            skipped_no_email += 1
            log.warning(
                "followup skipped (no victim email): inv=%s",
                c.investigation_id,
            )
            continue
        ok = send_followup(candidate=c, dsn=dsn)
        if ok:
            sent += 1
        elif email_disabled:
            # RECUPERO_DISABLE_EMAIL was set — not a real failure.
            # The cron should exit 0 in this case so dev / dry-run
            # workflows don't trip `set -e` or cron-failure alerts.
            skipped_disabled += 1
        else:
            failed += 1

    return {
        "candidates": len(candidates),
        "sent": sent,
        "failed": failed,
        "skipped_no_email": skipped_no_email,
        "skipped_disabled": skipped_disabled,
    }


# ----- prose helpers ----- #


def _fetch_recent_actions(
    dsn: str, investigation_id: UUID,
) -> list[dict[str, str]]:
    """Pull the last N emails_sent entries for this investigation
    as an action log. Returns a list of {timestamp, description}
    dicts ordered chronologically."""
    sql = """
        SELECT sent_at, email_type, to_address, subject
          FROM public.emails_sent
         WHERE investigation_id = %s
           AND error_message IS NULL
         ORDER BY sent_at ASC
         LIMIT 50
    """
    actions: list[dict[str, str]] = []
    try:
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                             connect_timeout=10, prepare_threshold=None) as conn, conn.cursor() as cur:
            cur.execute(sql, (str(investigation_id),))
            for r in cur.fetchall():
                desc = _describe_email_action(
                    r["email_type"], r["to_address"], r["subject"],
                )
                actions.append({
                    "timestamp": r["sent_at"].strftime("%Y-%m-%d"),
                    "description": desc,
                })
    except Exception as e:  # noqa: BLE001
        log.warning("followup actions query failed: %s", e)
    return actions


def _describe_email_action(email_type: str, to_address: str, subject: str) -> str:
    """Human-readable description of an action from its email_type."""
    if email_type == "victim_summary":
        return f"Diagnostic summary + artifacts sent to you ({to_address})."
    if email_type == "engagement_letter":
        return f"Engagement letter sent for signature ({to_address})."
    if email_type == "freeze_letter":
        return f"Compliance freeze request sent to {to_address}."
    if email_type == "le_handoff":
        return f"Law-enforcement handoff package sent to {to_address}."
    if email_type.startswith("followup_w"):
        return f"Prior weekly status update sent to you ({to_address})."
    return f"Email sent to {to_address}: {subject}"


def _build_status_summary(
    *,
    candidate: FollowupCandidate,
    recent_actions: list[dict[str, str]],
    days_since: int,
) -> str:
    """Build the prose paragraph for section 1 of the followup
    email. Tailored to whether the engagement is fresh, in
    progress, or near the end of the 30-day window."""
    freeze_sent = sum(
        1 for a in recent_actions
        if "Compliance freeze request" in a["description"]
    )
    le_sent = sum(
        1 for a in recent_actions
        if "Law-enforcement handoff" in a["description"]
    )

    if days_since < 3:
        return (
            f"Your active recovery engagement has just begun "
            f"({days_since} days in). Compliance freeze letters and the "
            f"law-enforcement handoff package are being prepared for "
            f"send within the 5-business-day commitment."
        )

    parts = []
    if freeze_sent > 0:
        parts.append(
            f"Compliance freeze requests have been sent to "
            f"{freeze_sent} issuer compliance team"
            f"{'s' if freeze_sent != 1 else ''}"
        )
    else:
        parts.append("Compliance freeze requests have not yet been sent")

    if le_sent > 0:
        parts.append("the law-enforcement handoff has been delivered")
    else:
        parts.append("the law-enforcement handoff has not yet been delivered")

    return (
        f"It's been {days_since} days since your engagement began. "
        + " and ".join(parts) + ". "
        "We're continuing to follow up on the sends and tracking "
        "any developments in the case."
    )


def _build_next_steps(
    *,
    candidate: FollowupCandidate,
    recent_actions: list[dict[str, str]],
) -> list[str]:
    """Build the bulleted 'what's next this week' list. Depends on
    what has and hasn't been done yet."""
    freeze_sent = any("Compliance freeze request" in a["description"]
                     for a in recent_actions)
    le_sent = any("Law-enforcement handoff" in a["description"]
                  for a in recent_actions)

    steps: list[str] = []
    if not freeze_sent:
        steps.append(
            "Send compliance freeze requests to the identified issuers "
            "(within 5 business days of engagement)."
        )
    else:
        steps.append(
            "Follow up with the issuer compliance teams for an "
            "acknowledgement and substantive response."
        )

    if not le_sent:
        steps.append(
            "Deliver the law-enforcement handoff package to the "
            "recommended filing channels."
        )
    else:
        steps.append(
            "Coordinate with any law-enforcement officer assigned to "
            "your case if you've filed."
        )

    steps.append(
        "Watch for new on-chain activity on any of the identified "
        "perpetrator wallets."
    )
    return steps


__all__ = (
    "FollowupCandidate",
    "find_followups_due",
    "run_followup_cron",
    "send_followup",
)
