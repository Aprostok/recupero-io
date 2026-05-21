"""Post-webhook intake side effects (v0.25.0).

After the Stripe webhook dispatcher creates an investigation from
a diagnostic payment, this module:

  1. Looks up the case's client_email
  2. Mints a portal token so the victim can track case progress
  3. Sends a confirmation email with the portal URL

Called by the dispatcher AFTER `conn.commit()` so a failed email
or token-mint cannot roll back the investigation creation. The
investigation is the source of truth for the worker pipeline;
notifications are downstream bookkeeping.

Failure mode: every function returns None on error and logs at
WARN. The dispatcher logs the side-effect outcome in the payments
row's `notes` column, so a failed notification is auditable.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class IntakeConfirmationResult:
    """Outcome of the post-webhook side-effect chain.

    Always returned (never raises) so the dispatcher can log it
    without a try/except wrapper at the call site.
    """
    success: bool
    portal_url: str | None
    email_sent: bool
    error: str | None


def send_intake_confirmation(
    *,
    case_id: UUID,
    investigation_id: UUID,
    dsn: str,
) -> IntakeConfirmationResult:
    """Mint a portal token + send the confirmation email to the
    victim. Best-effort: returns a structured result regardless of
    success, never raises.

    The portal URL goes in the email body so the victim can bookmark
    it and watch case progress in real time. The link is bearer-
    auth'd via the standard portal/tokens.verify_token flow.
    """
    # 1. Look up client_email + client_name from the cases row.
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return IntakeConfirmationResult(
            success=False, portal_url=None, email_sent=False,
            error="psycopg not installed",
        )

    from recupero._common import db_connect

    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_email, client_name, case_number
                  FROM public.cases
                 WHERE id = %s
                """,
                (str(case_id),),
            )
            row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "send_intake_confirmation: case lookup failed for "
            "case_id=%s: %s", case_id, exc,
        )
        return IntakeConfirmationResult(
            success=False, portal_url=None, email_sent=False,
            error="case lookup failed",
        )

    if not row:
        log.warning(
            "send_intake_confirmation: case %s not found", case_id,
        )
        return IntakeConfirmationResult(
            success=False, portal_url=None, email_sent=False,
            error=f"case {case_id} not found",
        )

    client_email = row[0]
    client_name = row[1] or "there"
    case_number = row[2] or str(case_id)[:8]

    if not client_email:
        log.warning(
            "send_intake_confirmation: case %s has no client_email; "
            "cannot send confirmation", case_id,
        )
        return IntakeConfirmationResult(
            success=False, portal_url=None, email_sent=False,
            error="case has no client_email on file",
        )

    # 2. Mint a portal token for the case.
    token_id_for_cleanup: UUID | None = None
    try:
        from recupero.portal.tokens import generate_token, public_portal_url
        _token_id, token, _expires_at = generate_token(
            case_id=case_id, dsn=dsn,
            label="intake-confirmation",
        )
        token_id_for_cleanup = _token_id
        portal_url = public_portal_url(token=token)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "send_intake_confirmation: portal token mint failed for "
            "case %s: %s", case_id, exc,
        )
        return IntakeConfirmationResult(
            success=False, portal_url=None, email_sent=False,
            error="portal token mint failed",
        )

    # 3. Build + send the confirmation email.
    subject = f"Recupero — Case {case_number} received, trace starting"
    html_body = _build_confirmation_html(
        client_name=client_name,
        case_number=case_number,
        portal_url=portal_url,
    )
    preview_text = (
        f"Your case {case_number} is in queue. We'll start tracing your "
        "stolen funds within minutes and email you the report when ready."
    )

    try:
        from recupero.worker._email import send_email
        result = send_email(
            to=client_email,
            subject=subject,
            html=html_body,
            investigation_id=investigation_id,
            email_type="intake_confirmation",
            preview_text=preview_text,
            sent_by="dispatcher:diagnostic-webhook",
            dsn=dsn,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "send_intake_confirmation: send_email crashed for case %s: %s",
            case_id, exc,
        )
        # v0.25.1 (HIGH C-2): orphaned token cleanup — the bearer
        # credential is in the DB but the victim never received it.
        # Revoke so it can't be brute-forced from logs / DB leaks.
        _revoke_orphan_token(token_id_for_cleanup, dsn)
        return IntakeConfirmationResult(
            success=False, portal_url=portal_url, email_sent=False,
            error="send_email crashed",
        )

    # v0.25.1 (HIGH E-1): in dev / CI (`RECUPERO_DISABLE_EMAIL=1`),
    # send_email returns `success=False, skipped=True`. Treat that as
    # a clean no-op rather than a failure — otherwise every CI smoke
    # test logs WARN and pollutes monitoring with false positives.
    if not result.success and getattr(result, "skipped", False):
        log.info(
            "send_intake_confirmation: email skipped "
            "(RECUPERO_DISABLE_EMAIL) for case=%s; portal_url=%s",
            case_id, portal_url,
        )
        return IntakeConfirmationResult(
            success=True, portal_url=portal_url, email_sent=False,
            error=None,
        )

    if not result.success:
        log.warning(
            "send_intake_confirmation: send_email failed for case %s: %s",
            case_id, result.error,
        )
        # v0.25.1 (HIGH C-2): see above.
        _revoke_orphan_token(token_id_for_cleanup, dsn)
        return IntakeConfirmationResult(
            success=False, portal_url=portal_url, email_sent=False,
            error=result.error,
        )

    log.info(
        "send_intake_confirmation: confirmation sent for case=%s "
        "(email=%s portal_url=%s)",
        case_id, client_email, portal_url,
    )
    return IntakeConfirmationResult(
        success=True, portal_url=portal_url, email_sent=True,
        error=None,
    )


def _revoke_orphan_token(token_id: UUID | None, dsn: str) -> None:
    """v0.25.1 (HIGH C-2): best-effort cleanup of a portal token that
    was minted but whose confirmation email never reached the victim.
    The unrevoked token is a valid bearer credential the victim
    doesn't have — revoke it so a DB leak or log-scrape can't yield
    a working portal link.
    """
    if token_id is None:
        return
    try:
        from recupero.portal.tokens import revoke_token
        revoke_token(token_id=token_id, dsn=dsn)
        log.info(
            "send_intake_confirmation: revoked orphan token %s after "
            "email failure",
            token_id,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "send_intake_confirmation: failed to revoke orphan "
            "token %s: %s", token_id, exc,
        )


def _build_confirmation_html(
    *, client_name: str, case_number: str, portal_url: str,
) -> str:
    """Render the confirmation email HTML.

    Plain inline-styled HTML so it renders consistently across
    Gmail / Outlook / Apple Mail without Resend's templating layer.
    Audience: a victim who just paid $499 minutes ago and wants
    reassurance that something is happening.
    """
    import html as _html
    safe_name = _html.escape(client_name)
    safe_case = _html.escape(case_number)
    safe_portal = _html.escape(portal_url, quote=True)
    return (
        '<div style="font-family:-apple-system,BlinkMacSystemFont,'
        '\'Segoe UI\',sans-serif;max-width:560px;margin:0 auto;'
        'padding:24px;color:#111;line-height:1.55">'
        f'<p style="font-size:13px;color:#6b7280;text-transform:uppercase;'
        'letter-spacing:0.10em;margin:0 0 8px">Recupero · Investigation Services</p>'
        f'<h2 style="font-size:22px;margin:0 0 14px">Your case is in queue, {safe_name}</h2>'
        f'<p style="font-size:15px;margin:0 0 18px">'
        f'We received your payment and have created case <strong>{safe_case}</strong>. '
        'A forensic on-chain trace is starting in the next few minutes; '
        'the full result will be in your inbox within 24 hours.</p>'
        '<p style="margin:24px 0">'
        f'<a href="{safe_portal}" '
        'style="background:#1e3a8a;color:#fff;padding:12px 22px;'
        'text-decoration:none;border-radius:6px;font-weight:600;'
        'display:inline-block">View case status</a>'
        '</p>'
        '<p style="font-size:14px;color:#374151;margin:18px 0">'
        '<strong>What happens next:</strong></p>'
        '<ol style="font-size:14px;color:#374151;padding-left:22px;margin:0 0 18px">'
        '<li>Within minutes — our worker picks up your case and starts the trace.</li>'
        '<li>Within 24 hours — you receive the forensic report with where your funds went, '
        'whether they are recoverable, and a recovery probability score.</li>'
        '<li>If recoverable — you can engage us to send formal freeze requests to '
        'the identified issuers / exchanges. Engagement is a separate decision; the '
        '$499 forensic is yours regardless.</li>'
        '<li>If not recoverable — we refund the $499 and tell you honestly why.</li>'
        '</ol>'
        '<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">'
        '<p style="font-size:12px;color:#6b7280;margin:0">'
        'Bookmark the case-status link above — you can return to it any time to '
        'see the current state of your trace. We will also email you when the '
        'report is ready.</p>'
        '</div>'
    )


__all__ = (
    "IntakeConfirmationResult",
    "send_intake_confirmation",
)
