"""Email-sending primitive (Resend REST API).

The worker generates customer-facing artifacts (victim summary,
engagement letter, compliance freeze letters, LE handoffs) but
until this module landed, sending them was manual operator work
— attach to email, type recipient address, hit send. For a
service company scaling past the first few cases, that's a real
drag.

This module is the lowest-level send primitive: it calls Resend's
REST API with optional file attachments and logs every attempt
(success or failure) to ``public.emails_sent`` for audit + idempotency.

Higher-level "auto-send victim summary on case completion" /
"operator-triggered freeze-letter send" wrappers live in
``worker/_deliverables.py`` and a future CLI helper. Keeping this
module narrow makes it easy to swap providers (SendGrid, Postmark)
later without rewriting the dispatch logic.

Configuration
-------------

Required env vars:
  * RESEND_API_KEY        — API key from https://resend.com
  * SUPABASE_DB_URL       — for the audit log (same DB the worker uses)

Optional env vars:
  * RECUPERO_EMAIL_FROM       — From: address (default "alec@recupero.io")
  * RECUPERO_EMAIL_FROM_NAME  — From: display name (default "Recupero Investigation Services")
  * RECUPERO_DISABLE_EMAIL    — If "1", skip sending entirely + log only.
                                For local development / testing.

Idempotency
-----------

The auto-send wrappers check the ``emails_sent`` audit log before
sending:

    SELECT 1 FROM emails_sent
     WHERE investigation_id = $1
       AND email_type = $2
       AND error_message IS NULL
     LIMIT 1

If a row matches (a previous successful send), the wrapper skips
re-sending. Failed sends DO NOT count toward idempotency — the
worker can re-attempt them on the next claim/resume cycle.
"""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg

log = logging.getLogger(__name__)


_RESEND_API_BASE = "https://api.resend.com"
_DEFAULT_FROM_ADDR = "alec@recupero.io"
_DEFAULT_FROM_NAME = "Recupero Investigation Services"

# Retry sequence (seconds) for transient Resend failures. Mirrors
# the ai_editorial retry budget so worker logs read consistently
# across email + AI transients. 4 total attempts (initial + 3
# retries) with 5s / 15s / 30s waits; tighter than the AI retry
# because we don't expect Resend to need a full minute to recover
# from a brief 5xx (their SLOs are tighter than the Anthropic
# capacity-overload events the AI retry was designed for).
_RESEND_RETRY_WAITS_SEC = (5, 15, 30)


def _resend_send_with_retry(req: urllib.request.Request) -> dict[str, Any]:
    """Send a Resend API request with retry-on-transient logic.

    Retriable: 5xx HTTP responses, urllib URLError (DNS/connect/
    timeout), socket timeout. Non-retriable: 4xx (caller bug: bad
    address, invalid template, auth) — re-raised immediately so
    the audit log captures the real error message instead of
    burning 50s on retries that will all fail the same way.

    Returns the parsed JSON response on success. Raises the
    LAST exception on exhaustion (HTTPError or URLError) so the
    existing handler in send_email can format it for the audit
    row without changes.
    """
    last_exc: BaseException | None = None
    total_attempts = len(_RESEND_RETRY_WAITS_SEC) + 1
    for attempt_idx in range(total_attempts):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # 4xx → caller bug. Don't retry — re-raise so the
            # audit row captures the right error.
            if 400 <= exc.code < 500 and exc.code != 429:
                raise
            last_exc = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
        if attempt_idx >= len(_RESEND_RETRY_WAITS_SEC):
            break
        wait_sec = _RESEND_RETRY_WAITS_SEC[attempt_idx]
        log.warning(
            "resend transient failure on attempt %d/%d — retrying in %ds: %s",
            attempt_idx + 1, total_attempts, wait_sec, last_exc,
        )
        time.sleep(wait_sec)
    assert last_exc is not None
    raise last_exc


@dataclass(frozen=True)
class EmailResult:
    """Outcome of a single send attempt. Always logged regardless
    of success/failure; the audit row's error_message disambiguates."""
    success: bool
    message_id: str | None
    error: str | None
    skipped: bool = False  # True when RECUPERO_DISABLE_EMAIL=1 was set


def send_email(
    *,
    to: str,
    subject: str,
    html: str,
    investigation_id: UUID | str | None = None,
    email_type: str,
    attachments: list[Path] | None = None,
    from_addr: str | None = None,
    from_name: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    preview_text: str | None = None,
    sent_by: str = "worker:auto",
    dsn: str | None = None,
) -> EmailResult:
    """Send one email via Resend. Logs the attempt to emails_sent
    regardless of outcome.

    ``email_type`` is one of: 'victim_summary', 'engagement_letter',
    'freeze_letter', 'le_handoff'. Drives the audit-log
    categorization + the idempotency check.

    ``attachments`` is a list of paths to local files; each is
    base64-encoded and attached. Resend's REST API caps total
    message size around 40MB — caller should filter to the
    intended attachments before calling.
    """
    # Honor the disable switch for local dev / testing.
    if os.environ.get("RECUPERO_DISABLE_EMAIL", "").strip() == "1":
        log.info(
            "RECUPERO_DISABLE_EMAIL=1 — skipping send to %s "
            "(would have sent: %s, type=%s, attachments=%d)",
            to, subject, email_type,
            len(attachments) if attachments else 0,
        )
        return EmailResult(
            success=False, message_id=None,
            error="skipped: RECUPERO_DISABLE_EMAIL=1",
            skipped=True,
        )

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        err = "RESEND_API_KEY not configured"
        log.warning("send_email: %s; cannot send to %s", err, to)
        _log_to_audit(
            dsn=dsn, investigation_id=investigation_id,
            to_address=to, subject=subject, email_type=email_type,
            message_id=None, error_message=err,
            sent_by=sent_by, preview_text=preview_text,
            attachment_names=[p.name for p in (attachments or [])],
        )
        return EmailResult(success=False, message_id=None, error=err)

    from_full = _format_from_header(from_addr, from_name)

    body: dict[str, Any] = {
        "from": from_full,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if cc:
        body["cc"] = cc
    if bcc:
        body["bcc"] = bcc

    # Encode attachments — Resend expects {filename, content (base64)}
    if attachments:
        encoded = []
        for ap in attachments:
            try:
                content = ap.read_bytes()
                encoded.append({
                    "filename": ap.name,
                    "content": base64.b64encode(content).decode("ascii"),
                    "content_type": (
                        mimetypes.guess_type(ap.name)[0]
                        or "application/octet-stream"
                    ),
                })
            except Exception as e:  # noqa: BLE001
                log.warning("email attachment %s read failed: %s", ap, e)
                continue
        if encoded:
            body["attachments"] = encoded

    req = urllib.request.Request(
        f"{_RESEND_API_BASE}/emails",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    message_id = None
    error_message = None
    try:
        resp_body = _resend_send_with_retry(req)
        message_id = resp_body.get("id")
        log.info(
            "sent email to=%s type=%s subject=%r message_id=%s",
            to, email_type, subject[:50], message_id,
        )
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8")
        except Exception:  # noqa: BLE001
            err_body = ""
        error_message = f"HTTP {exc.code}: {err_body[:500]}"
        log.warning(
            "send_email failed to=%s type=%s status=%d body=%s",
            to, email_type, exc.code, err_body[:200],
        )
    except urllib.error.URLError as exc:
        error_message = f"URLError: {exc.reason}"
        log.warning(
            "send_email URLError to=%s type=%s reason=%s",
            to, email_type, exc.reason,
        )
    except Exception as exc:  # noqa: BLE001
        error_message = f"{type(exc).__name__}: {exc}"
        log.warning(
            "send_email unexpected error to=%s type=%s err=%s",
            to, email_type, exc,
        )

    # Always log to audit (success or failure)
    _log_to_audit(
        dsn=dsn, investigation_id=investigation_id,
        to_address=to, subject=subject, email_type=email_type,
        message_id=message_id, error_message=error_message,
        sent_by=sent_by, preview_text=preview_text,
        attachment_names=[p.name for p in (attachments or [])],
    )

    return EmailResult(
        success=(error_message is None),
        message_id=message_id,
        error=error_message,
    )


def has_been_sent(
    *,
    investigation_id: UUID | str,
    email_type: str,
    dsn: str | None = None,
) -> bool:
    """Idempotency check: has the worker already successfully sent
    an email of this type for this investigation?

    Returns True if at least one emails_sent row exists with
    error_message IS NULL for the given (investigation_id, email_type).
    Failed sends don't count — the worker is allowed to retry them.
    """
    dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.warning("has_been_sent: no DSN; cannot check audit log")
        return False

    try:
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM public.emails_sent
                     WHERE investigation_id = %s
                       AND email_type = %s
                       AND error_message IS NULL
                     LIMIT 1
                    """,
                    (str(investigation_id), email_type),
                )
                return cur.fetchone() is not None
    except Exception as exc:  # noqa: BLE001
        log.warning("has_been_sent: audit query failed: %s", exc)
        return False


# ----- internals ----- #


def _format_from_header(
    from_addr: str | None, from_name: str | None,
) -> str:
    """Build the From: header. Resend accepts ``Name <email@host>``."""
    addr = (from_addr
            or os.environ.get("RECUPERO_EMAIL_FROM", "").strip()
            or _DEFAULT_FROM_ADDR)
    name = (from_name
            or os.environ.get("RECUPERO_EMAIL_FROM_NAME", "").strip()
            or _DEFAULT_FROM_NAME)
    return f"{name} <{addr}>"


def _log_to_audit(
    *,
    dsn: str | None,
    investigation_id: UUID | str | None,
    to_address: str,
    subject: str,
    email_type: str,
    message_id: str | None,
    error_message: str | None,
    sent_by: str,
    preview_text: str | None,
    attachment_names: list[str],
) -> None:
    """INSERT one row into public.emails_sent. Best-effort — log
    failures don't propagate up to the caller (we've already done
    the send), but they're logged so the operator sees them in
    Railway."""
    dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.warning("audit log write skipped: no DSN configured")
        return

    inv_id_str = str(investigation_id) if investigation_id else None
    try:
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.emails_sent
                        (investigation_id, to_address, subject,
                         preview_text, email_type, message_id,
                         error_message, sent_by, attachments)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        inv_id_str, to_address, subject[:500],
                        preview_text[:500] if preview_text else None,
                        email_type, message_id,
                        error_message[:4000] if error_message else None,
                        sent_by, attachment_names or None,
                    ),
                )
    except Exception as exc:  # noqa: BLE001
        log.warning("audit log write failed: %s", exc)


__all__ = ("EmailResult", "send_email", "has_been_sent")
