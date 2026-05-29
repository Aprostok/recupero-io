"""Email delivery for the daily watchlist digest.

When the nightly tick produces material changes, the cron sends a
plain-text summary email to a configurable recipient list, with the
rendered HTML attached as the body and the PDF as an attachment.

Why SMTP (not SendGrid SDK / Postmark SDK / Resend / etc.): standard
library coverage means no extra dependency, and every transactional-
email vendor exposes SMTP credentials. The operator can swap
providers by changing env vars without a code redeploy.

Env vars:

  RECUPERO_DIGEST_RECIPIENTS   comma-separated addresses (required
                               to enable email; absent → no-op).
  RECUPERO_DIGEST_FROM         "Sender Name <sender@domain>"; falls
                               back to "Recupero Digest
                               <digest@recupero.io>".
  RECUPERO_SMTP_HOST           e.g. "smtp.sendgrid.net"
  RECUPERO_SMTP_PORT           default 587 (STARTTLS)
  RECUPERO_SMTP_USER           SMTP username (often "apikey")
  RECUPERO_SMTP_PASSWORD       SMTP password / API key

  RECUPERO_DIGEST_ALWAYS_SEND  "1" to send the email even on
                               no-material-change ticks (off by
                               default — operators don't want
                               daily "all clear" inbox noise).

All sends are best-effort: a failure logs a warning but doesn't
fail the cron. The digest is still uploaded to the bucket, so the
operator can retrieve it manually.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

log = logging.getLogger(__name__)


_DEFAULT_SMTP_PORT = 587


def _resolve_smtp_port() -> int:
    """Wave-9 audit (type-coercion): a typo like ``RECUPERO_SMTP_PORT=auto``
    used to crash the nightly digest cron with an unhandled ValueError.
    Fall back to 587 (the STARTTLS default) on any non-integer or
    out-of-range value so the cron can still attempt delivery.
    """
    raw = (os.environ.get("RECUPERO_SMTP_PORT", "") or "").strip()
    if not raw:
        return _DEFAULT_SMTP_PORT
    try:
        n = int(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_SMTP_PORT is not an integer (%r) — using %d",
            raw, _DEFAULT_SMTP_PORT,
        )
        return _DEFAULT_SMTP_PORT
    if n < 1 or n > 65535:
        log.warning(
            "RECUPERO_SMTP_PORT %d is outside valid TCP range — using %d",
            n, _DEFAULT_SMTP_PORT,
        )
        return _DEFAULT_SMTP_PORT
    return n


def maybe_send_digest_email(
    *,
    html_path: Path,
    pdf_path: Path | None,
    digest_id: str,
    material_count: int,
    freezeable_count: int,
    total_outflow_usd: str,
    tick_date: str,
) -> bool:
    """Send the digest by email if SMTP env is configured.

    Returns ``True`` when an email was actually sent, ``False`` if
    skipped (no recipients configured, all-clear without
    ``ALWAYS_SEND``, missing SMTP creds, etc.).

    Per-failure errors are logged at WARNING — the caller (the cron
    entry) should treat a False return as "no harm done" because the
    bucket upload happened first.
    """
    recipients_raw = os.environ.get("RECUPERO_DIGEST_RECIPIENTS", "").strip()
    if not recipients_raw:
        log.info("digest email skipped — RECUPERO_DIGEST_RECIPIENTS not set")
        return False

    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        return False

    # Adversarial-input guard: an operator who pastes
    # RECUPERO_DIGEST_RECIPIENTS from a downstream system that
    # has CRLF in it would otherwise let `python's smtplib` reject
    # the whole digest (EmailMessage raises on `\n` in a header
    # str). Validate each recipient via the same regex the Resend
    # path uses — drop anything that fails. If nothing is left,
    # bail out before opening an SMTP connection.
    from recupero.worker._email import (
        _validate_email_address,  # local import: avoids cycle on cold import
    )
    valid_recipients = [r for r in recipients if _validate_email_address(r)]
    if not valid_recipients:
        log.warning(
            "digest email skipped — no valid recipient in "
            "RECUPERO_DIGEST_RECIPIENTS=%r (CRLF / control chars / "
            "malformed address rejected by validator)",
            recipients_raw,
        )
        return False
    recipients = valid_recipients

    # v0.19.2 (round-13 pipeline-MED-8): env_truthy so "true" / "yes" /
    # "on" all work, matching RECUPERO_DISABLE_EMAIL's canonical
    # parsing. Pre-v0.19.2 only the literal "1" enabled all-clear
    # digests; operators who set "true" got silent fall-through and
    # an empty inbox they couldn't diagnose.
    from recupero._common import env_truthy
    always_send = env_truthy("RECUPERO_DIGEST_ALWAYS_SEND")
    if material_count == 0 and not always_send:
        log.info(
            "digest email skipped — no material changes and "
            "RECUPERO_DIGEST_ALWAYS_SEND is not set"
        )
        return False

    smtp_host = os.environ.get("RECUPERO_SMTP_HOST", "").strip()
    smtp_user = os.environ.get("RECUPERO_SMTP_USER", "").strip()
    smtp_pass = os.environ.get("RECUPERO_SMTP_PASSWORD", "").strip()
    if not (smtp_host and smtp_user and smtp_pass):
        log.warning(
            "digest email skipped — RECUPERO_SMTP_HOST/USER/PASSWORD "
            "incomplete (configure all three to enable email)"
        )
        return False
    smtp_port = _resolve_smtp_port()

    from_header = (
        os.environ.get("RECUPERO_DIGEST_FROM", "").strip()
        or "Recupero Digest <digest@recupero.io>"
    )

    subject = _build_subject(
        material_count=material_count,
        freezeable_count=freezeable_count,
        total_outflow_usd=total_outflow_usd,
        tick_date=tick_date,
    )
    plain_body = _build_plain_body(
        material_count=material_count,
        freezeable_count=freezeable_count,
        total_outflow_usd=total_outflow_usd,
        tick_date=tick_date,
        digest_id=digest_id,
    )

    # Adversarial-input guard: strip CRLF / NUL / bidi controls from
    # every header value before handing them to EmailMessage. The
    # stdlib will raise `ValueError` on `\n` in a header str — that's
    # safer than silent injection, but the cron is supposed to ALWAYS
    # ship a digest if it has anything to say, so we sanitize instead
    # of raising. tick_date / material_count / freezeable_count flow
    # from internal computed integers + ISO date strings; the From
    # header is operator-set env. The risk is operator pastes a value
    # from a downstream system that contains a stray CRLF.
    from recupero.worker._email import _sanitize_email_header
    subject = _sanitize_email_header(subject)
    from_header = _sanitize_email_header(from_header)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = ", ".join(recipients)
    msg.set_content(plain_body)

    # HTML alternative — the rendered digest itself, so recipients
    # who view in a modern email client get the full letter inline.
    try:
        html_body = html_path.read_text(encoding="utf-8")
        msg.add_alternative(html_body, subtype="html")
    except Exception as exc:  # noqa: BLE001
        log.warning("digest email: HTML body read failed: %s", exc)

    # PDF attachment for the compliance-friendly archive.
    if pdf_path is not None and pdf_path.exists():
        try:
            pdf_bytes = pdf_path.read_bytes()
            msg.add_attachment(
                pdf_bytes,
                maintype="application", subtype="pdf",
                filename=pdf_path.name,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("digest email: PDF attach failed: %s", exc)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        log.info(
            "digest email sent: to=%s subject=%r",
            ", ".join(recipients), subject,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("digest email send failed: %s", exc)
        return False


def _build_subject(
    *, material_count: int, freezeable_count: int,
    total_outflow_usd: str, tick_date: str,
) -> str:
    """Subject line lead with the most-actionable signal."""
    if material_count == 0:
        return f"[Recupero] Daily Digest {tick_date} — all clear"
    if freezeable_count > 0:
        return (
            f"[Recupero] {freezeable_count} FREEZABLE wallet"
            f"{'s' if freezeable_count != 1 else ''} moved · "
            f"{tick_date}"
        )
    return (
        f"[Recupero] {material_count} watched wallet"
        f"{'s' if material_count != 1 else ''} moved · {tick_date}"
    )


def _build_plain_body(
    *, material_count: int, freezeable_count: int,
    total_outflow_usd: str, tick_date: str, digest_id: str,
) -> str:
    """Short plain-text body. The HTML alternative carries the full
    rendered digest — this is the fallback for plain-text-only mail
    clients and for the email client's preview pane."""
    if material_count == 0:
        return (
            f"Recupero Daily Watchlist Digest — {tick_date}\n\n"
            "No material movement observed across the active watchlist "
            "during the past tick. All wallets are within materiality "
            "thresholds.\n\n"
            f"Digest ID: {digest_id}\n\n"
            "— Recupero"
        )

    lines = [
        f"Recupero Daily Watchlist Digest — {tick_date}",
        "",
        f"{material_count} watched wallet"
        f"{'s' if material_count != 1 else ''} crossed a materiality "
        f"threshold during the past tick.",
    ]
    if freezeable_count > 0:
        lines.append(
            f"\nOf these, {freezeable_count} are flagged as freezeable "
            f"through an asset issuer. Any new outbound transfer from a "
            f"freezeable wallet is grounds to expedite the existing "
            f"freeze request — recommend immediate follow-up to the "
            f"relevant issuer compliance contact."
        )
    lines.append(f"\nTotal observed outflow (USD): {total_outflow_usd}")
    lines.append(
        "\nThe full digest with per-wallet detail is attached as a PDF, "
        "and rendered inline if your email client supports HTML."
    )
    lines.append(f"\nDigest ID: {digest_id}")
    lines.append("\n— Recupero")
    return "\n".join(lines)


__all__ = ("maybe_send_digest_email",)
