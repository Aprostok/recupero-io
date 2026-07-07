"""Transactional email for the /v2 layer — invite / verify / password-reset
links. A thin, best-effort wrapper over the engine's ``worker._email.send_email``
(Resend). NEVER raises: a missing ``RESEND_API_KEY`` makes ``send_email`` return
``success=False`` (it doesn't throw), and any other failure is swallowed +
logged. Delivery is fire-and-forget from the request handler — the token itself
is never exposed in an API response for the reset flow.
"""

from __future__ import annotations

import html as _html
import logging

log = logging.getLogger(__name__)

_SUBJECTS = {
    "invite": "You've been invited to a Recupero organization",
    "verify": "Verify your Recupero email",
    "password_reset": "Reset your Recupero password",
}
_INTROS = {
    "invite": "You've been invited to join a Recupero organization. Accept the invitation:",
    "verify": "Confirm your email address for Recupero:",
    "password_reset": "We received a request to reset your Recupero password. "
                      "If it wasn't you, ignore this email. Otherwise, reset it here:",
}


def send_link_email(*, to: str, kind: str, url: str) -> bool:
    """Send a one-link transactional email. Returns True on a successful send,
    False if email is unconfigured or the send failed (best-effort; never
    raises). ``kind`` ∈ {invite, verify, password_reset}."""
    try:
        from recupero.worker._email import send_email
    except Exception as exc:  # noqa: BLE001 — engine mailer unavailable
        log.warning("transactional email unavailable (%s): %s", kind, exc)
        return False
    safe_url = _html.escape(url, quote=True)
    subject = _SUBJECTS.get(kind, "Recupero")
    intro = _INTROS.get(kind, "")
    body = (
        f"<p>{_html.escape(intro)}</p>"
        f'<p><a href="{safe_url}">{safe_url}</a></p>'
        "<p style=\"color:#8b98a9;font-size:12px\">If you didn't expect this, "
        "you can safely ignore it.</p>"
    )
    try:
        res = send_email(to=to, subject=subject, html=body, email_type=f"platform_{kind}")
        return bool(getattr(res, "success", False))
    except Exception as exc:  # noqa: BLE001 — delivery must never break the request
        log.warning("transactional email (%s) to %s failed: %s", kind, to, exc)
        return False


__all__ = ("send_link_email",)
