"""Admin-gated cron-jobs visibility API (v0.32.1 HIGH-5).

Surfaces the FULL cron-jobs healthz payload — including the
``last_error_message`` field that's been STRIPPED from the public
``/cron/healthz`` endpoint as a defense-in-depth measure.

Gated by ``X-Recupero-Admin-Key`` (same shared secret as
``/v1/reviews/*`` and ``/v1/labels/*``). Operators see the error
text here; external uptime monitors and the public internet do NOT
see it via ``/cron/healthz``.

Why split the surface
---------------------

The v0.32.1 audit (CRIT-2 + HIGH-5) closed two adjacent risks:
  * CRIT-2: the cron-error redactor missed unlabeled bearer tokens
    (sk_live_*, re_*, JWTs). Even a partial-redact bug leaks secrets.
  * HIGH-5: the public ``/cron/healthz`` returned the redacted error
    text in its payload. A redact regression would ship the leaked
    secret to anyone hitting the URL.

Both are now defense-in-depth: redactor coverage was widened
(``_safe_error_text`` in ``cron_scheduler.py``) AND the public
endpoint no longer carries the error text at all. Operators see
errors via this admin-gated endpoint.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/cron", tags=["cron"])


def _require_admin_auth(provided: str | None) -> None:
    """Same shape as ``recupero.dispatcher.review_api._require_admin_auth``
    — duplicated here to keep this module standalone-importable.
    503 when the admin key is unset (deny-by-default), 401 otherwise.
    """
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "cron admin API disabled — set RECUPERO_ADMIN_KEY to "
                "enable"
            ),
        )
    if not provided or not provided.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing X-Recupero-Admin-Key",
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid X-Recupero-Admin-Key",
        )


@router.get(
    "/jobs",
    summary=(
        "Full cron-jobs status payload (includes last_error_message). "
        "Admin-gated."
    ),
)
def list_cron_jobs(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    try:
        from recupero.worker.cron_scheduler import build_cron_healthz_payload
        payload = build_cron_healthz_payload(include_error_message=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("cron admin: healthz build failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="cron healthz unavailable",
        ) from None
    return payload


__all__ = ("router",)
