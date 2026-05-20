"""Webhook + email dispatcher for live monitoring alerts (v0.13.2 / v0.21.0).

Stateless module — given a subscription + an alert payload, fans
out the alert across every channel listed in
``Subscription.alert_channels`` (webhook + email today), and
returns a structured result per channel + a combined audit row.

Retry handling is left to the caller. The dispatcher reports each
attempt; the worker decides whether to retry (writing additional
monitoring_alerts rows for each attempt) using exponential backoff.

The audit-log writer (record_alert_attempt) lives in the same
module so retries can be journaled atomically with the dispatch
attempt.

v0.21.0:
  * Added dispatch_email_alert() — sends a structured email via
    worker._email.send_email and returns an EmailDispatchResult.
  * Added dispatch_all_channels() — fans out per-channel results
    in one call; audit-log row captures both webhook + email
    columns. Per-sub per-day email quota guard prevents a chatty
    subscription from blowing the Resend daily allowance.
"""

from __future__ import annotations

from recupero._common import db_connect

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import httpx

log = logging.getLogger(__name__)

# Hard-cap on monitoring alert emails per subscription per
# rolling 24h window. A chatty wallet (e.g. a token contract address
# accidentally subscribed via any_movement) could otherwise burn the
# Resend daily quota in minutes. Override via env var. The webhook
# channel has no equivalent cap (the customer's receiver is
# responsible for its own load), only email.
_EMAIL_QUOTA_PER_SUB_PER_DAY_DEFAULT = 5


# Hard cap on response body bytes we persist into monitoring_alerts.
# Some webhook servers return giant HTML on error — truncating keeps
# the audit table healthy.
_RESPONSE_BODY_MAX_BYTES = 4_000


@dataclass(frozen=True)
class AlertPayload:
    """Structured alert data — what gets POSTed to the webhook."""
    subscription_id: UUID
    trigger_type: str           # e.g. 'movement_above_usd'
    address: str
    chain: str
    tx_hash: str
    block_time_iso: str
    amount_usd: Decimal | None
    counterparty: str | None
    counterparty_label: str | None
    explorer_url: str


@dataclass(frozen=True)
class WebhookDispatchResult:
    """Result of one dispatch attempt — what the audit log captures."""
    succeeded: bool
    status_code: int | None     # None on connection error
    response_body: str          # truncated to _RESPONSE_BODY_MAX_BYTES
    error_message: str | None
    attempt_number: int
    fired_at: datetime
    delivered_at: datetime | None


@dataclass(frozen=True)
class EmailDispatchResult:
    """Result of one email-channel dispatch attempt (v0.21.0).

    ``status_code`` semantics mirror the audit column:
      * 0   = Resend acknowledged the send (2xx)
      * 1   = Resend rejected the send (HTTP error, URLError, etc.)
      * None = email channel not attempted (subscription doesn't
              include 'email', or per-sub daily quota tripped)
    """
    succeeded: bool
    status_code: int | None     # 0 / 1 sentinel; None when not attempted
    message_id: str | None      # Resend message id on success
    to_address: str | None      # recipient captured at dispatch time
    error_message: str | None
    fired_at: datetime
    delivered_at: datetime | None


@dataclass(frozen=True)
class CombinedDispatchResult:
    """Composite of all per-channel dispatch results for one alert.

    Used by the worker to write a single monitoring_alerts row that
    captures both webhook + email outcome columns. ``succeeded`` is
    True iff every ATTEMPTED channel succeeded; channels that were
    not attempted (None result) do not affect the verdict.
    """
    webhook: WebhookDispatchResult | None
    email: EmailDispatchResult | None
    fired_at: datetime

    @property
    def succeeded(self) -> bool:
        webhook_ok = self.webhook is None or self.webhook.succeeded
        email_ok = self.email is None or self.email.succeeded
        # At least one channel must have been attempted — a record
        # with both None means the dispatch was a no-op (e.g.
        # subscription with empty alert_channels, which the DB
        # CHECK should prevent).
        attempted = self.webhook is not None or self.email is not None
        return attempted and webhook_ok and email_ok


def build_webhook_body(payload: AlertPayload) -> str:
    """Serialize the alert as the JSON body the receiver gets.

    Pure function — exposed so callers can preview / sign / test
    without touching httpx.
    """
    fired_at_iso = (
        datetime.now(UTC).isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    # v0.16.10 (round-9 worker MEDIUM): idempotency_key. A worker crash
    # between dispatch and cursor-update could redeliver the same alert
    # next tick; customers' webhook handlers should dedup on this key.
    # Stable across retries because it's derived purely from the
    # alert content (subscription_id + chain + tx_hash). The
    # `trigger_type` is intentionally NOT in the key because the same
    # tx could legitimately trigger different alert types on different
    # subscriptions (those want distinct deliveries).
    idempotency_key = (
        f"{payload.subscription_id}:{payload.chain}:{payload.tx_hash}"
        f":{payload.trigger_type}"
    )
    body = {
        "subscription_id": str(payload.subscription_id),
        "trigger_type": payload.trigger_type,
        "address": payload.address,
        "chain": payload.chain,
        "idempotency_key": idempotency_key,
        "alert": {
            "tx_hash": payload.tx_hash,
            "block_time": payload.block_time_iso,
            "amount_usd": (
                str(payload.amount_usd) if payload.amount_usd is not None
                else None
            ),
            "counterparty": payload.counterparty,
            "counterparty_label": payload.counterparty_label,
            "explorer_url": payload.explorer_url,
        },
        "fired_at": fired_at_iso,
    }
    # sort_keys for deterministic signature stability — receivers can
    # re-serialize and verify.
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def compute_signature(body: str, secret: str) -> str:
    """HMAC-SHA256 signature of ``body`` using ``secret``.

    Returns the ``sha256=<hex>`` string that goes in the
    X-Recupero-Signature header.
    """
    sig = hmac.new(
        secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={sig}"


def dispatch_alert(
    payload: AlertPayload,
    *,
    webhook_url: str,
    webhook_secret: str | None = None,
    attempt_number: int = 1,
    timeout_seconds: float = 10.0,
    http_client: httpx.Client | None = None,
) -> WebhookDispatchResult:
    """POST the alert to ``webhook_url``.

    Returns a WebhookDispatchResult — the caller writes this to the
    monitoring_alerts audit table.

    2xx → success. Anything else (incl. connection errors) →
    failure with a structured error_message.

    ``http_client`` injection point lets tests mock with respx.
    """
    body = build_webhook_body(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"Recupero/0.13.2 monitoring-dispatcher (attempt={attempt_number})",
    }
    if webhook_secret:
        headers["X-Recupero-Signature"] = compute_signature(body, webhook_secret)
    fired_at = datetime.now(UTC)
    client = http_client or httpx.Client(timeout=timeout_seconds)
    owns_client = http_client is None
    try:
        try:
            resp = client.post(webhook_url, content=body, headers=headers)
        except httpx.RequestError as e:
            return WebhookDispatchResult(
                succeeded=False,
                status_code=None,
                response_body="",
                error_message=f"connection error: {e}",
                attempt_number=attempt_number,
                fired_at=fired_at,
                delivered_at=None,
            )
        truncated_body = (resp.text or "")[:_RESPONSE_BODY_MAX_BYTES]
        succeeded = 200 <= resp.status_code < 300
        return WebhookDispatchResult(
            succeeded=succeeded,
            status_code=resp.status_code,
            response_body=truncated_body,
            error_message=(
                None if succeeded
                else f"non-2xx status: HTTP {resp.status_code}"
            ),
            attempt_number=attempt_number,
            fired_at=fired_at,
            delivered_at=datetime.now(UTC),
        )
    finally:
        if owns_client:
            client.close()


def build_email_alert_body(
    payload: AlertPayload,
    *,
    case_id: UUID | None = None,
    portal_base_url: str | None = None,
) -> tuple[str, str]:
    """Build ``(subject, html_body)`` for a monitoring alert email.

    Pure function so the body can be previewed without touching
    Resend. Surface-level only — heavier theming can land in a
    Jinja template in v0.21.x once the live-filing section in
    le.html.j2 is settled.

    The body deliberately leads with the alert (what moved, by how
    much, where to) before any branding — the investigator opens
    this on their phone at 2 AM and needs to make a call inside 30
    seconds.
    """
    amount_label = (
        f"${payload.amount_usd:,.2f}" if payload.amount_usd is not None
        else "(amount unpriced)"
    )
    counterparty_label = payload.counterparty_label or "(unlabeled)"
    counterparty_addr = payload.counterparty or "(unknown)"
    subject = (
        f"[Recupero alert] {payload.trigger_type} — "
        f"{amount_label} on {payload.chain}"
    )
    # Plain-text-first HTML so it survives rendering in Gmail's
    # text-only preview pane (the first 100 chars are what shows
    # in the notification on a locked phone).
    portal_link = ""
    if portal_base_url and case_id:
        portal_link = (
            f'<p style="margin:18px 0">'
            f'<a href="{portal_base_url}/case/{case_id}" '
            f'style="background:#1e3a8a;color:#fff;padding:10px 18px;'
            f'text-decoration:none;border-radius:4px;font-weight:600">'
            f'Open case dashboard</a></p>'
        )
    html = (
        f'<div style="font-family:-apple-system,BlinkMacSystemFont,'
        f'Segoe UI,sans-serif;max-width:560px;margin:0 auto;'
        f'padding:24px;color:#111">'
        f'<p style="font-size:13px;color:#6b7280;text-transform:uppercase;'
        f'letter-spacing:0.08em;margin:0 0 8px">Recupero Monitoring</p>'
        f'<h2 style="font-size:20px;margin:0 0 14px">'
        f'Movement detected on watched wallet</h2>'
        f'<p style="font-size:15px;margin:0 0 18px">'
        f'<strong>{payload.trigger_type}</strong> fired on '
        f'<code>{payload.address[:10]}…{payload.address[-6:]}</code> '
        f'({payload.chain}).</p>'
        f'<table style="border-collapse:collapse;width:100%;'
        f'font-size:14px">'
        f'<tr><td style="padding:6px 0;color:#6b7280">Amount</td>'
        f'<td style="padding:6px 0;text-align:right;font-weight:600">'
        f'{amount_label}</td></tr>'
        f'<tr><td style="padding:6px 0;color:#6b7280">Counterparty</td>'
        f'<td style="padding:6px 0;text-align:right">{counterparty_label}<br>'
        f'<code style="font-size:12px;color:#374151">{counterparty_addr}</code></td></tr>'
        f'<tr><td style="padding:6px 0;color:#6b7280">Tx hash</td>'
        f'<td style="padding:6px 0;text-align:right">'
        f'<a href="{payload.explorer_url}" style="color:#1e3a8a">'
        f'{payload.tx_hash[:14]}…</a></td></tr>'
        f'<tr><td style="padding:6px 0;color:#6b7280">Block time</td>'
        f'<td style="padding:6px 0;text-align:right">{payload.block_time_iso}</td></tr>'
        f'</table>'
        f'{portal_link}'
        f'<p style="font-size:12px;color:#6b7280;margin:24px 0 0;'
        f'border-top:1px solid #e5e7eb;padding-top:12px">'
        f'Subscription id: <code>{payload.subscription_id}</code>. '
        f'You are receiving this because this address is on your '
        f'Recupero watch list. To stop alerts, pause the subscription '
        f'in the case dashboard.</p>'
        f'</div>'
    )
    return subject, html


def _email_quota_exhausted(
    *,
    subscription_id: UUID,
    dsn: str,
    quota_per_day: int,
) -> bool:
    """Has this subscription already sent >= quota_per_day alert
    emails in the last 24 hours?

    Cheap query via monitor_alerts_email_quota_idx. Returns False
    (i.e. "send is allowed") on any DB error — the alternative
    (fail-closed) would silently drop legitimate alerts on a
    transient Supabase blip, and the worker's per-tick caps already
    bound the worst case.
    """
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return False
    sql = """
        SELECT COUNT(*) FROM public.monitoring_alerts
         WHERE subscription_id = %s
           AND email_status_code IS NOT NULL
           AND fired_at >= NOW() - INTERVAL '24 hours'
    """
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, (subscription_id,))
            row = cur.fetchone()
            count = row[0] if row else 0
            return count >= quota_per_day
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "email quota check failed for sub %s — allowing send: %s",
            subscription_id, exc,
        )
        return False


def dispatch_email_alert(
    payload: AlertPayload,
    *,
    to_email: str,
    case_id: UUID | None = None,
    investigation_id: UUID | str | None = None,
    portal_base_url: str | None = None,
    dsn: str | None = None,
    quota_per_day: int | None = None,
) -> EmailDispatchResult:
    """Send one monitoring-alert email via Resend.

    Returns an EmailDispatchResult. Daily per-subscription quota
    (env-overridable via RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY,
    default 5) prevents a chatty subscription from exhausting the
    Resend daily allowance — alerts that exceed the quota return
    succeeded=False with a sentinel error_message so the audit row
    still records the SKIPPED state.
    """
    fired_at = datetime.now(UTC)

    # Quota guard — only when we have a DSN to query and a real
    # subscription to attribute against.
    if quota_per_day is None:
        try:
            quota_per_day = int(
                os.environ.get(
                    "RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY",
                    str(_EMAIL_QUOTA_PER_SUB_PER_DAY_DEFAULT),
                )
            )
        except (TypeError, ValueError):
            quota_per_day = _EMAIL_QUOTA_PER_SUB_PER_DAY_DEFAULT

    if dsn and quota_per_day > 0 and _email_quota_exhausted(
        subscription_id=payload.subscription_id,
        dsn=dsn,
        quota_per_day=quota_per_day,
    ):
        log.info(
            "email quota exhausted for sub %s (>= %d/day) — skipping send",
            payload.subscription_id, quota_per_day,
        )
        return EmailDispatchResult(
            succeeded=False,
            status_code=1,
            message_id=None,
            to_address=to_email,
            error_message=f"quota exhausted (>= {quota_per_day}/day)",
            fired_at=fired_at,
            delivered_at=None,
        )

    subject, html_body = build_email_alert_body(
        payload, case_id=case_id, portal_base_url=portal_base_url,
    )

    # Lazy import — keeps the dispatcher module importable without
    # the worker stack (e.g. for CLI preview / pure-function tests).
    from recupero.worker._email import send_email

    result = send_email(
        to=to_email,
        subject=subject,
        html=html_body,
        investigation_id=investigation_id,
        email_type="monitoring_alert",
        sent_by="monitor_tick:auto",
        dsn=dsn,
    )

    delivered_at = datetime.now(UTC) if result.success else None
    return EmailDispatchResult(
        succeeded=result.success,
        status_code=0 if result.success else 1,
        message_id=result.message_id,
        to_address=to_email,
        error_message=result.error,
        fired_at=fired_at,
        delivered_at=delivered_at,
    )


def dispatch_all_channels(
    payload: AlertPayload,
    *,
    subscription,  # type hint avoids circular: poller.Subscription
    dsn: str | None = None,
    portal_base_url: str | None = None,
    http_client: httpx.Client | None = None,
) -> CombinedDispatchResult:
    """Fan out an alert across every channel in ``subscription.alert_channels``.

    Returns a CombinedDispatchResult capturing per-channel outcomes
    so the caller can write a single monitoring_alerts row (vs.
    one-row-per-channel, which would break the existing audit-log
    queries).

    Channels not in alert_channels return None — the audit columns
    for that channel stay NULL.
    """
    fired_at = datetime.now(UTC)
    webhook_result: WebhookDispatchResult | None = None
    email_result: EmailDispatchResult | None = None

    channels = tuple(subscription.alert_channels or ("webhook",))

    if "webhook" in channels and subscription.webhook_url:
        webhook_result = dispatch_alert(
            payload,
            webhook_url=subscription.webhook_url,
            webhook_secret=subscription.webhook_secret,
            http_client=http_client,
        )

    if "email" in channels and subscription.alert_email:
        email_result = dispatch_email_alert(
            payload,
            to_email=subscription.alert_email,
            case_id=getattr(subscription, "case_id", None),
            investigation_id=getattr(subscription, "investigation_id", None),
            portal_base_url=portal_base_url,
            dsn=dsn,
        )

    return CombinedDispatchResult(
        webhook=webhook_result,
        email=email_result,
        fired_at=fired_at,
    )


def record_alert_attempt(
    *,
    dsn: str,
    payload: AlertPayload,
    result: WebhookDispatchResult | CombinedDispatchResult,
) -> UUID | None:
    """Persist one dispatch attempt to ``public.monitoring_alerts``.

    Accepts either a legacy ``WebhookDispatchResult`` (pre-v0.21.0
    callers) or a ``CombinedDispatchResult`` (v0.21.0+ multi-channel
    callers). Both produce ONE row — the row captures webhook
    columns from .webhook and email columns from .email when
    present.

    Returns the inserted row's UUID, or None on DB failure (logs at
    WARN — alert dispatch itself should still be considered effective
    even if the audit write fails).
    """
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — alert audit skipped")
        return None

    # Normalize: a legacy WebhookDispatchResult is treated as a
    # CombinedDispatchResult with only the webhook channel attempted.
    if isinstance(result, WebhookDispatchResult):
        combined = CombinedDispatchResult(
            webhook=result,
            email=None,
            fired_at=result.fired_at,
        )
    else:
        combined = result

    webhook = combined.webhook
    email = combined.email

    sql = """
        INSERT INTO public.monitoring_alerts (
            subscription_id, trigger_type, tx_hash, explorer_url,
            amount_usd, counterparty_address, counterparty_label,
            webhook_status_code, webhook_response_body,
            webhook_attempt_number, webhook_succeeded,
            webhook_error_message,
            email_status_code, email_message_id, email_to,
            email_error_message,
            fired_at, delivered_at
        ) VALUES (
            %(sub)s, %(trigger)s, %(tx)s, %(url)s,
            %(usd)s, %(cp)s, %(cp_label)s,
            %(w_status)s, %(w_body)s,
            %(w_attempt)s, %(w_succeeded)s,
            %(w_err)s,
            %(e_status)s, %(e_msg_id)s, %(e_to)s,
            %(e_err)s,
            %(fired)s, %(delivered)s
        )
        RETURNING id;
    """
    # Delivery time is the latest of any attempted channel.
    delivered_candidates = [
        x for x in (
            webhook.delivered_at if webhook else None,
            email.delivered_at if email else None,
        ) if x is not None
    ]
    delivered_at = max(delivered_candidates) if delivered_candidates else None

    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "sub": payload.subscription_id,
                "trigger": payload.trigger_type,
                "tx": payload.tx_hash,
                "url": payload.explorer_url,
                "usd": payload.amount_usd,
                "cp": payload.counterparty,
                "cp_label": payload.counterparty_label,
                # Webhook columns — NULL when webhook channel not attempted.
                "w_status": webhook.status_code if webhook else None,
                "w_body": (
                    webhook.response_body[:_RESPONSE_BODY_MAX_BYTES]
                    if webhook else None
                ),
                "w_attempt": webhook.attempt_number if webhook else 1,
                "w_succeeded": webhook.succeeded if webhook else False,
                "w_err": webhook.error_message if webhook else None,
                # Email columns — NULL when email channel not attempted.
                "e_status": email.status_code if email else None,
                "e_msg_id": email.message_id if email else None,
                "e_to": email.to_address if email else None,
                "e_err": email.error_message if email else None,
                # Combined timing.
                "fired": combined.fired_at,
                "delivered": delivered_at,
            })
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as exc:  # noqa: BLE001
        log.warning("monitoring_alerts insert failed: %s", exc)
        return None


__all__ = (
    "AlertPayload",
    "WebhookDispatchResult",
    "EmailDispatchResult",
    "CombinedDispatchResult",
    "build_webhook_body",
    "build_email_alert_body",
    "compute_signature",
    "dispatch_alert",
    "dispatch_email_alert",
    "dispatch_all_channels",
    "record_alert_attempt",
)
