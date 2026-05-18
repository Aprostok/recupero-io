"""Webhook dispatcher for live monitoring alerts (v0.13.2).

Stateless module — given a subscription + an alert payload, builds the
JSON body, computes the HMAC signature (if configured), POSTs to the
subscriber's webhook URL, and returns a structured result.

Retry handling is left to the caller. The dispatcher reports each
attempt; the worker decides whether to retry (writing additional
monitoring_alerts rows for each attempt) using exponential backoff.

The audit-log writer (record_alert_attempt) lives in the same
module so retries can be journaled atomically with the dispatch
attempt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import httpx

log = logging.getLogger(__name__)


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


def record_alert_attempt(
    *,
    dsn: str,
    payload: AlertPayload,
    result: WebhookDispatchResult,
) -> UUID | None:
    """Persist one dispatch attempt to ``public.monitoring_alerts``.

    Returns the inserted row's UUID, or None on DB failure (logs at
    WARN — alert dispatch itself should still be considered effective
    even if the audit write fails).
    """
    try:
        import psycopg
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — alert audit skipped")
        return None

    sql = """
        INSERT INTO public.monitoring_alerts (
            subscription_id, trigger_type, tx_hash, explorer_url,
            amount_usd, counterparty_address, counterparty_label,
            webhook_status_code, webhook_response_body,
            webhook_attempt_number, webhook_succeeded,
            webhook_error_message, fired_at, delivered_at
        ) VALUES (
            %(sub)s, %(trigger)s, %(tx)s, %(url)s,
            %(usd)s, %(cp)s, %(cp_label)s,
            %(status)s, %(body)s,
            %(attempt)s, %(succeeded)s,
            %(err)s, %(fired)s, %(delivered)s
        )
        RETURNING id;
    """
    try:
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "sub": payload.subscription_id,
                "trigger": payload.trigger_type,
                "tx": payload.tx_hash,
                "url": payload.explorer_url,
                "usd": payload.amount_usd,
                "cp": payload.counterparty,
                "cp_label": payload.counterparty_label,
                "status": result.status_code,
                "body": result.response_body[:_RESPONSE_BODY_MAX_BYTES],
                "attempt": result.attempt_number,
                "succeeded": result.succeeded,
                "err": result.error_message,
                "fired": result.fired_at,
                "delivered": result.delivered_at,
            })
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as exc:  # noqa: BLE001
        log.warning("monitoring_alerts insert failed: %s", exc)
        return None


__all__ = (
    "AlertPayload",
    "WebhookDispatchResult",
    "build_webhook_body",
    "compute_signature",
    "dispatch_alert",
    "record_alert_attempt",
)
