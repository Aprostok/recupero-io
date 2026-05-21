"""Exchange / compliance-team monitoring API (v0.27.0).

Partners (exchanges, KYC providers, compliance teams) hit these
endpoints to subscribe wallet addresses to alerts. The worker's
existing monitoring pipeline (monitoring/poller.py +
monitoring/dispatcher.py) polls the chain and fires the partner's
webhook when the configured trigger condition is met.

Data-isolation contract:
  Every subscription is keyed on ``created_by = "api:<api_key_name>"``.
  The list / delete endpoints filter on this prefix so partner A
  cannot see / modify partner B's subscriptions. This MUST hold
  forever — it's the core multi-tenant boundary.

Webhook auth contract:
  Partners supply an optional ``webhook_secret``. The worker signs
  every webhook with HMAC-SHA256(secret, payload) and includes the
  digest in the ``X-Recupero-Signature`` header so partners can
  verify the callback came from us. The secret is opaque to
  Recupero — we store and replay it but never inspect content.

Surface:
  * POST   /v1/monitor/subscribe      — create
  * GET    /v1/monitor/subscriptions  — list (api-key scoped)
  * GET    /v1/monitor/{id}           — get one (api-key scoped)
  * DELETE /v1/monitor/{id}           — soft-delete
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

log = logging.getLogger(__name__)


# The created_by prefix marks subscriptions originating from the
# REST API (vs operator-CLI or emit_brief auto-subs). Listing the
# subscriptions for an api-key is then a simple LIKE filter on
# this prefix + the api_key name.
API_CREATED_BY_PREFIX = "api:"


_VALID_TRIGGER_TYPES = frozenset({
    "any_movement", "movement_above_usd",
    "balance_drop", "ofac_contact",
})

# Threshold-required triggers — these MUST carry a threshold_usd
# value (the worker compares the observed amount against this).
_THRESHOLD_REQUIRED_TRIGGERS = frozenset({
    "movement_above_usd", "balance_drop",
})

# Reasonable cap on webhook URL length to prevent absurd inputs
# (HTTP servers typically refuse > 8KB request URI; we cap our
# stored-URL field much shorter so partner typos don't fill the row).
_MAX_WEBHOOK_URL = 2048
_MAX_LABEL = 200
_MAX_WEBHOOK_SECRET = 256
_WEBHOOK_URL_RE = re.compile(r"^https?://[^\s<>\"]{1,2046}$")


class MonitoringApiError(ValueError):
    """Raised when the API caller supplies invalid input. Carries
    a ``field`` attribute the FastAPI handler turns into a 400."""

    def __init__(self, field: str, detail: str) -> None:
        super().__init__(f"{field}: {detail}")
        self.field = field
        self.detail = detail


@dataclass(frozen=True)
class SubscriptionRecord:
    """Public-facing subscription row. Hides internal cursor fields
    (last_observed_tx_hash, last_polled_at, etc.) — those are worker
    bookkeeping the partner does not need."""
    id: UUID
    address: str
    chain: str
    trigger_type: str
    threshold_usd: Decimal | None
    webhook_url: str
    label: str
    status: str
    created_at: str | None
    last_alerted_at: str | None
    expires_at: str | None

    def to_json_safe(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "address": self.address,
            "chain": self.chain,
            "trigger_type": self.trigger_type,
            "threshold_usd": (
                str(self.threshold_usd)
                if self.threshold_usd is not None else None
            ),
            "webhook_url": self.webhook_url,
            "label": self.label,
            "status": self.status,
            "created_at": self.created_at,
            "last_alerted_at": self.last_alerted_at,
            "expires_at": self.expires_at,
        }


def _validate_subscription_input(
    *,
    address: str,
    chain: str,
    trigger_type: str,
    threshold_usd: Decimal | None,
    webhook_url: str,
    label: str | None,
    webhook_secret: str | None,
) -> None:
    """Pure validation. Raises ``MonitoringApiError(field, detail)``
    on the first failing field."""
    if not address or not address.strip():
        raise MonitoringApiError("address", "Address is required.")
    if len(address) > 256:
        raise MonitoringApiError("address", "Address is too long.")

    if not chain or not chain.strip():
        raise MonitoringApiError("chain", "Chain is required.")
    if len(chain) > 64:
        raise MonitoringApiError("chain", "Chain is too long.")

    if trigger_type not in _VALID_TRIGGER_TYPES:
        raise MonitoringApiError(
            "trigger_type",
            f"Trigger must be one of: "
            f"{', '.join(sorted(_VALID_TRIGGER_TYPES))}.",
        )

    if trigger_type in _THRESHOLD_REQUIRED_TRIGGERS:
        if threshold_usd is None or threshold_usd <= 0:
            raise MonitoringApiError(
                "threshold_usd",
                f"Trigger {trigger_type!r} requires a positive "
                "threshold_usd value.",
            )

    if not webhook_url:
        raise MonitoringApiError(
            "webhook_url", "webhook_url is required.",
        )
    if len(webhook_url) > _MAX_WEBHOOK_URL:
        raise MonitoringApiError(
            "webhook_url",
            f"webhook_url exceeds {_MAX_WEBHOOK_URL} character limit.",
        )
    if not _WEBHOOK_URL_RE.match(webhook_url):
        raise MonitoringApiError(
            "webhook_url",
            "webhook_url must be a fully-qualified http(s):// URL.",
        )

    if label is not None and len(label) > _MAX_LABEL:
        raise MonitoringApiError(
            "label", f"label exceeds {_MAX_LABEL} character limit.",
        )

    if webhook_secret is not None and len(webhook_secret) > _MAX_WEBHOOK_SECRET:
        raise MonitoringApiError(
            "webhook_secret",
            f"webhook_secret exceeds {_MAX_WEBHOOK_SECRET} character limit.",
        )


def created_by_for_api_key(api_key_name: str) -> str:
    """Compose the canonical ``created_by`` value for a subscription
    originated via the REST API by a given api-key principal.

    Format: ``api:<key_name>`` (e.g. ``"api:exchange-acme"``).
    Listing endpoints filter by this exact prefix+name so partner
    A's keys cannot see partner B's data."""
    # api_key_name comes from require_api_key, which already
    # validated it against the configured key registry — so it's
    # not user-controlled at this point. We still strip any
    # whitespace defensively.
    return f"{API_CREATED_BY_PREFIX}{api_key_name.strip()}"


def create_subscription(
    *,
    api_key_name: str,
    address: str,
    chain: str,
    trigger_type: str,
    threshold_usd: Decimal | None,
    webhook_url: str,
    label: str | None,
    webhook_secret: str | None,
    dsn: str,
) -> SubscriptionRecord:
    """Insert a monitoring_subscriptions row scoped to ``api_key_name``.

    Idempotent on (address, chain, created_by) — UNIQUE constraint
    ON CONFLICT updates the existing row's trigger / webhook fields
    so a partner can re-POST to change configuration.

    Raises:
        MonitoringApiError — input validation failure.
        RuntimeError — DB error (caller surfaces as generic 5xx).
    """
    _validate_subscription_input(
        address=address, chain=chain, trigger_type=trigger_type,
        threshold_usd=threshold_usd, webhook_url=webhook_url,
        label=label, webhook_secret=webhook_secret,
    )

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        raise RuntimeError("psycopg not installed") from None

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    created_by = created_by_for_api_key(api_key_name)
    new_id = uuid4()
    eff_label = (label or "(api)")[:_MAX_LABEL]

    sql = """
        INSERT INTO public.monitoring_subscriptions
            (id, address, chain, created_by, label,
             trigger_type, threshold_usd,
             webhook_url, webhook_secret, status, created_at)
        VALUES (%(id)s, %(address)s, %(chain)s, %(created_by)s, %(label)s,
                %(trigger)s, %(threshold)s,
                %(url)s, %(secret)s, 'active', NOW())
        ON CONFLICT (address, chain, created_by) DO UPDATE
            SET label         = EXCLUDED.label,
                trigger_type  = EXCLUDED.trigger_type,
                threshold_usd = EXCLUDED.threshold_usd,
                webhook_url   = EXCLUDED.webhook_url,
                webhook_secret = EXCLUDED.webhook_secret,
                status        = 'active'
        RETURNING id, address, chain, trigger_type, threshold_usd,
                  webhook_url, label, status,
                  created_at::text, last_alerted_at::text,
                  expires_at::text
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "id": str(new_id),
                "address": address,
                "chain": chain,
                "created_by": created_by,
                "label": eff_label,
                "trigger": trigger_type,
                "threshold": threshold_usd,
                "url": webhook_url,
                "secret": webhook_secret,
            })
            row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "create_subscription failed (api_key=%s address=%s "
            "chain=%s): %s",
            api_key_name, address, chain, exc,
        )
        raise RuntimeError("subscription create failed") from None

    if not row:
        raise RuntimeError("INSERT returned no row")
    return _row_to_record(row)


def list_subscriptions(
    *,
    api_key_name: str,
    dsn: str,
    limit: int = 100,
) -> list[SubscriptionRecord]:
    """Return up to ``limit`` subscriptions scoped to ``api_key_name``.

    The created_by filter is the multi-tenant boundary — never
    return rows where created_by doesn't match this key's prefix.
    Status='deleted' rows are excluded.
    """
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return []

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    created_by = created_by_for_api_key(api_key_name)
    sql = """
        SELECT id, address, chain, trigger_type, threshold_usd,
               webhook_url, label, status,
               created_at::text, last_alerted_at::text, expires_at::text
          FROM public.monitoring_subscriptions
         WHERE created_by = %s
           AND status <> 'deleted'
         ORDER BY created_at DESC
         LIMIT %s
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, (created_by, limit))
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "list_subscriptions failed (api_key=%s): %s",
            api_key_name, exc,
        )
        return []
    return [_row_to_record(r) for r in rows]


def get_subscription(
    *,
    api_key_name: str,
    subscription_id: UUID,
    dsn: str,
) -> SubscriptionRecord | None:
    """Return one subscription by ID, ONLY if it was created by this
    api_key_name. Foreign-firm lookups return None — never raise so
    that probing for valid IDs can't enumerate other partners'
    subscriptions via 200-vs-404 timing.
    """
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return None

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    created_by = created_by_for_api_key(api_key_name)
    sql = """
        SELECT id, address, chain, trigger_type, threshold_usd,
               webhook_url, label, status,
               created_at::text, last_alerted_at::text, expires_at::text
          FROM public.monitoring_subscriptions
         WHERE id = %s AND created_by = %s
           AND status <> 'deleted'
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, (str(subscription_id), created_by))
            row = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "get_subscription failed (api_key=%s id=%s): %s",
            api_key_name, subscription_id, exc,
        )
        return None
    if not row:
        return None
    return _row_to_record(row)


def soft_delete_subscription(
    *,
    api_key_name: str,
    subscription_id: UUID,
    dsn: str,
) -> bool:
    """Mark the subscription as deleted. Status='deleted' is honored
    by the worker's claim filter so polling stops.

    Returns True on successful delete; False when the row doesn't
    exist or wasn't owned by this api_key_name.
    """
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return False

    from recupero._common import db_connect

    created_by = created_by_for_api_key(api_key_name)
    sql = """
        UPDATE public.monitoring_subscriptions
           SET status = 'deleted'
         WHERE id = %s AND created_by = %s AND status <> 'deleted'
        RETURNING id
    """
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, (str(subscription_id), created_by))
            row = cur.fetchone()
            return row is not None
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "soft_delete_subscription failed (api_key=%s id=%s): %s",
            api_key_name, subscription_id, exc,
        )
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _row_to_record(row: Any) -> SubscriptionRecord:
    """Convert a psycopg dict_row into a SubscriptionRecord.

    Handles both UUID-typed and string-typed `id` fields (psycopg's
    return type depends on row_factory config + the column's
    underlying type)."""
    rid = row["id"]
    if not isinstance(rid, UUID):
        rid = UUID(str(rid))
    threshold = row.get("threshold_usd")
    if threshold is not None and not isinstance(threshold, Decimal):
        threshold = Decimal(str(threshold))
    return SubscriptionRecord(
        id=rid,
        address=row["address"],
        chain=row["chain"],
        trigger_type=row["trigger_type"],
        threshold_usd=threshold,
        webhook_url=row["webhook_url"],
        label=row.get("label") or "",
        status=row.get("status") or "active",
        created_at=row.get("created_at"),
        last_alerted_at=row.get("last_alerted_at"),
        expires_at=row.get("expires_at"),
    )


__all__ = (
    "API_CREATED_BY_PREFIX",
    "MonitoringApiError",
    "SubscriptionRecord",
    "create_subscription",
    "list_subscriptions",
    "get_subscription",
    "soft_delete_subscription",
    "created_by_for_api_key",
)
