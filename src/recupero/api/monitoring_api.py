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

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

log = logging.getLogger(__name__)


# v0.27.1 (CRIT-1) — SSRF defense: deny private / loopback / link-local
# / metadata-service hosts when validating partner-supplied webhook
# URLs. Without this an exchange could subscribe with
# `webhook_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
# and use the worker's dispatcher to exfiltrate Recupero's cloud
# instance credentials.
#
# This module enforces the check at VALIDATION time (rejecting the
# subscription up-front) and the dispatcher enforces it again at
# DISPATCH time (defends against DNS rebinding — an attacker
# registers evil.example.com pointing at a public IP to pass
# validation, then flips it to 169.254.169.254 between validation
# and the worker's next poll).

# Operator escape hatch (dev environments need to subscribe to
# http://localhost:N for end-to-end testing). Comma-separated host
# names that bypass the deny list. Production deployments must
# leave this UNSET.
_SSRF_ALLOWLIST_ENV = "RECUPERO_WEBHOOK_ALLOWLIST_HOSTS"

# Hostnames we always block. These resolve to internal infrastructure
# regardless of DNS.
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.aws.internal",
    "metadata.azure.com",
    "169.254.169.254",  # AWS / GCP / Azure IMDSv1
    "fd00:ec2::254",    # AWS IMDSv2 IPv6
})

# Hostname suffixes blocked. These cover Railway's internal DNS
# (*.railway.internal), Docker's *.docker.internal, and *.local.
_BLOCKED_HOSTNAME_SUFFIXES = (
    ".internal",
    ".local",
    ".consul",
    ".cluster.local",
)


# The created_by prefix marks subscriptions originating from the
# REST API (vs operator-CLI or emit_brief auto-subs). Listing the
# subscriptions for an api-key is then a simple LIKE filter on
# this prefix + the api_key name.
API_CREATED_BY_PREFIX = "api:"


# RIGOR-Jacob Z12-3: bidi-override / zero-width / BOM code points
# rejected in the partner-supplied label. A label like
# ``"prod‮evil"`` renders as ``"prodlive"`` reversed in the
# operator triage UI — same Trojan-Source spoof class as the v0.21.0
# freeze_outcomes hardening.
_LABEL_TROJAN_CHARS = frozenset({
    "‪", "‫", "‬", "‭", "‮",  # bidi formatting / overrides
    "⁦", "⁧", "⁨", "⁩",       # bidi isolates
    "​", "‌", "‍",            # zero-width space / NJ / J
    "‎", "‏",                 # LTR / RTL marks
    "﻿",                       # BOM
    "\x00",                    # NUL (defense-in-depth)
})


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
# v0.27.1 (MED-3): require https:// only. Compliance webhooks
# transport sensitive watch-list data; cleartext http isn't
# defensible in 2026 (free Let's Encrypt certs).
_WEBHOOK_URL_RE = re.compile(r"^https://[^\s<>\"]{1,2046}$")
# v0.27.1 (HIGH-1): partner-supplied HMAC secrets must be long
# enough that brute-force isn't seconds (128 bits min).
_MIN_WEBHOOK_SECRET = 16


class MonitoringApiError(ValueError):
    """Raised when the API caller supplies invalid input. Carries
    a ``field`` attribute the FastAPI handler turns into a 400."""

    def __init__(self, field: str, detail: str) -> None:
        super().__init__(f"{field}: {detail}")
        self.field = field
        self.detail = detail


# v0.27.1 (HIGH-5): sentinel exception so the API layer can
# distinguish "DB query failed" (return 503) from "no row matches"
# (return 404 / empty list). Previously list / delete swallowed
# every error as [] / False — a partner whose subscriptions briefly
# returned empty due to a Supabase blip would assume their data
# vanished.
class MonitoringDbError(RuntimeError):
    """Raised when the DB layer fails. The endpoint catches this
    and surfaces a 503 with a generic detail (no DSN leak)."""


def _mask_webhook_url(url: str) -> str:
    """v0.27.1 (HIGH-4): redact the webhook URL beyond scheme + host
    + first path segment. Partners get the full URL on the create
    response (they just posted it) but list / get responses return
    only enough to identify which URL it is. Limits blast radius
    if the partner's API key leaks."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "***"
    scheme = parts.scheme or "https"
    host = parts.hostname or "***"
    port = f":{parts.port}" if parts.port else ""
    # First path segment only — keep enough to distinguish multiple
    # webhooks on the same host, drop any per-customer / per-secret
    # tokens that often live deeper in the path.
    path = parts.path or "/"
    first_seg = ""
    if path and path != "/":
        segments = [s for s in path.split("/") if s]
        if segments:
            first_seg = "/" + segments[0]
    return f"{scheme}://{host}{port}{first_seg}/…"


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

    def to_json_safe(self, *, mask_webhook_url: bool = False) -> dict[str, Any]:
        # v0.27.1 (HIGH-4): list/get endpoints set mask_webhook_url
        # True. The create response sends back the raw URL so the
        # partner sees the round-trip confirmation, but every
        # subsequent retrieval returns the masked form.
        webhook = (
            _mask_webhook_url(self.webhook_url) if mask_webhook_url
            else self.webhook_url
        )
        return {
            "id": str(self.id),
            "address": self.address,
            "chain": self.chain,
            "trigger_type": self.trigger_type,
            "threshold_usd": (
                str(self.threshold_usd)
                if self.threshold_usd is not None else None
            ),
            "webhook_url": webhook,
            "label": self.label,
            "status": self.status,
            "created_at": self.created_at,
            "last_alerted_at": self.last_alerted_at,
            "expires_at": self.expires_at,
        }


def _ssrf_host_allowlist() -> frozenset[str]:
    """Read the operator escape-hatch env var. Empty in production
    (no host bypasses the deny list)."""
    import os
    raw = (os.environ.get(_SSRF_ALLOWLIST_ENV, "") or "").strip()
    if not raw:
        return frozenset()
    return frozenset(
        h.strip().lower() for h in raw.split(",") if h.strip()
    )


def _is_blocked_ip(ip_str: str) -> bool:
    """True when ``ip_str`` parses as a private / loopback /
    link-local / multicast / reserved IP. Defends against partners
    pointing webhook_url at internal infra.

    RIGOR-Jacob Z12-1: ``ipaddress.ip_address`` is strict (RFC-only
    dotted-quad). The libc family (glibc inet_aton, used by curl /
    httpx / Linux name resolution) accepts alternative IPv4 literal
    forms:

      * ``2130706433``   (32-bit decimal of 127.0.0.1)
      * ``0177.0.0.1``   (leading-zero octal segment)
      * ``127.1``        (short-form trailing big-endian)
      * ``0x7f000001``   (hex)

    A partner that registers ``https://2130706433/`` previously passed
    every check here and the dispatcher then POSTed to 127.0.0.1.
    Real attack target: 169.254.169.254 in decimal (=2852039166) to
    reach the AWS IMDS through this gap.

    Fix: try ``socket.inet_aton`` (libc-form parser) as a fallback
    and re-check the resulting dotted-quad with strict ``ip_address``.
    """
    # Strict path first — covers IPv6 + canonical IPv4.
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        ip = None
    if ip is not None:
        return (
            ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
    # Fallback: libc-form IPv4 literal (decimal / octal / hex /
    # short-form). socket.inet_aton accepts all of these and returns
    # a 4-byte packed addr we can re-feed into ip_address.
    try:
        packed = socket.inet_aton(ip_str)
    except (OSError, TypeError):
        return False
    try:
        ip4 = ipaddress.IPv4Address(packed)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return (
        ip4.is_loopback or ip4.is_private or ip4.is_link_local
        or ip4.is_multicast or ip4.is_reserved or ip4.is_unspecified
    )


def _is_blocked_host(host: str) -> bool:
    """True when ``host`` should be rejected as a webhook target.

    Checks (in order):
      1. Operator allowlist override (RECUPERO_WEBHOOK_ALLOWLIST_HOSTS)
      2. Exact-match blocked hostnames
      3. Blocked hostname suffixes (.internal, .local, etc.)
      4. IP-literal host falls in a private/loopback/link-local range
    """
    if not host:
        return True
    host = host.lower()
    # Strip brackets from IPv6 literals: [::1] → ::1
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    if host in _ssrf_host_allowlist():
        return False

    if host in _BLOCKED_HOSTNAMES:
        return True
    if any(host.endswith(suf) for suf in _BLOCKED_HOSTNAME_SUFFIXES):
        return True
    if _is_blocked_ip(host):
        return True
    return False


def _resolves_to_blocked_ip(host: str) -> bool:
    """True when DNS resolves ``host`` to ANY blocked IP. Used at
    dispatch time to defend against DNS rebinding (attacker passes
    URL validation with a public IP, then flips DNS to a private
    target before the worker dispatches). Defensive only — failing
    resolution returns False so the underlying request can produce
    its own error.
    """
    if host in _ssrf_host_allowlist():
        return False
    try:
        addrs = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    for family, _kind, _proto, _name, sockaddr in addrs:
        ip = sockaddr[0]
        if _is_blocked_ip(ip):
            return True
    return False


def assert_webhook_url_safe(url: str) -> None:
    """Raises MonitoringApiError when ``url`` resolves to internal
    infra. Called at both validation time and dispatch time."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise MonitoringApiError(
            "webhook_url", f"Could not parse webhook URL: {exc}",
        ) from None
    if parts.scheme.lower() != "https":
        raise MonitoringApiError(
            "webhook_url",
            "webhook_url must use https:// (cleartext http is not "
            "permitted for production webhooks).",
        )
    host = parts.hostname or ""
    if _is_blocked_host(host):
        raise MonitoringApiError(
            "webhook_url",
            "webhook_url host is not permitted (loopback, private, "
            "link-local, or metadata-service targets are blocked).",
        )
    # Defense in depth: also resolve the hostname and reject if any
    # answer points at a blocked range. Catches the case where
    # ``host`` is a public-looking name with private DNS A records
    # (cloud-internal services often do this).
    if not _is_blocked_ip(host) and _resolves_to_blocked_ip(host):
        raise MonitoringApiError(
            "webhook_url",
            "webhook_url resolves to a private / internal IP. "
            "Use a publicly reachable host.",
        )


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

    # RIGOR-Jacob Z12-2: reject NaN / Infinity threshold_usd at the
    # validation layer. Decimal('Infinity') passes Pydantic's ge=0
    # check (Inf > 0 is True) and lands in monitoring_subscriptions.
    # threshold_usd; every downstream ``observed_amount >= threshold``
    # comparison in the worker then returns False forever — the
    # subscription appears active but never fires. Same shape as the
    # v0.21.0 freeze_outcomes Inf hardening.
    if threshold_usd is not None and not threshold_usd.is_finite():
        raise MonitoringApiError(
            "threshold_usd",
            "threshold_usd must be a finite number (no NaN/Inf).",
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
            "webhook_url must be a fully-qualified https:// URL.",
        )
    # v0.27.1 (CRIT-1): SSRF defense — block private / loopback /
    # link-local / metadata hosts.
    assert_webhook_url_safe(webhook_url)

    if label is not None and len(label) > _MAX_LABEL:
        raise MonitoringApiError(
            "label", f"label exceeds {_MAX_LABEL} character limit.",
        )
    # RIGOR-Jacob Z12-3: bidi-override / zero-width / BOM rejection
    # on the partner-supplied label. Spoofs the operator triage UI.
    if label is not None:
        for ch in label:
            if ch in _LABEL_TROJAN_CHARS:
                raise MonitoringApiError(
                    "label",
                    "label contains a bidi-override / zero-width / "
                    "BOM character (display-spoof / Trojan-Source).",
                )

    # v0.27.1 (HIGH-1): partner-supplied HMAC secret must be at
    # least 16 chars when provided (or omitted entirely).
    if webhook_secret is not None:
        if len(webhook_secret) < _MIN_WEBHOOK_SECRET:
            raise MonitoringApiError(
                "webhook_secret",
                f"webhook_secret must be at least {_MIN_WEBHOOK_SECRET} "
                "characters when provided (HMAC over a shorter key is "
                "brute-forceable).",
            )
        if len(webhook_secret) > _MAX_WEBHOOK_SECRET:
            raise MonitoringApiError(
                "webhook_secret",
                f"webhook_secret exceeds {_MAX_WEBHOOK_SECRET} "
                "character limit.",
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

    from psycopg.rows import dict_row

    from recupero._common import db_connect

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

    from psycopg.rows import dict_row

    from recupero._common import db_connect

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
        # v0.27.1 (HIGH-5): re-raise so the API layer can surface
        # 503 instead of falsely returning [] (which a partner would
        # read as "I have no subscriptions").
        raise MonitoringDbError("subscription list failed") from None
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

    from psycopg.rows import dict_row

    from recupero._common import db_connect

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
        # v0.27.1 (HIGH-5): distinguish DB error from missing row.
        raise MonitoringDbError("subscription lookup failed") from None
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
        # v0.27.1 (HIGH-5): re-raise so the API layer can return 503
        # instead of misleading the partner with a 404.
        raise MonitoringDbError("subscription delete failed") from None


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
    "MonitoringDbError",
    "SubscriptionRecord",
    "assert_webhook_url_safe",
    "create_subscription",
    "list_subscriptions",
    "get_subscription",
    "soft_delete_subscription",
    "created_by_for_api_key",
)
