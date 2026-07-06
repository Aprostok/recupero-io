"""Billing — Stripe webhook verification + pure event→tenant-state mapping.

Makes the SaaS layer BILLABLE without pulling the Stripe SDK into the runtime
(the webhook is HMAC-SHA256 — verifiable with stdlib, same posture as the session
JWT). The two testable, dependency-free pieces live here:

  * ``verify_stripe_signature`` — validates the ``Stripe-Signature`` header
    (constant-time HMAC over ``"{t}.{payload}"`` + a timestamp-tolerance replay
    guard), exactly Stripe's scheme.
  * ``apply_webhook_event`` — maps a parsed Stripe event to a ``BillingChange``
    (the org plan/status/period mutation to apply), or ``None`` for events we
    ignore. Pure → the billing state machine is unit-tested with fixture events.

The thin I/O edges (create a Checkout Session; persist a ``BillingChange``) call
Stripe / the DB and are wired in the router + store.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Any

# Subscription statuses Stripe reports → our org.status.
_ACTIVE_STATUSES = frozenset({"active", "trialing"})
_SUSPEND_STATUSES = frozenset({"past_due", "unpaid", "incomplete", "incomplete_expired"})


class StripeSignatureError(Exception):
    """Raised when a webhook signature is missing / malformed / invalid / stale."""


def verify_stripe_signature(
    payload: bytes, sig_header: str | None, secret: str,
    *, tolerance_seconds: int = 300, now: int | None = None,
) -> None:
    """Validate a Stripe ``Stripe-Signature`` header against the raw body.

    Raises ``StripeSignatureError`` on any failure (fail closed). Mirrors
    Stripe's construct_event: ``signed_payload = f"{t}.{body}"``, HMAC-SHA256
    with the endpoint secret, compared constant-time against any ``v1=`` sig,
    plus a ``|now - t| <= tolerance`` replay guard.
    """
    if not secret:
        raise StripeSignatureError("webhook secret not configured")
    if not sig_header:
        raise StripeSignatureError("missing Stripe-Signature header")
    parts = dict(
        seg.split("=", 1) for seg in sig_header.split(",") if "=" in seg
    )
    ts = parts.get("t")
    v1 = parts.get("v1")
    if not ts or not v1:
        raise StripeSignatureError("malformed Stripe-Signature header")
    try:
        ts_int = int(ts)
    except (TypeError, ValueError) as exc:
        raise StripeSignatureError("bad timestamp") from exc
    current = int(now if now is not None else time.time())
    if abs(current - ts_int) > tolerance_seconds:
        raise StripeSignatureError("timestamp outside tolerance (replay?)")
    signed = ts.encode() + b"." + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise StripeSignatureError("signature mismatch")


# --------------------------------------------------------------------------- #
# price → plan map (env-configured; no hardcoded Stripe ids in code)
# --------------------------------------------------------------------------- #


def price_plan_map() -> dict[str, str]:
    """``{stripe_price_id: plan_name}`` from env. Empty when unset → unknown
    prices fall back to 'free'. Env names are LITERAL (not f-string-built) so the
    env-var doc audit can statically see them."""
    out: dict[str, str] = {}
    for env_name, plan in (
        ("RECUPERO_STRIPE_PRICE_PRO", "pro"),
        ("RECUPERO_STRIPE_PRICE_ENTERPRISE", "enterprise"),
    ):
        pid = os.environ.get(env_name)
        if pid:
            out[pid] = plan
    return out


# --------------------------------------------------------------------------- #
# event → state change (pure)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BillingChange:
    """The tenant mutation implied by a Stripe event. ``customer_id`` locates the
    org; unset fields are left unchanged. ``reset_period`` zeroes the usage window
    on a successful invoice."""
    customer_id: str | None = None
    plan: str | None = None
    status: str | None = None
    stripe_subscription_id: str | None = None
    stripe_price_id: str | None = None
    plan_renews_at: int | None = None    # unix ts
    reset_period: bool = False


def _first_price_id(subscription: dict[str, Any]) -> str | None:
    try:
        items = (subscription.get("items") or {}).get("data") or []
        return (items[0].get("price") or {}).get("id") if items else None
    except (AttributeError, IndexError, TypeError):
        return None


def apply_webhook_event(
    event: dict[str, Any], *, price_to_plan: dict[str, str] | None = None,
) -> BillingChange | None:
    """Map a parsed Stripe event → ``BillingChange`` (or ``None`` to ignore).
    Pure: no I/O, so the billing state machine is fully unit-testable."""
    price_to_plan = price_to_plan or {}
    etype = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}

    if etype == "checkout.session.completed":
        cust = obj.get("customer")
        if not cust:
            return None
        return BillingChange(customer_id=cust, status="active",
                             stripe_subscription_id=obj.get("subscription"))

    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        cust = obj.get("customer")
        if not cust:
            return None
        price_id = _first_price_id(obj)
        plan = price_to_plan.get(price_id or "", "free")
        sub_status = obj.get("status", "active")
        status = "active" if sub_status in _ACTIVE_STATUSES else (
            "suspended" if sub_status in _SUSPEND_STATUSES else "active"
        )
        renews = obj.get("current_period_end")
        return BillingChange(
            customer_id=cust, plan=plan, status=status,
            stripe_subscription_id=obj.get("id"), stripe_price_id=price_id,
            plan_renews_at=int(renews) if isinstance(renews, (int, float)) else None,
        )

    if etype == "customer.subscription.deleted":
        cust = obj.get("customer")
        if not cust:
            return None
        # Downgrade to free; keep the org active (it just loses paid quota).
        return BillingChange(customer_id=cust, plan="free", status="active",
                             stripe_subscription_id=None)

    if etype == "invoice.paid":
        cust = obj.get("customer")
        return BillingChange(customer_id=cust, reset_period=True) if cust else None

    if etype == "invoice.payment_failed":
        cust = obj.get("customer")
        return BillingChange(customer_id=cust, status="suspended") if cust else None

    return None  # unhandled event type — ack 200, do nothing


__all__ = (
    "StripeSignatureError", "verify_stripe_signature",
    "price_plan_map", "BillingChange", "apply_webhook_event",
)
