"""Unit tests for the SaaS billing core (pure, no Stripe SDK, no DB).

Locks the two security/correctness-critical pieces: the Stripe webhook
signature verifier (constant-time HMAC + replay guard) and the pure
event→tenant-state mapping (`apply_webhook_event`).
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from recupero.platform import billing

_SECRET = "whsec_test_not_for_prod"


def _sign(payload: bytes, secret: str, ts: int) -> str:
    signed = f"{ts}".encode() + b"." + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ---- signature verification ---- #

def test_valid_signature_passes() -> None:
    body = b'{"type":"invoice.paid"}'
    header = _sign(body, _SECRET, 1_000_000)
    billing.verify_stripe_signature(body, header, _SECRET, now=1_000_010)  # no raise


def test_missing_header_rejected() -> None:
    with pytest.raises(billing.StripeSignatureError):
        billing.verify_stripe_signature(b"{}", None, _SECRET, now=1_000_000)


def test_missing_secret_rejected() -> None:
    body = b"{}"
    with pytest.raises(billing.StripeSignatureError):
        billing.verify_stripe_signature(body, _sign(body, _SECRET, 1_000_000), "", now=1_000_000)


def test_wrong_secret_rejected() -> None:
    body = b'{"type":"invoice.paid"}'
    header = _sign(body, _SECRET, 1_000_000)
    with pytest.raises(billing.StripeSignatureError):
        billing.verify_stripe_signature(body, header, "whsec_attacker", now=1_000_010)


def test_tampered_body_rejected() -> None:
    header = _sign(b'{"amount":100}', _SECRET, 1_000_000)
    with pytest.raises(billing.StripeSignatureError):
        billing.verify_stripe_signature(b'{"amount":999999}', header, _SECRET, now=1_000_010)


def test_stale_timestamp_rejected() -> None:
    body = b"{}"
    header = _sign(body, _SECRET, 1_000_000)
    with pytest.raises(billing.StripeSignatureError):  # replay far outside tolerance
        billing.verify_stripe_signature(body, header, _SECRET, now=1_000_000 + 10_000)


def test_malformed_header_rejected() -> None:
    with pytest.raises(billing.StripeSignatureError):
        billing.verify_stripe_signature(b"{}", "garbage", _SECRET, now=1_000_000)


# ---- event → state mapping ---- #

_PRICE_MAP = {"price_pro_123": "pro", "price_ent_999": "enterprise"}


def test_checkout_completed_sets_customer_active() -> None:
    ev = {"type": "checkout.session.completed",
          "data": {"object": {"customer": "cus_1", "subscription": "sub_1"}}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change is not None
    assert change.customer_id == "cus_1" and change.status == "active"
    assert change.stripe_subscription_id == "sub_1"


def test_subscription_updated_maps_price_to_plan() -> None:
    ev = {"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "customer": "cus_1", "status": "active",
        "current_period_end": 1_777_000_000,
        "items": {"data": [{"price": {"id": "price_pro_123"}}]},
    }}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.plan == "pro" and change.status == "active"
    assert change.stripe_price_id == "price_pro_123"
    assert change.plan_renews_at == 1_777_000_000


def test_subscription_past_due_suspends() -> None:
    ev = {"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "customer": "cus_1", "status": "past_due",
        "items": {"data": [{"price": {"id": "price_pro_123"}}]},
    }}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.status == "suspended"


def test_subscription_deleted_downgrades_to_free() -> None:
    ev = {"type": "customer.subscription.deleted",
          "data": {"object": {"id": "sub_1", "customer": "cus_1"}}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.plan == "free" and change.status == "active"
    assert change.stripe_subscription_id is None


def test_invoice_paid_resets_period() -> None:
    ev = {"type": "invoice.paid", "data": {"object": {"customer": "cus_1"}}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.reset_period is True and change.customer_id == "cus_1"


def test_invoice_failed_suspends() -> None:
    ev = {"type": "invoice.payment_failed", "data": {"object": {"customer": "cus_1"}}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.status == "suspended"


def test_unknown_event_ignored() -> None:
    assert billing.apply_webhook_event({"type": "charge.refunded", "data": {"object": {}}}) is None


def test_unknown_price_falls_back_to_free() -> None:
    ev = {"type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "customer": "cus_1", "status": "active",
        "items": {"data": [{"price": {"id": "price_unknown"}}]},
    }}}
    change = billing.apply_webhook_event(ev, price_to_plan=_PRICE_MAP)
    assert change.plan == "free"


def test_price_plan_map_from_env(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_STRIPE_PRICE_PRO", "price_abc")
    monkeypatch.setenv("RECUPERO_STRIPE_PRICE_ENTERPRISE", "price_xyz")
    m = billing.price_plan_map()
    assert m == {"price_abc": "pro", "price_xyz": "enterprise"}
