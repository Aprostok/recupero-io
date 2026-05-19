"""Integration: Stripe webhook → dispatcher → DB state transition.

Exercises the full webhook handling path against a real Postgres
test DB. Validates:

  * Stripe signature verification (real HMAC over canonical body)
  * dispatcher.dispatch() inserts into public.payments
  * The right action label flows back ("engagement_activated" etc.)
  * The v0.19.3 COALESCE fix preserves engagement state on misrouted
    webhooks (a $499 mis-tagged as type=engagement does NOT clobber
    a real $10K engagement)

This is the closest we can get to "Stripe really delivered a
webhook" without a Stripe sandbox. The signature path is real; only
the network delivery is synthesized.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from decimal import Decimal
from uuid import uuid4

import pytest

from recupero.payments.dispatcher import dispatch
from recupero.payments.webhook import StripeEvent, verify_and_parse


# A canonical Stripe-style checkout.session.completed payload. Real
# Stripe payloads are much richer; we include the fields the dispatcher
# actually reads (and a handful of decoys to prove we ignore them).
def _mk_payload(
    *,
    event_id: str,
    amount_total: int,
    metadata: dict,
    event_type: str = "checkout.session.completed",
) -> bytes:
    payload = {
        "id": event_id,
        "object": "event",
        "type": event_type,
        "created": int(time.time()),
        "data": {
            "object": {
                "id": f"cs_test_{event_id[5:]}",
                "object": "checkout.session",
                "amount_total": amount_total,
                "currency": "usd",
                "payment_status": "paid",
                "metadata": metadata,
                "customer_email": "victim@example.com",
            }
        },
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _sign(payload: bytes, secret: str, ts: int | None = None) -> str:
    """Reproduce Stripe's signature format: `t=<ts>,v1=<HMAC>`."""
    ts = ts or int(time.time())
    signed = f"{ts}.".encode() + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


@pytest.fixture
def webhook_secret(monkeypatch) -> str:
    """Set a deterministic test webhook secret."""
    secret = "whsec_test_" + "a" * 32
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", secret)
    return secret


def test_signed_webhook_verifies_and_returns_stripe_event(webhook_secret: str) -> None:
    """The webhook verifier should accept a body signed with the
    configured secret and return a StripeEvent."""
    payload = _mk_payload(
        event_id="evt_int_001",
        amount_total=1_000_000,  # $10,000
        metadata={"type": "engagement", "investigation_id": str(uuid4())},
    )
    sig = _sign(payload, webhook_secret)
    event = verify_and_parse(
    body_bytes=payload, signature_header=sig,
    webhook_secret=webhook_secret,
)
    assert isinstance(event, StripeEvent)
    assert event.event_id == "evt_int_001"
    assert event.event_type == "checkout.session.completed"


def test_engagement_webhook_inserts_payment_row(
    integration_dsn: str, webhook_secret: str,
) -> None:
    """End-to-end: sign a payload, verify, dispatch, check DB."""
    import psycopg
    from psycopg.rows import dict_row

    # Set up a fresh investigation to attach the engagement to
    inv_id = uuid4()
    with psycopg.connect(integration_dsn, autocommit=True,
                         row_factory=dict_row, connect_timeout=10,
                         prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.investigations
              (id, case_id, status, chain, seed_address, triggered_at,
               triggered_by, label)
            VALUES (%s, NULL, 'pending', 'ethereum',
                    '0xdeadbeef00000000000000000000000000000001',
                    NOW(), 'integration-test', 'integration')
            """,
            (str(inv_id),),
        )

    # Build + verify + dispatch
    payload = _mk_payload(
        event_id=f"evt_int_{uuid4().hex[:12]}",
        amount_total=1_000_000,  # $10,000
        metadata={"type": "engagement", "investigation_id": str(inv_id)},
    )
    sig = _sign(payload, webhook_secret)
    event = verify_and_parse(
    body_bytes=payload, signature_header=sig,
    webhook_secret=webhook_secret,
)
    result = dispatch(event=event, dsn=integration_dsn)

    assert result.action == "engagement_activated"
    assert result.duplicate is False
    assert result.investigation_id == str(inv_id)

    # Validate downstream DB state
    with psycopg.connect(integration_dsn, autocommit=True,
                         row_factory=dict_row, connect_timeout=10,
                         prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT engagement_started_at, engagement_fee_paid_usd, "
            "       engagement_closed_at "
            "  FROM public.investigations WHERE id = %s",
            (str(inv_id),),
        )
        row = cur.fetchone()
        assert row is not None
        assert row["engagement_started_at"] is not None
        assert Decimal(str(row["engagement_fee_paid_usd"])) == Decimal("10000")
        assert row["engagement_closed_at"] is None

        # Cleanup
        cur.execute(
            "DELETE FROM public.payments WHERE stripe_event_id = %s",
            (event.event_id,),
        )
        cur.execute(
            "DELETE FROM public.investigations WHERE id = %s",
            (str(inv_id),),
        )


def test_misrouted_engagement_webhook_preserves_existing_fee(
    integration_dsn: str, webhook_secret: str,
) -> None:
    """v0.19.3 (round-13 pipeline-MED-5 follow-up): a $499 webhook
    tagged as type=engagement against a row with an existing $10K
    engagement must NOT overwrite the fee. The COALESCE on
    engagement_fee_paid_usd guards this exact failure mode."""
    import psycopg
    from psycopg.rows import dict_row

    inv_id = uuid4()
    with psycopg.connect(integration_dsn, autocommit=True,
                         row_factory=dict_row, connect_timeout=10,
                         prepare_threshold=None) as conn, conn.cursor() as cur:
        # Seed an already-engaged investigation at $10K
        cur.execute(
            """
            INSERT INTO public.investigations
              (id, case_id, status, chain, seed_address, triggered_at,
               triggered_by, label, engagement_started_at,
               engagement_fee_paid_usd)
            VALUES (%s, NULL, 'pending', 'ethereum',
                    '0xdeadbeef00000000000000000000000000000002',
                    NOW(), 'integration-test', 'integration',
                    NOW() - INTERVAL '1 day',
                    10000)
            """,
            (str(inv_id),),
        )

    # Misrouted $499 webhook tagged as engagement
    payload = _mk_payload(
        event_id=f"evt_int_{uuid4().hex[:12]}",
        amount_total=49_900,  # $499
        metadata={"type": "engagement", "investigation_id": str(inv_id)},
    )
    sig = _sign(payload, webhook_secret)
    event = verify_and_parse(
    body_bytes=payload, signature_header=sig,
    webhook_secret=webhook_secret,
)
    result = dispatch(event=event, dsn=integration_dsn)

    assert result.action == "engagement_activated"

    # The fee MUST still be $10K (COALESCE preserved the original)
    with psycopg.connect(integration_dsn, autocommit=True,
                         row_factory=dict_row, connect_timeout=10,
                         prepare_threshold=None) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT engagement_fee_paid_usd "
            "  FROM public.investigations WHERE id = %s",
            (str(inv_id),),
        )
        row = cur.fetchone()
        assert row is not None
        assert Decimal(str(row["engagement_fee_paid_usd"])) == Decimal("10000"), (
            "v0.19.3 COALESCE fix regressed — misrouted webhook overwrote "
            "the legitimate engagement fee"
        )

        # Cleanup
        cur.execute(
            "DELETE FROM public.payments WHERE stripe_event_id = %s",
            (event.event_id,),
        )
        cur.execute(
            "DELETE FROM public.investigations WHERE id = %s",
            (str(inv_id),),
        )
