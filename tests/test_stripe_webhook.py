"""Tests for the Stripe webhook signature verifier.

The verifier is the single trust boundary for /webhooks/stripe —
if it accepts a forged signature, the dispatcher would insert
fraudulent payments rows + activate engagements without payment.

Contracts under test:
  * Valid signatures within the replay window verify successfully.
  * Tampered bodies fail verification.
  * Tampered signatures fail verification.
  * Old timestamps (outside 5-min tolerance) fail verification.
  * Missing/empty/malformed headers fail verification.
  * Multiple v1= entries (Stripe key rollover) are all checked.
  * The parsed event carries the expected (event_id, event_type,
    payload) tuple shape on success.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from recupero.payments.webhook import (
    StripeEvent,
    WebhookVerifyError,
    verify_and_parse,
)

_SECRET = "whsec_test_secret"


def _sign(body: bytes, *, timestamp: int, secret: str = _SECRET) -> str:
    """Helper: build a valid Stripe-Signature header for `body` at
    `timestamp` using `secret`. Mirrors Stripe's own signing flow."""
    payload = f"{timestamp}.".encode() + body
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


def _mk_event_body(
    event_id: str = "evt_test_abc",
    event_type: str = "checkout.session.completed",
    **kwargs: Any,
) -> bytes:
    """Minimal valid Stripe event JSON body."""
    body = {
        "id": event_id,
        "type": event_type,
        "data": {"object": kwargs or {"id": "cs_test_123"}},
    }
    return json.dumps(body).encode("utf-8")


# ---- Happy path ---- #


def test_verify_succeeds_with_valid_signature() -> None:
    """A valid signature within the replay window → returns
    a StripeEvent carrying the parsed payload."""
    now = int(time.time())
    body = _mk_event_body()
    sig = _sign(body, timestamp=now)
    event = verify_and_parse(
        body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
        now_unix=now,
    )
    assert isinstance(event, StripeEvent)
    assert event.event_id == "evt_test_abc"
    assert event.event_type == "checkout.session.completed"
    assert event.payload["data"]["object"]["id"] == "cs_test_123"


def test_verify_succeeds_with_multiple_v1_sigs_rollover() -> None:
    """During Stripe key rotation the header carries v1 signatures
    for BOTH the old and new secret. We accept the event if ANY
    v1 signature matches the active secret. Lock that behavior so
    a future "let's reject multi-v1" change has to update this
    test."""
    now = int(time.time())
    body = _mk_event_body()
    # Sign with the active secret, then prepend a bogus second v1.
    valid_sig = _sign(body, timestamp=now).split(",")[1]  # 'v1=...'
    bogus_sig = "v1=" + "0" * 64
    header = f"t={now},{bogus_sig},{valid_sig}"
    event = verify_and_parse(
        body_bytes=body, signature_header=header, webhook_secret=_SECRET,
        now_unix=now,
    )
    assert event.event_id == "evt_test_abc"


# ---- Tampering ---- #


def test_verify_rejects_tampered_body() -> None:
    """Signature was computed on body A; body B is sent → mismatch."""
    now = int(time.time())
    original = _mk_event_body(event_id="evt_test_real")
    tampered = _mk_event_body(event_id="evt_test_FAKE")
    sig = _sign(original, timestamp=now)
    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_and_parse(
            body_bytes=tampered, signature_header=sig, webhook_secret=_SECRET,
            now_unix=now,
        )


def test_verify_rejects_tampered_signature() -> None:
    """Body unchanged but the v1= signature byte was flipped → reject."""
    now = int(time.time())
    body = _mk_event_body()
    sig = _sign(body, timestamp=now)
    # Flip one byte of the signature
    tampered_sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_and_parse(
            body_bytes=body, signature_header=tampered_sig,
            webhook_secret=_SECRET, now_unix=now,
        )


def test_verify_rejects_wrong_secret() -> None:
    """Signature computed with secret A; verifier configured with
    secret B → reject."""
    now = int(time.time())
    body = _mk_event_body()
    sig = _sign(body, timestamp=now, secret="whsec_other_secret")
    with pytest.raises(WebhookVerifyError, match="signature mismatch"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=now,
        )


# ---- Replay window ---- #


def test_verify_rejects_old_timestamp() -> None:
    """Timestamp from 10 minutes ago → outside the 5-min replay
    tolerance → reject. Defends against replay-attack windows."""
    old_ts = int(time.time()) - 600
    body = _mk_event_body()
    sig = _sign(body, timestamp=old_ts)
    with pytest.raises(WebhookVerifyError, match="outside tolerance"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=int(time.time()),
        )


def test_verify_rejects_future_timestamp() -> None:
    """Timestamp from the FUTURE (clock skew or attacker probe)
    also fails the tolerance check. Both directions matter."""
    future_ts = int(time.time()) + 600
    body = _mk_event_body()
    sig = _sign(body, timestamp=future_ts)
    with pytest.raises(WebhookVerifyError, match="outside tolerance"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=int(time.time()),
        )


# ---- Malformed input ---- #


def test_verify_rejects_missing_signature_header() -> None:
    """No Stripe-Signature → reject. (Caller should have caught this
    at the HTTP layer; defensive.)"""
    with pytest.raises(WebhookVerifyError, match="missing Stripe-Signature"):
        verify_and_parse(
            body_bytes=b"{}", signature_header=None, webhook_secret=_SECRET,
        )


def test_verify_rejects_empty_secret() -> None:
    """STRIPE_WEBHOOK_SECRET unset → reject. The HTTP handler also
    short-circuits this with a 503 before reaching the verifier;
    the test locks the behavior at the verifier level too."""
    with pytest.raises(WebhookVerifyError, match="webhook secret not configured"):
        verify_and_parse(
            body_bytes=b"{}", signature_header="t=1,v1=x", webhook_secret="",
        )


def test_verify_rejects_header_without_v1_signature() -> None:
    """Header has timestamp but no v1= entry (e.g., only v0=) →
    reject. We don't accept the deprecated v0 scheme."""
    with pytest.raises(WebhookVerifyError, match="no v1 signature"):
        verify_and_parse(
            body_bytes=b"{}", signature_header="t=1234567890,v0=deprecated",
            webhook_secret=_SECRET, now_unix=1234567890,
        )


def test_verify_rejects_non_json_body() -> None:
    """Signature verifies but body isn't valid JSON → reject. The
    verifier signs+parses in one call, so a forged body that
    passed signature check but is non-JSON should still fail."""
    now = int(time.time())
    body = b"not actually json"
    sig = _sign(body, timestamp=now)
    with pytest.raises(WebhookVerifyError, match="not valid JSON"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=now,
        )


def test_verify_rejects_missing_event_id() -> None:
    """Payload JSON parsed OK but no 'id' field → reject. Stripe
    always sends evt_XXX as the top-level id."""
    now = int(time.time())
    body = json.dumps({"type": "checkout.session.completed"}).encode()
    sig = _sign(body, timestamp=now)
    with pytest.raises(WebhookVerifyError, match="missing or malformed event id"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=now,
        )


def test_verify_rejects_event_id_not_evt_prefix() -> None:
    """Malformed id ('foo' instead of 'evt_...') → reject. The
    'evt_' prefix is a Stripe invariant; not respecting it likely
    means a malicious replay or a malformed test event."""
    now = int(time.time())
    body = json.dumps({
        "id": "foo", "type": "checkout.session.completed",
    }).encode()
    sig = _sign(body, timestamp=now)
    with pytest.raises(WebhookVerifyError, match="missing or malformed event id"):
        verify_and_parse(
            body_bytes=body, signature_header=sig, webhook_secret=_SECRET,
            now_unix=now,
        )


def test_verify_rejects_non_integer_timestamp() -> None:
    """t=abc instead of t=12345 → reject loudly with a typed error.
    Defensive against header tampering / malformed Stripe responses."""
    with pytest.raises(WebhookVerifyError, match="non-integer timestamp"):
        verify_and_parse(
            body_bytes=b"{}",
            signature_header="t=not-a-number,v1=" + "0" * 64,
            webhook_secret=_SECRET,
        )
