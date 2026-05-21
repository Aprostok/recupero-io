"""Stripe webhook signature verification + entrypoint.

Stripe signs every webhook with HMAC-SHA256. The header
``Stripe-Signature`` carries one or more (t=timestamp,v1=signature)
pairs joined by commas — we verify against each v1 signature and
accept if any match.

Why hand-rolled (not the stripe SDK):
The SDK's `stripe.Webhook.construct_event` does exactly this with
~30 lines of HMAC + replay-protection logic. Doing it ourselves
keeps our dependency surface tight, makes the verification path
auditable in one file, and avoids the SDK's import cost on the
hot webhook path. If we ever need to CALL the Stripe API (e.g.,
create Checkout Sessions from the worker), we'll add the SDK
then.

Replay protection:
Stripe recommends rejecting events whose timestamp is more than
5 minutes old to limit replay-attack windows. We honor that.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, NamedTuple

log = logging.getLogger(__name__)


# Stripe's recommended tolerance for signature timestamps. Events
# older than this are rejected as potential replays. 5 minutes
# matches Stripe's own SDK default.
_REPLAY_TOLERANCE_SEC = 300


class WebhookVerifyError(ValueError):
    """Raised when signature verification fails for any reason
    (missing header, malformed header, bad signature, replay).
    Caught at the HTTP layer and turned into a 400 response."""


class StripeEvent(NamedTuple):
    """A verified + parsed Stripe webhook event."""
    event_id: str           # 'evt_1Abc...'
    event_type: str         # 'checkout.session.completed'
    payload: dict[str, Any] # full event JSON for downstream dispatch


def verify_and_parse(
    *,
    body_bytes: bytes,
    signature_header: str | None,
    webhook_secret: str,
    now_unix: float | None = None,
) -> StripeEvent:
    """Verify the Stripe-Signature header against `body_bytes` and
    return the parsed event. Raises WebhookVerifyError on any
    failure mode.

    ``now_unix`` is overridable for tests (so the replay-tolerance
    check has a deterministic anchor).
    """
    if not signature_header:
        raise WebhookVerifyError("missing Stripe-Signature header")
    if not webhook_secret:
        raise WebhookVerifyError("webhook secret not configured")

    timestamp, sigs = _parse_signature_header(signature_header)
    if not sigs:
        raise WebhookVerifyError("no v1 signature in header")

    # Replay-window check. Use the test-overridable clock so the
    # unit tests can pin a known timestamp.
    now = now_unix if now_unix is not None else time.time()
    if abs(now - timestamp) > _REPLAY_TOLERANCE_SEC:
        raise WebhookVerifyError(
            f"timestamp outside tolerance ({abs(now - timestamp):.0f}s)"
        )

    # The signed string is "<timestamp>.<body>". HMAC-SHA256 with the
    # webhook secret as the key.
    signed_payload = f"{timestamp}.".encode() + body_bytes
    expected = hmac.new(
        webhook_secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison against each candidate signature.
    # Stripe rotates secrets via "endpoint signing key rollover";
    # during the rollover window the header may carry signatures
    # from BOTH keys, so multiple v1 entries is expected behavior.
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise WebhookVerifyError("signature mismatch")

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookVerifyError(f"body is not valid JSON: {exc}") from exc

    # RIGOR-5 (caught by hypothesis): a body of `b'0'`, `b'"x"'`,
    # `b'null'`, `b'[]'` etc. is VALID JSON but NOT a JSON object.
    # Calling .get() on the non-dict result raises AttributeError —
    # the webhook handler crashed with a 500 + stack trace. Now we
    # reject non-dict payloads cleanly.
    if not isinstance(payload, dict):
        raise WebhookVerifyError(
            f"body is not a JSON object (got {type(payload).__name__})"
        )

    event_id = payload.get("id")
    event_type = payload.get("type")
    if not isinstance(event_id, str) or not event_id.startswith("evt_"):
        raise WebhookVerifyError(f"missing or malformed event id: {event_id!r}")
    if not isinstance(event_type, str) or "." not in event_type:
        raise WebhookVerifyError(f"missing or malformed event type: {event_type!r}")

    return StripeEvent(
        event_id=event_id,
        event_type=event_type,
        payload=payload,
    )


# v0.16.8 (round-9 security HIGH): cap the number of v1= signatures we'll
# accept from the Stripe-Signature header. Stripe rotates the secret
# during key transitions and may legitimately send 2-3 v1= entries; 5 is
# a generous ceiling. Pre-fix the parser was unbounded — an attacker
# could post `t=<now>,v1=AA,v1=AA,...(100k times)` and force the
# verifier to walk 100k `hmac.compare_digest` calls per request (CPU
# DoS). Reject the header (fail-closed) when the cap is exceeded.
_MAX_V1_SIGNATURES = 5


def _parse_signature_header(header: str) -> tuple[int, list[str]]:
    """Parse ``t=<unix>,v1=<sig>[,v1=<sig>...]`` into
    ``(timestamp, [signature, ...])``.

    Stripe's header format is documented at
    https://stripe.com/docs/webhooks/signatures. We accept up to
    ``_MAX_V1_SIGNATURES`` v1= entries (rollover) and ignore unknown
    scheme prefixes (v0= is the deprecated legacy scheme).
    """
    timestamp: int | None = None
    sigs: list[str] = []
    # Also bound the raw header size — Stripe's real headers are
    # ~150 bytes; rejecting anything over 8KB stops the worker from
    # processing a 1MB header at all.
    if len(header) > 8192:
        raise WebhookVerifyError(
            f"signature header too large ({len(header)} bytes); rejecting"
        )
    for part in header.split(","):
        if "=" not in part:
            continue
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise WebhookVerifyError(f"non-integer timestamp: {value!r}") from None
        elif key == "v1":
            if len(sigs) >= _MAX_V1_SIGNATURES:
                raise WebhookVerifyError(
                    f"too many v1= entries in signature header "
                    f"(>{_MAX_V1_SIGNATURES}); rejecting to avoid CPU DoS"
                )
            sigs.append(value.strip())
        # other schemes (v0, etc.) deliberately ignored
    if timestamp is None:
        raise WebhookVerifyError("missing t= component in header")
    return timestamp, sigs


def get_webhook_secret() -> str:
    """Resolve the webhook secret from env. Used by the HTTP
    handler at request time — separated so tests can patch it."""
    return os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()


__all__ = (
    "StripeEvent",
    "WebhookVerifyError",
    "verify_and_parse",
    "get_webhook_secret",
)
