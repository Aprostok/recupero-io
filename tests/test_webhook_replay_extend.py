"""Wave-5 adversarial-input hardening for the Stripe webhook
verifier (payments/webhook.py). Extends Z17 hex-validation +
the v0.16.8 v1=-count DoS cap with deeper-cut probes:

* W5-1: v1= signature with VALID hex chars but wrong LENGTH must
  be rejected at parse time. Stripe's HMAC-SHA256 hex digest is
  exactly 64 lowercase hex chars; anything else is malformed. The
  prior gate only checked the character class, so an attacker
  could send v1=ab (2 hex chars) which passes parsing and then
  reaches hmac.compare_digest. compare_digest does length-safe
  compare so it returns False (safe), but the verifier still
  burns CPU on every short-sig probe. Reject at parse time.

* W5-2: timestamp < 0 (e.g. ``t=-1``) is semantically nonsense
  (no Stripe event predates the Unix epoch). Currently int('-1')
  parses fine and only the 5-min replay window catches it.
  Belt-and-braces: reject explicitly so log noise + cache misses
  on negative-timestamp probes are bounded.

* W5-3: error message for non-hex v1= must NOT echo the raw
  attacker-controlled value verbatim. Pre-fix the message was
  ``f"v1= signature contains non-hex chars (or is empty): {v1_value!r}"``
  which copies up to ~8KB of attacker content into application
  logs — log-injection / log-spam vector. Sanitize.

* W5-4: replay PROTECTION inside the tolerance window — the
  verifier itself has no event-id dedupe (the dispatcher does
  via ON CONFLICT). Document that contract by asserting that
  ``verify_and_parse`` is stateless w.r.t. event_id (calling it
  twice with the same valid payload returns the same StripeEvent
  both times — no internal state change). This locks the
  contract so any future "verifier-side dedupe" refactor has to
  update this test AND wire persistent storage.

* W5-5: empty v1= value (``v1=,t=...``) must raise typed error,
  not silently skip. The existing hex-class check would let
  ``""`` slip through ``any(c not in "0..." for c in "")`` → False
  (the all-empty quantifier vacuously holds). The explicit
  ``if not v1_value`` short-circuit guards this — pin it.

* W5-6: signature header with ONLY a t= and zero v1= entries
  must raise typed error (currently does — pin it).
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from recupero.payments.webhook import (
    WebhookVerifyError,
    verify_and_parse,
)

_SECRET = "whsec_test_secret"
_BODY = b'{"id":"evt_test_abc","type":"x.y"}'
_NOW = 1700000000


def _good_sig(*, secret: str = _SECRET, body: bytes = _BODY, ts: int = _NOW) -> str:
    """Compute a valid Stripe-style HMAC-SHA256 hex digest for the
    given timestamp + body, signed with the given secret."""
    signed = f"{ts}.".encode() + body
    return hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


# -----------------------------------------------------------------
# W5-1: signature length enforcement
# -----------------------------------------------------------------

def test_v1_signature_with_short_hex_value_rejected_at_parse() -> None:
    """``v1=ab`` (2 hex chars) is structurally invalid — Stripe
    HMAC-SHA256 hex digests are always 64 chars. Reject at parse
    time so the verifier doesn't even reach hmac.compare_digest."""
    header = f"t={_NOW},v1=ab"
    with pytest.raises(WebhookVerifyError) as exc:
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )
    # Verify it's a parse-time / shape rejection, not "signature mismatch".
    assert "mismatch" not in str(exc.value).lower()


def test_v1_signature_with_long_hex_value_rejected_at_parse() -> None:
    """``v1=<128 hex chars>`` (twice the SHA-256 width) is also
    malformed. Reject at parse — pre-fix it slipped through and
    only failed at compare_digest (correct outcome, wasted work)."""
    header = f"t={_NOW},v1={'a' * 128}"
    with pytest.raises(WebhookVerifyError) as exc:
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )
    assert "mismatch" not in str(exc.value).lower()


def test_valid_64_hex_sig_still_accepted() -> None:
    """Regression guard: a real 64-char HMAC hex digest must
    continue to verify. The length gate must not break the happy
    path."""
    sig = _good_sig()
    header = f"t={_NOW},v1={sig}"
    ev = verify_and_parse(
        body_bytes=_BODY, signature_header=header,
        webhook_secret=_SECRET, now_unix=_NOW,
    )
    assert ev.event_id == "evt_test_abc"
    assert ev.event_type == "x.y"


# -----------------------------------------------------------------
# W5-2: negative timestamp
# -----------------------------------------------------------------

def test_negative_timestamp_rejected() -> None:
    """``t=-1`` is semantically impossible (Stripe events all
    postdate the Unix epoch). Reject — don't rely solely on the
    replay-tolerance window catching it."""
    header = f"t=-1,v1={'a' * 64}"
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )


# -----------------------------------------------------------------
# W5-3: error message must not echo attacker payload verbatim
# -----------------------------------------------------------------

def test_bad_v1_error_does_not_echo_attacker_value_verbatim() -> None:
    """Log-injection / log-spam guard. A v1= value carrying CRLF
    or other log-formatting noise must not appear inside the
    raised WebhookVerifyError message verbatim. Sanitized output
    is fine (e.g. ``"non-hex v1= value (32 bytes)"``)."""
    sentinel = "ZZZADVERSARIALZZZ"  # not hex, will trip the v1 hex gate
    header = f"t={_NOW},v1={sentinel}"
    with pytest.raises(WebhookVerifyError) as exc:
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )
    # The sentinel must NOT appear verbatim in the exception
    # message — that would mean attacker text is being copied
    # straight into application logs.
    assert sentinel not in str(exc.value)


# -----------------------------------------------------------------
# W5-4: verifier is stateless (no internal event-id dedupe)
# -----------------------------------------------------------------

def test_verify_and_parse_is_stateless_across_two_identical_calls() -> None:
    """Documents the contract: dedupe is the dispatcher's job, NOT
    the verifier's. Two identical verify_and_parse calls with the
    same valid payload return the same StripeEvent both times,
    with no internal state change. If we ever add verifier-side
    dedupe (persistent event-id cache), this test must change
    AND the new dedupe must be wired through persistent storage —
    not module-level globals (which lose state on worker restart
    and don't share across workers)."""
    sig = _good_sig()
    header = f"t={_NOW},v1={sig}"
    ev1 = verify_and_parse(
        body_bytes=_BODY, signature_header=header,
        webhook_secret=_SECRET, now_unix=_NOW,
    )
    ev2 = verify_and_parse(
        body_bytes=_BODY, signature_header=header,
        webhook_secret=_SECRET, now_unix=_NOW,
    )
    assert ev1 == ev2
    assert ev1.event_id == ev2.event_id == "evt_test_abc"


# -----------------------------------------------------------------
# W5-5 / W5-6: edge cases pinned
# -----------------------------------------------------------------

def test_empty_v1_value_rejected_with_typed_error() -> None:
    """``v1=`` with no value must raise WebhookVerifyError. The
    existing `if not v1_value` guard catches this; pin it so a
    refactor of the hex-class check can't accidentally re-open
    the empty-string path (where ``any(c not in HEX for c in '')``
    is vacuously False)."""
    header = f"t={_NOW},v1="
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )


def test_header_with_only_timestamp_no_v1_rejected() -> None:
    """``t=<now>`` with zero v1= entries must raise the typed
    error ``"no v1 signature in header"`` — already enforced, pin
    it so a future "accept v0 fallback" change has to update this
    test."""
    header = f"t={_NOW}"
    with pytest.raises(WebhookVerifyError) as exc:
        verify_and_parse(
            body_bytes=_BODY, signature_header=header,
            webhook_secret=_SECRET, now_unix=_NOW,
        )
    assert "v1" in str(exc.value).lower()
