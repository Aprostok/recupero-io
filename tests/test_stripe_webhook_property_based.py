"""Property-based tests for Stripe webhook signature verification.

The webhook is one of the most security-critical surfaces in the
product — a forged signature lets an attacker trigger arbitrary case
creation, payment confirmation emails, and investigation INSERTs.
Pre-RIGOR-5 extension, tests covered specific known-good and
known-bad signature shapes. These property tests probe the WHOLE
input space:

  * Replay attack: any timestamp outside ±tolerance MUST fail
    regardless of signature validity
  * CPU DoS: >5 v1= entries in the header MUST fail before any
    HMAC computation
  * Header bomb: >8KB header MUST fail before parsing
  * Signature forgery: any modification of body bytes MUST fail
    verification (HMAC integrity proof)
  * Timing-safe compare: hmac.compare_digest is the right primitive;
    we assert it's still used and never replaced with == in source
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recupero.payments.webhook import (
    _MAX_V1_SIGNATURES,
    WebhookVerifyError,
    _parse_signature_header,
    verify_and_parse,
)

_SETTINGS = settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


_TEST_SECRET = "whsec_test_secret_for_property_testing"


def _build_signed_request(
    body: bytes,
    timestamp: int,
    secret: str = _TEST_SECRET,
) -> tuple[bytes, str]:
    """Helper: produce (body_bytes, signature_header) using the
    documented Stripe signing convention."""
    signed_payload = f"{timestamp}.".encode() + body
    sig = _hmac.new(
        secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()
    header = f"t={timestamp},v1={sig}"
    return body, header


# ═════════════════════════════════════════════════════════════════════════════
# Property 1: signature tampering ALWAYS rejected
# ═════════════════════════════════════════════════════════════════════════════


@given(byte_pos=st.integers(0, 99))
@_SETTINGS
def test_property_modified_body_fails_verification(byte_pos: int) -> None:
    """Flip ONE byte of the signed body. The signature no longer
    matches. Verification MUST raise WebhookVerifyError."""
    now = int(time.time())
    original_body = (
        b'{"id":"evt_test_123","type":"checkout.session.completed",'
        b'"data":{"object":{"client_reference_id":"diag:CASE:eth:0xabc"}}}'
        # Pad to ensure byte_pos < len(body)
        + b" " * 100
    )
    body, header = _build_signed_request(original_body, now)

    # Tamper: flip 1 bit in the body.
    mutated = bytearray(body)
    mutated[byte_pos] = mutated[byte_pos] ^ 0x01
    tampered_body = bytes(mutated)

    if tampered_body == body:
        # Edge case: XOR 0x01 on a byte that's already toggled produces
        # the same value. Skip (extremely rare with random byte_pos).
        return

    with pytest.raises(WebhookVerifyError) as exc_info:
        verify_and_parse(
            body_bytes=tampered_body,
            signature_header=header,
            webhook_secret=_TEST_SECRET,
            now_unix=now,
        )
    assert "signature mismatch" in str(exc_info.value).lower() or \
           "json" in str(exc_info.value).lower(), (
        f"unexpected error class: {exc_info.value}"
    )


@given(forged_sig_hex=st.text(
    alphabet="0123456789abcdef",
    min_size=64, max_size=64,
))
@_SETTINGS
def test_property_random_signature_hex_always_fails(
    forged_sig_hex: str,
) -> None:
    """Hypothesis generates random 64-char hex strings. NONE of them
    should accidentally match the real HMAC of the body — birthday
    bound on 256-bit space makes this astronomically unlikely. The
    test asserts verification ALWAYS rejects them."""
    now = int(time.time())
    body = (
        b'{"id":"evt_test_x","type":"checkout.session.completed",'
        b'"data":{"object":{"x":"y"}}}'
    )
    header = f"t={now},v1={forged_sig_hex}"
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_TEST_SECRET,
            now_unix=now,
        )


# ═════════════════════════════════════════════════════════════════════════════
# Property 2: replay-attack timestamps always rejected
# ═════════════════════════════════════════════════════════════════════════════


@given(skew_sec=st.one_of(
    st.integers(min_value=601, max_value=10_000_000),
    st.integers(min_value=-10_000_000, max_value=-601),
))
@_SETTINGS
def test_property_replay_outside_tolerance_rejected(skew_sec: int) -> None:
    """Stripe's documented replay tolerance is ±5min (we use 600s).
    Any timestamp outside this window MUST be rejected even if the
    signature is otherwise valid. Replay attacks use captured-and-
    delayed legitimate webhook traffic; the tolerance is the only
    defense."""
    now = int(time.time())
    old_t = now - skew_sec
    body = (
        b'{"id":"evt_test","type":"checkout.session.completed",'
        b'"data":{"object":{"x":"y"}}}'
    )
    body, header = _build_signed_request(body, old_t)
    with pytest.raises(WebhookVerifyError) as exc_info:
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_TEST_SECRET,
            now_unix=now,
        )
    assert "tolerance" in str(exc_info.value).lower(), (
        f"replay outside tolerance should mention 'tolerance', got: "
        f"{exc_info.value}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 3: CPU DoS — too many v1= entries rejected before HMAC
# ═════════════════════════════════════════════════════════════════════════════


@given(n_extra=st.integers(min_value=1, max_value=200))
@_SETTINGS
def test_property_too_many_v1_entries_rejected(n_extra: int) -> None:
    """An attacker can stuff hundreds of v1= entries into the header
    to force the verifier to do hundreds of HMAC compares. The cap
    is 5; anything above MUST be rejected before the first compare.
    """
    now = int(time.time())
    total = _MAX_V1_SIGNATURES + n_extra
    fake_sig = "ff" * 32  # 64-char hex
    parts = [f"t={now}"]
    parts.extend(f"v1={fake_sig}" for _ in range(total))
    header = ",".join(parts)

    # The header itself must be under the size cap (8KB).
    if len(header) > 8192:
        # The size cap fires first — also acceptable behavior.
        pass
    with pytest.raises(WebhookVerifyError) as exc_info:
        _parse_signature_header(header)
    err = str(exc_info.value).lower()
    assert ("too many" in err or "too large" in err), (
        f"expected too-many or too-large error, got: {exc_info.value}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 4: oversized header (>8KB) rejected before parsing
# ═════════════════════════════════════════════════════════════════════════════


@given(size_kb=st.integers(min_value=9, max_value=64))
@_SETTINGS
def test_property_oversized_header_rejected(size_kb: int) -> None:
    """A 64KB Stripe-Signature header is implausible. The parser
    must reject anything over 8KB before doing any work — otherwise
    an attacker can post a 1MB header at request time and force the
    worker into the parsing loop on it."""
    header = "A" * (size_kb * 1024)
    with pytest.raises(WebhookVerifyError) as exc_info:
        _parse_signature_header(header)
    assert "too large" in str(exc_info.value).lower(), (
        f"oversize header should fail with 'too large', got: "
        f"{exc_info.value}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 5: hmac.compare_digest is still used (constant-time compare)
# ═════════════════════════════════════════════════════════════════════════════


def test_constant_time_compare_used_in_source() -> None:
    """Source contract: signature verification MUST use
    hmac.compare_digest (constant-time) rather than == (timing-
    leak). A mutation that replaces it with == would let a remote
    attacker recover the HMAC byte-by-byte over millions of probes.
    """
    import inspect

    from recupero.payments import webhook

    src = inspect.getsource(webhook.verify_and_parse)
    assert "hmac.compare_digest" in src, (
        "verify_and_parse no longer uses hmac.compare_digest — possible "
        "timing-leak regression. Signature equality must be constant-time."
    )
    # Negative — also assert raw == is NOT used to compare signatures.
    # Pattern: `expected == sig` or `sig == expected` near the
    # signature-compare comment.
    assert (
        "expected == " not in src and "== expected" not in src
    ), (
        "found raw == comparison near signature verify; likely a "
        "timing-leak regression."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Property 6: malformed JSON body rejected
# ═════════════════════════════════════════════════════════════════════════════


@given(body=st.binary(min_size=0, max_size=1000))
@_SETTINGS
def test_property_malformed_body_handled_cleanly(body: bytes) -> None:
    """Even with a VALID signature over arbitrary bytes, the body
    must parse as JSON with id + type. Garbage body should fail with
    WebhookVerifyError, never a JSONDecodeError leaking out."""
    now = int(time.time())
    body, header = _build_signed_request(body, now)
    try:
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_TEST_SECRET,
            now_unix=now,
        )
    except WebhookVerifyError:
        pass  # Expected for non-JSON / wrong-shape bodies.
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"unexpected {type(e).__name__} on body {body[:30]!r}: {e}"
        )


# ═════════════════════════════════════════════════════════════════════════════
# Property 7: missing webhook secret fails closed
# ═════════════════════════════════════════════════════════════════════════════


@given(empty_secret=st.sampled_from(["", " ", "\t", "\n"]))
@_SETTINGS
def test_property_empty_secret_fails_closed(empty_secret: str) -> None:
    """If the operator misconfigures STRIPE_WEBHOOK_SECRET to an
    empty / whitespace string, verification MUST refuse to run.
    Pre-fix a bare empty string compared as "matching" the body's
    HMAC under the empty key — accepting every request.
    """
    now = int(time.time())
    body = b'{"id":"evt_test","type":"x.y"}'
    body, header = _build_signed_request(body, now)
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=empty_secret,
            now_unix=now,
        )
