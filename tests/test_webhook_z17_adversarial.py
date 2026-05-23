"""RIGOR-Jacob Z17: adversarial-input hardening for the Stripe
webhook signature verifier (payments/webhook.py).

Bug covered:

* Z17-W1: non-ASCII chars in the v1= value (e.g.
  ``v1=café`` or ``v1=ñ``) caused ``hmac.compare_digest`` to raise
  ``TypeError: comparing strings with non-ASCII characters is not
  supported`` instead of cleanly raising WebhookVerifyError. The HTTP
  handler treats WebhookVerifyError → 400 but a bare TypeError leaks
  to the WSGI layer as a 500 + stack trace. An attacker probing
  ``/webhooks/stripe`` could trigger 500s at will (DoS / log spam /
  observability noise) just by posting headers with a non-ASCII byte.

  Fix: pre-filter v1= values at parse time — only accept hex chars
  (``[0-9a-fA-F]``) since Stripe HMAC-SHA256 hex digests are 64
  lowercase hex chars by definition. Anything else is malformed and
  must fail the typed verifier error.
"""

from __future__ import annotations

import time

import pytest

from recupero.payments.webhook import (
    WebhookVerifyError,
    verify_and_parse,
)

_SECRET = "whsec_test_secret"


def test_non_ascii_v1_value_raises_typed_error_not_typeerror() -> None:
    """v1=café (containing a non-ASCII char) MUST raise the typed
    WebhookVerifyError, not propagate a TypeError from
    hmac.compare_digest. Pre-fix the verifier crashed with
    ``TypeError: comparing strings with non-ASCII characters is not
    supported`` which the HTTP handler can't translate to a clean
    400 response — it leaks as a 500 + traceback."""
    now = int(time.time())
    body = b'{"id":"evt_test_abc","type":"x.y"}'
    # Non-ASCII char inside the v1= value — well below the 8KB cap,
    # but enough to break hmac.compare_digest if it reaches there.
    header = f"t={now},v1=café"
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_SECRET,
            now_unix=now,
        )


def test_v1_with_control_char_raises_typed_error() -> None:
    """v1=ab\\x01cd (containing a control byte) must also fail with
    the typed verifier error, not a downstream TypeError or weird
    compare result."""
    now = int(time.time())
    body = b'{"id":"evt_test_abc","type":"x.y"}'
    header = f"t={now},v1=abcd"
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_SECRET,
            now_unix=now,
        )


def test_v1_with_only_one_non_hex_char_raises_typed_error() -> None:
    """A single non-hex char in the v1= value invalidates the whole
    signature shape. Must reject cleanly."""
    now = int(time.time())
    body = b'{"id":"evt_test_abc","type":"x.y"}'
    # 63 valid hex chars + one 'z' (non-hex)
    header = f"t={now},v1={'a' * 63}z"
    with pytest.raises(WebhookVerifyError):
        verify_and_parse(
            body_bytes=body,
            signature_header=header,
            webhook_secret=_SECRET,
            now_unix=now,
        )
