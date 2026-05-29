"""PUNISH-B S-2: SSRF dispatch-time check.

v0.27.1 closed SSRF at subscription-CREATE time but the dispatcher
loop fires hours/days later. A partner who created a sub with a
benign public-IP URL can flip their DNS to 169.254.169.254 (or any
blocked target) before the next monitor_tick, and the worker would
happily POST to internal infra — exfiltrating AWS/GCP metadata
credentials or scanning internal services.

The fix: dispatch_alert() must re-run assert_webhook_url_safe() at
DISPATCH time, before httpx hits the wire. On reject the call
returns WebhookDispatchResult(succeeded=False, error_message=...)
without firing the HTTP request.

This file is the punishing test. It fails on the pre-fix dispatcher
because no SSRF check exists. The fix makes it pass without
softening any assertion.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest


def _make_payload(webhook_url_does_not_matter=True):
    """Build a real AlertPayload — the dispatcher accepts it directly."""
    from recupero.monitoring.dispatcher import AlertPayload
    return AlertPayload(
        subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
        trigger_type="any_movement",
        address="0xabc123",
        chain="ethereum",
        tx_hash="0xdeadbeef",
        block_time_iso="2026-05-20T12:00:00Z",
        amount_usd=Decimal("1000"),
        counterparty="0xdef456",
        counterparty_label="Mock",
        explorer_url="https://etherscan.io/tx/0xdeadbeef",
    )


@pytest.mark.parametrize("blocked_url", [
    # Metadata services
    "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "https://metadata.google.internal/computeMetadata/v1/instance/",
    # Loopback
    "https://127.0.0.1:6379/hook",
    "https://localhost:8443/hook",
    "https://[::1]/hook",
    # RFC1918 private
    "https://10.0.0.5/hook",
    "https://192.168.1.1/hook",
    "https://172.17.0.1/hook",
    # Cleartext http
    "http://hooks.example.com/recupero",
    # Railway / k8s internal
    "https://supabase-db.railway.internal/hook",
    "https://svc.cluster.local/hook",
    "https://foo.local/hook",
])
def test_dispatcher_rejects_blocked_url_without_posting(blocked_url):
    """dispatch_alert called with a blocked webhook_url MUST:
      1. NOT make an HTTP request (httpx.post must be untouched)
      2. Return WebhookDispatchResult(succeeded=False)
      3. error_message must explain why (e.g. 'url failed safety re-check')
    """
    from recupero.monitoring.dispatcher import dispatch_alert
    payload = _make_payload()

    # We don't even patch httpx.Client — if the dispatcher tries to
    # POST to localhost it'll fail with a connection error (which is
    # an even louder signal that the SSRF gate didn't fire). Patch
    # the client.post path to assert it was NOT called.
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        result = dispatch_alert(
            payload,
            webhook_url=blocked_url,
            webhook_secret=None,
            attempt_number=1,
        )
        # The CRITICAL assertion: the SSRF check must have run BEFORE
        # the HTTP request. mock_client.post must NEVER have been
        # called.
        assert not mock_client.post.called, (
            f"dispatcher hit {blocked_url!r} on the wire — SSRF "
            "dispatch-time check missing. This is the v0.27.1 "
            "audit's HIGH-2 finding still live."
        )

    assert result.succeeded is False, (
        f"dispatcher reported succeeded=True on blocked URL {blocked_url!r}"
    )
    # The error_message must say *why*, so the audit row tells the
    # operator the dispatch was security-blocked (not a network blip).
    err = (result.error_message or "").lower()
    assert any(
        kw in err for kw in ("safety", "blocked", "ssrf", "private", "loopback", "rejected")
    ), (
        f"error_message {result.error_message!r} doesn't explain "
        "the security rejection — operator can't tell this apart "
        "from a connection error"
    )


def test_dispatcher_allows_public_https_url():
    """Regression guard: real public URLs MUST still dispatch.
    The SSRF defense must not block legitimate webhooks."""

    from recupero.monitoring.dispatcher import dispatch_alert

    payload = _make_payload()
    # Use respx-style mock by patching the Client.post to return 200.
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_resp = type("MockResp", (), {
            "status_code": 200,
            "text": "ok",
        })()
        mock_client.post.return_value = mock_resp
        result = dispatch_alert(
            payload,
            webhook_url="https://hooks.example.com/recupero",
            webhook_secret=None,
            attempt_number=1,
        )
        assert mock_client.post.called, (
            "public URL should have hit the wire"
        )
    assert result.succeeded is True, (
        f"public URL dispatch reported succeeded=False: "
        f"{result.error_message!r}"
    )


def test_dispatcher_rejects_unparseable_url():
    """A malformed URL must be rejected at dispatch — no partial
    parse fallthrough to httpx."""
    from recupero.monitoring.dispatcher import dispatch_alert
    payload = _make_payload()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        result = dispatch_alert(
            payload,
            webhook_url="not-a-url-at-all",
            webhook_secret=None,
            attempt_number=1,
        )
        assert not mock_client.post.called
    assert result.succeeded is False


def test_dispatch_owned_client_pins_tls_verify_and_no_redirects():
    """v0.32.1 (security-audit cycle-2): the owned httpx client must be
    constructed with verify=True (TLS cert verification — the PRIMARY
    DNS-rebind defense: a rebound internal IP cannot present a cert valid
    for the attacker's webhook hostname) and follow_redirects=False (a 3xx
    to an internal URL would bypass the up-front SSRF check). Pinned
    explicitly so an httpx default change / refactor can't silently weaken
    the SSRF posture."""
    from unittest.mock import patch

    from recupero.monitoring.dispatcher import dispatch_alert
    payload = _make_payload()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = type(
            "R", (), {"status_code": 200, "text": "ok"},
        )()
        dispatch_alert(
            payload, webhook_url="https://hooks.example.com/recupero",
            webhook_secret=None, attempt_number=1,
        )
        assert mock_client_cls.called
        kwargs = mock_client_cls.call_args.kwargs
        assert kwargs.get("verify") is True, (
            "owned webhook client must verify TLS certs (DNS-rebind defense)"
        )
        assert kwargs.get("follow_redirects") is False, (
            "owned webhook client must NOT follow redirects (redirect SSRF)"
        )


def test_dispatch_treats_3xx_as_failure_not_success():
    """A 3xx (e.g. a redirect to an internal URL) must be recorded as a
    non-2xx FAILURE — never followed, never treated as a delivered alert."""
    from unittest.mock import patch

    from recupero.monitoring.dispatcher import dispatch_alert
    payload = _make_payload()
    with patch("httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.post.return_value = type(
            "R", (), {"status_code": 302, "text": ""},
        )()
        result = dispatch_alert(
            payload, webhook_url="https://hooks.example.com/recupero",
            webhook_secret=None, attempt_number=1,
        )
    assert result.succeeded is False
    assert result.status_code == 302
