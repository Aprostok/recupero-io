"""Adversarial-input wave: error messages must not leak secrets.

Many exception paths interpolate response bodies / URLs / payloads
into ``raise X(f"...")`` messages. The logging-setup redaction layer
(``recupero.logging_setup._SecretRedactingFilter``) catches a known
set of shapes (``Bearer ...``, ``?api-key=...``, Stripe / Resend /
JWT prefixes, ``Authorization: ...`` headers, full Postgres DSNs),
but it does NOT catch:

  * Path-segment API keys (``https://eth-mainnet.g.alchemy.com/v2/<KEY>``
    has no fixed prefix so no anchor for a regex).
  * Storage-API response bodies that echo back the request's bearer.
  * Arbitrary JSON envelopes interpolated via ``{payload!r}``.

These RED tests assert that each error-message construction path is
already scrubbed at the source — defense-in-depth so an exception
caught and stringified outside the logging pipeline (e.g., printed
to stdout via ``print(exc)``, surfaced in a Sentry breadcrumb tag,
or re-raised across a process boundary) does NOT carry the secret.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch


# -------- Alchemy: api_key is in URL path segment -------- #


def test_alchemy_transport_error_does_not_leak_api_key_in_url() -> None:
    """RED: A network error inside ``_rpc`` must not include the raw
    api_key (which lives in ``self.api_url``)."""
    import httpx
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
    )

    secret = "alch_secret_DO_NOT_LEAK_abc123XYZ"
    client = AlchemyClient(api_key=secret, chain_id=1)

    # Worst case: an httpx exception whose stringified form embeds the
    # full request URL with the api_key in the path segment. We
    # construct one explicitly so the test isn't sensitive to which
    # httpx version puts URLs into __str__.
    err = httpx.ConnectError(
        f"All connection attempts failed for url "
        f"'https://eth-mainnet.g.alchemy.com/v2/{secret}'"
    )
    client._client = MagicMock()
    client._client.post.side_effect = err
    client.limiter = MagicMock()

    raised: Exception | None = None
    try:
        client._rpc("eth_blockNumber", [])
    except AlchemyError as e:
        raised = e

    assert raised is not None, "expected AlchemyError"
    msg = str(raised)
    assert secret not in msg, f"api_key leaked in error message: {msg!r}"
    assert "[REDACTED]" in msg, (
        f"redaction sentinel missing: {msg!r}"
    )


def test_alchemy_429_response_text_redacted() -> None:
    """RED: A 429 body that echoes the request URL must be redacted
    before being interpolated into the AlchemyRateLimitError."""
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyRateLimitError,
    )

    secret = "alch_secret_DO_NOT_LEAK_xyz789"
    client = AlchemyClient(api_key=secret, chain_id=1)

    fake_resp = MagicMock()
    fake_resp.status_code = 429
    # Real Alchemy 429 bodies have been observed to echo the request
    # URL in the diagnostic message.
    fake_resp.text = (
        f"rate-limited by https://eth-mainnet.g.alchemy.com/v2/{secret}"
    )
    client._client = MagicMock()
    client._client.post.return_value = fake_resp
    client.limiter = MagicMock()

    raised: Exception | None = None
    try:
        client._rpc("eth_blockNumber", [])
    except AlchemyRateLimitError as e:
        raised = e

    assert raised is not None
    assert secret not in str(raised), (
        f"api_key leaked in 429 message: {raised!r}"
    )


def test_alchemy_non_json_body_redacted() -> None:
    """RED: A 200-but-HTML response (Cloudflare edge incident) goes
    through ``resp.json()`` which raises ``ValueError``; we re-raise
    as AlchemyError with ``resp.text[:200]`` — must be redacted."""
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
    )

    secret = "alch_secret_DO_NOT_LEAK_html"
    client = AlchemyClient(api_key=secret, chain_id=1)

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.side_effect = ValueError("Expecting value: line 1 column 1")
    fake_resp.text = (
        f"<html>requested {secret}.alchemy.com via /v2/{secret}</html>"
    )
    client._client = MagicMock()
    client._client.post.return_value = fake_resp
    client.limiter = MagicMock()

    raised: Exception | None = None
    try:
        client._rpc("eth_blockNumber", [])
    except AlchemyError as e:
        raised = e

    assert raised is not None
    assert secret not in str(raised), (
        f"api_key leaked in non-JSON-body path: {raised!r}"
    )


def test_alchemy_rpc_error_message_redacted() -> None:
    """RED: An Alchemy JSON-RPC error envelope (``{"error": {...}}``)
    sometimes echoes the request URL. Must be redacted before raising."""
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
    )

    secret = "alch_secret_DO_NOT_LEAK_rpcerr"
    client = AlchemyClient(api_key=secret, chain_id=1)

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "error": {
            "code": -32602,
            "message": f"invalid request to /v2/{secret}",
        }
    }
    client._client = MagicMock()
    client._client.post.return_value = fake_resp
    client.limiter = MagicMock()

    raised: Exception | None = None
    try:
        client._rpc("eth_blockNumber", [])
    except AlchemyError as e:
        raised = e

    assert raised is not None
    assert secret not in str(raised), (
        f"api_key leaked in rpc-error path: {raised!r}"
    )


# -------- Supabase Storage: response payload echo -------- #


def test_sign_storage_url_error_does_not_echo_full_payload() -> None:
    """RED: ``_sign_storage_url`` previously did ``raise RuntimeError(
    f"sign API returned no URL: {payload!r}")``. Supabase Storage
    error responses can echo the request's ``Authorization`` header
    (in diagnostic-mode mirrors) and always include the request's
    object_path (which carries a sensitive investigation case_id).
    The message must surface ONLY the response field names, not the
    full payload contents."""
    from recupero.worker.investigations_api import _sign_storage_url

    sensitive_path = "investigation-sensitive-case-id/private-victim-evidence.pdf"
    bearer = "eyJhbGciOiJIUzI1NiJ9.SENSITIVE_SERVICE_ROLE_JWT.signature"

    # Mock urlopen so we control the payload that comes back.
    error_payload = {
        "error": "unauthorized",
        "echo_authorization": f"Bearer {bearer}",
        "echo_path": sensitive_path,
    }

    class _FakeResp:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    with patch(
        "recupero.worker.investigations_api.urllib.request.urlopen",
        return_value=_FakeResp(json.dumps(error_payload).encode()),
    ):
        raised: Exception | None = None
        try:
            _sign_storage_url(
                supabase_url="https://example.supabase.co",
                service_role_key=bearer,
                object_path=sensitive_path,
                ttl_sec=60,
            )
        except RuntimeError as e:
            raised = e

    assert raised is not None
    msg = str(raised)
    assert bearer not in msg, f"service-role JWT leaked: {msg!r}"
    assert sensitive_path not in msg, f"case-id path leaked: {msg!r}"
    # Positive assertion: response keys should still be surfaced so the
    # message remains debuggable.
    assert "error" in msg or "keys" in msg, (
        f"diagnostic context missing from redacted message: {msg!r}"
    )


# -------- psycopg DSN propagation -------- #


def test_db_connect_redacts_dsn_password_on_operational_error() -> None:
    """RED: ``recupero._common.db_connect`` must re-raise psycopg
    ``OperationalError``s with the DSN password replaced by ``***``."""
    from recupero._common import db_connect

    secret_pw = "DO_NOT_LEAK_db_password_42"
    dsn = f"postgresql://postgres:{secret_pw}@db.example.supabase.co:5432/postgres"

    # Patch psycopg.connect to raise an OperationalError whose message
    # embeds the full DSN — this is the real psycopg behavior on
    # password-auth failure.
    import psycopg

    raised: Exception | None = None
    with patch(
        "psycopg.connect",
        side_effect=psycopg.OperationalError(
            f"connection failed: FATAL: password authentication failed for "
            f"user 'postgres' (dsn: {dsn})"
        ),
    ):
        try:
            db_connect(dsn)
        except psycopg.OperationalError as e:
            raised = e

    assert raised is not None
    msg = str(raised)
    assert secret_pw not in msg, f"DSN password leaked: {msg!r}"
    assert "***" in msg, f"redaction sentinel missing: {msg!r}"


# -------- Negative: ensure existing safe paths stay safe -------- #


def test_webhook_verify_does_not_echo_full_body() -> None:
    """RED: Webhook verify errors must not echo the raw request body —
    the body may carry payment-method tokens or PII (Stripe events
    include `customer_email`, `card.last4`, etc.)."""
    from recupero.payments.webhook import (
        WebhookVerifyError,
        verify_and_parse,
    )

    sensitive_email = "victim_aprostok+private@example.com"
    sensitive_pm = "pm_1Sensitive_secret_card_token_DO_NOT_LEAK"
    body = json.dumps({
        "id": "evt_INVALID_SHAPE",  # malformed event_id — wrong prefix
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "customer_email": sensitive_email,
                "payment_method": sensitive_pm,
            }
        },
    }).encode()

    raised: Exception | None = None
    # Pin the clock + bypass signature so we reach the body-parse path
    # where the malformed event_id will fail validation.
    with patch(
        "recupero.payments.webhook._parse_signature_header",
        return_value=(0, ["00" * 32]),
    ), patch(
        "recupero.payments.webhook.hmac.compare_digest",
        return_value=True,
    ):
        try:
            verify_and_parse(
                body_bytes=body,
                signature_header="t=0,v1=" + "00" * 32,
                webhook_secret="whsec_test",
                now_unix=0.0,
            )
        except WebhookVerifyError as e:
            raised = e

    # Tolerant assertion: if verify_and_parse accepts the payload
    # silently (current contract — body-shape validation happens at
    # the dispatcher layer, not the verifier), the no-leak property
    # holds vacuously. If a future change WOULD raise on this shape,
    # the raise message must still not echo the sensitive fields.
    msg = str(raised) if raised is not None else ""
    assert sensitive_email not in msg, f"email leaked: {msg!r}"
    assert sensitive_pm not in msg, f"payment-method token leaked: {msg!r}"
