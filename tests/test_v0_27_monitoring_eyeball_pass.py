"""PUNISH-A: punishing tests for v0.27 monitoring API + bulk screen.

Partner-facing JSON surface. Multi-tenant boundary integrity,
webhook payload determinism + signature stability, SSRF rejection,
bulk-screen per-row tolerance. The contract surface partners will
integrate against — needs to be airtight.

No "may contain" / "if found" softening; every assertion is
unconditional and quotes the failing field.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

_API_SECRET = "secret-test-token-xyz"
_KEY_NAME = "tester"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(monkeypatch):
    """API client with one valid API key + DSN configured."""
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY_NAME}:{_API_SECRET}")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


def _hdr() -> dict[str, str]:
    return {"X-Recupero-API-Key": _API_SECRET}


# ─────────────────────────────────────────────────────────────────────────────
# /v1/monitor/subscribe — create
# ─────────────────────────────────────────────────────────────────────────────


def _good_subscribe_body(**overrides):
    body = {
        "address": "0x" + "a" * 40,
        "chain": "ethereum",
        "trigger_type": "any_movement",
        "webhook_url": "https://hooks.example.com/recupero",
    }
    body.update(overrides)
    return body


def test_subscribe_201_returns_full_url_on_first_response(api_client):
    """The CREATE response is the one and only time the partner sees
    the full webhook URL echoed back (confirmation). Subsequent
    list/get responses must mask it."""
    from recupero.api.monitoring_api import SubscriptionRecord
    sub_id = UUID("11111111-1111-1111-1111-111111111111")
    fake = SubscriptionRecord(
        id=sub_id, address="0x" + "a" * 40, chain="ethereum",
        trigger_type="any_movement", threshold_usd=None,
        webhook_url="https://hooks.example.com/recupero/secret-path",
        label="x", status="active",
        created_at="2026-05-20T12:00:00",
        last_alerted_at=None, expires_at=None,
    )
    with patch(
        "recupero.api.monitoring_api.create_subscription",
        return_value=fake,
    ):
        resp = api_client.post(
            "/v1/monitor/subscribe",
            json=_good_subscribe_body(
                webhook_url="https://hooks.example.com/recupero/secret-path",
            ),
            headers=_hdr(),
        )
    assert resp.status_code == 201, (
        f"subscribe should 201, got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    assert body["id"] == str(sub_id), "id missing/wrong"
    # CREATE response carries full URL.
    assert body["webhook_url"] == (
        "https://hooks.example.com/recupero/secret-path"
    ), "create response should return the full webhook_url"


def test_subscribe_401_without_api_key(api_client):
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(),
    )
    assert resp.status_code == 401, (
        f"missing API key must 401, got {resp.status_code}"
    )


def test_subscribe_rejects_blocked_ssrf_target(api_client):
    """v0.27.1 SSRF defense: webhook_url = metadata service IP MUST
    be rejected at validation time. The platform's IAM credentials
    are at stake."""
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(
            webhook_url="https://169.254.169.254/latest/meta-data/",
        ),
        headers=_hdr(),
    )
    # The SSRF check raises MonitoringApiError → 400 from the endpoint.
    assert resp.status_code in (400, 422), (
        f"169.254.169.254 webhook_url must be rejected, got "
        f"{resp.status_code}: {resp.text}"
    )


def test_subscribe_rejects_loopback_url(api_client):
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(
            webhook_url="https://localhost:8443/hook",
        ),
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        f"loopback webhook_url must be rejected, got {resp.status_code}"
    )


def test_subscribe_rejects_private_ip_url(api_client):
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(
            webhook_url="https://10.0.0.5/hook",
        ),
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422)


def test_subscribe_rejects_cleartext_http_url(api_client):
    """v0.27.1 MED-3: webhook_url must use https://, not http://."""
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(
            webhook_url="http://hooks.example.com/recupero",
        ),
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        "http:// webhook_url must be rejected"
    )


def test_subscribe_rejects_short_webhook_secret(api_client):
    """v0.27.1 HIGH-1: webhook_secret must be ≥16 chars when provided."""
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json={
            **_good_subscribe_body(),
            "webhook_secret": "tooshort",
        },
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        "short webhook_secret must be rejected"
    )


def test_subscribe_rejects_missing_threshold_for_movement_above_usd(api_client):
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_subscribe_body(trigger_type="movement_above_usd"),
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        "movement_above_usd without threshold must be rejected"
    )


# ─────────────────────────────────────────────────────────────────────────────
# /v1/monitor/subscriptions — list (URL masking)
# ─────────────────────────────────────────────────────────────────────────────


def test_list_response_masks_webhook_url(api_client):
    """HIGH-4: list/get must mask the webhook URL so a leaked API
    key doesn't yield the partner's internal endpoint paths."""
    from recupero.api.monitoring_api import SubscriptionRecord
    sub_id = UUID("11111111-1111-1111-1111-111111111111")
    fake = SubscriptionRecord(
        id=sub_id, address="0x" + "a" * 40, chain="ethereum",
        trigger_type="any_movement", threshold_usd=None,
        webhook_url=(
            "https://compliance.acme-exchange.com/webhooks/recupero/"
            "deeply-nested/secret-token-abc-12345"
        ),
        label="x", status="active",
        created_at="2026-05-20T12:00:00",
        last_alerted_at=None, expires_at=None,
    )
    with patch(
        "recupero.api.monitoring_api.list_subscriptions",
        return_value=[fake],
    ):
        resp = api_client.get(
            "/v1/monitor/subscriptions",
            headers=_hdr(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    masked = body["subscriptions"][0]["webhook_url"]
    # The secret-token tail must be GONE.
    assert "secret-token-abc-12345" not in masked, (
        f"list response leaked the full webhook URL secret tail: "
        f"{masked!r}. HIGH-4 mask should have stripped it."
    )
    # The scheme + host + first path segment must still be there
    # so the partner recognizes which webhook this is.
    assert "compliance.acme-exchange.com" in masked, (
        "list response masked too aggressively — partner can't tell "
        "which webhook this is"
    )


def test_list_503_when_db_unreachable(api_client):
    """HIGH-5: DB error must surface as 503, not empty list."""
    from recupero.api.monitoring_api import MonitoringDbError
    with patch(
        "recupero.api.monitoring_api.list_subscriptions",
        side_effect=MonitoringDbError("simulated DB outage"),
    ):
        resp = api_client.get(
            "/v1/monitor/subscriptions",
            headers=_hdr(),
        )
    assert resp.status_code == 503, (
        f"DB error must surface as 503, got {resp.status_code}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# /v1/monitor/{id} — get + delete
# ─────────────────────────────────────────────────────────────────────────────


def test_get_returns_404_for_foreign_subscription(api_client):
    """A subscription owned by partner B must look identical to a
    non-existent ID when partner A queries it — same 404, same
    body. No oracle."""
    with patch(
        "recupero.api.monitoring_api.get_subscription",
        return_value=None,
    ):
        resp = api_client.get(
            "/v1/monitor/22222222-2222-2222-2222-222222222222",
            headers=_hdr(),
        )
    assert resp.status_code == 404
    detail = resp.json().get("detail", "")
    # No mention of "foreign" / "not yours" / partner-id hints.
    assert "not yours" not in detail.lower()
    assert "foreign" not in detail.lower()


def test_get_404_on_malformed_uuid(api_client):
    """A non-UUID id must 404, not 422 or 500."""
    resp = api_client.get(
        "/v1/monitor/not-a-uuid",
        headers=_hdr(),
    )
    assert resp.status_code == 404


def test_get_response_masks_webhook_url(api_client):
    from recupero.api.monitoring_api import SubscriptionRecord
    sub_id = UUID("11111111-1111-1111-1111-111111111111")
    fake = SubscriptionRecord(
        id=sub_id, address="0x" + "a" * 40, chain="ethereum",
        trigger_type="any_movement", threshold_usd=None,
        webhook_url=(
            "https://example.com/webhooks/secret-path-xyz-789"
        ),
        label="x", status="active",
        created_at=None, last_alerted_at=None, expires_at=None,
    )
    with patch(
        "recupero.api.monitoring_api.get_subscription",
        return_value=fake,
    ):
        resp = api_client.get(
            f"/v1/monitor/{sub_id}",
            headers=_hdr(),
        )
    assert resp.status_code == 200
    masked = resp.json()["webhook_url"]
    assert "secret-path-xyz-789" not in masked, (
        "get response leaked webhook URL secret"
    )


def test_delete_returns_404_on_foreign_id(api_client):
    with patch(
        "recupero.api.monitoring_api.soft_delete_subscription",
        return_value=False,
    ):
        resp = api_client.delete(
            "/v1/monitor/22222222-2222-2222-2222-222222222222",
            headers=_hdr(),
        )
    assert resp.status_code == 404


def test_delete_returns_200_on_owned_id(api_client):
    sub_id = UUID("11111111-1111-1111-1111-111111111111")
    with patch(
        "recupero.api.monitoring_api.soft_delete_subscription",
        return_value=True,
    ):
        resp = api_client.delete(
            f"/v1/monitor/{sub_id}",
            headers=_hdr(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("deleted") is True


def test_delete_503_on_db_error(api_client):
    from recupero.api.monitoring_api import MonitoringDbError
    with patch(
        "recupero.api.monitoring_api.soft_delete_subscription",
        side_effect=MonitoringDbError("simulated DB outage"),
    ):
        resp = api_client.delete(
            "/v1/monitor/22222222-2222-2222-2222-222222222222",
            headers=_hdr(),
        )
    assert resp.status_code == 503, (
        f"delete on DB outage must 503, got {resp.status_code}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Webhook payload + signature
# ─────────────────────────────────────────────────────────────────────────────


def _make_payload():
    from recupero.monitoring.dispatcher import AlertPayload
    return AlertPayload(
        subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
        trigger_type="any_movement",
        address="0xabc123",
        chain="ethereum",
        tx_hash="0xdeadbeef",
        block_time_iso="2026-05-20T12:00:00Z",
        amount_usd=Decimal("1234.56"),
        counterparty="0xdef456",
        counterparty_label="Binance hot wallet",
        explorer_url="https://etherscan.io/tx/0xdeadbeef",
    )


def test_webhook_body_is_deterministic():
    """Same payload → same byte-for-byte body. Receiver re-serializes
    + compares signatures, so any non-determinism breaks signature
    verification."""
    from recupero.monitoring.dispatcher import build_webhook_body
    # Patch the timestamp generator so two calls produce identical
    # output — the rest of the payload is static so any difference
    # would be in key ordering / separators.
    p = _make_payload()
    with patch(
        "recupero.monitoring.dispatcher.datetime"
    ) as fake_dt:
        from datetime import UTC, datetime
        fake_dt.now.return_value = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)
        fake_dt.UTC = UTC
        body1 = build_webhook_body(p)
        body2 = build_webhook_body(p)
    assert body1 == body2, "webhook body non-deterministic"


def test_webhook_body_includes_idempotency_key():
    from recupero.monitoring.dispatcher import build_webhook_body
    body = json.loads(build_webhook_body(_make_payload()))
    assert "idempotency_key" in body, "no idempotency_key"
    key = body["idempotency_key"]
    # The key must encode subscription_id + chain + tx_hash + trigger.
    assert "11111111-1111-1111-1111-111111111111" in key
    assert "ethereum" in key
    assert "0xdeadbeef" in key
    assert "any_movement" in key


def test_webhook_signature_verifies():
    """HMAC-SHA256 of the body using the secret must equal what
    compute_signature returns. Partners doing their own HMAC must
    get a matching digest."""
    from recupero.monitoring.dispatcher import (
        build_webhook_body,
        compute_signature,
    )
    body = build_webhook_body(_make_payload())
    secret = "very-secret-32-character-string!"
    sig = compute_signature(body, secret)
    # Format: "sha256=<hex>"
    assert sig.startswith("sha256="), f"bad signature format: {sig!r}"
    hex_part = sig.removeprefix("sha256=")
    # Manually compute and compare.
    expected = hmac.new(
        secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert hex_part == expected, "HMAC signature mismatch"


def test_webhook_body_keys_sorted():
    """JSON body is sort_keys=True so the byte representation is
    stable for signature stability."""
    from recupero.monitoring.dispatcher import build_webhook_body
    body = build_webhook_body(_make_payload())
    # The top-level keys appear in alphabetical order.
    # Crude check: 'address' appears before 'fired_at' which appears
    # before 'subscription_id'.
    idx_address = body.find('"address"')
    idx_fired = body.find('"fired_at"')
    idx_sub = body.find('"subscription_id"')
    assert idx_address < idx_fired < idx_sub, (
        "JSON keys not sorted — signature will not be stable"
    )


# ─────────────────────────────────────────────────────────────────────────────
# /v1/screen/bulk
# ─────────────────────────────────────────────────────────────────────────────


def test_bulk_screen_returns_one_result_per_address(api_client):
    """Length of results must equal length of input addresses."""
    addrs = ["0x" + c * 40 for c in "abcde"]
    with patch(
        "recupero.screen.screener.screen_address",
    ) as mock:
        # Each call returns an object with to_json_safe()
        fake_result = MagicMock()
        fake_result.to_json_safe.return_value = {
            "address": "x", "verdict": "clean",
        }
        mock.return_value = fake_result
        resp = api_client.post(
            "/v1/screen/bulk",
            json={"addresses": addrs, "chain": "ethereum"},
            headers=_hdr(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 5, (
        f"bulk screen returned count={body['count']}, expected 5"
    )
    assert len(body["results"]) == 5


def test_bulk_screen_per_row_runtime_error_does_not_abort_batch(api_client):
    """v0.27.1 CRIT-3: a RuntimeError on row 3 must NOT 500 the
    whole batch. Rows 1+2 + 4+5 must still return results, row 3
    gets an error entry."""
    addrs = ["0x" + c * 40 for c in "abcde"]
    call_count = {"n": 0}

    def fake_screen(addr, **kw):
        call_count["n"] += 1
        if call_count["n"] == 3:
            raise RuntimeError("simulated DB outage on address 3")
        r = MagicMock()
        r.to_json_safe.return_value = {"address": addr, "verdict": "clean"}
        return r

    with patch(
        "recupero.screen.screener.screen_address",
        side_effect=fake_screen,
    ):
        resp = api_client.post(
            "/v1/screen/bulk",
            json={"addresses": addrs, "chain": "ethereum"},
            headers=_hdr(),
        )
    assert resp.status_code == 200, (
        f"per-row failure should NOT abort the batch, got "
        f"{resp.status_code}"
    )
    results = resp.json()["results"]
    assert len(results) == 5
    # Row 3 has an "error" key, others have "verdict".
    assert "error" in results[2], (
        "row that raised must come back with error entry"
    )
    # Generic error message — no DSN/internal info leakage.
    assert "DB outage" not in results[2]["error"], (
        "per-row error should not echo raw exception text"
    )


def test_bulk_screen_rejects_oversize_batch(api_client):
    """v0.27.1 CRIT-2: list capped at 100 elements."""
    resp = api_client.post(
        "/v1/screen/bulk",
        json={"addresses": ["0x" + "a" * 40] * 101, "chain": "ethereum"},
        headers=_hdr(),
    )
    assert resp.status_code == 422


def test_bulk_screen_rejects_oversize_address(api_client):
    """v0.27.1 CRIT-2: per-element 128-char cap."""
    resp = api_client.post(
        "/v1/screen/bulk",
        json={
            "addresses": ["0x" + "a" * 200],
            "chain": "ethereum",
        },
        headers=_hdr(),
    )
    assert resp.status_code == 422


def test_bulk_screen_rejects_empty_batch(api_client):
    resp = api_client.post(
        "/v1/screen/bulk",
        json={"addresses": [], "chain": "ethereum"},
        headers=_hdr(),
    )
    assert resp.status_code == 422


def test_bulk_screen_401_without_api_key(api_client):
    resp = api_client.post(
        "/v1/screen/bulk",
        json={"addresses": ["0x" + "a" * 40], "chain": "ethereum"},
    )
    assert resp.status_code == 401
