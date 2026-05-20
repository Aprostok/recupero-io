"""Tests for v0.21.0 monitoring email channel + multi-channel fan-out.

Covers:
  * build_email_alert_body() — pure-function preview / subject line
  * dispatch_email_alert() — Resend integration mocked, quota guard
  * dispatch_all_channels() — webhook + email fan-out semantics
  * record_alert_attempt() — single row captures both per-channel results

DB I/O is mocked; the focus is on the per-channel result aggregation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import httpx
import pytest
import respx

from recupero.monitoring.dispatcher import (
    AlertPayload,
    CombinedDispatchResult,
    EmailDispatchResult,
    WebhookDispatchResult,
    build_email_alert_body,
    dispatch_all_channels,
    dispatch_email_alert,
)
from recupero.monitoring.poller import Subscription


SUB_ID = UUID("22222222-2222-2222-2222-222222222222")
CASE_ID = UUID("33333333-3333-3333-3333-333333333333")
INV_ID = UUID("44444444-4444-4444-4444-444444444444")


def _payload() -> AlertPayload:
    return AlertPayload(
        subscription_id=SUB_ID,
        trigger_type="any_movement",
        address="0xfeed" + "0" * 36,
        chain="ethereum",
        tx_hash="0xabcd" + "ef" * 30,
        block_time_iso="2026-05-20T12:34:56Z",
        amount_usd=Decimal("123456.78"),
        counterparty="0xbeef" + "0" * 36,
        counterparty_label="Binance hot wallet",
        explorer_url="https://etherscan.io/tx/0xabcd",
    )


def _sub(
    *,
    alert_channels: tuple[str, ...] = ("webhook", "email"),
    alert_email: str | None = "investigator@example.com",
    webhook_url: str | None = "https://hook.example.com/alert",
) -> Subscription:
    return Subscription(
        subscription_id=SUB_ID,
        address="0xfeed" + "0" * 36,
        chain="ethereum",
        trigger_type="any_movement",
        threshold_usd=None,
        webhook_url=webhook_url,
        webhook_secret=None,
        last_observed_tx_hash=None,
        alert_channels=alert_channels,
        alert_email=alert_email,
        case_id=CASE_ID,
        investigation_id=INV_ID,
    )


# ─────────────────────────────────────────────────────────────────────────────
# build_email_alert_body — pure function
# ─────────────────────────────────────────────────────────────────────────────


def test_build_email_alert_body_subject_includes_trigger_and_amount():
    """Subject must lead with the trigger type and the USD amount — the
    investigator scans it on a locked phone, so the first 100 chars matter."""
    subject, _ = build_email_alert_body(_payload())
    assert "any_movement" in subject
    assert "$123,456.78" in subject
    assert "ethereum" in subject


def test_build_email_alert_body_unpriced_amount_falls_back():
    """When usd_value is None (unpriced transfer), the subject must not
    render 'None' or '$None' — use a clear fallback string instead."""
    p = _payload()
    p_no_usd = AlertPayload(**{**p.__dict__, "amount_usd": None})
    subject, html = build_email_alert_body(p_no_usd)
    assert "None" not in subject
    assert "(amount unpriced)" in subject
    assert "(amount unpriced)" in html


def test_build_email_alert_body_includes_portal_link_when_case_id_set():
    """When case_id + portal_base_url are both provided, the body must
    embed a 'Open case dashboard' CTA so the investigator can jump in
    with one tap."""
    _, html = build_email_alert_body(
        _payload(),
        case_id=CASE_ID,
        portal_base_url="https://app.recupero.io",
    )
    assert "Open case dashboard" in html
    assert f"https://app.recupero.io/case/{CASE_ID}" in html


def test_build_email_alert_body_omits_portal_link_when_case_id_missing():
    """Without case_id the CTA is omitted (no dead-link)."""
    _, html = build_email_alert_body(
        _payload(),
        portal_base_url="https://app.recupero.io",
    )
    assert "Open case dashboard" not in html


# ─────────────────────────────────────────────────────────────────────────────
# dispatch_email_alert — Resend integration
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatch_email_alert_success_records_message_id():
    """A successful Resend send must produce status_code=0 and capture
    the Resend message_id for the audit log."""
    fake_send_result = type(
        "FakeEmailResult", (),
        {"success": True, "message_id": "msg-abc-123", "error": None, "skipped": False},
    )()
    with patch(
        "recupero.worker._email.send_email",
        return_value=fake_send_result,
    ):
        result = dispatch_email_alert(
            _payload(),
            to_email="investigator@example.com",
            case_id=CASE_ID,
            investigation_id=INV_ID,
            portal_base_url="https://app.recupero.io",
            quota_per_day=0,  # quota disabled for this test
        )
    assert result.succeeded is True
    assert result.status_code == 0
    assert result.message_id == "msg-abc-123"
    assert result.to_address == "investigator@example.com"
    assert result.error_message is None
    assert result.delivered_at is not None


def test_dispatch_email_alert_failure_records_error():
    """A Resend failure must produce status_code=1 and capture the
    error message for the audit log."""
    fake_send_result = type(
        "FakeEmailResult", (),
        {"success": False, "message_id": None, "error": "HTTP 422: invalid recipient",
         "skipped": False},
    )()
    with patch(
        "recupero.worker._email.send_email",
        return_value=fake_send_result,
    ):
        result = dispatch_email_alert(
            _payload(),
            to_email="investigator@example.com",
            quota_per_day=0,
        )
    assert result.succeeded is False
    assert result.status_code == 1
    assert result.message_id is None
    assert "HTTP 422" in (result.error_message or "")
    assert result.delivered_at is None


def test_dispatch_email_alert_quota_exhausted_skips_send():
    """When the per-sub daily quota is exhausted, the dispatcher must
    return status_code=1 with a 'quota exhausted' error WITHOUT calling
    send_email — preserves the Resend daily allowance from a chatty
    wallet subscription."""
    send_called = False

    def _stub_send(*args, **kwargs):
        nonlocal send_called
        send_called = True
        return type("FakeEmailResult", (),
                    {"success": True, "message_id": "x", "error": None,
                     "skipped": False})()

    with patch(
        "recupero.monitoring.dispatcher._email_quota_exhausted",
        return_value=True,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=_stub_send,
    ):
        result = dispatch_email_alert(
            _payload(),
            to_email="investigator@example.com",
            dsn="postgres://fake",
            quota_per_day=5,
        )
    assert send_called is False, "send_email must not be called when quota exhausted"
    assert result.succeeded is False
    assert result.status_code == 1
    assert "quota exhausted" in (result.error_message or "").lower()


# ─────────────────────────────────────────────────────────────────────────────
# dispatch_all_channels — fan-out semantics
# ─────────────────────────────────────────────────────────────────────────────


@respx.mock
def test_dispatch_all_channels_both_webhook_and_email_succeed():
    """A subscription with both channels must dispatch to both. The
    combined result.succeeded must be True iff every attempted channel
    succeeded."""
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200, text="ok")
    )
    fake_send = type("FakeEmailResult", (),
                    {"success": True, "message_id": "msg-1", "error": None,
                     "skipped": False})()
    with patch("recupero.worker._email.send_email", return_value=fake_send):
        result = dispatch_all_channels(
            _payload(),
            subscription=_sub(alert_channels=("webhook", "email")),
        )
    assert result.webhook is not None and result.webhook.succeeded
    assert result.email is not None and result.email.succeeded
    assert result.succeeded is True


@respx.mock
def test_dispatch_all_channels_webhook_only_back_compat():
    """A pre-v0.21.0 subscription (alert_channels=['webhook'], no
    alert_email) must continue to behave identically — only the webhook
    is dispatched, email result is None."""
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200, text="ok")
    )
    result = dispatch_all_channels(
        _payload(),
        subscription=_sub(alert_channels=("webhook",), alert_email=None),
    )
    assert result.webhook is not None and result.webhook.succeeded
    assert result.email is None
    assert result.succeeded is True


def test_dispatch_all_channels_email_only_subscription():
    """An email-only subscription (alert_channels=['email'], no
    webhook_url) must dispatch only the email — webhook result is None.
    Validates the migration-017 nullable webhook_url path."""
    fake_send = type("FakeEmailResult", (),
                    {"success": True, "message_id": "msg-2", "error": None,
                     "skipped": False})()
    with patch("recupero.worker._email.send_email", return_value=fake_send):
        result = dispatch_all_channels(
            _payload(),
            subscription=_sub(alert_channels=("email",), webhook_url=None),
        )
    assert result.webhook is None
    assert result.email is not None and result.email.succeeded
    assert result.succeeded is True


@respx.mock
def test_dispatch_all_channels_webhook_succeeds_email_fails():
    """When one channel fails, .succeeded must be False — but the
    succeeding channel's result is preserved for the audit log so the
    operator can see the partial success."""
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200, text="ok")
    )
    fake_send = type("FakeEmailResult", (),
                    {"success": False, "message_id": None,
                     "error": "HTTP 500: resend down", "skipped": False})()
    with patch("recupero.worker._email.send_email", return_value=fake_send):
        result = dispatch_all_channels(
            _payload(),
            subscription=_sub(alert_channels=("webhook", "email")),
        )
    assert result.webhook is not None and result.webhook.succeeded
    assert result.email is not None and not result.email.succeeded
    assert result.succeeded is False  # combined verdict is failure


def test_combined_dispatch_result_succeeded_requires_attempted_channel():
    """A CombinedDispatchResult with both channels None must report
    succeeded=False — there's no positive outcome to claim."""
    result = CombinedDispatchResult(
        webhook=None, email=None, fired_at=datetime.now(UTC),
    )
    assert result.succeeded is False


# ─────────────────────────────────────────────────────────────────────────────
# record_alert_attempt — back-compat + combined-result handling
# ─────────────────────────────────────────────────────────────────────────────


def test_record_alert_attempt_accepts_legacy_webhook_result():
    """Pre-v0.21.0 callers pass a WebhookDispatchResult directly. The
    audit row must capture the webhook columns and leave email columns
    NULL."""
    captured_params = {}

    class _StubCursor:
        def execute(self, sql, params):
            captured_params.update(params)
        def fetchone(self):
            return ("fake-uuid",)
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    legacy_result = WebhookDispatchResult(
        succeeded=True,
        status_code=200,
        response_body="ok",
        error_message=None,
        attempt_number=1,
        fired_at=datetime.now(UTC),
        delivered_at=datetime.now(UTC),
    )

    from recupero.monitoring import dispatcher as disp
    with patch.object(disp, "db_connect", return_value=_StubConn()):
        disp.record_alert_attempt(
            dsn="postgres://fake",
            payload=_payload(),
            result=legacy_result,
        )

    assert captured_params["w_status"] == 200
    assert captured_params["w_succeeded"] is True
    # Email columns must be NULL (channel not attempted)
    assert captured_params["e_status"] is None
    assert captured_params["e_msg_id"] is None
    assert captured_params["e_to"] is None


def test_record_alert_attempt_captures_both_channels_in_one_row():
    """A combined result with both channels must produce ONE row with
    both webhook and email columns populated — not two rows (which would
    break the existing subscription_id+fired_at index assumptions)."""
    captured_params = {}
    insert_calls = []

    class _StubCursor:
        def execute(self, sql, params):
            insert_calls.append(sql)
            captured_params.update(params)
        def fetchone(self):
            return ("fake-uuid",)
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    combined = CombinedDispatchResult(
        webhook=WebhookDispatchResult(
            succeeded=True, status_code=200, response_body="ok",
            error_message=None, attempt_number=1,
            fired_at=datetime.now(UTC), delivered_at=datetime.now(UTC),
        ),
        email=EmailDispatchResult(
            succeeded=True, status_code=0, message_id="msg-1",
            to_address="investigator@example.com",
            error_message=None,
            fired_at=datetime.now(UTC), delivered_at=datetime.now(UTC),
        ),
        fired_at=datetime.now(UTC),
    )

    from recupero.monitoring import dispatcher as disp
    with patch.object(disp, "db_connect", return_value=_StubConn()):
        disp.record_alert_attempt(
            dsn="postgres://fake",
            payload=_payload(),
            result=combined,
        )

    assert len(insert_calls) == 1, "Must produce exactly ONE audit row"
    assert captured_params["w_status"] == 200
    assert captured_params["w_succeeded"] is True
    assert captured_params["e_status"] == 0
    assert captured_params["e_msg_id"] == "msg-1"
    assert captured_params["e_to"] == "investigator@example.com"
