"""Tests for v0.13.2 monitoring (dispatcher + poller).

DB I/O is skipped; HTTP is mocked via respx.
"""

from __future__ import annotations

import json
from decimal import Decimal
from uuid import UUID, uuid4

import httpx
import pytest
import respx

from recupero.monitoring.dispatcher import (
    AlertPayload,
    build_webhook_body,
    compute_signature,
    dispatch_alert,
)
from recupero.monitoring.poller import (
    ObservedActivity,
    Subscription,
    evaluate_all_activities,
    evaluate_trigger,
)


SUB_ID = UUID("11111111-1111-1111-1111-111111111111")


def _sub(
    *,
    trigger_type: str = "any_movement",
    threshold_usd: Decimal | None = None,
    last_observed_tx_hash: str | None = None,
) -> Subscription:
    return Subscription(
        subscription_id=SUB_ID,
        address="0xperp",
        chain="ethereum",
        trigger_type=trigger_type,
        threshold_usd=threshold_usd,
        webhook_url="https://hook.example.com/alert",
        webhook_secret=None,
        last_observed_tx_hash=last_observed_tx_hash,
    )


def _activity(
    *,
    tx_hash: str = "0xnew",
    amount_usd: Decimal | None = Decimal("1000"),
    direction: str = "outflow",
    counterparty: str = "0xexch",
    counterparty_is_ofac: bool = False,
) -> ObservedActivity:
    return ObservedActivity(
        tx_hash=tx_hash,
        block_time_iso="2026-05-17T12:00:00Z",
        amount_usd=amount_usd,
        direction=direction,
        counterparty=counterparty,
        counterparty_label=None,
        counterparty_is_ofac=counterparty_is_ofac,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


# ---- evaluate_trigger: any_movement ---- #


def test_any_movement_fires_on_outflow() -> None:
    sub = _sub(trigger_type="any_movement", last_observed_tx_hash="0xold")
    act = _activity(direction="outflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is True
    assert d.next_last_observed_tx_hash == "0xnew"


def test_any_movement_fires_on_inflow() -> None:
    sub = _sub(trigger_type="any_movement", last_observed_tx_hash="0xold")
    act = _activity(direction="inflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is True


def test_already_alerted_dedupe() -> None:
    """If activity.tx_hash matches cursor, don't fire."""
    sub = _sub(trigger_type="any_movement", last_observed_tx_hash="0xnew")
    act = _activity(tx_hash="0xnew")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False
    assert "already-alerted" in (d.reason or "")


# ---- evaluate_trigger: movement_above_usd ---- #


def test_movement_above_usd_fires_when_threshold_met() -> None:
    sub = _sub(
        trigger_type="movement_above_usd",
        threshold_usd=Decimal("5000"),
        last_observed_tx_hash="0xold",
    )
    act = _activity(amount_usd=Decimal("10000"), direction="outflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is True


def test_movement_above_usd_does_not_fire_below_threshold() -> None:
    sub = _sub(
        trigger_type="movement_above_usd",
        threshold_usd=Decimal("5000"),
        last_observed_tx_hash="0xold",
    )
    act = _activity(amount_usd=Decimal("100"), direction="outflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False


def test_movement_above_usd_does_not_fire_on_inflow() -> None:
    """Threshold trigger applies only to outflows."""
    sub = _sub(
        trigger_type="movement_above_usd",
        threshold_usd=Decimal("5000"),
        last_observed_tx_hash="0xold",
    )
    act = _activity(amount_usd=Decimal("10000"), direction="inflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False


# ---- evaluate_trigger: ofac_contact ---- #


def test_ofac_contact_fires_when_counterparty_is_ofac() -> None:
    sub = _sub(trigger_type="ofac_contact", last_observed_tx_hash="0xold")
    act = _activity(counterparty_is_ofac=True)
    d = evaluate_trigger(sub, act)
    assert d.should_fire is True


def test_ofac_contact_does_not_fire_for_non_ofac() -> None:
    sub = _sub(trigger_type="ofac_contact", last_observed_tx_hash="0xold")
    act = _activity(counterparty_is_ofac=False)
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False


# ---- evaluate_trigger: balance_drop ---- #


def test_balance_drop_fires_on_outflow() -> None:
    sub = _sub(trigger_type="balance_drop", last_observed_tx_hash="0xold")
    act = _activity(direction="outflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is True


def test_balance_drop_does_not_fire_on_inflow() -> None:
    sub = _sub(trigger_type="balance_drop", last_observed_tx_hash="0xold")
    act = _activity(direction="inflow")
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False


# ---- Invalid trigger type ---- #


def test_invalid_trigger_type_does_not_fire() -> None:
    sub = _sub(trigger_type="bogus", last_observed_tx_hash="0xold")
    act = _activity()
    d = evaluate_trigger(sub, act)
    assert d.should_fire is False
    assert "invalid trigger_type" in (d.reason or "")


# ---- evaluate_all_activities: cursor logic ---- #


def test_first_poll_no_cursor_does_not_fire_on_history() -> None:
    """A brand-new subscription (no cursor) bookmarks the newest tx
    without firing on historical activity. Prevents alert spam when
    a subscription gets created for an already-active address."""
    sub = _sub(trigger_type="any_movement", last_observed_tx_hash=None)
    activities = [
        _activity(tx_hash="0xnewest"),
        _activity(tx_hash="0xmiddle"),
        _activity(tx_hash="0xoldest"),
    ]
    to_fire, new_cursor = evaluate_all_activities(sub, activities)
    assert to_fire == []
    assert new_cursor == "0xnewest"


def test_subsequent_poll_fires_on_new_activity_only() -> None:
    """With a cursor at '0xmiddle', activities newer than that
    should fire; older ones already alerted."""
    sub = _sub(
        trigger_type="any_movement",
        last_observed_tx_hash="0xmiddle",
    )
    activities = [
        _activity(tx_hash="0xnewest"),
        _activity(tx_hash="0xmiddle"),  # cursor
        _activity(tx_hash="0xoldest"),
    ]
    to_fire, new_cursor = evaluate_all_activities(sub, activities)
    assert [a.tx_hash for a in to_fire] == ["0xnewest"]
    assert new_cursor == "0xnewest"


def test_cursor_not_in_batch_skips_firing() -> None:
    """If the cursor's tx isn't in the current batch (it scrolled off
    or was a different session), advance cursor without firing —
    avoids burst on cursor desync."""
    sub = _sub(
        trigger_type="any_movement",
        last_observed_tx_hash="0xancient_not_returned",
    )
    activities = [_activity(tx_hash="0xnew1"), _activity(tx_hash="0xnew2")]
    to_fire, new_cursor = evaluate_all_activities(sub, activities)
    assert to_fire == []
    assert new_cursor == "0xnew1"


def test_no_activities_returns_empty() -> None:
    sub = _sub(trigger_type="any_movement", last_observed_tx_hash="0xold")
    to_fire, new_cursor = evaluate_all_activities(sub, [])
    assert to_fire == []
    assert new_cursor == "0xold"


# ============ Dispatcher tests ============ #


def _payload() -> AlertPayload:
    return AlertPayload(
        subscription_id=SUB_ID,
        trigger_type="movement_above_usd",
        address="0xperp",
        chain="ethereum",
        tx_hash="0xnew",
        block_time_iso="2026-05-17T12:00:00Z",
        amount_usd=Decimal("12500.00"),
        counterparty="0xexch",
        counterparty_label="Binance Hot Wallet",
        explorer_url="https://etherscan.io/tx/0xnew",
    )


def test_webhook_body_contains_required_fields() -> None:
    body = build_webhook_body(_payload())
    parsed = json.loads(body)
    assert parsed["subscription_id"] == str(SUB_ID)
    assert parsed["trigger_type"] == "movement_above_usd"
    assert parsed["address"] == "0xperp"
    assert parsed["chain"] == "ethereum"
    assert parsed["alert"]["tx_hash"] == "0xnew"
    assert parsed["alert"]["amount_usd"] == "12500.00"
    assert parsed["alert"]["counterparty_label"] == "Binance Hot Wallet"
    assert "fired_at" in parsed


def test_signature_deterministic_and_correct_length() -> None:
    """HMAC-SHA256 → 64 hex chars after 'sha256=' prefix."""
    body = build_webhook_body(_payload())
    sig1 = compute_signature(body, "secret-1")
    sig2 = compute_signature(body, "secret-1")
    assert sig1 == sig2  # deterministic
    assert sig1.startswith("sha256=")
    assert len(sig1) == len("sha256=") + 64  # SHA-256 hex


def test_signature_changes_with_secret() -> None:
    body = build_webhook_body(_payload())
    sig1 = compute_signature(body, "secret-1")
    sig2 = compute_signature(body, "secret-2")
    assert sig1 != sig2


def test_signature_changes_with_body() -> None:
    sig1 = compute_signature("body-1", "secret")
    sig2 = compute_signature("body-2", "secret")
    assert sig1 != sig2


# ---- dispatch_alert (HTTP) ---- #


@respx.mock
def test_dispatch_2xx_succeeds() -> None:
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200, json={"ok": True}),
    )
    result = dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
    )
    assert result.succeeded is True
    assert result.status_code == 200
    assert result.delivered_at is not None
    assert result.error_message is None


@respx.mock
def test_dispatch_5xx_fails() -> None:
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(503, text="upstream down"),
    )
    result = dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
    )
    assert result.succeeded is False
    assert result.status_code == 503
    assert "non-2xx" in (result.error_message or "")
    # Response body is captured for audit (truncated if huge).
    assert "upstream down" in result.response_body


@respx.mock
def test_dispatch_connection_error_returns_failure() -> None:
    respx.post("https://hook.example.com/alert").mock(
        side_effect=httpx.ConnectError("dns failed"),
    )
    result = dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
    )
    assert result.succeeded is False
    assert result.status_code is None
    assert "connection error" in (result.error_message or "")


@respx.mock
def test_dispatch_includes_signature_header_when_secret_set() -> None:
    route = respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200),
    )
    dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
        webhook_secret="test-secret",
    )
    req = route.calls.last.request
    sig = req.headers.get("X-Recupero-Signature")
    assert sig is not None
    assert sig.startswith("sha256=")
    # Verify the signature matches what we'd compute over the body
    body_text = req.content.decode("utf-8")
    expected = compute_signature(body_text, "test-secret")
    assert sig == expected


@respx.mock
def test_dispatch_omits_signature_header_when_no_secret() -> None:
    route = respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(200),
    )
    dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
    )
    req = route.calls.last.request
    assert "X-Recupero-Signature" not in req.headers


@respx.mock
def test_dispatch_truncates_huge_response_body() -> None:
    big_body = "X" * 10_000
    respx.post("https://hook.example.com/alert").mock(
        return_value=httpx.Response(500, text=big_body),
    )
    result = dispatch_alert(
        _payload(),
        webhook_url="https://hook.example.com/alert",
    )
    # Should be truncated to 4000 chars per _RESPONSE_BODY_MAX_BYTES.
    assert len(result.response_body) <= 4_000
