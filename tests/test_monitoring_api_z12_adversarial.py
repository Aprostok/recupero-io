"""RIGOR-Jacob Z12: adversarial-input hunt on monitoring API + dispatcher.

Three bugs locked by this file:

  Z12-1 (CRIT — SSRF bypass via libc-only IPv4 literal forms):
    The v0.27.1 SSRF defense in ``_is_blocked_ip`` relies on
    ``ipaddress.ip_address``, which is STRICT (RFC-compliant): it
    rejects ``2130706433`` (decimal), ``0177.0.0.1`` (octal-leading),
    ``127.1`` (short form), ``0x7f000001`` (hex), etc. But the
    glibc ``inet_aton``/``inet_addr`` family — which libc + curl +
    most HTTP stacks on Linux use to resolve a literal IP host —
    ACCEPTS all of these as 127.0.0.1. On the worker's Railway
    (Linux) production box, a partner can register
    ``https://2130706433/`` and the dispatcher will POST to
    127.0.0.1 — bypassing the entire SSRF defense. Real attack:
    use 169.254.169.254 in decimal (=2852039166) to reach the
    AWS IMDS through this gap.

  Z12-2 (HIGH — Inf threshold_usd corrupts trigger comparisons):
    ``MonitorSubscribeRequest.threshold_usd: float | None = Field(
    None, ge=0)``. Pydantic v2 rejects NaN at ge=0 but ACCEPTS
    ``float('inf')`` (Inf > 0). The endpoint then casts via
    ``Decimal(str(Inf))`` → ``Decimal('Infinity')``, which inserts
    into ``monitoring_subscriptions.threshold_usd`` and silently
    breaks every ``observed_amount >= threshold_usd`` comparison
    in the worker (anything < Inf is False, so the trigger never
    fires). The partner thinks they're monitoring; the wallet drains
    and no webhook ever lands. Mirror of the v0.21.0 freeze_outcomes
    Inf fix; was missed on this endpoint.

  Z12-3 (MED — Unicode trojans accepted in subscription label):
    ``label`` field has no rejection of bidi-override / zero-width /
    BOM characters. A partner can submit a label containing RLO that
    spoofs how it renders in the operator UI (e.g.
    ``"prod‮evil"`` displays as ``"prodlive"`` reversed).
    Same shape as the v0.21.0 freeze-outcomes _reject_text_trojans
    fix in app.py; was not applied to the monitoring label.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi.testclient import TestClient

_API_SECRET = "secret-test-token-z12-xyz"
_KEY_NAME = "tester-z12"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def api_client(monkeypatch):
    monkeypatch.setenv("RECUPERO_API_KEYS", f"{_KEY_NAME}:{_API_SECRET}")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    from recupero.api.app import app
    return TestClient(app)


def _hdr() -> dict[str, str]:
    return {"X-Recupero-API-Key": _API_SECRET}


def _good_body(**overrides):
    body = {
        "address": "0x" + "a" * 40,
        "chain": "ethereum",
        "trigger_type": "any_movement",
        "webhook_url": "https://hooks.example.com/recupero",
    }
    body.update(overrides)
    return body


# ─────────────────────────────────────────────────────────────────────────────
# Z12-1: SSRF bypass via libc-only IPv4 literal forms (CRIT)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("host", [
    # 127.0.0.1 in alternative IPv4 literal forms accepted by glibc
    # inet_aton (i.e. the form curl/libc/Python httpx on Linux will
    # actually resolve at dispatch time).
    "2130706433",       # 32-bit decimal of 127.0.0.1
    "0177.0.0.1",       # leading-zero octal of 127.0.0.1
    "127.1",            # short-form (1-byte trailing) of 127.0.0.1
    "0x7f000001",       # hex of 127.0.0.1
    # 169.254.169.254 (AWS IMDS) in decimal — the real attack target.
    "2852039166",
])
def test_z12_1_inet_aton_ipv4_literal_blocked(host):
    """The v0.27.1 SSRF defense MUST reject every IPv4 literal form
    that libc accepts — not only the dotted-quad form Python's
    strict ipaddress.ip_address recognizes."""
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        assert_webhook_url_safe,
    )
    url = f"https://{host}/webhook"
    with pytest.raises(MonitoringApiError) as exc:
        assert_webhook_url_safe(url)
    assert exc.value.field == "webhook_url"


def test_z12_1_subscribe_rejects_decimal_loopback(api_client):
    """End-to-end: POST /v1/monitor/subscribe with decimal-form loopback
    MUST be rejected at validation time, not silently accepted."""
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=_good_body(webhook_url="https://2130706433/webhook"),
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        f"decimal-form loopback should be rejected, got "
        f"{resp.status_code}: {resp.text}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Z12-2: Inf threshold_usd silently corrupts comparisons (HIGH)
# ─────────────────────────────────────────────────────────────────────────────


def test_z12_2_validator_rejects_infinite_threshold():
    """At the monitoring_api layer, infinite Decimal must not survive
    _validate_subscription_input — it corrupts every downstream
    threshold comparison in the worker."""
    from decimal import Decimal

    from recupero.api.monitoring_api import (
        MonitoringApiError,
        _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40,
            chain="ethereum",
            trigger_type="movement_above_usd",
            threshold_usd=Decimal("Infinity"),
            webhook_url="https://hooks.example.com/recupero",
            label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "threshold_usd"


def test_z12_2_subscribe_rejects_inf_threshold(api_client):
    """End-to-end: POST with threshold_usd=Infinity in the JSON body
    MUST 400/422, not 201. Inf compares False to every finite amount,
    so accepting it silently breaks the trigger forever.

    Real attackers don't go through ``json.dumps``; they construct
    the raw body. JSON spec disallows ``Infinity`` literally, but
    Python's stdlib ``json.loads`` (and therefore Starlette's body
    parser by default) ACCEPT ``Infinity`` as a float. Send the raw
    body to exercise the path attackers actually use.
    """
    raw = (
        '{"address":"0x' + "a" * 40 + '",'
        '"chain":"ethereum",'
        '"trigger_type":"movement_above_usd",'
        '"threshold_usd":Infinity,'
        '"webhook_url":"https://hooks.example.com/recupero"}'
    )
    resp = api_client.post(
        "/v1/monitor/subscribe",
        content=raw,
        headers={**_hdr(), "Content-Type": "application/json"},
    )
    assert resp.status_code in (400, 422), (
        f"Inf threshold_usd must be rejected, got "
        f"{resp.status_code}: {resp.text}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Z12-3: Unicode trojans in subscription label (MED)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("trojan", [
    "prod‮evil-acme",     # RLO: visually reversed
    "x​" + "y" * 20,      # ZWSP
    "x‭" + "z",           # LRO
    "﻿label",             # BOM at front
])
def test_z12_3_validator_rejects_unicode_trojan_label(trojan):
    """A label that contains a bidi-override / zero-width / BOM
    character spoofs the operator's triage display and is rejected
    at validation time — same policy as /v1/freeze-outcomes
    free-text fields (v0.21.0 _reject_text_trojans)."""
    from recupero.api.monitoring_api import (
        MonitoringApiError,
        _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40,
            chain="ethereum",
            trigger_type="any_movement",
            threshold_usd=None,
            webhook_url="https://hooks.example.com/recupero",
            label=trojan,
            webhook_secret=None,
        )
    assert exc.value.field == "label"


def test_z12_3_subscribe_rejects_unicode_trojan_label(api_client):
    """End-to-end: POST with bidi-spoof label MUST 400."""
    body = _good_body(label="prod‮evil")
    resp = api_client.post(
        "/v1/monitor/subscribe",
        json=body,
        headers=_hdr(),
    )
    assert resp.status_code in (400, 422), (
        f"trojan label must be rejected, got "
        f"{resp.status_code}: {resp.text}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Defense-in-depth: dispatcher-time re-check on libc-form IPv4
# ─────────────────────────────────────────────────────────────────────────────


def test_z12_1_dispatcher_recheck_blocks_decimal_loopback():
    """The dispatcher's PUNISH-B S-2 re-check runs the same
    assert_webhook_url_safe. After the fix, a partner that somehow
    persisted https://2130706433/ (e.g. a sub from before the fix
    landed) MUST be blocked at dispatch time too."""
    from decimal import Decimal

    from recupero.monitoring.dispatcher import (
        AlertPayload,
        dispatch_alert,
    )
    payload = AlertPayload(
        subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
        trigger_type="any_movement",
        address="0x" + "a" * 40,
        chain="ethereum",
        tx_hash="0x" + "b" * 64,
        block_time_iso="2026-05-20T12:00:00+00:00",
        amount_usd=Decimal("100"),
        counterparty=None,
        counterparty_label=None,
        explorer_url="https://etherscan.io/tx/0xbb",
    )
    result = dispatch_alert(payload, webhook_url="https://2130706433/")
    assert result.succeeded is False
    assert result.status_code is None
    assert "SSRF" in (result.error_message or "") or "rejected" in (
        result.error_message or ""
    ).lower()
