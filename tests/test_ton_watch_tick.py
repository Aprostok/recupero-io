"""TON monitoring in watch_tick — native TON + Jetton balance snapshots.

Closes the reach↔monitor loop for TON (the adapter reaches TON resting places;
pre-this watch_tick skipped every `ton` row). Pins the balance fetch + snapshot
valuation (pinned USDT-TON + authoritative-decimals generalization).
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import httpx
import respx

from recupero.chains.ton.client import TonCenterClient
from recupero.worker.watch_tick import _native_token_for, _snapshot_ton_one

USDT = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"
OTHER = "0:" + "cd" * 32


def test_native_token_for_ton() -> None:
    tok = _native_token_for("ton")
    assert tok is not None
    assert tok.symbol == "TON"
    assert tok.coingecko_id == "the-open-network"
    assert tok.decimals == 9
    assert tok.contract is None


def test_snapshot_prices_native_and_pinned_usdt() -> None:
    """2 TON @ $6 = $12 + 5 USDT @ $1 = $5 → $17."""
    fake_client = SimpleNamespace(
        account_balances=lambda a: (2_000_000_000, {USDT: 5_000_000}),
        jetton_decimals=lambda m: 6,
    )
    fake_price = SimpleNamespace(
        price_now=lambda t: SimpleNamespace(
            usd_value=Decimal("6") if t.contract is None else Decimal("1")),
    )
    snap = _snapshot_ton_one({"address": "EQabc"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.native_balance_raw == 2_000_000_000
    assert snap.source == "toncenter"
    assert len(snap.token_balances) == 1
    assert snap.token_balances[0]["symbol"] == "USDT"
    assert snap.total_usd == Decimal("17")


def test_snapshot_generalized_jetton_via_authoritative_decimals() -> None:
    """A non-pinned jetton with API-resolved decimals is valued (coingecko by
    contract); native TON priced too."""
    fake_client = SimpleNamespace(
        account_balances=lambda a: (0, {OTHER: 3_000_000_000}),  # 3 units @ 9-dec
        jetton_decimals=lambda m: 9,
    )
    fake_price = SimpleNamespace(
        price_now=lambda t: SimpleNamespace(usd_value=Decimal("2")),
    )
    snap = _snapshot_ton_one({"address": "EQabc"}, fake_client, fake_price)
    assert snap.error is None
    assert len(snap.token_balances) == 1
    assert snap.token_balances[0]["contract"] == OTHER
    assert snap.total_usd == Decimal("6")  # 3 * $2


def test_snapshot_skips_jetton_with_unresolvable_decimals() -> None:
    fake_client = SimpleNamespace(
        account_balances=lambda a: (0, {OTHER: 999}),
        jetton_decimals=lambda m: None,  # unresolvable → skip (no guess)
    )
    fake_price = SimpleNamespace(price_now=lambda t: SimpleNamespace(usd_value=Decimal("1")))
    snap = _snapshot_ton_one({"address": "EQabc"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.token_balances == []
    assert snap.total_usd == Decimal("0")


def test_snapshot_balance_error_captured() -> None:
    def _boom(_a):
        raise RuntimeError("toncenter down")
    fake_client = SimpleNamespace(account_balances=_boom)
    fake_price = SimpleNamespace(price_now=lambda t: SimpleNamespace(usd_value=Decimal("6")))
    snap = _snapshot_ton_one({"address": "EQabc"}, fake_client, fake_price)
    assert snap.error is not None and "toncenter down" in snap.error
    assert snap.total_usd is None


@respx.mock
def test_client_account_balances_parses_native_and_jettons() -> None:
    c = TonCenterClient(requests_per_second=10_000.0)
    respx.get("https://toncenter.com/api/v2/getAddressInformation").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"balance": "1500000000"}}),
    )
    respx.get("https://toncenter.com/api/v3/jetton/wallets").mock(
        return_value=httpx.Response(200, json={"jetton_wallets": [
            {"balance": "5000000", "jetton": USDT, "owner": "0:aa"},
        ]}),
    )
    ton_nano, jettons = c.account_balances("EQabc")
    assert ton_nano == 1_500_000_000
    assert jettons[USDT] == 5_000_000


@respx.mock
def test_client_jetton_decimals_from_masters() -> None:
    c = TonCenterClient(requests_per_second=10_000.0)
    route = respx.get("https://toncenter.com/api/v3/jetton/masters").mock(
        return_value=httpx.Response(200, json={"jetton_masters": [
            {"address": USDT, "jetton_content": {"decimals": "6"}},
        ]}),
    )
    assert c.jetton_decimals(USDT) == 6
    # cached → second call makes no new request
    assert c.jetton_decimals(USDT) == 6
    assert route.call_count == 1
