"""#4 Tron coverage — Tron monitoring in watch_tick.

The tracer reaches Tron resting places (USDT-TRC20 is the dominant stablecoin-
laundering rail) and auto-subscription adds them to the watchlist, but pre-this
watch_tick skipped every ``tron`` row (``skipped_unsupported_chain``) — a holder
we could REACH we could not MONITOR. These pin the new TronGrid balance fetch +
snapshot (native TRX + priceable TRC-20s), mirroring the BTC closure.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import httpx
import respx

from recupero.chains.tron.client import TronGridClient
from recupero.worker.watch_tick import _native_token_for, _snapshot_tron_one

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
UNKNOWN_TRC20 = "TUnknownContractAddressThatHasNoPriceMeta00"


def _client() -> TronGridClient:
    return TronGridClient(requests_per_second=10_000.0)


@respx.mock
def test_account_balances_parses_trx_and_trc20() -> None:
    c = _client()
    addr = "TXYZopqrstuvabcdefghijklmnopqrstuv"
    respx.get(f"{c.base_url}/v1/accounts/{addr}").mock(
        return_value=httpx.Response(200, json={
            "data": [{
                "address": addr,
                "balance": 1_500_000,  # 1.5 TRX in SUN
                "trc20": [
                    {USDT: "2500000"},          # 2.5 USDT (6 decimals)
                    {UNKNOWN_TRC20: "999"},     # kept; valuation drops it later
                ],
            }],
            "success": True,
        }),
    )
    trx_sun, trc20 = c.account_balances(addr)
    assert trx_sun == 1_500_000
    assert trc20[USDT] == 2_500_000
    assert trc20[UNKNOWN_TRC20] == 999


@respx.mock
def test_account_balances_empty_address_is_zero() -> None:
    c = _client()
    addr = "TNeverObservedOnChain000000000000000"
    respx.get(f"{c.base_url}/v1/accounts/{addr}").mock(
        return_value=httpx.Response(200, json={"data": [], "success": True}),
    )
    assert c.account_balances(addr) == (0, {})


def test_native_token_for_tron() -> None:
    tok = _native_token_for("tron")
    assert tok is not None
    assert tok.symbol == "TRX"
    assert tok.coingecko_id == "tron"
    assert tok.decimals == 6
    assert tok.contract is None


def test_snapshot_tron_one_prices_native_and_usdt() -> None:
    """1.5 TRX @ $0.12 = $0.18 + 2.5 USDT @ $1 = $2.50 → total $2.68."""
    def _balances(_addr):
        return 1_500_000, {USDT: 2_500_000}

    def _price(token):
        # native TRX vs TRC-20 USDT distinguished by contract presence
        if token.contract is None:
            return SimpleNamespace(usd_value=Decimal("0.12"))
        return SimpleNamespace(usd_value=Decimal("1.00"))

    fake_client = SimpleNamespace(account_balances=_balances)
    fake_price = SimpleNamespace(price_now=_price)
    snap = _snapshot_tron_one({"address": "TXabc"}, fake_client, fake_price)

    assert snap.error is None
    assert snap.native_balance_raw == 1_500_000
    assert snap.source == "trongrid"
    assert len(snap.token_balances) == 1
    tb = snap.token_balances[0]
    assert tb["symbol"] == "USDT"
    assert tb["contract"] == USDT
    assert Decimal(tb["usd_value"]) == Decimal("2.50")
    assert snap.total_usd == Decimal("2.68")  # 0.18 + 2.50


def test_snapshot_tron_one_ignores_unpriceable_trc20() -> None:
    """A TRC-20 with no price metadata is dropped from valuation, not crashed."""
    fake_client = SimpleNamespace(
        account_balances=lambda a: (0, {UNKNOWN_TRC20: 12345}),
    )
    fake_price = SimpleNamespace(
        price_now=lambda t: SimpleNamespace(usd_value=Decimal("1")),
    )
    snap = _snapshot_tron_one({"address": "TXabc"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.token_balances == []
    assert snap.total_usd == Decimal("0")


def test_snapshot_tron_one_balance_error_is_captured() -> None:
    def _boom(_addr):
        raise RuntimeError("trongrid down")
    fake_client = SimpleNamespace(account_balances=_boom)
    fake_price = SimpleNamespace(
        price_now=lambda t: SimpleNamespace(usd_value=Decimal("1")),
    )
    snap = _snapshot_tron_one({"address": "TXabc"}, fake_client, fake_price)
    assert snap.error is not None and "trongrid down" in snap.error
    assert snap.total_usd is None


def test_snapshot_tron_one_zero_balance_is_zero_usd() -> None:
    fake_client = SimpleNamespace(account_balances=lambda a: (0, {}))
    fake_price = SimpleNamespace(
        price_now=lambda t: SimpleNamespace(usd_value=Decimal("0.12")),
    )
    snap = _snapshot_tron_one({"address": "TXabc"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.total_usd == Decimal("0")
