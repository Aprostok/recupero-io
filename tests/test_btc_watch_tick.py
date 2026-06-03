"""v0.37.5 (deep-reach cleanup, Tier 2) — Bitcoin monitoring in watch_tick.

Closes the #4↔#5 loop: the THORChain decoder (v0.37.4) reaches native-Bitcoin
resting places and auto-subscription adds them to the watchlist, but pre-v0.37.5
watch_tick skipped every `bitcoin` row (`skipped_unsupported_chain`) — so a BTC
holder we could REACH we could not MONITOR. These pin the new balance fetch +
snapshot.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

import httpx
import respx

from recupero.chains.bitcoin.esplora import EsploraClient
from recupero.worker.watch_tick import _native_token_for, _snapshot_bitcoin_one


def _client() -> EsploraClient:
    return EsploraClient(requests_per_second=10_000.0)  # no rate limit in tests


@respx.mock
def test_esplora_address_balance_sats_confirmed_only() -> None:
    """confirmed balance = chain_stats.funded_txo_sum - spent_txo_sum; mempool
    (unconfirmed) is excluded."""
    c = _client()
    addr = "bc1q8w2ypqgx39gucxcypqv2m90wz9rvhmmrcnpdjs"
    respx.get(f"{c.base_url}/address/{addr}").mock(
        return_value=httpx.Response(200, json={
            "address": addr,
            "chain_stats": {"funded_txo_sum": 500_000_000, "spent_txo_sum": 100_000_000},
            "mempool_stats": {"funded_txo_sum": 9_999, "spent_txo_sum": 0},
        }),
    )
    assert c.address_balance_sats(addr) == 400_000_000  # 4 BTC, confirmed only


@respx.mock
def test_esplora_address_balance_uninitialized_is_zero() -> None:
    c = _client()
    addr = "bc1qneverused0000000000000000000000000000"
    respx.get(f"{c.base_url}/address/{addr}").mock(
        return_value=httpx.Response(200, json={
            "address": addr,
            "chain_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0},
        }),
    )
    assert c.address_balance_sats(addr) == 0


def test_native_token_for_bitcoin() -> None:
    tok = _native_token_for("bitcoin")
    assert tok is not None
    assert tok.symbol == "BTC"
    assert tok.coingecko_id == "bitcoin"
    assert tok.decimals == 8
    assert tok.contract is None


def test_snapshot_bitcoin_one_prices_native_balance() -> None:
    """2 BTC @ $60,000 → total_usd $120,000; no tokens on Bitcoin."""
    fake_client = SimpleNamespace(
        address_balance_sats=lambda addr: 200_000_000,  # 2 BTC
    )
    fake_price = SimpleNamespace(
        price_now=lambda token: SimpleNamespace(usd_value=Decimal("60000")),
    )
    snap = _snapshot_bitcoin_one({"address": "bc1qxyz"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.native_balance_raw == 200_000_000
    assert snap.total_usd == Decimal("120000")
    assert snap.token_balances == []
    assert snap.source == "esplora"


def test_snapshot_bitcoin_one_balance_error_is_captured() -> None:
    def _boom(_addr):
        raise RuntimeError("esplora down")
    fake_client = SimpleNamespace(address_balance_sats=_boom)
    fake_price = SimpleNamespace(price_now=lambda t: SimpleNamespace(usd_value=Decimal("60000")))
    snap = _snapshot_bitcoin_one({"address": "bc1qxyz"}, fake_client, fake_price)
    assert snap.error is not None and "esplora down" in snap.error
    assert snap.total_usd is None


def test_snapshot_bitcoin_one_zero_balance_is_zero_usd() -> None:
    fake_client = SimpleNamespace(address_balance_sats=lambda addr: 0)
    fake_price = SimpleNamespace(price_now=lambda t: SimpleNamespace(usd_value=Decimal("60000")))
    snap = _snapshot_bitcoin_one({"address": "bc1qxyz"}, fake_client, fake_price)
    assert snap.error is None
    assert snap.total_usd == Decimal("0")
