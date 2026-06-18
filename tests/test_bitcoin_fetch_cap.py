"""Bitcoin fetch budget: the adapter now threads a config-derived pagination cap
into the Esplora client instead of leaving it on the hardcoded 50-page (~2500 tx)
default — a silent truncation below the project standard. The Esplora client
already WARNS on max_pages exhaustion; this wires the cap to
RECUPERO_MAX_TRANSFERS_PER_ADDRESS.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from recupero.chains.bitcoin.adapter import (
    _HARD_PAGE_CEILING,
    BitcoinAdapter,
    _resolve_btc_max_pages,
)

_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # valid P2PKH (the genesis address)


def test_resolve_btc_max_pages_math(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    assert _resolve_btc_max_pages() == 2000                 # 50_000 / 25
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "500")
    assert _resolve_btc_max_pages() == 20                   # ceil(500/25)
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "0")
    assert _resolve_btc_max_pages() == _HARD_PAGE_CEILING   # disabled = unbounded
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "10000000")
    assert _resolve_btc_max_pages() == _HARD_PAGE_CEILING   # clamped
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "garbage")
    assert _resolve_btc_max_pages() == 2000                 # garbage → default


def test_adapter_threads_default_cap(monkeypatch):
    monkeypatch.delenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", raising=False)
    client = MagicMock()
    client.get_address_txs.return_value = []
    ad = BitcoinAdapter(client=client)
    ad.fetch_native_outflows(_BTC, 0)
    client.get_address_txs.assert_called_once()
    _, kwargs = client.get_address_txs.call_args
    assert kwargs.get("max_pages") == 2000     # was the client default 50


def test_adapter_honors_env_override(monkeypatch):
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_ADDRESS", "1000")
    client = MagicMock()
    client.get_address_txs.return_value = []
    ad = BitcoinAdapter(client=client)       # cap resolved in __init__
    assert ad._max_pages == 40               # ceil(1000/25)
    ad.fetch_native_outflows(_BTC, 0)
    _, kwargs = client.get_address_txs.call_args
    assert kwargs.get("max_pages") == 40
