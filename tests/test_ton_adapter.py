"""TonAdapter — native TON (v2) + Jetton/USDT-TON (v3) outflow normalization.

Fixtures are shaped from REAL toncenter.com responses captured before
implementation. Adapter logic is tested with an injected fake client; one
respx test exercises the client transport.
"""

from __future__ import annotations

import httpx
import respx

from recupero.chains.ton.adapter import TonAdapter
from recupero.chains.ton.address import raw_to_friendly
from recupero.chains.ton.client import TonCenterClient
from recupero.models import Chain

A_RAW = "0:7b27ada438eeffc7a7eea02e44b966726f4e21322f35fda51dc6a2e0cd6a04d5"
B_RAW = "0:0b6073a6132acb17fed859a58ea651d6050d2fe751a7c76d30bb041302b8b772"
USDT_RAW = "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"
A_EQ = raw_to_friendly(A_RAW)
B_EQ = raw_to_friendly(B_RAW)

START = 1_700_000_000  # unix-ts cutoff
LATER = 1_780_000_000  # > START


class _FakeClient:
    def __init__(self, txs=None, jettons=None, decimals_by_master=None) -> None:
        self._txs = txs or []
        self._jettons = jettons or {"jetton_transfers": []}
        self._decimals = decimals_by_master or {}

    def get_transactions(self, address, *, limit=100, to_lt=None):  # noqa: ANN001
        return self._txs

    def get_jetton_transfers(self, *, owner_address, limit=100, offset=0):  # noqa: ANN001
        return self._jettons

    def jetton_decimals(self, master):  # noqa: ANN001
        return self._decimals.get(master)

    def close(self) -> None:
        pass


def _native_tx(*, source_eq, dest_eq, value, utime=LATER, txhash="aGFzaA=="):
    return {
        "utime": utime,
        "transaction_id": {"hash": txhash, "lt": "123"},
        "in_msg": {"source": "", "destination": source_eq, "value": "0"},
        "out_msgs": [
            {"source": source_eq, "destination": dest_eq, "value": str(value)},
        ],
    }


def _adapter(txs=None, jettons=None, decimals_by_master=None) -> TonAdapter:
    return TonAdapter(client=_FakeClient(
        txs=txs, jettons=jettons, decimals_by_master=decimals_by_master,
    ))


# ---- native TON ---- #


def test_native_outflow_normalized_to_canonical_raw() -> None:
    a = _adapter(txs=[_native_tx(source_eq=A_EQ, dest_eq=B_EQ, value=12076667)])
    rows = a.fetch_native_outflows(A_EQ, START)
    assert len(rows) == 1
    r = rows[0]
    assert r["chain"] == Chain.ton
    assert r["from"] == A_RAW          # canonicalized from friendly
    assert r["to"] == B_RAW
    assert r["amount_raw"] == 12076667
    assert r["token"].symbol == "TON"
    assert r["token"].decimals == 9
    assert r["token"].coingecko_id == "the-open-network"
    assert r["tx_hash"] == "aGFzaA=="
    assert r["explorer_url"].startswith("https://tonviewer.com/transaction/")


def test_native_filters_before_start_block() -> None:
    a = _adapter(txs=[_native_tx(source_eq=A_EQ, dest_eq=B_EQ, value=5, utime=START - 100)])
    assert a.fetch_native_outflows(A_EQ, START) == []


def test_native_drops_zero_value_and_self() -> None:
    a = _adapter(txs=[
        _native_tx(source_eq=A_EQ, dest_eq=B_EQ, value=0),       # zero
        _native_tx(source_eq=A_EQ, dest_eq=A_EQ, value=999),     # self
    ])
    assert a.fetch_native_outflows(A_EQ, START) == []


# ---- Jetton / USDT-TON ---- #


def _jetton_transfer(*, source, destination, amount, master=USDT_RAW,
                     now=LATER, txhash="amV0dA=="):
    return {
        "source": source,
        "destination": destination,
        "amount": str(amount),
        "jetton_master": master,
        "transaction_hash": txhash,
        "transaction_now": now,
    }


def test_jetton_usdt_outflow_normalized() -> None:
    body = {"jetton_transfers": [
        _jetton_transfer(source=A_RAW, destination=B_RAW, amount=1752300),
    ]}
    a = _adapter(jettons=body)
    rows = a.fetch_erc20_outflows(A_EQ, START)
    assert len(rows) == 1
    r = rows[0]
    assert r["from"] == A_RAW
    assert r["to"] == B_RAW
    assert r["amount_raw"] == 1752300
    assert r["token"].symbol == "USDT"
    assert r["token"].decimals == 6
    assert r["token"].coingecko_id == "tether"
    assert r["token"].contract == USDT_RAW


def test_jetton_inbound_skipped() -> None:
    # source != owner → not an outflow.
    body = {"jetton_transfers": [
        _jetton_transfer(source=B_RAW, destination=A_RAW, amount=500),
    ]}
    a = _adapter(jettons=body)
    assert a.fetch_erc20_outflows(A_EQ, START) == []


def test_jetton_unknown_master_skipped_when_decimals_unresolvable() -> None:
    # Unknown jetton + no API decimals → untrusted → skipped (no fabricated USD).
    body = {"jetton_transfers": [
        _jetton_transfer(source=A_RAW, destination=B_RAW, amount=500,
                         master="0:" + "ff" * 32),
    ]}
    a = _adapter(jettons=body)  # _FakeClient.jetton_decimals → None
    assert a.fetch_erc20_outflows(A_EQ, START) == []


def test_jetton_non_pinned_priced_via_authoritative_decimals() -> None:
    """A non-pinned jetton whose decimals TON Center resolves is emitted with
    those decimals + coingecko_id=None (pricing resolves by master contract)."""
    other = "0:" + "ab" * 32
    body = {"jetton_transfers": [
        _jetton_transfer(source=A_RAW, destination=B_RAW, amount=12_000_000_000,
                         master=other),
    ]}
    a = _adapter(jettons=body, decimals_by_master={other: 9})
    rows = a.fetch_erc20_outflows(A_EQ, START)
    assert len(rows) == 1
    tok = rows[0]["token"]
    assert tok.contract == other
    assert tok.decimals == 9
    assert tok.coingecko_id is None  # CoinGecko resolves by contract on TON
    assert rows[0]["amount_raw"] == 12_000_000_000


def test_jetton_filters_before_start_block() -> None:
    body = {"jetton_transfers": [
        _jetton_transfer(source=A_RAW, destination=B_RAW, amount=500, now=START - 1),
    ]}
    a = _adapter(jettons=body)
    assert a.fetch_erc20_outflows(A_EQ, START) == []


# ---- misc adapter surface ---- #


def test_is_contract_and_block_and_explorer() -> None:
    a = _adapter()
    assert a.is_contract(A_RAW) is False
    assert a.explorer_address_url(A_RAW) == "https://tonviewer.com/" + A_EQ


# ---- client transport (respx) ---- #


@respx.mock
def test_client_get_transactions_unwraps_v2_result() -> None:
    c = TonCenterClient(requests_per_second=10_000.0)
    respx.get("https://toncenter.com/api/v2/getTransactions").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": [{"utime": 1}]}),
    )
    out = c.get_transactions(A_EQ, limit=1)
    assert out == [{"utime": 1}]


@respx.mock
def test_client_v3_jetton_transfers_returns_body() -> None:
    c = TonCenterClient(requests_per_second=10_000.0)
    respx.get("https://toncenter.com/api/v3/jetton/transfers").mock(
        return_value=httpx.Response(200, json={"jetton_transfers": [], "address_book": {}}),
    )
    body = c.get_jetton_transfers(owner_address=A_EQ)
    assert "jetton_transfers" in body
