"""Tests for v0.13.0 EsploraClient."""

from __future__ import annotations

import httpx
import pytest
import respx

from recupero.chains.bitcoin.esplora import (
    ESPLORA_MEMPOOL_SPACE,
    EsploraClient,
    EsploraError,
)


GENESIS_ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def _mk_tx(*, txid: str = "abcd1234", value: int = 50_000_000) -> dict:
    """One Esplora-shaped transaction object (minimal)."""
    return {
        "txid": txid,
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": "prev_" + txid,
                "vout": 0,
                "prevout": {
                    "scriptpubkey_address": GENESIS_ADDR,
                    "value": value,
                },
                "scriptsig": "",
                "sequence": 4294967295,
            }
        ],
        "vout": [
            {
                "scriptpubkey_address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "value": value - 10000,
            },
        ],
        "size": 250,
        "fee": 10000,
        "status": {
            "confirmed": True,
            "block_height": 700000,
            "block_time": 1633000000,
        },
    }


def _new_client() -> EsploraClient:
    return EsploraClient(requests_per_second=10_000.0)  # no rate limit in tests


# ---- get_address_txs ---- #


@respx.mock
def test_address_txs_returns_list() -> None:
    client = _new_client()
    page = [_mk_tx(txid="a"), _mk_tx(txid="b")]
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{GENESIS_ADDR}/txs"
    ).mock(return_value=httpx.Response(200, json=page))
    out = client.get_address_txs(GENESIS_ADDR)
    assert len(out) == 2
    assert out[0]["txid"] == "a"


@respx.mock
def test_address_txs_paginates_via_last_seen_txid() -> None:
    """Esplora returns 25+ txs in a page; pagination cursors via
    /address/{addr}/txs/chain/{last_txid}."""
    client = _new_client()
    full_page = [_mk_tx(txid=f"tx{i}") for i in range(25)]  # full page = 25
    next_page = [_mk_tx(txid="last")]
    call_count = {"n": 0}

    def _side_effect(_request: httpx.Request) -> httpx.Response:
        i = call_count["n"]
        call_count["n"] += 1
        if i == 0:
            return httpx.Response(200, json=full_page)
        return httpx.Response(200, json=next_page)

    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{GENESIS_ADDR}/txs"
    ).mock(side_effect=_side_effect)
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{GENESIS_ADDR}/txs/chain/tx24"
    ).mock(side_effect=_side_effect)
    out = client.get_address_txs(GENESIS_ADDR)
    # Should have hit both endpoints; first call gives 25, second
    # gives 1 (< 25 so we stop).
    assert call_count["n"] == 2
    assert len(out) == 26


@respx.mock
def test_address_txs_stops_when_page_is_short() -> None:
    """Page with < 25 results → no more pages."""
    client = _new_client()
    short = [_mk_tx(txid=f"tx{i}") for i in range(3)]
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{GENESIS_ADDR}/txs"
    ).mock(return_value=httpx.Response(200, json=short))
    out = client.get_address_txs(GENESIS_ADDR)
    assert len(out) == 3


@respx.mock
def test_address_txs_empty_response_is_empty_list() -> None:
    """Address never observed → empty list (no exception)."""
    client = _new_client()
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{GENESIS_ADDR}/txs"
    ).mock(return_value=httpx.Response(200, json=[]))
    out = client.get_address_txs(GENESIS_ADDR)
    assert out == []


# ---- get_transaction ---- #


@respx.mock
def test_get_transaction_returns_object() -> None:
    client = _new_client()
    txid = "abc123"
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/tx/{txid}"
    ).mock(return_value=httpx.Response(200, json=_mk_tx(txid=txid)))
    tx = client.get_transaction(txid)
    assert tx["txid"] == txid
    assert "vin" in tx
    assert "vout" in tx


@respx.mock
def test_get_transaction_404_raises() -> None:
    client = _new_client()
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/tx/nonexistent"
    ).mock(return_value=httpx.Response(404, text="Transaction not found"))
    with pytest.raises(EsploraError, match="404"):
        client.get_transaction("nonexistent")


# ---- get_tip_height ---- #


@respx.mock
def test_tip_height_as_integer() -> None:
    """Esplora's tip-height endpoint returns the height as a bare
    integer (sometimes as text). Our client handles both."""
    client = _new_client()
    # First test: response parses as JSON int (recent Esplora)
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/blocks/tip/height"
    ).mock(return_value=httpx.Response(200, json=850000))
    assert client.get_tip_height() == 850000


@respx.mock
def test_tip_height_as_text() -> None:
    """Older Esplora returns the height as plain text. The client
    falls back to text parsing on non-JSON responses."""
    client = _new_client()
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/blocks/tip/height"
    ).mock(return_value=httpx.Response(200, text="850000"))
    assert client.get_tip_height() == 850000


# ---- 429 retry ---- #


@respx.mock
def test_429_retries_and_succeeds() -> None:
    """Two 429s then a 200 — tenacity retries with exponential
    backoff. Final result is the 200 body."""
    client = _new_client()
    responses = [
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json=_mk_tx(txid="ok")),
    ]
    call_count = {"n": 0}

    def _side_effect(_request: httpx.Request) -> httpx.Response:
        i = call_count["n"]
        call_count["n"] += 1
        return responses[min(i, len(responses) - 1)]

    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/tx/abc"
    ).mock(side_effect=_side_effect)
    tx = client.get_transaction("abc")
    assert call_count["n"] == 3
    assert tx["txid"] == "ok"


@respx.mock
def test_500_retries() -> None:
    """5xx server errors trigger the same retry path as 429."""
    client = _new_client()
    responses = [
        httpx.Response(503, text="upstream down"),
        httpx.Response(200, json=_mk_tx(txid="recovered")),
    ]
    call_count = {"n": 0}

    def _side_effect(_request: httpx.Request) -> httpx.Response:
        i = call_count["n"]
        call_count["n"] += 1
        return responses[min(i, len(responses) - 1)]

    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/tx/abc"
    ).mock(side_effect=_side_effect)
    tx = client.get_transaction("abc")
    assert call_count["n"] == 2
    assert tx["txid"] == "recovered"
