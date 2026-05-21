"""Tests for v0.12.0 TronGridClient.

HTTP is fully mocked via respx — these tests verify:
  * Account / TRC-20 / latest-block calls hit the right URLs
  * API-key header is set when provided, absent when not
  * Pagination via ``meta.fingerprint`` threads through multiple pages
  * Direction filters (only_to / only_from) appear in params
  * 429 triggers tenacity retry, eventually succeeds
  * 200 with embedded ``Error`` field raises TronGridError
  * Non-JSON response raises TronGridError cleanly
"""

from __future__ import annotations

import httpx
import pytest
import respx

from recupero.chains.tron.client import (
    TRONGRID_BASE_MAINNET,
    TronGridClient,
    TronGridError,
)

# A real-shape Tron base58 address (USDT-TRC20 contract).
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# Synthetic TRC-20 transfer event matching TronGrid's actual schema.
def _make_transfer(
    *,
    tx_id: str = "abc123",
    from_addr: str = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9",
    to_addr: str = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX",
    value: str = "1000000",
    block_ts: int = 1750000000000,
) -> dict:
    return {
        "transaction_id": tx_id,
        "block_timestamp": block_ts,
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "type": "Transfer",
        "token_info": {
            "symbol": "USDT",
            "decimals": 6,
            "name": "Tether USD",
            "address": USDT_CONTRACT,
        },
    }


def _new_client(api_key: str = "") -> TronGridClient:
    """Construct a client with rate-limiting disabled (would slow tests)."""
    return TronGridClient(api_key=api_key, requests_per_second=10_000.0)


# ---- get_account ---- #


@respx.mock
def test_get_account_hits_correct_url() -> None:
    client = _new_client()
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(200, json={"data": [{"balance": 100}]}))
    body = client.get_account(USDT_CONTRACT)
    assert route.called
    assert body == {"data": [{"balance": 100}]}


@respx.mock
def test_api_key_header_set_when_provided() -> None:
    client = _new_client(api_key="test-api-key-123")
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    client.get_account(USDT_CONTRACT)
    assert route.called
    request = route.calls.last.request
    assert request.headers.get("TRON-PRO-API-KEY") == "test-api-key-123"


@respx.mock
def test_no_api_key_header_when_unset() -> None:
    client = _new_client()
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    client.get_account(USDT_CONTRACT)
    assert "TRON-PRO-API-KEY" not in route.calls.last.request.headers


# ---- get_trc20_transfers ---- #


@respx.mock
def test_trc20_transfers_basic() -> None:
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
    transfers = [_make_transfer(tx_id="tx1"), _make_transfer(tx_id="tx2")]
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(return_value=httpx.Response(200, json={"data": transfers}))
    out = client.get_trc20_transfers(addr)
    assert len(out) == 2
    assert out[0]["transaction_id"] == "tx1"


@respx.mock
def test_trc20_transfers_paginates_via_fingerprint() -> None:
    """When meta.fingerprint is present in the response, the client
    issues another request with ``fingerprint`` in the params. We
    return page1 with a fingerprint, then page2 with empty meta to
    terminate."""
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
    page1 = {
        "data": [_make_transfer(tx_id="tx1")],
        "meta": {"fingerprint": "next-cursor-xyz"},
    }
    page2 = {
        "data": [_make_transfer(tx_id="tx2")],
        "meta": {},  # no fingerprint → stop
    }
    responses = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    call_count = {"n": 0}

    def _side_effect(request: httpx.Request) -> httpx.Response:
        i = call_count["n"]
        call_count["n"] += 1
        # Page 2 onwards must carry the fingerprint param.
        if i >= 1:
            assert request.url.params.get("fingerprint") == "next-cursor-xyz"
        return responses[min(i, len(responses) - 1)]

    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(side_effect=_side_effect)
    out = client.get_trc20_transfers(addr)
    assert call_count["n"] == 2
    assert [t["transaction_id"] for t in out] == ["tx1", "tx2"]


@respx.mock
def test_trc20_transfers_pagination_hits_max_pages_safely() -> None:
    """If TronGrid returns a fingerprint on EVERY page (pathological /
    infinite-loop scenario), we should stop at max_pages without
    OOMing."""
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"

    def _always_more(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "data": [_make_transfer(tx_id="t")],
            "meta": {"fingerprint": "never-ends"},
        })

    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(side_effect=_always_more)
    out = client.get_trc20_transfers(addr, max_pages=3)
    assert route.call_count == 3
    assert len(out) == 3


@respx.mock
def test_trc20_transfers_passes_direction_filter() -> None:
    """only_to=True should appear as a query parameter for server-
    side filtering."""
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    client.get_trc20_transfers(addr, only_to=True)
    assert route.calls.last.request.url.params.get("only_to") == "true"


@respx.mock
def test_trc20_transfers_passes_contract_filter() -> None:
    """contract_address=USDT should appear in params so we get only
    USDT events even on an address that holds many TRC-20s."""
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    client.get_trc20_transfers(addr, contract_address=USDT_CONTRACT)
    assert route.calls.last.request.url.params.get("contract_address") == USDT_CONTRACT


# ---- Error handling ---- #


@respx.mock
def test_429_retries_and_eventually_succeeds() -> None:
    """tenacity retries 429s with exponential backoff. After 2
    rate-limited responses, the 3rd succeeds."""
    client = _new_client()
    addr = USDT_CONTRACT
    responses = [
        httpx.Response(429, headers={"Retry-After": "0"}, json={}),
        httpx.Response(429, headers={"Retry-After": "0"}, json={}),
        httpx.Response(200, json={"data": [{"balance": 1}]}),
    ]
    call_count = {"n": 0}

    def _side_effect(_request: httpx.Request) -> httpx.Response:
        i = call_count["n"]
        call_count["n"] += 1
        return responses[min(i, len(responses) - 1)]

    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}"
    ).mock(side_effect=_side_effect)
    body = client.get_account(addr)
    assert call_count["n"] == 3
    assert body == {"data": [{"balance": 1}]}


@respx.mock
def test_200_with_embedded_error_field_raises() -> None:
    """TronGrid sometimes returns 200 with ``{"Error": "..."}`` for
    bad inputs. We surface it as TronGridError so the caller
    doesn't silently accept the empty result."""
    client = _new_client()
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(200, json={"Error": "bad address"}))
    with pytest.raises(TronGridError, match="bad address"):
        client.get_account(USDT_CONTRACT)


@respx.mock
def test_404_raises_tron_grid_error() -> None:
    client = _new_client()
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(404, text="not found"))
    with pytest.raises(TronGridError, match="HTTP 404"):
        client.get_account(USDT_CONTRACT)


@respx.mock
def test_non_json_body_raises_tron_grid_error() -> None:
    client = _new_client()
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{USDT_CONTRACT}"
    ).mock(return_value=httpx.Response(200, text="<html>error page</html>"))
    with pytest.raises(TronGridError, match="non-JSON"):
        client.get_account(USDT_CONTRACT)


# ---- get_latest_block ---- #


@respx.mock
def test_latest_block_hits_correct_url() -> None:
    client = _new_client()
    route = respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/blocks/latest"
    ).mock(return_value=httpx.Response(200, json={"data": [{"block_id": "..."}]}))
    body = client.get_latest_block()
    assert route.called
    assert "data" in body
