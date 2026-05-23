"""RIGOR-Jacob Z14: harden pagination cursors against stuck/repeated
cursors from buggy or adversarial servers.

Concrete trigger:
  * Helius mirror bug → returns the same ``signature`` as the last
    element of every page. ``get_parsed_transactions`` reads
    ``batch[-1].get("signature")`` blindly as the next cursor —
    same signature → same page → same signature → loop until
    max_pages, burning quota on duplicate work.
  * Esplora mirror bug → same shape with ``txid``.

The TronGrid fingerprint path is already covered by
``test_trc20_transfers_pagination_hits_max_pages_safely`` — the
loop hits max_pages with NEW fingerprints each time, but the
"same fingerprint forever" case isn't tested. The TronGrid client
threads the SAME cursor into the next request and TronGrid
returns the same page → loop.

Fix contract: pagination must detect a non-advancing cursor and
break (not just rely on max_pages as a backstop), AND not append
duplicate batches on repeated cursors.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import respx

from recupero.chains.bitcoin.esplora import (
    ESPLORA_MEMPOOL_SPACE,
    EsploraClient,
)


def _mk_btc_tx(txid: str) -> dict:
    return {
        "txid": txid,
        "vin": [],
        "vout": [],
        "status": {"confirmed": True, "block_height": 1, "block_time": 1},
    }


@respx.mock
def test_esplora_stuck_cursor_does_not_burn_max_pages() -> None:
    """A buggy mirror returns 25-tx pages with the SAME last-txid every
    time. The cursor never advances. We must detect and break, NOT
    burn all max_pages slots making duplicate calls.

    Before the fix: 50 requests, 1250 duplicate txs in the result.
    After: stop after the second identical cursor, < 5 requests.
    """
    client = EsploraClient(requests_per_second=10_000.0)
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    # 25 txs but the LAST one always has txid "stuck"
    page = [_mk_btc_tx(f"tx{i}") for i in range(24)] + [_mk_btc_tx("stuck")]

    call_count = {"n": 0}

    def _side_effect(_request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json=page)

    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{addr}/txs"
    ).mock(side_effect=_side_effect)
    respx.get(
        f"{ESPLORA_MEMPOOL_SPACE}/address/{addr}/txs/chain/stuck"
    ).mock(side_effect=_side_effect)

    out = client.get_address_txs(addr, max_pages=50)
    # Should NOT burn all 50 max_pages slots on a stuck cursor.
    assert call_count["n"] < 10, (
        f"stuck cursor burned {call_count['n']} requests; "
        f"client should detect and break on non-advancing cursor"
    )
    # And result should not be inflated by repeated duplicate pages.
    assert len(out) < 100, (
        f"stuck cursor produced {len(out)} duplicates; "
        f"client should not append the same batch repeatedly"
    )


def test_helius_stuck_cursor_does_not_burn_max_pages() -> None:
    """Same contract for Helius get_parsed_transactions."""
    from recupero.chains.solana.helius import HeliusClient

    client = HeliusClient.__new__(HeliusClient)
    client._client = MagicMock()
    client.api_key = "fake"
    client.BASE = "https://fake-api"
    client.RPC = "https://fake-rpc"
    client.limiter = MagicMock()
    client.limiter.wait = lambda: None

    call_count = {"n": 0}

    def _fake_get(*_args: object, **_kw: object) -> MagicMock:
        call_count["n"] += 1
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        # Always returns 5 txs with the SAME oldest "signature"
        fake_resp.json.return_value = [
            {"signature": "a", "timestamp": 100},
            {"signature": "b", "timestamp": 99},
            {"signature": "c", "timestamp": 98},
            {"signature": "d", "timestamp": 97},
            {"signature": "stuck", "timestamp": 96},
        ]
        return fake_resp

    client._client.get = _fake_get

    out = client.get_parsed_transactions("addr", limit=5, max_pages=50)
    assert call_count["n"] < 10, (
        f"stuck cursor burned {call_count['n']} requests; "
        f"Helius client should detect and break"
    )
    assert len(out) < 100, (
        f"stuck cursor produced {len(out)} duplicates"
    )
