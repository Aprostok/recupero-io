"""RIGOR-Jacob Z14: TronGrid pagination must detect a stuck fingerprint.

Concrete trigger: a buggy or adversarial TronGrid mirror returns
``meta.fingerprint = "stuck"`` on every page. The client threads the
fingerprint into the next request, the mirror returns the same page
with the same fingerprint, ad infinitum (until max_pages). Result:
50 duplicate requests, 50x bandwidth/quota burn, duplicated transfers
flooding the adapter.

Companion to test_pagination_cursor_safety.py — that test covers
Esplora + Helius; this one locks the Tron path.
"""

from __future__ import annotations

import httpx
import respx

from recupero.chains.tron.client import (
    TRONGRID_BASE_MAINNET,
    TronGridClient,
)


def _make_transfer(tx_id: str) -> dict:
    return {
        "transaction_id": tx_id,
        "block_timestamp": 1750000000000,
        "from": "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9",
        "to": "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX",
        "value": "1000000",
        "type": "Transfer",
        "token_info": {"symbol": "USDT", "decimals": 6, "address": "TR7N..."},
    }


@respx.mock
def test_tron_stuck_fingerprint_does_not_burn_max_pages() -> None:
    """A mirror that returns the same fingerprint forever must NOT
    burn all 50 max_pages slots. The client must detect cursor
    non-advancement and break."""
    client = TronGridClient(requests_per_second=10_000.0)
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"

    call_count = {"n": 0}

    def _stuck(_request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={
            "data": [_make_transfer("dup-tx")],
            "meta": {"fingerprint": "stuck-forever"},
        })

    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(side_effect=_stuck)

    out = client.get_trc20_transfers(addr, max_pages=50)
    assert call_count["n"] < 10, (
        f"stuck fingerprint burned {call_count['n']} requests; "
        f"client should detect non-advancing cursor and break"
    )
    assert len(out) < 25, (
        f"stuck fingerprint produced {len(out)} duplicate transfers; "
        f"client should not append the same page repeatedly"
    )
