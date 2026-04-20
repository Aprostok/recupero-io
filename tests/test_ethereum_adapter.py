"""EthereumAdapter tests using respx to mock Etherscan."""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from recupero.chains.ethereum.adapter import EthereumAdapter
from recupero.config import EthereumParams, RecuperoConfig, RecuperoEnv


@pytest.fixture
def adapter() -> EthereumAdapter:
    cfg = RecuperoConfig(ethereum=EthereumParams(requests_per_second=1000.0))  # no rate limit in tests
    env = RecuperoEnv(ETHERSCAN_API_KEY="TEST")
    return EthereumAdapter((cfg, env))


def _ok(result):
    return {"status": "1", "message": "OK", "result": result}


class TestEthereumAdapter:
    @respx.mock
    def test_block_at_or_before(self, adapter: EthereumAdapter) -> None:
        respx.get("https://api.etherscan.io/v2/api").mock(
            return_value=httpx.Response(200, json=_ok("19000000"))
        )
        when = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        block = adapter.block_at_or_before(when)
        assert block == 19000000

    @respx.mock
    def test_native_outflows_filters_inbound_and_zero_value(self, adapter: EthereumAdapter) -> None:
        seed = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        target = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d"
        rows = [
            # outbound (kept)
            {
                "blockNumber": "19000001",
                "timeStamp": "1736942400",
                "hash": "0xaaa",
                "from": seed,
                "to": target,
                "value": "1000000000000000000",
                "isError": "0",
            },
            # zero value (dropped)
            {
                "blockNumber": "19000002",
                "timeStamp": "1736942500",
                "hash": "0xbbb",
                "from": seed,
                "to": target,
                "value": "0",
                "isError": "0",
            },
            # inbound (dropped — wrong direction)
            {
                "blockNumber": "19000003",
                "timeStamp": "1736942600",
                "hash": "0xccc",
                "from": target,
                "to": seed,
                "value": "500000000000000000",
                "isError": "0",
            },
            # failed tx (dropped)
            {
                "blockNumber": "19000004",
                "timeStamp": "1736942700",
                "hash": "0xddd",
                "from": seed,
                "to": target,
                "value": "1000000000000000000",
                "isError": "1",
            },
        ]
        respx.get("https://api.etherscan.io/v2/api").mock(
            return_value=httpx.Response(200, json=_ok(rows))
        )
        out = adapter.fetch_native_outflows(seed, start_block=19000000)
        # Both normal and internal endpoints get the same mock — so we'll see
        # the kept tx duplicated. That's fine for this filter test; we assert
        # at least one of them is present and properly normalized.
        assert any(t["tx_hash"] == "0xaaa" for t in out)
        assert all(t["tx_hash"] != "0xbbb" for t in out)
        assert all(t["tx_hash"] != "0xccc" for t in out)
        assert all(t["tx_hash"] != "0xddd" for t in out)

    @respx.mock
    def test_erc20_outflows_normalizes_token_metadata(self, adapter: EthereumAdapter) -> None:
        seed = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        target = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d"
        rows = [{
            "blockNumber": "19000005",
            "timeStamp": "1736942800",
            "hash": "0xeee",
            "from": seed,
            "to": target,
            "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "tokenSymbol": "USDT",
            "tokenDecimal": "6",
            "value": "1000000000",  # 1000 USDT
            "logIndex": "0",
        }]
        respx.get("https://api.etherscan.io/v2/api").mock(
            return_value=httpx.Response(200, json=_ok(rows))
        )
        out = adapter.fetch_erc20_outflows(seed, start_block=19000000)
        assert len(out) == 1
        t = out[0]
        assert t["tx_hash"] == "0xeee"
        assert t["token"].symbol == "USDT"
        assert t["token"].decimals == 6
        assert t["amount_raw"] == 1000000000

    @respx.mock
    def test_no_records_found_is_handled_as_empty(self, adapter: EthereumAdapter) -> None:
        respx.get("https://api.etherscan.io/v2/api").mock(
            return_value=httpx.Response(200, json={
                "status": "0", "message": "No transactions found", "result": [],
            })
        )
        out = adapter.fetch_native_outflows(
            "0x0cdC902f4448b51289398261DB41E8ADC99bE955", start_block=19000000
        )
        assert out == []

    def test_explorer_urls(self, adapter: EthereumAdapter) -> None:
        assert adapter.explorer_tx_url("0xabc") == "https://etherscan.io/tx/0xabc"
        url = adapter.explorer_address_url("0x0cdc902f4448b51289398261db41e8adc99be955")
        assert url == "https://etherscan.io/address/0x0cdC902f4448b51289398261DB41E8ADC99bE955"
