"""Tests for v7 — Arbitrum client-side startblock filter workaround.

Etherscan V2's free tier on Arbitrum returns empty results when `startblock`
is a large value, even though transactions exist at blocks > startblock.
Workaround: query from block 0 and filter client-side.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from recupero.chains.evm.adapter import EvmAdapter, _profile_for
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


def _make_adapter(chain: Chain) -> EvmAdapter:
    cfg = RecuperoConfig()
    env = RecuperoEnv(ETHERSCAN_API_KEY="test-key")
    adapter = EvmAdapter((cfg, env), chain=chain)
    # Replace the real client with a mock
    adapter.client = MagicMock()
    return adapter


class TestClientSideStartblockFilter:
    """Arbitrum and (as needed) other chains need startblock applied client-side."""

    def test_ethereum_does_NOT_need_client_side_filter(self):
        adapter = _make_adapter(Chain.ethereum)
        assert adapter._needs_client_side_start_block_filter() is False

    def test_arbitrum_DOES_need_client_side_filter(self):
        adapter = _make_adapter(Chain.arbitrum)
        assert adapter._needs_client_side_start_block_filter() is True

    def test_bsc_does_NOT_need_client_side_filter(self):
        # Our testing has only confirmed the quirk on Arbitrum. BSC may be fine.
        # If BSC ends up needing it too we add chain_id=56 to the set.
        adapter = _make_adapter(Chain.bsc)
        assert adapter._needs_client_side_start_block_filter() is False


class TestArbitrumWorkaroundQueriesFromZero:
    """When the workaround is active, we must call the client with start_block=0
    and then drop transactions below the requested start_block client-side."""

    def test_erc20_workaround_calls_with_start_block_zero(self):
        adapter = _make_adapter(Chain.arbitrum)
        adapter.client.get_erc20_transfers.return_value = []

        adapter.fetch_erc20_outflows(
            from_address="0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2",
            start_block=387_515_936,
        )
        # The client must have been called with start_block=0, NOT 387515936.
        call_kwargs = adapter.client.get_erc20_transfers.call_args.kwargs
        assert call_kwargs["start_block"] == 0

    def test_erc20_workaround_filters_old_blocks_client_side(self):
        """Pre-incident txs must be filtered out client-side."""
        addr = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        to_addr = "0x000000000000000000000000000000000000dEaD"
        usdc_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        adapter = _make_adapter(Chain.arbitrum)
        adapter.client.get_erc20_transfers.return_value = [
            # Pre-incident, must be filtered out
            {"from": addr, "to": to_addr, "contractAddress": usdc_contract,
             "blockNumber": "100000000", "timeStamp": "1700000000", "hash": "0xold",
             "tokenSymbol": "USDC", "tokenDecimal": "6", "value": "1000000"},
            # Post-incident, must be kept
            {"from": addr, "to": to_addr, "contractAddress": usdc_contract,
             "blockNumber": "387600000", "timeStamp": "1760000000", "hash": "0xnew",
             "tokenSymbol": "USDC", "tokenDecimal": "6", "value": "2000000"},
        ]
        result = adapter.fetch_erc20_outflows(from_address=addr, start_block=387_515_936)
        # Only the post-incident tx should be kept
        assert len(result) == 1
        assert result[0]["tx_hash"] == "0xnew"

    def test_ethereum_does_NOT_apply_workaround(self):
        """Baseline: Ethereum keeps the old behavior (start_block passed to client)."""
        adapter = _make_adapter(Chain.ethereum)
        adapter.client.get_erc20_transfers.return_value = []
        adapter.fetch_erc20_outflows(
            from_address="0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2",
            start_block=23_536_162,
        )
        # Ethereum should still pass the real start_block to the API
        call_kwargs = adapter.client.get_erc20_transfers.call_args.kwargs
        assert call_kwargs["start_block"] == 23_536_162

    def test_native_workaround_also_applies(self):
        addr = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        adapter = _make_adapter(Chain.arbitrum)
        adapter.client.get_normal_transactions.return_value = []
        adapter.client.get_internal_transactions.return_value = []
        adapter.fetch_native_outflows(from_address=addr, start_block=387_515_936)
        # Both native fetches should use start_block=0
        assert adapter.client.get_normal_transactions.call_args.kwargs["start_block"] == 0
        assert adapter.client.get_internal_transactions.call_args.kwargs["start_block"] == 0
