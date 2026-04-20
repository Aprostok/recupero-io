"""Tests for v9 — Solana support via Helius."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from recupero.chains.base import ChainAdapter
from recupero.chains.solana.adapter import (
    SolanaAdapter,
    USDC_SOLANA_MINT,
    _symbol_from_mint,
)
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


def _make_adapter() -> SolanaAdapter:
    cfg = RecuperoConfig()
    env = RecuperoEnv(ETHERSCAN_API_KEY="eth", HELIUS_API_KEY="hel-test-key")
    adapter = SolanaAdapter((cfg, env))
    # Mock the Helius client so tests never hit the network
    adapter.client = MagicMock()
    return adapter


class TestSolanaFactory:
    def test_factory_produces_solana_adapter(self):
        cfg = RecuperoConfig()
        env = RecuperoEnv(ETHERSCAN_API_KEY="eth", HELIUS_API_KEY="hel-test-key")
        adapter = ChainAdapter.for_chain(Chain.solana, (cfg, env))
        assert isinstance(adapter, SolanaAdapter)
        assert adapter.chain == Chain.solana

    def test_missing_helius_key_raises(self):
        cfg = RecuperoConfig()
        env = RecuperoEnv(ETHERSCAN_API_KEY="eth", HELIUS_API_KEY="")
        try:
            SolanaAdapter((cfg, env))
        except ValueError as e:
            assert "HELIUS_API_KEY" in str(e)
        else:
            raise AssertionError("Expected ValueError for missing Helius key")


class TestBlockAtOrBefore:
    def test_returns_unix_timestamp(self):
        """On Solana we use unix ts as start_block proxy."""
        adapter = _make_adapter()
        ts = datetime(2025, 10, 9, 0, 0, 0, tzinfo=timezone.utc)
        # 2025-10-09T00:00:00Z = unix 1759968000
        assert adapter.block_at_or_before(ts) == 1759968000

    def test_assumes_utc_when_naive(self):
        adapter = _make_adapter()
        naive_ts = datetime(2025, 10, 9, 0, 0, 0)
        assert adapter.block_at_or_before(naive_ts) == 1759968000


class TestFetchNativeOutflows:
    ADDR = "32C1jYfLi8mA75e777CnXTWJ5W12739YFreSWGHstrxG"

    def _helius_tx(self, *, sig, ts, native_transfers=None, token_transfers=None, slot=300000000):
        return {
            "signature": sig, "slot": slot, "timestamp": ts,
            "nativeTransfers": native_transfers or [],
            "tokenTransfers": token_transfers or [],
        }

    def test_keeps_only_outflows_from_seed_address(self):
        adapter = _make_adapter()
        adapter.client.get_parsed_transactions.return_value = [
            self._helius_tx(
                sig="sig1", ts=1760140900,
                native_transfers=[
                    {"fromUserAccount": self.ADDR, "toUserAccount": "OTHER1", "amount": 1000000000},
                    # Should be skipped (someone else's outflow)
                    {"fromUserAccount": "OTHER2", "toUserAccount": self.ADDR, "amount": 500000000},
                ],
            ),
        ]
        out = adapter.fetch_native_outflows(self.ADDR, start_block=1760140800)
        assert len(out) == 1
        assert out[0]["from"] == self.ADDR
        assert out[0]["to"] == "OTHER1"
        assert out[0]["amount_raw"] == 1000000000
        assert out[0]["token"].symbol == "SOL"
        assert out[0]["token"].decimals == 9

    def test_filters_by_start_timestamp(self):
        adapter = _make_adapter()
        adapter.client.get_parsed_transactions.return_value = [
            # Before cutoff — dropped
            self._helius_tx(sig="old", ts=1759000000, native_transfers=[
                {"fromUserAccount": self.ADDR, "toUserAccount": "X", "amount": 1_000_000},
            ]),
            # After cutoff — kept
            self._helius_tx(sig="new", ts=1760200000, native_transfers=[
                {"fromUserAccount": self.ADDR, "toUserAccount": "Y", "amount": 2_000_000},
            ]),
        ]
        out = adapter.fetch_native_outflows(self.ADDR, start_block=1760140800)
        assert len(out) == 1
        assert out[0]["tx_hash"] == "new"

    def test_skips_zero_amount(self):
        adapter = _make_adapter()
        adapter.client.get_parsed_transactions.return_value = [
            self._helius_tx(sig="zero", ts=1760140900, native_transfers=[
                {"fromUserAccount": self.ADDR, "toUserAccount": "X", "amount": 0},
            ]),
        ]
        out = adapter.fetch_native_outflows(self.ADDR, start_block=1760140800)
        assert out == []


class TestFetchSPLOutflows:
    ADDR = "32C1jYfLi8mA75e777CnXTWJ5W12739YFreSWGHstrxG"

    def _tx_with_spl(self, *, sig, ts, mint, amount_raw, decimals, from_addr):
        return {
            "signature": sig, "slot": 300000000, "timestamp": ts,
            "nativeTransfers": [],
            "tokenTransfers": [
                {
                    "fromUserAccount": from_addr,
                    "toUserAccount": "RECIPIENT",
                    "mint": mint,
                    "rawTokenAmount": {"tokenAmount": str(amount_raw), "decimals": decimals},
                },
            ],
        }

    def test_usdc_transfer_normalized_correctly(self):
        adapter = _make_adapter()
        # 100 USDC with 6 decimals = 100_000_000 raw
        adapter.client.get_parsed_transactions.return_value = [
            self._tx_with_spl(
                sig="usdc-tx", ts=1760140900,
                mint=USDC_SOLANA_MINT, amount_raw=100_000_000, decimals=6,
                from_addr=self.ADDR,
            ),
        ]
        out = adapter.fetch_erc20_outflows(self.ADDR, start_block=1760140800)
        assert len(out) == 1
        t = out[0]
        assert t["token"].symbol == "USDC"
        assert t["token"].contract == USDC_SOLANA_MINT
        assert t["token"].decimals == 6
        assert t["token"].coingecko_id == "usd-coin"
        assert t["amount_raw"] == 100_000_000
        assert t["from"] == self.ADDR
        assert t["to"] == "RECIPIENT"
        assert "solscan.io/tx/usdc-tx" in t["explorer_url"]

    def test_unknown_spl_mint_uses_symbol_prefix(self):
        adapter = _make_adapter()
        unknown_mint = "UnknownMint1111111111111111111111111111111"
        adapter.client.get_parsed_transactions.return_value = [
            self._tx_with_spl(
                sig="unk", ts=1760140900,
                mint=unknown_mint, amount_raw=500_000_000, decimals=9,
                from_addr=self.ADDR,
            ),
        ]
        out = adapter.fetch_erc20_outflows(self.ADDR, start_block=1760140800)
        assert len(out) == 1
        # Unknown mints get a 4-char prefix as a placeholder symbol
        assert out[0]["token"].symbol == "Unkn"
        assert out[0]["token"].coingecko_id is None

    def test_skips_inflows(self):
        adapter = _make_adapter()
        adapter.client.get_parsed_transactions.return_value = [
            self._tx_with_spl(
                sig="in", ts=1760140900,
                mint=USDC_SOLANA_MINT, amount_raw=50_000_000, decimals=6,
                from_addr="SOMEONE_ELSE",  # not our seed
            ),
        ]
        out = adapter.fetch_erc20_outflows(self.ADDR, start_block=1760140800)
        assert out == []


class TestExplorerUrls:
    def test_tx_url_uses_solscan(self):
        adapter = _make_adapter()
        assert adapter.explorer_tx_url("5xY..." ) == "https://solscan.io/tx/5xY..."

    def test_address_url_uses_solscan(self):
        adapter = _make_adapter()
        assert adapter.explorer_address_url("ABC123") == "https://solscan.io/account/ABC123"


class TestSymbolLookup:
    def test_known_mints_resolve(self):
        assert _symbol_from_mint(USDC_SOLANA_MINT) == "USDC"
        assert _symbol_from_mint("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263") == "BONK"

    def test_unknown_mint_returns_prefix(self):
        assert _symbol_from_mint("ZZZZxyzabc") == "ZZZZ"
        assert _symbol_from_mint("") == "?"
