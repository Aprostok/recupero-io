"""Tests for v12 — chain-aware CoinGecko pricing.

Critical bug being fixed: pre-v12, Arbitrum USDC (0xaf88d065...) was being
rejected as a spoofed USDC token because its contract address didn't match
Ethereum USDC (0xa0b86991...). The canonical-stablecoin map and the
contract-to-id lookup both hardcoded Ethereum as the only chain.

v12 scopes stablecoin canonicals and contract-id caches by (chain, address).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain, TokenRef
from recupero.pricing.coingecko import (
    CoinGeckoClient,
    _CANONICAL_STABLECOIN_CONTRACTS,
    _CHAIN_TO_CG_PLATFORM,
)


def _make_client(tmp_path: Path) -> CoinGeckoClient:
    cfg = RecuperoConfig()
    env = RecuperoEnv(ETHERSCAN_API_KEY="eth", COINGECKO_API_KEY="", COINGECKO_TIER="demo")
    return CoinGeckoClient(cfg, env, tmp_path / "prices_cache")


WHEN = datetime(2025, 10, 9, 0, 0, 0, tzinfo=timezone.utc)


class TestArbitrumStablecoinsPriceCorrectly:
    """The core bug: Arbitrum USDC was being rejected as a spoof. Fix it."""

    def test_arbitrum_usdc_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.arbitrum,
            contract="0xaf88d065e77c8cC2239327C5EDb3A432268e5831",  # Arbitrum native USDC
            symbol="USDC",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")
        assert result.source == "stablecoin_par"
        assert result.error is None

    def test_arbitrum_usdt_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.arbitrum,
            contract="0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",  # Arbitrum USDT
            symbol="USDT",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")
        assert result.source == "stablecoin_par"

    def test_arbitrum_dai_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.arbitrum,
            contract="0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1",
            symbol="DAI",
            decimals=18,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")


class TestBscStablecoinsPriceCorrectly:
    def test_bsc_usdt_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.bsc,
            contract="0x55d398326f99059fF775485246999027B3197955",  # BSC USDT (18 decimals!)
            symbol="USDT",
            decimals=18,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")


class TestSolanaStablecoinsPriceCorrectly:
    def test_solana_usdc_prices_at_par_via_canonical(self, tmp_path):
        """Solana's USDC has a base58 mint, stored lowercased."""
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.solana,
            contract="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # Canonical USDC mint
            symbol="USDC",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")
        assert result.source == "stablecoin_par"


class TestEthereumStablecoinsStillWork:
    """Regression test — make sure we didn't break Ethereum pricing."""

    def test_ethereum_usdc_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.ethereum,
            contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            symbol="USDC",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")
        assert result.source == "stablecoin_par"

    def test_ethereum_dai_prices_at_par(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.ethereum,
            contract="0x6B175474E89094C44Da98b954EedeAC495271d0F",
            symbol="DAI",
            decimals=18,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value == Decimal("1.00")


class TestSpoofRejectionStillWorks:
    """CRITICAL — the spoof-protection must still fire for fake stablecoins."""

    def test_fake_usdc_on_ethereum_rejected(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.ethereum,
            contract="0x1234567890AbcdEF1234567890aBcdef12345678",  # Attacker-controlled
            symbol="USDC",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        # Still no USD value because contract doesn't match canonical Ethereum USDC
        assert result.usd_value is None
        # Error should flag the spoof clearly
        assert result.error is not None
        assert "spoofed_canonical_symbol" in result.error
        assert "USDC" in result.error
        assert "ethereum" in result.error

    def test_fake_usdc_on_arbitrum_rejected(self, tmp_path):
        """Even on a chain we support, a non-canonical USDC must be rejected."""
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.arbitrum,
            contract="0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef",
            symbol="USDC",
            decimals=6,
        )
        result = client.price_at(token, WHEN)
        assert result.usd_value is None
        assert result.error is not None
        assert "spoofed_canonical_symbol" in result.error
        assert "arbitrum" in result.error


class TestContractLookupIsChainAware:
    """The API-fallback path must hit the right CoinGecko platform per chain."""

    def test_arbitrum_lookup_hits_arbitrum_one_platform(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.arbitrum,
            contract="0x1234567890123456789012345678901234567890",
            symbol="SOMETOKEN",
            decimals=18,
        )
        with patch.object(client, "_fetch_contract_to_id", return_value=None) as mock_fetch:
            client.price_at(token, WHEN)
        # Must have been called with chain=Chain.arbitrum
        mock_fetch.assert_called_once()
        args, kwargs = mock_fetch.call_args
        assert args[0] == Chain.arbitrum or kwargs.get("chain") == Chain.arbitrum

    def test_ethereum_lookup_hits_ethereum_platform(self, tmp_path):
        client = _make_client(tmp_path)
        token = TokenRef(
            chain=Chain.ethereum,
            contract="0xabcdef0000000000000000000000000000000001",
            symbol="RANDOM",
            decimals=18,
        )
        with patch.object(client, "_fetch_contract_to_id", return_value=None) as mock_fetch:
            client.price_at(token, WHEN)
        mock_fetch.assert_called_once()
        args, _ = mock_fetch.call_args
        assert args[0] == Chain.ethereum

    def test_cache_key_is_chain_scoped(self, tmp_path):
        """Arbitrum USDC and Ethereum USDC have identical-looking hex contracts
        on rare collisions — but our cache must keep them separate."""
        client = _make_client(tmp_path)
        same_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        # Populate Ethereum cache entry
        client._contract_id_cache[(Chain.ethereum, same_addr)] = "tether"
        # Solana shouldn't see it
        client._contract_id_cache[(Chain.arbitrum, same_addr)] = None

        token_eth = TokenRef(chain=Chain.ethereum, contract=same_addr, symbol="X", decimals=18)
        token_arb = TokenRef(chain=Chain.arbitrum, contract=same_addr, symbol="X", decimals=18)

        assert client._resolve_cg_id(token_eth) == "tether"
        assert client._resolve_cg_id(token_arb) is None


class TestPlatformMap:
    """Sanity check — the platform map covers the chains we actually use."""

    def test_ethereum_maps_to_ethereum(self):
        assert _CHAIN_TO_CG_PLATFORM[Chain.ethereum] == "ethereum"

    def test_arbitrum_maps_to_arbitrum_one(self):
        assert _CHAIN_TO_CG_PLATFORM[Chain.arbitrum] == "arbitrum-one"

    def test_bsc_maps_to_binance_smart_chain(self):
        assert _CHAIN_TO_CG_PLATFORM[Chain.bsc] == "binance-smart-chain"

    def test_solana_maps_to_solana(self):
        assert _CHAIN_TO_CG_PLATFORM[Chain.solana] == "solana"


class TestCanonicalStablecoinCoverage:
    """Sanity check — common stablecoin/chain combos must all have entries."""

    def test_ethereum_usdc_is_canonical(self):
        assert (Chain.ethereum, "USDC") in _CANONICAL_STABLECOIN_CONTRACTS

    def test_arbitrum_usdc_is_canonical(self):
        assert (Chain.arbitrum, "USDC") in _CANONICAL_STABLECOIN_CONTRACTS

    def test_bsc_usdt_is_canonical(self):
        assert (Chain.bsc, "USDT") in _CANONICAL_STABLECOIN_CONTRACTS

    def test_solana_usdc_is_canonical(self):
        assert (Chain.solana, "USDC") in _CANONICAL_STABLECOIN_CONTRACTS
