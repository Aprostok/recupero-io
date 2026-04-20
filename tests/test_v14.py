"""Tests for v14 — dormant wallet detection from a case."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
from recupero.dormant.finder import (
    DormantCandidate,
    TokenHolding,
    find_dormant_in_case,
    write_dormant_report,
)
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.pricing.coingecko import PriceResult


VICTIM = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP_DORMANT_DAI = "0x3daFC6a860334d4feB0467a3D58C3687E9E921B6"
PERP_DORMANT_DAI_2 = "0x415D8D075CAcB5A61Ae854A8e5ea53DF3A76F688"
PERP_LOW_BALANCE = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"

DAI_CONTRACT = "0x6b175474e89094c44da98b954eedeac495271d0f"


def _dai_token() -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=DAI_CONTRACT,
        symbol="DAI", decimals=18, coingecko_id="dai",
    )


def _make_transfer(from_addr: str, to_addr: str, usd: Decimal, tx_hash: str = "0xabc") -> Transfer:
    return Transfer(
        transfer_id=f"test:{tx_hash}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=23000000,
        block_time=datetime(2025, 10, 9, tzinfo=timezone.utc),
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=_dai_token(),
        amount_raw=str(int(usd * Decimal(10**18))),
        amount_decimal=usd,
        usd_value_at_tx=usd,
        pricing_source="stablecoin_par",
        pricing_error=None,
        hop_depth=0,
        fetched_at=datetime.now(timezone.utc),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _make_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="TEST",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2025, 10, 9, tzinfo=timezone.utc),
        trace_started_at=datetime.now(timezone.utc),
        trace_completed_at=datetime.now(timezone.utc),
        transfers=transfers,
    )


@pytest.fixture
def cfg(tmp_path: Path):
    config = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    env = RecuperoEnv(ETHERSCAN_API_KEY="test", COINGECKO_API_KEY="test")
    return config, env


def _patched_finder(monkeypatch, balances: dict[str, dict[str, int]], eth_balances: dict[str, int] | None = None):
    """Install a fake EthereumAdapter + CoinGeckoClient so finder runs without HTTP.

    balances: {address: {contract_lower: raw_int_amount}}
    eth_balances: {address: raw_wei}
    """
    from recupero.dormant import finder as finder_mod

    eth_balances = eth_balances or {}

    def fake_ethereum_adapter(_bundle):
        adapter = MagicMock()
        adapter.client = MagicMock()
        def get_token_balance(contract, address, tag="latest"):
            return balances.get(address.lower(), {}).get(contract.lower(), 0)
        def get_eth_balance(address, tag="latest"):
            return eth_balances.get(address.lower(), 0)
        adapter.client.get_token_balance.side_effect = get_token_balance
        adapter.client.get_eth_balance.side_effect = get_eth_balance
        adapter.explorer_address_url.side_effect = lambda a: f"https://etherscan.io/address/{a}"
        return adapter

    def fake_price_client(_cfg, _env, _cache_dir):
        client = MagicMock()
        # All DAI = $1, all ETH = $4500
        def price_now(token):
            if token.symbol.upper() == "DAI":
                return PriceResult(usd_value=Decimal("1.00"), source="stablecoin_par", error=None)
            if token.symbol.upper() == "ETH":
                return PriceResult(usd_value=Decimal("4500"), source="fake", error=None)
            return PriceResult(usd_value=None, source=None, error="not_in_test_fixture")
        client.price_now.side_effect = price_now
        client.close = MagicMock()
        return client

    monkeypatch.setattr(finder_mod, "EthereumAdapter", fake_ethereum_adapter)
    monkeypatch.setattr(finder_mod, "CoinGeckoClient", fake_price_client)


class TestDormantBasic:
    def test_finds_dormant_address_with_dai_balance(self, cfg, monkeypatch):
        config, env = cfg
        # Case: victim sent $10M DAI to PERP_DORMANT_DAI
        transfers = [_make_transfer(VICTIM, PERP_DORMANT_DAI, Decimal("10000000"))]
        case = _make_case(transfers)
        # On-chain: that address still holds 9.98M DAI (no outflow)
        balances = {
            PERP_DORMANT_DAI.lower(): {DAI_CONTRACT: int(Decimal("9980000") * Decimal(10**18))},
        }
        _patched_finder(monkeypatch, balances)

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("100000"),
        )
        assert len(candidates) == 1
        c = candidates[0]
        assert c.address == PERP_DORMANT_DAI
        assert c.total_usd == Decimal("9980000.00")
        assert c.inflow_usd_during_case == Decimal("10000000")
        assert c.inflow_count == 1
        # Holding details
        assert len(c.holdings) == 1
        assert c.holdings[0].token.symbol == "DAI"
        assert c.holdings[0].decimal_amount == Decimal("9980000")

    def test_skips_addresses_below_threshold(self, cfg, monkeypatch):
        config, env = cfg
        transfers = [
            _make_transfer(VICTIM, PERP_DORMANT_DAI, Decimal("10000000")),
            _make_transfer(VICTIM, PERP_LOW_BALANCE, Decimal("5000")),
        ]
        case = _make_case(transfers)
        balances = {
            PERP_DORMANT_DAI.lower(): {DAI_CONTRACT: int(Decimal("9980000") * Decimal(10**18))},
            PERP_LOW_BALANCE.lower(): {DAI_CONTRACT: int(Decimal("100") * Decimal(10**18))},  # holds $100
        }
        _patched_finder(monkeypatch, balances)

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("100000"),
        )
        # Only the big one passes the threshold
        assert len(candidates) == 1
        assert candidates[0].address == PERP_DORMANT_DAI

    def test_sorts_by_usd_value_descending(self, cfg, monkeypatch):
        config, env = cfg
        transfers = [
            _make_transfer(VICTIM, PERP_DORMANT_DAI, Decimal("7000000"), tx_hash="0xa"),
            _make_transfer(VICTIM, PERP_DORMANT_DAI_2, Decimal("10000000"), tx_hash="0xb"),
        ]
        case = _make_case(transfers)
        balances = {
            PERP_DORMANT_DAI.lower():   {DAI_CONTRACT: int(Decimal("6910000") * Decimal(10**18))},
            PERP_DORMANT_DAI_2.lower(): {DAI_CONTRACT: int(Decimal("9980000") * Decimal(10**18))},
        }
        _patched_finder(monkeypatch, balances)

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("1000000"),
        )
        assert len(candidates) == 2
        # Bigger one first
        assert candidates[0].address == PERP_DORMANT_DAI_2
        assert candidates[0].total_usd == Decimal("9980000.00")
        assert candidates[1].address == PERP_DORMANT_DAI
        assert candidates[1].total_usd == Decimal("6910000.00")

    def test_excludes_seed_address(self, cfg, monkeypatch):
        """The victim's own wallet should never appear as a freeze target."""
        config, env = cfg
        # Suppose someone sent money TO the victim during the case (refund? misdirection?)
        transfers = [_make_transfer(PERP_DORMANT_DAI, VICTIM, Decimal("100"))]
        case = _make_case(transfers)
        balances = {VICTIM.lower(): {DAI_CONTRACT: int(Decimal("1000000") * Decimal(10**18))}}
        _patched_finder(monkeypatch, balances)

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("1000"),
        )
        assert len(candidates) == 0

    def test_skips_hyperliquid_placeholder_addresses(self, cfg, monkeypatch):
        """Synthetic 'hyperliquid:unknown_*' counterparties from the HL scraper
        must not be treated as on-chain Ethereum addresses."""
        config, env = cfg
        transfers = [_make_transfer(VICTIM, "hyperliquid:unknown_destination", Decimal("100000"))]
        case = _make_case(transfers)
        _patched_finder(monkeypatch, {})

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("100"),
        )
        assert candidates == []

    def test_empty_balance_address_excluded(self, cfg, monkeypatch):
        """Address received money during the case but has since drained — exclude."""
        config, env = cfg
        transfers = [_make_transfer(VICTIM, PERP_DORMANT_DAI, Decimal("1000000"))]
        case = _make_case(transfers)
        # No balance — they moved it
        _patched_finder(monkeypatch, {PERP_DORMANT_DAI.lower(): {}})

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("1000"),
        )
        assert candidates == []

    def test_native_eth_dust_below_threshold_excluded(self, cfg, monkeypatch):
        """An address that holds only a tiny amount of ETH gas dust shouldn't surface."""
        config, env = cfg
        transfers = [_make_transfer(VICTIM, PERP_LOW_BALANCE, Decimal("100"))]
        case = _make_case(transfers)
        # 0.001 ETH = $4.50
        eth_balances = {PERP_LOW_BALANCE.lower(): int(Decimal("0.001") * Decimal(10**18))}
        _patched_finder(monkeypatch, {}, eth_balances=eth_balances)

        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("100"),
        )
        assert candidates == []


class TestNonEthereumChain:
    def test_solana_case_returns_empty_for_now(self, cfg, monkeypatch, caplog):
        """Phase 1 only supports Ethereum dormant detection. Solana cases
        should warn and return empty rather than crash."""
        config, env = cfg
        case = Case(
            case_id="TEST", seed_address="SOLADDR",
            chain=Chain.solana,
            incident_time=datetime(2025, 10, 9, tzinfo=timezone.utc),
            trace_started_at=datetime.now(timezone.utc),
            transfers=[],
        )
        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=Decimal("100"),
        )
        assert candidates == []


class TestTopHoldingSummary:
    def test_sorts_holdings_by_usd_value(self):
        c = DormantCandidate(
            address="0xabc", chain=Chain.ethereum,
            total_usd=Decimal("11000"),
            holdings=[
                TokenHolding(
                    token=TokenRef(chain=Chain.ethereum, contract="0xdai", symbol="DAI", decimals=18),
                    raw_amount=1000, decimal_amount=Decimal("1000"), usd_value=Decimal("1000"),
                ),
                TokenHolding(
                    token=TokenRef(chain=Chain.ethereum, contract="0xusdc", symbol="USDC", decimals=6),
                    raw_amount=10000, decimal_amount=Decimal("10000"), usd_value=Decimal("10000"),
                ),
            ],
        )
        summary = c.top_holding_summary()
        # USDC (10K) should be listed before DAI (1K)
        assert summary.startswith("10,000.0000 USDC")
        assert "DAI" in summary


class TestWriteReport:
    def test_writes_json_report(self, tmp_path):
        candidates = [
            DormantCandidate(
                address="0xabc", chain=Chain.ethereum,
                total_usd=Decimal("9980000"),
                holdings=[TokenHolding(
                    token=TokenRef(chain=Chain.ethereum, contract="0xdai", symbol="DAI", decimals=18),
                    raw_amount=10**24, decimal_amount=Decimal("9980000"), usd_value=Decimal("9980000"),
                )],
                inflow_usd_during_case=Decimal("10000000"), inflow_count=5,
                explorer_url="https://etherscan.io/address/0xabc",
            ),
        ]
        path = write_dormant_report(tmp_path, candidates)
        assert path.exists()
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["candidates"]) == 1
        assert data["candidates"][0]["address"] == "0xabc"
        assert data["candidates"][0]["total_usd"] == "9980000"
        assert data["candidates"][0]["holdings"][0]["symbol"] == "DAI"
