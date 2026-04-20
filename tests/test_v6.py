"""Tests for v6 — Arbitrum/BSC EVM support + aggregate dedup fix."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from recupero.chains.base import ChainAdapter
from recupero.chains.evm.adapter import _profile_for
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.aggregate import aggregate_stolen


def _now():
    return datetime(2025, 10, 9, 1, 13, 47, tzinfo=timezone.utc)


def _transfer(*, from_addr, to_addr, symbol, amount_usd, tx) -> Transfer:
    return Transfer(
        transfer_id=f"ethereum:{tx}:0",
        chain=Chain.ethereum, tx_hash=tx, block_number=1,
        block_time=_now(),
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol=symbol,
                       decimals=18, coingecko_id="ethereum"),
        amount_raw="1000",
        amount_decimal=Decimal(str(amount_usd)) / Decimal("3000"),
        usd_value_at_tx=Decimal(str(amount_usd)),
        hop_depth=0,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx}",
    )


class TestMultiChainProfiles:
    """Profiles for all three EVM chains should be buildable."""

    def test_ethereum_profile(self):
        cfg = RecuperoConfig()
        p = _profile_for(Chain.ethereum, cfg)
        assert p.chain == Chain.ethereum
        assert p.chain_id == 1
        assert p.native_symbol == "ETH"
        assert "etherscan.io" in p.explorer_base

    def test_arbitrum_profile(self):
        cfg = RecuperoConfig()
        p = _profile_for(Chain.arbitrum, cfg)
        assert p.chain == Chain.arbitrum
        assert p.chain_id == 42161
        assert p.native_symbol == "ETH"  # Arbitrum gas = ETH
        assert "arbiscan.io" in p.explorer_base
        assert p.coingecko_platform == "arbitrum-one"

    def test_bsc_profile(self):
        cfg = RecuperoConfig()
        p = _profile_for(Chain.bsc, cfg)
        assert p.chain == Chain.bsc
        assert p.chain_id == 56
        assert p.native_symbol == "BNB"
        assert "bscscan.com" in p.explorer_base
        assert p.coingecko_native_id == "binancecoin"

    def test_factory_produces_adapter_for_arbitrum(self):
        cfg = RecuperoConfig()
        env = RecuperoEnv(ETHERSCAN_API_KEY="test-key")
        adapter = ChainAdapter.for_chain(Chain.arbitrum, (cfg, env))
        assert adapter is not None
        assert adapter.explorer_tx_url("0xabc").startswith("https://arbiscan.io/tx/")

    def test_factory_produces_adapter_for_bsc(self):
        cfg = RecuperoConfig()
        env = RecuperoEnv(ETHERSCAN_API_KEY="test-key")
        adapter = ChainAdapter.for_chain(Chain.bsc, (cfg, env))
        assert adapter.explorer_tx_url("0xabc").startswith("https://bscscan.com/tx/")


class TestAggregateDedup:
    """Perpetrator-to-perpetrator transfers must not be double-counted."""

    def test_perp_to_perp_excluded_by_default(self):
        """The Zigha-case bug: perp wallet #1 forwarded $3.12M to perp wallet #2.
        That's the SAME stolen money moving, not new theft. Must not be counted."""
        victim = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        perp1 = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        perp2 = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"

        case = Case(
            case_id="TEST", seed_address=victim, chain=Chain.ethereum,
            incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
            transfers=[
                # Legitimate theft: victim -> perp1
                _transfer(from_addr=victim, to_addr=perp1, symbol="ETH",
                          amount_usd=3119023, tx="0xtheft"),
                # Internal forwarding: perp1 -> perp2. Same money, not new theft.
                _transfer(from_addr=perp1, to_addr=perp2, symbol="ETH",
                          amount_usd=3119023, tx="0xforward"),
            ],
        )

        result = aggregate_stolen(
            cases=[case],
            perpetrator_addresses=[perp1, perp2],
        )
        # Only the victim→perp transfer counts; perp→perp is excluded.
        assert result.transfer_count == 1
        assert result.total_usd == Decimal("3119023")
        # Victim wallet in the by_victim table should NOT include perp1.
        assert victim in result.by_victim_wallet
        assert perp1 not in result.by_victim_wallet

    def test_perp_to_perp_included_if_explicitly_requested(self):
        """Some analyses may want to include internal flows (flow-through view)."""
        victim = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        perp1 = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        perp2 = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"

        case = Case(
            case_id="TEST", seed_address=victim, chain=Chain.ethereum,
            incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
            transfers=[
                _transfer(from_addr=victim, to_addr=perp1, symbol="ETH",
                          amount_usd=3119023, tx="0xtheft"),
                _transfer(from_addr=perp1, to_addr=perp2, symbol="ETH",
                          amount_usd=3119023, tx="0xforward"),
            ],
        )
        result = aggregate_stolen(
            cases=[case],
            perpetrator_addresses=[perp1, perp2],
            exclude_internal_transfers=False,
        )
        # Both transfers counted when override is set
        assert result.transfer_count == 2
        assert result.total_usd == Decimal("6238046")
