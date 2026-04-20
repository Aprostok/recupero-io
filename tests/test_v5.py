"""Tests for the v5 patch — spoofed-stablecoin protection + aggregate."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.pricing.coingecko import (
    _CANONICAL_STABLECOIN_CONTRACTS,
    _PER_TRANSFER_USD_SANITY_CEILING,
    CoinGeckoClient,
)
from recupero.reports.aggregate import aggregate_stolen, format_aggregate_markdown


def _now():
    return datetime(2025, 10, 9, 1, 13, 47, tzinfo=timezone.utc)


def _make_token(symbol: str, contract: str | None) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=contract, symbol=symbol,
        decimals=18, coingecko_id=None,
    )


def _transfer(*, from_addr, to_addr, symbol, contract, amount, usd, tx_hash="0xabc") -> Transfer:
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum, tx_hash=tx_hash, block_number=1,
        block_time=_now(),
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=_make_token(symbol, contract),
        amount_raw=str(int(amount * Decimal(10**18))),
        amount_decimal=amount,
        usd_value_at_tx=usd, hop_depth=0,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


class TestSpoofedStablecoin:
    """Pricing must reject 'USDC'/'USDT'/etc symbols at non-canonical contracts."""

    def _client(self, tmp_path):
        from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
        cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
        env = RecuperoEnv(ETHERSCAN_API_KEY="x", COINGECKO_API_KEY="")
        return CoinGeckoClient(cfg, env, tmp_path)

    def test_real_usdc_priced_at_par(self, tmp_path):
        client = self._client(tmp_path)
        token = _make_token("USDC", _CANONICAL_STABLECOIN_CONTRACTS["USDC"])
        result = client.price_at(token, _now())
        assert result.usd_value == Decimal("1.00")
        assert result.source == "stablecoin_par"
        assert result.error is None

    def test_real_usdt_priced_at_par_case_insensitive(self, tmp_path):
        client = self._client(tmp_path)
        token = _make_token("usdt", _CANONICAL_STABLECOIN_CONTRACTS["USDT"].upper())
        result = client.price_at(token, _now())
        assert result.usd_value == Decimal("1.00")

    def test_spoofed_usdc_at_wrong_contract_refused(self, tmp_path):
        """The actual bug from the Zigha case: 'USDC' symbol at attacker's contract."""
        client = self._client(tmp_path)
        token = _make_token("USDC", "0x0cD8CC2Ddeadbeefdeadbeefdeadbeefdeadbeef")
        result = client.price_at(token, _now())
        assert result.usd_value is None
        assert result.error is not None
        assert "spoofed_canonical_symbol" in result.error
        assert "USDC" in result.error

    def test_spoofed_usdc_with_no_contract_refused(self, tmp_path):
        client = self._client(tmp_path)
        token = _make_token("USDC", None)
        result = client.price_at(token, _now())
        assert result.usd_value is None
        assert "spoofed_canonical_symbol" in (result.error or "")


class TestAggregate:
    def test_filters_to_perpetrator_destinations_only(self):
        victim = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        perp = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        not_perp = "0x88888888888888888888888888888888deadbeef"

        case = Case(
            case_id="TEST", seed_address=victim, chain=Chain.ethereum,
            incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
            transfers=[
                _transfer(from_addr=victim, to_addr=perp, symbol="USDC",
                          contract=_CANONICAL_STABLECOIN_CONTRACTS["USDC"],
                          amount=Decimal("100000"), usd=Decimal("100000"),
                          tx_hash="0x1"),
                # Non-perpetrator destination — should be excluded
                _transfer(from_addr=victim, to_addr=not_perp, symbol="USDC",
                          contract=_CANONICAL_STABLECOIN_CONTRACTS["USDC"],
                          amount=Decimal("50000"), usd=Decimal("50000"),
                          tx_hash="0x2"),
                _transfer(from_addr=victim, to_addr=perp, symbol="ETH",
                          contract=None, amount=Decimal("10"), usd=Decimal("30000"),
                          tx_hash="0x3"),
            ],
        )

        result = aggregate_stolen(cases=[case], perpetrator_addresses=[perp])
        # 2 transfers matched perpetrator (the 100K USDC and 10 ETH)
        assert result.transfer_count == 2
        # Total USD = 100K + 30K = 130K
        assert result.total_usd == Decimal("130000")
        assert len(result.by_asset) == 2

    def test_handles_unpriced_transfers(self):
        victim = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
        perp = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
        case = Case(
            case_id="T", seed_address=victim, chain=Chain.ethereum,
            incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
            transfers=[
                _transfer(from_addr=victim, to_addr=perp, symbol="WEIRD",
                          contract="0xabc", amount=Decimal("1000"), usd=None,
                          tx_hash="0x1"),
            ],
        )
        result = aggregate_stolen(cases=[case], perpetrator_addresses=[perp])
        assert result.transfer_count == 1
        assert result.total_usd == Decimal("0")
        assert result.by_asset[0].has_unpriced_transfers is True

    def test_markdown_renders_without_errors(self):
        victim = "0xVic"
        perp = "0xPerp"
        case = Case(
            case_id="T", seed_address=victim, chain=Chain.ethereum,
            incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
            transfers=[
                _transfer(from_addr=victim, to_addr=perp, symbol="ETH",
                          contract=None, amount=Decimal("1"), usd=Decimal("3000"),
                          tx_hash="0x1"),
            ],
        )
        result = aggregate_stolen(cases=[case], perpetrator_addresses=[perp])
        md = format_aggregate_markdown(result)
        assert "Stolen funds aggregate" in md
        assert "$3,000.00" in md
        assert "ETH" in md
