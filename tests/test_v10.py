"""Tests for v10 — Hyperliquid ledger scraper."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch, MagicMock

from recupero.chains.hyperliquid.client import (
    HyperliquidLedgerEvent,
    _parse_ledger_event,
)
from recupero.chains.hyperliquid.scraper import (
    ARBITRUM_USDC,
    _events_to_transfers,
    scrape_hyperliquid_case,
)
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain


USER = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"


class TestParseLedgerEvent:
    def test_withdraw_event_parsed(self):
        raw = {
            "time": 1760000000000,
            "hash": "abc123",
            "delta": {"type": "withdraw", "usdc": "-1000000.50", "destination": PERP},
        }
        evt = _parse_ledger_event(raw)
        assert evt is not None
        assert evt.time_ms == 1760000000000
        assert evt.delta_type == "withdraw"
        assert evt.usdc_delta == Decimal("-1000000.50")
        assert evt.destination == PERP

    def test_deposit_event_parsed(self):
        raw = {
            "time": 1759000000000,
            "hash": "dep1",
            "delta": {"type": "deposit", "usdc": "500000"},
        }
        evt = _parse_ledger_event(raw)
        assert evt is not None
        assert evt.delta_type == "deposit"
        assert evt.usdc_delta == Decimal("500000")
        assert evt.destination is None

    def test_malformed_event_returns_none(self):
        # No time field — unparseable
        assert _parse_ledger_event({"hash": "x"}) is None

    def test_zero_usdc_delta_still_parses(self):
        raw = {"time": 1, "hash": "z", "delta": {"type": "accountClassTransfer"}}
        evt = _parse_ledger_event(raw)
        # Zero delta events parse but will be filtered later by the scraper
        assert evt is not None
        assert evt.usdc_delta == Decimal("0")


class TestEventsToTransfers:
    def _event(self, *, time_ms, delta_type, usdc_delta, destination=None):
        return HyperliquidLedgerEvent(
            time_ms=time_ms,
            hash=f"h-{time_ms}",
            delta_type=delta_type,
            usdc_delta=Decimal(str(usdc_delta)),
            destination=destination,
            raw={},
        )

    def test_withdrawal_becomes_outflow_transfer(self):
        """$1M withdraw from USER to PERP (Arbitrum destination) on Hyperliquid."""
        events = [self._event(
            time_ms=1760000000000,
            delta_type="withdraw",
            usdc_delta="-1000000",
            destination=PERP,
        )]
        transfers = _events_to_transfers(events, USER)
        assert len(transfers) == 1
        t = transfers[0]
        assert t.from_address == USER
        assert t.to_address == PERP
        assert t.amount_decimal == Decimal("1000000")
        assert t.usd_value_at_tx == Decimal("1000000")  # USDC = $1
        assert t.token.contract == ARBITRUM_USDC
        assert t.token.symbol == "USDC"
        assert t.pricing_source == "hyperliquid_native_usdc"

    def test_deposit_becomes_inflow_transfer(self):
        events = [self._event(
            time_ms=1759000000000,
            delta_type="deposit",
            usdc_delta="+500000",
        )]
        transfers = _events_to_transfers(events, USER)
        assert len(transfers) == 1
        t = transfers[0]
        # Inflow: user is the recipient
        assert t.to_address == USER
        assert t.from_address.startswith("hyperliquid:unknown_source")
        assert t.amount_decimal == Decimal("500000")

    def test_zero_delta_events_skipped(self):
        """Position class transfers with no USDC movement are excluded."""
        events = [self._event(
            time_ms=1, delta_type="accountClassTransfer", usdc_delta="0",
        )]
        transfers = _events_to_transfers(events, USER)
        assert transfers == []

    def test_multiple_events_get_unique_transfer_ids(self):
        events = [
            self._event(time_ms=1, delta_type="withdraw", usdc_delta="-100", destination=PERP),
            self._event(time_ms=2, delta_type="withdraw", usdc_delta="-200", destination=PERP),
            self._event(time_ms=3, delta_type="deposit", usdc_delta="50"),
        ]
        transfers = _events_to_transfers(events, USER)
        assert len(transfers) == 3
        assert len({t.transfer_id for t in transfers}) == 3  # all unique

    def test_amount_raw_uses_6_decimals(self):
        """USDC on Hyperliquid uses 6 decimals. $1,000,000 = 1_000_000_000_000 raw."""
        events = [self._event(
            time_ms=1, delta_type="withdraw", usdc_delta="-1000000", destination=PERP,
        )]
        transfers = _events_to_transfers(events, USER)
        assert transfers[0].amount_raw == "1000000000000"


class TestScrapeHyperliquidCase:
    """Integration test: full scrape flow, client mocked."""

    def test_produces_case_with_expected_structure(self):
        cfg = RecuperoConfig()
        env = RecuperoEnv(ETHERSCAN_API_KEY="x")

        fake_events = [
            HyperliquidLedgerEvent(
                time_ms=1760000000000, hash="w1", delta_type="withdraw",
                usdc_delta=Decimal("-1000000"), destination=PERP, raw={},
            ),
            HyperliquidLedgerEvent(
                time_ms=1760001000000, hash="w2", delta_type="withdraw",
                usdc_delta=Decimal("-2000000"), destination=PERP, raw={},
            ),
        ]

        with patch("recupero.chains.hyperliquid.scraper.HyperliquidClient") as mock_cls:
            instance = MagicMock()
            instance.get_non_funding_ledger_updates.return_value = fake_events
            mock_cls.return_value = instance

            case = scrape_hyperliquid_case(
                user_address=USER,
                case_id="TEST-HL",
                incident_time=datetime(2025, 10, 9, tzinfo=timezone.utc),
                config=cfg,
                env=env,
            )

        assert case.case_id == "TEST-HL"
        assert case.seed_address == USER
        assert case.chain == Chain.ethereum  # Hyperliquid uses EVM-format addresses
        assert len(case.transfers) == 2
        total_usd = sum(t.usd_value_at_tx for t in case.transfers)
        assert total_usd == Decimal("3000000")
