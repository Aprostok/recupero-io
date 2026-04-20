"""TracePolicy tests."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from recupero.models import (
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.policies import TracePolicy


def _now() -> datetime:
    return datetime(2025, 1, 15, tzinfo=timezone.utc)


def _transfer(usd: Decimal | None, label_cat: LabelCategory | None = None, hop_depth: int = 0) -> Transfer:
    label = None
    if label_cat is not None:
        label = Label(
            address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
            name="x",
            category=label_cat,
            source="test",
            confidence="high",
            added_at=_now(),
        )
    return Transfer(
        transfer_id="ethereum:0xabc:0",
        chain=Chain.ethereum,
        tx_hash="0xabc",
        block_number=1,
        block_time=_now(),
        from_address="0x0cdC902f4448b51289398261DB41E8ADC99bE955",
        to_address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
        counterparty=Counterparty(
            address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
            label=label,
        ),
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH", decimals=18, coingecko_id="ethereum"),
        amount_raw="1",
        amount_decimal=Decimal("0.000000000000000001"),
        usd_value_at_tx=usd,
        hop_depth=hop_depth,
        fetched_at=_now(),
        explorer_url="https://etherscan.io/tx/0xabc",
    )


class TestTracePolicy:
    def test_dust_filtered(self) -> None:
        p = TracePolicy(dust_threshold_usd=Decimal("50"))
        assert p.should_include(_transfer(Decimal("10"))) is False
        assert p.should_include(_transfer(Decimal("100"))) is True

    def test_unknown_usd_passes_through(self) -> None:
        p = TracePolicy(dust_threshold_usd=Decimal("50"))
        # If we don't know the USD, we still keep the transfer (better than dropping silently)
        assert p.should_include(_transfer(None)) is True

    def test_max_depth_blocks_traversal(self) -> None:
        p = TracePolicy(max_depth=1)
        # depth 0, max_depth 1 → next would be depth 1 = max → don't traverse
        assert p.should_traverse(_transfer(Decimal("100"), hop_depth=0)) is False

    def test_exchange_terminates_traversal(self) -> None:
        p = TracePolicy(max_depth=10, stop_at_exchange=True)
        assert p.should_traverse(
            _transfer(Decimal("100"), label_cat=LabelCategory.exchange_deposit)
        ) is False

    def test_mixer_terminates_traversal(self) -> None:
        p = TracePolicy(max_depth=10, stop_at_mixer=True)
        assert p.should_traverse(_transfer(Decimal("100"), label_cat=LabelCategory.mixer)) is False

    def test_unlabeled_address_traversed(self) -> None:
        p = TracePolicy(max_depth=10)
        assert p.should_traverse(_transfer(Decimal("100"), label_cat=None)) is True
