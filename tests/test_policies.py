"""TracePolicy tests."""

from __future__ import annotations

from datetime import UTC, datetime
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
    return datetime(2025, 1, 15, tzinfo=UTC)


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

    def test_unknown_usd_with_substantial_amount_passes(self) -> None:
        """v0.18.0 (round-11 forensic-HIGH-003): unpriced transfers
        with a substantial token amount (>=10 units) still pass — we
        can't know the USD but the on-chain amount is real and
        worth surfacing.
        """
        p = TracePolicy(dust_threshold_usd=Decimal("50"))
        # Build a transfer with usd=None but amount_decimal=100 token units.
        t = _transfer(None)
        t = t.model_copy(update={"amount_decimal": Decimal("100")})
        assert p.should_include(t) is True

    def test_unknown_usd_with_dust_amount_filtered(self) -> None:
        """v0.18.0 (round-11 forensic-HIGH-003): unpriced transfers
        with <10 token units are treated as dust. Pre-v0.18.0
        unpriced dust passed silently, bloating the counterparty
        list with phantom hops. Fixture default amount_decimal is
        1 wei (essentially zero) so the bare unpriced transfer
        is now filtered.
        """
        p = TracePolicy(dust_threshold_usd=Decimal("50"))
        # Default fixture has amount_decimal = 1 wei (< 0.001 micro-dust floor).
        assert p.should_include(_transfer(None)) is False

    def test_unknown_usd_high_value_low_unit_token_now_traced(self) -> None:
        """v0.32.1 (trace-depth #2): the unpriced floor was lowered from
        10 units to 1e-3 because the old floor was VALUE-BLIND — it dropped
        a transfer of 5 units of an unpriced token even though 5 units could
        be 5 WBTC (~$300K). Since this filter also gates frontier expansion,
        the old floor silently lost the onward trail through a low-liquidity
        / unpriced token. A 5-unit unpriced transfer must now be KEPT (and
        thus traced + recorded)."""
        p = TracePolicy(dust_threshold_usd=Decimal("50"))
        t = _transfer(None).model_copy(update={"amount_decimal": Decimal("5")})
        assert p.should_include(t) is True
        # And a 0.5-unit unpriced transfer (e.g. 0.5 WBTC ~$30K) is kept too.
        t2 = _transfer(None).model_copy(update={"amount_decimal": Decimal("0.5")})
        assert p.should_include(t2) is True
        # But literal micro-dust (below 1e-3 units) is still dropped.
        t3 = _transfer(None).model_copy(update={"amount_decimal": Decimal("0.0000001")})
        assert p.should_include(t3) is False

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
