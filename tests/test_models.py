"""Model serialization & validation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from recupero.models import (
    SCHEMA_VERSION,
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)


def _now() -> datetime:
    return datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)


def _eth_token() -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract=None,
        symbol="ETH",
        decimals=18,
        coingecko_id="ethereum",
    )


def _label(addr: str = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d") -> Label:
    return Label(
        address=addr,
        name="MEXC Deposit",
        category=LabelCategory.exchange_deposit,
        exchange="MEXC",
        source="local_seed:cex_deposits.json",
        confidence="high",
        added_at=_now(),
    )


def _transfer(tx_hash: str = "0xabc", to_addr: str = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d") -> Transfer:
    cp = Counterparty(address=to_addr, label=_label(to_addr), is_contract=False, first_seen_at=_now())
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=19000000,
        block_time=_now(),
        log_index=None,
        from_address="0x0cdC902f4448b51289398261DB41E8ADC99bE955",
        to_address=to_addr,
        counterparty=cp,
        token=_eth_token(),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("3000.00"),
        pricing_source="coingecko:ethereum:2025-01-15",
        pricing_error=None,
        hop_depth=0,
        parent_transfer_id=None,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


class TestModels:
    def test_amount_raw_must_be_integer_string(self) -> None:
        with pytest.raises(ValueError):
            Transfer(
                transfer_id="ethereum:0xabc:0",
                chain=Chain.ethereum,
                tx_hash="0xabc",
                block_number=1,
                block_time=_now(),
                log_index=None,
                from_address="0xa",
                to_address="0xb",
                counterparty=Counterparty(address="0xb"),
                token=_eth_token(),
                amount_raw="1.5",  # not an integer
                amount_decimal=Decimal("1.5"),
                fetched_at=_now(),
                explorer_url="https://etherscan.io/tx/0xabc",
            )

    def test_amount_decimal_rejects_negative_and_nonfinite(self) -> None:
        """`amount_decimal` is what the pipeline does arithmetic on; a
        negative or NaN/Inf value would silently corrupt loss totals.
        The model must reject both at construction."""
        for bad in (Decimal("-1"), Decimal("NaN"), Decimal("Infinity"),
                    Decimal("-Infinity")):
            with pytest.raises(ValueError):
                Transfer(
                    transfer_id="ethereum:0xabc:0",
                    chain=Chain.ethereum,
                    tx_hash="0xabc",
                    block_number=1,
                    block_time=_now(),
                    log_index=None,
                    from_address="0xa",
                    to_address="0xb",
                    counterparty=Counterparty(address="0xb"),
                    token=_eth_token(),
                    amount_raw="1000000",
                    amount_decimal=bad,
                    fetched_at=_now(),
                    explorer_url="https://etherscan.io/tx/0xabc",
                )

    def test_usd_value_rejects_negative_and_nonfinite_but_allows_none(self) -> None:
        """`usd_value_at_tx` is optional (None passes), but a present value
        must be finite and non-negative — a poisoned price feed must not
        enter the Decimal column the recovery math sums over."""
        # None is allowed.
        t = _transfer()
        assert t.usd_value_at_tx == Decimal("3000.00")
        for bad in (Decimal("-0.01"), Decimal("NaN"), Decimal("Infinity")):
            with pytest.raises(ValueError):
                Transfer(
                    transfer_id="ethereum:0xabc:0",
                    chain=Chain.ethereum,
                    tx_hash="0xabc",
                    block_number=1,
                    block_time=_now(),
                    log_index=None,
                    from_address="0xa",
                    to_address="0xb",
                    counterparty=Counterparty(address="0xb"),
                    token=_eth_token(),
                    amount_raw="1000000",
                    amount_decimal=Decimal("1.0"),
                    usd_value_at_tx=bad,
                    fetched_at=_now(),
                    explorer_url="https://etherscan.io/tx/0xabc",
                )

    def test_token_decimals_rejects_negative(self) -> None:
        """`TokenRef.decimals` is the exponent in amount = raw/10**decimals;
        a negative value (malformed RPC/label response) would inflate every
        derived USD figure. The model must reject it at the boundary."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            TokenRef(chain=Chain.ethereum, symbol="EVIL", decimals=-1)
        # Sanity: a normal value still constructs.
        ok = TokenRef(chain=Chain.ethereum, symbol="USDC", decimals=6)
        assert ok.decimals == 6

    def test_extra_fields_forbidden(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            Label(
                address="0xa",
                name="x",
                category=LabelCategory.unknown,
                source="x",
                added_at=_now(),
                bogus_field="should fail",  # type: ignore[call-arg]
            )

    def test_case_round_trips_through_json(self) -> None:
        case = Case(
            case_id="TEST",
            seed_address="0x0cdC902f4448b51289398261DB41E8ADC99bE955",
            chain=Chain.ethereum,
            incident_time=_now(),
            transfers=[_transfer()],
            trace_started_at=_now(),
        )
        payload = case.model_dump(mode="json")
        assert payload["schema_version"] == SCHEMA_VERSION
        rebuilt = Case.model_validate(payload)
        assert rebuilt.case_id == case.case_id
        assert len(rebuilt.transfers) == 1
        assert rebuilt.transfers[0].usd_value_at_tx == Decimal("3000.00")

    def test_label_category_enum(self) -> None:
        label = _label()
        assert label.category == LabelCategory.exchange_deposit
        # Serialization preserves enum value
        assert label.model_dump(mode="json")["category"] == "exchange_deposit"
