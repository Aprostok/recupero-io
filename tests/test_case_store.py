"""CaseStore tests — verify case.json round-trips and CSV is well-formed."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from recupero.config import RecuperoConfig, StorageParams
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    ExchangeEndpoint,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.storage.case_store import CaseStore


def _now() -> datetime:
    return datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _sample_case() -> Case:
    label = Label(
        address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
        name="MEXC Deposit",
        category=LabelCategory.exchange_deposit,
        exchange="MEXC",
        source="local_seed",
        confidence="high",
        added_at=_now(),
    )
    cp = Counterparty(
        address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
        label=label,
        is_contract=False,
        first_seen_at=_now(),
    )
    transfer = Transfer(
        transfer_id="ethereum:0xabc:0",
        chain=Chain.ethereum,
        tx_hash="0xabc",
        block_number=19000000,
        block_time=_now(),
        log_index=None,
        from_address="0x0cdC902f4448b51289398261DB41E8ADC99bE955",
        to_address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
        counterparty=cp,
        token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH", decimals=18, coingecko_id="ethereum"),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("3000.00"),
        pricing_source="coingecko:ethereum:2025-01-15",
        pricing_error=None,
        hop_depth=0,
        parent_transfer_id=None,
        fetched_at=_now(),
        explorer_url="https://etherscan.io/tx/0xabc",
    )
    return Case(
        case_id="UNITTEST",
        seed_address="0x0cdC902f4448b51289398261DB41E8ADC99bE955",
        chain=Chain.ethereum,
        incident_time=_now(),
        transfers=[transfer],
        exchange_endpoints=[ExchangeEndpoint(
            address="0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
            exchange="MEXC",
            label_name="MEXC Deposit",
            transfer_ids=["ethereum:0xabc:0"],
            total_received_usd=Decimal("3000"),
            first_deposit_at=_now(),
            last_deposit_at=_now(),
        )],
        total_usd_out=Decimal("3000"),
        trace_started_at=_now(),
        trace_completed_at=_now(),
    )


class TestCaseStore:
    def test_write_then_read_round_trips(self, tmp_path: Path) -> None:
        store = CaseStore(RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path))))
        case = _sample_case()
        store.write_case(case)
        rebuilt = store.read_case("UNITTEST")
        assert rebuilt.case_id == "UNITTEST"
        assert len(rebuilt.transfers) == 1
        assert rebuilt.transfers[0].usd_value_at_tx == Decimal("3000.00")
        assert rebuilt.exchange_endpoints[0].exchange == "MEXC"

    def test_writes_manifest_and_csv(self, tmp_path: Path) -> None:
        store = CaseStore(RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path))))
        case = _sample_case()
        store.write_case(case)
        case_dir = tmp_path / "cases" / "UNITTEST"
        assert (case_dir / "case.json").exists()
        assert (case_dir / "manifest.json").exists()
        assert (case_dir / "transfers.csv").exists()

        # Confirm CSV has expected columns and data
        with (case_dir / "transfers.csv").open() as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["to_exchange"] == "MEXC"
        assert rows[0]["token_symbol"] == "ETH"
        assert rows[0]["usd_value_at_tx"] == "3000.00"
