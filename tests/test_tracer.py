"""Tracer tests using a fake adapter and price client.

Verifies the tracer's logic in isolation from network — given known inputs,
confirms it produces the expected case structure: dust filtering, label
resolution, exchange endpoint computation, USD aggregation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams, TraceParams
from recupero.models import Chain, EvidenceReceipt, TokenRef
from recupero.pricing.coingecko import PriceResult


SEED = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
MEXC = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d"
RANDOM = "0x000000000000000000000000000000000000dEaD"


def _eth() -> TokenRef:
    return TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH", decimals=18, coingecko_id="ethereum")


class FakeAdapter(ChainAdapter):
    chain = Chain.ethereum

    def __init__(self, outflows: list[dict[str, Any]]) -> None:
        self._outflows = outflows

    def block_at_or_before(self, ts: datetime) -> int:
        return 19000000

    def is_contract(self, address: str) -> bool:
        return False

    def fetch_native_outflows(self, from_address: str, start_block: int) -> list[dict[str, Any]]:
        return list(self._outflows)

    def fetch_erc20_outflows(self, from_address: str, start_block: int) -> list[dict[str, Any]]:
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        return EvidenceReceipt(
            chain=Chain.ethereum,
            tx_hash=tx_hash,
            block_number=19000001,
            block_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            raw_transaction={"hash": tx_hash},
            raw_receipt={"status": "0x1"},
            raw_block_header={"number": "0x1221b81"},
            fetched_at=datetime.now(timezone.utc),
            fetched_from="fake",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"https://etherscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address: str) -> str:
        return f"https://etherscan.io/address/{address}"


class FixedPriceClient:
    def __init__(self, price_per_eth: Decimal = Decimal("3000")) -> None:
        self.price = price_per_eth

    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        return PriceResult(usd_value=self.price, source="fake:fixed", error=None)

    def close(self) -> None:
        pass


@pytest.fixture
def cfg(tmp_path: Path) -> tuple[RecuperoConfig, RecuperoEnv]:
    cfg = RecuperoConfig(
        trace=TraceParams(max_depth=1, dust_threshold_usd=50.0, incident_buffer_minutes=60),
        storage=StorageParams(data_dir=str(tmp_path)),
    )
    env = RecuperoEnv(ETHERSCAN_API_KEY="TEST", COINGECKO_API_KEY="TEST")
    return cfg, env


def _native_row(tx_hash: str, to_addr: str, eth_amount: str, ts: int = 1736942400) -> dict[str, Any]:
    wei = int(Decimal(eth_amount) * Decimal(10**18))
    return {
        "chain": Chain.ethereum,
        "tx_hash": tx_hash,
        "block_number": 19000001,
        "block_time": datetime.fromtimestamp(ts, tz=timezone.utc),
        "log_index": None,
        "from": SEED,
        "to": to_addr,
        "token": _eth(),
        "amount_raw": wei,
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
    }


class TestTracer:
    def test_end_to_end_with_exchange_endpoint(
        self, cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recupero.trace import tracer as tracer_mod

        config, env = cfg
        rows = [
            _native_row("0xaaa", MEXC, "10"),     # 10 ETH * $3000 = $30,000 to MEXC
            _native_row("0xbbb", RANDOM, "5"),    # 5 ETH * $3000 = $15,000 to unlabeled
            _native_row("0xccc", MEXC, "0.001"),  # 0.001 ETH * $3000 = $3 — dust, dropped
        ]

        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: FakeAdapter(rows)),
        )
        monkeypatch.setattr(tracer_mod, "CoinGeckoClient", lambda *_a, **_kw: FixedPriceClient())

        case_dir = tmp_path / "cases" / "TEST"
        case_dir.mkdir(parents=True)

        case = tracer_mod.run_trace(
            chain=Chain.ethereum,
            seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="TEST",
            config=config,
            env=env,
            case_dir=case_dir,
        )

        # Two transfers retained (dust dropped)
        assert len(case.transfers) == 2

        # MEXC endpoint surfaced
        assert len(case.exchange_endpoints) == 1
        ep = case.exchange_endpoints[0]
        assert ep.exchange == "MEXC"
        assert ep.total_received_usd == Decimal("30000")

        # Total USD includes both kept transfers
        assert case.total_usd_out == Decimal("45000")

        # Unlabeled counterparty surfaced
        assert RANDOM in case.unlabeled_counterparties

    def test_no_outflows_produces_empty_but_valid_case(
        self, cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from recupero.trace import tracer as tracer_mod

        config, env = cfg
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: FakeAdapter([])),
        )
        monkeypatch.setattr(tracer_mod, "CoinGeckoClient", lambda *_a, **_kw: FixedPriceClient())

        case_dir = tmp_path / "cases" / "EMPTY"
        case_dir.mkdir(parents=True)

        case = tracer_mod.run_trace(
            chain=Chain.ethereum,
            seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="EMPTY",
            config=config,
            env=env,
            case_dir=case_dir,
        )

        assert case.transfers == []
        assert case.exchange_endpoints == []
        assert case.total_usd_out is None
        assert case.trace_completed_at is not None
