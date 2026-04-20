"""Tests for v13 — recursive multi-hop tracer.

Previous behavior: tracer called fetch_*_outflows once for the seed, produced a
single-hop case. Users had to manually re-run trace on each interesting
counterparty.

New behavior: if config.trace.max_depth > 1, the tracer BFS-recursively
follows eligible destinations. Eligibility is governed by TracePolicy:
  - stop at labeled exchanges / mixers / bridges (terminal)
  - stop at contract addresses by default
  - stop at dust threshold
  - stop at max_depth
  - cycle detection via visited set
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


# All addresses padded to 40 hex chars so to_checksum_address accepts them
SEED  = "0x1111111111111111111111111111111111111111"
HOP1A = "0x2222222222222222222222222222222222222222"
HOP1B = "0x3333333333333333333333333333333333333333"
HOP2A = "0x4444444444444444444444444444444444444444"
HOP2B = "0x5555555555555555555555555555555555555555"
EXCHG = "0x6666666666666666666666666666666666666666"
CYCLE = "0x7777777777777777777777777777777777777777"
CONTRACT = "0x8888888888888888888888888888888888888888"


def _eth() -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        decimals=18, coingecko_id="ethereum",
    )


def _native_row(from_addr: str, to_addr: str, tx_hash: str, eth: str) -> dict[str, Any]:
    wei = int(Decimal(eth) * Decimal(10**18))
    return {
        "chain": Chain.ethereum,
        "tx_hash": tx_hash,
        "block_number": 19_000_000,
        "block_time": datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc),
        "log_index": None,
        "from": from_addr,
        "to": to_addr,
        "token": _eth(),
        "amount_raw": wei,
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
    }


class GraphAdapter(ChainAdapter):
    """An adapter that returns different outflows based on the from_address.

    Takes a dict mapping lowered address → list of outflow dicts, and a set
    of lowered addresses considered "contracts" (is_contract returns True).
    """
    chain = Chain.ethereum

    def __init__(self, graph: dict[str, list[dict[str, Any]]], contracts: set[str] | None = None) -> None:
        self._graph = {k.lower(): v for k, v in graph.items()}
        self._contracts = contracts or set()
        self.is_contract_calls: list[str] = []  # tracked for assertions

    def block_at_or_before(self, ts: datetime) -> int:
        return 19_000_000

    def is_contract(self, address: str) -> bool:
        self.is_contract_calls.append(address.lower())
        return address.lower() in self._contracts

    def fetch_native_outflows(self, from_address: str, start_block: int) -> list[dict[str, Any]]:
        return list(self._graph.get(from_address.lower(), []))

    def fetch_erc20_outflows(self, from_address: str, start_block: int) -> list[dict[str, Any]]:
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        return EvidenceReceipt(
            chain=Chain.ethereum, tx_hash=tx_hash, block_number=19_000_001,
            block_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            raw_transaction={"hash": tx_hash}, raw_receipt={"status": "0x1"},
            raw_block_header={"number": "0x1221b81"},
            fetched_at=datetime.now(timezone.utc),
            fetched_from="fake",
            explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"https://etherscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address: str) -> str:
        return f"https://etherscan.io/address/{address}"


class FixedPriceClient:
    """All ETH prices at $3000. Deterministic."""
    def price_at(self, token, when):
        return PriceResult(usd_value=Decimal("3000"), source="fake", error=None)
    def close(self):
        pass


@pytest.fixture
def cfg_with_depth(tmp_path: Path):
    def _make(depth: int):
        cfg = RecuperoConfig(
            trace=TraceParams(
                max_depth=depth, dust_threshold_usd=50.0, incident_buffer_minutes=60
            ),
            storage=StorageParams(data_dir=str(tmp_path)),
        )
        env = RecuperoEnv(ETHERSCAN_API_KEY="test", COINGECKO_API_KEY="test")
        return cfg, env
    return _make


def _install_adapter(monkeypatch, adapter: GraphAdapter):
    from recupero.trace import tracer as tracer_mod
    monkeypatch.setattr(
        ChainAdapter, "for_chain",
        classmethod(lambda cls, chain, bundle: adapter),
    )
    monkeypatch.setattr(tracer_mod, "CoinGeckoClient", lambda *_a, **_kw: FixedPriceClient())


class TestDepthOneBackwardCompat:
    """Regression: max_depth=1 behaves exactly like before (no recursion)."""

    def test_only_seed_is_traced(self, cfg_with_depth, tmp_path, monkeypatch):
        config, env = cfg_with_depth(1)
        adapter = GraphAdapter({
            SEED:  [_native_row(SEED, HOP1A, "0xa", "10")],  # $30K outflow to HOP1A
            HOP1A: [_native_row(HOP1A, HOP2A, "0xb", "10")], # would be followed at depth>1
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "T1"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="T1", config=config, env=env, case_dir=case_dir,
        )
        # Only one hop — only the seed→HOP1A transfer, not HOP1A→HOP2A
        assert len(case.transfers) == 1
        assert case.transfers[0].to_address.lower() == HOP1A.lower()


class TestDepthTwoRecursion:
    def test_follows_unlabeled_destinations(self, cfg_with_depth, tmp_path, monkeypatch):
        config, env = cfg_with_depth(2)
        adapter = GraphAdapter({
            SEED:  [_native_row(SEED, HOP1A, "0xa", "10")],
            HOP1A: [_native_row(HOP1A, HOP2A, "0xb", "10")],
            HOP2A: [],  # terminal (out of funds)
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "T2"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="T2", config=config, env=env, case_dir=case_dir,
        )
        # Two transfers: seed→HOP1A and HOP1A→HOP2A
        assert len(case.transfers) == 2
        dests = {t.to_address.lower() for t in case.transfers}
        assert dests == {HOP1A.lower(), HOP2A.lower()}
        # Hop depths are correctly assigned
        depths_by_dest = {t.to_address.lower(): t.hop_depth for t in case.transfers}
        assert depths_by_dest[HOP1A.lower()] == 0
        assert depths_by_dest[HOP2A.lower()] == 1

    def test_fan_out_all_followed(self, cfg_with_depth, tmp_path, monkeypatch):
        """Seed → {HOP1A, HOP1B} → each leads to HOP2. All six transfers should appear."""
        config, env = cfg_with_depth(2)
        adapter = GraphAdapter({
            SEED: [
                _native_row(SEED, HOP1A, "0xa", "10"),
                _native_row(SEED, HOP1B, "0xb", "10"),
            ],
            HOP1A: [_native_row(HOP1A, HOP2A, "0xc", "10")],
            HOP1B: [_native_row(HOP1B, HOP2B, "0xd", "10")],
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "FAN"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="FAN", config=config, env=env, case_dir=case_dir,
        )
        assert len(case.transfers) == 4


class TestCycleDetection:
    def test_cycle_not_infinite_loop(self, cfg_with_depth, tmp_path, monkeypatch):
        """SEED → CYCLE → SEED → CYCLE → ... must terminate."""
        config, env = cfg_with_depth(5)
        adapter = GraphAdapter({
            SEED:  [_native_row(SEED, CYCLE, "0xa", "10")],
            CYCLE: [_native_row(CYCLE, SEED, "0xb", "10")],  # back to SEED
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "CYC"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="CYC", config=config, env=env, case_dir=case_dir,
        )
        # Seed visited once, CYCLE visited once. The CYCLE→SEED transfer IS recorded
        # (it's real data) but the recursion doesn't re-queue SEED since it's visited.
        # So we expect 2 transfers total.
        assert len(case.transfers) == 2


class TestContractStop:
    def test_contracts_not_traversed_by_default(self, cfg_with_depth, tmp_path, monkeypatch):
        """If HOP1A is a contract, we do not follow it — even though max_depth=3."""
        config, env = cfg_with_depth(3)
        adapter = GraphAdapter({
            SEED:  [_native_row(SEED, HOP1A, "0xa", "10")],
            HOP1A: [_native_row(HOP1A, HOP2A, "0xb", "10")],  # would be traced if followed
        }, contracts={HOP1A.lower()})
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "CON"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="CON", config=config, env=env, case_dir=case_dir,
        )
        # Only seed→HOP1A recorded; HOP1A not further traced
        assert len(case.transfers) == 1
        assert case.transfers[0].to_address.lower() == HOP1A.lower()

    def test_is_contract_called_once_per_address_by_driver(self, cfg_with_depth, tmp_path, monkeypatch):
        """Driver's contract-stop check caches; two transfers to same destination
        should only trigger ONE extra is_contract call from the driver on top of
        the per-transfer calls that _trace_one_hop makes to set Counterparty.is_contract.

        Test invariant: the count for a duplicated destination is bounded — if
        both transfers triggered the driver check, we'd see 4 calls (2 from
        _trace_one_hop + 2 from driver). Caching should limit it to 3.
        """
        config, env = cfg_with_depth(3)
        adapter = GraphAdapter({
            SEED:  [
                _native_row(SEED, HOP1A, "0xa", "10"),
                _native_row(SEED, HOP1A, "0xb", "5"),  # same destination
            ],
            HOP1A: [],
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "CACHE"; case_dir.mkdir(parents=True)
        tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="CACHE", config=config, env=env, case_dir=case_dir,
        )
        hop1a_checks = [a for a in adapter.is_contract_calls if a == HOP1A.lower()]
        # 2 from _trace_one_hop (per-transfer counterparty labeling) + 1 from
        # driver's stop-at-contract check (cached for the second traversal)
        # = 3 total. If caching failed we'd see 4+.
        assert len(hop1a_checks) == 3, (
            f"is_contract called {len(hop1a_checks)}x, want 3 "
            f"(2 from _trace_one_hop, 1 from driver cache)"
        )


class TestDustAndLabelStops:
    def test_dust_transfer_not_traversed(self, cfg_with_depth, tmp_path, monkeypatch):
        """Dust transfer to HOP1A — HOP1A should not be followed even at depth=2."""
        config, env = cfg_with_depth(2)
        adapter = GraphAdapter({
            SEED:  [_native_row(SEED, HOP1A, "0xa", "0.001")],  # 0.001 ETH = $3, below $50 dust
            HOP1A: [_native_row(HOP1A, HOP2A, "0xb", "10")],   # would be traced
        })
        _install_adapter(monkeypatch, adapter)

        from recupero.trace import tracer as tracer_mod
        case_dir = tmp_path / "cases" / "DUST"; case_dir.mkdir(parents=True)
        case = tracer_mod.run_trace(
            chain=Chain.ethereum, seed_address=SEED,
            incident_time=datetime(2025, 1, 15, tzinfo=timezone.utc),
            case_id="DUST", config=config, env=env, case_dir=case_dir,
        )
        # The dust transfer is filtered out by should_include, AND we don't follow.
        # Expected: 0 transfers (dust dropped, no recursion).
        assert len(case.transfers) == 0
