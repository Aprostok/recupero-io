"""Inspector tests using a fake adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
from recupero.inspect.inspector import inspect_address
from recupero.labels.store import LabelStore
from recupero.models import Chain, EvidenceReceipt


SEED = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
MEXC = "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d"


class FakeEtherscanClient:
    """Minimal stand-in for the EtherscanClient methods the inspector uses."""

    def __init__(self, normal_txs=None, contract_meta=None, balance=0):
        self._normal_txs = normal_txs or []
        self._contract_meta = contract_meta or {}
        self._balance = balance

    def get_normal_transactions(self, address, start_block=0, page=1, offset=1000):
        return list(self._normal_txs)

    def get_contract_source(self, address):
        return dict(self._contract_meta)

    def get_eth_balance(self, address, tag="latest"):
        return self._balance


class FakeAdapter(ChainAdapter):
    chain = Chain.ethereum

    def __init__(self, *, is_contract: bool, etherscan: FakeEtherscanClient):
        self._is_contract = is_contract
        self.client = etherscan

    def block_at_or_before(self, ts):
        return 0

    def is_contract(self, address):
        return self._is_contract

    def fetch_native_outflows(self, from_address, start_block):
        return []

    def fetch_erc20_outflows(self, from_address, start_block):
        return []

    def fetch_evidence_receipt(self, tx_hash):
        return EvidenceReceipt(
            chain=Chain.ethereum, tx_hash=tx_hash, block_number=0,
            block_time=datetime.now(timezone.utc),
            raw_transaction={}, raw_receipt={}, raw_block_header={},
            fetched_at=datetime.now(timezone.utc),
            fetched_from="fake", explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash):
        return f"https://etherscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address):
        return f"https://etherscan.io/address/{address}"


@pytest.fixture
def cfg(tmp_path):
    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    env = RecuperoEnv(ETHERSCAN_API_KEY="TEST")
    return cfg, env


def _tx(from_addr, to_addr, block=19000000, ts=1736942400):
    return {
        "blockNumber": str(block),
        "timeStamp": str(ts),
        "from": from_addr,
        "to": to_addr,
        "hash": f"0x{block:064x}",
        "value": "0",
        "isError": "0",
    }


class TestInspector:
    def test_eoa_with_known_label_uses_label_as_identity(self, cfg, monkeypatch):
        config, env = cfg
        fake = FakeAdapter(
            is_contract=False,
            etherscan=FakeEtherscanClient(normal_txs=[_tx(SEED, PERP)], balance=10**18),
        )
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: fake),
        )
        # Seed labels include the perpetrator? We use the default seeds (no PERP entry),
        # so manually inject one
        store = LabelStore.load(config)
        from recupero.models import Label, LabelCategory
        store.add(Label(
            address=PERP, name="Test Perpetrator", category=LabelCategory.perpetrator,
            source="test", confidence="high", added_at=datetime.now(timezone.utc),
        ))
        profile = inspect_address(
            address=PERP, chain=Chain.ethereum, config=config, env=env, label_store=store,
        )
        assert profile.is_contract is False
        assert profile.existing_label is not None
        assert profile.existing_label.name == "Test Perpetrator"
        assert profile.likely_identity == "Test Perpetrator"
        assert profile.eth_balance == Decimal("1")

    def test_verified_contract_name_used_for_identity(self, cfg, monkeypatch):
        config, env = cfg
        fake = FakeAdapter(
            is_contract=True,
            etherscan=FakeEtherscanClient(
                normal_txs=[_tx(SEED, PERP)],
                contract_meta={"ContractName": "AggregationRouterV6", "Proxy": "0"},
            ),
        )
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: fake),
        )
        profile = inspect_address(
            address="0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE",
            chain=Chain.ethereum, config=config, env=env,
        )
        assert profile.is_contract is True
        assert profile.contract_name == "AggregationRouterV6"
        assert profile.likely_identity == "AggregationRouterV6"

    def test_top_counterparty_aggregation(self, cfg, monkeypatch):
        config, env = cfg
        # 5 txs: 3 with PERP, 2 with MEXC
        txs = [
            _tx(SEED, PERP, block=100, ts=1700000000),
            _tx(SEED, PERP, block=200, ts=1700000100),
            _tx(PERP, SEED, block=300, ts=1700000200),
            _tx(SEED, MEXC, block=400, ts=1700000300),
            _tx(MEXC, SEED, block=500, ts=1700000400),
        ]
        fake = FakeAdapter(is_contract=False, etherscan=FakeEtherscanClient(normal_txs=txs))
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: fake),
        )
        profile = inspect_address(
            address=SEED, chain=Chain.ethereum, config=config, env=env,
        )
        assert len(profile.top_counterparties) == 2
        assert profile.top_counterparties[0].address == PERP
        assert profile.top_counterparties[0].tx_count == 3
        assert profile.top_counterparties[1].address == MEXC
        assert profile.top_counterparties[1].tx_count == 2
        assert profile.observed_tx_count == 5

    def test_partial_failure_returns_partial_profile(self, cfg, monkeypatch):
        """If the chain queries error, inspector still returns a profile."""
        config, env = cfg

        class BrokenClient:
            def get_normal_transactions(self, *a, **kw):
                raise RuntimeError("boom")
            def get_contract_source(self, *a, **kw):
                raise RuntimeError("boom")
            def get_eth_balance(self, *a, **kw):
                raise RuntimeError("boom")

        fake = FakeAdapter(is_contract=False, etherscan=BrokenClient())
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: fake),
        )
        profile = inspect_address(
            address=SEED, chain=Chain.ethereum, config=config, env=env,
        )
        # Did NOT crash. Got back a profile with mostly None fields.
        assert profile.address == SEED
        assert profile.observed_tx_count == 0
        assert profile.eth_balance is None

    def test_first_and_last_seen_extracted(self, cfg, monkeypatch):
        config, env = cfg
        txs = [
            _tx(SEED, PERP, block=100, ts=1700000000),
            _tx(SEED, PERP, block=500, ts=1700500000),
            _tx(SEED, MEXC, block=900, ts=1700900000),
        ]
        fake = FakeAdapter(is_contract=False, etherscan=FakeEtherscanClient(normal_txs=txs))
        monkeypatch.setattr(
            ChainAdapter, "for_chain",
            classmethod(lambda cls, chain, bundle: fake),
        )
        profile = inspect_address(
            address=SEED, chain=Chain.ethereum, config=config, env=env,
        )
        assert profile.first_seen_block == 100
        assert profile.last_seen_block == 900
