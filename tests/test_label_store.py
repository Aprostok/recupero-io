"""LabelStore tests — verifies seed lists load and lookup is case-insensitive."""

from __future__ import annotations

import json
from pathlib import Path

from recupero.config import RecuperoConfig, StorageParams
from recupero.labels.store import LabelStore
from recupero.models import Chain, LabelCategory


def _config(tmp_path: Path) -> RecuperoConfig:
    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    return cfg


class TestLabelStore:
    def test_loads_seed_lists(self, tmp_path: Path) -> None:
        store = LabelStore.load(_config(tmp_path))
        # MEXC Zigha-observed deposit must be present in seed list
        label = store.lookup("0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d", Chain.ethereum)
        assert label is not None
        assert label.exchange == "MEXC"
        assert label.category == LabelCategory.exchange_deposit

    def test_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        store = LabelStore.load(_config(tmp_path))
        upper = store.lookup("0xEEADD1F663E5CD8CDB2102D42756168762457B9D", Chain.ethereum)
        lower = store.lookup("0xeeadd1f663e5cd8cdb2102d42756168762457b9d", Chain.ethereum)
        assert upper is not None
        assert lower is not None
        assert upper.address == lower.address

    def test_lookup_unknown_returns_none(self, tmp_path: Path) -> None:
        store = LabelStore.load(_config(tmp_path))
        assert store.lookup("0x0000000000000000000000000000000000000001", Chain.ethereum) is None

    def test_local_overrides_apply(self, tmp_path: Path) -> None:
        local_dir = tmp_path / "labels"
        local_dir.mkdir(parents=True)
        custom = [{
            "address": "0x0000000000000000000000000000000000000042",
            "name": "Custom Test Address",
            "category": "perpetrator",
            "source": "test",
            "confidence": "high",
            "added_at": "2025-01-01T00:00:00Z",
        }]
        (local_dir / "local_test.json").write_text(json.dumps(custom))

        store = LabelStore.load(_config(tmp_path))
        label = store.lookup("0x0000000000000000000000000000000000000042", Chain.ethereum)
        assert label is not None
        assert label.category == LabelCategory.perpetrator

    def test_invalid_address_lookup_returns_none(self, tmp_path: Path) -> None:
        store = LabelStore.load(_config(tmp_path))
        assert store.lookup("not-an-address", Chain.ethereum) is None
