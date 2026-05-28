"""v0.31.2 (Gap #5): point-in-time label resolution.

Labels reflect TODAY. A wallet labeled "exchange deposit" today wasn't
necessarily one six months ago when the theft happened, so briefs
grounded in today's labels can mislabel historical state.

This test pins down the new opt-in semantics:

* Existing labels (no ``valid_from`` / ``valid_until``) keep the
  "labeled forever from ``added_at``" behavior every existing caller
  relied on.
* New labels can declare a validity window; lookups can pass
  ``point_in_time`` to filter labels whose window covers that moment.
* Pydantic rejects forensically-broken windows where ``valid_until``
  closes before ``valid_from`` opens — a seed author who swapped the
  dates would otherwise produce a label that never matches any lookup.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from recupero.config import RecuperoConfig, StorageParams
from recupero.labels.store import LabelStore
from recupero.models import Chain, Label, LabelCategory


def _config(tmp_path: Path) -> RecuperoConfig:
    return RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))


def _write_local_labels(tmp_path: Path, entries: list[dict]) -> None:
    local_dir = tmp_path / "labels"
    local_dir.mkdir(parents=True, exist_ok=True)
    (local_dir / "local_pit_test.json").write_text(json.dumps(entries))


class TestPointInTimeWindow:
    """A label with an explicit ``valid_from`` + ``valid_until`` window."""

    # Address picked from the EVM zero-prefix space so it won't collide
    # with any real seed-list entry.
    ADDR = "0x00000000000000000000000000000000000000A1"

    @pytest.fixture()
    def store(self, tmp_path: Path) -> LabelStore:
        _write_local_labels(tmp_path, [{
            "address": self.ADDR,
            "name": "Exchange Deposit With Window",
            "category": "exchange_deposit",
            "source": "test-pit",
            "confidence": "high",
            "added_at": "2024-01-01T00:00:00Z",
            "valid_from": "2024-06-01T00:00:00Z",
            "valid_until": "2024-12-31T23:59:59Z",
        }])
        return LabelStore.load(_config(tmp_path))

    def test_before_valid_from_returns_none(self, store: LabelStore) -> None:
        # 2024-03-01 is after added_at (2024-01-01) but BEFORE valid_from
        # (2024-06-01). The label hasn't "turned on" yet — must be None.
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2024, 3, 1, tzinfo=UTC),
        )
        assert result is None

    def test_inside_window_returns_label(self, store: LabelStore) -> None:
        # 2024-08-01 sits inside [2024-06-01, 2024-12-31] → label active.
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2024, 8, 1, tzinfo=UTC),
        )
        assert result is not None
        assert result.category == LabelCategory.exchange_deposit
        assert result.name == "Exchange Deposit With Window"

    def test_after_valid_until_returns_none(self, store: LabelStore) -> None:
        # 2025-03-01 is after valid_until (2024-12-31) → expired.
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2025, 3, 1, tzinfo=UTC),
        )
        assert result is None

    def test_no_point_in_time_returns_label(self, store: LabelStore) -> None:
        # Existing callers passing no point_in_time get the current-
        # state default: the label is returned regardless of window.
        # This is the backward-compat guarantee for the entire
        # codebase (15+ existing call sites).
        result = store.lookup(self.ADDR, Chain.ethereum)
        assert result is not None
        assert result.name == "Exchange Deposit With Window"


class TestNoValidityWindow:
    """A label WITHOUT validity window — pre-v0.31.2 schema."""

    ADDR = "0x00000000000000000000000000000000000000B2"

    @pytest.fixture()
    def store(self, tmp_path: Path) -> LabelStore:
        # Note: no valid_from / valid_until → preserves "labeled forever
        # from added_at" semantics. This is what every seed file
        # committed before v0.31.2 looks like.
        _write_local_labels(tmp_path, [{
            "address": self.ADDR,
            "name": "Plain Old Label",
            "category": "exchange_hot_wallet",
            "source": "test-no-window",
            "confidence": "medium",
            "added_at": "2024-01-01T00:00:00Z",
        }])
        return LabelStore.load(_config(tmp_path))

    def test_before_added_at_returns_none(self, store: LabelStore) -> None:
        # 2023-06-01 is BEFORE added_at (2024-01-01). Even without a
        # validity window we should still respect "the label didn't
        # exist yet". Otherwise a 2026-curated label would silently
        # back-stamp onto 2023 transfers.
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2023, 6, 1, tzinfo=UTC),
        )
        assert result is None

    def test_after_added_at_returns_label(self, store: LabelStore) -> None:
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2024, 6, 1, tzinfo=UTC),
        )
        assert result is not None
        assert result.name == "Plain Old Label"

    def test_far_future_returns_label(self, store: LabelStore) -> None:
        # No valid_until → no expiration. 2099 still resolves.
        result = store.lookup(
            self.ADDR, Chain.ethereum,
            point_in_time=datetime(2099, 1, 1, tzinfo=UTC),
        )
        assert result is not None
        assert result.name == "Plain Old Label"


class TestPydanticValidation:
    """The Label model itself rejects broken validity windows."""

    def test_valid_until_before_valid_from_is_rejected(self) -> None:
        # valid_until 2024-01-01 BEFORE valid_from 2024-12-31 — author
        # almost certainly swapped the dates. Silently accepting it
        # would produce a label that never matches any point_in_time
        # lookup, which is forensically worse than crashing the load.
        with pytest.raises(ValidationError):
            Label(
                address="0x00000000000000000000000000000000000000c3",
                name="Broken Window",
                category=LabelCategory.exchange_hot_wallet,
                source="test-broken",
                confidence="low",
                added_at=datetime(2023, 1, 1, tzinfo=UTC),
                valid_from=datetime(2024, 12, 31, tzinfo=UTC),
                valid_until=datetime(2024, 1, 1, tzinfo=UTC),
            )

    def test_equal_endpoints_are_accepted(self) -> None:
        # A single-instant validity window (valid_from == valid_until)
        # is degenerate but not forensically broken — accept it. Useful
        # for "label was true on exactly this snapshot timestamp".
        same = datetime(2024, 6, 1, tzinfo=UTC)
        label = Label(
            address="0x00000000000000000000000000000000000000d4",
            name="Instant Window",
            category=LabelCategory.exchange_hot_wallet,
            source="test-instant",
            confidence="low",
            added_at=datetime(2024, 1, 1, tzinfo=UTC),
            valid_from=same,
            valid_until=same,
        )
        assert label.valid_from == label.valid_until

    def test_no_validity_fields_is_valid(self) -> None:
        # Backward-compat: the existing schema (added_at only) still
        # validates. Default None on both new fields.
        label = Label(
            address="0x00000000000000000000000000000000000000e5",
            name="Legacy",
            category=LabelCategory.exchange_hot_wallet,
            source="test-legacy",
            confidence="low",
            added_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert label.valid_from is None
        assert label.valid_until is None
