"""RIGOR-Jacob W: label store survives malformed entries.

``LabelStore._load_file`` iterates over the JSON list and constructs
a Label per entry. The except clause catches ``(KeyError, ValueError)``
but NOT ``TypeError`` — so an entry that's a list/string/number
(instead of a dict) crashes the whole load on ``entry["address"]``.

Real-world scenario: a labels.json file got corrupted, or an
operator pasted a non-dict by mistake. Loading should LOG and SKIP
the bad entry, not abort the whole startup.
"""

from __future__ import annotations

import json
from pathlib import Path


def test_load_file_skips_non_dict_entry(tmp_path: Path) -> None:
    """A list of mixed-shape entries: one good dict, one list, one
    int, one string. Only the good dict should load; the bad ones
    are logged + skipped."""
    from recupero.labels.store import LabelStore

    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps([
        # Good
        {
            "address": "0x" + "a" * 40,
            "name": "GoodLabel",
            "category": "exchange_hot_wallet",
        },
        # Bad: list instead of dict
        [1, 2, 3],
        # Bad: bare string
        "not a label",
        # Bad: int
        42,
        # Bad: None
        None,
        # Good
        {
            "address": "0x" + "b" * 40,
            "name": "AnotherGood",
            "category": "mixer",
        },
    ]), encoding="utf-8")

    store = LabelStore.__new__(LabelStore)
    store._by_addr_lower = {}

    try:
        store._load_file(labels_path, source_prefix="test")
    except TypeError as e:
        raise AssertionError(
            f"LabelStore._load_file crashed on non-dict entry: {e}. "
            f"The except clause must include TypeError so bad entries "
            f"are logged + skipped instead of aborting load."
        ) from e
    # Both good entries should have loaded.
    assert len(store._by_addr_lower) == 2


def test_load_file_skips_dict_with_wrong_field_type(tmp_path: Path) -> None:
    """Address field is an int — Label construction crashes."""
    from recupero.labels.store import LabelStore

    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps([
        {
            "address": 42,  # not a string
            "name": "BadShape",
            "category": "exchange_hot_wallet",
        },
        {
            "address": "0x" + "c" * 40,
            "name": "Good",
            "category": "mixer",
        },
    ]), encoding="utf-8")

    store = LabelStore.__new__(LabelStore)
    store._by_addr_lower = {}

    try:
        store._load_file(labels_path, source_prefix="test")
    except (TypeError, AttributeError) as e:
        raise AssertionError(
            f"LabelStore crashed on int address: {e}"
        ) from e

    # The good entry should still load.
    assert len(store._by_addr_lower) >= 1


def test_load_file_valid_entries_still_work(tmp_path: Path) -> None:
    """Sanity: a clean labels.json loads normally."""
    from recupero.labels.store import LabelStore

    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps([
        {
            "address": "0x" + "a" * 40,
            "name": "Coinbase Hot",
            "category": "exchange_hot_wallet",
        },
    ]), encoding="utf-8")

    store = LabelStore.__new__(LabelStore)
    store._by_addr_lower = {}
    store._load_file(labels_path, source_prefix="test")
    assert len(store._by_addr_lower) == 1
