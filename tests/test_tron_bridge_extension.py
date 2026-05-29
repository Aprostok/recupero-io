"""Schema + integrity tests for the Tron bridge extension seed.

The extension JSON (bridges_tron_extension.json) is a HOLD-OUT file
not yet merged into bridges.json — it stages 6-8 Tron-side canonical
bridges that the audit identified as missing seeds. These tests pin
schema integrity so a malformed entry would never silently land in
the merge wave.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

# Tron base58: T + 33 chars from base58 alphabet (no 0, O, I, l).
TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")

# Schema fields every entry MUST have (matches bridges.json schema).
REQUIRED_FIELDS = {
    "address",
    "name",
    "category",
    "source",
    "confidence",
    "supports_to_chains",
    "follow_up_url",
    "notes",
    "added_at",
    "chain",
}


@pytest.fixture(scope="module")
def extension_data() -> dict:
    """Load the extension seed file once per test module."""
    path = Path(__file__).resolve().parent.parent / (
        "src/recupero/labels/seeds/bridges_tron_extension.json"
    )
    assert path.exists(), f"extension seed not found at {path}"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_json_parses_cleanly(extension_data):
    """File must be valid JSON (this test is implicit in the fixture
    but pinned explicitly so a regression in JSON parsing fails
    with a clear test name)."""
    assert isinstance(extension_data, dict)


def test_top_level_metadata_present(extension_data):
    """The file has the meta-fields documenting its hold-out status."""
    assert "__schema_note__" in extension_data
    assert "__merge_target__" in extension_data
    assert extension_data["__merge_target__"] == (
        "src/recupero/labels/seeds/bridges.json"
    )
    assert "__wave__" in extension_data
    assert "entries" in extension_data
    assert isinstance(extension_data["entries"], list)


def test_entries_count_at_least_six(extension_data):
    """The audit asks for 6-8 entries; pin >= 6."""
    n = len(extension_data["entries"])
    assert n >= 6, f"need at least 6 Tron bridge entries; got {n}"
    assert n <= 12, (
        f"sanity ceiling 12; got {n} — if you intentionally added more, "
        "raise this cap"
    )


def test_every_entry_chain_is_tron(extension_data):
    """All entries must be on Tron (this file is the Tron extension)."""
    for entry in extension_data["entries"]:
        assert entry.get("chain") == "tron", (
            f"non-Tron entry in tron extension: {entry.get('name')!r} "
            f"chain={entry.get('chain')!r}"
        )


def test_every_entry_address_matches_tron_pattern(extension_data):
    """Tron addresses are T + 33 base58 chars."""
    for entry in extension_data["entries"]:
        addr = entry.get("address", "")
        assert TRON_ADDR_RE.match(addr), (
            f"address {addr!r} does not match Tron base58 pattern "
            f"(entry name={entry.get('name')!r})"
        )


def test_every_entry_has_required_schema_fields(extension_data):
    """Schema parity with bridges.json: each entry has every required field."""
    for entry in extension_data["entries"]:
        missing = REQUIRED_FIELDS - set(entry.keys())
        assert not missing, (
            f"entry {entry.get('name')!r} missing fields: {missing}"
        )


def test_every_entry_category_is_bridge(extension_data):
    """All entries are bridges (this is the bridge extension)."""
    for entry in extension_data["entries"]:
        assert entry["category"] == "bridge", (
            f"entry {entry.get('name')!r} has category "
            f"{entry.get('category')!r}, expected 'bridge'"
        )


def test_entries_have_verified_flag(extension_data):
    """Each entry MUST carry a 'verified' boolean (per spec) so the
    operator review queue can distinguish placeholder addresses from
    fully-confirmed ones."""
    for entry in extension_data["entries"]:
        assert "verified" in entry, (
            f"entry {entry.get('name')!r} missing 'verified' flag"
        )
        assert isinstance(entry["verified"], bool)


def test_unverified_entries_have_low_or_medium_confidence(extension_data):
    """An unverified placeholder must NOT be labeled high-confidence —
    that would defeat the operator-review safety property."""
    for entry in extension_data["entries"]:
        if entry["verified"] is False:
            assert entry["confidence"] in {"low", "medium"}, (
                f"unverified entry {entry.get('name')!r} has "
                f"confidence={entry.get('confidence')!r}; must be "
                "low/medium"
            )


def test_addresses_are_unique(extension_data):
    """Two entries cannot share the same address."""
    addrs = [e["address"] for e in extension_data["entries"]]
    assert len(addrs) == len(set(addrs)), (
        f"duplicate addresses in extension: "
        f"{[a for a in addrs if addrs.count(a) > 1]}"
    )


def test_source_field_marks_audit_origin(extension_data):
    """Every entry's source string mentions the audit origin so we
    can grep the seed history."""
    for entry in extension_data["entries"]:
        src = entry.get("source", "")
        assert "v0_32_1_adversary" in src or "manual" in src, (
            f"entry {entry.get('name')!r} source {src!r} does not "
            "document audit origin"
        )
