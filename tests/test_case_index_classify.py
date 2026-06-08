"""Real-investigation vs dev/test/validation-fixture classification (v0.39).

The operator Case-Index console hides test/validation fixtures by default so it
shows only real cases. These pin the pure classifier + the local victim.json
reader so the heuristic stays conservative (a genuine victim name is NEVER
hidden) and the markers that DO hide are explicit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recupero.api.case_index_api import (
    _read_victim_name_local,
    classify_is_test,
)


@pytest.mark.parametrize("name", [
    "Sky Mavis / Ronin Network",
    "Acme Trading Ltd",
    "Jane Doe",
    "Bittrex Global GmbH",
    "Smokehouse Holdings",      # 'smoke' without a word boundary → real
    "Contestant Capital",       # 'test' mid-word, no boundary → real
    "Greatest Recoveries LLC",  # 'test' mid-word, no boundary → real
])
def test_real_victim_names_are_not_test(name: str) -> None:
    is_test, reason = classify_is_test(name, has_victim_json=True)
    assert is_test is False, f"{name!r} wrongly flagged test ({reason})"
    assert reason == ""


@pytest.mark.parametrize("name", [
    "TEST CFI-00265 Validation",
    "test case alpha",
    "Form Test Case",
    "Phase 2 baseline run",
    "Phase 10 smoke",
    "Zigha reachability Validation",
    "(no victim)",
    "regression fixture",
    "sample case 4",
    "demo case for screenshots",
])
def test_fixture_victim_names_are_test(name: str) -> None:
    is_test, reason = classify_is_test(name, has_victim_json=True)
    assert is_test is True, f"{name!r} should be flagged a fixture"
    assert reason


def test_missing_or_blank_victim_is_test() -> None:
    is_test, reason = classify_is_test(None, has_victim_json=False)
    assert is_test is True and "no victim" in reason
    is_test, reason = classify_is_test("   ", has_victim_json=True)
    assert is_test is True and "empty" in reason
    is_test, reason = classify_is_test(None, has_victim_json=True)
    assert is_test is True and "empty" in reason


def test_read_victim_name_local(tmp_path: Path) -> None:
    # absent → (False, None)
    assert _read_victim_name_local(tmp_path) == (False, None)
    # present with a real name
    (tmp_path / "victim.json").write_text(
        json.dumps({"name": "Sky Mavis / Ronin Network"}), encoding="utf-8"
    )
    assert _read_victim_name_local(tmp_path) == (True, "Sky Mavis / Ronin Network")


def test_read_victim_name_local_malformed_is_present_but_nameless(tmp_path: Path) -> None:
    # A present-but-unreadable victim.json → (True, None): the case is NOT
    # silently hidden on a parse error (classify treats blank name as test, but
    # the file being present is recorded).
    (tmp_path / "victim.json").write_text("{not json", encoding="utf-8")
    has_v, name = _read_victim_name_local(tmp_path)
    assert has_v is True and name is None
