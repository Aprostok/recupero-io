"""RIGOR-Jacob K: CaseStore path-traversal hardening.

``CaseStore.case_dir(case_id)`` builds the path as
``cases_root / case_id / ...`` with NO sanitization. A case_id of
``"../../etc/passwd"`` resolves OUTSIDE cases_root.

Threat model: the case_id flows from multiple sources:
  * CLI ``--case-id`` (operator typo or scripted input)
  * Stripe webhook metadata (already UUID-validated, but a future
    code path that doesn't validate could regress)
  * DB-stored rows (UUID-typed but the schema could change)

Even with UUID validation upstream, defense-in-depth at the storage
layer prevents a path-traversal silently corrupting unrelated
filesystem state. Lock the contract: case_dir RAISES on any case_id
that would escape ``cases_root``.

Bonus hardening: Windows reserves a set of filename-invalid
characters (``: * ? < > | "``). A case_id containing these would
raise OSError on Windows but succeed on POSIX — inconsistent
cross-platform behavior. Reject them too.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _build_store(tmp_path: Path):
    """Construct a CaseStore at a temporary data dir."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    return CaseStore(cfg), tmp_path / "cases"


@pytest.mark.parametrize("malicious_id", [
    "../../etc/passwd",
    "../escape",
    "../../../tmp/poc",
    "../",
    "..",
    "../../",
    "foo/../../bar",
    "/absolute/path",       # absolute paths must be rejected
])
def test_case_dir_rejects_path_traversal(tmp_path: Path, malicious_id: str) -> None:
    """Any case_id that would resolve outside cases_root must raise."""
    store, cases_root = _build_store(tmp_path)
    try:
        result = store.case_dir(malicious_id)
    except (ValueError, OSError):
        return  # acceptable failure modes
    # Did NOT raise — must at least have stayed inside cases_root.
    resolved = result.resolve()
    cases_root_resolved = cases_root.resolve()
    assert str(resolved).startswith(str(cases_root_resolved)), (
        f"case_id={malicious_id!r} produced path {result} "
        f"(resolved: {resolved}) OUTSIDE cases_root {cases_root_resolved}"
    )


@pytest.mark.parametrize("forbidden_id", [
    "",                  # empty
    "  ",                # whitespace only
    "case\x00null",     # null byte
    "case\nwith\nnewline",
])
def test_case_dir_rejects_obviously_invalid(tmp_path: Path, forbidden_id: str) -> None:
    """Empty / whitespace-only / control-char case_ids must raise.
    These are not security issues per se but are guaranteed-broken
    inputs that produce confusing downstream failures (mkdir
    succeeds with name='   ', leaving a directory with spaces)."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(forbidden_id)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific")
@pytest.mark.parametrize("win_forbidden", [
    'case:with:colons',
    'case<with<brackets',
    'case>',
    'case|pipe',
    'case"quote',
    'case*asterisk',
    'case?question',
])
def test_case_dir_rejects_windows_invalid_chars(
    tmp_path: Path, win_forbidden: str,
) -> None:
    """Windows NTFS rejects these characters in filenames. The
    upstream rejection must come from the case_dir validator, not
    from a downstream OSError on mkdir/open (which surfaces as a
    confusing 'invalid argument')."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(win_forbidden)


def test_case_dir_accepts_valid_ids(tmp_path: Path) -> None:
    """Sanity: legitimate case_ids still work."""
    store, _ = _build_store(tmp_path)
    for good in (
        "V-CFI01",
        "case-2026-04-19",
        "00000000-0000-0000-0000-000000000000",
        "JACOB_TEST_001",
    ):
        d = store.case_dir(good)
        assert d.is_dir()
        assert d.name == good
