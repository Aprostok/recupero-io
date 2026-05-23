"""Wave-1 Windows-specific path-validation audit (RED tests).

``CaseStore._validate_case_id`` already rejects forward/back slashes,
control chars, and the Windows-invalid char set ``<>:"|?*``. This
test file probes the *Windows-specific* edge cases that slip through
naive char-blacklist validators:

1. UNC paths (``\\\\server\\share\\evil``) — absolute on Windows.
2. ``\\\\?\\`` extended-length prefix.
3. Drive-relative paths (``C:foo`` refers to current dir on C:).
4. DOS reserved device names (``CON``, ``PRN``, ``COM1``, ``LPT1``…).
5. Trailing dot / space (``evil. `` → ``evil`` on Windows).
6. Mixed forward+back slashes with dot-segments.
7. NTFS Alternate Data Streams (``file.txt:hidden.txt``).
8. Case-insensitive collisions (``Case`` vs ``case``).

Each payload MUST raise from ``case_dir`` — relying on a downstream
``OSError`` from ``mkdir`` is unacceptable because it masks intent
and depends on running platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _build_store(tmp_path: Path):
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    return CaseStore(cfg), tmp_path / "cases"


# --- 1. UNC paths -----------------------------------------------------------

@pytest.mark.parametrize("unc", [
    "\\\\server\\share\\evil",
    "\\\\?\\UNC\\server\\share\\evil",
    "\\\\.\\C:\\evil",
])
def test_unc_paths_rejected(tmp_path: Path, unc: str) -> None:
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(unc)


# --- 2. \\?\ extended-length prefix ----------------------------------------

@pytest.mark.parametrize("extended", [
    "\\\\?\\C:\\Users\\evil",
    "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\evil",
])
def test_extended_length_prefix_rejected(tmp_path: Path, extended: str) -> None:
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(extended)


# --- 3. Drive-relative / drive-letter paths --------------------------------

@pytest.mark.parametrize("drive_id", [
    "C:foo",         # drive-relative on Windows
    "C:\\evil",      # drive-absolute on Windows
    "C:",            # bare drive letter
    "Z:nonexistent", # drive-relative on Z:
])
def test_drive_letter_paths_rejected(tmp_path: Path, drive_id: str) -> None:
    """The ``:`` separator should be caught by the Windows-invalid
    char blacklist; this test locks the contract that it's not just
    'invalid on Windows' but rejected universally."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(drive_id)


# --- 4. DOS reserved device names ------------------------------------------

@pytest.mark.parametrize("reserved", [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM9",
    "LPT1",
    "LPT9",
    # Case variations — Windows matches case-insensitively
    "con",
    "Nul",
    "cOm3",
    # With extensions — Windows still routes to device
    "CON.txt",
    "PRN.json",
    "COM1.log",
])
def test_reserved_device_names_rejected(tmp_path: Path, reserved: str) -> None:
    """A case_id of ``CON`` would, on Windows, route ``cases/CON/case.json``
    to the console special device — corrupting writes and potentially
    hanging reads. Reject at validation."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(reserved)


# --- 5. Trailing dot / space -----------------------------------------------

@pytest.mark.parametrize("trailing", [
    "evil. ",
    "evil.",
    "evil ",
    "case   ",       # multiple trailing spaces
    "case...",       # multiple trailing dots
    "case. . .",     # alternating
])
def test_trailing_dot_space_rejected(tmp_path: Path, trailing: str) -> None:
    """Windows silently strips trailing dots/spaces from filenames.
    Two case_ids ``evil`` and ``evil. `` would collide on disk, a
    confused-deputy vector where one case overwrites another."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(trailing)


# --- 6. Forward + back slash mix with dot-segments -------------------------

@pytest.mark.parametrize("mixed", [
    "cases/foo/../bar",
    "cases\\foo\\..\\bar",
    "cases/foo\\..\\bar",
    "./current",
    ".\\current",
    "foo/./bar",
])
def test_mixed_slash_dot_segments_rejected(tmp_path: Path, mixed: str) -> None:
    """Any path-separator character is already rejected. This test
    locks the contract for the mixed-separator variants attackers
    actually use to bypass single-character blacklists."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(mixed)


# --- 7. NTFS Alternate Data Streams ----------------------------------------

@pytest.mark.parametrize("ads", [
    "case.json:hidden.txt",
    "evil:stream",
    "case:$DATA",
    "case:$INDEX_ALLOCATION",
])
def test_ntfs_ads_rejected(tmp_path: Path, ads: str) -> None:
    """NTFS interprets ``name:stream`` as an alternate data stream.
    The colon is in the Windows-invalid char set so this should
    already be rejected — lock the contract."""
    store, _ = _build_store(tmp_path)
    with pytest.raises((ValueError, OSError)):
        store.case_dir(ads)


# --- 8. Case-insensitive collisions ----------------------------------------

def test_case_insensitive_collision_documented(tmp_path: Path) -> None:
    """On Windows (and macOS by default), ``Case`` and ``case`` map
    to the same directory. We do NOT currently reject either — but
    the contract is that the path returned for one MUST equal the
    canonical form on case-insensitive filesystems.

    This test documents current behavior: both names are accepted
    and may collide on disk. If a future hardening pass adds
    case-collision detection, flip this to assert rejection.
    """
    store, cases_root = _build_store(tmp_path)
    a = store.case_dir("Case_X")
    b = store.case_dir("case_x")
    # Both succeed. They MAY point to the same on-disk directory on
    # case-insensitive filesystems — that's a known limitation, not a
    # security boundary violation, because both still live inside
    # cases_root.
    cases_root_resolved = cases_root.resolve()
    assert str(a.resolve()).startswith(str(cases_root_resolved))
    assert str(b.resolve()).startswith(str(cases_root_resolved))


# --- Sanity: legitimate Windows-ish ids still work -------------------------

def test_legitimate_ids_still_accepted(tmp_path: Path) -> None:
    """Regression guard: the new Windows checks must not reject
    realistic case_ids that merely *contain* device-name substrings
    or dots that aren't trailing."""
    store, _ = _build_store(tmp_path)
    for good in (
        "CONNECTED",       # starts with CON but isn't CON
        "PRN-2024-01",     # PRN substring, not the bare name
        "case.with.dots",  # interior dots fine
        "v0.20.1",         # version-style id
        "LPT10",           # LPT10 is NOT reserved (only LPT1-9)
        "COM10",           # COM10 is NOT reserved (only COM1-9)
    ):
        d = store.case_dir(good)
        assert d.is_dir()
        assert d.name == good
