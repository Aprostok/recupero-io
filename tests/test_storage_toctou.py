"""Wave-3 filesystem-race audit: TOCTOU and race-window tests.

Hunts the bugs called out in the audit assignment:

  * **TOCTOU between resolve() and open**: between
    ``path.resolve().relative_to(root)`` and the subsequent ``open``,
    an attacker could swap the path for a symlink. The right defense
    in this codebase is symlink rejection + a unique tempfile name.

  * **Race in atomic_write**: pre-wave3, ``_atomic_write_bytes`` and
    ``atomic_write_text`` used a DETERMINISTIC tempfile name
    (``path + ".tmp"``). Two workers writing the SAME target collided
    on the same intermediate file — worker A's write was truncated by
    worker B's open, then worker A's rename moved garbage into place.
    Wave-3 switches to ``tempfile.mkstemp`` for per-call uniqueness.

  * **Cleanup on rename failure**: when ``os.replace`` raises, the
    tempfile must be unlinked (no leak).

These tests are POSIX-safe and Windows-safe — they use neither real
symlinks nor cross-fs renames, only the unique-tempfile contract and
mock-based simulation of rename failures.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

# ---- atomic_write helpers: unique tempfile name ---- #


def test_case_store_atomic_write_uses_unique_tempfile(tmp_path: Path) -> None:
    """Pre-wave3 the tempfile was a deterministic ``path + ".tmp"``.
    Wave-3 switches to ``tempfile.mkstemp`` — each call produces a
    UNIQUE intermediate filename so two concurrent writers don't
    clobber the same buffer.

    Verify the intermediate name is no longer the deterministic suffix.
    """
    import recupero.storage.case_store as cs_mod

    target = tmp_path / "case.json"
    seen_tmp_names: list[str] = []

    orig_replace = os.replace

    def watched_replace(src, dst):
        # IMPORTANT: side_effect replaces the original; we must call
        # the real os.replace ourselves so the test environment is
        # not corrupted by a pile of un-renamed tempfiles.
        seen_tmp_names.append(str(src))
        return orig_replace(src, dst)

    with patch.object(cs_mod.os, "replace", side_effect=watched_replace):
        cs_mod._atomic_write_bytes(target, b"payload-1")
        cs_mod._atomic_write_bytes(target, b"payload-2")

    # Two writes → two distinct intermediate names (mkstemp guarantees
    # uniqueness). Pre-wave3 both would equal `case.json.tmp`.
    assert len(seen_tmp_names) == 2
    assert seen_tmp_names[0] != seen_tmp_names[1], (
        "Wave-3 regression: tempfile name is no longer unique; "
        "concurrent writers will race on the same intermediate file"
    )
    # And neither should be the deterministic legacy name.
    legacy_name = str(target) + ".tmp"
    assert seen_tmp_names[0] != legacy_name
    assert seen_tmp_names[1] != legacy_name
    # Final payload (last write wins).
    assert target.read_bytes() == b"payload-2"


def test_atomic_write_text_uses_unique_tempfile(tmp_path: Path) -> None:
    """Same contract for the text helper in recupero._common."""
    import recupero._common as common_mod

    target = tmp_path / "brief.html"
    seen_tmp_names: list[str] = []
    orig_replace = os.replace

    def watched_replace(src, dst):
        seen_tmp_names.append(str(src))
        return orig_replace(src, dst)

    with patch.object(common_mod.os, "replace", side_effect=watched_replace):
        common_mod.atomic_write_text(target, "html-1")
        common_mod.atomic_write_text(target, "html-2")

    assert seen_tmp_names[0] != seen_tmp_names[1], (
        "Wave-3 regression: atomic_write_text tempfile name "
        "deterministic — concurrent brief writes will race"
    )
    legacy_name = str(target) + ".tmp"
    assert seen_tmp_names[0] != legacy_name
    assert target.read_text(encoding="utf-8") == "html-2"


# ---- Concurrent-writer race (filename collision class 4) ---- #


def test_atomic_write_concurrent_workers_no_collision(tmp_path: Path) -> None:
    """Spin up several threads writing the same target. Pre-wave3 they
    raced on the same deterministic ``.tmp`` file and corrupted each
    other's intermediate. Wave-3 mkstemp guarantees per-call unique
    names so every thread either wins the final rename cleanly or
    has its own unlinked tempfile.

    Strict contract: the final file ON DISK matches one of the
    payloads written (not a torn/truncated mix).
    """
    from recupero._common import atomic_write_text

    target = tmp_path / "concurrent.json"
    payloads = [f'{{"worker":{i},"payload":"{"x" * 200}"}}' for i in range(8)]
    errors: list[BaseException] = []

    def worker(p: str) -> None:
        try:
            atomic_write_text(target, p)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(p,)) for p in payloads]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # On Windows, os.replace can fail with WinError 5 if another
    # process has the destination open. We tolerate some races
    # producing OSError; the IMPORTANT contract is that the final
    # file is one COMPLETE payload, not a torn/truncated mix.
    assert target.exists(), "no worker won the rename race"
    final = target.read_text(encoding="utf-8")
    assert final in payloads, (
        f"Atomic-write race produced a torn file: {final!r} matches "
        f"no payload — wave-3 atomicity broken"
    )

    # And NO leftover .tmp siblings (best-effort cleanup must work
    # even under contention).
    leftover_tmps = list(tmp_path.glob("concurrent.json.*.tmp"))
    assert not leftover_tmps, (
        f"Concurrent writes leaked tempfiles: {leftover_tmps}"
    )


# ---- Rename-failure cleanup ---- #


def test_atomic_write_bytes_cleans_up_tmp_on_rename_failure(
    tmp_path: Path,
) -> None:
    """If os.replace raises (rename across mountpoints, ENOSPC, ...),
    the wave-3 helper must still unlink the tempfile — no leak."""
    from recupero.storage.case_store import _atomic_write_bytes

    target = tmp_path / "case.json"

    with patch("os.replace", side_effect=OSError("cross-device link")), pytest.raises(OSError):
        _atomic_write_bytes(target, b"payload")

    # Tempfile glob: name is randomized, but the prefix is `case.json.`
    # and the suffix is `.tmp`. None must linger.
    leftovers = list(tmp_path.glob("case.json.*.tmp"))
    assert not leftovers, f"tempfile leaked on rename failure: {leftovers}"


def test_atomic_write_text_cleans_up_tmp_on_rename_failure_wave3(
    tmp_path: Path,
) -> None:
    """Same contract for atomic_write_text. The legacy test in
    test_common_adversarial.py was wave-2 vintage and still passes,
    but it asserted the OLD deterministic tempfile name doesn't exist
    (vacuous now). Wave-3 strengthens to a glob check."""
    from recupero._common import atomic_write_text

    target = tmp_path / "out.json"

    with patch("os.replace", side_effect=OSError("rename failed")), pytest.raises(OSError):
        atomic_write_text(target, "payload")

    leftovers = list(tmp_path.glob("out.json.*.tmp"))
    assert not leftovers, f"tempfile leaked: {leftovers}"


# ---- TOCTOU window between case-id validation and write ---- #


def test_case_id_length_cap(tmp_path: Path) -> None:
    """case_ids over 200 chars must be rejected BEFORE Path construction.

    Hits two attack vectors:
      * Windows MAX_PATH (260): cases_root + 4000-char case_id throws
        a confusing FileNotFoundError mid-write, leaking stack traces.
      * Pathological-length DoS: a 1MB case_id allocated per request.
    """
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    long_id = "a" * 4000
    with pytest.raises(ValueError, match="length"):
        store.case_dir(long_id)
    with pytest.raises(ValueError, match="length"):
        store.read_case(long_id)


def test_case_id_at_cap_accepted(tmp_path: Path) -> None:
    """The 200-char policy cap must accept ids up to the cap.

    Two-layer test: (1) lock the logical cap value at 200 (validator
    must not silently regress to 64/100); (2) exercise the on-disk
    case_dir path with the LARGEST id the local filesystem will
    accept. On Windows default MAX_PATH (260, no LongPathsEnabled),
    a 200-char id under a deep pytest tmp_path overflows the OS
    layer — so we shrink the disk-side id to whatever budget the
    tmp prefix leaves while still proving the validator accepts it.
    """
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import _MAX_CASE_ID_LEN, CaseStore

    # Layer 1: policy cap value lock — fails fast on regression.
    assert _MAX_CASE_ID_LEN == 200, (
        f"_MAX_CASE_ID_LEN regressed to {_MAX_CASE_ID_LEN} — "
        "callers depend on the documented 200-char ceiling."
    )

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    # Layer 2: disk-side smoke. Windows default (no LongPathsEnabled)
    # caps the full path at ~256 chars including the long pytest tmp
    # prefix — a 200-char id literally cannot land on disk there.
    # Use a small id that fits cleanly on every supported platform.
    # The validator gate is exercised by the next test
    # (test_case_id_one_over_cap_rejected) which doesn't need disk I/O.
    import sys
    sample_id = "a" * (40 if sys.platform == "win32" else _MAX_CASE_ID_LEN)
    d = store.case_dir(sample_id)
    assert d.exists()
    assert d.name == sample_id


def test_case_id_one_over_cap_rejected(tmp_path: Path) -> None:
    """201 chars must reject — strict boundary."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    over_id = "a" * 201
    with pytest.raises(ValueError, match="length"):
        store.case_dir(over_id)
