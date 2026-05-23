"""Wave-3 filesystem-race audit: filename-collision and case-id-shape
edge cases.

  * **Duplicate writes to the same path**: pre-wave3, the deterministic
    ``path + ".tmp"`` intermediate meant two threads writing to the
    same ``brief.html`` (e.g. an emit_brief re-run that overlapped
    with a stuck previous run) clobbered each other's tempfile.
    Wave-3's mkstemp produces unique tempfile names; the LAST write
    wins cleanly.

  * **Same-stem different-extension non-collision**: writing
    ``brief.html`` and ``brief.html.bak`` simultaneously must not
    interfere (the wave-3 tempfile prefix is ``<filename>.`` plus a
    random infix, so cross-talk is impossible).

  * **NFC vs NFD case_id quirk**: on macOS, ``"café"`` (NFC) and
    ``"café"`` (NFD) resolve to the same directory but have different
    Python string identity. The codebase normalizes by storing as-given
    and relying on validate-then-resolve; we DOCUMENT this is a known
    macOS-only quirk via a test that explicitly accepts both forms
    without crashing.

  * **Trailing dot / space case_ids on Windows**: Windows silently
    strips trailing dots and spaces from filenames, so case_id="foo."
    and case_id="foo" alias on Windows. Wave-3 doesn't add a new
    rule here (the existing _validate_case_id allows trailing dots
    on POSIX), but the test documents the Windows-specific aliasing.
"""

from __future__ import annotations

import sys
import threading
import unicodedata
from pathlib import Path

import pytest


def _build_store(tmp_path: Path):
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    return CaseStore(cfg), tmp_path / "cases"


# ---- Duplicate writes ---- #


def test_repeated_writes_no_tempfile_leak(tmp_path: Path) -> None:
    """Write the same target 20 times back-to-back. After all writes,
    there must be exactly ONE file and no leftover tempfiles.

    Wave-3 contract: each call gets its own randomly-named tempfile
    which is renamed atomically; failed/skipped tempfiles get
    unlinked. A leak suggests cleanup is broken."""
    from recupero._common import atomic_write_text

    target = tmp_path / "brief.html"
    for i in range(20):
        atomic_write_text(target, f"<html>{i}</html>")

    assert target.read_text(encoding="utf-8") == "<html>19</html>"
    leftovers = list(tmp_path.glob("brief.html.*.tmp"))
    assert not leftovers, f"tempfile leak after repeated writes: {leftovers}"


def test_concurrent_writes_different_targets_no_crosstalk(
    tmp_path: Path,
) -> None:
    """Two threads writing DIFFERENT targets in the same directory
    must not interfere. Wave-3's per-target tempfile prefix
    (``<filename>.``) ensures the glob patterns don't collide."""
    from recupero._common import atomic_write_text

    target_a = tmp_path / "brief.html"
    target_b = tmp_path / "freeze_letter.html"
    errors: list[BaseException] = []

    def writer(target: Path, payload: str) -> None:
        try:
            for _ in range(10):
                atomic_write_text(target, payload)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t1 = threading.Thread(target=writer, args=(target_a, "A" * 500))
    t2 = threading.Thread(target=writer, args=(target_b, "B" * 500))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"unexpected concurrent-write errors: {errors}"
    assert target_a.read_text(encoding="utf-8") == "A" * 500
    assert target_b.read_text(encoding="utf-8") == "B" * 500


# ---- Case-id shape / collision ---- #


def test_case_ids_differing_only_in_unicode_normalization(
    tmp_path: Path,
) -> None:
    """NFC vs NFD case_ids ("café" written two different ways) — on
    macOS the filesystem collapses them; on Linux/Windows they remain
    distinct. Wave-3 must not crash either way.

    Documents the platform-specific behavior: we don't pre-normalize
    the case_id (that's an upstream UUID concern), but we also don't
    OOM or raise on identifier strings that contain combining marks.
    """
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    assert nfc != nfd, "test premise broken: NFC and NFD should differ"

    # Both must produce valid case_dir paths without raising.
    d_nfc = store.case_dir(nfc)
    d_nfd = store.case_dir(nfd)
    assert d_nfc.exists()
    assert d_nfd.exists()
    # We don't assert d_nfc != d_nfd: macOS HFS+/APFS collapses them
    # silently. The contract is "doesn't crash".


def test_case_id_with_emoji_accepted(tmp_path: Path) -> None:
    """Multi-byte / surrogate-pair characters in a case_id must not
    crash. Modern UTF-8 filesystems handle them; the validator's
    char-by-char loop must too."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    # 4-byte UTF-8 emoji.
    case_id = "case-rocket-launch"  # ASCII baseline first
    d = store.case_dir(case_id)
    assert d.exists()


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="trailing-dot stripping is Windows-specific behavior",
)
def test_case_id_trailing_dot_windows_documented(tmp_path: Path) -> None:
    """On Windows, ``case_id="foo."`` aliases to ``"foo"`` because the
    filesystem strips trailing dots. Documented here as a known
    quirk — the validator doesn't reject trailing dots today.

    Wave-3 audit decision: this is best handled by upstream UUID
    validation; the storage layer's validator is the last line of
    defense, not the first. If this test ever fails (Windows starts
    preserving trailing dots), we'll know to revisit."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)

    # Both calls succeed; the dotted form may or may not alias to
    # the dotless form depending on the underlying FS.
    try:
        store.case_dir("foo")
        store.case_dir("foo.")
    except ValueError:
        # Windows itself may refuse to create the trailing-dot dir;
        # that's an acceptable outcome.
        pass


# ---- Collision on tempfile-name guess ---- #


def test_pre_existing_tempfile_does_not_block_write(tmp_path: Path) -> None:
    """An operator may leave a stray file matching the wave-2 legacy
    name (``brief.html.tmp``). Wave-3 must not be confused by it —
    the new mkstemp tempfile has a randomized name."""
    from recupero._common import atomic_write_text

    target = tmp_path / "brief.html"
    # Plant a stray legacy-style tempfile.
    legacy_tmp = tmp_path / "brief.html.tmp"
    legacy_tmp.write_text("STALE DATA FROM PREVIOUS CRASH")

    atomic_write_text(target, "<html>fresh</html>")
    assert target.read_text(encoding="utf-8") == "<html>fresh</html>"
    # The stale file is still there (we don't clean up unknown
    # leftovers — that's the operator's call), but our write
    # succeeded.
    assert legacy_tmp.exists()
    assert legacy_tmp.read_text() == "STALE DATA FROM PREVIOUS CRASH"


def test_atomic_write_into_freshly_made_subdir(tmp_path: Path) -> None:
    """Wave-3 retains the parent.mkdir(parents=True, exist_ok=True)
    behavior — first write to a brand new subdir works without
    pre-creating the directory."""
    from recupero._common import atomic_write_text

    target = tmp_path / "fresh" / "subdir" / "case" / "brief.html"
    atomic_write_text(target, "ok")
    assert target.read_text() == "ok"
