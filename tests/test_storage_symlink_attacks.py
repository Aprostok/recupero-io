"""Wave-3 filesystem-race audit: symlink-following attacks.

Attack scenarios:

  * **Write to a symlink**: an operator (or attacker with FS access)
    plants ``cases_root/<case_id>/case.json`` as a symlink to
    ``/etc/passwd`` (POSIX) or ``C:\\Windows\\System32\\drivers\\etc\\hosts``
    (Windows). The wave-2 writer would happily follow the link and
    overwrite the target. Wave-3 detects ``path.is_symlink()`` and
    refuses with a clear error.

  * **Read through a symlink**: ``cases/<case_id>/case.json`` is a
    symlink to ``/etc/shadow``. ``read_case`` follows it. Wave-3
    rejects symlinked files AND symlinked parent directories.

  * **Symlinked parent directory**: ``cases/<case_id>/`` is a
    symlink to ``cases/other_case/``. The file `case.json` is NOT
    a symlink, but reading it discloses ``other_case``'s contents
    under the requester's case_id. Wave-3 walks parents to catch
    this.

Windows note: creating real symlinks requires either Developer Mode
or admin privileges. To keep these tests portable, we mock
``Path.is_symlink`` rather than relying on actual filesystem links.
The CRITICAL property is that the SOURCE CODE invokes the
``is_symlink`` check; behavior under a real symlink follows
mechanically from Python's stdlib semantics.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Detect whether real symlinks work on this platform. Used to gate
# "real-symlink" assertions; mock-based assertions always run.
_CAN_REAL_SYMLINK = sys.platform != "win32"
if sys.platform == "win32":
    # On Windows, Path.symlink_to requires elevation OR Developer Mode.
    # Try a probe in tempfile to confirm before running the few tests
    # that use real symlinks.
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as _d:
            _target = Path(_d) / "t"
            _target.write_text("x")
            _link = Path(_d) / "l"
            _link.symlink_to(_target)
            _CAN_REAL_SYMLINK = True
    except (OSError, NotImplementedError):
        _CAN_REAL_SYMLINK = False


# ---- Write to a symlink (case_store._atomic_write_bytes) ---- #


def test_atomic_write_bytes_refuses_symlink_destination(
    tmp_path: Path,
) -> None:
    """Wave-3: if the destination is a symlink, refuse to write.

    Mock-based: we patch Path.is_symlink on the target to True and
    verify the write helper raises BEFORE opening any file.
    """
    from recupero.storage.case_store import _atomic_write_bytes

    target = tmp_path / "case.json"
    # Plant a real file (or not — content doesn't matter; we mock
    # is_symlink). Don't actually create the file: the check fires
    # before any I/O.

    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(ValueError, match="symlink"):
            _atomic_write_bytes(target, b"payload")

    # The file must NOT exist on disk (the check fired pre-write).
    assert not target.exists()


def test_atomic_write_text_refuses_symlink_destination(
    tmp_path: Path,
) -> None:
    """Same contract for atomic_write_text in recupero._common."""
    from recupero._common import atomic_write_text

    target = tmp_path / "brief.html"

    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(ValueError, match="symlink"):
            atomic_write_text(target, "<html>")

    assert not target.exists()


def test_atomic_write_bytes_real_symlink_refused(tmp_path: Path) -> None:
    """End-to-end: an actual link at the destination must be refused.

    v0.31.3: pre-v0.31.3 this was skipped on Windows because file
    symlinks need Dev Mode. Now we ALSO exercise the new
    junction-aware path with a sibling junction-based test that
    catches the same code via NTFS junctions (no privilege needed).
    """
    from recupero.storage.case_store import _atomic_write_bytes
    from tests._link_helper import LinkUnsupported, make_file_link

    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text("secret data")

    link = tmp_path / "case.json"
    try:
        make_file_link(sensitive, link)
    except LinkUnsupported as e:
        pytest.skip(f"file symlink unavailable: {e}")

    with pytest.raises(ValueError, match="symlink"):
        _atomic_write_bytes(link, b'{"hacked": true}')

    # The sensitive file MUST still contain the original secret.
    assert sensitive.read_text() == "secret data"


def test_atomic_write_bytes_real_junction_refused(tmp_path: Path) -> None:
    """v0.31.3 — Windows-only junction equivalent of the test above.

    Pre-v0.31.3 the production guard used ``Path.is_symlink``, which
    returns False for NTFS junctions. An attacker who can write
    inside the data dir could plant a junction (no admin needed)
    pointing at a sensitive directory and the next file write
    would land inside it. ``is_link_like`` now catches junctions
    too — this test pins the fix.
    """
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows NTFS concept")

    from recupero.storage.case_store import _atomic_write_bytes
    from tests._link_helper import LinkUnsupported, make_dir_link

    # The junction points the SUBJECT directory at a sensitive
    # location. We then try to atomic-write a FILE inside the
    # junctioned dir — _atomic_write_bytes' parent.mkdir runs first,
    # then is_link_like is checked on `path` itself, which is a
    # regular path inside the junctioned parent. To actually catch
    # this we plant the junction AT THE FILE PATH (one level up
    # from a typical attack: the attacker mklink-/J's the case.json
    # spot — Windows allows junctioning over a non-existent target
    # name, so this is the realistic shape).
    sensitive_dir = tmp_path / "sensitive_dir"
    sensitive_dir.mkdir()
    (sensitive_dir / "marker.txt").write_text("DO NOT TOUCH")

    link_path = tmp_path / "case.json"
    try:
        make_dir_link(sensitive_dir, link_path)
    except LinkUnsupported as e:
        pytest.skip(f"junction unavailable: {e}")

    with pytest.raises(ValueError, match="symlink"):
        _atomic_write_bytes(link_path, b'{"hacked": true}')

    # The sensitive marker MUST still be intact.
    assert (sensitive_dir / "marker.txt").read_text() == "DO NOT TOUCH"


# ---- Read through a symlink (case_store.read_case) ---- #


def _build_store(tmp_path: Path):
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    return CaseStore(cfg), tmp_path / "cases"


def test_read_case_refuses_symlinked_case_json(tmp_path: Path) -> None:
    """Wave-3: read_case must reject when case.json is itself a
    symlink. Mock-based — works on any platform."""
    store, cases_root = _build_store(tmp_path)

    case_dir = cases_root / "VICTIM"
    case_dir.mkdir(parents=True)
    case_path = case_dir / "case.json"
    case_path.write_text('{"case_id":"VICTIM"}', encoding="utf-8")

    # Make Path.is_symlink return True ONLY for the case.json path.
    orig_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        if self.name == "case.json":
            return True
        return orig_is_symlink(self)

    with patch.object(Path, "is_symlink", fake_is_symlink):
        with pytest.raises(ValueError, match="symlink"):
            store.read_case("VICTIM")


def test_read_case_refuses_symlinked_parent(tmp_path: Path) -> None:
    """Wave-3: a symlinked PARENT directory (cases/<id>/ → cases/other/)
    must be detected by the parent walk in read_case."""
    store, cases_root = _build_store(tmp_path)

    case_dir = cases_root / "FRONT"
    case_dir.mkdir(parents=True)
    case_path = case_dir / "case.json"
    case_path.write_text('{"case_id":"FRONT"}', encoding="utf-8")

    orig_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        if self.name == "FRONT":
            return True
        return orig_is_symlink(self)

    with patch.object(Path, "is_symlink", fake_is_symlink):
        with pytest.raises(ValueError, match="symlink"):
            store.read_case("FRONT")


def test_read_case_real_symlinked_case_json_refused(
    tmp_path: Path,
) -> None:
    """End-to-end with a real link: case.json is a link to a foreign
    file. Wave-3 must refuse. v0.31.3 — on Windows without Dev
    Mode the file-symlink probe falls back; the junction-based
    parent-link test below covers the same is_link_like path."""
    from tests._link_helper import LinkUnsupported, make_file_link

    store, cases_root = _build_store(tmp_path)

    secret = tmp_path / "secret.json"
    secret.write_text('{"leaked":"data"}')

    case_dir = cases_root / "MARK"
    case_dir.mkdir(parents=True)
    link = case_dir / "case.json"
    try:
        make_file_link(secret, link)
    except LinkUnsupported as e:
        pytest.skip(f"file symlink unavailable: {e}")

    with pytest.raises(ValueError, match="symlink"):
        store.read_case("MARK")


def test_read_case_real_symlinked_dir_refused(tmp_path: Path) -> None:
    """End-to-end: case directory is itself a link (symlink on POSIX,
    NTFS junction on Windows). Wave-3 catches via the parent walk.

    v0.31.3: pre-v0.31.3 this test skipped on Windows because file
    symlinks need Dev Mode. But the production guard now uses
    ``is_link_like`` which detects NTFS junctions too — and
    ``mklink /J`` works for any user. The test now runs everywhere.
    """
    from tests._link_helper import LinkUnsupported, make_dir_link

    store, cases_root = _build_store(tmp_path)

    # Plant a victim case so it has a valid layout.
    real_dir = cases_root / "REAL"
    real_dir.mkdir(parents=True)
    (real_dir / "case.json").write_text(
        '{"case_id":"REAL"}', encoding="utf-8"
    )

    # And a link (symlink on POSIX, junction on Windows) that points at it.
    cases_root.mkdir(parents=True, exist_ok=True)
    link_dir = cases_root / "FAKE"
    try:
        make_dir_link(real_dir, link_dir)
    except LinkUnsupported as e:  # pragma: no cover — only on locked-down hosts
        pytest.skip(f"directory link unavailable: {e}")

    with pytest.raises(ValueError, match="symlink"):
        store.read_case("FAKE")


# ---- Symlink check fires BEFORE I/O ---- #


def test_atomic_write_symlink_check_is_early(tmp_path: Path) -> None:
    """The symlink rejection must happen BEFORE the tempfile is
    created — otherwise we leak tempfiles into the directory of the
    symlink target. Verify no tempfile is left behind."""
    from recupero.storage.case_store import _atomic_write_bytes

    target = tmp_path / "case.json"

    with patch.object(Path, "is_symlink", return_value=True), pytest.raises(ValueError):
        _atomic_write_bytes(target, b"payload")

    # No tempfile should have been created.
    leftovers = list(tmp_path.glob("case.json.*"))
    assert not leftovers, (
        f"Symlink check fired too late — tempfiles leaked: {leftovers}"
    )
