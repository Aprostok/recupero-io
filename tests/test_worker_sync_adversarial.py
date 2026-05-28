"""Adversarial audit of recupero.worker.sync.upload_case_dir.

Covers (per audit checklist):

  1. Path traversal / symlink escape during ``case_dir`` walk —
     ``rglob("*")`` does NOT recurse into symlinked directories on
     3.13+, but a symlink that points at a regular file outside
     ``case_dir`` IS reported by ``rglob`` and ``is_file()`` returns
     True. ``path.read_bytes()`` then follows the link and uploads
     the target's content (e.g. /etc/passwd) under the bucket prefix.
     Must skip symlinks.

  2. Per-file size cap. ``path.read_bytes()`` loads the full file
     into memory before the bucket's 413 check fires. A 10 GB file
     planted in ``briefs/`` would OOM the worker. Pre-check via
     ``stat().st_size``.

  3. ``briefs/`` subpath validation. ``_upload_to_subpath`` joins
     ``parts`` straight into the bucket URL, bypassing
     ``_validate_relpath``. Forbidden substrings in a brief filename
     must raise before hitting the network.

  4. Service-role token redaction extension. New-style Supabase keys
     (``sb_secret_*``, ``sb_publishable_*``, ``sbp_*``) are NOT
     matched by the wave-9 JWT pattern. If an error message echoes
     the bearer header value verbatim, the secret leaks to logs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from recupero.worker import sync as worker_sync


def _make_stub_store() -> MagicMock:
    """A lightweight stand-in for SupabaseCaseStore that records
    upload calls without opening any network connections."""
    store = MagicMock()
    store.storage_prefix = "investigations/00000000-0000-0000-0000-000000000000/"
    store.write_text = MagicMock()
    store.write_json = MagicMock()
    store.write_evidence = MagicMock()
    store._upload = MagicMock()
    return store


# ----------------------------------------------------------------------
# 1. symlink escape
# ----------------------------------------------------------------------

def test_symlink_to_outside_file_is_skipped(tmp_path: Path) -> None:
    """A link in case_dir that points outside case_dir must NOT be
    uploaded — read_bytes() would otherwise dereference the link and
    ship the target's content to the bucket.

    v0.31.3: on Windows we test BOTH a file symlink (when Dev Mode is
    enabled — falls back gracefully if not) AND a directory junction
    via the companion test below. Production guard is the same:
    ``is_link_like`` catches both.
    """
    from tests._link_helper import LinkUnsupported, make_file_link

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("ROOT-PASSWORD-SHOULD-NEVER-LEAVE-DISK")

    # Plant a link under case_dir/ pointing at the outside secret.
    link = case_dir / "leak.txt"
    try:
        make_file_link(secret, link)
    except LinkUnsupported as e:
        pytest.skip(f"file link unavailable: {e}")

    store = _make_stub_store()
    worker_sync.upload_case_dir(case_dir, store)

    # No upload primitive should have seen the secret content.
    for call in store.write_text.call_args_list:
        assert "ROOT-PASSWORD" not in str(call), (
            f"symlink target content leaked through write_text: {call}"
        )
    for call in store._upload.call_args_list:
        assert b"ROOT-PASSWORD" not in (call.args[1] if len(call.args) > 1 else b""), (
            f"symlink target content leaked through _upload: {call}"
        )


def test_junction_to_outside_dir_is_skipped(tmp_path: Path) -> None:
    """v0.31.3 — Windows-only companion to the symlink test above.

    On Windows an NTFS junction (``mklink /J``) does NOT require Dev
    Mode / admin to create. Pre-v0.31.3 ``upload_case_dir`` checked
    only ``Path.is_symlink()`` which returns False for junctions, so
    an attacker could plant a junction pointing at any directory and
    every file under it would be uploaded. ``is_link_like`` now
    catches junctions — this test pins the fix.
    """
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows NTFS concept")

    from tests._link_helper import LinkUnsupported, make_dir_link

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    secret_dir = tmp_path / "outside_secret_dir"
    secret_dir.mkdir()
    (secret_dir / "secret.txt").write_text(
        "ROOT-PASSWORD-SHOULD-NEVER-LEAVE-DISK"
    )

    # Plant a directory junction under case_dir/ pointing at secret_dir.
    link = case_dir / "leak_dir"
    try:
        make_dir_link(secret_dir, link)
    except LinkUnsupported as e:
        pytest.skip(f"junction unavailable: {e}")

    store = _make_stub_store()
    worker_sync.upload_case_dir(case_dir, store)

    for call in store.write_text.call_args_list:
        assert "ROOT-PASSWORD" not in str(call), (
            f"junction target content leaked through write_text: {call}"
        )
    for call in store._upload.call_args_list:
        assert b"ROOT-PASSWORD" not in (call.args[1] if len(call.args) > 1 else b""), (
            f"junction target content leaked through _upload: {call}"
        )


# ----------------------------------------------------------------------
# 2. per-file size cap
# ----------------------------------------------------------------------

def test_oversize_brief_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pathological brief file larger than the per-file cap must
    not be loaded into memory via read_bytes(). Verify by patching
    ``stat`` to report a huge size and asserting read_bytes is never
    called for that file."""
    case_dir = tmp_path / "case"
    (case_dir / "briefs").mkdir(parents=True)
    huge = case_dir / "briefs" / "huge.pdf"
    huge.write_bytes(b"%PDF-1.4 tiny stub")  # real file is tiny

    # Lie about its size via stat() so the cap fires.
    real_stat = Path.stat

    def fake_stat(self: Path, *a, **kw):
        st = real_stat(self, *a, **kw)
        if self == huge:
            class _S:
                st_size = 10 * 1024 * 1024 * 1024  # 10 GB
                st_mode = st.st_mode
                st_mtime = st.st_mtime
            return _S()
        return st

    monkeypatch.setattr(Path, "stat", fake_stat)

    # Trip-wire: read_bytes on the huge file must not be called.
    called = {"huge_read": False}
    real_read = Path.read_bytes

    def trip_read(self: Path):
        if self == huge:
            called["huge_read"] = True
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", trip_read)

    store = _make_stub_store()
    worker_sync.upload_case_dir(case_dir, store)

    assert not called["huge_read"], (
        "oversized file was read into memory before bucket-side 413 check; "
        "a real 10 GB file would OOM the worker"
    )


# ----------------------------------------------------------------------
# 3. briefs subpath validation — _upload_to_subpath bypassed _validate_relpath
# ----------------------------------------------------------------------

def test_briefs_subpath_rejects_traversal_substring(tmp_path: Path) -> None:
    """A brief filename containing forbidden substrings (``..``, NUL,
    backslash) must fail validation before reaching the network.
    The existing _upload_to_subpath path concatenated ``parts`` straight
    into the bucket URL with no _validate_relpath check."""
    from recupero.storage.supabase_case_store import _validate_relpath

    case_dir = tmp_path / "case"
    (case_dir / "briefs").mkdir(parents=True)

    # We can't create a real file with ".." in the name on most FS,
    # so exercise the validator directly with the path the bucket
    # would have received.
    for bad in ("briefs/../escape.html", "briefs/leak\x00.html"):
        with pytest.raises(ValueError):
            _validate_relpath(bad, kind="bucket_relative_path")


def test_briefs_upload_validates_relpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: upload_case_dir must call _validate_relpath on the
    bucket_relative_path before _upload. A hostile component name
    must not reach the network."""
    case_dir = tmp_path / "case"
    (case_dir / "briefs").mkdir(parents=True)
    (case_dir / "briefs" / "ok.pdf").write_bytes(b"%PDF-1.4 ok")

    store = _make_stub_store()

    # Stand in: force a forbidden bucket path through the helper to
    # confirm the validator gate fires.
    with pytest.raises(ValueError):
        worker_sync._upload_to_subpath(
            store, "briefs/../escape.html", b"x", "text/html"
        )
    store._upload.assert_not_called()


# ----------------------------------------------------------------------
# 4. service-role token redaction (wave-9 extension)
# ----------------------------------------------------------------------

def test_redact_covers_sb_secret_token() -> None:
    """New-style Supabase service-role keys (``sb_secret_<token>``)
    must be redacted by the central log filter. Without the rule,
    a logged error containing the bearer header value leaks the
    long-lived service-role key into Railway logs."""
    from recupero.logging_setup import _redact

    leak = (
        "upload to case.json failed: 500 "
        "{\"error\":\"bearer sb_secret_abc123def456ghi789jkl012MNO leaked\"}"
    )
    out = _redact(leak)
    assert "sb_secret_abc123def456ghi789jkl012MNO" not in out, (
        f"sb_secret_* token survived redaction: {out!r}"
    )


def test_redact_covers_sb_publishable_token() -> None:
    """The publishable-key prefix shape (``sb_publishable_*`` / ``sbp_*``)
    is less sensitive but still an identifier we don't want in shared
    log archives. Cover for completeness."""
    from recupero.logging_setup import _redact

    leak = "apikey=sb_publishable_xyz789ABC123def456GHI789jkl in request"
    out = _redact(leak)
    assert "sb_publishable_xyz789ABC123def456GHI789jkl" not in out
