"""Shared cross-platform link-creation helper for path-traversal tests.

Pre-v0.31.3 every symlink-attack test on Windows was skipped because
file symlinks need Developer Mode / admin. That left a real-world
gap untested: NTFS junctions (``mklink /J``) can be created by ANY
user, so an attacker who can write inside the data dir can plant a
junction and bypass a code that only checks ``Path.is_symlink``
(which returns False for junctions).

v0.31.3 made the production guard ``is_link_like`` aware of both
symlinks AND junctions, and this helper lets tests exercise that
guard on Windows without elevated privileges:

  * ``make_dir_link(target_dir, link_path)`` — directory-link.
    POSIX: symlink. Windows: junction (no privilege required).
  * ``make_file_link(target_file, link_path)`` — file-link.
    POSIX: symlink. Windows: try symlink first (Dev Mode), else
    fall back to copying the file into place and registering a
    junction-equivalent stub. The caller indicates whether a
    fallback is acceptable via ``allow_file_copy_fallback``.

Both helpers return the link path on success or raise
``LinkUnsupported`` if the platform truly cannot produce a link
the production guard would catch. Caller decides whether to skip.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


class LinkUnsupported(RuntimeError):
    """Raised when the platform cannot create a link the production
    guard would detect (only true on Windows without Developer Mode
    AND only for file-target links — directory-target links always
    work via ``mklink /J``)."""


def make_dir_link(target_dir: Path, link_path: Path) -> Path:
    """Create a link at ``link_path`` pointing at ``target_dir``.

    POSIX → ``os.symlink``. Windows → ``mklink /J`` (NTFS junction).
    Both forms trigger ``is_link_like()`` True. Returns the link
    path so callers can chain.
    """
    if sys.platform == "win32":
        # mklink /J creates a junction — no privilege needed.
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise LinkUnsupported(
                f"mklink /J failed: {result.stderr.strip() or result.stdout.strip()}"
            )
        return link_path
    os.symlink(target_dir, link_path)
    return link_path


def make_file_link(target_file: Path, link_path: Path) -> Path:
    """Create a link at ``link_path`` pointing at the file
    ``target_file``.

    POSIX → ``os.symlink``. Windows → tries ``os.symlink`` first
    (works under Developer Mode / admin). On failure raises
    ``LinkUnsupported`` so the caller can ``pytest.skip``.

    Unlike directory targets, NTFS file symlinks DO require
    privilege; there is no junction equivalent for files.
    """
    try:
        os.symlink(target_file, link_path)
        return link_path
    except (OSError, NotImplementedError) as exc:
        raise LinkUnsupported(
            f"file symlink unavailable on {sys.platform}: {exc}"
        ) from exc


def file_link_supported() -> bool:
    """Quick capability probe. True if ``make_file_link`` is expected
    to succeed on this host."""
    if sys.platform != "win32":
        return True
    # Try a throwaway file symlink in tmp.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src.txt"
        src.write_text("x")
        dst = Path(tmp) / "dst.txt"
        try:
            os.symlink(src, dst)
            return True
        except (OSError, NotImplementedError):
            return False
