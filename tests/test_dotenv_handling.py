"""Audit of .env loading discipline (wave 8 narrow audit).

Hunts:
  1. Worker startup must NOT call ``load_dotenv()`` in a production
     environment (Railway/Docker). Env vars come from the platform.
     A stale ``.env`` baked into a deploy image must not be silently
     read — that's how a leftover dev key ends up running in prod.
  2. ``override=True`` would clobber explicit shell exports. Root
     conftest must NOT override.
  3. The fallback parser in the root conftest must reject obviously
     malformed lines (no '=', no key, etc.) rather than silently
     accept them and populate ``os.environ`` with garbage.
  4. The fallback parser must not crash the test session (or leak
     ``.env`` contents into a traceback) when the file is corrupt
     (e.g., non-UTF-8 bytes). Exception must be swallowed.
  5. ``_candidate_dotenv_paths`` must not blindly follow a path the
     operator can hijack — a symlink at ``./.env`` pointing at
     ``/etc/passwd`` (or any non-env file) is a footgun. We assert
     the loader either refuses to follow the symlink OR, at minimum,
     ignores the parse failure.
  6. Already-set env vars MUST win over .env values (no clobber).
     CI sets vars via shell exports; the dev .env in the worktree
     must not overwrite those.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_CONFTEST = REPO_ROOT / "conftest.py"


def _load_root_conftest_module():
    """Import the repo-root conftest.py as a standalone module so we
    can call its helpers without re-running its import-time
    side-effect on every test."""
    spec = importlib.util.spec_from_file_location(
        "_root_conftest_for_audit", ROOT_CONFTEST
    )
    assert spec and spec.loader, "root conftest must be importable"
    mod = importlib.util.module_from_spec(spec)
    # The conftest runs _load_dotenv_into_environ() at import.
    # We snapshot os.environ around the load so we can isolate.
    snap = dict(os.environ)
    try:
        spec.loader.exec_module(mod)
    finally:
        # Restore to test isolation.
        os.environ.clear()
        os.environ.update(snap)
    return mod


# ---- Hunt #1: production worker must NOT load .env ---- #


def test_worker_main_skips_load_dotenv_in_production(monkeypatch):
    """Hunt #1: ``src/recupero/worker/main.py`` calls ``load_dotenv()``
    unconditionally at startup. In a Railway/Docker production deploy,
    the env is provided by the platform — reading a stray ``.env``
    file that shipped in the image is a supply-chain-style footgun.

    The fix: guard the load_dotenv() call behind a production-marker
    check (same pattern as ``recupero.api.auth._is_production_environment``).
    """
    main_src = (REPO_ROOT / "src" / "recupero" / "worker" / "main.py").read_text(
        encoding="utf-8"
    )
    # We accept any of these production-aware guard patterns. The
    # raw `load_dotenv()` with no guard must NOT appear in the
    # file's `main()` block.
    has_guard = any(
        marker in main_src
        for marker in (
            "RAILWAY_ENVIRONMENT",
            "RECUPERO_ENV",
            "_is_production_environment",
            "_should_load_dotenv",
        )
    )
    assert has_guard, (
        "src/recupero/worker/main.py calls load_dotenv() with no "
        "production-environment guard. In Railway/Docker the .env "
        "should NOT be loaded; env comes from the platform."
    )


# ---- Hunt #2 + #6: never clobber already-set env vars ---- #


def test_root_conftest_does_not_override_existing_env(tmp_path, monkeypatch):
    """Hunt #2/#6: ``load_dotenv(override=True)`` would clobber
    shell-exported vars. The root conftest must never override —
    explicit exports (CI, operator shell) always win.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("RECUPERO_DOTENV_AUDIT_KEY=from_dotenv\n", encoding="utf-8")

    monkeypatch.setenv("RECUPERO_DOTENV_PATH", str(env_file))
    monkeypatch.setenv("RECUPERO_DOTENV_AUDIT_KEY", "from_shell")

    mod = _load_root_conftest_module()
    mod._load_dotenv_into_environ()

    assert os.environ["RECUPERO_DOTENV_AUDIT_KEY"] == "from_shell", (
        "Root conftest must NOT override existing env vars. Got "
        f"{os.environ['RECUPERO_DOTENV_AUDIT_KEY']!r}."
    )


# ---- Hunt #3: fallback parser must reject malformed lines ---- #


def test_fallback_parser_rejects_malformed_lines(tmp_path, monkeypatch):
    """Hunt #3: when python-dotenv is unavailable, the conftest
    fallback parser must not silently accept lines like ``=oops``
    (no key) or pollute os.environ with empty-key garbage.

    We don't exercise the ImportError branch directly (python-dotenv
    is installed); instead we verify the documented behavior by
    constructing a malformed file and ensuring the merged env stays
    clean of obviously-bogus keys.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        textwrap.dedent(
            """\
            =no_key_here
            no_equals_at_all
               =leading_ws_no_key
            REAL_KEY=ok_value
            """
        ),
        encoding="utf-8",
    )

    # Wipe any previously-set REAL_KEY so we know the loader set it.
    monkeypatch.delenv("REAL_KEY", raising=False)
    monkeypatch.setenv("RECUPERO_DOTENV_PATH", str(env_file))

    mod = _load_root_conftest_module()
    mod._load_dotenv_into_environ()

    # Valid line must load.
    assert os.environ.get("REAL_KEY") == "ok_value"
    # Empty-key garbage must NOT make it into os.environ.
    assert "" not in os.environ, (
        "Fallback parser populated os.environ with an empty-string "
        "key from a malformed '=no_key_here' line."
    )


# ---- Hunt #4: corrupt .env must not crash or leak in traceback ---- #


def test_corrupt_dotenv_does_not_crash_session(tmp_path, monkeypatch):
    """Hunt #4: a corrupt ``.env`` (invalid UTF-8) must not raise
    out of ``_load_dotenv_into_environ`` — that would abort the
    entire test session AND embed the raw byte contents in the
    traceback (potentially leaking surrounding secret material if
    the file is partially-readable)."""
    env_file = tmp_path / ".env"
    # Non-UTF-8 bytes: 0x80 is an invalid lead byte in UTF-8.
    env_file.write_bytes(b"REAL_KEY=ok\n\x80\x81\xff\nOTHER=val\n")
    monkeypatch.setenv("RECUPERO_DOTENV_PATH", str(env_file))

    mod = _load_root_conftest_module()
    # Must not raise.
    mod._load_dotenv_into_environ()


# ---- Hunt #5: symlinked .env should not silently get followed ---- #


@pytest.mark.skipif(sys.platform == "win32", reason="symlink perms vary on Windows")
def test_symlinked_dotenv_does_not_leak_arbitrary_file(tmp_path, monkeypatch):
    """Hunt #5: if ``./.env`` is a symlink to ``/etc/passwd`` (or any
    non-env file), ``_candidate_dotenv_paths`` returns it and
    ``is_file()`` follows the link. The loader currently parses the
    target. We assert that the parse cannot introduce arbitrary
    environment variables: a passwd-style line (``root:x:0:0:...``)
    has no ``=`` so the fallback parser rejects it; for python-dotenv
    it returns no usable values. Either way, ``root`` or ``daemon``
    must NOT end up in os.environ.
    """
    target = tmp_path / "passwd_like"
    target.write_text(
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        encoding="utf-8",
    )
    link = tmp_path / ".env"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not permitted in this sandbox")

    monkeypatch.setenv("RECUPERO_DOTENV_PATH", str(link))

    mod = _load_root_conftest_module()
    mod._load_dotenv_into_environ()

    # Neither passwd field name should ever appear as an env key.
    assert "root" not in os.environ
    assert "daemon" not in os.environ
