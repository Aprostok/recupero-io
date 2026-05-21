"""Root pytest config — auto-loads .env so tests pick up API keys.

This conftest is at the repo root (NOT under tests/). pytest loads
the closest conftest.py walking up from the test file's directory,
so a root conftest applies to every test in the suite.

RIGOR-Jacob (no-bypass discipline): pre-fix the live-API tests
(e.g., `test_recupero_trace_cli_against_real_etherscan`) skipped
unless the operator manually set RECUPERO_INTEGRATION_LIVE=1 even
though they had ETHERSCAN_API_KEY in their .env. That was a
discipline gap — the operator's intent ("I have the key, run the
live test") wasn't surfacing to pytest.

Now: this conftest reads .env at startup. If ETHERSCAN_API_KEY is
present, RECUPERO_INTEGRATION_LIVE is auto-set to '1'. The
operator still has explicit opt-out via setting
RECUPERO_INTEGRATION_LIVE=0 or deleting the key from .env.

Where the .env is found:
  1. Repo root (typical case): ../../../../.env relative to this file
     when the worktree is at .claude/worktrees/<name>/
  2. CWD-anchored: ./.env relative to the worktree itself
  3. Operator-supplied: RECUPERO_DOTENV_PATH env var (escape hatch
     for CI / one-off runs that point at a different file)
"""

from __future__ import annotations

import os
from pathlib import Path


def _candidate_dotenv_paths() -> list[Path]:
    """Return all paths to try, in priority order."""
    out: list[Path] = []
    # 1. Operator-supplied path takes top priority.
    if override := os.environ.get("RECUPERO_DOTENV_PATH"):
        out.append(Path(override))
    here = Path(__file__).resolve().parent
    # 2. Worktree-local .env.
    out.append(here / ".env")
    # 3. Repo root .env — walk up from worktree to find the main
    # repo. Heuristic: look for a parent that has a .git directory
    # (the main repo) rather than a .git FILE (worktree marker).
    for parent in here.parents:
        gitp = parent / ".git"
        if gitp.is_dir():
            out.append(parent / ".env")
            break
    # 4. Common Windows + POSIX install paths.
    home = Path.home()
    out.append(home / "Downloads" / "recupero-io" / ".env")
    return out


def _load_dotenv_into_environ() -> None:
    """Read the first .env we find and merge into os.environ. We
    deliberately do NOT overwrite already-set variables — explicit
    shell exports win, so CI can override via env without touching
    the file."""
    for path in _candidate_dotenv_paths():
        if not path.is_file():
            continue
        try:
            from dotenv import dotenv_values
        except ImportError:
            # Manual minimal parser fallback so test runs work even
            # if python-dotenv isn't installed.
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                return
            for raw_line in content.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
            return
        try:
            values = dotenv_values(str(path))
        except Exception:  # noqa: BLE001
            continue
        for key, val in values.items():
            if val is None:
                continue
            # Explicit shell exports win — don't clobber.
            if key not in os.environ:
                os.environ[key] = val
        return


# Side-effect: run at import time so the env is populated before
# any conftest fixture or test reads os.environ.
_load_dotenv_into_environ()


# RIGOR-Jacob: auto-enable live tests when the operator has the key.
# The user explicitly said "I have an API key in my .env folder, why
# are we skipping etherscan." The skip was discipline gap — we
# required the operator to ALSO set RECUPERO_INTEGRATION_LIVE=1.
# Inferring the intent from the key's presence is the right behavior.
if "RECUPERO_INTEGRATION_LIVE" not in os.environ:
    if os.environ.get("ETHERSCAN_API_KEY", "").strip():
        os.environ["RECUPERO_INTEGRATION_LIVE"] = "1"
