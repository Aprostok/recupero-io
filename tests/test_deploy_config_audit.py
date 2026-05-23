"""Security/hardening audit for container + deploy configuration.

Covers Dockerfile, railway.json, and the (currently missing) .dockerignore.
RED tests document concrete weaknesses we want to fix; each xfail/skip
marker explains the intended remediation so a future patch can flip them
to PASS rather than rewrite the assertion.

Scope: only file-system audit. We do not boot the container.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
RAILWAY_JSON = REPO_ROOT / "railway.json"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"


# ---------------------------------------------------------------------------
# Presence tripwire: if Docker/Railway files disappear, surface it loudly
# instead of silently turning every check below into a no-op.
# ---------------------------------------------------------------------------


def test_dockerfile_and_railway_json_present() -> None:
    """Worker is deployed via Railway+Dockerfile; both files must exist."""
    assert DOCKERFILE.is_file(), (
        "Dockerfile is the Railway builder per railway.json; deletion would "
        "fail the deploy. If you intentionally moved to nixpacks, update this "
        "test."
    )
    assert RAILWAY_JSON.is_file(), "railway.json drives the Railway deploy"


# ---------------------------------------------------------------------------
# RED audit findings — each currently fails. xfail keeps CI green while the
# finding stays documented; remove the marker once the Dockerfile is hardened.
# ---------------------------------------------------------------------------


def test_dockerfile_runs_as_non_root() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    # Match `USER <name-or-uid>` where the value is NOT literal `root` or `0`.
    user_lines = re.findall(r"(?mi)^\s*USER\s+(\S+)", text)
    assert user_lines, "no USER directive in Dockerfile"
    last = user_lines[-1].strip()
    assert last not in {"root", "0"}, f"final USER is privileged: {last!r}"


def test_healthcheck_present_or_railway_does_not_expect_http() -> None:
    docker_text = DOCKERFILE.read_text(encoding="utf-8")
    has_hc = re.search(r"(?mi)^\s*HEALTHCHECK\s", docker_text) is not None
    has_expose = re.search(r"(?mi)^\s*EXPOSE\s+\d+", docker_text) is not None

    railway = json.loads(RAILWAY_JSON.read_text(encoding="utf-8"))
    expects_http_health = "healthcheckPath" in railway.get("deploy", {})

    # If Railway is configured to poll an HTTP path, the image MUST expose
    # a port AND declare a HEALTHCHECK so deploys fail fast on regressions.
    if expects_http_health:
        assert has_expose, "railway.json sets healthcheckPath but Dockerfile has no EXPOSE"
        assert has_hc, "railway.json sets healthcheckPath but Dockerfile has no HEALTHCHECK"


def test_dockerignore_excludes_dangerous_paths() -> None:
    assert DOCKERIGNORE.is_file(), ".dockerignore not present"
    contents = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
    entries = {ln.strip() for ln in contents if ln.strip() and not ln.startswith("#")}
    required = {".env", "*.pyc", "__pycache__", "tests/", ".git/", "data/cases/"}
    missing = required - entries
    assert not missing, f".dockerignore missing entries: {sorted(missing)}"


# ---------------------------------------------------------------------------
# GREEN audit findings — these guard properties we already get right; if a
# future edit breaks them the test should fail immediately.
# ---------------------------------------------------------------------------


def test_apt_get_install_uses_no_install_recommends() -> None:
    """Minimize attack surface from transitive recommended packages."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    # Every `apt-get install` invocation must carry --no-install-recommends.
    for match in re.finditer(r"apt-get\s+install\b[^\n&|;]*", text):
        chunk = match.group(0)
        assert "--no-install-recommends" in chunk, (
            f"apt-get install without --no-install-recommends: {chunk!r}"
        )


def test_pip_install_uses_no_cache_dir() -> None:
    """Avoid baking ~/.cache/pip wheels into the final image layer.

    Scope the check to actual ``RUN`` instructions so a Dockerfile
    comment that documents the pattern (``# we use pip install .``)
    doesn't trip the regex.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    # Match lines that start with `RUN` (possibly indented under a
    # multi-line continuation) and contain `pip install`.
    run_blocks: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue  # comment line
        if "pip install" in stripped and (
            stripped.startswith("RUN")
            or stripped.startswith("&&")
            or stripped.startswith("&& ")
            or stripped.startswith("&&  ")
        ):
            run_blocks.append(stripped)
    for chunk in run_blocks:
        assert "--no-cache-dir" in chunk, (
            f"RUN pip install without --no-cache-dir: {chunk!r}"
        )


def test_no_hardcoded_secrets_in_dockerfile() -> None:
    """Block accidental `ENV PASSWORD=…` / `ENV SECRET=…` commits."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"(?mi)^\s*(?:ENV|ARG)\s+("
        r"[A-Z_]*PASSWORD[A-Z_]*"
        r"|[A-Z_]*SECRET[A-Z_]*"
        r"|[A-Z_]*API_KEY[A-Z_]*"
        r"|[A-Z_]*TOKEN[A-Z_]*"
        r")\s*=\s*\S+",
    )
    hits = forbidden.findall(text)
    assert not hits, f"hardcoded secret-like ENV/ARG in Dockerfile: {hits}"


def test_cmd_uses_exec_form_not_shell_form() -> None:
    """Exec form `CMD ["bin", "arg"]` avoids `/bin/sh -c` arg interpolation,
    which is a shell-injection vector when args come from env vars.

    NOTE: the `CMD` keyword that appears INSIDE a HEALTHCHECK directive
    (`HEALTHCHECK ... CMD ...`) is legitimately shell-form per Docker's
    spec — only the top-level container CMD must be exec-form. Filter
    the HEALTHCHECK lines out before checking.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    # Drop multi-line HEALTHCHECK blocks first. A HEALTHCHECK directive
    # continues with `\` until a logical end-of-line; flatten + strip.
    lines = text.splitlines()
    cmd_lines: list[str] = []
    in_healthcheck = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"(?i)^HEALTHCHECK\b", stripped):
            in_healthcheck = True
        if in_healthcheck:
            if not stripped.endswith("\\"):
                in_healthcheck = False
            continue
        m = re.match(r"(?i)^\s*CMD\s+(.+)$", line)
        if m:
            cmd_lines.append(m.group(1))
    assert cmd_lines, "no top-level CMD directive in Dockerfile"
    for line in cmd_lines:
        stripped = line.strip()
        assert stripped.startswith("["), (
            f"CMD must use exec/JSON-array form, got shell form: {stripped!r}"
        )


def test_railway_start_command_matches_dockerfile_cmd() -> None:
    """Drift between railway.json startCommand and Dockerfile CMD silently
    bypasses container-defined defaults. Keep them aligned."""
    railway = json.loads(RAILWAY_JSON.read_text(encoding="utf-8"))
    start_cmd = railway.get("deploy", {}).get("startCommand", "").strip()
    docker_text = DOCKERFILE.read_text(encoding="utf-8")
    cmd_match = re.search(r"(?mi)^\s*CMD\s+\[(.+?)\]\s*$", docker_text)
    assert cmd_match, "Dockerfile CMD not in exec form"
    # Pull the first element of the JSON-array CMD (the binary).
    first = cmd_match.group(1).split(",")[0].strip().strip('"').strip("'")
    assert start_cmd == first or start_cmd.split()[0] == first, (
        f"railway.json startCommand ({start_cmd!r}) does not match "
        f"Dockerfile CMD entrypoint ({first!r})"
    )
