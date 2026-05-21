"""Nightly Recupero codebase audit (v0.28.0).

Runs a battery of deterministic health checks against the working
tree and emits:

  1. A JSON digest at ``--out-json`` (default ``nightly_audit.json``)
     suitable for shipping into a metrics pipeline / dashboard.
  2. A human-readable text summary on stdout for the operator on call.

Designed for a daily cron (Railway scheduled job or GitHub Actions).
Every check is self-contained: one check crashing does not abort the
rest. The script's own exit code is 0 unless a check tripped a
configured red-line (e.g., pytest failures, mypy increasing past
the configured budget). Operators read the digest, address the
specific finding, then re-run.

Checks performed (all read-only):

  A. tests             — pytest pass/fail counts + slowest 10 tests
  B. lint              — ruff warning counts by category
  C. types             — mypy error counts by module
  D. git_activity      — commit count + diff stats over 24h / 7d
  E. todo_inventory    — count + delta of TODO/FIXME/XXX comments
  F. lazy_imports      — count of ``def ... from x import y`` smells
  G. large_files       — files that grew > 10% since last week
  H. test_coverage     — test/source LoC ratio per top-level module
  I. migrations        — migration count vs. last recorded apply
  J. llm_review        — optional, env-gated; sends the digest to
                         Claude for narrative review

Use:
    python scripts/nightly_audit.py
    python scripts/nightly_audit.py --skip tests,types
    python scripts/nightly_audit.py --baseline ./.audits/yesterday.json
    python scripts/nightly_audit.py --llm-review   # requires ANTHROPIC_API_KEY

Exit codes:
    0   all checks completed (findings may be present in digest)
    1   one or more checks tripped a red-line (configurable)
    2   USAGE — missing env vars / bad arguments
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# CheckResult — a uniform shape so every check writes the same JSON
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """Result of one audit check.

    Attributes:
        name:      Stable identifier (used in the JSON digest + CLI flags).
        status:    "ok" | "warn" | "fail" | "skipped" | "error".
                   "error" means the check itself crashed.
                   "fail" means the check produced a red-line finding.
        summary:   One-line human-readable headline.
        data:      Structured findings (counts, lists, deltas).
        duration_s: Wall-clock seconds the check took.
        red_line:  True if this should set the script's exit code to 1.
    """
    name: str
    status: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    red_line: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(
    cmd: list[str], *, timeout: float = 600.0, env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess, capture stdout + stderr, return
    (returncode, stdout, stderr). Never raises (timeout returns -1)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=({**os.environ, **env} if env else None),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return -1, exc.stdout or "", (exc.stderr or "") + f"\n[timeout {timeout}s]"
    except FileNotFoundError as exc:
        return -2, "", f"command not found: {exc}"


def _src_files() -> list[Path]:
    """Every .py file under src/recupero/."""
    return sorted((REPO_ROOT / "src" / "recupero").rglob("*.py"))


def _test_files() -> list[Path]:
    """Every test_*.py file under tests/."""
    return sorted((REPO_ROOT / "tests").rglob("test_*.py"))


def _file_loc(path: Path) -> int:
    try:
        return sum(1 for _ in path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# A. pytest
# ─────────────────────────────────────────────────────────────────────────────


_PYTEST_SUMMARY_RE = re.compile(
    r"(?P<passed>\d+) passed"
    r"(?:, (?P<failed>\d+) failed)?"
    r"(?:, (?P<skipped>\d+) skipped)?"
    r"(?:, (?P<errors>\d+) error[s]?)?"
    r"(?:, (?P<warnings>\d+) warning[s]?)?"
)
_PYTEST_SLOWEST_RE = re.compile(
    r"^([0-9.]+)s\s+(?:call|setup|teardown)\s+(tests/[^\s]+)\s*$"
)


def check_tests(*, timeout_s: float = 600.0) -> CheckResult:
    """Run pytest with --durations=10 -q. Captures pass/fail counts and
    the 10 slowest tests."""
    start = time.monotonic()
    rc, out, err = _run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "--durations=10",
         "--tb=no"],
        timeout=timeout_s,
    )
    duration = time.monotonic() - start

    text = out + "\n" + err
    summary_line = ""
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for line in text.splitlines():
        m = _PYTEST_SUMMARY_RE.search(line)
        if m and "passed" in line:
            summary_line = line.strip()
            for k in counts:
                v = m.group(k)
                counts[k] = int(v) if v else 0
            break

    slowest = []
    for line in text.splitlines():
        m = _PYTEST_SLOWEST_RE.match(line)
        if m:
            slowest.append({"seconds": float(m.group(1)), "test": m.group(2)})
        if len(slowest) >= 10:
            break

    status = "ok"
    red_line = False
    if rc == -1:
        status, red_line = "error", True
        summary = f"pytest timed out after {timeout_s}s"
    elif rc < 0:
        status, red_line = "error", True
        summary = "pytest could not be invoked"
    elif counts["failed"] or counts["errors"]:
        status, red_line = "fail", True
        summary = (
            f"{counts['failed']} failed, "
            f"{counts['errors']} errors, "
            f"{counts['passed']} passed"
        )
    else:
        summary = (
            f"{counts['passed']} passed, {counts['skipped']} skipped"
        )

    return CheckResult(
        name="tests",
        status=status,
        summary=summary,
        red_line=red_line,
        duration_s=round(duration, 2),
        data={
            "summary_line": summary_line,
            "counts": counts,
            "slowest_tests": slowest,
            "returncode": rc,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# B. ruff
# ─────────────────────────────────────────────────────────────────────────────


def check_lint() -> CheckResult:
    """Run ruff check + output structured JSON. Aggregate by rule code."""
    start = time.monotonic()
    rc, out, err = _run(
        [sys.executable, "-m", "ruff", "check", ".", "--output-format=json"],
        timeout=120,
    )
    duration = time.monotonic() - start

    by_rule: dict[str, int] = {}
    findings: list[dict] = []
    if rc == -2:
        return CheckResult(
            name="lint", status="skipped",
            summary="ruff not installed; skipping",
            duration_s=round(duration, 2),
            data={"hint": "pip install ruff"},
        )
    try:
        parsed = json.loads(out) if out.strip() else []
        for f in parsed:
            code = f.get("code") or "?"
            by_rule[code] = by_rule.get(code, 0) + 1
            findings.append({
                "file": f.get("filename", ""),
                "line": f.get("location", {}).get("row"),
                "code": code,
                "message": f.get("message", "")[:200],
            })
    except json.JSONDecodeError:
        # Ruff sometimes writes errors on stderr in non-json mode.
        return CheckResult(
            name="lint", status="error",
            summary=f"ruff JSON parse failed: {err[:200]}",
            duration_s=round(duration, 2),
        )

    total = sum(by_rule.values())
    status = "ok" if total == 0 else "warn"
    return CheckResult(
        name="lint", status=status,
        summary=f"{total} ruff findings across {len(by_rule)} rules",
        duration_s=round(duration, 2),
        data={"by_rule": by_rule, "first_50": findings[:50]},
    )


# ─────────────────────────────────────────────────────────────────────────────
# C. mypy
# ─────────────────────────────────────────────────────────────────────────────


_MYPY_ERROR_RE = re.compile(r"^(.+?):(\d+): (error|note|warning): (.+)$")


def check_types() -> CheckResult:
    """Run mypy on src/recupero; aggregate errors by file."""
    start = time.monotonic()
    rc, out, err = _run(
        [sys.executable, "-m", "mypy", "src/recupero", "--no-color-output",
         "--no-error-summary"],
        timeout=300,
    )
    duration = time.monotonic() - start

    if rc == -2:
        return CheckResult(
            name="types", status="skipped",
            summary="mypy not installed; skipping",
            duration_s=round(duration, 2),
            data={"hint": "pip install mypy"},
        )

    by_file: dict[str, int] = {}
    samples: list[str] = []
    for line in out.splitlines():
        m = _MYPY_ERROR_RE.match(line)
        if not m:
            continue
        kind = m.group(3)
        if kind != "error":
            continue
        by_file[m.group(1)] = by_file.get(m.group(1), 0) + 1
        if len(samples) < 30:
            samples.append(line.strip())

    total_errors = sum(by_file.values())
    status = "ok" if total_errors == 0 else "warn"
    return CheckResult(
        name="types", status=status,
        summary=f"{total_errors} mypy errors across {len(by_file)} files",
        duration_s=round(duration, 2),
        data={
            "errors_by_file": dict(sorted(
                by_file.items(), key=lambda kv: kv[1], reverse=True,
            )[:20]),
            "samples": samples,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# D. git activity
# ─────────────────────────────────────────────────────────────────────────────


def check_git_activity() -> CheckResult:
    """Summarize git activity over the last 24h + 7d."""
    start = time.monotonic()
    rc1, out_24h, _ = _run(
        ["git", "log", "--since=24 hours ago", "--pretty=format:%h %s"],
        timeout=30,
    )
    rc2, out_7d, _ = _run(
        ["git", "log", "--since=7 days ago", "--pretty=format:%h"],
        timeout=30,
    )
    rc3, out_diff, _ = _run(
        ["git", "diff", "--shortstat", "HEAD@{7 days ago}..HEAD"],
        timeout=30,
    )
    rc4, out_branch, _ = _run(
        ["git", "rev-list", "--count", "@{upstream}..HEAD"],
        timeout=30,
    )
    duration = time.monotonic() - start

    commits_24h = [
        line for line in out_24h.splitlines() if line.strip()
    ]
    commits_7d = len([
        line for line in out_7d.splitlines() if line.strip()
    ])
    diff_summary = out_diff.strip() or "no changes in last 7 days"
    ahead_of_origin = 0
    try:
        ahead_of_origin = int(out_branch.strip() or "0")
    except ValueError:
        pass

    return CheckResult(
        name="git_activity", status="ok",
        summary=(
            f"{len(commits_24h)} commits in 24h, {commits_7d} in 7d; "
            f"{ahead_of_origin} ahead of upstream"
        ),
        duration_s=round(duration, 2),
        data={
            "commits_24h": commits_24h[:20],
            "commits_24h_count": len(commits_24h),
            "commits_7d_count": commits_7d,
            "diff_7d_shortstat": diff_summary,
            "ahead_of_upstream": ahead_of_origin,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# E. TODO / FIXME inventory
# ─────────────────────────────────────────────────────────────────────────────


_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b", re.IGNORECASE)


def check_todo_inventory(baseline: dict | None = None) -> CheckResult:
    """Count TODO / FIXME / XXX / HACK markers in source. If a baseline
    digest is supplied, report the delta."""
    start = time.monotonic()
    by_marker: dict[str, int] = {}
    by_module: dict[str, int] = {}
    samples: list[dict] = []
    for path in _src_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        module = rel.split("/", 3)[2] if rel.count("/") >= 2 else rel
        try:
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1,
            ):
                for m in _TODO_RE.finditer(line):
                    marker = m.group(1).upper()
                    by_marker[marker] = by_marker.get(marker, 0) + 1
                    by_module[module] = by_module.get(module, 0) + 1
                    if len(samples) < 50:
                        samples.append({
                            "file": rel,
                            "line": lineno,
                            "marker": marker,
                            "text": line.strip()[:160],
                        })
        except OSError:
            continue
    duration = time.monotonic() - start

    total = sum(by_marker.values())
    delta = None
    if baseline:
        prev_total = (
            baseline.get("checks", {}).get("todo_inventory", {})
            .get("data", {}).get("total", 0)
        )
        delta = total - prev_total

    return CheckResult(
        name="todo_inventory", status="ok",
        summary=(
            f"{total} TODO/FIXME/XXX/HACK markers"
            + (f" (Δ {delta:+d} vs baseline)" if delta is not None else "")
        ),
        duration_s=round(duration, 2),
        data={
            "total": total,
            "by_marker": by_marker,
            "by_module": dict(sorted(
                by_module.items(), key=lambda kv: kv[1], reverse=True,
            )),
            "delta_vs_baseline": delta,
            "samples": samples,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# F. Lazy-import smell counter
# ─────────────────────────────────────────────────────────────────────────────


_DEF_RE = re.compile(r"^(\s*)def\s+\w+\(", re.MULTILINE)
_LAZY_IMPORT_RE = re.compile(
    r"^(\s+)(?:from\s+\S+\s+import\s+|import\s+)", re.MULTILINE,
)


def check_lazy_imports() -> CheckResult:
    """Heuristic: count ``from x import y`` / ``import x`` statements
    that appear INSIDE a function body (indented). High counts suggest
    circular-import workarounds that should be flattened."""
    start = time.monotonic()
    by_module: dict[str, int] = {}
    samples: list[dict] = []
    for path in _src_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        module = rel.split("/", 3)[2] if rel.count("/") >= 2 else rel
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        # An import is "lazy" when its line is indented (inside a def
        # or class body). We don't care about top-level imports
        # (zero leading whitespace).
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line:
                continue
            stripped = line.lstrip()
            if not (
                stripped.startswith("from ")
                or stripped.startswith("import ")
            ):
                continue
            indent = len(line) - len(stripped)
            if indent == 0:
                continue
            by_module[module] = by_module.get(module, 0) + 1
            if len(samples) < 30:
                samples.append({
                    "file": rel,
                    "line": lineno,
                    "text": stripped[:160],
                })
    duration = time.monotonic() - start

    total = sum(by_module.values())
    return CheckResult(
        name="lazy_imports", status="ok",
        summary=f"{total} lazy imports across {len(by_module)} modules",
        duration_s=round(duration, 2),
        data={
            "total": total,
            "by_module": dict(sorted(
                by_module.items(), key=lambda kv: kv[1], reverse=True,
            )),
            "samples": samples,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# G. Large-file regression (growth tracking)
# ─────────────────────────────────────────────────────────────────────────────


def check_large_files(baseline: dict | None = None) -> CheckResult:
    """Report files larger than 600 LoC and (if a baseline digest is
    supplied) flag files that grew more than 10% in the past week."""
    start = time.monotonic()
    sizes: dict[str, int] = {}
    for path in _src_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        sizes[rel] = _file_loc(path)
    duration = time.monotonic() - start

    threshold_loc = 600
    large_files = [
        {"file": f, "loc": loc}
        for f, loc in sorted(sizes.items(), key=lambda kv: kv[1], reverse=True)
        if loc > threshold_loc
    ]

    grew = []
    if baseline:
        prev_sizes = (
            baseline.get("checks", {}).get("large_files", {})
            .get("data", {}).get("all_sizes", {})
        )
        for f, loc in sizes.items():
            prev = prev_sizes.get(f, 0)
            if prev > 0 and (loc - prev) / prev > 0.10:
                grew.append({
                    "file": f, "prev_loc": prev, "loc": loc,
                    "growth_pct": round((loc - prev) / prev * 100, 1),
                })

    status = "ok"
    summary = f"{len(large_files)} files > {threshold_loc} LoC"
    if grew:
        status = "warn"
        summary += f"; {len(grew)} files grew > 10% vs baseline"

    return CheckResult(
        name="large_files", status=status,
        summary=summary,
        duration_s=round(duration, 2),
        data={
            "threshold_loc": threshold_loc,
            "large_files": large_files[:30],
            "grew_vs_baseline": grew,
            "all_sizes": sizes,  # for tomorrow's baseline
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# H. Test / source ratio per module
# ─────────────────────────────────────────────────────────────────────────────


def check_test_coverage() -> CheckResult:
    """Compute test-LoC vs source-LoC per top-level module under
    src/recupero/. Modules with ratio < 0.20 are flagged as
    under-tested."""
    start = time.monotonic()
    src_by_mod: dict[str, int] = {}
    for path in _src_files():
        rel = path.relative_to(REPO_ROOT / "src" / "recupero").as_posix()
        parts = rel.split("/")
        module = parts[0] if len(parts) > 1 else "_root"
        if path.name == "__init__.py":
            continue
        src_by_mod[module] = src_by_mod.get(module, 0) + _file_loc(path)

    test_by_mod: dict[str, int] = {}
    for path in _test_files():
        name = path.stem
        # Heuristic: tests/test_<module>_<rest>.py → module
        # Best-effort; doesn't have to be exact.
        if "_" in name:
            module = name.split("_", 2)[1]
            test_by_mod[module] = test_by_mod.get(module, 0) + _file_loc(path)
        else:
            test_by_mod["_general"] = (
                test_by_mod.get("_general", 0) + _file_loc(path)
            )
    duration = time.monotonic() - start

    rows = []
    under = []
    for mod, src_loc in sorted(src_by_mod.items()):
        test_loc = test_by_mod.get(mod, 0)
        ratio = test_loc / src_loc if src_loc else 0.0
        rows.append({
            "module": mod, "src_loc": src_loc,
            "test_loc": test_loc, "ratio": round(ratio, 2),
        })
        if src_loc >= 200 and ratio < 0.20:
            under.append({"module": mod, "ratio": round(ratio, 2)})

    status = "warn" if under else "ok"
    return CheckResult(
        name="test_coverage", status=status,
        summary=(
            f"{len(rows)} modules surveyed; "
            f"{len(under)} under-tested (ratio < 0.20)"
        ),
        duration_s=round(duration, 2),
        data={"per_module": rows, "under_tested": under},
    )


# ─────────────────────────────────────────────────────────────────────────────
# I. Migrations
# ─────────────────────────────────────────────────────────────────────────────


def check_migrations() -> CheckResult:
    """Count migrations + ensure naming sequence is monotonic + report
    the latest one."""
    start = time.monotonic()
    mig_dir = REPO_ROOT / "migrations"
    if not mig_dir.is_dir():
        return CheckResult(
            name="migrations", status="skipped",
            summary="no migrations/ directory",
        )
    files = sorted(mig_dir.glob("*.sql"))
    duration = time.monotonic() - start
    return CheckResult(
        name="migrations", status="ok",
        summary=f"{len(files)} migrations; latest: {files[-1].name if files else 'none'}",
        duration_s=round(duration, 2),
        data={
            "count": len(files),
            "files": [f.name for f in files],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# J. Optional LLM narrative review
# ─────────────────────────────────────────────────────────────────────────────


def check_llm_review(digest: dict) -> CheckResult:
    """Optional. Sends a compact digest to Claude for a one-paragraph
    narrative review ("yesterday vs today: what looks worse, what
    looks better"). Gated on ANTHROPIC_API_KEY + --llm-review flag.

    If anthropic isn't installed or the key is unset, returns skipped.
    """
    start = time.monotonic()
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return CheckResult(
            name="llm_review", status="skipped",
            summary="ANTHROPIC_API_KEY unset",
        )
    try:
        import anthropic  # type: ignore
    except ImportError:
        return CheckResult(
            name="llm_review", status="skipped",
            summary="anthropic SDK not installed",
        )

    # Compose a compact prompt — never send file contents, only the
    # digest counts + names. Operator's choice to widen later.
    compact = {
        "tests": digest["checks"]["tests"]["summary"],
        "lint":  digest["checks"].get("lint", {}).get("summary", "skipped"),
        "types": digest["checks"].get("types", {}).get("summary", "skipped"),
        "todos": digest["checks"]["todo_inventory"]["summary"],
        "lazy_imports": digest["checks"]["lazy_imports"]["summary"],
        "git_activity": digest["checks"]["git_activity"]["summary"],
        "large_files": digest["checks"]["large_files"]["summary"],
        "test_coverage": digest["checks"]["test_coverage"]["summary"],
    }
    prompt = (
        "You are reviewing a daily codebase health digest for the "
        "Recupero crypto-forensics platform. Below are one-line "
        "summaries of each check. Identify the SINGLE most concerning "
        "trend and propose ONE specific improvement task for tomorrow. "
        "Be concrete, not motivational.\n\n"
        + "\n".join(f"  * {k}: {v}" for k, v in compact.items())
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            (block.text if hasattr(block, "text") else str(block))
            for block in resp.content
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="llm_review", status="error",
            summary=f"LLM call failed: {type(exc).__name__}",
            duration_s=round(time.monotonic() - start, 2),
        )

    return CheckResult(
        name="llm_review", status="ok",
        summary="LLM narrative review completed",
        duration_s=round(time.monotonic() - start, 2),
        data={"narrative": text.strip()},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────


# All checks the script knows about. Each runs in this order.
# RIGOR-3 (hang-fix): late-bound check dispatch. Pre-fix this list
# captured function REFERENCES at module-load time. When tests used
# `patch.object(audit_module, "check_tests", ...)`, the patch replaced
# the module attribute but the captured reference in this list was
# untouched — main() ran the ORIGINAL check_tests, which invoked
# pytest as a subprocess WHILE WE WERE INSIDE A PYTEST RUN → recursive
# pytest invocation → hang past the 60s test-timeout.
#
# Fix: store function NAMES; the dispatch loop in main() resolves
# each name via globals() at call time so patches take effect.
ALL_CHECKS: list[tuple[str, str]] = [
    ("tests",          "check_tests"),
    ("lint",           "check_lint"),
    ("types",          "check_types"),
    ("git_activity",   "check_git_activity"),
    ("todo_inventory", "check_todo_inventory"),
    ("lazy_imports",   "check_lazy_imports"),
    ("large_files",    "check_large_files"),
    ("test_coverage",  "check_test_coverage"),
    ("migrations",     "check_migrations"),
]


def _load_baseline(path: str) -> dict | None:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-json", default="nightly_audit.json",
        help="Write the JSON digest to this path.",
    )
    parser.add_argument(
        "--baseline", default=None,
        help="Compare against a previous digest (yesterday's).",
    )
    parser.add_argument(
        "--skip", default="",
        help="Comma-separated check names to skip (e.g. tests,types).",
    )
    parser.add_argument(
        "--only", default="",
        help="Comma-separated check names to run (mutually exclusive "
             "with --skip).",
    )
    parser.add_argument(
        "--llm-review", action="store_true",
        help="Append an LLM narrative review (requires "
             "ANTHROPIC_API_KEY).",
    )
    parser.add_argument(
        "--tests-timeout-s", type=float, default=600.0,
        help="Pytest timeout in seconds (default 600).",
    )
    args = parser.parse_args(argv)

    if args.skip and args.only:
        print("ERROR: --skip and --only are mutually exclusive.",
              file=sys.stderr)
        return 2

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    baseline = _load_baseline(args.baseline) if args.baseline else None

    results: list[CheckResult] = []
    for name, fn_name in ALL_CHECKS:
        if only and name not in only:
            continue
        if name in skip:
            results.append(CheckResult(
                name=name, status="skipped",
                summary=f"{name} skipped via --skip",
            ))
            continue
        try:
            # Late-bind: resolve the check function via the module's
            # globals so unittest.mock.patch.object(audit_module,
            # "check_tests", ...) actually substitutes here.
            fn = globals()[fn_name]
            kwargs: dict[str, Any] = {}
            if name in ("todo_inventory", "large_files"):
                kwargs["baseline"] = baseline
            if name == "tests":
                kwargs["timeout_s"] = args.tests_timeout_s
            r = fn(**kwargs)
        except Exception as exc:  # noqa: BLE001
            r = CheckResult(
                name=name, status="error",
                summary=f"{name} crashed: {type(exc).__name__}: {exc}",
            )
        results.append(r)
        print(f"[{r.status.upper():7}] {r.name:18}{r.summary}",
              file=sys.stderr)

    digest = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_head": _run(
            ["git", "rev-parse", "HEAD"], timeout=10,
        )[1].strip(),
        "checks": {r.name: asdict(r) for r in results},
        "any_red_line": any(r.red_line for r in results),
    }

    # Optional LLM step uses the digest itself.
    if args.llm_review and not (only and "llm_review" not in only):
        llm = check_llm_review(digest)
        digest["checks"]["llm_review"] = asdict(llm)
        print(f"[{llm.status.upper():7}] {llm.name:18}{llm.summary}",
              file=sys.stderr)

    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(digest, indent=2, default=str), encoding="utf-8",
    )
    print(f"\nDigest written to: {out_path}", file=sys.stderr)

    return 1 if digest["any_red_line"] else 0


if __name__ == "__main__":
    sys.exit(main())
