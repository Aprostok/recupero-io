"""Tests for scripts/nightly_audit.py.

Exercises the orchestrator + the parsing logic of each check.
External tools (pytest, ruff, mypy, git) are mocked via patching
``_run`` so the test doesn't depend on which versions of those
tools are installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "nightly_audit.py"


@pytest.fixture(scope="module")
def audit_module():
    """Import scripts/nightly_audit as a module. Registers in
    sys.modules so dataclass introspection (which looks up the
    class's defining module via sys.modules[__module__]) works."""
    import importlib.util
    mod_name = "nightly_audit_under_test"
    spec = importlib.util.spec_from_file_location(
        mod_name, SCRIPT_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    # CRITICAL: register BEFORE exec so dataclass field resolution
    # can find the module's namespace.
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop(mod_name, None)


# ─────────────────────────────────────────────────────────────────────────────
# CheckResult shape
# ─────────────────────────────────────────────────────────────────────────────


def test_check_result_has_uniform_shape(audit_module):
    """Every check returns the same dataclass shape — guarantees the
    JSON digest is parseable downstream."""
    r = audit_module.CheckResult(
        name="x", status="ok", summary="placeholder",
    )
    assert r.name == "x"
    assert r.status == "ok"
    assert r.duration_s == 0.0
    assert r.data == {}
    assert r.red_line is False


# ─────────────────────────────────────────────────────────────────────────────
# A. pytest parser
# ─────────────────────────────────────────────────────────────────────────────


def test_check_tests_parses_passed_count(audit_module):
    fake_out = (
        "................................                                  [100%]\n"
        "============================== slowest 10 durations ==============================\n"
        "1.23s call     tests/test_foo.py::test_bar\n"
        "0.45s setup    tests/test_baz.py::test_qux\n"
        "==================== 1807 passed, 6 skipped in 130.45s ====================\n"
    )
    with patch.object(audit_module, "_run", return_value=(0, fake_out, "")):
        r = audit_module.check_tests(timeout_s=60)
    assert r.status == "ok"
    assert r.data["counts"]["passed"] == 1807
    assert r.data["counts"]["skipped"] == 6
    assert r.data["counts"]["failed"] == 0
    assert r.red_line is False
    assert len(r.data["slowest_tests"]) >= 1
    assert r.data["slowest_tests"][0]["seconds"] == 1.23


def test_check_tests_red_lines_on_failure(audit_module):
    fake_out = (
        "................F.......                                          [100%]\n"
        "==================== 50 passed, 2 failed in 12.3s ====================\n"
    )
    with patch.object(audit_module, "_run", return_value=(1, fake_out, "")):
        r = audit_module.check_tests(timeout_s=60)
    assert r.status == "fail"
    assert r.red_line is True
    assert r.data["counts"]["failed"] == 2


def test_check_tests_timeout(audit_module):
    """A -1 return code from _run indicates timeout; check sets
    status=error + red_line=True."""
    with patch.object(audit_module, "_run", return_value=(-1, "", "[timeout 60s]")):
        r = audit_module.check_tests(timeout_s=60)
    assert r.status == "error"
    assert r.red_line is True


# ─────────────────────────────────────────────────────────────────────────────
# B. ruff parser
# ─────────────────────────────────────────────────────────────────────────────


def test_check_lint_groups_by_rule(audit_module):
    fake = [
        {"code": "F401", "filename": "src/x.py",
         "location": {"row": 12}, "message": "unused import"},
        {"code": "F401", "filename": "src/y.py",
         "location": {"row": 4}, "message": "unused import"},
        {"code": "E501", "filename": "src/z.py",
         "location": {"row": 99}, "message": "line too long"},
    ]
    with patch.object(
        audit_module, "_run", return_value=(0, json.dumps(fake), ""),
    ):
        r = audit_module.check_lint()
    assert r.data["by_rule"]["F401"] == 2
    assert r.data["by_rule"]["E501"] == 1
    assert r.status == "warn"


def test_check_lint_skipped_when_ruff_missing(audit_module):
    with patch.object(audit_module, "_run", return_value=(-2, "", "no ruff")):
        r = audit_module.check_lint()
    assert r.status == "skipped"


def test_check_lint_empty_clean(audit_module):
    with patch.object(audit_module, "_run", return_value=(0, "[]", "")):
        r = audit_module.check_lint()
    assert r.status == "ok"
    assert r.data["by_rule"] == {}


# ─────────────────────────────────────────────────────────────────────────────
# C. mypy parser
# ─────────────────────────────────────────────────────────────────────────────


def test_check_types_counts_errors_by_file(audit_module):
    fake_out = (
        "src/recupero/foo.py:12: error: Incompatible types\n"
        "src/recupero/foo.py:30: error: Returning Any from typed func\n"
        "src/recupero/bar.py:5: error: Missing return type\n"
        "src/recupero/bar.py:8: note: see other line\n"   # note, not error
    )
    with patch.object(audit_module, "_run", return_value=(1, fake_out, "")):
        r = audit_module.check_types()
    assert r.data["errors_by_file"]["src/recupero/foo.py"] == 2
    assert r.data["errors_by_file"]["src/recupero/bar.py"] == 1
    assert r.status == "warn"


# ─────────────────────────────────────────────────────────────────────────────
# D. git activity parser
# ─────────────────────────────────────────────────────────────────────────────


def test_check_git_activity_counts_commits(audit_module):
    def _fake_run(cmd, **kw):
        if "--since=24 hours ago" in cmd:
            return (0, "abc1234 commit one\ndef5678 commit two\n", "")
        if "--since=7 days ago" in cmd:
            return (
                0,
                "a\nb\nc\nd\ne\n",  # 5 commits
                "",
            )
        if "--shortstat" in cmd:
            return (
                0,
                " 12 files changed, 345 insertions(+), 67 deletions(-)",
                "",
            )
        if "rev-list" in cmd and "--count" in cmd:
            return (0, "3\n", "")
        return (0, "", "")

    with patch.object(audit_module, "_run", side_effect=_fake_run):
        r = audit_module.check_git_activity()
    assert r.data["commits_24h_count"] == 2
    assert r.data["commits_7d_count"] == 5
    assert r.data["ahead_of_upstream"] == 3
    assert "12 files changed" in r.data["diff_7d_shortstat"]


# ─────────────────────────────────────────────────────────────────────────────
# E. TODO inventory + baseline delta
# ─────────────────────────────────────────────────────────────────────────────


def test_check_todo_inventory_finds_markers(audit_module, tmp_path):
    """Create a small fake src tree and ensure the TODO regex catches
    each marker family."""
    fake_src = tmp_path / "src" / "recupero" / "foo"
    fake_src.mkdir(parents=True)
    (fake_src / "bar.py").write_text(
        "# TODO: fix this\n"
        "x = 1  # FIXME later\n"
        "y = 2  # plain comment\n"
        "z = 3  # XXX dangerous\n"
        "w = 4  # HACK temporary workaround\n",
        encoding="utf-8",
    )
    with patch.object(audit_module, "REPO_ROOT", tmp_path):
        r = audit_module.check_todo_inventory()
    assert r.data["total"] == 4
    assert r.data["by_marker"]["TODO"] == 1
    assert r.data["by_marker"]["FIXME"] == 1
    assert r.data["by_marker"]["XXX"] == 1
    assert r.data["by_marker"]["HACK"] == 1


def test_check_todo_inventory_delta_vs_baseline(audit_module, tmp_path):
    fake_src = tmp_path / "src" / "recupero" / "foo"
    fake_src.mkdir(parents=True)
    (fake_src / "bar.py").write_text(
        "# TODO: one\n# TODO: two\n", encoding="utf-8",
    )
    baseline = {
        "checks": {"todo_inventory": {"data": {"total": 5}}}
    }
    with patch.object(audit_module, "REPO_ROOT", tmp_path):
        r = audit_module.check_todo_inventory(baseline=baseline)
    # 2 found, baseline 5 → delta -3 (improvement).
    assert r.data["delta_vs_baseline"] == -3


# ─────────────────────────────────────────────────────────────────────────────
# F. Lazy-import smell counter
# ─────────────────────────────────────────────────────────────────────────────


def test_check_lazy_imports_counts_indented_imports_only(audit_module, tmp_path):
    fake_src = tmp_path / "src" / "recupero" / "bar"
    fake_src.mkdir(parents=True)
    (fake_src / "mod.py").write_text(
        "import os  # top-level, not counted\n"
        "from sys import path  # top-level, not counted\n"
        "\n"
        "def f():\n"
        "    from collections import OrderedDict  # COUNTED\n"
        "    import json  # COUNTED\n"
        "    return OrderedDict()\n",
        encoding="utf-8",
    )
    with patch.object(audit_module, "REPO_ROOT", tmp_path):
        r = audit_module.check_lazy_imports()
    assert r.data["total"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# G. Large files + growth tracking
# ─────────────────────────────────────────────────────────────────────────────


def test_check_large_files_detects_growth_vs_baseline(audit_module, tmp_path):
    fake_src = tmp_path / "src" / "recupero" / "x"
    fake_src.mkdir(parents=True)
    big = fake_src / "huge.py"
    big.write_text("\n".join(f"# line {i}" for i in range(700)), encoding="utf-8")
    baseline = {
        "checks": {"large_files": {"data": {"all_sizes": {
            "src/recupero/x/huge.py": 500,
        }}}}
    }
    with patch.object(audit_module, "REPO_ROOT", tmp_path):
        r = audit_module.check_large_files(baseline=baseline)
    assert any(
        item["file"] == "src/recupero/x/huge.py"
        for item in r.data["grew_vs_baseline"]
    )
    assert r.status == "warn"


# ─────────────────────────────────────────────────────────────────────────────
# I. Migrations
# ─────────────────────────────────────────────────────────────────────────────


def test_check_migrations_counts(audit_module):
    """The real migrations/ directory has 20+ files; just verify the
    count check returns a positive number with the expected shape."""
    r = audit_module.check_migrations()
    assert r.status in ("ok", "skipped")
    if r.status == "ok":
        assert r.data["count"] > 0
        assert isinstance(r.data["files"], list)


# ─────────────────────────────────────────────────────────────────────────────
# J. LLM review — gated on env var
# ─────────────────────────────────────────────────────────────────────────────


def test_llm_review_skipped_when_api_key_unset(audit_module, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    digest = {"checks": {}}
    r = audit_module.check_llm_review(digest)
    assert r.status == "skipped"


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator: --skip / --only / exit code
# ─────────────────────────────────────────────────────────────────────────────


def test_main_writes_digest_to_file(audit_module, tmp_path, monkeypatch):
    """End-to-end: run main() with --only=migrations, which is cheap
    and doesn't shell out; assert the digest file lands on disk."""
    out = tmp_path / "digest.json"
    monkeypatch.chdir(REPO_ROOT)
    rc = audit_module.main([
        "--out-json", str(out),
        "--only", "migrations",
    ])
    assert rc == 0
    digest = json.loads(out.read_text(encoding="utf-8"))
    assert "checks" in digest
    assert "migrations" in digest["checks"]
    # Other checks recorded as not run (because --only).
    assert "tests" not in digest["checks"]


def test_main_skip_and_only_mutually_exclusive(audit_module, tmp_path):
    rc = audit_module.main([
        "--out-json", str(tmp_path / "digest.json"),
        "--skip", "tests",
        "--only", "migrations",
    ])
    assert rc == 2


def test_main_red_line_propagates_to_exit_code(audit_module, tmp_path, monkeypatch):
    """Force the tests check to fail by patching to return a red-line
    result; assert main() returns 1."""
    monkeypatch.chdir(REPO_ROOT)
    out = tmp_path / "digest.json"

    fail_result = audit_module.CheckResult(
        name="tests", status="fail", summary="X failed",
        red_line=True,
    )
    with patch.object(
        audit_module, "check_tests", return_value=fail_result,
    ):
        rc = audit_module.main([
            "--out-json", str(out),
            "--only", "tests",
        ])
    assert rc == 1
    digest = json.loads(out.read_text(encoding="utf-8"))
    assert digest["any_red_line"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Smoke: import-as-script doesn't crash on a fresh checkout
# ─────────────────────────────────────────────────────────────────────────────


def test_script_runs_help_without_crashing():
    """Belt-and-suspenders: `python scripts/nightly_audit.py --help`
    must not raise."""
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    assert "Nightly Recupero codebase audit" in proc.stdout
