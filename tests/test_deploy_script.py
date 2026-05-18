"""Tests for scripts/deploy_to_production.py — pure functions only.

DB / git / network calls are mocked. We verify:
  * discover_migration_files sorts deterministically
  * file_sha256 is stable + correct
  * preflight_git_state detects dirty working copies
  * run_smoke_checks invokes the script + parses output
  * check_deployed_health handles HTTP success / failure / version mismatch
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

# Load deploy_to_production.py as a module (it's not in src/ — it's a
# script). Import via spec so test discovery finds it. The module
# MUST be registered in sys.modules BEFORE exec_module so dataclass
# field type-hint resolution works (the @dataclass decorator looks up
# the module via cls.__module__ → sys.modules).
_REPO_ROOT = Path(__file__).parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "deploy_to_production.py"
_spec = importlib.util.spec_from_file_location("deploy_to_production", _SCRIPT_PATH)
deploy = importlib.util.module_from_spec(_spec)
sys.modules["deploy_to_production"] = deploy
_spec.loader.exec_module(deploy)


# ---- discover_migration_files ---- #


def test_discover_returns_empty_for_nonexistent_dir() -> None:
    with TemporaryDirectory() as tmp:
        non_existent = Path(tmp) / "nope"
        assert deploy.discover_migration_files(non_existent) == []


def test_discover_returns_sql_files_sorted() -> None:
    with TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "003_third.sql").write_text("-- 3")
        (d / "001_first.sql").write_text("-- 1")
        (d / "002_second.sql").write_text("-- 2")
        # Non-SQL files should be filtered out.
        (d / "README.md").write_text("readme")
        (d / "notes.txt").write_text("notes")
        files = deploy.discover_migration_files(d)
    names = [f.name for f in files]
    assert names == ["001_first.sql", "002_second.sql", "003_third.sql"]


def test_discover_filters_directories() -> None:
    """A subdirectory matching *.sql shouldn't accidentally be
    treated as a migration file."""
    with TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "001_first.sql").write_text("-- 1")
        sub = d / "subdir.sql"
        sub.mkdir()
        files = deploy.discover_migration_files(d)
    assert len(files) == 1
    assert files[0].name == "001_first.sql"


def test_discover_returns_committed_migrations() -> None:
    """The real migrations dir should yield migrations 001-013."""
    files = deploy.discover_migration_files()
    assert len(files) >= 13
    names = [f.name for f in files]
    assert "001_watchlist.sql" in names
    assert "011_address_observations.sql" in names
    assert "013_freeze_outcomes.sql" in names


# ---- file_sha256 ---- #


def test_sha256_stable_for_same_content() -> None:
    with TemporaryDirectory() as tmp:
        p = Path(tmp) / "test.sql"
        p.write_text("CREATE TABLE foo (id INT);")
        h1 = deploy.file_sha256(p)
        h2 = deploy.file_sha256(p)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex


def test_sha256_changes_with_content() -> None:
    with TemporaryDirectory() as tmp:
        p1 = Path(tmp) / "a.sql"
        p2 = Path(tmp) / "b.sql"
        p1.write_text("ALTER TABLE foo ADD COLUMN x INT;")
        p2.write_text("ALTER TABLE foo ADD COLUMN y INT;")
        assert deploy.file_sha256(p1) != deploy.file_sha256(p2)


# ---- preflight_git_state ---- #


def test_preflight_detects_clean_working_copy() -> None:
    """With git mocked to report no changes, preflight passes."""
    def _mock_run(args):
        if args == ["status", "--porcelain"]:
            return 0, ""
        if args == ["rev-parse", "--short", "HEAD"]:
            return 0, "abc1234"
        if args == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return 0, "main"
        return 0, ""

    with patch.object(deploy, "_run_git", side_effect=_mock_run):
        result = deploy.preflight_git_state()
    assert result.ok is True
    assert "abc1234" in result.detail
    assert "main" in result.detail


def test_preflight_detects_dirty_working_copy() -> None:
    """If `git status --porcelain` returns lines, preflight fails."""
    def _mock_run(args):
        if args == ["status", "--porcelain"]:
            return 0, " M src/recupero/cli.py\n?? scripts/temp.py"
        return 0, "abc1234"

    with patch.object(deploy, "_run_git", side_effect=_mock_run):
        result = deploy.preflight_git_state()
    assert result.ok is False
    assert "uncommitted" in result.detail.lower()


def test_preflight_warns_on_non_main_branch() -> None:
    """A clean working copy on a feature branch should pass with
    a warning."""
    def _mock_run(args):
        if args == ["status", "--porcelain"]:
            return 0, ""
        if args == ["rev-parse", "--short", "HEAD"]:
            return 0, "abc1234"
        if args == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return 0, "pdf-deliverables"
        return 0, ""

    with patch.object(deploy, "_run_git", side_effect=_mock_run):
        result = deploy.preflight_git_state()
    assert result.ok is True
    assert any("pdf-deliverables" in w for w in result.warnings)


def test_preflight_handles_git_unavailable() -> None:
    """If git itself fails (not installed, not a repo), preflight
    reports the error, doesn't crash."""
    def _mock_run(args):
        return 128, "fatal: not a git repository"

    with patch.object(deploy, "_run_git", side_effect=_mock_run):
        result = deploy.preflight_git_state()
    assert result.ok is False


# ---- run_smoke_checks ---- #


def test_run_smoke_checks_parses_output() -> None:
    """If the smoke script returns rc=0 with [OK] lines, we parse
    those into the detail."""
    from unittest.mock import MagicMock
    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = (
        "=== smoke ===\n"
        "[OK ] smoke_bitcoin: Esplora OK\n"
        "[OK ] smoke_tron: TronGrid OK\n"
        "All smoke checks passed\n"
    )
    with patch("subprocess.run", return_value=fake_proc):
        result = deploy.run_smoke_checks()
    assert result.ok is True
    assert "Esplora OK" in result.detail
    assert "TronGrid OK" in result.detail


def test_run_smoke_checks_reports_failure_on_nonzero_rc() -> None:
    from unittest.mock import MagicMock
    fake_proc = MagicMock()
    fake_proc.returncode = 1
    fake_proc.stdout = "[FAIL] smoke_tron: ...\n"
    with patch("subprocess.run", return_value=fake_proc):
        result = deploy.run_smoke_checks()
    assert result.ok is False
    assert "FAIL" in result.detail


def test_run_smoke_checks_handles_missing_script() -> None:
    """If the smoke script file doesn't exist, fail cleanly."""
    fake_path = _REPO_ROOT / "scripts" / "nonexistent_smoke.py"
    with patch.object(deploy, "_SMOKE_SCRIPT", fake_path):
        result = deploy.run_smoke_checks()
    assert result.ok is False
    assert "not found" in result.detail


# ---- check_deployed_health ---- #


def test_check_deployed_health_success() -> None:
    """A 200 response with a version field passes."""
    import httpx
    from unittest.mock import MagicMock

    def _mock_get(url, timeout):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "0.14.6", "git_sha": "63fb294"}
        return resp

    with patch("httpx.get", side_effect=_mock_get), patch.object(
        deploy, "_run_git", side_effect=lambda args: (0, "63fb294"),
    ):
        result = deploy.check_deployed_health("https://recupero.io/health")
    assert result.ok is True
    assert "0.14.6" in result.detail


def test_check_deployed_health_unreachable() -> None:
    """ConnectError → ok=False with informative detail."""
    import httpx

    def _mock_get(url, timeout):
        raise httpx.ConnectError("dns failed")

    with patch("httpx.get", side_effect=_mock_get):
        result = deploy.check_deployed_health("https://recupero.io/health")
    assert result.ok is False
    assert "unreachable" in result.detail


def test_check_deployed_health_warns_on_sha_mismatch() -> None:
    """If the deployed git_sha doesn't match local HEAD, warn but
    don't fail — Railway may legitimately lag behind."""
    from unittest.mock import MagicMock

    def _mock_get(url, timeout):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "0.14.5", "git_sha": "deadbeef"}
        return resp

    with patch("httpx.get", side_effect=_mock_get), patch.object(
        deploy, "_run_git", side_effect=lambda args: (0, "63fb294"),
    ):
        result = deploy.check_deployed_health("https://recupero.io/health")
    assert result.ok is True
    assert any("git_sha" in w for w in result.warnings)


def test_check_deployed_health_non_2xx_fails() -> None:
    from unittest.mock import MagicMock

    def _mock_get(url, timeout):
        resp = MagicMock()
        resp.status_code = 503
        resp.text = "Service Unavailable"
        return resp

    with patch("httpx.get", side_effect=_mock_get):
        result = deploy.check_deployed_health("https://recupero.io/health")
    assert result.ok is False
    assert "503" in result.detail


# ---- DeployReport.ok ---- #


def test_report_ok_true_when_all_steps_pass() -> None:
    r = deploy.DeployReport()
    r.steps.append(deploy.StepResult("a", ok=True))
    r.steps.append(deploy.StepResult("b", ok=True))
    assert r.ok is True


def test_report_ok_false_when_any_step_fails() -> None:
    r = deploy.DeployReport()
    r.steps.append(deploy.StepResult("a", ok=True))
    r.steps.append(deploy.StepResult("b", ok=False))
    assert r.ok is False


def test_report_ok_true_for_empty() -> None:
    r = deploy.DeployReport()
    assert r.ok is True  # vacuous truth — no failures recorded
