"""Adversarial-input audit for scripts/*.py.

Static / behavioural checks that scripts/ helpers do NOT contain known-
bad patterns (shell=True string interpolation, pickle.load on untrusted
input, eval/exec, f-string SQL with user input). Also exercises the
path-traversal hardening added to ``download_validation_briefs.py``.

Production-facing scripts in scripts/ get invoked by operators with
attacker-influenced arguments (investigation_id from a bucket listing,
chain names from victim tipoffs, SQL files from the migrations/ dir).
A single ``shell=True`` slip or unchecked ``Path / argv[1]`` would be a
real RCE / arbitrary-write vector. This test fixes the bar in CI so
future commits to scripts/ can't regress.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
_PY_FILES = sorted(p for p in _SCRIPTS_DIR.glob("*.py") if p.is_file())

# mutation_smoke.py contains shell-out / subprocess machinery as part
# of its harness; the audit task explicitly excludes it.
_EXCLUDE = {"mutation_smoke.py"}
_AUDIT_FILES = [p for p in _PY_FILES if p.name not in _EXCLUDE]


def _ids(paths: list[Path]) -> list[str]:
    return [p.name for p in paths]


def test_scripts_dir_has_python_files():
    """Sanity: at least one .py under scripts/ for the audit to bite."""
    assert _AUDIT_FILES, "expected at least one python helper under scripts/"


@pytest.mark.parametrize("path", _AUDIT_FILES, ids=_ids(_AUDIT_FILES))
def test_no_shell_true_subprocess(path: Path):
    """subprocess.run/Popen with shell=True + interpolation is the
    classic RCE footgun. None of our scripts need it (we always pass
    list-form argv), so ban it outright."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    bad.append(f"line {kw.lineno}: shell=True")
    assert not bad, f"{path.name}: shell=True usage forbidden -> {bad}"


@pytest.mark.parametrize("path", _AUDIT_FILES, ids=_ids(_AUDIT_FILES))
def test_no_eval_or_exec(path: Path):
    """eval() / exec() on any argument trivially escalates to RCE if
    the input is attacker-influenced. Ban them in scripts/ wholesale."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec"}:
                bad.append(f"line {node.lineno}: {node.func.id}()")
    assert not bad, f"{path.name}: eval/exec forbidden -> {bad}"


@pytest.mark.parametrize("path", _AUDIT_FILES, ids=_ids(_AUDIT_FILES))
def test_no_pickle_load_on_io(path: Path):
    """pickle.load / pickle.loads is RCE if the bytes come from an
    untrusted source. None of our scripts legitimately need pickle."""
    src = path.read_text(encoding="utf-8")
    forbidden = ("pickle.load", "pickle.loads", "cPickle.load")
    hits = [p for p in forbidden if p in src]
    assert not hits, f"{path.name}: forbidden pickle API -> {hits}"


# f-string SQL detection: cur.execute(f"...") is the canonical SQLi
# footgun. psycopg supports %s parameter binding everywhere; any
# f-string into execute() is suspect.
_FSTRING_EXEC = re.compile(r"""\.execute\s*\(\s*f["']""")


@pytest.mark.parametrize("path", _AUDIT_FILES, ids=_ids(_AUDIT_FILES))
def test_no_fstring_sql_execute(path: Path):
    src = path.read_text(encoding="utf-8")
    matches = _FSTRING_EXEC.findall(src)
    assert not matches, (
        f"{path.name}: f-string passed to .execute() — use %s binding"
    )


def test_download_validation_briefs_rejects_path_traversal_id(monkeypatch, capsys):
    """investigation_id is interpolated into a filesystem Path. Reject
    anything that isn't an alphanumeric-ish identifier so an operator
    pasting ``../../etc/passwd`` from a malicious bucket listing can't
    cause us to mkdir/write outside the intended download folder."""
    spec = importlib.util.spec_from_file_location(
        "_dvb_for_test",
        _SCRIPTS_DIR / "download_validation_briefs.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Loading the module imports recupero.* — if that fails (e.g.
    # supabase deps missing in CI), the test should xfail informatively
    # rather than masquerade as a real audit failure.
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # pragma: no cover - environmental
        pytest.skip(f"module not importable in this env: {exc!r}")

    for bad in ("..", "../etc", "a/b", r"a\b", "/abs", ""):
        monkeypatch.setattr(sys, "argv", ["download_validation_briefs.py", bad])
        rc = mod.main()
        assert rc == 2, f"expected refusal for investigation_id={bad!r}, got rc={rc}"
        err = capsys.readouterr().err
        assert "investigation_id must match" in err


def test_download_validation_briefs_safe_local_path_blocks_traversal(tmp_path):
    """The bucket-listing path-join helper must refuse ``..`` segments
    and absolute paths inside server-returned filenames."""
    spec = importlib.util.spec_from_file_location(
        "_dvb_for_test2",
        _SCRIPTS_DIR / "download_validation_briefs.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # pragma: no cover - environmental
        pytest.skip(f"module not importable in this env: {exc!r}")

    safe = mod._safe_local_path(tmp_path, "report.pdf")
    assert safe == (tmp_path / "report.pdf").resolve()

    safe_nested = mod._safe_local_path(tmp_path, "sub/report.pdf")
    assert str(safe_nested).startswith(str(tmp_path.resolve()))

    for bad in (
        "../escape.txt",
        "../../etc/passwd",
        "/tmp/abs.txt",
        "\\windows\\abs.txt",
        "",
        "sub/../../escape.txt",
    ):
        with pytest.raises(ValueError):
            mod._safe_local_path(tmp_path, bad)
