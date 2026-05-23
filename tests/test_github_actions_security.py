"""Security audit for GitHub Actions workflows.

If no workflows exist, this is a no-op assertion documenting that fact.
Once workflows are added under .github/workflows/, expand this file with
the RED tests scaffolded below (pull_request_target+secrets, SHA pinning,
explicit permissions blocks, persist-credentials=false on checkout, etc.).
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _workflow_files() -> list[Path]:
    if not WORKFLOWS_DIR.is_dir():
        return []
    return sorted(
        p for p in WORKFLOWS_DIR.iterdir()
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
    )


def test_no_workflows_or_audit_applies() -> None:
    """Baseline: either there are zero workflows, or the audit tests below run.

    This single assertion documents that as of the audit, no
    .github/workflows/*.yml files exist in the repository, so the
    pull_request_target / SHA-pinning / permissions checks are vacuously
    satisfied. When workflows are introduced, replace this with the full
    suite (see module docstring).
    """
    assert _workflow_files() == [], (
        "Workflows exist; replace this placeholder test with the full "
        "GitHub Actions security audit suite."
    )
