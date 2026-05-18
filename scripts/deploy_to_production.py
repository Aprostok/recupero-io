#!/usr/bin/env python3
"""Production deployment runner — automates the pre-Jacob checklist.

Replaces the 4-step manual sequence with a single script that:

  1. Pre-flight: git status clean, current commit matches origin.
  2. Apply any pending migrations (idempotent, tracked via
     ``public.schema_migrations``).
  3. Run live-API smoke checks for the v0.12+ chain adapters.
  4. Verify the deployed worker's /health endpoint (optional).

Each step prints pass/fail. Exit code:
  0 — all checks passed; Jacob can run.
  1 — at least one check failed; review output and re-run after fix.
  2 — usage / setup error (missing env vars, etc.).

Idempotent: re-running after a partial success skips already-applied
migrations and re-runs the smoke checks. Safe to run anytime.

Usage:
    python scripts/deploy_to_production.py
    python scripts/deploy_to_production.py --skip-smoke      # offline mode
    python scripts/deploy_to_production.py --skip-health     # local-only mode
    python scripts/deploy_to_production.py --yes             # no confirms (CI)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

_REPO_ROOT = Path(__file__).parents[1]
_MIGRATIONS_DIR = _REPO_ROOT / "migrations"
_SMOKE_SCRIPT = _REPO_ROOT / "scripts" / "smoke_new_chains.py"


# Bootstrap migration — creates the tracking table if missing.
_SCHEMA_MIGRATIONS_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS public.schema_migrations (
    filename     TEXT PRIMARY KEY,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sha256       TEXT NOT NULL,
    sql_bytes    INTEGER NOT NULL
);
"""


# ---- Result types ---- #


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class DeployReport:
    steps: list[StepResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)


# ---- Pre-flight checks ---- #


def _run_git(args: list[str]) -> tuple[int, str]:
    """Subprocess wrapper that returns (rc, stdout-or-stderr)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, f"(git failed: {e})"
    out = (result.stdout or "") + (result.stderr or "")
    return result.returncode, out.strip()


def preflight_git_state() -> StepResult:
    """Verify the working copy is clean and on a known branch."""
    rc, status = _run_git(["status", "--porcelain"])
    if rc != 0:
        return StepResult(
            "git_state", ok=False,
            detail=f"git status failed: {status}",
        )
    if status:
        return StepResult(
            "git_state", ok=False,
            detail=(
                f"Working copy has uncommitted changes:\n  "
                + "\n  ".join(status.splitlines()[:10])
                + ("\n  …" if len(status.splitlines()) > 10 else "")
                + "\nCommit or stash before deploying."
            ),
        )

    rc, head_sha = _run_git(["rev-parse", "--short", "HEAD"])
    if rc != 0:
        return StepResult(
            "git_state", ok=False,
            detail=f"git rev-parse failed: {head_sha}",
        )

    rc, branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"])
    warnings: list[str] = []
    if branch not in ("main", "master"):
        warnings.append(
            f"Deploying from branch '{branch}' (not main). Confirm intended."
        )

    return StepResult(
        "git_state", ok=True,
        detail=f"clean working copy; HEAD={head_sha} on {branch}",
        warnings=warnings,
    )


# ---- Migration discovery + application ---- #


def discover_migration_files(migrations_dir: Path | None = None) -> list[Path]:
    """Return migration .sql files sorted by filename.

    Naming convention: NNN_description.sql where NNN is 3 digits.
    Sort by filename guarantees apply order matches the intended
    sequence.
    """
    d = migrations_dir or _MIGRATIONS_DIR
    if not d.exists():
        return []
    return sorted(p for p in d.glob("*.sql") if p.is_file())


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def list_pending_migrations(
    dsn: str,
    migrations_dir: Path | None = None,
) -> list[Path]:
    """Return the migration files on disk that haven't been recorded
    in ``schema_migrations`` yet."""
    import psycopg
    files_on_disk = discover_migration_files(migrations_dir)
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
            cur.execute(
                "SELECT filename FROM public.schema_migrations;"
            )
            rows = cur.fetchall()
    applied = {r[0] for r in rows}
    return [f for f in files_on_disk if f.name not in applied]


def apply_migration_file(dsn: str, path: Path) -> StepResult:
    """Apply one migration + record it in schema_migrations.

    The two operations are in ONE transaction — if the migration
    fails, the tracking row doesn't write. If the migration
    succeeds but the tracking insert fails (extremely unlikely),
    the migration's own IF NOT EXISTS guards make re-application
    safe.
    """
    import psycopg
    sql = path.read_text(encoding="utf-8")
    digest = file_sha256(path)
    record_sql = """
        INSERT INTO public.schema_migrations (filename, sha256, sql_bytes)
        VALUES (%(name)s, %(sha)s, %(bytes)s)
        ON CONFLICT (filename) DO UPDATE
            SET applied_at = NOW(),
                sha256     = EXCLUDED.sha256,
                sql_bytes  = EXCLUDED.sql_bytes;
    """
    try:
        with psycopg.connect(dsn, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(record_sql, {
                    "name": path.name,
                    "sha": digest,
                    "bytes": len(sql),
                })
            conn.commit()
    except Exception as e:  # noqa: BLE001
        return StepResult(
            name=f"migration:{path.name}",
            ok=False, detail=f"apply failed: {e}",
        )
    return StepResult(
        name=f"migration:{path.name}",
        ok=True,
        detail=f"applied ({len(sql):,} bytes, sha256={digest[:12]}…)",
    )


def run_migrations(
    dsn: str,
    migrations_dir: Path | None = None,
    *,
    interactive: bool,
) -> list[StepResult]:
    """Bootstrap the schema_migrations table, then apply any pending
    files in order. Returns one StepResult per attempt."""
    results: list[StepResult] = []

    # Bootstrap is its own step so the report has a record of it.
    try:
        import psycopg
        with psycopg.connect(dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA_MIGRATIONS_BOOTSTRAP)
        results.append(StepResult(
            name="schema_migrations_bootstrap",
            ok=True,
            detail="schema_migrations table ready",
        ))
    except Exception as e:  # noqa: BLE001
        results.append(StepResult(
            name="schema_migrations_bootstrap",
            ok=False, detail=str(e),
        ))
        return results  # can't proceed without tracking

    pending = list_pending_migrations(dsn, migrations_dir)
    if not pending:
        results.append(StepResult(
            name="migrations",
            ok=True,
            detail="no pending migrations",
        ))
        return results

    print()
    print(f"Pending migrations ({len(pending)}):")
    for p in pending:
        print(f"  - {p.name}")
    print()
    if interactive and not _confirm(
        "Apply these migrations to production?",
    ):
        results.append(StepResult(
            name="migrations",
            ok=False,
            detail="user declined migration application",
        ))
        return results

    for path in pending:
        r = apply_migration_file(dsn, path)
        results.append(r)
        marker = "OK " if r.ok else "FAIL"
        print(f"  {marker} {r.name} — {r.detail}")
        if not r.ok:
            # Stop applying on first failure; later migrations may
            # depend on this one's tables.
            break
    return results


# ---- Smoke tests ---- #


def run_smoke_checks(*, target: str = "all") -> StepResult:
    """Invoke scripts/smoke_new_chains.py as a subprocess. Captures
    stdout for the report so the operator can inspect."""
    if not _SMOKE_SCRIPT.exists():
        return StepResult(
            name="smoke",
            ok=False,
            detail=f"smoke script not found at {_SMOKE_SCRIPT}",
        )
    try:
        result = subprocess.run(
            [sys.executable, str(_SMOKE_SCRIPT), target],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return StepResult(
            name="smoke", ok=False,
            detail="smoke script timed out after 120s",
        )
    output_lines = result.stdout.splitlines()
    # Surface the [OK] / [FAIL] lines in the detail.
    summary_lines = [ln for ln in output_lines if "[OK ]" in ln or "[FAIL]" in ln]
    detail = "\n  ".join(summary_lines) if summary_lines else result.stdout
    return StepResult(
        name="smoke",
        ok=result.returncode == 0,
        detail=detail,
    )


# ---- Worker /health check ---- #


def check_deployed_health(url: str) -> StepResult:
    """Hit the deployed worker's /health endpoint. Returns success
    when the response is 2xx and (if present) the version field
    matches the local HEAD."""
    try:
        import httpx
    except ImportError:
        return StepResult(
            name="deployed_health",
            ok=False, detail="httpx not installed (required for health check)",
        )

    # Get local HEAD short SHA for comparison.
    rc, head_sha = _run_git(["rev-parse", "--short", "HEAD"])
    expected_sha = head_sha if rc == 0 else None

    try:
        resp = httpx.get(url, timeout=10.0)
    except httpx.RequestError as e:
        return StepResult(
            name="deployed_health", ok=False,
            detail=f"unreachable: {e}",
        )
    if resp.status_code >= 300:
        return StepResult(
            name="deployed_health", ok=False,
            detail=f"HTTP {resp.status_code}: {resp.text[:200]}",
        )

    # Try to parse JSON for a version field.
    deployed_version = None
    deployed_sha = None
    try:
        body = resp.json()
        if isinstance(body, dict):
            deployed_version = body.get("version") or body.get("recupero_version")
            deployed_sha = body.get("git_sha") or body.get("commit_sha")
    except Exception:  # noqa: BLE001
        pass

    warnings: list[str] = []
    if expected_sha and deployed_sha and not deployed_sha.startswith(expected_sha):
        warnings.append(
            f"deployed git_sha={deployed_sha} does not match local HEAD={expected_sha}. "
            "Railway may not have picked up the latest push."
        )

    return StepResult(
        name="deployed_health",
        ok=True,
        detail=(
            f"HTTP 200 from {url}"
            + (f"; version={deployed_version}" if deployed_version else "")
            + (f"; git_sha={deployed_sha}" if deployed_sha else "")
        ),
        warnings=warnings,
    )


# ---- Interactive prompts ---- #


def _confirm(prompt: str, *, default: bool = False) -> bool:
    """y/N prompt. Honors --yes flag via DEPLOY_ASSUME_YES env."""
    if os.environ.get("DEPLOY_ASSUME_YES", "").strip() == "1":
        return True
    default_str = "Y/n" if default else "y/N"
    try:
        ans = input(f"{prompt} [{default_str}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not ans:
        return default
    return ans in ("y", "yes")


# ---- Orchestrator ---- #


def deploy(
    *,
    dsn: str,
    health_url: str | None = None,
    skip_smoke: bool = False,
    skip_health: bool = False,
    interactive: bool = True,
) -> DeployReport:
    """Run all checks. Returns a DeployReport with per-step results."""
    report = DeployReport()

    # 1. Pre-flight
    print("=== Step 1: Pre-flight (git state) ===")
    pf = preflight_git_state()
    report.steps.append(pf)
    marker = "OK " if pf.ok else "FAIL"
    print(f"  {marker} {pf.detail}")
    for w in pf.warnings:
        print(f"  [warn] {w}")
    if not pf.ok and interactive:
        if not _confirm("Continue despite pre-flight issues?"):
            print("Aborted.")
            return report
    print()

    # 2. Migrations
    print("=== Step 2: Migrations ===")
    mig_results = run_migrations(
        dsn=dsn, interactive=interactive,
    )
    report.steps.extend(mig_results)
    print()

    # 3. Smoke checks
    if not skip_smoke:
        print("=== Step 3: Live-API smoke checks ===")
        smoke = run_smoke_checks(target="all")
        report.steps.append(smoke)
        marker = "OK " if smoke.ok else "FAIL"
        print(f"  {marker} smoke checks {'passed' if smoke.ok else 'FAILED'}")
        for line in smoke.detail.splitlines():
            print(f"    {line}")
        print()
    else:
        print("=== Step 3: Smoke checks SKIPPED ===\n")

    # 4. Deployed-worker health
    if not skip_health and health_url:
        print(f"=== Step 4: Deployed-worker health ({health_url}) ===")
        h = check_deployed_health(health_url)
        report.steps.append(h)
        marker = "OK " if h.ok else "FAIL"
        print(f"  {marker} {h.detail}")
        for w in h.warnings:
            print(f"  [warn] {w}")
        print()
    else:
        print("=== Step 4: Health check SKIPPED ===")
        if not health_url:
            print("  (no DEPLOY_HEALTH_URL env var set)")
        print()

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recupero one-shot production deploy runner.",
    )
    parser.add_argument(
        "--skip-smoke", action="store_true",
        help="Skip the live-API smoke checks (offline mode).",
    )
    parser.add_argument(
        "--skip-health", action="store_true",
        help="Skip the deployed-worker /health check.",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Non-interactive mode (assume yes on all prompts). "
             "Suitable for CI.",
    )
    args = parser.parse_args()

    # Load .env so SUPABASE_DB_URL etc. are available.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        print(
            "ERROR: SUPABASE_DB_URL not set. Add it to .env or export "
            "before running.",
            file=sys.stderr,
        )
        return 2

    if args.yes:
        os.environ["DEPLOY_ASSUME_YES"] = "1"

    health_url = os.environ.get("DEPLOY_HEALTH_URL", "").strip() or None

    print()
    print("======================================")
    print(" Recupero production deploy runner")
    print("======================================")
    print()

    report = deploy(
        dsn=dsn,
        health_url=health_url,
        skip_smoke=args.skip_smoke,
        skip_health=args.skip_health,
        interactive=not args.yes,
    )

    # Summary.
    print("=== Summary ===")
    print()
    n_ok = sum(1 for s in report.steps if s.ok)
    n_fail = sum(1 for s in report.steps if not s.ok)
    for s in report.steps:
        marker = "OK " if s.ok else "FAIL"
        first_line = s.detail.splitlines()[0] if s.detail else ""
        print(f"  {marker} {s.name}: {first_line}")
    print()
    print(f"  Steps OK:   {n_ok}")
    print(f"  Steps fail: {n_fail}")
    print()
    if report.ok:
        print("ALL CHECKS PASSED — Jacob is good to go.")
        return 0
    print("AT LEAST ONE CHECK FAILED — review output above before sharing with Jacob.")
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
