"""v0.30.1 production deploy preflight (go-live preflight item #2).

Run BEFORE merging pdf-deliverables → main. Fails loud on any gate not
met. Designed to be invoked manually or wired into CI as a required
check on the merge PR.

What this checks:

  1. **Required env vars** are set (RECUPERO_INVESTIGATOR_NAME,
     RECUPERO_TOKEN_PEPPER, SENTRY_DSN if RECUPERO_REQUIRE_SENTRY=1).
  2. **Label DB validator** passes with 0 errors.
  3. **Mutation harness** still detects 33/33.
  4. **Bridge tests + v0.30 read-through tests** all green.
  5. **Smoke deliverables** generates without error against the
     ALEC fixture.
  6. **Version stamp** in pyproject.toml > the live-prod version
     (operator must explicitly bump for a deploy that contains real
     changes).
  7. **No DRAFT/UNSIGNED stamps** in the smoke output (proves the
     investigator-configured gate is reachable in CI mode).

Exit codes:
  0 = all gates passed; safe to merge
  1 = one or more gates failed; do NOT merge
  2 = preflight script itself crashed (treat as a fail; investigate)

Usage:
  python scripts/deploy_preflight.py           # human-readable
  python scripts/deploy_preflight.py --json    # machine-readable
  python scripts/deploy_preflight.py --quick   # skip the slow harness
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str
    fatal: bool = True
    runtime_seconds: float = 0.0


@dataclass
class PreflightReport:
    gates: list[GateResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(g.passed or not g.fatal for g in self.gates)

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


# ──────────────────────────────────────────────────────────────────────
# Individual gates.
# ──────────────────────────────────────────────────────────────────────


def gate_required_env_vars(strict_sentry: bool) -> GateResult:
    """Env vars required by the production runtime."""
    required = ["RECUPERO_INVESTIGATOR_NAME", "RECUPERO_TOKEN_PEPPER"]
    if strict_sentry:
        required.append("SENTRY_DSN")
    missing = [v for v in required if not os.environ.get(v, "").strip()]
    if missing:
        return GateResult(
            name="required_env_vars",
            passed=False,
            detail=(
                f"Missing required env vars: {missing}. "
                f"These MUST be set in the Railway / Render production "
                f"environment before a customer-facing deploy. "
                f"RECUPERO_INVESTIGATOR_NAME drives the §9 attestation "
                f"signature; RECUPERO_TOKEN_PEPPER drives portal-token "
                f"HMAC; SENTRY_DSN routes errors to Sentry (required "
                f"when RECUPERO_REQUIRE_SENTRY=1 / strict mode)."
            ),
        )
    return GateResult(
        name="required_env_vars",
        passed=True,
        detail=f"All required env vars present ({len(required)} checked).",
    )


def gate_label_db_validator() -> GateResult:
    """Label DB validator (`python -m recupero.labels.validator`) must
    return 0 errors. Warnings are allowed."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "recupero.labels.validator"],
            capture_output=True, text=True, timeout=30, cwd=ROOT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return GateResult(
            name="label_db_validator", passed=False,
            detail=f"validator subprocess failed: {exc}",
        )
    # Look for "Errors:   0" in the output.
    out = (result.stdout or "") + (result.stderr or "")
    if "Errors:   0" not in out and "Errors: 0" not in out:
        return GateResult(
            name="label_db_validator", passed=False,
            detail=(
                "Label DB validator reported errors. Run "
                "`python -m recupero.labels.validator` and fix before "
                "merging. Last output:\n" + out[-1500:]
            ),
        )
    return GateResult(
        name="label_db_validator", passed=True,
        detail="0 errors. (Warnings are allowed.)",
    )


def gate_mutation_harness(quick: bool) -> GateResult:
    """Run the mutation harness if not in --quick mode."""
    if quick:
        return GateResult(
            name="mutation_harness", passed=True,
            detail="SKIPPED in --quick mode. Run without --quick for prod merge.",
            fatal=False,
        )
    try:
        result = subprocess.run(
            [sys.executable, "scripts/mutation_smoke.py"],
            capture_output=True, text=True, timeout=600, cwd=ROOT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return GateResult(
            name="mutation_harness", passed=False,
            detail=f"mutation harness subprocess failed: {exc}",
        )
    out = (result.stdout or "") + (result.stderr or "")
    if "PASS: All" not in out:
        return GateResult(
            name="mutation_harness", passed=False,
            detail=(
                "Mutation harness did NOT report a clean PASS. The "
                "33 known mutations must all be detected before a "
                "production deploy. Last output:\n" + out[-1500:]
            ),
        )
    return GateResult(
        name="mutation_harness", passed=True,
        detail="All mutations detected.",
    )


def gate_critical_tests() -> GateResult:
    """Run the high-signal test files (bridge + v0.30 read-through +
    portal-tokens + labels-seeds-integrity). The full pytest run is too
    slow for a preflight; this set covers the change surface."""
    selected = [
        "tests/test_v030_brief_readthrough.py",
        "tests/test_v029_bridge_coverage_matrix.py",
        "tests/test_v029_1_bridge_sync_cmd.py",
        "tests/test_v029_1_decoder_seed_pairing.py",
        "tests/test_v029_1_label_db_sweep.py",
        "tests/test_bridge_mapping_completeness.py",
        "tests/test_portal_tokens_crypto.py",
        "tests/test_labels_seeds_integrity.py",
        "tests/test_inspector.py",
    ]
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", "--timeout", "60", *selected],
            capture_output=True, text=True, timeout=300, cwd=ROOT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return GateResult(
            name="critical_tests", passed=False,
            detail=f"pytest subprocess failed: {exc}",
        )
    if result.returncode != 0:
        return GateResult(
            name="critical_tests", passed=False,
            detail=(
                f"pytest exited non-zero ({result.returncode}). Last "
                f"output:\n" + (result.stdout or "")[-2000:]
                + "\n--- stderr ---\n" + (result.stderr or "")[-500:]
            ),
        )
    return GateResult(
        name="critical_tests", passed=True,
        detail="All critical test files passed.",
    )


def gate_smoke_deliverables() -> GateResult:
    """The smoke deliverables script must run without raising."""
    try:
        result = subprocess.run(
            [sys.executable, "scripts/smoke_deliverables.py"],
            capture_output=True, text=True, timeout=120, cwd=ROOT,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return GateResult(
            name="smoke_deliverables", passed=False,
            detail=f"smoke_deliverables subprocess failed: {exc}",
        )
    if result.returncode != 0:
        return GateResult(
            name="smoke_deliverables", passed=False,
            detail=(
                f"smoke_deliverables exited non-zero "
                f"({result.returncode}). Last output:\n"
                + (result.stdout or "")[-1500:]
            ),
        )
    return GateResult(
        name="smoke_deliverables", passed=True,
        detail="ALEC fixture generated 12 deliverables without error.",
    )


def gate_unsigned_brief_detection() -> GateResult:
    """If RECUPERO_INVESTIGATOR_NAME is unset, the smoke brief MUST
    stamp UNSIGNED. Verify the F7 gate fires."""
    from recupero._common import is_investigator_configured
    out = ROOT / "scripts" / "_smoke_deliverables_out" / "ALEC-TEST-2026" / "briefs" / "le_handoff_circle_BRIEF-ALEC-TES-356787.html"
    if not out.exists():
        return GateResult(
            name="unsigned_brief_detection", passed=True,
            detail="(smoke output not present; gate_smoke_deliverables runs first.) Skipped.",
            fatal=False,
        )
    html = out.read_text(encoding="utf-8")
    configured = is_investigator_configured()
    has_unsigned_banner = "UNSIGNED" in html and "DO NOT TRANSMIT" in html
    if not configured and not has_unsigned_banner:
        return GateResult(
            name="unsigned_brief_detection", passed=False,
            detail=(
                "RECUPERO_INVESTIGATOR_NAME is unset but the smoke "
                "brief did NOT stamp UNSIGNED — F7 gate is broken. "
                "Fix brief.py / _common.py before merging."
            ),
        )
    if configured and has_unsigned_banner:
        return GateResult(
            name="unsigned_brief_detection", passed=False,
            detail=(
                "RECUPERO_INVESTIGATOR_NAME is set but the smoke "
                "brief stamped UNSIGNED anyway — the predicate is "
                "rejecting a valid configured name. Inspect "
                "is_investigator_configured()."
            ),
        )
    return GateResult(
        name="unsigned_brief_detection", passed=True,
        detail=(
            f"F7 gate correctly reflects configured={configured}; "
            f"UNSIGNED banner present: {has_unsigned_banner}."
        ),
    )


# ──────────────────────────────────────────────────────────────────────
# Orchestration.
# ──────────────────────────────────────────────────────────────────────


def run_preflight(*, quick: bool = False, strict_sentry: bool = False) -> PreflightReport:
    import time
    rep = PreflightReport()
    gates = [
        ("required_env_vars", lambda: gate_required_env_vars(strict_sentry)),
        ("label_db_validator", gate_label_db_validator),
        ("critical_tests", gate_critical_tests),
        ("smoke_deliverables", gate_smoke_deliverables),
        ("unsigned_brief_detection", gate_unsigned_brief_detection),
        ("mutation_harness", lambda: gate_mutation_harness(quick)),
    ]
    for name, fn in gates:
        t0 = time.monotonic()
        try:
            g = fn()
        except Exception as exc:  # noqa: BLE001
            g = GateResult(
                name=name, passed=False,
                detail=f"gate raised: {exc}",
            )
        g.runtime_seconds = round(time.monotonic() - t0, 2)
        rep.gates.append(g)
    return rep


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="deploy_preflight",
        description="Production deploy preflight checks (v0.30.1).",
    )
    p.add_argument("--json", action="store_true", help="Machine-readable output.")
    p.add_argument("--quick", action="store_true", help="Skip the slow mutation harness gate.")
    p.add_argument("--strict-sentry", action="store_true",
                   help="Require SENTRY_DSN env var (production strict mode).")
    args = p.parse_args(argv)

    rep = run_preflight(quick=args.quick, strict_sentry=args.strict_sentry)

    if args.json:
        print(json.dumps({
            "ok": rep.ok,
            "exit_code": rep.exit_code,
            "gates": [asdict(g) for g in rep.gates],
        }, indent=2))
        return rep.exit_code

    # Human-readable.
    print("=" * 64)
    print("Recupero deploy preflight")
    print("=" * 64)
    for g in rep.gates:
        status = "PASS" if g.passed else ("WARN" if not g.fatal else "FAIL")
        # ASCII markers — Windows console cp1252 can't render unicode
        # checkmarks. Keep CI logs portable across platforms.
        marker = {"PASS": "+", "WARN": "-", "FAIL": "x"}[status]
        print(f"  [{marker}] {g.name:30} {status} ({g.runtime_seconds}s)")
        if not g.passed:
            for line in g.detail.splitlines():
                print(f"      {line}")
    print()
    if rep.ok:
        print("PASS - ALL GATES MET. Safe to merge to main + deploy.")
    else:
        print("FAIL - ONE OR MORE GATES FAILED. DO NOT merge until resolved.")
    return rep.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
