"""test_pipeline.py — end-to-end smoke test for the $99 Triage pipeline.

Runs the full Recupero trace → freeze-targets → emit-brief pipeline against
the ALEC-TEST-2026 case and verifies the output at each stage. Designed as a
regression guard: if refactoring breaks the pipeline, this test fails loudly.

Two modes:
  --fast (default): skip `list-freeze-targets` if freeze_asks.json is fresh
                    and has the expected structure. Fast re-runs, no Etherscan
                    API calls, no rate-limit risk. The file's contents are still
                    validated so the test isn't a rubber-stamp.
  --full:           force fresh `list-freeze-targets` run. Takes ~10 minutes,
                    hits Etherscan API 400+ times. Use when you've changed the
                    trace or freeze logic and want to verify it end-to-end.

What it does NOT test:
  - ai-editorial (costs money per run; requires Anthropic API key)
  - JS builders (separate test harness; left for a future integration test)
  - Specific docx content (brittle; docx internals change between library versions)
  - The trace step itself (takes 10+ minutes; assumes case.json already exists)

Usage:
    python test_pipeline.py           # fast mode (default)
    python test_pipeline.py --full    # force regen of freeze_asks.json

Exit codes:
    0 = all checks passed
    1 = one or more checks failed
    2 = setup problem (missing case, missing .env, etc.)

Run from the recupero-io repo root with the venv active.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from decimal import Decimal
from pathlib import Path


# ==================== CONFIG ====================
CASE_ID = "ALEC-TEST-2026"
EXPECTED_LOSS_USD_APPROX = Decimal("21317.94")
LOSS_TOLERANCE_USD = Decimal("500")  # allow small float-to-USD rounding drift

EXPECTED_ISSUERS = {"Circle", "Tether"}
EXPECTED_LOSS_MATCHES_CEILING = True  # MAX_RECOVERABLE should cap at TOTAL_LOSS

# Paths (relative to repo root)
REPO_ROOT = Path(__file__).parent
CASE_DIR = REPO_ROOT / "data" / "cases" / CASE_ID
CASE_JSON = CASE_DIR / "case.json"
FREEZE_ASKS_PATH = CASE_DIR / "freeze_asks.json"
EDITORIAL_PATH = CASE_DIR / "brief_editorial.json"
FREEZE_BRIEF_PATH = CASE_DIR / "freeze_brief.json"


# ==================== HELPERS ====================
class TestFailure(Exception):
    """A test assertion failed."""


class SetupError(Exception):
    """Prerequisite missing — test can't run."""


def run_cli(args: list[str], expect_success: bool = True) -> subprocess.CompletedProcess:
    """Run a `recupero` command and return the result."""
    cmd = ["recupero", *args]
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    if expect_success and result.returncode != 0:
        print(f"    STDOUT: {result.stdout[:500]}")
        print(f"    STDERR: {result.stderr[:500]}")
        raise TestFailure(f"{' '.join(cmd)} exited {result.returncode} (expected success)")
    return result


def parse_usd(s: str) -> Decimal:
    """'$47,840.12' -> Decimal('47840.12'). Returns Decimal('0') on failure."""
    s = str(s or "$0").replace("$", "").replace(",", "").strip()
    try:
        return Decimal(s)
    except Exception:
        return Decimal("0")


def assert_eq(label: str, actual, expected):
    if actual != expected:
        raise TestFailure(f"{label}: expected {expected!r}, got {actual!r}")
    print(f"  ✓ {label}")


def assert_in(label: str, needle, haystack):
    if needle not in haystack:
        raise TestFailure(f"{label}: expected {needle!r} in {haystack!r}")
    print(f"  ✓ {label}")


def assert_close(label: str, actual: Decimal, expected: Decimal, tolerance: Decimal):
    if abs(actual - expected) > tolerance:
        raise TestFailure(
            f"{label}: expected {expected} ± {tolerance}, got {actual} (diff {abs(actual - expected)})"
        )
    print(f"  ✓ {label} ({actual} ≈ {expected})")


def freeze_asks_looks_fresh() -> tuple[bool, str]:
    """Decide whether we can skip list-freeze-targets in fast mode.

    Returns (ok, reason). ok=True means the existing freeze_asks.json is usable
    for validation. reason is a short explanation for the log.
    """
    if not FREEZE_ASKS_PATH.exists():
        return False, "freeze_asks.json does not exist"
    if not CASE_JSON.exists():
        return False, "case.json does not exist (unexpected)"

    # If case.json is newer than freeze_asks.json, the freeze data is stale.
    asks_mtime = FREEZE_ASKS_PATH.stat().st_mtime
    case_mtime = CASE_JSON.stat().st_mtime
    if case_mtime > asks_mtime:
        return False, f"case.json is newer than freeze_asks.json (case was re-traced)"

    # Validate structure — if by_issuer is missing or empty, treat as stale.
    try:
        asks = json.loads(FREEZE_ASKS_PATH.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return False, f"freeze_asks.json is not valid JSON: {e}"
    by_issuer = asks.get("by_issuer", {})
    if not by_issuer:
        return False, "freeze_asks.json has no by_issuer entries"

    return True, f"freeze_asks.json is fresh ({len(by_issuer)} issuers)"


# ==================== CHECKS ====================
def check_setup():
    """Verify prerequisites before running the test."""
    print("\n[Setup check]")

    if not CASE_DIR.exists():
        raise SetupError(
            f"Case directory not found: {CASE_DIR}\n"
            f"  Run `recupero trace` on {CASE_ID} first (see README for flags)."
        )
    print(f"  ✓ Case directory exists: {CASE_DIR}")

    if not CASE_JSON.exists():
        raise SetupError(f"case.json not found in {CASE_DIR}")
    print(f"  ✓ case.json exists")

    victim_json = CASE_DIR / "victim.json"
    if not victim_json.exists():
        raise SetupError(f"victim.json not found in {CASE_DIR}")
    print(f"  ✓ victim.json exists")

    # Ensure the recupero CLI is importable / on PATH
    result = subprocess.run(["recupero", "--help"], capture_output=True, text=True, cwd=REPO_ROOT)
    if result.returncode != 0:
        raise SetupError(
            "`recupero --help` failed. Is the venv active? Did you `pip install -e .`?"
        )
    print(f"  ✓ recupero CLI is on PATH")


def step_1_list_freeze_targets(full_mode: bool):
    """Stage 1: ensure freeze_asks.json exists and has Circle + Tether entries.

    In --full mode, always runs the CLI (10-minute scan).
    In --fast mode (default), skips the CLI call if the existing file is fresh
    and has the expected structure — but still validates its contents.
    """
    print("\n[Step 1: freeze_asks.json has Circle + Tether]")

    ran_cli = False
    if full_mode:
        print("  --full mode: regenerating freeze_asks.json (this takes ~10 min)")
        if FREEZE_ASKS_PATH.exists():
            FREEZE_ASKS_PATH.unlink()
            print(f"  (deleted existing {FREEZE_ASKS_PATH.name})")
        run_cli(["list-freeze-targets", CASE_ID, "--min-usd", "1000"])
        ran_cli = True
    else:
        fresh, reason = freeze_asks_looks_fresh()
        if fresh:
            print(f"  (fast mode) skipping CLI call: {reason}")
        else:
            print(f"  (fast mode) CLI call needed: {reason}")
            run_cli(["list-freeze-targets", CASE_ID, "--min-usd", "1000"])
            ran_cli = True

    # Either way, the file must exist now.
    if not FREEZE_ASKS_PATH.exists():
        raise TestFailure(f"{FREEZE_ASKS_PATH} was not created")
    if ran_cli:
        print(f"  ✓ freeze_asks.json created by CLI")
    else:
        print(f"  ✓ freeze_asks.json exists (reused from previous run)")

    # Validate contents — the real assertion.
    asks = json.loads(FREEZE_ASKS_PATH.read_text(encoding="utf-8-sig"))
    issuers_found = set(asks.get("by_issuer", {}).keys())
    for expected in EXPECTED_ISSUERS:
        assert_in(f"{expected} in by_issuer", expected, issuers_found)


def step_2_emit_brief_blocked_by_review_gate():
    """Stage 2: emit-brief without reviewed editorial should fail cleanly."""
    print("\n[Step 2: emit-brief blocks on REVIEW_REQUIRED]")

    # Need an editorial file present (AI-generated or template). Check if the
    # AI editorial exists; if not, write a template and ensure REVIEW_REQUIRED=true.
    if not EDITORIAL_PATH.exists():
        # emit-brief --init writes a template
        run_cli(["emit-brief", CASE_ID, "--init"])
        print(f"  (wrote template editorial)")
    else:
        # Re-flip to REVIEW_REQUIRED=true to test the gate
        ed = json.loads(EDITORIAL_PATH.read_text(encoding="utf-8-sig"))
        if ed.get("AI_GENERATED"):
            ed["REVIEW_REQUIRED"] = True
            EDITORIAL_PATH.write_text(json.dumps(ed, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  (flipped REVIEW_REQUIRED=true on existing AI editorial)")

    # This should fail with exit 2 due to the review gate or the TODO check
    result = run_cli(["emit-brief", CASE_ID], expect_success=False)
    if result.returncode == 0:
        raise TestFailure(
            "emit-brief exited 0 but was expected to fail due to REVIEW_REQUIRED or TODO placeholders."
        )
    print(f"  ✓ emit-brief refused to proceed (exit {result.returncode}) as expected")


def step_3_emit_brief_success_after_review():
    """Stage 3: flip REVIEW_REQUIRED=false, emit-brief should succeed."""
    print("\n[Step 3: emit-brief succeeds after review flag flipped]")

    if not EDITORIAL_PATH.exists():
        raise TestFailure(f"{EDITORIAL_PATH} missing — previous step should have created it")

    ed = json.loads(EDITORIAL_PATH.read_text(encoding="utf-8-sig"))

    # If this is the template (not AI-generated), the TODO placeholders will block
    # emit-brief. In that case we skip the success-path test with a note, because
    # filling in all TODOs requires real narrative + address data that we don't have
    # in a generic test context.
    is_ai_generated = ed.get("AI_GENERATED", False)
    if not is_ai_generated:
        print(f"  ! editorial is a template (not AI-generated), skipping success-path check")
        print(f"    To fully test, run `recupero ai-editorial {CASE_ID}` first (~$0.15 API cost)")
        return

    ed["REVIEW_REQUIRED"] = False
    EDITORIAL_PATH.write_text(json.dumps(ed, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  (set REVIEW_REQUIRED=false)")

    # Delete existing brief so we verify it's regenerated
    if FREEZE_BRIEF_PATH.exists():
        FREEZE_BRIEF_PATH.unlink()

    run_cli(["emit-brief", CASE_ID])

    if not FREEZE_BRIEF_PATH.exists():
        raise TestFailure(f"{FREEZE_BRIEF_PATH} was not created")
    print(f"  ✓ freeze_brief.json created")


def step_4_validate_brief_numbers():
    """Stage 4: check the produced freeze_brief.json has the right headline numbers."""
    print("\n[Step 4: validate freeze_brief.json numbers]")

    if not FREEZE_BRIEF_PATH.exists():
        print(f"  ! freeze_brief.json doesn't exist — Step 3 was skipped, skipping number checks")
        return

    brief = json.loads(FREEZE_BRIEF_PATH.read_text(encoding="utf-8-sig"))

    # Check case ID
    assert_eq("CASE_ID", brief.get("CASE_ID"), CASE_ID)

    # Check TOTAL_LOSS_USD (should be ~$21,317.94)
    total_loss = parse_usd(brief.get("TOTAL_LOSS_USD"))
    assert_close("TOTAL_LOSS_USD", total_loss, EXPECTED_LOSS_USD_APPROX, LOSS_TOLERANCE_USD)

    # Check MAX_RECOVERABLE_USD is capped at loss (the honest-numbers invariant)
    max_recoverable = parse_usd(brief.get("MAX_RECOVERABLE_USD"))
    if EXPECTED_LOSS_MATCHES_CEILING and max_recoverable > total_loss:
        raise TestFailure(
            f"MAX_RECOVERABLE_USD ({max_recoverable}) exceeds TOTAL_LOSS_USD ({total_loss}). "
            f"The customer-facing ceiling should always be capped at loss."
        )
    print(f"  ✓ MAX_RECOVERABLE_USD ({max_recoverable}) is ≤ TOTAL_LOSS_USD ({total_loss})")

    # Check that FREEZABLE list has Circle and Tether
    freezable_issuers = {f.get("issuer") for f in brief.get("FREEZABLE", [])}
    for expected in EXPECTED_ISSUERS:
        assert_in(f"{expected} in FREEZABLE", expected, freezable_issuers)

    # Check RECOVERABLE_PERCENT is a string with a % (format sanity)
    pct = brief.get("RECOVERABLE_PERCENT", "")
    if not isinstance(pct, str) or "%" not in pct:
        raise TestFailure(f"RECOVERABLE_PERCENT has unexpected format: {pct!r}")
    print(f"  ✓ RECOVERABLE_PERCENT format OK ({pct})")


# ==================== RUN ====================
def main():
    parser = argparse.ArgumentParser(description="Recupero pipeline smoke test")
    parser.add_argument(
        "--full", action="store_true",
        help="Force fresh list-freeze-targets run (~10 minutes, hits Etherscan API). "
             "Default is fast mode: skip that step if freeze_asks.json is already fresh.",
    )
    args = parser.parse_args()

    mode_label = "full (regenerate everything)" if args.full else "fast (reuse fresh freeze_asks.json if possible)"
    print("=" * 70)
    print(f"Recupero pipeline smoke test — case: {CASE_ID}")
    print(f"Mode: {mode_label}")
    print("=" * 70)

    try:
        check_setup()
    except SetupError as e:
        print(f"\n[SETUP ERROR] {e}")
        return 2

    try:
        step_1_list_freeze_targets(full_mode=args.full)
        step_2_emit_brief_blocked_by_review_gate()
        step_3_emit_brief_success_after_review()
        step_4_validate_brief_numbers()
    except TestFailure as e:
        print(f"\n[FAIL] {e}")
        return 1

    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
