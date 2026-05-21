#!/usr/bin/env python
"""Mini mutation-testing harness for safety-critical paths.

Mutmut + cosmic-ray are both Windows-incompatible on this Python
build (3.14). This script does the equivalent for the highest-value
mutations: pick a specific change in a known-critical function, apply
it, run the targeted test, assert that the test FAILS (proving the
test catches the mutation), then revert.

If every mutation in this script causes the targeted test to fail,
the test suite has real bug-catching power on the critical paths.
If any mutation goes UNDETECTED, that mutation is the seed of a
missing test.

Coverage:
  1. dispatcher._handle_diagnostic — remove the advisory_xact_lock
     line. The W-1 concurrent test MUST detect this (race re-opens,
     N investigations created).

  2. api.app._intake_rl_client_ip — change `len(xff_chain) -
     trusted_hops` to `0`. The XFF property test MUST detect this
     (attacker now picks chain[0]).

  3. api.monitoring_api._is_blocked_ip — remove `is_private`. The
     SSRF property test MUST detect this (10.x.x.x slips through).

  4. _common.canonical_address_key — remove the `.lower()` call.
     The canonical-key property test MUST detect this (EVM dedup
     breaks).

  5. api.monitoring_api._is_blocked_host — remove the `host.lower()`
     line. The SSRF case-insensitivity test MUST detect this
     (LOCALHOST bypasses the denylist).

Run:
  python scripts/mutation_smoke.py

Output: PASS/FAIL summary per mutation. Non-zero exit if any
mutation went undetected.

Requires RECUPERO_RUN_INTEGRATION=1 + RECUPERO_INTEGRATION_DSN for
the W-1 race mutation. Skip with --no-integration to run the rest.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


@dataclass
class Mutation:
    name: str
    file_path: Path
    find: str               # exact substring to find
    replace_with: str       # what to replace it with
    test_target: str        # pytest -k or path::test_name
    requires_integration: bool = False


MUTATIONS: list[Mutation] = [
    Mutation(
        name="W-1: advisory_xact_lock removed",
        file_path=REPO_ROOT / "src/recupero/payments/dispatcher.py",
        find=(
            'cur.execute(\n'
            '        "SELECT pg_advisory_xact_lock(hashtext(\'diagnostic:\' || %s))",\n'
            '        (str(case_uuid),),\n'
            '    )'
        ),
        replace_with=(
            'pass  # MUTATION: advisory_xact_lock removed'
        ),
        test_target=(
            "tests/integration/test_real_concurrent_races.py::"
            "test_w1_concurrent_dispatchers_create_exactly_one_investigation"
        ),
        requires_integration=True,
    ),
    Mutation(
        name="XFF: rightmost-N offset broken (set to 0)",
        file_path=REPO_ROOT / "src/recupero/api/app.py",
        find="idx = max(0, len(xff_chain) - trusted_hops)",
        replace_with="idx = 0  # MUTATION: always picks leftmost",
        test_target=(
            "tests/test_xff_property_based.py::"
            "test_property_trusted_hops_picks_correct_element"
        ),
    ),
    Mutation(
        name="SSRF: is_private check removed from _is_blocked_ip",
        file_path=REPO_ROOT / "src/recupero/api/monitoring_api.py",
        find="ip.is_loopback or ip.is_private or ip.is_link_local",
        replace_with="ip.is_loopback or ip.is_link_local  # MUTATION: is_private dropped",
        test_target=(
            "tests/test_ssrf_property_based.py::"
            "test_property_every_private_ipv4_is_blocked"
        ),
    ),
    Mutation(
        name="canonical_address_key: .lower() removed",
        file_path=REPO_ROOT / "src/recupero/_common.py",
        find="return s.lower()",
        replace_with="return s  # MUTATION: lower() removed",
        test_target=(
            "tests/test_canonical_address_key_properties.py::"
            "test_property_evm_lowercase_and_uppercase_dedup"
        ),
    ),
    Mutation(
        name="SSRF: host.lower() removed (case-insensitive bypass)",
        file_path=REPO_ROOT / "src/recupero/api/monitoring_api.py",
        find="    host = host.lower()",
        replace_with="    pass  # MUTATION: lower() removed; case bypass",
        test_target=(
            "tests/test_ssrf_property_based.py::"
            "test_property_blocked_hostnames_are_case_insensitive"
        ),
    ),
]


def apply_mutation(m: Mutation) -> tuple[str, bool]:
    """Apply the mutation. Returns (original_text, success)."""
    original = m.file_path.read_text(encoding="utf-8")
    if m.find not in original:
        return original, False
    mutated = original.replace(m.find, m.replace_with, 1)
    m.file_path.write_text(mutated, encoding="utf-8", newline="\n")
    return original, True


def revert(m: Mutation, original: str) -> None:
    m.file_path.write_text(original, encoding="utf-8", newline="\n")


def run_test(target: str) -> tuple[bool, str]:
    """Run pytest. Returns (passed, last 30 lines of stdout)."""
    cmd = [
        sys.executable, "-m", "pytest", target,
        "-q", "--tb=line", "-x", "--no-header",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=REPO_ROOT, timeout=180,
    )
    passed = result.returncode == 0
    tail = "\n".join(result.stdout.splitlines()[-15:])
    return passed, tail


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--no-integration", action="store_true",
        help="Skip mutations that require a real DB.",
    )
    args = p.parse_args()

    print("=============================================================")
    print("  RIGOR-3: mini mutation-smoke harness")
    print("=============================================================")
    print(f"Repo:   {REPO_ROOT}")
    print(f"Integration tests: {'SKIP' if args.no_integration else 'RUN'}")
    print()

    detected = 0
    undetected = 0
    skipped = 0

    for m in MUTATIONS:
        print(f"-- {m.name} --")
        print(f"   file:   {m.file_path.relative_to(REPO_ROOT)}")
        print(f"   target: {m.test_target.split('::', 1)[-1]}")

        if m.requires_integration and args.no_integration:
            print("   SKIP (integration test)")
            skipped += 1
            print()
            continue
        if m.requires_integration and not os.environ.get("RECUPERO_RUN_INTEGRATION"):
            print("   SKIP (RECUPERO_RUN_INTEGRATION not set)")
            skipped += 1
            print()
            continue

        # 1. Baseline: confirm the test PASSES without the mutation.
        baseline_pass, baseline_tail = run_test(m.test_target)
        if not baseline_pass:
            print(f"   BASELINE FAIL — test is broken before mutation:")
            print("   " + baseline_tail.replace("\n", "\n   "))
            undetected += 1
            continue

        # 2. Apply the mutation.
        original, applied = apply_mutation(m)
        if not applied:
            print(f"   MUTATION SITE NOT FOUND — script needs updating")
            undetected += 1
            continue

        try:
            # 3. Run the targeted test on mutated code; expect it to FAIL.
            mutated_pass, mutated_tail = run_test(m.test_target)
            if mutated_pass:
                print(f"   UNDETECTED — test still passes on mutated code!")
                print("   " + mutated_tail.replace("\n", "\n   "))
                undetected += 1
            else:
                print(f"   DETECTED — test fails on the mutation as expected.")
                detected += 1
        finally:
            revert(m, original)

        print()

    total = len(MUTATIONS) - skipped
    print("=============================================================")
    print(f"  Results: {detected}/{total} mutations detected "
          f"(skipped {skipped})")
    print("=============================================================")
    if undetected > 0:
        print(f"  FAIL: {undetected} mutation(s) went UNDETECTED.")
        print("  This means the test suite has a coverage gap that a")
        print("  real bug of the same shape would slip through.")
        return 1
    if detected == 0:
        print(f"  WARN: No mutations were actually tested (all skipped).")
        return 2
    print(f"  PASS: All {detected} mutations were detected by the test suite.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
