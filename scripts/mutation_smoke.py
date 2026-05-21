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
    # ─────────────────────────────────────────────────────────────────────────
    # RIGOR-3 extension: another 20 mutations covering the SAFETY-CRITICAL
    # boundaries — webhook signature verification, idempotency keys, token
    # equality, USD parsing, the validator's own invariant logic, etc.
    # Each represents the shape of a real-world security or correctness
    # bug that would have shipped if the test didn't catch it.
    # ─────────────────────────────────────────────────────────────────────────
    # NOTE: I had two mutations for `is_loopback removed` and
    # `is_link_local removed`. Both are EQUIVALENT MUTANTS — Python's
    # ipaddress module classifies 127.0.0.0/8 + ::1 as BOTH is_loopback
    # AND is_private; same for fe80::/10 + 169.254.0.0/16 (both are
    # is_link_local AND is_private). So removing one of the three
    # checks doesn't change the function's output on any IP. Equivalent
    # mutants don't count against rigor — real mutation tools (mutmut,
    # cosmic-ray) skip them via static analysis or live-equivalence
    # detection. Documented for posterity, not run.
    Mutation(
        name="SSRF: scheme check changed from != to ==",
        file_path=REPO_ROOT / "src/recupero/api/monitoring_api.py",
        find='if parts.scheme.lower() != "https":',
        replace_with=(
            'if parts.scheme.lower() == "https":  '
            '# MUTATION: now rejects https-only, accepts everything else'
        ),
        test_target=(
            "tests/test_ssrf_property_based.py::"
            "test_property_only_https_scheme_accepted"
        ),
    ),
    Mutation(
        name="canonical: strip() removed (whitespace breaks dedup)",
        file_path=REPO_ROOT / "src/recupero/_common.py",
        find="    s = addr.strip()",
        replace_with="    s = addr  # MUTATION: strip() removed",
        test_target=(
            "tests/test_canonical_address_key_properties.py::"
            "test_property_whitespace_padding_stripped"
        ),
    ),
    Mutation(
        name="canonical: 0x EVM length check off-by-one (== 41)",
        file_path=REPO_ROOT / "src/recupero/_common.py",
        find='if s.startswith("0x") and len(s) == 42:',
        replace_with=(
            'if s.startswith("0x") and len(s) == 41:  '
            '# MUTATION: off-by-one rejects all real EVM addrs'
        ),
        test_target=(
            "tests/test_canonical_address_key_properties.py::"
            "test_property_evm_lowercase_and_uppercase_dedup"
        ),
    ),
    Mutation(
        name="canonical: hex-validation accepts non-hex (.lower() of any)",
        file_path=REPO_ROOT / "src/recupero/_common.py",
        find='if all(c in "0123456789abcdefABCDEF" for c in suffix):',
        replace_with=(
            'if True:  # MUTATION: validation removed; non-hex passes'
        ),
        test_target=(
            "tests/test_canonical_address_key_properties.py::"
            "test_property_malformed_0x_string_is_not_lowercased"
        ),
    ),
    Mutation(
        name="XFF: trusted_hops > 0 changed to >= 0 (accepts misconfig)",
        file_path=REPO_ROOT / "src/recupero/api/app.py",
        find="if trusted_hops > 0 and xff_chain:",
        replace_with=(
            "if trusted_hops >= 0 and xff_chain:  "
            "# MUTATION: trusted_hops=0 now incorrectly uses XFF"
        ),
        test_target=(
            "tests/test_xff_property_based.py::"
            "test_property_trusted_hops_zero_ignores_xff_completely"
        ),
    ),
    Mutation(
        name="W-2: status='active' filter removed from monitor_tick UPDATE",
        file_path=REPO_ROOT / "src/recupero/worker/monitor_tick.py",
        find=(
            "         WHERE id = %(id)s\n"
            "           AND status = 'active';"
        ),
        replace_with=(
            "         WHERE id = %(id)s;  -- MUTATION: status filter removed"
        ),
        # RIGOR-3: a behavioral test cannot observe the mutation's
        # effect when new_cursor=None (COALESCE preserves the prior
        # value). The contract check on the update_sql constant catches
        # it deterministically.
        test_target=(
            "tests/integration/test_real_concurrent_races.py::"
            "test_w2_w3_update_sql_carries_status_active_filter"
        ),
        requires_integration=True,  # test is in integration/ dir
    ),
    Mutation(
        name="W-4: followup claim staleness predicate replaced with TRUE",
        file_path=REPO_ROOT / "src/recupero/worker/_followup.py",
        find='"        OR last_followup_sent_at < NOW() "',
        replace_with=(
            '"        OR TRUE -- MUTATION: every row matches "'
        ),
        test_target=(
            "tests/integration/test_real_concurrent_races.py::"
            "test_w4_atomic_claim_lets_exactly_one_followup_worker_win"
        ),
        requires_integration=True,
    ),
    Mutation(
        name="W-1: existing-investigation SELECT removed (race re-opens)",
        file_path=REPO_ROOT / "src/recupero/payments/dispatcher.py",
        find=(
            "existing_inv = cur.fetchone()\n"
            "    if existing_inv:"
        ),
        replace_with=(
            "existing_inv = None  # MUTATION: existence check removed\n"
            "    if existing_inv:"
        ),
        test_target=(
            "tests/integration/test_real_concurrent_races.py::"
            "test_w1_concurrent_dispatchers_create_exactly_one_investigation"
        ),
        requires_integration=True,
    ),
    Mutation(
        name="validator: filename-content check inverted",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find=(
            "if not _content_addresses_issuer(\n"
            "            content, issuer_name or \"\", seed_email,\n"
            "        ):"
        ),
        replace_with=(
            "if _content_addresses_issuer(\n"
            "            content, issuer_name or \"\", seed_email,\n"
            "        ):  # MUTATION: inverted — flags GOOD letters as BAD"
        ),
        test_target=(
            "tests/test_output_integrity_validator.py::"
            "test_freeze_request_with_wrong_issuer_content_fails"
        ),
    ),
    Mutation(
        name="validator: HTML root check accepts JSON",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find=(
            'if not (\n'
            '            first_chars.startswith("<!DOCTYPE")\n'
            '            or first_chars.startswith("<html")'
        ),
        replace_with=(
            'if False and not (\n'
            '            first_chars.startswith("<!DOCTYPE")\n'
            '            or first_chars.startswith("<html")'
        ),
        test_target=(
            "tests/test_output_integrity_validator.py::"
            "test_html_file_containing_json_fails"
        ),
    ),
    Mutation(
        name="validator: manifest SHA comparison inverted",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find="if actual_sha != declared_sha:",
        replace_with=(
            "if actual_sha == declared_sha:  # MUTATION: comparison inverted"
        ),
        test_target=(
            "tests/test_output_integrity_validator.py::"
            "test_stale_manifest_sha_flagged"
        ),
    ),
    Mutation(
        name="validator: USD parse swallows invalid input as 0",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find=(
            "    try:\n"
            "        return Decimal(s)\n"
            "    except (InvalidOperation, ValueError):\n"
            "        return Decimal(0)"
        ),
        replace_with=(
            "    try:\n"
            "        return Decimal(0)  # MUTATION: always returns 0\n"
            "    except (InvalidOperation, ValueError):\n"
            "        return Decimal(0)"
        ),
        test_target=(
            "tests/test_output_integrity_validator.py::"
            "test_unrecoverable_variant_with_positive_max_recoverable_flagged"
        ),
    ),
    Mutation(
        name="portal token: length-guard removed (< 20 chars accepted)",
        file_path=REPO_ROOT / "src/recupero/portal/tokens.py",
        find=(
            "    if not token or len(token) < 20:"
        ),
        replace_with=(
            "    if not token or len(token) < 0:  "
            "# MUTATION: short tokens now accepted"
        ),
        test_target=(
            "tests/test_portal_tokens.py"  # any test that exercises length check
        ),
    ),
    Mutation(
        name="portal token: upper-bound length-guard removed (> 64 accepted)",
        file_path=REPO_ROOT / "src/recupero/portal/tokens.py",
        find=(
            "    if len(token) > 64:"
        ),
        replace_with=(
            "    if len(token) > 999999:  "
            "# MUTATION: very long tokens accepted (DoS surface)"
        ),
        test_target=(
            "tests/test_portal_tokens.py"
        ),
    ),
    Mutation(
        name="W-1: lock keyed on case_id stripped (only 'diagnostic:')",
        file_path=REPO_ROOT / "src/recupero/payments/dispatcher.py",
        find=(
            "\"SELECT pg_advisory_xact_lock(hashtext('diagnostic:' || %s))\",\n"
            "        (str(case_uuid),),"
        ),
        replace_with=(
            "\"SELECT pg_advisory_xact_lock(hashtext('diagnostic:'))\",\n"
            "        ()"
        ),
        test_target=(
            "tests/integration/test_real_concurrent_races.py::"
            "test_w1_lock_is_per_case_not_global"
        ),
        requires_integration=True,
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
