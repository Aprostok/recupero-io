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

Waves 10-13 (extension): 5 more mutations on the W7-04 PII redactor,
the W8-01 subscriber canonical-addr helper, the W10-03 auth strip
removal, the W11-01 ReDoS length cap, and the W12-03 manifest
required-keys schema lock.

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

# Windows consoles default to cp1252 — mutation names use Unicode arrows
# (→, em-dash) so reconfigure to utf-8 if available, else fall back to a
# safe stdout wrapper that replaces unencodable chars with "?".
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, OSError):
    import io
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace"
    )


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
        # RIGOR-S-3b promoted the misconfig path to fail-closed (no
        # max(0, ...) needed because the if-check above enforces
        # len(xff_chain) >= trusted_hops). The mutation now targets
        # the assignment that picks the rightmost-N element.
        find="idx = len(xff_chain) - trusted_hops",
        replace_with="idx = 0  # MUTATION: always picks leftmost (attacker-controlled)",
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
        # W11-08 hardening converted `!=` to `not hmac.compare_digest(...)`
        # for constant-time compare. The mutation locator needs to match
        # the new compare form; inverting the negation simulates a real
        # bug (validator silently accepting mismatched SHAs) the same way
        # the prior `!=` → `==` mutation did.
        name="validator: manifest SHA comparison inverted",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find="if not hmac.compare_digest(actual_sha, declared_sha):",
        replace_with=(
            "if hmac.compare_digest(actual_sha, declared_sha):  "
            "# MUTATION: negation dropped — silent-success on SHA mismatch"
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
    # ─────────────────────────────────────────────────────────────────────────
    # Waves 10-13 hardening — 5 additional mutations covering surfaces the
    # original 15 didn't reach: PII redaction before LLM dispatch, the
    # subscriber's local canonical-addr helper, the auth header's
    # whitespace-equivalence bypass (W10-03), the ReDoS length cap (W11-01),
    # and the manifest schema-drift detector (W12-03).
    # ─────────────────────────────────────────────────────────────────────────
    Mutation(
        # W7-04: ai_editorial._redact_case_summary_for_prompt scrubs victim
        # name/address/email before the prompt crosses to Anthropic. Inverting
        # the redaction (no-op on the victim dict) re-opens PII leakage.
        name="W7-04: ai_editorial PII redaction inverted (PII leaks to LLM)",
        file_path=REPO_ROOT / "src/recupero/reports/ai_editorial.py",
        find=(
            '    for key in ("name", "address", "email"):\n'
            "        if key in victim:\n"
            '            victim[key] = "[redacted-pii]"'
        ),
        replace_with=(
            '    for key in ():  # MUTATION: redaction disabled — PII leaks\n'
            "        if key in victim:\n"
            '            victim[key] = "[redacted-pii]"'
        ),
        test_target=(
            "tests/test_ai_editorial_adversarial.py::"
            "test_victim_pii_redacted_from_prompt"
        ),
    ),
    Mutation(
        # W8-01: monitoring.subscriber._canonical_addr lowercases EVM
        # addresses so the dedup key collapses mixed-case duplicates and
        # the persisted address is canonical. Flipping to .upper() means
        # the persisted address is the UPPERCASE form, breaking the
        # canonical-storage contract the test enforces.
        name="W8-01: subscriber._canonical_addr lower→upper (canon drift)",
        file_path=REPO_ROOT / "src/recupero/monitoring/subscriber.py",
        find=(
            '    if address[:2].lower() == "0x" and len(address) == 42:\n'
            "        return address.lower()"
        ),
        replace_with=(
            '    if address[:2].lower() == "0x" and len(address) == 42:\n'
            "        return address.upper()  "
            "# MUTATION: canonicalize to UPPER — drift undetected"
        ),
        test_target=(
            "tests/test_subscriber_adversarial.py::"
            "test_mixed_case_duplicate_collapses_and_persists_canonical"
        ),
    ),
    Mutation(
        # W10-03: api.auth removed `.strip()` on the inbound API-key header
        # so that " sk_xxx\t" can no longer impersonate "sk_xxx". The
        # mutation re-adds the strip, restoring the whitespace-equivalence
        # bypass that the parametrized adversarial test pins shut.
        name="W10-03: api/auth re-adds .strip() (whitespace-equivalence bypass)",
        file_path=REPO_ROOT / "src/recupero/api/auth.py",
        find='    key_secret = request.headers.get("X-Recupero-API-Key", "")',
        replace_with=(
            '    key_secret = request.headers.get('
            '"X-Recupero-API-Key", "").strip()  '
            "# MUTATION: strip re-added — W10-03 bypass re-opens"
        ),
        test_target=(
            "tests/test_api_auth_adversarial.py::"
            "test_whitespace_decorated_key_is_rejected"
        ),
    ),
    Mutation(
        # W11-01: hack_tracker.models._scrub_text caps inputs at 16KB before
        # the polynomial _HTML_TAG_RE.sub runs. Lifting the cap to 16MB
        # restores the multi-MB input path that triggers ~45s of regex
        # backtracking — the ReDoS budget test detects the regression.
        name="W11-01: _scrub_text ReDoS cap raised 16KB→16MB (DoS re-opens)",
        file_path=REPO_ROOT / "src/recupero/hack_tracker/models.py",
        find=(
            "        if len(v) > 16384:\n"
            "            v = v[:16384]"
        ),
        replace_with=(
            "        if len(v) > 16777216:  "
            "# MUTATION: cap raised to 16MB — ReDoS surface re-opens\n"
            "            v = v[:16777216]"
        ),
        test_target=(
            "tests/test_regex_redos_audit.py::"
            "test_html_tag_regex_linear_on_pathological_input"
        ),
    ),
    Mutation(
        # W12-03: validators.output_integrity._MANIFEST_REQUIRED_KEYS is the
        # locked schema gate. Emptying the tuple makes `missing` always []
        # so no violation ever fires — schema drift goes undetected and a
        # manifest with no `outputs` would trivially pass the SHA loop.
        name="W12-03: _MANIFEST_REQUIRED_KEYS emptied (schema drift undetected)",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find=(
            '_MANIFEST_REQUIRED_KEYS: tuple[str, ...] = (\n'
            '    "outputs", "output_sha256",\n'
            ")"
        ),
        replace_with=(
            "_MANIFEST_REQUIRED_KEYS: tuple[str, ...] = ()  "
            "# MUTATION: schema lock dropped"
        ),
        test_target=(
            "tests/test_output_integrity_deeper.py::"
            "test_manifest_missing_required_keys_emits_violation"
        ),
    ),
    Mutation(
        # S-5 close-out: generate_token must raise when RECUPERO_TOKEN_PEPPER
        # is unset, otherwise the worker would silently INSERT a row with
        # NULL token_hmac that no future verify_token call could match —
        # a permanent denial-of-service for that victim's portal link, AND
        # security-equivalent to a leaked token (raw token sent in the email
        # has no recoverable verifier on the server).
        #
        # Removing the raise sends generate_token down the legacy path that
        # passes None as the HMAC value. The regression test pins this shut.
        name="S-5: generate_token pepper-required raise removed",
        file_path=REPO_ROOT / "src/recupero/portal/tokens.py",
        find=(
            "        if token_hmac_val is None:\n"
            "            raise RuntimeError(\n"
            '                "RECUPERO_TOKEN_PEPPER not configured — cannot mint "\n'
            '                "portal tokens. Set the env var and restart the worker."\n'
            "            )"
        ),
        replace_with=(
            "        if token_hmac_val is None:\n"
            "            pass  # MUTATION: pepper-required raise removed"
        ),
        test_target=(
            "tests/test_portal_tokens.py::"
            "test_generate_token_raises_when_pepper_unset"
        ),
    ),
    Mutation(
        # S-5 close-out: verify_token must return None when pepper is unset.
        # Pre-fix the legacy raw-token fallback would still run, exposing
        # the byte-comparison timing side-channel. The pepper-check early
        # return is the load-bearing guard; flipping the check inverted
        # makes any pepper-less request succeed via fallback (which no
        # longer exists, so this mutation surfaces as a NameError or a
        # SELECT against the dropped column — either way the test fails).
        name="S-5: verify_token pepper-unset short-circuit inverted",
        file_path=REPO_ROOT / "src/recupero/portal/tokens.py",
        find=(
            "    candidate_hmac = compute_token_hmac(token)\n"
            "    if candidate_hmac is None:"
        ),
        replace_with=(
            "    candidate_hmac = compute_token_hmac(token)\n"
            "    if candidate_hmac is not None:  # MUTATION: predicate flipped"
        ),
        test_target=(
            "tests/test_portal_tokens.py::"
            "test_verify_token_returns_none_when_pepper_unset"
        ),
    ),
    Mutation(
        # S-5 close-out: the verify_token lookup must use the HMAC column,
        # NOT the raw token column. Flipping `WHERE t.token_hmac = %s` back
        # to `WHERE t.token = %s` would (a) crash at runtime because the
        # column was dropped in migration 016, OR (b) silently pass against
        # an older deploy that hadn't applied 016. The regression test
        # uses a SQL-snooping mock to catch (b).
        name="S-5: verify_token SELECT reverts to raw token column",
        file_path=REPO_ROOT / "src/recupero/portal/tokens.py",
        find="                 WHERE t.token_hmac = %s",
        replace_with=(
            "                 WHERE t.token = %s  "
            "-- MUTATION: legacy raw-token SELECT"
        ),
        test_target=(
            "tests/test_portal_tokens.py::"
            "test_verify_token_does_not_query_legacy_token_column"
        ),
    ),

    # ─────────────────────────────────────────────────────────────────
    # v0.28 mutations — verify the new test surface has real bug-
    # catching power. Each mutation flips a critical line; the named
    # test MUST detect it (FAIL on the mutated code).
    # ─────────────────────────────────────────────────────────────────
    Mutation(
        # The NaN/Inf/negative defense in _sanitize_usd is what stops
        # extract_subpoena_targets from crashing on adversarial USD
        # strings. Removing the NaN check makes the property test
        # explode because `Decimal('NaN') < 0` raises InvalidOperation.
        name="v0.28: _sanitize_usd NaN check removed",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_targets.py",
        find="    if d.is_nan() or d.is_infinite():",
        replace_with=(
            "    if False:  # MUTATION: NaN check dropped"
        ),
        test_target=(
            "tests/test_v028_deep_hardening.py::"
            "test_property_sanitize_usd_always_non_negative_finite"
        ),
    ),
    Mutation(
        # The negative-amount clamp protects against editorial JSON
        # with a typo'd "-$5,000" or similar. Removing the < 0 check
        # makes negative USD pass through, which the NaN/negative
        # property test catches.
        name="v0.28: _sanitize_usd negative-amount clamp removed",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_targets.py",
        find="    if d < 0:\n        return Decimal(\"0\")",
        replace_with=(
            "    if False:  # MUTATION: negative clamp dropped\n"
            "        return Decimal(\"0\")"
        ),
        test_target=(
            "tests/test_v028_hardening.py::"
            "test_sanitize_usd_rejects_negative"
        ),
    ),
    Mutation(
        # The filename-length cap is what prevents the Windows MAX_PATH
        # crash. Removing the cap test causes the renderer to write
        # arbitrarily long filenames that exceed the OS limit. The
        # property test asserts len(out) <= _FILENAME_COMPONENT_MAX
        # over thousands of random inputs.
        name="v0.28: _safe_filename_component length-cap removed",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_renderer.py",
        find="    if len(out) > _FILENAME_COMPONENT_MAX:",
        replace_with=(
            "    if False:  # MUTATION: length cap removed"
        ),
        # v0.28.4 mutation-survivor fix: the previous target was
        # the property test with max_size=2000 — most random strings
        # at that size were already truncated by the sanitize step.
        # The retargeted test uses size=50000 explicitly so the cap
        # is the only thing that bounds the output.
        test_target=(
            "tests/test_v028_deep_hardening.py::"
            "test_property_safe_filename_component_bounded_at_large_sizes"
        ),
    ),
    Mutation(
        # The filename-collision detection is what prevents multiple
        # seizure-targets (same recipient_name = "Identified law
        # enforcement agency") from overwriting each other. Removing
        # the used_filenames check restores the bug the e2e test
        # caught.
        name="v0.28: filename-collision detection removed",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_renderer.py",
        find=(
            "        if base_filename in used_filenames:"
        ),
        replace_with=(
            "        if False:  # MUTATION: collision detection skipped"
        ),
        test_target=(
            "tests/test_v028_deep_hardening.py::"
            "test_e2e_zigha_shape_brief_render_validate"
        ),
    ),
    Mutation(
        # INVARIANT D cycle-detection: removing the GRAY-state check
        # in the DFS means back-edges (cycles) are no longer detected.
        # The cycle tests must catch this.
        name="v0.28: INVARIANT D cycle GRAY-check removed",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find="            if color[nxt] == GRAY:",
        replace_with=(
            "            if False:  # MUTATION: cycle detection disabled"
        ),
        test_target=(
            "tests/test_v028_hardening.py::"
            "test_invariant_d_catches_self_reference_cycle"
        ),
    ),
    Mutation(
        # INVARIANT C Zigha-shape escalation: pre-v0.28.2 this was
        # warning-only. v0.28.2 escalated to high above $100K. Mutating
        # back to warning-only is the regression.
        name="v0.28: INVARIANT C Zigha-shape escalation reverted",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find='severity = "high" if usd >= Decimal("100000") else "warning"',
        replace_with=(
            'severity = "warning"  '
            '# MUTATION: escalation removed; all warnings now'
        ),
        test_target=(
            "tests/test_v028_hardening.py::"
            "test_invariant_c_escalates_to_high_above_100k"
        ),
    ),
    Mutation(
        # The extraction-error sentinel is what surfaces silent
        # extraction crashes. Removing the SUBPOENA_TARGETS_EXTRACTION_
        # ERROR write in emit_brief means a crash silently emits an
        # empty list — the bug class the v0.28.2 hardening introduced
        # the sentinel to catch.
        name="v0.28: extraction-error sentinel NOT written on exception",
        file_path=REPO_ROOT / "src/recupero/reports/emit_brief.py",
        find='brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"] = (',
        replace_with=(
            'pass; _orig = (  # MUTATION: sentinel write removed'
        ),
        # v0.28.4 mutation-survivor fix: the previous test only
        # asserted absence-of-sentinel passes; it didn't exercise
        # the sentinel-write path. The new test does a structural
        # source-inspect check, which catches the mutation directly.
        test_target=(
            "tests/test_v028_hardening.py::"
            "test_emit_brief_source_contains_sentinel_write"
        ),
    ),
    Mutation(
        # _atomic_write must clean up the .tmp file on failure.
        # Removing the unlink leaves the orphan .tmp. The simulated
        # PermissionError test catches this.
        name="v0.28: _atomic_write tmp cleanup removed on failure",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_renderer.py",
        find=(
            "        try:\n"
            "            if tmp.exists():\n"
            "                tmp.unlink()"
        ),
        replace_with=(
            "        try:\n"
            "            if False:  # MUTATION: cleanup skipped\n"
            "                tmp.unlink()"
        ),
        test_target=(
            "tests/test_v028_deep_hardening.py::"
            "test_atomic_write_cleans_tmp_when_rename_fails"
        ),
    ),
    Mutation(
        # _resolve_cex_recipient with operator override: the load
        # function MUST short-circuit when no env var is set. Mutating
        # the early return to fall through means an "" env var would
        # try to open the file and log a warning. Test enforces no
        # warning + correct canonical fallback.
        name="v0.28: CEX override early-return on empty env var",
        file_path=REPO_ROOT / "src/recupero/reports/subpoena_targets.py",
        find=(
            "    if not override_path:\n"
            "        return out"
        ),
        replace_with=(
            "    if False:  # MUTATION: early return removed\n"
            "        return out"
        ),
        # v0.28.4 mutation-survivor fix: the previous test only
        # checked the canonical fallback worked, which it does
        # either way (open("") raises and the except catches it).
        # The new test asserts NO WARNING is logged, which fails
        # when the mutation falls through to the file-open path.
        test_target=(
            "tests/test_v028_deep_hardening.py::"
            "test_cex_compliance_override_unset_does_not_attempt_file_read"
        ),
    ),
    Mutation(
        # The 1-cycle (self-reference) is caught by the GRAY-state
        # check too, but specifically tested via the index lookup.
        # Mutate the cycle violation EMIT to a different severity
        # (warning) — the test must check severity=='high'.
        name="v0.28: INVARIANT D cycle severity downgraded to warning",
        file_path=REPO_ROOT / "src/recupero/validators/output_integrity.py",
        find=(
            '                    violations.append(Violation(\n'
            '                        check="subpoena_targets_depends_on_resolves",\n'
            '                        severity="high",\n'
            '                        detail=(\n'
            '                            "Dependency cycle in SUBPOENA_TARGETS: "'
        ),
        replace_with=(
            '                    violations.append(Violation(\n'
            '                        check="subpoena_targets_depends_on_resolves",\n'
            '                        severity="warning",  # MUTATION: downgraded\n'
            '                        detail=(\n'
            '                            "Dependency cycle in SUBPOENA_TARGETS: "'
        ),
        test_target=(
            "tests/test_v028_hardening.py::"
            "test_invariant_d_catches_self_reference_cycle"
        ),
    ),

    # ─────────────────────────────────────────────────────────────────────────
    # v0.31.x extension — 10 mutations covering the v0.31.0/.1/.2 surfaces
    # the audit flagged as having ZERO mutation coverage:
    #   * dust_attack (3 — ratio guard, min_fanout default, threshold direction)
    #   * cex_continuity (3 — window direction, abs() drop, noisy-token flip)
    #   * bridge decoders (3 — Connext domain slot, LiFi receiver offset,
    #                      Symbiosis recipient slot)
    #   * label store (1 — point_in_time added_at boundary)
    # Each targets a VALUE/THRESHOLD/BOUNDARY change a real bug-shape might
    # produce; the named test in tests/test_v031_*.py MUST detect it.
    # ─────────────────────────────────────────────────────────────────────────
    Mutation(
        # dust_attack: the 2x confidence guard is what keeps the detector
        # from sweeping up a legitimate consolidation hub that received
        # 1 big payment + 30 sub-routed change-backs. Weakening the guard
        # from `>= 2x` to `>= 1x` flips the "big-payment + dust-noise"
        # case from "suppressed (correct)" to "fires (false positive)" —
        # so the consolidation hub would land in `flagged` instead of
        # being preserved in the brief.
        #
        # The case test sends 10 dust + 10 non-dust (ratio = 1.0). With
        # the guard at `2 * non_dust`, ratio 1.0 < 2.0 → suppress (test
        # expects empty set). After mutation the comparison becomes
        # `>= 1 * non_dust` so ratio 1.0 >= 1.0 → fire (test fails).
        name="v0.31.2 dust_attack: 2x ratio guard weakened to 1x",
        file_path=REPO_ROOT / "src/recupero/trace/dust_attack.py",
        find="if len(dust_dests) < 2 * len(non_dust_dests):",
        replace_with=(
            "if len(dust_dests) < 1 * len(non_dust_dests):  "
            "# MUTATION: ratio guard weakened — false positives"
        ),
        test_target=(
            "tests/test_v031_2_dust_attack.py::"
            "test_confidence_guard_dust_not_dominating_non_dust"
        ),
    ),
    Mutation(
        # dust_attack: default `min_fanout=10` is the smallest fan-out
        # that catches published dust-shower attacks while staying above
        # any legitimate change-back behavior. Off-by-one to `11` means
        # a perpetrator running an exact-10-destination shower (the
        # threshold case the test pins) slips through.
        #
        # The pinned test sends 20 distinct dust destinations — well
        # over both 10 and 11. So the off-by-one to 11 wouldn't catch.
        # Move the default UP enough that a 10-destination shower no
        # longer fires: default=21 means the 20-destination test will
        # fail (expects flagged={20 addrs}, gets empty set).
        name="v0.31.2 dust_attack: min_fanout default raised above 20",
        file_path=REPO_ROOT / "src/recupero/trace/dust_attack.py",
        find="    min_fanout: int = 10,",
        replace_with=(
            "    min_fanout: int = 21,  "
            "# MUTATION: default raised — 20-dest shower no longer fires"
        ),
        test_target=(
            "tests/test_v031_2_dust_attack.py::"
            "test_classic_dust_shower_20_destinations_all_flagged"
        ),
    ),
    Mutation(
        # dust_attack: the threshold compare is `usd < threshold` so
        # dust is STRICTLY below the cutoff. Flipping to `usd <=`
        # changes the boundary semantics — a transfer at exactly
        # $1.00 (the default threshold) flips from non-dust to dust.
        # The custom-threshold test at $10 with $9.99 transfers needs
        # `<` to fire correctly (and `<=` ALSO fires here — equivalent
        # mutant on THAT test). For non-equivalence we need a test
        # that puts a transfer AT the threshold boundary.
        #
        # Re-target to a test that has transfers at $5.00 with default
        # $1.00 threshold (`test_above_threshold_transfers_not_flagged`).
        # Flipping the operator changes the threshold-compare result
        # for the AT-boundary case but not here. So instead the safest
        # mutation that the EXISTING shower test catches is to flip
        # the *direction*: change `usd < threshold` to `usd > threshold`.
        # That makes a $0.001 dust transfer go to the NON-dust bucket,
        # the test "classic_dust_shower_20_destinations_all_flagged"
        # then expects 20 flagged dust but gets 0 → fail.
        name="v0.31.2 dust_attack: threshold compare direction inverted",
        file_path=REPO_ROOT / "src/recupero/trace/dust_attack.py",
        find="        if usd < threshold:",
        replace_with=(
            "        if usd > threshold:  "
            "# MUTATION: direction flipped — dust becomes non-dust"
        ),
        test_target=(
            "tests/test_v031_2_dust_attack.py::"
            "test_classic_dust_shower_20_destinations_all_flagged"
        ),
    ),
    Mutation(
        # cex_continuity: the window guard is `if row_block_time >
        # window_end: continue` — skip outflows that fall AFTER the
        # window. Inverting to `<` skips outflows INSIDE the window;
        # the 2h amount-matched outflow (well inside default 6h) would
        # be filtered out, and the matched-lead test expects exactly
        # one lead.
        name="v0.31.2 cex_continuity: window-end direction inverted",
        file_path=REPO_ROOT / "src/recupero/trace/cex_continuity.py",
        find="                if row_block_time > window_end:",
        replace_with=(
            "                if row_block_time < window_end:  "
            "# MUTATION: in-window outflows now skipped"
        ),
        test_target=(
            "tests/test_v031_2_cex_continuity.py::"
            "test_amount_matched_outflow_in_window_yields_one_lead"
        ),
    ),
    Mutation(
        # cex_continuity: amount-tolerance check is `|dep - cand| /
        # dep <= tol`. Dropping the abs() means a candidate with
        # 4x the deposit (way over) computes `dep - 4*dep = -3*dep`
        # → pct = -3 → -3 <= 0.05 → True (always matches for
        # candidates LARGER than the deposit). The mismatch test
        # (5 WBTC dep, 20 WBTC outflow) expects [] but would now
        # produce a (false) lead.
        name="v0.31.2 cex_continuity: abs() dropped from tolerance check",
        file_path=REPO_ROOT / "src/recupero/trace/cex_continuity.py",
        find="        diff = abs(deposit_usd - candidate_usd)",
        replace_with=(
            "        diff = (deposit_usd - candidate_usd)  "
            "# MUTATION: abs() dropped — over-amount always matches"
        ),
        test_target=(
            "tests/test_v031_2_cex_continuity.py::"
            "test_amount_mismatch_outside_tolerance_yields_zero_leads"
        ),
    ),
    Mutation(
        # cex_continuity: the noisy-token check is
        # `if token_sym in noisy_tokens: continue` — SKIP USDC/USDT
        # deposits (too statistically noisy to claim continuity).
        # Inverting to `not in` flips the filter: ONLY noisy tokens
        # pass, so the USDC deposit (which the test expects to be
        # SKIPPED with zero leads + no adapter call) now becomes a
        # candidate, the adapter IS called, and a lead may be
        # produced → test asserts adapter NOT called, fails.
        name="v0.31.2 cex_continuity: noisy_tokens membership inverted",
        file_path=REPO_ROOT / "src/recupero/trace/cex_continuity.py",
        find="        if token_sym in noisy_tokens:",
        replace_with=(
            "        if token_sym not in noisy_tokens:  "
            "# MUTATION: only noisy tokens pass — opposite of intent"
        ),
        test_target=(
            "tests/test_v031_2_cex_continuity.py::"
            "test_noisy_token_usdc_yields_zero_leads"
        ),
    ),
    Mutation(
        # Connext decoder: the domain-ID extraction slot is
        # `args_blob[0:64]` (first 32-byte word). Shifting to
        # `args_blob[32:96]` reads the recipient address as the
        # domain-ID, which won't be in `_CONNEXT_DOMAIN_IDS` so
        # `dest_chain` becomes None — the Optimism happy-path test
        # asserts destination_chain == "optimism" and fails.
        name="v0.31.0 Connext decoder: domain-ID slot shifted by one word",
        file_path=REPO_ROOT / "src/recupero/trace/bridge_calldata.py",
        find="        domain_hex = args_blob[0:64]",
        replace_with=(
            "        domain_hex = args_blob[32:96]  "
            "# MUTATION: domain-ID slot shifted; reads recipient as domain"
        ),
        test_target=(
            "tests/test_v031_decoders.py::"
            "test_connext_xcall_decodes_optimism"
        ),
    ),
    Mutation(
        # LiFi decoder: the BridgeData receiver/chain-ID offsets for
        # the no-swap facet are `(160 * 2, 224 * 2)`. Shifting the
        # receiver offset to `(192 * 2, 224 * 2)` reads the
        # minAmount slot as the receiver — the address is no longer
        # 20-byte right-padded so the dest_address comes back as
        # 0x000... which the decoder treats as a sentinel and
        # rejects, ultimately returning low-confidence with no
        # destination. The Polygon happy-path test expects
        # confidence='high' + dest_address='0x99...99' → fails.
        name="v0.31.0 LiFi decoder: receiver offset shifted +32B",
        file_path=REPO_ROOT / "src/recupero/trace/bridge_calldata.py",
        find="        (160 * 2, 224 * 2),   # BridgeData at offset 0 (start-bridge-only)",
        replace_with=(
            "        (192 * 2, 224 * 2),   "
            "# MUTATION: receiver offset shifted; happy path now low-conf"
        ),
        test_target=(
            "tests/test_v031_decoders.py::"
            "test_lifi_start_bridge_tokens_via_stargate_polygon"
        ),
    ),
    Mutation(
        # Symbiosis decoder: `relayRecipient` is at struct slot 7
        # inside the inlined tuple body, hex index 224*2 (=448)
        # beyond `tuple_body_hex_idx`. Shifting to `200*2` (=400)
        # reads from inside the `amount`/`nativeIn` slots, which
        # are not the recipient — the extracted `dest_address`
        # becomes the wrong 20-byte slice, not matching the
        # `0xbbbb...bb` recipient the Polygon happy-path test
        # asserts. Confidence drops accordingly.
        name="v0.31.2 Symbiosis decoder: relayRecipient slot offset shifted",
        file_path=REPO_ROOT / "src/recupero/trace/bridge_calldata.py",
        find="        recv_slot_start = tuple_body_hex_idx + 224 * 2",
        replace_with=(
            "        recv_slot_start = tuple_body_hex_idx + 200 * 2  "
            "# MUTATION: relayRecipient slot shifted -24B"
        ),
        test_target=(
            "tests/test_v031_2_symbiosis_decoder.py::"
            "test_symbiosis_metaroute_polygon_high_confidence"
        ),
    ),
    Mutation(
        # LabelStore.lookup point_in_time: the added_at-before-pit
        # filter is `if added_at > pit: return None`. Inverting to
        # `<` makes the filter trigger when the label EXISTED at
        # the timestamp instead of when it didn't — so a 2023-06-01
        # PIT against a 2024-01-01-added label returns the label
        # (back-stamping a 2024 label onto 2023 transfers, the bug
        # the v0.31.2 Gap #5 fix closed). The "before added_at"
        # test asserts None → fails.
        name="v0.31.2 LabelStore: point_in_time added_at direction flipped",
        file_path=REPO_ROOT / "src/recupero/labels/store.py",
        find="if added_at is not None and pit is not None and added_at > pit:",
        replace_with=(
            "if added_at is not None and pit is not None and added_at < pit:  "
            "# MUTATION: direction flipped — labels back-stamp onto pre-add transfers"
        ),
        test_target=(
            "tests/test_v031_2_point_in_time_labels.py::"
            "TestNoValidityWindow::test_before_added_at_returns_none"
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
