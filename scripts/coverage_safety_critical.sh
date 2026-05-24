#!/usr/bin/env bash
#
# RIGOR-4: branch-coverage measurement for safety-critical modules.
#
# Why scoped (vs. full-repo)? Branch coverage with pytest tracking
# imposes ~5x overhead. A full-repo run takes 60+ min on this machine.
# This scoped run completes in <3 min and gives an accurate picture
# of coverage on the modules that MATTER:
#
#     payments/        — Stripe webhook + dispatcher; idempotency-
#                        critical, customer-money-handling
#     validators/      — output_integrity (Jacob's Part 4/5 spec)
#     freeze_learning/ — recorder + status + nightly priors
#     api/             — auth, monitoring_api, app endpoints
#     portal/          — intake form, status page, token verifier
#
# What's not measured here: chains/, dormant/, hack_tracker/, trace/,
# reports/. Those have their own dedicated test suites and the full
# pytest -q run measures their behavior; coverage tracking is just
# slow on the whole-tree.
#
# Usage:
#   bash scripts/coverage_safety_critical.sh
#
# Required env (for the integration subset):
#   PGPASSWORD
#   RECUPERO_INTEGRATION_DSN (or this script sets it for the standard
#       local recupero_int_test DB the bootstrap script creates)
#
# Output:
#   * Console report with module-by-module branch + line coverage
#   * .coverage data file for `coverage html` follow-up

set -euo pipefail

# Set up env if the operator hasn't already.
if [ -z "${RECUPERO_INTEGRATION_DSN:-}" ] && [ -n "${PGPASSWORD:-}" ]; then
  export RECUPERO_INTEGRATION_DSN="postgresql://postgres:${PGPASSWORD}@127.0.0.1:5432/recupero_int_test"
fi
export RECUPERO_RUN_INTEGRATION=1

SCOPE="src/recupero/payments,src/recupero/validators,src/recupero/freeze_learning,src/recupero/api,src/recupero/portal"

# Test groups by concern. Each group runs as ONE coverage execution
# (--append on subsequent runs accumulates branch hits).

CORE_TESTS=(
  tests/test_stripe_webhook.py
  tests/test_stripe_dispatcher.py
  tests/test_stripe_mode.py
  tests/test_payment_links.py
  tests/test_punish_b_w1_diagnostic_race.py
  tests/test_punish_b_s2_ssrf_dispatch.py
  tests/test_punish_b_s4_token_logging.py
  tests/test_output_integrity_validator.py
  tests/test_freeze_learning.py
  tests/test_freeze_outcome_intake.py
  tests/test_s1_freeze_outcome_multi_tenant.py
  tests/test_v0_25_intake.py
  tests/test_v0_25_intake_eyeball_pass.py
  tests/test_v0_25_intake_notifications.py
  tests/test_portal_tokens.py
  tests/test_portal_server.py
  tests/test_api_app.py
  tests/test_v0_27_monitoring_api.py
  tests/test_v0_27_1_audit_fixes.py
  tests/test_v0_21_live_filings.py
  tests/test_le_handoff_live_status.py
  tests/test_punish_b_forensic_returned_usd.py
  tests/test_canonical_address_key_properties.py
  tests/test_ssrf_property_based.py
  tests/test_xff_property_based.py
  tests/test_observability.py
  tests/test_engagement_api.py
  tests/test_email_sender.py
)

INTEGRATION_TESTS=(
  tests/integration/test_real_concurrent_races.py
  tests/integration/test_stripe_to_dispatcher.py
)

echo "=== Coverage: clearing prior data ==="
rm -f .coverage

echo "=== Coverage: core unit + mock tests ==="
python -m coverage run --branch --source="$SCOPE" -m pytest -q --tb=no \
  "${CORE_TESTS[@]}"

echo "=== Coverage: real-DB integration tests (--append) ==="
python -m coverage run --branch --append --source="$SCOPE" -m pytest -q --tb=line \
  "${INTEGRATION_TESTS[@]}"

echo "=== Coverage report ==="
python -m coverage report --skip-covered --skip-empty --sort=miss

# Floor gate — RIGOR-4. Current measured coverage (2026-05-24): 73%.
# Floor is set at 70% to allow ±3% noise from test-set drift; ratchet
# this up as new tests land. The goal remains 90%; this gate prevents
# backsliding from the current state. Aspirational targets per file:
#   * Tier-A (payments, validators, portal/tokens, api/auth): 90%+
#   * Tier-B (intake, monitoring_api, dispatcher): 85%+
#   * Tier-C (api/app, portal/server, recorder): 70%+ → 80%+
# Override the floor with RECUPERO_COVERAGE_FLOOR if testing locally.
COVERAGE_FLOOR="${RECUPERO_COVERAGE_FLOOR:-70}"
echo ""
echo "=== Coverage floor gate: fail if total < ${COVERAGE_FLOOR}% ==="
if ! python -m coverage report --fail-under="${COVERAGE_FLOOR}" >/dev/null 2>&1; then
    echo "FAIL: total coverage dropped below floor (${COVERAGE_FLOOR}%)." >&2
    echo "      Either restore the tests that lapsed, or argue the floor down" >&2
    echo "      with a PR comment explaining what shifted (e.g. a large new" >&2
    echo "      module landed and dilutes the percentage while net branches" >&2
    echo "      covered grew). Don't blindly drop the floor." >&2
    exit 1
fi
echo "PASS: total coverage at or above ${COVERAGE_FLOOR}% floor."

echo ""
echo "=== Done ==="
echo "Generate HTML drill-down:    python -m coverage html"
echo "Find untested branches:      python -m coverage report --show-missing"
