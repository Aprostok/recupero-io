# Recupero Testing Rigor

This document describes the test-suite discipline that backs the
correctness claims for production-paid customer cases. Updated by
the RIGOR-1..RIGOR-8 pass (commits a4f66b5..9e364ac, 2026-05-21).

The product handles real money (Stripe payments), real customer
trust (case data, victim PII), and real legal evidence (LE handoffs,
freeze requests). The test suite holds up the line against
regressions that would compromise any of those.

## Test discipline categories

### 1. Unit tests (`tests/test_*.py`)

~2000 tests covering individual functions + small interaction
graphs. Each test is hermetic (no shared state across tests),
deterministic (no Random / Now drift), and fast (full run ~15 min).

Run:
```bash
python -m pytest -q
```

### 2. Integration tests against real Postgres (`tests/integration/`)

Gated on `RECUPERO_RUN_INTEGRATION=1`. Tests that need a real
Postgres database — webhook dispatch, payment idempotency, case-store
round-trip, post-deploy reaper, concurrent-race reproducers.

Setup (one command):
```bash
PGPASSWORD=<your-postgres-password> bash scripts/setup_test_db.sh
```

Run:
```bash
export RECUPERO_RUN_INTEGRATION=1
export RECUPERO_INTEGRATION_DSN='postgresql://postgres:$PGPASSWORD@127.0.0.1:5432/recupero_int_test'
python -m pytest tests/integration/ -v
```

### 3. Real concurrent-race tests (`tests/integration/test_real_concurrent_races.py`)

The PUNISH-B W-1..W-4 fixes are guarded by SOURCE-LEVEL grep tests
(checking SQL keywords appear) AND by REAL behavioral tests that
spawn N concurrent transactions against the test Postgres and
assert exactly-once outcomes:

  * **W-1** (diagnostic dispatch): 8 concurrent dispatchers hit the
    same case_id → exactly 1 investigation row, 7 audit_only.
  * **W-2** (monitor_tick claim): 4 overlapping crons → each
    subscription claimed exactly once across all workers.
  * **W-3** (status-filter resurrection): partner DELETE mid-poll
    does NOT have its last_polled_at rewritten.
  * **W-4** (followup claim): 8 concurrent followup workers →
    exactly 1 winner per row.

These tests CAUGHT a real race the source-level guard had hidden
(W-2 transaction scope was wrong — fixed in commit c3d2ba1).

### 4. Property-based tests (hypothesis)

20 tests across 3 critical parsers (commit e083f10):

  * `test_ssrf_property_based.py` — 7 tests, 200+ adversarial inputs
    each, probing the SSRF guard's IP/hostname/scheme deny list.
  * `test_canonical_address_key_properties.py` — 7 tests, 300+
    inputs, probing the address-dedup normalizer's algebraic
    properties (idempotence, EVM case-insensitivity, base58 case-
    preservation, malformed-input safety).
  * `test_xff_property_based.py` — 6 tests, 200+ inputs each,
    probing the rate-limit IP extractor against XFF-rotation
    attacks.

### 5. Output-integrity validator (`recupero.validators.output_integrity`)

27 structural invariants over the freeze-letter / LE-handoff
output. Catches CATEGORIES of bugs (routing, content, dedup, $
consistency) rather than specific instances. See
`docs/jacob-validation-spec.md` for the full check list.

### 6. Mutation smoke (`scripts/mutation_smoke.py`)

The canonical A++ proof: deliberately break specific known-critical
functions and confirm the test suite catches it. Current run
detects 5/5 mutations:

| # | Mutation | Detected by |
|---|---|---|
| 1 | dispatcher remove pg_advisory_xact_lock | test_w1_concurrent_dispatchers |
| 2 | api.app rate-limit offset → 0 | test_property_trusted_hops |
| 3 | _is_blocked_ip drop is_private | test_property_every_private_ipv4_is_blocked |
| 4 | canonical_address_key drop .lower() | test_property_evm_lowercase_and_uppercase_dedup |
| 5 | _is_blocked_host drop host.lower() | test_property_blocked_hostnames_case_insensitive |

Run:
```bash
export RECUPERO_RUN_INTEGRATION=1
export RECUPERO_INTEGRATION_DSN='postgresql://postgres:$PGPASSWORD@127.0.0.1:5432/recupero_int_test'
python scripts/mutation_smoke.py
```

The script auto-reverts each mutation and exits non-zero if any
goes undetected. Safe to run on a clean working tree.

### 7. Branch coverage gate (`scripts/coverage_safety_critical.sh`)

Scoped branch-coverage measurement for the modules that handle
customer money + legal evidence:
  * `payments/` — Stripe webhook + dispatcher
  * `validators/` — output_integrity
  * `freeze_learning/` — recorder + status + priors
  * `api/` — auth + monitoring_api + app endpoints
  * `portal/` — intake + status page + tokens

Current branch coverage:

| Module | Cover |
|---|---|
| payments/payment_links | 96% |
| portal/intake_notifications | 91% |
| portal/tokens | 88% |
| payments/webhook | 88% |
| portal/intake | 85% |
| api/auth | 84% |
| api/monitoring_api | 85% |
| payments/dispatcher | 84% |
| validators/output_integrity | 80% |
| freeze_learning/status | 76% |
| portal/server | 68% |
| freeze_learning/recorder | 67% |
| api/app | 65% |
| **TOTAL (scoped)** | **79%** |

Target: ≥90% on the scoped set. Current gaps are tracked in
RIGOR-4 (in-progress).

### 8. Static analysis (`ruff` + `bandit` + `mypy`)

Ruff config in `pyproject.toml`. Current ruleset: E/F/I/N/UP/B/A/
C4/RET/SIM. Per-file ignores for typer + FastAPI `Option/Depends`-
in-default patterns (B008 is intentional there).

Run:
```bash
python -m ruff check src/ tests/
```

Real bugs caught + fixed during the RIGOR-2 pass:
  * F821 in `freeze/asks.py:808` (latent crash)
  * B039 in `logging_setup.py:41` (concurrency leak)
  * B905 in `test_email_retry.py:110` (silent truncation)
  * 6 × B017 in test files (narrowed exception types)
  * 26 collateral regressions caught by tests (psycopg mock-patch pattern)

### Where to start, by role

* **New engineer**: `scripts/setup_test_db.sh` + `python -m pytest -q`
* **Reviewer of a freeze-letter change**: run the V-CFI01 e2e fixture
  through the 27-invariant validator
  (`tests/test_output_integrity_validator.py::test_v_cfi01_e2e_passes_validator`)
* **Reviewer of a race-condition fix**: run the
  `test_real_concurrent_races.py` battery
* **Reviewer of any security-sensitive change**: run the mutation
  smoke harness (`scripts/mutation_smoke.py`)
* **Pre-release sign-off**: full `pytest -q` (no skips) + scoped
  coverage gate + mutation smoke + validator on V-CFI01.
