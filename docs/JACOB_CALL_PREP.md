# Call prep: validator design + v0.20+ deferred items

For the walkthrough Jacob asked for after the v0.21.x sign-off.

---

## 1. The validator architecture — what it is, why it works

### The problem it solves

Pre-validator pattern (v0.18 through v0.20.14): each release added unit
tests for the **specific bug** found. The next bug landed in a layer
those tests didn't cover. Jacob's v0.20.15 review caught the
build_all_deliverables routing bug (issuer X's content written to
issuer Y's file) **because he opened 16 artifacts in a browser**. 1,800
existing unit tests didn't catch it because they were calibrated to
bugs already fixed, not to "the artifact as Jacob reads it."

### The validator approach

`recupero/validators/output_integrity.py` checks **structural
properties of the rendered output** that must hold for every case
regardless of shape. Each invariant derives its expected values from
the case's own data (`freeze_asks.json`, `freeze_brief.json`, the
manifest) — not hardcoded V-CFI01 facts. Works for any case shape.

### 28 invariants, three layers

**Layer 1 — basic file integrity (1-5)**
- Filename↔content consistency for issuer-named files
- HTML files have HTML root; JSON files parse as JSON
- No two files byte-identical
- Manifest `output_sha256` matches disk

**Layer 2 — case-correctness (6-12)**
- Every freezable issuer has both freeze_request + le_handoff
- TOTAL_FREEZABLE_USD reconciles across brief, engagement letter,
  victim summary
- STOLEN_ASSET_ISSUER ≠ FREEZE_TARGET_ISSUER in narrative
  (catches "USDT issued by Circle"-shape conflation)
- victim_summary variant matches MAX_RECOVERABLE_USD sign
- No unrendered Jinja in any HTML
- UNRECOVERABLE addresses don't appear as FREEZABLE anywhere
- Sky / DAI → UNRECOVERABLE everywhere

**Layer 3 — per-artifact + cross-artifact (13-27)**
- freeze_request `<title>` names the issuer
- freeze_request carries NO foreign compliance emails
- LE handoff Section 4.2 enumerates every issuer in ALL_ISSUER_HOLDINGS
- LE handoff body cites a $ figure (unfileable without one)
- trace_report doesn't carry freeze-request language (cross-template
  leakage)
- engagement_letter exists iff MAX_RECOVERABLE_USD > 0
- engagement_letter / victim_summary contain victim name + $ figure
- flow_*.svg has `<?xml`/`<svg` root
- CSV well-formed when FREEZABLE non-empty
- CASE_ID consistent across every artifact
- brief.asset.symbol matches trace_report + LE handoff
- brief.victim.name matches every customer artifact
- recovery_snapshot exists iff MAX_RECOVERABLE_USD > 0

**Layer 4 — Jacob's v0.21.x signoff residuals (28)**
- `unrecoverable_total_matches_holdings` — TOTAL_UNRECOVERABLE_USD
  equals sum of UNRECOVERABLE-status holdings across ALL_ISSUER_HOLDINGS
  (±$1 rounding tolerance).

### Severity rubric

| severity | meaning | gates publication? |
|---|---|---|
| `critical` | structural — file missing, content/filename mismatch, manifest SHA mismatch | yes |
| `high`     | factual — totals don't reconcile, victim name wrong, issuer conflation | yes |
| `medium`   | content quality — narrative says one thing, classification says another | warn but ship |
| `info`     | hygienic — orphan files, unusual filename patterns | report only |

### Where it runs

1. **In-test**: `tests/test_jacob_eyeball_pass.py::test_validator_passes_with_zero_critical_or_high` — every fixture build.
2. **In-CI**: post-deliverables stage in the worker pipeline.
3. **Ops CLI**: `recupero-ops validate-output <case_dir>`.
4. **Coverage**: 0 violations of any severity on V-CFI01 fresh-build.

### Why this pattern beats the old one

- Adding a new invariant catches the **class** of bug, not just one
  instance. Every future Jacob-style finding becomes a generic check.
- The validator runs against the **rendered output**, not the source.
  So even template-only edits that change rendered semantics get caught.
- Cheap to add: one Python function returning `list[Violation]`. No
  fixture changes needed for invariants that read brief.json fields
  the case already produces.

---

## 2. v0.20+ deferred items list

Items tracked but not yet landed, ranked by signal/blast radius.

### Will-do-soon

#### #129 — RIGOR-naming: rename `letter_language` → `letter_tier`
The column in `freeze_letters_sent` + `issuer_freeze_priors` is
misnamed. Values are escalation tiers (`standard`, `le_backed`,
`ausa_signed`, `mlat_routed`, `314b`, `subpoena`), not languages.

**Status:** drafted as a two-phase migration (additive ADD COLUMN +
backfill + dual-read window, then drop). Not yet applied. Schema
rename has real prod risk so it's a flagged decision.

#### #118 — S-5: drop raw `case_tokens.token` column
`case_tokens` stores both `token_hash` and the raw `token` value. The
raw value is sensitive (it's the portal access token in clear). Code
already prefers the hash for lookups. The raw column is a security
hygiene removal.

**Status:** dry-run drafted. Needs a code audit to confirm no callsite
still reads the raw column, then a migration to drop. Same risk
profile as #129.

#### #122 — RIGOR-4: coverage gate ≥90% on safety-critical modules
Codebase coverage is uneven. Safety-critical modules (payments
dispatcher, portal tokens, validators, freeze-outcomes intake,
canonical_address_key) should be at ≥90%. Right now the gate is
informal — operators run `coverage run -m pytest` ad hoc.

**Status:** in progress. The CI config exists but isn't wired into a
hard fail. Plan: add a `pytest --cov` step to CI with module-specific
fail-under thresholds.

### Future / non-urgent

#### #125 — RIGOR-7: production-shape E2E with zero warnings
The full pipeline runs in tests, but with assorted `DeprecationWarning`
hits from 3rd-party libs. The "production shape" E2E test should
elevate every recupero-namespace warning to an error and run the full
intake → trace → brief → letters pipeline against the test DB.

**Status:** open. Needs a single integration test that wraps the
ingest path with `filterwarnings = ["error::DeprecationWarning:recupero.*"]`.

### Closed in v0.21.x

These are the items Jacob flagged on 2026-05-23 that landed in this
release:

- **UNRECOVERABLE_USD rollup bug**: `TOTAL_UNRECOVERABLE_USD` now sums
  Sky-shape ($655K DAI) holdings from `ALL_ISSUER_HOLDINGS`, not just
  the editorial regex parse.
- **Perp-hub role/status mismatch**: role text branches on
  `freeze_capability` — "Holds DAI — UNRECOVERABLE" when
  `freeze_capability='no'`, "Holds X — freezable" otherwise.
- **New validator invariant**: `unrecoverable_total_matches_holdings`
  catches future drift between the two with $1 rounding tolerance.

---

## 3. Talking points

### "Why is the validator different from the punishing eyeball test?"
The eyeball test (`test_jacob_eyeball_pass.py`) is the regression
ladder — it pins specific findings from Jacob's actual reviews. The
validator is the **forward-looking** structural check — it catches the
*shape* of every class of bug we've seen, including ones Jacob hasn't
explicitly flagged.

Both should keep growing. Eyeball test → "we caught this specific bug
shape." Validator → "no case can ship in this broken shape going forward."

### "What's the next class of bug we're not covering?"
Three candidates:

1. **Cross-chain freeze logic.** Validator currently asserts symbols
   match across artifacts. Doesn't yet assert that chain IDs are
   consistent (a USDT row that mentions Solana in the brief but uses
   etherscan.io explorer URLs in the trace report).
2. **Timeline reconciliation.** Earliest-observed timestamps from
   freeze_asks should be ≤ the brief's `theft_event` timestamp.
   Catches future cases where the trace finds a destination wallet
   that received funds BEFORE the theft (suggests fixture corruption
   or upstream caching bug).
3. **Live-status pipeline truth.** Section 5.5 LE handoff renders
   "Pending issuer outreach" vs. "Letter sent, awaiting response" vs.
   "Frozen." Validator should assert that the rendered state matches
   the latest row in `freeze_letters_sent` + `freeze_outcomes`.

### "Can we measure the validator's bug-catching power?"
Yes — the mutation harness (`scripts/mutation_smoke.py`, 25/25). Each
mutation lifts a check; if any test still passes against the mutated
code, the test isn't doing real work. Today's harness covers the
canonical-address + advisory-lock + SSRF + portal-token + ReDoS layers.
We'd extend it with validator-specific mutations (flip the
`severity="high"` to `severity="info"`, swap `==` for `!=` in the
manifest SHA check) and assert each kills its targeted test.

---

## 4. Quick reference table

| Question | Answer |
|---|---|
| Where is the validator entry point? | `recupero.validators.output_integrity:validate_case_output(case_dir)` |
| How many invariants today? | 28 |
| Coverage on V-CFI01 fixture? | 0 violations of any severity |
| Coverage on prod (Jacob's real-Zigha smoke)? | Will be measured by Jacob's run after the v0.21.x deploy |
| Mutation harness kill rate? | 25/25 (was 15/15 pre-RIGOR sweep) |
| Where's the operator CLI? | `recupero-ops validate-output <case_dir>` |
| Where's the in-pipeline trigger? | `worker/_deliverables.py` (post-render stage) |
| What's the dev workflow for a new invariant? | Write a `_check_*` helper in `output_integrity.py`, add it to the `checks` list, write a unit test in `tests/test_output_integrity_deeper.py` |
