# V030_2 narrow self-audit: dba4d1a (+ f7def81 carry-over)

Scope: only changes introduced by `dba4d1a` (`v0.30.1` preflight) layered
on `f7def81`. Earlier surfaces covered by `V029_AUDIT_FINDINGS.md` /
`V030_ROUND_N_AUDIT.md` are out of scope.

Diff manifest used: `git diff f7def81 dba4d1a` — 14 files,
+1127 / -43.

---

## TIER-1 CRITICAL — fix before merge to `main`

### T1-A. `gate_label_db_validator` fails on the clean path
`scripts/deploy_preflight.py:124-127` checks for the substring
`"Errors:   0"` (or `"Errors: 0"`) in the validator output. But
`src/recupero/labels/validator.py:442-444` returns early with only
`"Clean — zero issues."` when `report.issues` is empty — the `Errors:`
line is never printed in the all-clean case.

Effect: a fully-clean Label DB makes this gate report FAIL with
"Label DB validator reported errors", blocking every prod merge until
someone adds a (placeholder) warning to issuers.json or operator
ignores the gate. Replace the substring scan with
`result.returncode != 0` (validator already exits 0/1 correctly per
line 444 / line 462 of validator.py).

### T1-B. `gate_smoke_deliverables` hardcodes a Windows-only fixture path
`scripts/smoke_deliverables.py:33` —
`Path(r"C:\Users\apros\Downloads\recupero-io\data\cases\ALEC-TEST-2026")`
is the developer's machine. The preflight invokes this as a
subprocess (`scripts/deploy_preflight.py:155-159`). On the CI
runner / Linux Railway runner that path does not exist; smoke
prints `FAIL: fixture not found` and returns 1, failing the gate
unconditionally. The preflight as shipped is therefore not runnable
in CI — only on the author's laptop. Parameterize via
`scripts/_smoke_deliverables_out/..` relative to the repo, or read
the fixture path from an env var with a portable default.

---

## TIER-2 HIGH — degrades quality

### T2-A. Preflight detail strings + JSON mode can leak env values
`scripts/deploy_preflight.py:131-137`, `170-176`, `199-205` embed
the last 1500–2000 chars of subprocess `stdout`/`stderr` into the
gate `detail`. `--json` (line 313-321) re-emits these verbatim.
Pytest tracebacks routinely include `assert os.environ ==` /
`assert "RECUPERO_..." in str(...)` style frames, and a failed gate
detail pasted into Slack/Jira would leak whichever env value
appeared in the traceback. Add a redactor: scrub any value matching
`RECUPERO_TOKEN_PEPPER` / `SENTRY_DSN` / `SUPABASE_DB_URL` /
`PGPASSWORD` substrings before writing into `detail`. The same risk
applies to `gate_label_db_validator` (it concatenates stdout+stderr
without filtering).

### T2-B. `--quick` silently skips the mutation harness on prod merges
`scripts/deploy_preflight.py:96-103` returns `passed=True, fatal=False`
when `--quick` is set. Combined with the `PASS` print at line 339,
an operator who copies a stale `--quick` invocation from a dev iteration
will see green and merge to main without the 33/33 mutation
guarantee that the doctext at line 16-17 claims. Either (a) refuse
`--quick` when stdout is a TTY and the working tree is at `main`,
or (b) print a banner at the bottom like `WARN: --quick skipped
mutation_harness — DO NOT use for prod merges.`

### T2-C. Coinbase issuer metadata in test fixtures is now stale
The seed (`src/recupero/labels/seeds/issuers.json:102`) changed
Coinbase `primary_contact` to `subpoenas@coinbase.com`, but
`tests/test_v_cfi01_full_render.py:401-405` (`_build_issuer_metadata`)
still hardcodes `contact_email: "compliance@coinbase.com"`. That
metadata wins over the seed in `emit_brief.py:805`, so every
V-CFI01 test renders an artifact that contradicts the seed. Update
the fixture or the audit value is invisible in fixture-driven
end-to-end output.

---

## TIER-3 MEDIUM — polish

### T3-A. `__all__` rationale comment is inaccurate
`src/recupero/_common.py:672-677` justifies the export by claiming
"without this the deploy gate is bypassable via wildcard import."
No module in the tree uses `from recupero._common import *` (grep
verified). The export is defensible as future-proofing but the
threat model in the comment is fictional — soften the wording.

### T3-B. `display_country` TypeError on non-string `country`
`src/recupero/worker/_le_routing.py:368` does
`(parsed_country or country or "").strip()`. If a caller passes a
non-string truthy `country` (signature is `str | None` but Python
doesn't enforce), `parsed_country` is `None` (parser returns
`(None, None)` for non-str), `country` is truthy, and `.strip()`
on a non-str raises `AttributeError`. Defensive: coerce with
`str(... )` before strip. Low likelihood; cheap fix.

### T3-C. `_v030_1_contact_note` provenance lives in a field nobody reads
`src/recupero/labels/seeds/issuers.json:294` adds a long inline
`_v030_1_contact_note` and `validator.py:106-111` whitelists it.
The note will not surface in any operator-facing output. Acceptable
for one-off provenance, but if this becomes a pattern, route it
through a `source` field with structured metadata instead of free-text
keys that proliferate per audit cycle.

### T3-D. FBI VAU contact "softening" still ships the unverified address
`src/recupero/worker/_le_routing.py:91` keeps
`email="cryptocurrency@fbi.gov"` even though the description (lines
93-103) admits it has not been independently verified. The contact
card is still rendered into the LE handoff. Per the V030_CONTACT_AUDIT
principle ("never claim this is the official VAU email in client
correspondence"), consider setting `email=""` and surfacing only the
description prose, so a customer reading the rendered HTML never
sees the unverified address as a `To:` field.

---

## Negative findings (examined, found nothing)

* **Thread-safe LabelStore cache** (`src/recupero/reports/brief.py:1308-1345`):
  double-checked locking is correctly implemented. The outer-guard
  uses both `_LABEL_STORE_CACHE[0]` (capture into local `store`) AND
  `_LABEL_STORE_LOAD_ATTEMPTED[0]`; the inner-guard re-checks both
  under the lock. The failed-load case (`cache=None, attempted=True`)
  correctly suppresses further load attempts. `threading.Lock` is
  non-reentrant but `LabelStore.load` does not re-call
  `_enrich_via_label_store`, so re-entry is not reachable. List-as-cell
  mutation under the GIL + lock is atomic. **No bug.**

* **Conftest pepper auto-set** (`tests/conftest.py:160-182`): set only
  when env is empty (`if not os.environ.get(...).strip()`), so a CI
  with a real prod pepper is untouched. 64-hex-char value is a valid
  32-byte input for `_token_pepper()` (`src/recupero/portal/tokens.py:79-88`).
  The deterministic value is clearly labeled. **No leak risk.**

* **Citizenship strip in `issuer_freeze_request.html.j2`**: no test
  asserts `victim.citizenship` appears in this template; the only
  passing-citizenship test (`tests/test_brief.py:245`) does not check
  for it in output. **No test breakage.**

* **FRAX `freeze_capability` flip `limited` → `no`**: grep of `src/`
  found zero `freeze_capability == "limited"` literal branches —
  consumers route via `_NON_FREEZABLE_CAPABILITIES` /
  `_FREEZABLE_CAPABILITIES` frozensets in `src/recupero/_common.py:47-52`,
  and `"limited"` is in the freezable set while `"no"` is in the
  non-freezable set. The flip correctly moves FRAX from
  freezable-route to UNRECOVERABLE-route. **No silent mishandling.**

* **`__all__` additions to `_common.py`**: symbols exist in the file
  (`is_investigator_configured` line 501, `require_investigator_configured`
  line 522, `INVESTIGATOR_NAME_UNCONFIGURED` line 462) and the
  `__all__` tuple is syntactically valid. **No import surface error.**

* **Paxos / First-Digital / Tether contact updates**: no test asserts
  the OLD addresses as required substrings; `tests/test_v028_hardening.py:931`
  already expects the NEW `subpoenas@coinbase.com`. **No test regression.**

* **`unsigned_brief_detection` ordering**: `gate_smoke_deliverables`
  precedes `gate_unsigned_brief_detection` in the `gates` list
  (`scripts/deploy_preflight.py:225-232`), so the smoke output is
  on disk before F7 reads it. If smoke fails, F7 returns
  `passed=True, fatal=False` (line 195-198) — overall preflight still
  fails on the smoke gate. **Order is correct.**

---
*Audit by: opus-4.7-1M-context, 2026-05-26. Read-only — no code modified.*
