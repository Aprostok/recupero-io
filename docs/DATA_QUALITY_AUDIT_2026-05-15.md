# Data-quality audit — 2026-05-15

Snapshot of the production `public.cases` and `public.investigations`
tables after the wallet-trace fix push. Captures what's in the
operator triage queue, what's already-resolved test data, and which
rows still need human attention.

Audited against **17 cases total** (whole DB at time of audit).

## Findings

### 1. Placeholder seed_address (1 case) — RESOLVED

**Case 07831546** — Hekla (`hekla.partners@gmail.com`)
**Investigation:** `55703e71-aa74-4ee8-8ba6-1dddd045f27d`
**Seed:** `0x1234567890123456789012345678901234567890`

Sequential-digit placeholder, accepted by the intake form because
it's valid 0x-prefixed-hex. Pipeline ran fully, burned ~$0.15 of
Anthropic budget, sat in `awaiting_review` from 2026-05-09 to
2026-05-15.

**Resolution:** Marked failed with explanatory error_message. The
new `_is_obvious_placeholder_address` guard (commit `5069666`)
catches this pattern at claim time going forward. Frontend spec to
mirror the worker-side guard lives at
`docs/INTAKE_ADDRESS_VALIDATION.md`.

### 2. Submitted-but-never-traced Hekla cases (6) — OPERATOR DECISION

Six cases from `hekla.partners@gmail.com`, all in
`status='Submitted'` or `'Under Review'`, none with an investigation
row:

| Case # | Name | Status | Description |
|--------|------|--------|-------------|
| 58773133 | Fake | Submitted | "bad terrible horrible" |
| 87927731 | Fake | Submitted | "bad bad thing" |
| 79132039 | Fake | Submitted | "bad bad bad" |
| 35911400 | Test | Submitted | (other test data) |
| 33195664 | HP | Under Review | (other test data) |
| 81464285 | Hekla Partners | Submitted | (other test data) |

The names ("Fake", "Test", "HP") and descriptions ("bad terrible
horrible") strongly suggest Hekla was testing the intake form
repeatedly with junk data, not submitting real cases. No
investigations were ever triggered.

**Recommended action:** Manually verify with Hekla via email
(`hekla.partners@gmail.com`) — either close all 6 as test
submissions, OR if any are real (Hekla may have intended one of
the later "Hekla Partners" submissions to be real), promote that
one to a real investigation with a verified seed_address.

**NOT auto-resolved during this audit** — these are user-submitted
rows and the right disposition is an operator call.

### 3. Synthetic test fixtures from CI/local (4) — AUTO-CLOSED

Closed as `status='closed'`, `case_state='closed'` during this audit:

| Case # | Name | Email |
|--------|------|-------|
| V-058868 | Validation Run | val@test.local |
| T-form01 | Form Test Case | test@recupero.example |
| V-96a9b7 | Validation Run | val@test.local |
| S-77bd68 | E2E Smoke | e2e@test.local |

These are all my own test fixtures from prior validation passes.
Emails match the `*@test.local` and `*@recupero.example` synthetic
patterns. Closed to remove them from the operator triage queue.

### 4. Wallet-trace canaries (3) — PRESERVED for admin UI

| Inv ID | Label | Use |
|--------|-------|-----|
| `849062ab-6a82-4af2-bfd9-d7092a2701c5` | real-case validation | Primary — 3 transfers, $21,647 flow |
| `fa34bb56-4319-423c-9eed-c55d3b134948` | wallet-trace fix verification | Empty-trace edge case |
| `c78b2865-73c1-42cd-aa75-4ab168486512` | pre-fix canary | Historical |

Documented in `docs/INVESTIGATIONS_API.md`. Don't close these — the
admin UI builds against them.

### 5. Seed-address concentration (10 of 17)

Ten investigations all trace the same wallet
`0x8E3b200f356724299643402148a25FD4B852Bd53` — that's the standard
test fixture from `scripts/e2e_smoke.py`. Some belong to closed-out
test cases; some belong to ongoing validation runs (the canaries
above). Not a data-quality issue, just shape information for the
admin UI: the test wallet is over-represented in the index views
because of repeated validation runs.

If the admin UI needs to filter test runs out of the operator-facing
views, the simplest path is `label_prefix=` or filtering by
`triggered_by != 'alec@recupero.io'` (since most validation runs
were triggered by me).

## After-audit state

Pre-audit:

- 11 active cases in triage queue (incl. 4 synthetic test fixtures)
- 1 stale awaiting_review investigation (Hekla)
- 6 unprocessed Hekla submissions

Post-audit:

- 7 active cases in triage queue (4 synthetic closed, Hekla stays)
- 0 stale awaiting_review investigations (Hekla failed with proper
  error_message)
- 6 unprocessed Hekla submissions remain, flagged here for operator
  email follow-up

## Recurring audit recommendation

Run this audit monthly. The queries:

```sql
-- 1. Placeholder seed_addresses still slipping through (should be empty
--    once the frontend spec lands).
SELECT i.id, c.case_number, i.seed_address, i.status
  FROM public.investigations i
  JOIN public.cases c ON c.id = i.case_id
 WHERE i.seed_address ~ '^0x([0-9a-fA-F])\1{39}$'
    OR i.seed_address = '0x1234567890123456789012345678901234567890'
    OR i.seed_address = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

-- 2. Stale awaiting_review (should be < 24h, flag anything older).
SELECT id, case_id, review_required_at
  FROM public.investigations
 WHERE status = 'awaiting_review'
   AND review_required_at < NOW() - INTERVAL '24 hours';

-- 3. Submitted cases without an investigation row (intake-form failures).
SELECT c.case_number, c.client_email, c.created_at
  FROM public.cases c
  LEFT JOIN public.investigations i ON i.case_id = c.id
 WHERE i.id IS NULL
   AND c.status IN ('Submitted', 'submitted')
   AND c.created_at < NOW() - INTERVAL '7 days'
 ORDER BY c.created_at DESC;
```

The next followup (5-3, stale-awaiting_review alert) automates query
#2 so the operator gets notified instead of having to remember to
run the audit.
