# Jacob — test note for the v0.32.1 full-audit deploy

**Merged to `main` and deployed:** `78f3dcb` (Merge pdf-deliverables → main:
full-full audit fix wave). Railway auto-deploys `main`, so prod is shipping
this now. Local full regression before merge: **5071 passed, 0 failed, 28
skipped** (skips are env-gated only — live RPC opt-ins, Windows symlink
privilege, Postgres-integration with no test DB). Ruff: zero new errors.

---

## 1. Apply migration 031 (only new migration this deploy)

```
python scripts/apply_migration.py migrations/031_freeze_outcomes_silence_dedup.sql
```

- It's the **only** migration introduced vs. the prior `main` (021–030 already
  applied in earlier deploys).
- Additive + idempotent: `CREATE UNIQUE INDEX IF NOT EXISTS
  freeze_outcomes_one_silence_14d_per_letter ON public.freeze_outcomes
  (letter_id) WHERE outcome_type = 'silence_14d'`. Safe to run mid-deploy /
  re-run.
- **Not deploy-blocking for the worker.** The `recupero-worker` request path
  never touches it. Only the `recupero-cron` freeze-followup silence-write
  uses the paired `ON CONFLICT (letter_id) WHERE outcome_type='silence_14d'`,
  and that call is guarded (error → rollback stage advance → retry next tick),
  so a letter hitting the 14-day mark before 031 lands simply records its
  `silence_14d` marker on the next cron tick after you apply it. No crash, no
  data loss.
- **If `CREATE INDEX` errors** it means duplicate `silence_14d` rows already
  exist for some `letter_id`. De-dup manually (keep the earliest `observed_at`)
  then re-run. (Pre-031 the insert was unguarded, so a historical retry/race
  could have produced a duplicate.)

**Verify post-state** (read-only):
```sql
SELECT indexname FROM pg_indexes
 WHERE tablename = 'freeze_outcomes'
   AND indexname = 'freeze_outcomes_one_silence_14d_per_letter';
```

---

## 2. Production smoke test (the real-Zigha row)

Per your 2026-05-23 plan: insert / re-run the real-Zigha production row and
confirm the deliverable bundle matches the V-CFI01 fixture shape.

- **Case:** `ae47ab1e-61d6-468d-8bed-fa923b9fba3d`
- **Pass criteria** (same as the V-CFI01 acceptance bundle):
  1. **4 issuer freeze letters** rendered (one per freezable issuer).
  2. **Recoverable variant** of the victim summary selected (not
     UNRECOVERABLE / not EXCHANGE-only).
  3. **Manifest SHAs reconcile end-to-end** — every artifact's on-disk SHA
     matches its `manifest_*.json` entry.
  4. **Validator clean:** `validate_case_output(case_dir)` returns no
     `critical`/`high` violations.

The output-integrity validator is the fastest gate — run it on the produced
case dir and it will flag any cross-doc divergence, unrendered template, or
filename/content mismatch automatically.

---

## 3. What changed (10 commits) — where to look if a deliverable looks off

| Area | Change | Reviewer cue |
|------|--------|--------------|
| Bridge decode | Squid decoder no longer accepts free text as a **high-confidence** destination (operator-precedence bug; mirrored the Axelar fix). | A Squid hop with a garbage `destinationAddress` should now surface `confidence="medium"` and **no** destination address — never `high`. |
| Money model | `Transfer.amount_decimal` / `usd_value_at_tx` reject **negative + non-finite** at construction. `TokenRef.decimals` constrained `[0,255]`. | If a malformed RPC/price row used to slip a negative/NaN into a total, it now fails loudly at the model boundary instead of corrupting the loss figure. |
| Worker race | `watch_tick` now uses an atomic `FOR UPDATE SKIP LOCKED` claim (was a bare SELECT). | Two overlapping watch-tick crons no longer double-snapshot the same wallet / double-charge the RPC budget. |
| API | 256 KiB inbound request-body cap (Content-Length + streaming guard). | Any POST body > 256 KiB → `413`. Largest legit endpoint (`/v1/screen/bulk`, 100×128-char addrs ≈ 13 KB) is well under. |
| Validator | `validate_case_output` now scans `legal_requests/` for unrendered Jinja, not just `briefs/`. | A template bug in a subpoena/314(b)/MLAT draft is now caught. **Intentional `[TODO:]` attorney fill-ins are deliberately NOT flagged** — they're by-design blanks (courthouse, judicial district, return date) you fill in. |
| Trace | Unlabeled-counterparty list dedups on the **canonical** address key (collapses EVM checksum-case variants). | No more the-same-address-listed-twice in the brief's counterparty list. |

---

## 4. Two items I consciously deferred for your call (not bugs — judgment calls)

1. **Cross-document "total stolen" methodology.** `brief.py::_find_theft_events`
   clusters outbound seed transfers within a **168h window** of the largest
   event; `emit_brief.py::_compute_total_drained` sums **all** seed outflows
   (no window) → `TOTAL_LOSS_USD`. On a drain that spans **>7 days** these two
   figures diverge, and that materially changes the loss number we put in a
   legal document. I did **not** pick a winner — which one is "the loss" is a
   forensic-methodology decision (windowed-incident vs. total-exfiltration).
   **Need your ruling**, then I'll make them consistent + add an invariant.

2. **`Label.name` / `Label.notes` model-level validator.** I left this OFF.
   The ingestion boundary already rejects control/invisible-Unicode names
   (`auto_ingest.promote_candidate`), and downstream is escaped/sanitized. A
   model validator would be defense-in-depth but risks rejecting legitimate
   seed labels (non-ASCII exchange names, long notes). Low marginal benefit,
   real blast radius — flagging rather than landing unilaterally.

---

## 5. Rollback

If anything looks wrong post-deploy: revert the merge commit and push.
```
git revert -m 1 78f3dcb && git push origin main
```
Migration 031 is additive (an index) and safe to leave in place on a code
rollback — nothing reads it that the old code didn't tolerate.
