# Stage-level checkpointing — design doc

> Response to Jacob's reliability Ask #3, 2026-05-16. Sized: 1
> day + open-question discussion, not the original 4–5 days.
> The codebase has more checkpointing infrastructure than I
> realized when I wrote the first reply.

---

## TL;DR

The artifact-existence resume mechanism Jacob proposed is
**already implemented** for same-investigation re-runs. What's
actually missing is:

1. **Retry-from-failed inheritance** — Jacob's retry endpoint
   creates a fresh `pending` row, but the new row doesn't see
   the old row's artifacts (bucket prefix is keyed by
   investigation_id). Need either artifact-copy on retry, or
   a "resumable failed" state model.
2. **Staleness TTL per artifact type** — trace + freeze-target
   artifacts capture point-in-time balances; reusing them a
   week later silently drifts. Today there's no expiry check.
3. **DB-side stage state for ops visibility** — the resume
   logic works correctly without it, but the admin UI can't
   currently show "paused at editorial_drafting for 3 hours"
   because completion timestamps for intermediate stages aren't
   recorded.

Total real work: **1 day**, not 4–5. Most of the heavy lifting
is already on disk.

---

## What's already in place

Pipeline (`src/recupero/worker/pipeline.py:311–334`) already
checks bucket existence before each stage:

```python
has_case      = store.exists("case.json")
has_freeze    = store.exists("freeze_asks.json")
has_editorial = store.exists("brief_editorial.json")

if not has_case:
    _run_stage(db, inv.id, S.TRACING, lambda: _stage_trace(...))
else:
    _hydrate_local_from_bucket(...)  # reuse, don't regenerate

if not has_freeze:
    _run_stage(db, inv.id, S.LISTING_FREEZE_TARGETS, ...)
else:
    _hydrate_local_from_bucket(...)
# ... same pattern for editorial
```

Side effects are already idempotent:

- `_populate_watchlist` uses `ON CONFLICT (address, chain,
  investigation_id) DO UPDATE` (watchlist.py:91) — re-runs
  refresh in place.
- `mark_*` DB writes on `investigations` are idempotent UPDATEs
  by primary key.
- `_local_case_dir` is a temp-dir context manager; nothing leaks
  between runs.
- `claim_one` uses `FOR UPDATE SKIP LOCKED` (db.py:222) so two
  workers can't both pick up the same investigation.

So the **same-investigation resume case already works correctly
today**. A worker crash mid-pipeline → next claim cycle re-picks
the row (status stays `claimed`) → existence checks skip
completed stages → resume from first missing artifact. This is
the design Jacob outlined; it's just been quietly working.

## What's actually missing

### Gap #1 — Retry-from-failed inheritance

Jacob's `POST /api/admin/investigations/[id]/retry` creates a
**new** investigation row with a **new** UUID. The artifact
existence check looks at `investigations/<NEW_UUID>/case.json`,
which doesn't exist, so the new row redoes the trace from
scratch. The original investigation's artifacts sit unreferenced.

**Two options:**

**A. Same-investigation-id resume (recommended)**
- Don't create a new row on retry. Instead:
  - Reset `status` from `failed` → `pending`
  - Clear `worker_id` / `claimed_at` / `failed_at` / `error_message`
  - Increment a new column `retry_count` for audit
- The next `claim_one` picks it up. Existence checks skip past
  completed stages. Same investigation_id means same artifacts.
- Trade-off: loses the "preserve failed rows as audit history"
  property. Mitigation: copy the failed row's `error_message`
  and `failed_at` to a `prior_failures` jsonb column before
  resetting, so the audit trail is preserved on the same row.

**B. New-row-with-copied-artifacts**
- Retry creates a new investigation_id (current behavior).
- Before insert, copy the bucket prefix
  `investigations/<old_id>/*` → `investigations/<new_id>/*`.
- The new row's existence checks then see the prior artifacts.
- Trade-off: doubles bucket storage; copy operation can fail
  partially and leave the new row in a weird half-resumed
  state.

**My recommendation: A.** Cleaner semantics, no storage waste,
preserves the audit chain on a single row. The `prior_failures`
array column captures the history without needing a parallel
row.

### Gap #2 — Staleness TTL

Today, an artifact written 2 weeks ago is reused on resume
without question. For text-only artifacts (editorial draft)
that's fine — the prose doesn't decay. For balance-sensitive
artifacts (trace, freeze_targets), balances can move
substantially in 24h, and a stale freeze letter sent to an
issuer based on yesterday's balance is at best embarrassing.

**Schema addition:**

```sql
ALTER TABLE public.investigations
  ADD COLUMN stage_completed_at jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Shape:
-- {
--   "tracing":             "2026-05-16T22:00:00+00:00",
--   "listing_freeze_targets": "2026-05-16T22:03:12+00:00",
--   "editorial_drafting":  "2026-05-16T22:08:45+00:00",
--   "emitting":            "2026-05-16T22:09:30+00:00",
--   "building_package":    "2026-05-16T22:09:55+00:00"
-- }
```

The pipeline writes one timestamp per completed stage. The
existence check becomes:

```python
def is_artifact_valid(stage_name: str, artifact_name: str) -> bool:
    """Check whether the on-disk artifact for `stage_name` is
    both present AND not past its staleness TTL."""
    if not store.exists(artifact_name):
        return False
    completed_at = inv.stage_completed_at.get(stage_name)
    if completed_at is None:
        # Pre-checkpoint-feature row — trust the artifact. The
        # alternative (forcing regen on every legacy row) is
        # too aggressive.
        return True
    ttl = STAGE_STALENESS_TTL.get(stage_name)
    if ttl is None:
        return True  # never stale (text-only stages)
    return (datetime.now(timezone.utc) - completed_at) < ttl

STAGE_STALENESS_TTL = {
    "tracing":                timedelta(hours=24),
    "listing_freeze_targets": timedelta(hours=24),
    "editorial_drafting":     None,  # never stale
    "emitting":               None,
    "building_package":       None,
}
```

24h is conservative — sufficient for "I crashed last night,
resume in the morning" but tight enough that a week-old trace
gets regenerated automatically.

### Gap #3 — Ops visibility

The dashboard currently surfaces `awaiting_review` rows past 24h
(my v0.4.3 `stale_review` widget). It can't surface "paused
mid-stage for X hours" because the per-stage timestamps don't
exist.

Once gap #2 lands, this is free — the dashboard query becomes:

```sql
SELECT id, case_id, status,
       stage_completed_at,
       triggered_at,
       (SELECT max(value::timestamptz)
          FROM jsonb_each_text(stage_completed_at)) AS last_progress_at
  FROM public.investigations
 WHERE status IN ('claimed', 'tracing', 'editorial_drafting', 'emitting', 'building_package')
   AND triggered_at < NOW() - INTERVAL '30 minutes';
```

`last_progress_at` lets the UI show "stuck at editorial_drafting
since 2h ago" instead of just "stuck somewhere."

---

## Effort estimate (revised)

| Phase | Work | Hours |
|---|---|---|
| 1 | Migration 010 (`stage_completed_at` jsonb, `prior_failures` jsonb, `retry_count` int) | 1 |
| 2 | Pipeline writes per-stage timestamp on completion | 1 |
| 3 | Existence check becomes existence+TTL check | 1 |
| 4 | `db.mark_resumable(inv_id)` replaces the new-row retry pattern; Jacob updates the API endpoint to call it | 1 |
| 5 | Dashboard `stale_mid_stage` widget (parallel to `stale_review`) | 1 |
| 6 | Tests + canary verify + docs | 2 |

**Total: ~1 day of focused work.** Down from my original 4–5
estimate because I was assuming we'd build the existence-check
resume from scratch; that's already done.

## Open questions for Jacob

1. **Same-id-resume (A) vs new-id-with-copy (B)?** I recommend
   A; want your read on whether the admin UI's history view
   needs separate rows per attempt or can render attempts from
   a `prior_failures` jsonb column on one row.

2. **24h TTL for trace + freeze_targets — too aggressive?**
   Most cases finish in <30 minutes, so this only matters for
   crash-during-night-batch scenarios. If your customers
   typically want fresh balances even on a same-day resume, we
   could drop to 4h.

3. **Should the retry endpoint surface the prior failure to the
   operator before retrying?** "This investigation failed 3
   times at editorial_drafting (last error: 529 capacity).
   Retry anyway?" feels like a useful UX guard but adds a click.

4. **Wallet-trace investigations** (skip_editorial=true) don't
   currently pause at `awaiting_review` — they ride straight
   through to `complete`. Do they need separate staleness
   semantics, or does the trace-24h TTL already cover them?

## What I'd ship in phase 1 if we can't agree on phase 4

Phases 1–3 + 5 (schema, timestamps, TTL, dashboard widget) are
fully self-contained — they improve visibility and prevent
stale-artifact reuse without touching Jacob's retry endpoint.

Phase 4 (resume-from-failed) is the cross-team piece that
needs coordination. If we ship 1–3+5 in v0.6.0 and defer 4 to
when Jacob has bandwidth on the admin-UI side, the worker
still gets a meaningful reliability improvement.

---

## Anti-goals (out of scope)

- **Resume across worker version upgrades.** If artifacts were
  written by v0.4.x and we deploy v0.5.x with schema-breaking
  changes to `case.json`, regenerate. The TTL check covers
  this implicitly (artifacts older than TTL regenerate); for
  shorter-lived format changes, a one-off migration sets
  `stage_completed_at = '{}'` to force regen.
- **Multi-worker collaboration on a single investigation.**
  `FOR UPDATE SKIP LOCKED` keeps one worker per investigation;
  no need to coordinate parallel stage execution.
- **Customer-visible progress streaming.** Worth doing
  eventually for the portal — but a separate feature, not
  part of this design.
