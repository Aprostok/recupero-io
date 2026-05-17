# Reply to Jacob — 2026-05-17

> Draft of the response. Trim / re-tone before sending; this is the
> raw substance. Sections roughly follow the order of Jacob's two
> emails (reliability asks + the night-end PR-shipped update).

---

Hey Jacob —

Quick status before the substance: **Asks #1 and #2 are shipped on
the worker.** Tags `v0.5.1` (retry-with-backoff) and `v0.5.2`
(editorial pre-fill) are on `main` and Railway-deploying now.
Run another smoke test against V-ZTST01 whenever — the editorial
pre-fill will populate three of the four fields from the cases
row; one (address_line2) is preserved as TODO because that column
in your test row has the literal string `'TODO: victim
city/state/zip'` persisted in it (probably stamped during the
smoke runs). The pre-fill defensively rejects any value that
already starts with `TODO`, so the operator review form prompts
cleanly there.

Also separately shipped today: **v0.5.0 customer portal** at
`/portal/<token>` (status page + e-sign flow + signed-URL artifact
downloads) and a **promote-freezable ops command** for the
INVESTIGATE→FREEZABLE workflow. New tables: `case_tokens`,
`engagement_signatures`. New columns on `watchlist`:
`kyc_confirmed_at`, `kyc_confirmed_by_operator`,
`kyc_confirmation_note`. All migrations applied to prod.

---

## Ask #1 — Retry-with-backoff (shipped in v0.5.1)

Wrapped `client.messages.create` (the editorial drafting call —
where the 529 hit) in an explicit 10s / 30s / 60s retry loop on
transient failures: `APIStatusError` (incl. 529), `APITimeoutError`,
`APIConnectionError`, `RateLimitError`, `httpx.TimeoutException`,
`httpx.ConnectError`, `httpx.RemoteProtocolError`. The Anthropic
SDK's built-in retry is disabled (`max_retries=0`) so our loop is
the single source of truth.

Non-transient errors (`BadRequestError` 400, validation) raise
immediately — no retry budget burned on caller bugs.

The audit you'd care about: **the Etherscan / Helius / Hyperliquid
/ CoinGecko clients already had `@retry` decorators** (4–5
attempts each, exponential backoff catching `httpx.TransportError`
+ rate-limit exceptions). Your ReadTimeout on the freeze-targets
stage was a Helius `get_parsed_transaction` call, which I noticed
is the one path that's missing the decorator — flagged that as a
follow-up; will roll it into a future patch.

Gaps I deliberately didn't wrap:
- **Resend email** (urllib-based, no retry). Email failures aren't
  blocking the pipeline cycle, so the impact of a one-off is
  small; I'll add tenacity wrap when it bites.
- **Supabase Storage PUT/GET** (httpx, no retry). Same reasoning.

Worst-case extra latency on a healthy run: 0. Worst case on a
sustained 529: ~100s, vs the 25-minute restart it would have cost.

Every retry logs a WARNING with status code + attempt number, so
you'll see them in the Railway logs and can quantify how often
they fire.

## Ask #2 — Editorial pre-fill (shipped in v0.5.2)

Four-field mapping, exactly as you specified:

| brief_editorial field   | cases column    |
|-------------------------|-----------------|
| VICTIM_ADDRESS_LINE1    | address_line1   |
| VICTIM_ADDRESS_LINE2    | address_line2   |
| VICTIM_JURISDICTION     | jurisdiction    |
| IC3_CASE_ID             | ic3_case_id     |

Wired through `WorkerDB.fetch_case` → `CaseData` → the worker's
editorial stage builds a `case_row_prefill` dict from non-empty
columns → `run_ai_editorial` applies it as the LAST step in
editorial assembly (so case-row values beat both AI TODO output
and the heuristic split from `victim.json`).

`IC3_CASE_ID` is a new key in the editorial dict. It also lands
in the final brief alongside the existing `IC3_COMPLAINT_NUMBER`
(I kept both — IC3_COMPLAINT_NUMBER is reserved for the
post-filing complaint number IC3 sends back, distinct from the
operator-curated `ic3_case_id` captured at intake).

Backward compat: NULL columns → no pre-fill → existing TODO
behavior preserved. Pre-PR-#12 rows behave identically to today.

Other operator-supplied fields the worker currently TODOs that
DON'T have cases columns yet — three candidates worth discussing
if you want a follow-up pass:

- `CASE_ID` — currently auto-derived from case_number, no TODO
  in practice. No column needed.
- `INCIDENT_DATE` — pulled from `cases.incident_date`; already
  not a TODO in the normal path.
- A few static investigator-identity fields (NAME, EMAIL,
  ENTITY) — these are constants in `STATIC_EDITORIAL_DEFAULTS`,
  not TODOs.

So I think we've covered the operator-pain TODOs that have
existing-or-natural cases-row backing. If you spot another in
the wild, ping me.

## Ask #3 — Stage-level checkpointing (discussion)

> *Whether the implementation outline matches how I'd approach it*

Mostly yes, with one re-shape:

I'd prefer **per-stage timestamps in a JSONB column on
investigations** over a separate `investigation_stages` table.
Concretely:

```sql
ALTER TABLE public.investigations
  ADD COLUMN stage_state jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Per-stage completion fingerprint:
-- {
--   "tracing":             {"completed_at": "...", "artifact": "case.json",  "artifact_etag": "abc..."},
--   "freeze_targets":      {"completed_at": "...", "artifact": "freeze_asks.json",  "artifact_etag": "..."},
--   "editorial_drafting":  {"completed_at": "...", "artifact": "brief_editorial.json", ...},
--   "emitting":            {"completed_at": "...", "artifacts": ["freeze_request_*.pdf", ...]}
-- }
```

Two reasons over a separate table:

1. The stages aren't really first-class entities — they're
   transient pipeline state. A JSONB blob is the right
   abstraction.
2. We can write the stage marker in the same transaction as the
   `investigations.status` update, so resume logic never sees a
   half-committed state.

On the artifact-staleness question — "valid for resume vs needs
regen" — the simplest answer is **a staleness TTL per stage**:

- `tracing`            → stale at 24h (balances move)
- `freeze_targets`     → stale at 24h (balances move)
- `editorial_drafting` → never stale (text doesn't decay)
- `emitting`           → never stale

Stored on the stage_state entry as `valid_until`. Resume reads
each stage's marker, and if `valid_until < NOW()` regenerates
from that stage forward. Conservative default, no surprise
staleness.

> *Rough effort estimate*

I'd budget **4–5 days end-to-end**, broken down:

| Phase | Work | Days |
|---|---|---|
| 1 | Schema (stage_state jsonb) + write markers from each stage | 1 |
| 2 | Resume entry point (claim_one reads stage_state + skips ahead) | 1 |
| 3 | Idempotency audit on every stage's side effects | 1–2 |
| 4 | Staleness TTL + tests + production rollout | 1 |

Phase 3 is the big variable. There are at least 5 places where
stages write DB rows or upsert watchlist entries that need
review for idempotency (re-running them shouldn't double-count
or duplicate). Most will be one-line tweaks (`INSERT ... ON
CONFLICT DO NOTHING`); the watchlist sync is the one I'd want
to think about hardest.

> *Gotchas in the current pipeline state machine*

Three real ones:

1. **The `failed` status is terminal today**, and your new retry
   endpoint creates a fresh `pending` row that inherits the
   parameters. Resume mechanics would either need:
   - A new `failed_resumable` status that the resume claim can
     pick up, OR
   - Modify your retry endpoint to copy `stage_state` from the
     source row into the new row, so the new row starts already
     "skipped past" the completed stages.

   I'd recommend option 2 — keeps the state-machine simple and
   reuses your existing retry plumbing.

2. **Stage boundaries aren't currently clean.** The `_stage_*`
   functions in `pipeline.py` return implicitly via side effect
   (writing case.json, freeze_asks.json, etc.). To check `is
   this stage's artifact present and valid?` reliably we'd need
   each stage to return a structured `StageResult` carrying the
   artifact name + an etag/hash. Mechanical refactor — couple
   of hours.

3. **The freeze-target enumeration also writes to `public.watchlist`**
   (inserts FREEZABLE rows for the dashboard to monitor). Resume
   needs to either:
   - Upsert by (case_id, address) so re-runs don't duplicate, or
   - Skip the watchlist write if the stage marker says completed.

   The upsert is cheaper to implement and more robust.

Want me to write a 1-page design doc you can review before I
queue this in? I'd rather we agree on the state-machine shape
in 30 mins of email back-and-forth than discover a gotcha at
day 3 of implementation.

---

## Capability mapping — confirm

> *Is yes/limited/no/default → HIGH/MEDIUM/NOT FREEZABLE/LOW
> canonical?*

Confirmed canonical, with one tightening:

| Internal (`freeze_capability`) | UI display    |
|--------------------------------|---------------|
| `yes`                          | HIGH          |
| `limited`                      | MEDIUM        |
| `no`                           | NOT FREEZABLE |
| `unknown`                      | LOW           |

The fourth value is explicitly `"unknown"` — not just "anything
not in the first three." `freeze/asks.py` line 56 documents the
enum, and `seeds/issuer_freeze_capability.json` is the curated
source of truth. Lock the comment as "yes / limited / no /
unknown → HIGH / MEDIUM / NOT FREEZABLE / LOW (definitive)."

---

## Engagement state — heads-up on the portal flow

Two paths now write to `engagement_started_at` /
`engagement_closed_at` / `engagement_fee_paid_usd`:

1. **Admin UI** — your `Mark Engaged` / `Mark Closed` / `Reopen`
   buttons.
2. **Customer portal** — when the victim e-signs at
   `/portal/<token>/sign`, the worker INSERTs an
   `engagement_signatures` row + UPDATEs the investigation's
   engagement columns.

The portal flow is **idempotent on the engagement clock**: it
uses `COALESCE(engagement_started_at, NOW())` so it never
resets an already-set start time. Sequence-wise:

- Operator Mark-Engaged first, then customer signs → signature
  recorded, engagement_started_at preserved (operator's
  timestamp wins). The customer's signature_name + agreement
  text still appear in `engagement_signatures` for audit.
- Customer signs first, then operator Mark-Engaged → if your UI
  uses `engagement_started_at = NOW()` unconditionally, it WILL
  overwrite the portal's timestamp. Probably worth changing the
  admin UI to also use `COALESCE` so the earlier of the two
  wins. Tiny tweak, big consistency win.

Other operator UI guards you mentioned to think about:

- **`engagement_started_at < engagement_closed_at`** — yes, my
  automation assumes this. The follow-up cron skips
  `engagement_closed_at IS NOT NULL` rows, but if `closed_at`
  ever precedes `started_at`, the dashboard's `days_remaining`
  and the portal's `days_since_start` will both go negative.
  Worth a UI guard.
- **Fee can only be set during an active engagement** — my
  side doesn't care (the portal only reads
  `engagement_fee_paid_usd` for display); but it'd be cleaner
  semantically to gate the inline fee editor on
  `engagement_started_at IS NOT NULL`.

---

## TODO-rejection at the UI — nice

Your new "review form blocks operator approval when TODOs
remain" is a great move; it pulls the safety net forward into
the UI where it's actionable. After v0.5.2's pre-fill, the
common case is **zero TODOs** on case-driven runs where the
cases row is populated. The UI guard catches the edge cases
(operator skipped an intake field, or the AI hallucinated a
TODO into a field that doesn't have a cases column yet).

If you want a clean way to surface "what TODOs are left" at the
top of the review form, the editorial dict's
`AI_GENERATED: true` + `REVIEW_REQUIRED: true` markers are still
in there, and each field has a `_AI_CONFIDENCE` sibling
(`low | medium | high`). Pre-filled fields are now marked `high`
so you can de-emphasize them in the review UI.

---

## Customer portal — heads-up + the open question

`/portal/<token>` is live but it's behind whatever URL Railway
deploys to. We need a **public hostname** for `RECUPERO_PORTAL_BASE_URL`
before we email any of these links to customers. Options:

- Re-use the Railway-assigned domain (works, ugly URL).
- Point a subdomain at the worker (`portal.recupero.io` →
  Railway).

If you've got DNS access, the subdomain takes ~10 mins; I'll
update the worker's env var once it's pointed.

In the meantime, the `recupero-ops generate-customer-link
<case_id>` command warns when the env var is unset and falls
back to a `localhost:8080` URL so we don't accidentally email
a customer a broken link.

---

Holler if you want me to expand on the checkpointing design,
or if any of v0.5.1/v0.5.2 surfaces problems on the smoke test.

— Alec
