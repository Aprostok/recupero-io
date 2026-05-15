# Operator runbook

The on-call playbook when something breaks. Skim once before going on
vacation; refer to it when paged.

## Quick triage (first 60 seconds)

1. **Open Railway** → `recupero-worker` service. Are recent deployments
   green? Is the service Active?
2. **Hit `/healthz`** in a browser:
   `https://<railway-domain>/healthz` should return `{"ok": true}`.
   - 200 with ok=true → process is alive
   - timeout / 502 → process is down → check Railway logs
   - 503 / unhealthy → /healthz didn't bind → check application logs
3. **Hit `/health`** (slower, full readiness probe):
   `https://<railway-domain>/health` returns the env-var, DB, bucket,
   and package-integrity check results.
4. **Check the queue:** open the admin UI or run

   ```bash
   python scripts/check_stale_reviews.py --threshold-hours 0
   ```

   to see if any rows are stuck.

## Common failure modes

### Deploy fails healthcheck, container keeps restarting

Symptom in Railway logs:
```
1/1 replicas never became healthy!
Healthcheck failed!
```

**Cause is almost always missing/empty env var.** The strict startup
check (`worker/main.py:_missing_env_vars`) refuses to start the worker
unless all six required vars are present:

| Var | Where to find |
|---|---|
| `SUPABASE_URL` | Supabase dashboard → Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase dashboard → Settings → API → service_role |
| `SUPABASE_DB_URL` | Supabase dashboard → Settings → Database → Connection string. Use the **transaction pooler** URL (port 6543, hostname starts with `aws-1-...pooler.supabase.com`), not the direct host. |
| `ETHERSCAN_API_KEY` | https://etherscan.io/myapikey |
| `ANTHROPIC_API_KEY` | https://console.anthropic.com/settings/keys |
| `COINGECKO_API_KEY` | https://www.coingecko.com/en/api (demo tier OK) |

The first log line in the failed deploy says exactly which var is missing:
```
ERROR  missing required env vars: ETHERSCAN_API_KEY. The worker refuses to start...
```

**Fix:** add the missing var in Railway → Variables → save. Railway
auto-redeploys. New deployment should pass healthcheck within ~60s.

### Worker is up but every investigation fails

Look at `error_stage` in Supabase:

```sql
SELECT status, error_stage, COUNT(*)
  FROM public.investigations
 WHERE failed_at > NOW() - INTERVAL '1 hour'
 GROUP BY status, error_stage;
```

| `error_stage` | What it means | Fix |
|---|---|---|
| `tracing` | Etherscan call failed (rate limit, timeout, or bad API key) | Check ETHERSCAN_API_KEY validity. Look at error_message for HTTP status. |
| `finding_freeze_targets` | Dormant detector or freeze matcher failed. Often a pricing-API issue or contract enumeration. | Check error_message. Most common: CoinGecko timeout. |
| `drafting_editorial` | Anthropic API failure | Check ANTHROPIC_API_KEY validity, account credit balance, and Anthropic status page. |
| `emitting` | brief_editorial.json malformed (TODOs not filled, REVIEW_REQUIRED still true) | Open the bucket file, check, re-save. |
| `building_package` | Brief generator failure (template error, fund-flow rendering) | Check error_message; often a Graphviz binary issue if it's a fresh container. |
| `setup` | cases row referenced by case_id not found | The investigations row references a case_id that doesn't exist in `cases`. Either the cases row was deleted or never existed. |

### Stale `awaiting_review` rows piling up

Symptom: the daily `recupero-stale-review-check` task fires with rows
older than 24h that nobody has approved.

**Cause:** human review checkpoint. The pipeline pauses every
investigation at `awaiting_review` so the operator can review the
AI-drafted editorial before the brief ships. If nobody clicks
approve, the row sits there forever.

**Fix:** for each row in the alert,
1. Open the admin UI → review the AI editorial → approve or edit
2. Or set status='review_approved' directly in SQL if you trust the
   draft as-is

### Worker claims a row, never transitions, no errors

Symptom: investigation status sits at `tracing` or `finding_freeze_targets`
for >30 min with no error and no transition.

**Likely cause:** trace fan-out exploded into a service wallet (was a
problem before commit `a6e743a`'s fan-out cap). Or genuine network
slowness on Etherscan / CoinGecko.

**Triage steps:**

1. Check `last_heartbeat_at` on the row. If it's recent (<60s), the
   worker is alive and making progress, just slow. Be patient or check
   Railway logs for `INFO  fetching outflows` lines progressing.
2. If `last_heartbeat_at` is stale (>5min), the stale-claim reaper
   will pick it up automatically on the next claim cycle. The row gets
   marked `failed` with `error_message='reaper: heartbeat older than 300s'`.
3. To force-reclaim immediately, set the row's status='pending' and
   worker_id=NULL via SQL. The next worker that polls will pick it up
   and resume from where it left off (case.json, freeze_asks.json,
   brief_editorial.json — whichever exist in the bucket).

### Disk fills up on Railway

Shouldn't happen — the worker writes to a tempdir per investigation
and cleans up on exit. But if it ever does:

1. Restart the worker (Railway → service → ⋯ → Restart)
2. Tempdir contents are wiped at container exit

### Supabase project paused

Free-tier Supabase projects pause after a week of inactivity. Symptom:
`connection refused` or `Tenant or user not found` errors in worker logs.

**Fix:** log into Supabase dashboard, click "Restore project". Takes
~30s. Worker will reconnect on next claim attempt.

### Anthropic credit balance hit

Symptom: every editorial stage fails with a 401/403 from Anthropic.

**Fix:** add credit to https://console.anthropic.com/settings/billing.

## Manual interventions

### Force-fail a stuck investigation

```sql
UPDATE public.investigations
   SET status='failed',
       failed_at=NOW(),
       error_stage='manual_intervention',
       error_message='operator force-fail: <reason>',
       worker_id=NULL
 WHERE id = '<inv_id>';
```

### Re-queue a failed investigation

```sql
UPDATE public.investigations
   SET status='pending',
       worker_id=NULL,
       failed_at=NULL,
       error_stage=NULL,
       error_message=NULL,
       triggered_at=NOW()
 WHERE id = '<inv_id>';
```

The next worker poll will claim it. If trace artifacts are still in
the bucket, the pipeline resumes from the furthest-along stage rather
than redoing the trace.

### Force-approve a stuck `awaiting_review` row

1. Open `brief_editorial.json` in the bucket
2. Set `REVIEW_REQUIRED: false`
3. Replace any remaining `TODO:` placeholders
4. Save
5. SQL: `UPDATE investigations SET status='review_approved' WHERE id='<inv_id>'`

### Take the worker offline temporarily

Railway → service → ⋯ → Pause. Queued investigations sit in `pending`;
no harm. Resume to come back online.

## Where to look for context

| Question | Where |
|---|---|
| Latest commit on prod | `https://github.com/Aprostok/recupero-io/commits/main` (top of the list) |
| What deployed when | Railway → Deployments tab |
| What env vars are set | Railway → Variables tab |
| Application logs | Railway → Deployments → click deployment → View Logs |
| DB state | Supabase → Table Editor → public.investigations |
| Bucket state | Supabase → Storage → investigation-files |
| Architecture overview | `docs/RAILWAY_DEPLOY.md` |
| Worker code entry point | `src/recupero/worker/main.py` |
| Pipeline orchestration | `src/recupero/worker/pipeline.py` |
| Investigation state machine | `src/recupero/worker/state.py` |

## Last resort

If everything is broken and you can't figure out why:

1. **Pause the worker** (Railway → ⋯ → Pause). Queue stops being processed; no new failures.
2. **Roll back to last known good deploy:** Railway → Deployments → find a green deploy from before the issue → click ⋯ → Redeploy.
3. **Open an issue** with: deploy commit hash, error_stage of failing rows, last 50 lines of application logs, last `git diff` if you know what changed.

The stale-claim reaper means orphaned rows recover automatically on
worker restart — you can't permanently corrupt the queue by killing
the worker mid-stage.

---

## Phase 4 additions (2026-05-15)

Phase 4 added a watch-tick cron + digest deliverable, wallet-trace
investigations (case_id=NULL), multi-chain watchlist coverage
(Solana + Hyperliquid), a dashboard endpoint, kill switches for
optional building_package features, and an internal forensic
worksheet artifact.

### Second Railway service: watch-tick cron

The nightly watchlist snapshot loop runs in a **separate Railway
service**, not the main worker. Same Docker image, different start
command + cron schedule:

| Setting | Value |
|---|---|
| Builder | `DOCKERFILE` |
| Dockerfile path | `Dockerfile` |
| Start command | `recupero-worker --watch-tick` |
| Cron schedule | `0 3 * * *` (03:00 UTC — 23:00 EST) |
| Restart policy | never (cron jobs shouldn't auto-restart on exit) |

Env vars are shared with the main worker; SMTP + digest recipient
vars are additional. See `docs/WATCHLIST_DIGEST.md` for the deep
dive on watch-tick behavior.

**Triage if a tick didn't fire:** check the Railway cron service's
Deployments tab. Cron failures usually show up as a non-zero exit
on the latest deploy.

### Wallet-trace investigations (case_id=NULL)

Investigations with `case_id IS NULL` are "scratch" traces — intake
calls, ZachXBT-tagged wallets, internal R&D. They have no backing
`cases` row and no victim info. The pipeline:

1. Skips `cases` row fetch + victim.json seed.
2. Force-sets `skip_editorial=True` and `skip_freeze_briefs=True`
   regardless of what the row carries (editorial needs victim
   context; freeze letters need a victim to address).
3. Runs trace → freeze → emit (synthesized freeze_brief.json from
   freeze_asks.json) → building_package.
4. Produces ONLY `trace_report_<hash>.html` (the internal forensic
   worksheet). No customer-facing freeze letters or LE handoffs.

The admin UI surfaces these at `/admin/wallet-trace`. Schema:
`investigations.case_id` nullable, plus columns `label`,
`skip_editorial`, `skip_freeze_briefs`.

### Internal trace_report.html artifact

Emitted on **every** investigation (regardless of case_id /
skip flags / FREEZABLE count). Filename: `trace_report_<hash>.html`
in `briefs/`. Contains:

1. Trace summary stats (transfers, depth, total flow USD, destinations)
2. Destinations table (every distinct destination + holdings + USD)
3. Freeze-potential table (only destinations with freezable assets,
   with HIGH / MEDIUM / LOW / NOT FREEZABLE capability badges)
4. Flow visualization pointer (to `flow_<hash>.svg`)

"Internal Use Only" marker in the cover + footer. Forensic
worksheet aesthetic; no salutations or customer prose. For the
external-shareable summary, see `freeze_request_*.html` and
`le_handoff_*.html`.

### Multi-chain watchlist coverage

Watch-tick now supports:

| Chain | Provider | What gets snapshotted |
|---|---|---|
| ethereum | Etherscan v2 | Native ETH + named ERC-20 (from `asset_contract`) + tx count |
| arbitrum | Etherscan v2 | same |
| base | Etherscan v2 | same |
| polygon | Etherscan v2 | same |
| bsc | Etherscan v2 | same |
| solana | Helius RPC | Native SOL + SPL tokens via `getTokenAccountsByOwner` |
| hyperliquid | Public `/info` | Perp `clearinghouseState.accountValue` + spot USDC |

### Watchlist priority tier (migration 004)

`public.watchlist.priority` column with three values:

| Value | Cooldown | Use case |
|---|---|---|
| `standard` (default) | 12h (`RECUPERO_WATCH_MIN_INTERVAL_SEC`) | Steady-state watchlist |
| `hot` | 1h (`RECUPERO_WATCH_HOT_INTERVAL_SEC`) | Active investigation: perpetrator is moving funds |
| `paused` | never | Keep on watchlist for cross-reference; don't burn API budget |

Toggle via the admin UI (priority column on the wallet detail
page) or directly:

```sql
UPDATE public.watchlist SET priority='hot'
 WHERE address IN ('0xabc...', '0xdef...');
```

### `/dashboard.json` endpoint

Aggregated counters for the admin UI homepage. Same Railway port
as `/healthz`. Schema in `src/recupero/worker/dashboard_summary.py`.

```bash
# CLI form for one-shot inspection:
python -m recupero.worker.main --dashboard-summary
```

### Kill switches (escape hatches)

Two kept on purpose (production has neither set in normal operation):

| Var | Effect | When to set |
|---|---|---|
| `RECUPERO_DISABLE_PDF_RENDER=1` | Skip WeasyPrint entirely. Ships HTML deliverables only. | WeasyPrint is breaking on production and you need to ship deliverables now. Recipients can print-to-PDF from a browser. |
| `RECUPERO_ENABLE_LINK_PATCH=1` | Opt-in pypdf link-annotation patcher. WeasyPrint native gives ~54% clickable-address coverage in body PDFs; the patcher closes the gap to ~100%. | Once verified non-hanging on Railway, this becomes default-on. Until then it's opt-in due to historical worker-hang issues on Railway runtime. |

Two **removed** kill switches that no longer earn their keep
(both were debug crutches; their root causes are fixed):

- `RECUPERO_DISABLE_FLOW_POLISH` — was for OOM debugging. Subprocess
  isolation fixed the OOM; the switch is dead.
- `RECUPERO_DISABLE_FREEZABLE_PROMOTION` — same.

### Subprocess isolation for PDF rendering

WeasyPrint and pypdf both run in one-shot Python subprocesses
(`worker/_deliverables.py:_render_pdf_in_subprocess` and
`_patch_pdf_links_subprocess`). Pattern uses `Popen` + a 1s
poll() loop so the parent worker's heartbeat thread keeps firing
during long renders (CPU-throttled Railway containers can take
30s+ on a single PDF). Subprocess stderr lands in a tempfile, not
a PIPE, to avoid the 64KB buffer deadlock on noisy stderr output.

If a render hangs or exceeds the per-PDF timeout (120s WeasyPrint,
60s pypdf), the subprocess is killed and the worker continues to
the next file. Partial deliverable output is shipped — the HTML
always lands even if the PDF doesn't.

### Files added in Phase 4

```
docs/WATCHLIST_DIGEST.md             Watch-tick + digest deep dive
docs/OPERATOR_RUNBOOK.md             This file (with the Phase 4
                                     section above)

migrations/004_watchlist_priority.sql priority column

scripts/insert_validation_row.py     Quick "insert pending row"
scripts/approve_validation_row.py    Quick "fill TODOs + flip to
                                     review_approved"
scripts/e2e_smoke.py                 Single-command full pipeline
                                     validation
scripts/download_validation_briefs.py Pull bucket → local disk

src/recupero/worker/_pdf_links.py    Stdlib html.parser anchor
                                     extractor + pypdf /Link
                                     annotation injector
src/recupero/worker/_trace_report.py Internal forensic worksheet
                                     renderer
src/recupero/worker/watch_tick.py    Nightly snapshot loop
src/recupero/worker/mini_freeze.py   Daily digest deliverable
src/recupero/worker/digest_email.py  SMTP email delivery
src/recupero/worker/dashboard_summary.py /dashboard.json builder

src/recupero/reports/templates/trace_report.html.j2
src/recupero/reports/templates/mini_freeze_digest.html.j2
```

## Phase 5 additions (v0.4.x — 2026-05-15)

This section covers the customer-facing workflow that v0.4.x
shipped. If you've never engaged a real customer through Recupero
before, **read this section in full once before your first Tier-2
case**. The operator commands below are the only path you should
need — direct SQL into `public.investigations` is a fallback for
abnormal cases.

### The customer lifecycle in one diagram

```
  Victim submits intake form (Jacob's UI)
        │
        ▼
  Pay $499 ──► Diagnostic auto-runs on Railway
        │
        ▼
  Pipeline produces:
    - trace_report.html + PDF
    - flow_diagram.svg + PDF
    - case.json, manifest.json, freeze_brief.json, ...
    - If recoverable:
        - per-issuer freeze_request HTML + PDF (one per issuer)
        - per-issuer le_handoff HTML + PDF (one per issuer)
        - engagement_letter.html + PDF (Tier-2 contract)
        - victim_summary_recoverable.html + PDF
    - If unrecoverable:
        - victim_summary_unrecoverable.html + PDF
        - (no engagement letter — nothing to engage on)
        │
        ▼
  Auto-email victim_summary + attached PDFs ──► victim's email
  (handled by build_all_deliverables on case completion)
        │
        ▼
  Victim emails operator: "Yes, engage you for active recovery"
        │
        ▼
  Operator: `recupero-ops mark-engaged <inv_id> --fee 1500`
        │
        ▼
  Operator: `recupero-ops send-freeze-letters <inv_id>`
       (batch confirmation prompt before any send)
        │
        ▼
  Operator: `recupero-ops send-le-handoff <inv_id> --to officer@...`
        │
        ▼
  Daily Railway cron: `recupero-worker --send-followups`
       (sends a weekly status update to victim for 30 days)
        │
        ▼
  Recovery happens (or doesn't)
        │
        ▼
  Operator: `recupero-ops mark-closed <inv_id> --reason "..."`
       (cron stops sending follow-ups)
```

**Total operator time per case** (excluding diagnostic auto-run +
weekly cron auto-sends): roughly **10 minutes** spread across the
30-day engagement window.

### The `recupero-ops` CLI (v0.4.1)

Six commands. Run `recupero-ops <command> --help` for arg detail.

#### `recupero-ops status <inv_id>`

Read-only. Single command that shows everything: row metadata,
engagement status (days remaining, fee paid, last follow-up),
emails-sent audit log, artifact inventory from the bucket. Run
this first when you're not sure what state a case is in.

```bash
recupero-ops status e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c
```

#### `recupero-ops mark-engaged <inv_id> [--fee 1500]`

Activate a Tier-2 engagement. Sets `engagement_started_at=NOW()`
and `engagement_fee_paid_usd=<fee>`. Activates the daily
follow-up cron for this case.

**Idempotent** — running twice does NOT reset the start time
(preserves the 30-day anchor).

The `--fee` is the **incremental** engagement fee, NOT the total.
For a standard Tier-2 case: $1,500 incremental on top of the
$499 already paid for the diagnostic (total $1,999). For a
Tier-3 case: $4,500 incremental ($4,999 total).

```bash
# Tier 2 standard
recupero-ops mark-engaged <inv_id> --fee 1500

# Tier 3 high-value
recupero-ops mark-engaged <inv_id> --fee 4500
```

#### `recupero-ops send-freeze-letters <inv_id> [--issuer NAME]`

**Most sensitive command.** Sends prepared compliance freeze
letters to issuer compliance teams. Always shows the full
dispatch plan first (issuer + email + amount + filename) and
asks for batch confirmation BEFORE sending any letter. This is
the operator's "spot the wrong-typed compliance@ before it
goes out" checkpoint.

```bash
# Send to every issuer in the FREEZABLE list
recupero-ops send-freeze-letters <inv_id>

# Send to only one issuer (e.g., re-send to Circle after a
# response from another issuer changed the analysis)
recupero-ops send-freeze-letters <inv_id> --issuer Circle
```

Per-issuer-per-recipient idempotency via `public.emails_sent`.
Re-running skips issuers we've already sent for (logged as
"SKIP <issuer>: freeze letter already sent to ...").

#### `recupero-ops send-le-handoff <inv_id> --to EMAIL`

Sends the LE handoff package to a specific officer or attorney.
The recipient address is **operator-supplied** (no auto-routing)
because the right recipient depends on which agency the
operator + victim selected from the LE routing recommendation in
section 6.1 of the LE handoff.

```bash
recupero-ops send-le-handoff <inv_id> --to officer@fbi.gov
recupero-ops send-le-handoff <inv_id> --to attorney@firm.example
```

Attaches:
- The LE handoff PDF (primary artifact for LE)
- The trace_report PDF (full forensic detail)
- The flow_diagram PDF (visualization)

Per-recipient idempotency — re-sending to the same email is a no-op.

#### `recupero-ops followup-now <inv_id>`

Force-send a follow-up status email immediately, bypassing the
6-day cadence check. Used when:

- You just activated the engagement and want to send the first
  weekly status right away (don't want to wait for the cron's
  next firing).
- You have material news to share (issuer responded, LE
  engaged, recovery occurred) and want to update the victim
  sooner than the 6-day cadence.
- You're testing the follow-up rendering for a specific case.

Updates `last_followup_sent_at` on success.

```bash
recupero-ops followup-now <inv_id>
```

#### `recupero-ops mark-closed <inv_id> [--reason TEXT]`

Closes an active engagement. Sets `engagement_closed_at=NOW()`
and appends an audit event to `change_summary` (jsonb).

Cron stops sending follow-ups for this case once closed.

```bash
recupero-ops mark-closed <inv_id> --reason "$14k recovered, victim notified"
recupero-ops mark-closed <inv_id> --reason "victim withdrew, refund processed"
recupero-ops mark-closed <inv_id> --reason "30-day window elapsed"
```

### Email automation + audit log (v0.4.0 — migration 005)

The worker now auto-sends the victim summary letter (with all
PDF attachments) to the victim's email the moment the diagnostic
completes. **No operator action required** for that send.

Operator-controlled sends (freeze letters, LE handoff,
followup-now) go through the same `worker/_email.py` primitive,
which writes every send attempt — success or failure — to the
`public.emails_sent` audit table.

**Idempotency:** the audit log doubles as a "have we already sent
this?" check. Re-running send commands skips successful prior
sends. Failed sends DO retry on re-run.

**Configuration:**
- `RESEND_API_KEY` — required for actual sends
- `RECUPERO_EMAIL_FROM` — default `alec@recupero.io`
- `RECUPERO_EMAIL_FROM_NAME` — default `"Recupero Investigation Services"`
- `RECUPERO_DISABLE_EMAIL=1` — skip sending entirely (local dev /
  testing — the dispatch logs what *would* have been sent so the
  operator can see the plan without committing)
- `RECUPERO_OPS_ASSUME_YES=1` — skip confirmation prompts in
  ops commands (for scripted batch ops)

**Audit log columns** (`public.emails_sent`):
```
id              uuid
investigation_id uuid (FK, SET NULL on delete)
to_address      text
subject         text
preview_text    text
email_type      text  -- 'victim_summary' / 'engagement_letter'
                      -- / 'freeze_letter' / 'le_handoff'
                      -- / 'followup_w<N>'
sent_at         timestamptz
message_id      text  -- Resend's message ID on success
error_message   text  -- populated on failure
sent_by         text  -- 'worker:auto' or 'recupero-ops:operator'
                      -- or 'worker:followup-cron'
attachments     text[]
```

### Tier-2 engagement tracking (v0.4.0 — migration 006)

Four new columns on `public.investigations`:

- `engagement_started_at` — when operator confirmed Tier 2 active
- `engagement_closed_at` — when engagement ended (set by mark-closed)
- `engagement_fee_paid_usd` — incremental engagement fee
- `last_followup_sent_at` — daily-cron's last-send timestamp

The daily cron (`recupero-worker --send-followups`) eligibility
query:

```sql
SELECT i.id, c.client_email, ...
  FROM public.investigations i
  LEFT JOIN public.cases c ON c.id = i.case_id
 WHERE i.engagement_started_at IS NOT NULL
   AND i.engagement_closed_at IS NULL
   AND i.engagement_started_at > NOW() - INTERVAL '30 days'
   AND (i.last_followup_sent_at IS NULL
        OR i.last_followup_sent_at < NOW() - INTERVAL '6 days')
   AND c.client_email IS NOT NULL
 ORDER BY i.last_followup_sent_at ASC NULLS FIRST
```

Cron is wired in via the `--send-followups` flag. Set up the
daily Railway cron as a second service with start command:

```
recupero-worker --send-followups
```

Schedule: daily, e.g., `0 9 * * *` (9 AM UTC).

### Customer-facing artifact templates (v0.3.x → v0.4.x)

Every case-driven investigation with case_id set produces:

| Artifact | Audience | Notes |
|---|---|---|
| `trace_report.html` + PDF | Internal-facing | Operator + audit |
| `flow_diagram.svg` + PDF | Reference | Embedded in letters |
| `freeze_request_<issuer>.html` + PDF (one per issuer) | Issuer compliance team | Sent via `send-freeze-letters` |
| `le_handoff_<issuer>.html` + PDF (one per issuer) | Law enforcement | Sent via `send-le-handoff` |
| `victim_summary_recoverable.html` + PDF | Victim | Auto-sent on case completion |
| `victim_summary_unrecoverable.html` + PDF | Victim | Auto-sent when no recoverable funds (carries the $99 refund notice) |
| `engagement_letter.html` + PDF | Victim (signs for Tier 2) | Pre-generated; sent on operator request |
| `followup_status.html` (per weekly send) | Victim | Auto-sent by daily cron during active engagement |

Wallet-trace investigations (case_id=NULL) skip everything except
the trace_report + flow_diagram — they have no victim to address.

### Daily cron schedule (Railway)

Three scheduled tasks to set up on Railway:

| Cron service | Start command | Schedule |
|---|---|---|
| `recupero-worker` (main) | `recupero-worker` | Long-running, always on |
| Watchlist tick | `recupero-worker --watch-tick` | Hourly during active hours, or every 12h for standard tier |
| **Follow-up sends** | `recupero-worker --send-followups` | Daily at 9 AM UTC |

The follow-up cron exits 0 unless real sends failed (NOT
including `RECUPERO_DISABLE_EMAIL=1` skips). Hook Railway's
failure alerts to the non-zero exit code.

### Backfilling pre-v0.4.x cases

Investigations completed before the v0.4.x changes shipped don't
have engagement_started_at set. They also don't have the
engagement_letter artifact (it's only generated for new runs).

If a customer wants to engage a pre-v0.4.x case:

1. **Re-trigger the investigation** so it regenerates with the
   new artifact set (engagement_letter + auto-email):
   ```sql
   UPDATE public.investigations
      SET status = 'pending', worker_id = NULL,
          claimed_at = NULL, last_heartbeat_at = NULL,
          completed_at = NULL, failed_at = NULL,
          error_message = NULL, error_stage = NULL,
          supabase_storage_path = NULL
    WHERE id = '<inv_id>';
   ```
   Worker auto-picks it up (60-90s for a re-run since the trace
   is cached).
2. Then activate engagement normally: `recupero-ops mark-engaged
   <inv_id> --fee 1500`

### Quick reference SQL (when ops CLI isn't enough)

These should rarely be needed — the ops CLI covers the
operator-friendly paths. Reach for direct SQL when something is
abnormal:

```sql
-- Manually set engagement (bypass mark-engaged, e.g., to override
-- a historical date the operator wants to record)
UPDATE public.investigations
   SET engagement_started_at = '2026-05-01 12:00:00+00',
       engagement_fee_paid_usd = 1500
 WHERE id = '<inv_id>';

-- Force-clear all engagement state (e.g., to redo from scratch)
UPDATE public.investigations
   SET engagement_started_at = NULL,
       engagement_closed_at = NULL,
       engagement_fee_paid_usd = NULL,
       last_followup_sent_at = NULL,
       change_summary = NULL
 WHERE id = '<inv_id>';

-- Find all stale-expired engagements (active >30 days, no close)
SELECT id, engagement_started_at,
       NOW() - engagement_started_at AS age
  FROM public.investigations
 WHERE engagement_started_at IS NOT NULL
   AND engagement_closed_at IS NULL
   AND engagement_started_at < NOW() - INTERVAL '30 days'
 ORDER BY engagement_started_at ASC;

-- Audit log: what emails went out for an investigation
SELECT sent_at, email_type, to_address,
       message_id, error_message
  FROM public.emails_sent
 WHERE investigation_id = '<inv_id>'
 ORDER BY sent_at ASC;

-- Audit log: failures across all cases in the last 7 days
SELECT investigation_id, sent_at, email_type,
       to_address, error_message
  FROM public.emails_sent
 WHERE sent_at > NOW() - INTERVAL '7 days'
   AND error_message IS NOT NULL
 ORDER BY sent_at DESC;
```

### When something goes wrong

| Symptom | Investigation step |
|---|---|
| Operator sees no auto-email after diagnostic completes | Check `emails_sent` for the investigation_id. If error_message says `RESEND_API_KEY not configured`, set the env var on Railway. |
| Follow-up cron logs `failed=N` daily | Run `recupero-ops status <inv_id>` on the affected investigation. Check `emails_sent.error_message` for the actual failure. |
| `mark-engaged` errors `change_summary` constraint | Check the column type — should be jsonb. Migration 006 should have applied. |
| Cron says `candidates=0` but I know I just engaged a case | Check `engagement_started_at` IS NOT NULL + `engagement_closed_at` IS NULL + cases.client_email IS NOT NULL. The cron requires all three. |
| `recupero-ops send-freeze-letters` says no letters in bucket | The investigation was probably run before the per-issuer letter changes (v0.2.1). Re-trigger the row to regenerate artifacts. |

