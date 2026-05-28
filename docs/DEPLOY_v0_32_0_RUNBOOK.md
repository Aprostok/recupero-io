# v0.32.0 Production Deploy Runbook

**Target:** merge `pdf-deliverables` → `main`, triggering Railway
auto-deploy of both `recupero-worker` and `recupero-cron` services.

**Commit:** `af7cf0f` ("v0.32.0: close all Tier-0 + Tier-1 pre-mortem gaps")

**Stakes:** this merge applies 4 new DB migrations and adds 7 new
RECUPERO_* env vars. The worker WILL fail to start if any of the
following pre-flight steps are skipped.

---

## Why this runbook exists

Memory note `project_railway_main_autodeploy.md`: merging
`pdf-deliverables` → `main` triggers a prod deploy.

Memory note `project_jacob_v021_residuals.md`: pre-existing deferred
items unrelated to this deploy.

The v0.32.0 change set is the biggest schema delta since v0.21.0:

| Migration | Adds | Breaks-if-missing |
|---|---|---|
| `027_recovery_disclosures.sql` | Audit table for intake disclosures | Intake POST returns 500 |
| `028_brief_review_status.sql` | Review-gate table | `build_all_deliverables` logs ERROR, no artifacts blocked yet (graceful) |
| `029_cron_jobs_lock.sql` | Cron HA lock | Cron jobs run unlocked on first deploy (graceful) |
| `030_label_candidates.sql` | Auto-ingest queue | `label_auto_ingest` cron logs ERROR (graceful) |

**Migrations 028-030 fail gracefully**; migration 027 is the only one
that breaks intake-side functionality. Apply ALL FOUR before merge.

---

## Step 0 — Pre-flight (5 minutes)

```bash
# Verify we're on the right commit
cd C:/Users/apros/Downloads/recupero-io/.claude/worktrees/cranky-fermat-54fcfb
git status
# Expected: clean working tree on pdf-deliverables, commit af7cf0f at HEAD

# Verify regression is still green
python -m pytest tests/ --ignore=tests/integration -q --tb=line
# Expected: 4598 passed, 10 skipped, 0 failed

# Verify integration golden case
python -m pytest tests/integration/test_trace_to_brief.py -q
# Expected: 12 passed

# Verify mutation harness
python scripts/mutation_smoke.py
# Expected: 43/43 mutations detected
```

If any of the above fails, STOP — don't proceed. Open an issue.

---

## Step 1 — Apply DB migrations (10 minutes)

The Railway prod DSN is in your password manager under `SUPABASE_DB_URL`.

**DO NOT** export it to your shell history. Use the password
manager's "copy to clipboard for 30s" feature, paste into a
temporary variable in a NEW shell, run the migration, close the
shell.

```bash
# In a fresh terminal — do NOT use shell history
export SUPABASE_DB_URL='postgresql://...PASTED FROM PASSWORD MANAGER...'

# Verify connectivity + current schema version
python scripts/apply_migration.py --dry-run migrations/027_recovery_disclosures.sql

# Apply in numeric order — each one is wrapped in BEGIN/COMMIT so a
# failure rolls back cleanly.
python scripts/apply_migration.py migrations/027_recovery_disclosures.sql
python scripts/apply_migration.py migrations/028_brief_review_status.sql
python scripts/apply_migration.py migrations/029_cron_jobs_lock.sql
python scripts/apply_migration.py migrations/030_label_candidates.sql

# Verify all four tables now exist
python -c "
import os
from recupero._common import db_connect
with db_connect() as conn, conn.cursor() as cur:
    for tbl in ['recovery_disclosures', 'brief_reviews', 'cron_jobs_lock', 'label_candidates']:
        cur.execute('SELECT 1 FROM information_schema.tables WHERE table_name=%s', (tbl,))
        print(f'{tbl}: ', 'OK' if cur.fetchone() else 'MISSING')
"
# Expected: all four OK

# Close the shell so the DSN is gone
exit
```

If any migration fails, the BEGIN/COMMIT rolls it back automatically.
Investigate the error before retrying.

---

## Step 2 — Set new Railway env vars (10 minutes)

Open the Railway dashboard. For the `recupero-worker` service AND the
`recupero-cron` service (when you provision it), set:

### Required (worker refuses to gate-check without these)

| Variable | Source | Purpose |
|---|---|---|
| `RECUPERO_ADMIN_KEY` | Generate: `openssl rand -hex 32` | Auth for review API + labels API endpoints. Constant-time match. |

### Recommended (operational visibility)

| Variable | Recommended | Purpose |
|---|---|---|
| `RECUPERO_CRON_ALERT_WEBHOOK_URL` | Your Slack incoming-webhook URL | Cron failures POST here at consecutive_failures ≥ 2 |
| `RECUPERO_API_BUDGET_USD_PER_CASE` | `0.50` | Per-case API spend cap; tracer marks `partial_budget_hit` over this |
| `RECUPERO_CRON_HEALTHZ_STALE_HOURS` | `25` | `/cron/healthz` returns "stale" when a job's last_success_utc > this |

### Optional (have sane defaults)

| Variable | Default | Purpose |
|---|---|---|
| `RECUPERO_CRON_LEASE_SECONDS` | `300` | Lock lease before another replica can steal |
| `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP` | `100` | Max new candidate labels per day |
| `RECUPERO_LABEL_DECAY_DAYS` | `180` | Per-tier confidence decay window |
| `RECUPERO_REVIEW_SLA_HOURS` | `24` | Hours before a review row is flagged overdue |

### Already set (verify still present)

`ETHERSCAN_API_KEY`, `HELIUS_API_KEY`, `COINGECKO_API_KEY`,
`SUPABASE_DB_URL`, `STRIPE_*`, `RESEND_API_KEY`, etc.

**Etherscan free-tier note:** at 50+ cases/day you'll burn the free
tier by noon. Recommend upgrading `ETHERSCAN_API_KEY` to Pro ($399/mo,
10x quota) before the first paid customer. NOT a blocker for the
v0.32.0 merge, but the budget-cap will kick in earlier without the
upgrade.

---

## Step 3 — Provision the cron service (15 minutes, ONE-TIME)

Railway:
1. New Service → Connect to the same `recupero-io` repo
2. Branch: `main`
3. Build: Dockerfile (same as worker)
4. Deploy → Start command: `recupero-cron`
5. Replicas: **1** (the leader-election lets you bump to 2 later for HA, but start with 1)
6. Env vars: clone all from `recupero-worker` (Railway has a "share env vars" feature)

The cron service does NOT need a public domain or a healthcheck path
on its own (it has no HTTP listener). The `/cron/healthz` endpoint is
exposed by the WORKER service — it queries the `cron_jobs_lock` table
that the cron service writes to.

---

## Step 4 — The merge (2 minutes)

This is the irreversible step. Everything before this is reversible;
this triggers prod deploy.

```bash
cd C:/Users/apros/Downloads/recupero-io/.claude/worktrees/cranky-fermat-54fcfb

# Push pdf-deliverables to origin first so CI can run against it
git push origin pdf-deliverables

# Switch to main and merge
git checkout main
git pull origin main
git merge pdf-deliverables --no-ff -m "Merge v0.32.0: close all Tier-0 + Tier-1 pre-mortem gaps"
git push origin main

# Switch back to the working branch
git checkout pdf-deliverables
```

The `git push origin main` triggers Railway's auto-deploy. Watch the
Railway logs.

---

## Step 5 — Post-deploy verification (15 minutes)

### 5.1 Worker boot

Railway logs should show:
```
recupero-worker startup ok
db schema: 30 migrations applied
```

If logs show "ERROR: relation 'recovery_disclosures' does not exist"
or similar, the migration step was skipped or rolled back. Fix
Step 1, then redeploy.

### 5.2 Cron boot

Cron service logs should show:
```
cron: scheduler starting (4 jobs)  # ofac_sync, retrace_backfill, stale_label_alert, label_auto_ingest
cron:   ofac_sync next fires at 2026-05-29T04:00:00+00:00
...
```

### 5.3 Healthz endpoints

```bash
# General healthz (existed pre-v0.32)
curl https://recupero-worker.up.railway.app/healthz
# Expected: 200 {"status":"ok"}

# v0.32 cron healthz
curl https://recupero-worker.up.railway.app/cron/healthz
# First call: 503 down (no jobs have run yet)
# After OFAC sync fires (next 04:00 UTC): 200 ok
```

### 5.4 Intake portal disclosure

Open https://app.recupero.io/intake in a browser. Verify:
- The recovery-rate disclosure block renders ABOVE the checkout button
- The "I understand" checkbox is required (HTML5 + server-side)
- Submitting without the checkbox returns 400

### 5.5 Review gate

Verify the review gate is active:
```bash
# Pull one in-flight case from prod (read-only)
curl -H "X-Recupero-Admin-Key: $RECUPERO_ADMIN_KEY" \
  https://recupero-worker.up.railway.app/v1/reviews/queue
# Expected: list of awaiting_review rows for every recently-built case
```

If the queue is empty for the most recent case (`SELECT MAX(case_id),
MAX(created_at) FROM brief_reviews`), the auto-create on
`build_all_deliverables` isn't firing. Check worker logs for
`create_review_row` warnings.

### 5.6 Smoke test a brief through the gate

```bash
# Pick a test case from staging (NOT a real customer case)
CASE_ID="..."
ARTIFACT_KIND="brief"

# Find the awaiting_review row
psql $SUPABASE_DB_URL -c "
  SELECT id, artifact_path, status
  FROM brief_reviews
  WHERE case_id = '$CASE_ID' AND artifact_kind = '$ARTIFACT_KIND';
"

# Try dispatching WITHOUT approval — should fail
recupero-ops dispatch-brief --case $CASE_ID
# Expected: BriefNotReviewedError raised

# Approve via API
ROW_ID="..."  # from the SELECT above
curl -X POST \
  -H "X-Recupero-Admin-Key: $RECUPERO_ADMIN_KEY" \
  -d '{"reviewer_email":"smoke-test@recupero.io"}' \
  -H "Content-Type: application/json" \
  https://recupero-worker.up.railway.app/v1/reviews/$ROW_ID/approve

# Now dispatch — should succeed
recupero-ops dispatch-brief --case $CASE_ID
# Expected: success, email sent, log shows "review approved by smoke-test@recupero.io"
```

---

## Step 6 — Rollback plan (if needed)

If something is wrong post-merge:

### 6.1 Quick mitigation — keep the merge, disable the feature

The review gate fails OPEN when DSN is unset. Set this env var on
the worker to bypass the gate temporarily:

```
RECUPERO_DISPATCHER_REVIEW_GATE_BYPASS=1
```

(NOTE: this env var doesn't exist yet. If we need it, ship as v0.32.1
hotfix. The current design has the gate fail OPEN on `dsn=None` for
local-dev convenience; in prod the DSN is always set, so the gate
will block.)

Better quick mitigation: revert the merge.

### 6.2 Full revert

```bash
git checkout main
git revert -m 1 HEAD  # creates a revert commit
git push origin main
```

Railway auto-deploys the revert. The DB migrations remain applied
(safe — the columns/tables are additive; existing code doesn't read
them).

---

## Post-deploy follow-up (next 7 days)

These don't block the merge but should be queued:

1. **Hook up the Slack webhook** — `RECUPERO_CRON_ALERT_WEBHOOK_URL`
   needs a real URL. Without it, cron failures are stdout-only and
   no one gets paged.

2. **Set up an external uptime monitor** pointing at
   `/cron/healthz`. Better Uptime free tier supports this. Alert when
   the endpoint returns 503.

3. **First-week brief-review SLA**: the `review_sla_scan` cron flags
   reviews > 24h old. With no operator looking at the dashboard,
   reviews will pile up. Decide who's on review-rotation duty and
   document.

4. **OFAC sync first run**: at the next 04:00 UTC the cron will
   attempt a sync. If `RECUPERO_CRON_ALERT_WEBHOOK_URL` is set, you'll
   see either "ok" or a webhook ping. If neither, check the cron
   service logs.

5. **Manual canary case**: send a test case through the full intake →
   trace → review → dispatch flow within 24h of deploy. The Zigha
   golden-case in `tests/integration/test_trace_to_brief.py` validates
   the synthetic pipeline; a real-shape case validates the cross-
   service wiring.

6. **Smoke-test the label auto-ingest**: at 02:00 UTC the new cron
   pulls candidates. Next morning, `SELECT COUNT(*) FROM
   label_candidates WHERE status='pending_review'` should be > 0.
   Review at least one via the API.

---

## What gets BETTER immediately after deploy

- Every brief now requires human review before dispatch (Tier-0 #1)
- Every intake records a customer's recovery-rate acknowledgment
  (Tier-0 #2)
- Two cron replicas could now run safely (HA — bump replicas when
  ready)
- Per-case API spend is capped (no more whale case burning the day's
  budget for everyone)
- Stale labels degrade automatically — 180-day-old "high" labels
  read as "medium" effective
- Cron failure with `consecutive_failures ≥ 2` pings the webhook
- `/cron/healthz` exposes operational state to external monitors

## What's still on the v0.32.x backlog (non-blocking)

- AUSA contact directory (Tier-2 #1)
- Auto-rendered subpoena packages (Tier-2 #1)
- Hosted PDF service migration (Tier-2 #2)
- Time-zone picker on intake (Tier-2 #3)
- Mobile-responsive brief layout (Tier-3)
- E&O insurance + lawyer disclaimer (non-engineering)

These are in the post-mortem doc and can ship as v0.32.1 / v0.33.x
without blocking the v0.32.0 production deploy.
