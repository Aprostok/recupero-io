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

---

## v0.32.1 deltas

The v0.32.1 cycle is a remediation pass on top of v0.32.0 driven by
the round-2 Jacob-style audit (six parallel reviewers). It is
**code-only** — no new migrations, no new required env vars beyond
the v0.32.0 set above. Treat this as a rolling forward fix on the same
production deploy.

### What's in v0.32.1

#### 1. Rollup-canonical bridge decoders (closes adversary Route 1)

`src/recupero/trace/bridge_calldata.py` now decodes the canonical
bridge entrypoints for the five major rollups so the cross-chain
continuation pass anchors at the actual destination recipient instead
of inferring it from a heuristic:

- Polygon PoS bridge (`RootChainManager.depositFor` /
  `MintableERC20PredicateProxy`)
- Optimism standard bridge (`L1StandardBridge.depositERC20To` /
  `depositETHTo`)
- Arbitrum standard bridge (`Inbox.depositEth` /
  `L1ERC20Gateway.outboundTransferCustomRefund`)
- zkSync Era bridge (`L1ERC20Bridge.deposit` /
  `L1SharedBridge.bridgehubDepositBaseToken`)
- Base bridge (`L1StandardBridge.bridgeERC20To` — Base shares
  Optimism's contract surface but on its own chain id)

**Smoke test:**
```bash
# A staging case with a known Ethereum→Polygon PoS hop
recupero trace --chain ethereum --address 0x... --incident-time ... --case-id SMOKE-V0321-ROLLUP
# Expected: the destination Polygon address appears in case.json under
# trace.dst_chain_hops, NOT in trace.bridge_dead_ends.
pytest tests/test_bridge_calldata_canonical.py -q
# Expected: all rollup-canonical cases pass.
```

#### 2. CEX cross-token continuity at parity (closes HIGH-10)

`src/recupero/trace/cex_continuity.py` now matches deposit + withdraw
pairs at the same exchange across the canonical parity-token sets:

- Stablecoin parity: USDT ↔ USDC ↔ DAI ↔ FDUSD ↔ TUSD
- ETH parity: ETH ↔ WETH ↔ stETH ↔ wstETH ↔ rETH
- BTC parity: WBTC ↔ cbBTC ↔ tBTC ↔ renBTC (where still active)

Deposit-in-USDT, withdraw-in-USDC at the same exchange within the
continuity window now produces a `tier=2 cross_token_parity` lead
instead of dead-ending the continuity scan.

**Smoke test:**
```bash
pytest tests/test_cex_continuity_parity.py -q
# Expected: all parity-pair cases produce a tier-2 continuity edge.
```

#### 3. Trace dst-chain anchor fix (closes CRIT-3)

`src/recupero/trace/tracer.py` cross-chain continuation pass now
anchors the destination-chain BFS at the bridge's recipient address
extracted by the (v0.32.1 enhanced) decoder, not at the source-chain
seed re-mapped to the destination chain. The v0.32.0 bug truncated
destination-chain traces in cases where the bridge recipient differed
from the source-chain seed (the common case for routed bridge
transactions).

**Smoke test:**
```bash
pytest tests/test_v032_1_trace_crit_fixes.py -q
# Expected: dst-chain anchor cases land at the recipient, not the seed.
```

#### 4. Cron scheduler secret redactor expansion (closes SEC CRIT-2)

`src/recupero/worker/cron_scheduler.py` log-redactor now covers the
full set of secret-shaped tokens that can land in cron stderr:

- `RECUPERO_TOKEN_PEPPER`, `RECUPERO_ADMIN_KEY`,
  `RECUPERO_RANDOMIZATION_SECRET`
- API keys: `ETHERSCAN_*`, `HELIUS_*`, `ALCHEMY_*`, `COINGECKO_*`,
  `ANTHROPIC_*`, `RESEND_*`, `STRIPE_*`
- DSN-shaped strings (`postgresql://...`) with password components
- JWT-shaped strings and 32+ byte hex tokens

**Smoke test:**
```bash
pytest tests/test_v032_1_security_fixes.py::test_cron_redactor -q
# Expected: pepper, admin key, DSN password all redacted in captured stderr.
```

#### 5. Auto-ingest promote validation + `confirm_sha256` (closes SEC CRIT-1)

`src/recupero/labels/api.py` — the `POST /v1/labels/promote/{id}`
endpoint now requires the caller to echo back the candidate's content
SHA-256 in the request body. Closes the label-promote JSON-injection
window where an attacker who got an admin-key replay could promote a
crafted candidate row to a `high`-tier label without re-fetching its
content.

**Smoke test:**
```bash
# Promote a real candidate with the correct hash
curl -X POST -H "X-Recupero-Admin-Key: $RECUPERO_ADMIN_KEY" \
  -d '{"confirm_sha256":"<the candidate's sha256>"}' \
  https://recupero-worker.up.railway.app/v1/labels/promote/<candidate_id>
# Expected: 200 ok.

# Same with a wrong hash
curl -X POST -H "X-Recupero-Admin-Key: $RECUPERO_ADMIN_KEY" \
  -d '{"confirm_sha256":"deadbeef..."}' \
  https://recupero-worker.up.railway.app/v1/labels/promote/<candidate_id>
# Expected: 409 confirm_sha256 mismatch.
```

#### 6. Admin-gated `/v1/cron/jobs` (closes SEC HIGH-5)

`src/recupero/api/cron_admin_api.py` — the cron status endpoint now
requires the same `X-Recupero-Admin-Key` header used by the review API
and the labels admin API. v0.32.0 left this endpoint unauthenticated.

**Smoke test:**
```bash
curl https://recupero-worker.up.railway.app/v1/cron/jobs
# Expected: 401 invalid X-Recupero-Admin-Key.

curl -H "X-Recupero-Admin-Key: $RECUPERO_ADMIN_KEY" \
  https://recupero-worker.up.railway.app/v1/cron/jobs
# Expected: 200 + list of jobs and their last_success_utc.
```

#### 7. Validator semantic INVARIANTS G–P (coverage 30% → 90%)

`src/recupero/validators/output_integrity.py` ships INVARIANTS G
through P for v0.32.1:

| Invariant | Checks |
|---|---|
| G | Intra-artifact cross-section USD sums reconcile to the headline figure |
| H | Address ↔ chain ↔ explorer URL coherence (no Etherscan link on a Polygon address, etc.) |
| I | Time-window coherence (no transfer dated before incident_time on the freeze letter) |
| J | Per-section USD sums in the LE handoff reconcile to brief totals |
| K | Brief ↔ freeze-letter token / amount / recipient consistency |
| L | Address ↔ chain ↔ explorer URL coherence across templates (template-level check 1 tightening) |
| M | Cross-document time-window coherence |
| N | Stale-label / PIT render verification (no v0.32 candidate-tier label appears as `high` in customer-facing artifacts) |
| O | AI-editorial claim grounding (every assertion in `ai_editorial.py` output traces to a section of the LE handoff or brief) |
| P | Parent-link / disclosure metadata coherence (every artifact carries the case's parent disclosure ID) |

**Smoke test:**
```bash
pytest tests/test_output_integrity_g_h_i.py -q
pytest tests/test_output_integrity.py -q   # full INVARIANT A-P suite
# Expected: all pass.
```

### Migration list

**No new migrations.** Migrations 027-030 from v0.32.0 still apply.
Verify with:

```bash
python -c "
import os
from recupero._common import db_connect
with db_connect() as conn, conn.cursor() as cur:
    for tbl in ['recovery_disclosures', 'brief_reviews', 'cron_jobs_lock', 'label_candidates']:
        cur.execute('SELECT 1 FROM information_schema.tables WHERE table_name=%s', (tbl,))
        print(f'{tbl}: ', 'OK' if cur.fetchone() else 'MISSING')
"
# Expected: all four OK (unchanged from v0.32.0)
```

If you are deploying v0.32.1 directly without v0.32.0 in production
first, follow Step 1 of this runbook to apply 027-030, then continue
with the code-only path below.

### Deploy procedure (v0.32.1)

Because v0.32.1 is code-only, the merge is the only ship step:

```bash
cd C:/Users/apros/Downloads/recupero-io/.claude/worktrees/cranky-fermat-54fcfb

# Pre-flight: full regression + mutation harness
pytest -q --ignore=tests/integration
# Expected: 4600+ passed, 10 skipped, 0 failed (the v0.32.1 cycle adds
# ~30 new tests; exact count will be in the merge commit message).

python scripts/mutation_smoke.py
# Expected: 43/43+ mutations detected.

# Push pdf-deliverables for CI
git push origin pdf-deliverables

# Merge to main → triggers Railway auto-deploy
git checkout main
git pull origin main
git merge pdf-deliverables --no-ff -m "Merge v0.32.1: round-2 audit remediation"
git push origin main

git checkout pdf-deliverables
```

Watch the Railway logs:

```
recupero-worker startup ok
db schema: 30 migrations applied        ← unchanged from v0.32.0
v0.32.1 deltas active                   ← if your worker boot logs the version line
```

### Rollback procedure (v0.32.1 → v0.32.0)

Because v0.32.1 ships no migrations, the rollback is a single
revert:

```bash
git checkout main
git pull origin main
git revert -m 1 HEAD                    # the v0.32.1 merge commit
git push origin main
```

Railway auto-deploys the revert. The schema stays at 030 (unchanged
between v0.32.0 and v0.32.1) so no DB rollback is required.

**Caveat:** any review-gate approvals or label promotions that
exercised the v0.32.1 surfaces (confirm_sha256, admin-gated cron jobs)
will see the v0.32.0 looser surface restored. This is safe — the
v0.32.0 endpoints still validate the admin key for the review and
labels surfaces — but it widens the v0.32.0 attack surface back to its
pre-v0.32.1 footprint. Treat the rollback as a pause, not a fix.
