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
