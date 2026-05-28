# V0.30 Observability Gaps — SRE Audit

**Date:** 2026-05-26 · **Branch:** `pdf-deliverables` · **Author:** SRE audit pass

The question: when something breaks at 3 AM, will anyone know within minutes? Verdict: **partial.** Sentry + Prometheus + JSON logs + `/health` + a strict env-var pre-flight already exist and are wired up correctly. What's missing is the *outside-the-box* alerting — nothing scrapes `/metrics`, nothing pages on a stuck queue, nothing watches the cron services, and three failure modes will still wait for a customer email.

---

## STATE OF THE WORLD

| Surface | Where | Status |
|---|---|---|
| Structured logs | `src/recupero/logging_setup.py` — JSON via `RECUPERO_LOG_FORMAT=json`, `run_context` correlation (`investigation_id`, `case_id`, `stage`, `request_id`), secret redaction, log-injection strip | Present; Railway captures stdout |
| Sentry | `src/recupero/observability/sentry.py` — opt-in via `SENTRY_DSN`; merges `run_context` into tags; redacts secrets in `before_send`/`before_breadcrumb`; `LoggingIntegration(INFO breadcrumbs, WARNING events)` | Code-ready; **DSN must be set in Railway** to actually route |
| Prometheus metrics | `src/recupero/observability/metrics.py` — in-process `recupero_claims_total`, `recupero_stage_runs_total{stage,outcome}`, `recupero_stage_duration_seconds`, `recupero_freeze_letters_sent_total`, `recupero_alerts_fired_total`, `recupero_brief_render_seconds`, `recupero_trace_transfers_count` | Exposed at `/metrics` on the worker health port; **no scraper consumes it** |
| Healthcheck (liveness) | `GET /healthz` — `src/recupero/worker/_health_server.py`; `railway.json` polls every deploy with 60s timeout | Working |
| Healthcheck (readiness) | `GET /health` — env vars + DB SELECT 1 + bucket reachability + package-integrity (`_run_checks`, `_check_package_integrity`) | Working; not on a recurring external probe |
| Heartbeat / stale-row reaper | `worker/main.py` (`_Heartbeat`, `db.reap_stale_claims(stale_after_sec=300)`, `db.reap_post_deploy_orphans()`) | Self-healing; orphaned `tracing/claimed` rows recover within 5min |
| Crash-loop guard | `_MIN_UPTIME_SEC=30` in `worker/main.py` | Working |
| API uptime | `GET /v1/health` (`api/app.py`) — version + git_sha + uptime; docs auth-gated in prod | Working |
| Alerting / paging | None | **MISSING** |
| Dashboards | None checked into repo | **MISSING** |
| External uptime probe | `docs/RAILWAY_DEPLOY.md` documents UptimeRobot setup; no evidence it's configured | **UNVERIFIED** |
| Nightly audit | `scripts/nightly_audit.py` — pytest, ruff, mypy, TODO inventory, git activity, migrations; emits JSON digest | Present; **no scheduled runner found** |
| Stale-review alert | `scripts/check_stale_reviews.py` — exit-1 if rows >24h in `awaiting_review`; GitHub Actions example in docs | Documented, not in repo as `.github/workflows/*.yml` |
| Watchlist digest cron | `recupero-worker --watch-tick` separate Railway service, 03:00 UTC; emails digest via `digest_email.py` | Working but **silent fail** — failures only show in Railway deploy tab |
| Monitor-tick cron | `recupero-worker --monitor-tick` (every 5 min) for `monitoring_subscriptions` | Wired; emits `recupero_alerts_fired_total` |
| Freeze follow-up cron | `recupero-worker --freeze-followups` (every 6h) | Wired; sets non-zero exit on send failures |
| On-call rotation | `docs/OPERATOR_RUNBOOK.md` exists; no PagerDuty/Opsgenie | Solo operator |

---

## TOP 10 GAPS (impact × ease ordering)

### 1. CRITICAL — Nothing scrapes `/metrics` or routes Sentry pages
**Failure modes covered:** all 10. Detection today: customer email or Railway dashboard glance. Target: <5 min.
**Fix (1 day):** Set `SENTRY_DSN`, `RECUPERO_ENV=production`, `RECUPERO_RELEASE`, `SENTRY_TRACES_SAMPLE_RATE=0` in Railway. Configure Sentry project alerts: ≥3 events/5min on `level:error` → email/Slack. Add Sentry alert: `tag:stage:trace AND level:error` count >5/hr → page. Total Sentry cost in time: ~30min config.

### 2. CRITICAL — No "worker stopped claiming" alert (failure mode #1)
**Detection today:** `recupero_claims_total{outcome="empty"}` is the only signal that worker is alive but idle; no one watches it. A deadlocked worker still heartbeats from the heartbeat thread (separate from the polling loop), so even `/health` returns 200 while the polling loop hangs.
**Time-to-detect:** hours, until a customer notices their case never moves.
**Fix (1 day):** Add a Sentry cron heartbeat — emit a `log.info("worker_loop_alive", extra={...})` at the top of every polling iteration in `worker/main.py:run_forever` and use Sentry's "Crons" feature with a 2-minute schedule. Alternative: add an `inv_loop_iterations_total` counter to `observability/metrics.py` and a UptimeRobot keyword check on `/metrics` for `inv_loop_iterations_total` strictly increasing.

### 3. CRITICAL — Stripe webhook failures invisible (failure mode #7)
**Detection today:** `log.warning("stripe webhook verify failed: %s")` in `worker/_health_server.py:_handle_stripe_webhook`; Stripe dashboard shows 400s on the Webhook page; **nobody watches it**. A signing-secret rotation that wasn't propagated drops 100% of revenue silently.
**Time-to-detect:** hours-to-days (when a customer asks where their report is).
**Fix (1 day):** Sentry alert on `logger:recupero.worker._health_server level:warning message:"stripe webhook"`. Threshold: ≥1 event/hr → page. Also add a `recupero_stripe_webhook_total{outcome}` counter alongside `claims_total` in `observability/metrics.py`; alert on `outcome="verify_fail"` rate > 0.

### 4. CRITICAL — Portal token verification regression (failure mode #8)
**Detection today:** `verify_token` in `portal/tokens.py` logs `WARNING verify_token: RECUPERO_TOKEN_PEPPER not configured`; a key rotation that wipes the pepper drops 100% of portal traffic to 401. The legacy-mode warning is the *only* signal.
**Time-to-detect:** "next time a customer complains the link is broken."
**Fix (1 day):** Add `recupero_portal_verify_total{outcome="ok"|"expired"|"invalid"|"legacy_mode"}` counter; Sentry alert on `outcome="invalid"` rate suddenly >50% of total. Also: emit a startup `log.error` if `RECUPERO_TOKEN_PEPPER` is unset AND `RECUPERO_ENV=production` — fail-loud, not silent-warn.

### 5. CRITICAL — Cron services fail silently (failure modes #5, partial #1)
**Detection today:** Railway's deploy tab shows cron-job exit codes only when an operator clicks in. `_run_watch_tick_once` swallows render errors with `return 0` (`worker/main.py:660`) so even a fundamentally broken digest reports success.
**Time-to-detect:** days (when no digest email lands and someone notices).
**Fix (1 day):** Configure a Sentry cron monitor per cron service (watch-tick, monitor-tick, freeze-followups, send-followups). Sentry pages when a scheduled check-in is missed by 2× the expected interval. Also: change `_run_watch_tick_once` to exit non-zero on render failure so Railway surfaces it.

### 6. HIGH — No `/metrics` consumer (failure modes #3, #2, #10)
**Detection today:** Histogram exists for `stage_duration` but the data dies in-process when the worker exits or restarts. Etherscan-rate-limit retry storms, CoinGecko 500s, and memory growth all manifest as quietly elevated stage durations.
**Time-to-detect:** never (data is not persisted).
**Fix (1 week):** Stand up Grafana Cloud's free tier (10k series, fine for our cardinality cap of 10k). Configure a Prometheus remote-write agent (Grafana Agent or `prometheus-pushgateway`) reading the worker's `/metrics`. Build 3 panels: claim rate, stage duration p50/p95/p99 by stage, alerts-fired rate. Alert on stage_duration_p95{stage="trace"} > 600s for 15min.

### 7. HIGH — Disk fills are invisible (failure mode #9)
**Detection today:** `worker/sync.py` has a 256MB per-file cap (`_UPLOAD_HARD_CAP_BYTES`) but nothing watches *aggregate* disk on the Railway container. Railway containers ship with ~10GB ephemeral; a runaway evidence dump fills it and the worker OOMs on the next `_upload`.
**Time-to-detect:** "next time the worker crashes with `OSError: No space left on device`."
**Fix (1 day):** Add a `recupero_disk_free_bytes` gauge in `observability/metrics.py` populated from `shutil.disk_usage("/tmp")` every 60s from a daemon thread. Sentry alert on value < 1GB. Also wire it into `/health` so Railway healthcheck flips to 503 below 500MB.

### 8. HIGH — CoinGecko / Etherscan circuit-breaker doesn't exist (failure modes #2, #3)
**Detection today:** Both clients use `tenacity` `@retry` (exponential backoff, `stop_after_attempt`) in `pricing/coingecko.py` and `chains/ethereum/etherscan.py`. There is **no circuit breaker** — every concurrent worker keeps hammering during an outage. A 1-hour CoinGecko outage means N×60×retries hitting the dead endpoint, with each individual investigation eventually failing on `finding_freeze_targets`.
**Time-to-detect:** hours (manifest as `error_stage=finding_freeze_targets` cluster in admin UI).
**Fix (1 week):** Add a process-wide circuit breaker (simple shared `threading.Event` flipped after N consecutive 5xx in a 60s window). Failing fast lets cases fail-and-retry on the next worker iteration instead of pinning the worker on retry storms. Plus: `recupero_upstream_circuit_state{provider}` gauge so Sentry/Grafana surface "CoinGecko is down right now."

### 9. MEDIUM — Postgres pool exhaustion is invisible (failure mode #4)
**Detection today:** `_common.db_connect` opens one connection per call against the pooler (port 6543); psycopg's connection failures bubble up as `OperationalError` which Sentry would catch — but only if Sentry is wired (gap #1). The pooler itself can saturate without surfacing.
**Time-to-detect:** sporadic worker errors with no pattern.
**Fix (1 day):** Add `recupero_db_connect_seconds` histogram around every `db_connect()` call site (helpers in `_common.py`); Sentry/Grafana alert on p95 > 5s. Also: validate `SUPABASE_DB_URL` uses port `6543` (pooler) at startup — log error if it's `5432` (direct).

### 10. MEDIUM — Brief render corruption is silent (failure mode #6)
**Detection today:** `recupero_brief_render_seconds` histogram exists, but there is no sanity check on the output (no minimum byte size, no required-section validator). A template change that breaks freeze-letter rendering silently emits a 200-byte stub HTML and the worker marks the row `complete`.
**Time-to-detect:** "customer says the brief is empty / wrong."
**Fix (1 week):** Add a post-render sanity check in `reports/brief.py`: minimum HTML size, presence of `<h1>` + `victim_name` + `total_outflow_usd`. Emit `recupero_brief_render_total{outcome="ok"|"sanity_fail"}`. Sentry-alert on any `sanity_fail`.

---

## CRITICAL items that block go-live

Items #1–5 (Sentry routing, worker-loop heartbeat, Stripe webhook alert, portal-token alert, cron-job heartbeats). Total effort: **2–3 engineer-days, all on existing primitives.** Without these, the failure mode is "customer notices first" for every revenue-touching path.

## NICE-TO-HAVE (ship after first customer)

Items #6–10 (Grafana, disk gauge, circuit breaker, DB latency, brief sanity). Each is a real gap but the existing JSON logs + Sentry breadcrumbs make them survivable for a low-traffic period (first 10 customers). Schedule for v0.31.

---

## MINIMUM RUNBOOK (operator on-call playbook)

`docs/OPERATOR_RUNBOOK.md` already covers most of this; the additions below are the **alert → action** wiring that doesn't exist yet.

1. **"Worker stopped processing cases"** — Sentry cron heartbeat missed (gap #2). Action: hit `/healthz`; if 200, SSH to Railway logs, look for last `claim_one FAILED`; if `/healthz` times out, Railway → Restart. Reaper will reclaim orphans on next boot.
2. **"Stripe webhook 400s spiking"** — Sentry alert (gap #3). Action: Stripe Dashboard → Webhooks → verify signing secret matches Railway `STRIPE_WEBHOOK_SECRET`. Resend failed events from Stripe UI after fix.
3. **"Portal 401 rate >50%"** — Sentry alert (gap #4). Action: verify `RECUPERO_TOKEN_PEPPER` is set in Railway and matches the value used at token-issue time. If pepper rotated, regenerate tokens via `recupero-ops generate-customer-link`.
4. **"CoinGecko / Etherscan circuit open"** — Sentry alert (gap #8 once shipped). Action: check provider status page; if upstream really down, pause worker (Railway → Pause). Reaper handles in-flight rows. Resume when upstream recovers.
5. **"Cron job missed check-in"** — Sentry cron monitor (gap #5). For watch-tick (03:00 UTC), monitor-tick (every 5min), freeze-followups (every 6h), send-followups (daily). Action: Railway → cron service → Deployments → click latest → View Logs.
6. **"Victim emailing about missing brief"** — Check `investigations.status` in Supabase. If `awaiting_review`, run `scripts/check_stale_reviews.py`; if `failed`, look at `error_stage` (mapping in `OPERATOR_RUNBOOK.md`). Brief-corruption case (gap #10): pull `briefs/freeze_request_*.html` from bucket and eyeball.
7. **"Disk fills"** — Sentry alert on `recupero_disk_free_bytes` (gap #7). Action: Railway → Restart (tempdir wipes). If recurring, check for a runaway investigation with unusual transfer count via `recupero_trace_transfers_count`.
8. **"Anthropic 401/429"** — error_stage=`drafting_editorial`. Action: console.anthropic.com → billing; check credit + key validity.
9. **"Supabase paused / connection refused"** — covered in `OPERATOR_RUNBOOK.md`; restore from Supabase dashboard.
10. **"Everything is broken"** — Pause worker → roll back to last green deploy (Railway → Deployments → Redeploy a green one). Reaper recovers state on next boot.

---

**Bottom line:** the *instrumentation* is in place (logs, metrics, Sentry hooks, healthchecks, runbook). The *routing* is the gap — wire `SENTRY_DSN`, set up a cron heartbeat, and the first five customer-facing failure modes drop from "customer complains" to "operator paged in <5 min" for 2-3 days of work.
