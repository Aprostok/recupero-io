# v0.30.1 Go-Live Runbook

This is the deploy + on-call playbook for the first customer-facing
Recupero deployment. Closes items 2, 4, and part of 6 from the go-live
preflight sweep. See also:
- `docs/V030_OBSERVABILITY_GAPS.md` — what's instrumented vs unwired
- `docs/V030_CONTACT_AUDIT.md` — issuer + LE contact freshness
- `docs/V030_ROUND_N_AUDIT.md` — security/correctness Tier 1-4
- `docs/V030_DEPLOY_PREFLIGHT.md` — gate-by-gate spec (this doc)

---

## Pre-merge gate (item #2)

Run, before merging `pdf-deliverables` → `main`:

    python scripts/deploy_preflight.py [--strict-sentry]

The preflight enforces six gates in sequence:

1. **required_env_vars** — RECUPERO_INVESTIGATOR_NAME and
   RECUPERO_TOKEN_PEPPER MUST be set in the deploy env (Railway
   Variables). With `--strict-sentry`, SENTRY_DSN also required.
2. **label_db_validator** — `python -m recupero.labels.validator`
   must report 0 errors.
3. **critical_tests** — pytest on the 9 most change-relevant files
   (bridge expansion, v0.30 read-through, portal tokens, labels
   seeds integrity, inspector).
4. **smoke_deliverables** — `scripts/smoke_deliverables.py` must
   generate 12 deliverables against the bundled ALEC fixture.
5. **unsigned_brief_detection** — proves F7 gate fires. With
   RECUPERO_INVESTIGATOR_NAME unset, the brief MUST stamp
   "UNSIGNED — DO NOT TRANSMIT" across every page.
6. **mutation_harness** — `scripts/mutation_smoke.py` must detect
   33/33 known mutations.

Exit 0 = safe to merge. Non-zero = STOP, investigate the failed gate.

For machine-readable output (CI integration):

    python scripts/deploy_preflight.py --json --strict-sentry

---

## Production env vars

Railway Variables that MUST be set before a customer-facing deploy:

| Var | Purpose | Failure mode if unset |
|---|---|---|
| `RECUPERO_INVESTIGATOR_NAME` | §9 attestation signature on every LE brief | F7 gate auto-stamps "UNSIGNED — DO NOT TRANSMIT" |
| `RECUPERO_TOKEN_PEPPER` | HMAC pepper for portal tokens | `generate_token` raises RuntimeError; all portal links broken |
| `RECUPERO_INVESTIGATOR_EMAIL` | Default investigator contact in brief headers | Falls back to `compliance@recupero.io` (works but not customizable) |
| `RECUPERO_INVESTIGATOR_ENTITY` | "Recupero LLC" or similar on attestation | Defaults to "Recupero LLC" |
| `SENTRY_DSN` | Routes exceptions to Sentry | No error visibility on prod — silent failures |
| `SUPABASE_DB_URL` | Postgres DSN | Worker refuses to start (preflight in `worker/main.py`) |
| `STRIPE_API_KEY` | Live mode Stripe credentials | Payment links can't be generated |
| `STRIPE_WEBHOOK_SECRET` | Webhook signature verification | `/v1/stripe-webhook` returns 400; revenue silently dropped |
| `ETHERSCAN_API_KEY` | Free tier ok for low volume | Rate-limits at 5 req/sec; cases stall |
| `COINGECKO_API_KEY` | Pro tier for historical pricing | Falls back to free tier; USD valuations may be missing |
| `HELIUS_API_KEY` | Solana cases only | Solana traces fail; non-Solana cases unaffected |

**One-time setup checklist** (before first customer):

- [ ] Set all 11 required vars in Railway Variables
- [ ] Verify Stripe is in LIVE mode (`STRIPE_API_KEY` starts with `sk_live_`, not `sk_test_`)
- [ ] Verify Postmark / Resend account is set up, DKIM-signed, and the
      sending domain matches `RECUPERO_INVESTIGATOR_EMAIL`
- [ ] Verify the Supabase service-role key is scoped to non-admin RLS
      (a leaked service key = full DB dump)
- [ ] Run `python scripts/deploy_preflight.py --strict-sentry` against
      the actual prod env (via Railway shell) — all 6 gates must pass

---

## Merge procedure (`pdf-deliverables` → `main`)

The current PR has 4 minor releases of unreleased work (v0.28 + v0.28.x
+ v0.29.0 + v0.29.1 + v0.30.0 + v0.30.1). This is a LARGE merge — do
NOT just hit "merge" on the GitHub PR. Procedure:

1. **Pre-merge**: run `deploy_preflight.py --strict-sentry` against
   Railway's prod env shell. All gates pass.
2. **Tag the merge commit** with the version: `git tag v0.30.1 main`.
3. **Push tag separately** so Railway can deploy by tag if needed:
   `git push origin v0.30.1`.
4. **Merge**: prefer a single merge commit (NOT squash) so the per-
   release history (v0.28 / v0.29 / v0.30) is preserved on `main`.
5. **Watch the Railway deploy** for the first 15 minutes:
   - `/healthz` returns 200
   - `/metrics` exposes Prometheus counters
   - Sentry receives the deploy event (proves SENTRY_DSN wired)
   - First scheduled `--watch-tick` cron run completes without
     raising in the Railway deploy tab
6. **Manual smoke test**: hit `https://recupero.io/intake/test-form`
   (or whatever the prod intake URL is) with a fake case, walk
   through the journey. Time it.
7. **Rollback procedure** if something explodes:
   - `git revert <merge-commit>` and force-push to `main`
   - Railway redeploys automatically
   - Verify `/healthz` recovers
   - Open incident report in `docs/INCIDENTS/`

---

## Customer journey — what's wired vs aspirational (item #4)

| Step | Status | Notes |
|---|---|---|
| Intake form (`/intake`) | **WIRED** | `src/recupero/portal/server.py`; honeypot, rate-limiting (`_intake_rl_client_ip`), validation present (v0.25.0) |
| Stripe payment link | **WIRED, but TEST MODE by default** | Verify `STRIPE_API_KEY` starts with `sk_live_` before going live |
| Stripe webhook → case creation | **WIRED** | `src/recupero/api/stripe_webhook.py` (signature-verified) |
| Portal token email to victim | **WIRED** | Migration 017 + dispatcher email channel (v0.21.0). Verify Postmark/Resend account |
| Worker picks up case + traces | **WIRED** | `worker/watch_tick.py` polls; `worker/main.py` runs the loop |
| Brief generation | **WIRED** | `worker/_deliverables.py::build_all_deliverables` (12-file bundle) |
| Brief delivery via email | **WIRED** | `worker/_email.py` sends LE handoff + invoice |
| Freeze letter cron follow-up | **WIRED** | `--freeze-followups` cron (v0.21.0); 72h/7d/14d cadence |
| Customer portal (view case status) | **WIRED** | Token-gated; portal token verify path |
| Law firm dashboard | **WIRED** | v0.26.0; standalone deliverable |
| Recovery snapshot pre-engagement | **WIRED** | v0.22.0 |
| **End-to-end timing** | **NOT MEASURED** | Need to walk the full intake → brief journey on prod and time each step. Target: < 30 min from payment to brief delivery for a simple case |

**Single biggest unknown for go-live**: has anyone run the customer
journey end-to-end on a real prod deploy with real Stripe live-mode
keys? If no, this is the first thing to do after merge.

---

## Minimum on-call runbook (item #6 abridged)

If `docs/OPERATOR_RUNBOOK.md` exists, that's the canonical version.
Below is the v0.30.1 minimum subset:

### Worker stopped processing cases
- Check Railway `worker` service: process running?
- Hit `/healthz` on the worker port — does it return 200 within 5s?
- Check Sentry for unhandled exceptions in the last hour
- Check Supabase: are there cases in `pending` status with old `updated_at`?
- `recupero-ops status` for a quick worker snapshot
- If stuck: `railway redeploy` on the worker service

### Etherscan / CoinGecko / Helius rate-limited
- Symptom: cases stall mid-trace; logs show 429s
- Verify the API key in Railway Variables is the right tier
- For Etherscan: pro tier is 30 req/sec; free is 5 req/sec
- The HTTP client (`src/recupero/http_client.py`) retries with backoff;
  if you see persistent 429s after retries, the tier needs upgrade
- Short-term: pause `--watch-tick` cron, drain in-flight cases, resume

### Stripe webhook 4xx (revenue at risk)
- Check Stripe Dashboard → Developers → Webhooks → recent events
- Verify `STRIPE_WEBHOOK_SECRET` matches the endpoint's secret
- If signing key rotated: update the env var, redeploy
- For each missed event: replay from Stripe Dashboard

### Portal token verification 100% failing
- Likely cause: `RECUPERO_TOKEN_PEPPER` was rotated
- Tokens issued under the old pepper will permanently fail
- Procedure: issue new tokens via `recupero-ops generate-customer-link`
  for affected cases, email victims with the replacement link
- DO NOT rotate the pepper casually — it invalidates every outstanding portal link

### Brief silently malformed (customer complains)
- Pull the case_dir from the case archive
- Run `python scripts/smoke_deliverables.py` against the case (modify
  to point at the failing case's dir)
- Compare against ALEC-TEST-2026 output for shape
- Most common cause: missing token in `_TOKEN_ASSET_DESCRIPTIONS` →
  asset description shows generic "ERC-20 token". Add the token to
  the map in `brief.py` and re-render

### CoinGecko returns 500s for an hour
- Cases mid-flight will have `usd_value_at_tx = None` for affected
  transfers
- The trace pipeline tolerates None and renders "(unknown)" in the brief
- Operator can re-price post-hoc via `recupero-ops repriced-trace`
- Sentry should alert on >10% None pricing rate

### Disk full (case_dir / evidence receipts)
- `df -h` on Railway shell
- Identify large dirs: `du -sh data/cases/* | sort -h | tail`
- Archive old cases: see `scripts/backup_investigations.py`
- Long-term: move evidence receipts to S3 / Supabase storage

### Sentry DSN unset / Sentry not receiving events
- Verify `SENTRY_DSN` in Railway Variables
- Sentry SDK initializes at `src/recupero/observability/sentry.py`
- Test: `python -c "from recupero.observability.sentry import init; init(); raise RuntimeError('test')"` —
  should land in Sentry within 30s

### Crash loop on deploy
- Railway will show a "deploy failed" if `worker/main.py` exits within
  `_MIN_UPTIME_SEC` (30s). This is intentional — it prevents Railway
  from restarting a misconfigured worker every 5s and burning budget
- Look at the last log line before exit; almost always a missing
  env var (see `_missing_env_vars` preflight)
- Fix env var, redeploy

---

## Post-deploy verification checklist

After every merge to main:

- [ ] Railway deploy status: succeeded
- [ ] `/healthz` returns 200 in < 5s
- [ ] `/metrics` exposes counters (curl from Railway shell)
- [ ] First `--watch-tick` cron run completes (Railway logs)
- [ ] Sentry receives a synthetic test event
- [ ] One manual case ingest end-to-end (intake → payment → brief)
- [ ] Compare the generated LE brief against the ALEC fixture for shape
- [ ] No "UNSIGNED — DO NOT TRANSMIT" stamps on the production brief
- [ ] Update `docs/OPERATOR_RUNBOOK.md` if procedure changed
