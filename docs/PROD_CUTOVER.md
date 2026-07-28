# Recupero SaaS — Production Cutover Checklist

One page to take the `/v2` multi-tenant SaaS layer live on Railway (prod
auto-deploys from `main`). The engine + `/v1` API already ship; this is the
tenancy/platform layer. Everything below **degrades gracefully when unset** — an
unconfigured deploy stays up, the affected feature just returns 501 / falls back
/ no-ops. Full env reference: [ENV_VARS.md](ENV_VARS.md); design:
[PLATFORM_ARCHITECTURE.md](PLATFORM_ARCHITECTURE.md); infra:
[../infra/README.md](../infra/README.md).

Legend: **[REQUIRED]** blocks the `/v2` surface · **[RECOMMENDED]** needed at
real scale · **[OPTIONAL]** feature flip.

---

## 1. Services (Railway)

- [ ] **`recupero-api`** — `uvicorn recupero.api.app:app`, healthcheck `/healthz`.
      *Without this service the `/v2` API + `/v1/console` are unreachable even though the code ships.*
- [ ] **`recupero-worker`** — the SKIP-LOCKED queue consumer (runs traces, writes case artifacts).
- [ ] **`recupero-cron`** (scheduler) — `platform_maintenance`, freeze-followup, OFAC sync, attribution harvest, etc.
- [ ] **`recupero-web`** — the CUSTOMER-FACING Next.js app (`web/`). This is a
      SEPARATE service: the root `Dockerfile` builds only the Python services and
      copies `src/`, so nothing in the API deploy ships the frontend.
      Railway: new service, **Root Directory = `web`**, Dockerfile Path =
      `Dockerfile` (see [../web/railway.json](../web/railway.json)).
      Vercel alternative: point a project at `web/` — no Dockerfile needed.
      - [ ] `NEXT_PUBLIC_API_BASE_URL` = the API origin. **Build-time** (it is a
            `NEXT_PUBLIC_*` var, inlined into the client bundle) — set it as a
            build arg/env BEFORE the image is built, or every call fails with
            "network error — is the API reachable?".
      - [ ] Set `RECUPERO_API_CORS_ORIGINS` on the **API** service to this web
            origin (the browser calls `/v2` cross-origin).
      - [ ] `PREVIEW_PASSWORD` — OPTIONAL. Set it to gate the whole site behind
            HTTP Basic while reviewing; **leave it unset for a public launch**
            (it used to be a hardcoded `"preview"` that 401'd every customer).
- [ ] For horizontal scale: k8s manifests + KEDA queue-depth autoscaling in [../infra/k8s](../infra/k8s).

## 2. Database — [REQUIRED]

- [ ] Provision Supabase Postgres; set `RECUPERO_DATABASE_URL` (or `DATABASE_URL`) + `SUPABASE_DB_URL`.
- [ ] Run migrations **in order through `043`** (`migrations/037_multitenancy` … `041_user_tokens`, `042_wallet_guard`, `043_stripe_event_dedup`). 042 creates `watched_addresses` + `wallet_alerts`, which back the shipped `/v2/guard/*` endpoints and the Wallet Guard UI — stopping at 041 ships that surface with no tables. 043 creates `stripe_events`, the webhook replay guard — without it a duplicate Stripe delivery re-grants monthly quota.
      Sequence 021 before flipping older cron jobs (historical note); apply the rest ascending.
- [ ] Confirm RLS is on for the tables that actually declare it: `organizations` (NOT `orgs`), `memberships`, `org_api_keys`, `usage_events` (037), `org_invites` (039), `watched_addresses`, `wallet_alerts` (042).
- [ ] **Decision required:** `users` (037) and `audit_log` (034) have **no RLS policy anywhere**. Either add one or accept service-role-only access — do not tick this line without deciding.

## 3. Required platform env — [REQUIRED] (auth FAILS CLOSED / 503 if unset)

- [ ] `RECUPERO_PLATFORM_JWT_SECRET` — HS256 signing secret for `/v2` sessions. Long random; rotate on a schedule.
- [ ] `RECUPERO_ADMIN_KEY` — gates every `/v1` admin console + review API (deny-by-default when unset).
- [ ] `RECUPERO_APP_BASE_URL` — public web origin (invite / verify / reset links + Stripe redirects).
- [ ] `RECUPERO_GIT_SHA` — set at deploy so `/healthz` confirms the running commit.

## 4. Object storage (artifact downloads) — [RECOMMENDED]

- [ ] `RECUPERO_ARTIFACT_BUCKET` + `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ `RECUPERO_ARTIFACT_REGION`).
      Enables presigned `GET /v2/traces/{id}/artifacts/{name}` and the worker→S3 mirror. Unset → those endpoints 501.
- [ ] S3-compatible (R2 / MinIO / GCS-XML): also set `RECUPERO_S3_ENDPOINT`.
- [ ] The bespoke `GET /v2/traces/{id}/graph` (JSON) does **not** need S3 — it builds from the case store, so it works regardless.

## 5. Scale & delivery flips — [RECOMMENDED]

- [ ] `RECUPERO_REDIS_URL` — shared rate-limit bucket + API-key cache. **Set once you run >1 API replica** (in-process limiter is correct for one replica only; fails open if Redis is unreachable).
- [ ] `RESEND_API_KEY` — transactional email (invite / verify / **password-reset**). Until set, reset tokens are minted but never delivered (reset is unusable by design — the token is emailed only, never returned).
- [ ] Stripe: `RECUPERO_STRIPE_SECRET_KEY`, `RECUPERO_STRIPE_WEBHOOK_SECRET`, `RECUPERO_STRIPE_PRICE_PRO` / `_ENTERPRISE`. Point a Stripe webhook at `POST /v2/webhooks/stripe`.

## 6. Optional extras (opt-in; keep default install lean) — [OPTIONAL]

- [ ] `pip install .[argon2]` + `RECUPERO_PASSWORD_ARGON2=1` → argon2id for new hashes (rehash-on-login; scrypt otherwise).
- [ ] `pip install .[otel]` + `RECUPERO_OTEL_ENABLED=1` (+ `OTEL_EXPORTER_OTLP_ENDPOINT`) → request tracing.
- [ ] `RECUPERO_PLATFORM_REQUEST_LOG=1` → structured per-tenant JSON request log (`recupero.platform.request`).
- [ ] `RECUPERO_API_ALLOWED_HOSTS` / `RECUPERO_API_CORS_ORIGINS` once the API is on a public domain.

## 7. Smoke test (post-deploy)

- [ ] `GET /healthz` → 200 with the expected `git_sha`.
- [ ] `POST /v2/auth/signup` → 201 + token; `GET /v2/me` with it → plan/usage.
- [ ] `POST /v2/traces` → 202 queued; worker claims it; `GET /v2/traces/{id}` → completes.
- [ ] `GET /v2/traces/{id}/graph` → `{nodes, edges, meta}`; `…/artifacts/brief.pdf` → presigned URL (or 501 if §4 skipped).
- [ ] `GET /v2/traces/{id}/stream` (with `?token=`) emits SSE status until terminal.
- [ ] Idempotency: repeat `POST /v2/traces` with the same `Idempotency-Key` → `idempotent_replay: true`, no double-meter.

## 8. Observability

- [ ] Scrape `GET /v2/metrics` (API) + the worker health-port `/metrics` with Prometheus.
- [ ] Import [../infra/grafana/recupero-saas-dashboard.json](../infra/grafana/recupero-saas-dashboard.json).
- [ ] Confirm `GET /v2/audit` returns org-scoped events (auth/admin actions).

## 9. Safety invariants to re-confirm before real traffic

- [ ] Freeze letters are **human-gated** — the dispatcher never auto-sends; keep it gated in prod.
- [ ] `POST /v2/auth/password/reset-request` always returns 202 and **never** returns the token (no user enumeration).
- [ ] API-key cache is positive-only + revoke-invalidated; revoking a key stops auth at once.
- [ ] Signed custody chain: set `RECUPERO_CUSTODY_KEY_PATH` if you rely on signed litigation artifacts.

## 10. Rollback

Prod deploys from `main`; to roll back, revert the offending commit on `main`
(auto-redeploys) or pin the previous Railway deployment. Migrations are additive
(FKs `ON DELETE SET NULL/CASCADE`); a code rollback does not require a DB
down-migration.
