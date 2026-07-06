# Recupero — Production SaaS Architecture

> How the battle-tested forensic **engine** becomes a multi-tenant SaaS that
> scales to millions of users. This document is the target design; the
> **minimal scalable slice** (the multi-tenant `/v2` API) is built in
> `src/recupero/platform/` + `migrations/037_multitenancy.sql`.

## 0. Reality check (what already exists — do NOT rebuild)

Recupero is **not** greenfield. The following are built, tested (6,300+ tests),
and production-shaped — they are *dependencies*, not work items:

| Layer | Status | Where |
|---|---|---|
| Forensic **engine** (BFS value-tracer, 10 chain adapters, bridge oracle, spam/poison prune) | ✅ mature | `src/recupero/trace`, `src/recupero/chains` |
| Freeze artifacts + legal deliverables (LE handoff, SAR/STR, exhibit pack) | ✅ | `src/recupero/reports`, `worker/_deliverables.py` |
| **Async job queue** — `investigations` table drained by workers via `FOR UPDATE SKIP LOCKED` (multi-worker safe) | ✅ | `src/recupero/worker` |
| REST API framework (FastAPI, 30+ endpoints, OpenAPI) | ✅ `/v1` | `src/recupero/api/app.py` |
| DB migrations (raw SQL, numbered) on Supabase Postgres | ✅ 001–037 | `migrations/` |
| Deploy (Railway, `$PORT`, `/healthz`) | ✅ | `railway.json`, `Dockerfile` |

**The gap** for a millions-user SaaS is the **product/tenancy layer**: auth today
is a flat set of named API keys (`require_api_key` → a name), not org-scoped;
there is no self-serve signup, no per-tenant quotas/billing, no customer web app,
no edge rate-limiting. That is what this design + the `/v2` slice add — **in
stack** (FastAPI + psycopg + SQL migrations), reusing the queue and engine.

---

## 1. System architecture

```
                    ┌────────────────────────────────────────────────────┐
   Browser  ─────►  │  CDN / Edge (Cloudflare)                            │
   (Next.js app)    │   • TLS, WAF, DDoS, static assets, edge rate-limit  │
                    └───────────────┬────────────────────────────────────┘
   API clients ─────────────────────┤ (X-API-Key: rk_live_…)
   (exchanges,                       ▼
    attorneys)      ┌────────────────────────────────────────────────────┐
                    │  API tier — FastAPI (stateless, N replicas)         │
                    │   /v2  multi-tenant  (this build)                   │
                    │   /v1  legacy flat-key (back-compat)                │
                    │   auth: JWT (web) | org API key (machine)           │
                    │   per-org quota + rate limit + usage metering       │
                    └───────┬───────────────────────────┬────────────────┘
             enqueue (row)  │                            │ read (org-scoped)
                            ▼                            ▼
             ┌──────────────────────────┐   ┌───────────────────────────────┐
             │  Postgres (primary + RRs)│   │  Redis (cache, rate-limit,     │
             │   organizations, users,  │   │  pub/sub for job SSE)          │
             │   memberships, api_keys, │   └───────────────────────────────┘
             │   usage_events,          │
             │   investigations (queue) │◄─── FOR UPDATE SKIP LOCKED
             └──────────┬───────────────┘
                        │ claim job
                        ▼
             ┌──────────────────────────────────────────────────────────┐
             │  Worker fleet (K replicas, autoscaled on queue depth)     │
             │   • runs recupero engine (run_trace, build_deliverables)  │
             │   • wall-clock bounded (#253), spam-pruned, deep-reach     │
             │   • writes case artifacts → object storage                │
             └──────────┬───────────────────────────────────────────────┘
                        ▼
             ┌──────────────────────────┐   ┌───────────────────────────────┐
             │  Object storage (S3/GCS/ │   │  External RPC/data providers   │
             │  Supabase Storage):      │   │  Etherscan v2, Helius, TronGrid,│
             │  case.json, PDFs, CSVs   │   │  Sui/Aptos/Cosmos, CoinGecko,   │
             └──────────────────────────┘   │  OFAC/OpenSanctions, MistTrack  │
                                            └───────────────────────────────┘

Cross-cutting: OpenTelemetry traces + Prometheus metrics + structured logs;
Stripe (billing); SES/Resend (email); cron scheduler (label sync, freeze follow-up).
```

**Why this scales to millions:**
- **Stateless API tier** → scale horizontally behind a load balancer; sessions are
  JWTs (no server session store).
- **Work is never done in the request.** A trace is minutes-long; the API only
  *enqueues* a row and returns `202`. Throughput is decoupled from worker speed.
- **Queue is the shock absorber.** `SKIP LOCKED` lets an arbitrary number of
  workers drain safely; autoscale workers on queue depth, API on RPS.
- **Reads scale on read-replicas + Redis cache**; writes are small (enqueue + meter).
- **Per-tenant isolation** by `org_id` on every row (+ RLS defense-in-depth),
  and **quotas/rate-limits** protect shared infra from any one tenant.

---

## 2. File structure (target)

```
recupero/
├── src/recupero/
│   ├── trace/  chains/  reports/  labels/  screen/   # ENGINE (exists)
│   ├── worker/                                        # queue consumer (exists)
│   ├── api/app.py                                     # /v1 flat-key API (exists)
│   └── platform/                                      # ◄── SaaS layer (this build)
│       ├── tenancy.py     # pure crypto + plan/quota (stdlib, no new deps)
│       ├── store.py       # psycopg DAO, org-scoped
│       ├── deps.py        # FastAPI auth (JWT + API key) + rate limit
│       ├── router.py      # /v2 endpoints
│       └── billing.py     # Stripe webhooks → plan/status (NEXT)
├── migrations/037_multitenancy.sql                    # ◄── tenancy schema (this build)
├── web/                                               # ◄── customer app (Next.js — §5)
│   ├── app/(marketing)/  app/(dashboard)/
│   ├── components/  lib/api-client.ts  lib/auth.ts
│   └── package.json
├── infra/                                             # IaC (Terraform) + k8s/Helm (NEXT)
└── docs/PLATFORM_ARCHITECTURE.md                      # this file
```

---

## 3. Database schema (multi-tenant core)

`migrations/037_multitenancy.sql` (shipped). All tenant rows carry `org_id`;
RLS enabled as defense-in-depth (workers use the service role / `BYPASSRLS`).

| Table | Purpose | Key columns |
|---|---|---|
| `organizations` | the tenant | `id`, `slug` (unique), `plan`, `stripe_customer_id`, `period_start`, `trace_used_period`, `status` |
| `users` | global identity | `id`, `email` (citext unique), `password_hash` (scrypt), `email_verified_at` |
| `memberships` | user ↔ org + role | PK `(org_id,user_id)`, `role` = owner/admin/member/viewer |
| `org_api_keys` | machine access | `key_hash` (sha256, unique), `last4`, `revoked_at` (plaintext never stored) |
| `usage_events` | append-only metering | `org_id`, `kind`, `quantity`, `investigation_id` → drives billing + quota |
| `investigations` (existing) | the job queue | **+`org_id`, +`submitted_by`** (added; legacy rows backfilled to a system org) |

**Scaling notes:** partition `usage_events` by month once it's large; `investigations`
gets a partial index on `status='queued'` for the claim query; move closed cases to
cold storage after `plan.retention_days`.

---

## 4. API endpoints

### `/v2` — multi-tenant (this build)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v2/auth/signup` | — | create user+org+owner, return JWT |
| POST | `/v2/auth/login` | — | email+password → JWT |
| GET | `/v2/me` | JWT/key | principal, plan, usage/quota remaining |
| POST | `/v2/api-keys` | JWT (owner/admin) | mint org API key (**shown once**) |
| GET | `/v2/api-keys` | JWT/key | list keys (metadata only) |
| DELETE | `/v2/api-keys/{id}` | JWT (owner/admin) | revoke |
| POST | `/v2/traces` | JWT/key + rate-limit + quota | **enqueue** a trace → `202 {investigation_id}` |
| GET | `/v2/traces/{id}` | JWT/key | tenant-scoped status |
| GET | `/v2/traces` | JWT/key | list this org's traces |

**Conventions:** `202 Accepted` for async submit (never block on the trace);
`402 Payment Required` on quota exhaustion; `429` on rate limit; cursor pagination
on list endpoints; idempotency-key header on POST (NEXT); OpenAPI at `/docs`.

### `/v1` — legacy flat-key (unchanged, back-compat)
Screening, token-risk, monitoring, operator consoles. New signups get `/v2` keys.

---

## 5. UI architecture (customer web app)

**✅ Scaffold SHIPPED in `web/`** — a lean Next.js (App Router) + TypeScript app:
`web/src/lib/api.ts` (typed client for every `/v2` endpoint), `web/src/lib/auth.tsx`
(`AuthProvider`/`useAuth`), and pages for login / signup / dashboard (submit +
recent traces) / API keys / billing. Zero-dependency styling (`globals.css`) to
keep the scaffold minimal; see `web/README.md`. The fuller target below
(shadcn/TanStack/D3 flow graph, trace detail, member management, SSE live
status) is the next layer on top of this working base.

**Stack (target):** Next.js (App Router) + TypeScript + Tailwind + shadcn/ui +
TanStack Query, deployed to Vercel/Cloudflare. Talks only to `/v2`.

```
web/app/
  (marketing)/            # public: landing, pricing, docs
  (auth)/login  /signup   # posts to /v2/auth/*; stores JWT (httpOnly cookie)
  (dashboard)/
    layout.tsx            # org switcher, nav, auth guard
    page.tsx              # overview: quota gauge, recent traces, alerts
    traces/
      page.tsx            # list (TanStack Query, polling/SSE on status)
      new/page.tsx        # submit form → POST /v2/traces
      [id]/page.tsx       # trace detail: status, flow graph, freezable holdings
    keys/page.tsx         # API-key management (create → one-time reveal modal)
    billing/page.tsx      # plan, usage, Stripe portal link
    settings/members      # invite/role management
components/  ui/ (shadcn), TraceGraph (D3, reuse engine's graph JSON),
             QuotaGauge, StatusBadge
lib/  api-client.ts (typed fetch, injects Bearer), auth.ts, hooks/useTrace.ts
```

**Patterns:** server components for first paint + auth guard in `layout`; client
components for interactive (graph, live status via SSE from `/v2/traces/{id}/stream`,
NEXT); optimistic UI on submit; the D3 flow graph reuses the engine's existing
graph-JSON (no new backend). Accessibility + dark mode via shadcn tokens.

---

## 6. What needs to change / update (prioritized)

**Shipped in this slice**
1. `migrations/037_multitenancy.sql` — orgs/users/memberships/api_keys/usage + `org_id` on the queue + RLS.
2. `src/recupero/platform/*` — tenancy crypto, DAO, auth deps, `/v2` router.
3. `api/app.py` — mounts `/v2` (guarded include).
4. Unit tests for the security-critical primitives (`tests/test_platform_tenancy.py`).

**Next (to reach a billable GA), in order**
1. ✅ **DONE (`26dd413`) — Billing** — `platform/billing.py`: Stripe checkout + webhook → set `organizations.plan/status/stripe_customer_id`; reset `period_start`/`trace_used_period` monthly. Idempotency keys on `POST /v2/traces`.
2. ✅ **DONE — Metering + retention** — `platform/retention.py` + the `platform_maintenance` cron job (09:00 UTC): reconcile `usage_events(kind='trace_completed')` from the queue's terminal state (decoupled from the worker hot path, idempotent) and purge finished investigations older than the owning org's `plan.retention_days`.
3. **Object storage for artifacts** — case outputs to S3/GCS with per-org prefixes + signed URLs (today they're on the case dir / bucket); serve via `/v2/traces/{id}/artifacts`.
4. ✅ **DONE — Redis rate limiter** — `platform/ratelimit.py`: `RateLimiter` protocol with an in-process default and a shared **Redis** token bucket (atomic server-side Lua) selected by `RECUPERO_REDIS_URL`; fails open to in-process if Redis is missing/unreachable. Required once the API runs >1 replica. (Still TODO: cache `resolve_api_key` in Redis.)
5. ✅ **DONE — Org invites + member management** — migration `039_org_invites` + `platform/store` DAO + `/v2/members` routes: list members, change role, remove (last-owner guarded), invite by email (seat-quota gated over members+pending, single-use hash-only token), list/revoke pending invites, and a PUBLIC `POST /v2/members/invites/accept` (token-gated: joins an existing user or creates the account). `web/` gets a Members page + `/invite` accept page. (Still TODO: email verification + password reset.)
6. **Observability** — OpenTelemetry middleware on the API, Prometheus `/metrics`, per-tenant dashboards; structured request logs with `org_id`.
7. **Config/secrets** — `RECUPERO_PLATFORM_JWT_SECRET` (rotate; move to asymmetric ES256), `RECUPERO_DATABASE_URL`; load from a secret manager.
8. **Hardening** — argon2id passwords (drop-in via the versioned hash format), idempotency keys on POST (done in `26dd413`), per-endpoint request-size caps. ✅ **Audit log DONE** — migration `040_audit_org` adds `org_id` to `audit_log`; `platform/audit.py` records org-scoped events (org.created, auth.login, apikey.created/revoked, member.invited, invite.accepted/revoked, member.role_changed/removed) in the request txn (best-effort, never breaks the action); `GET /v2/audit` (owner/admin) + a web Activity page. (Still TODO: argon2id, size caps.)
9. **Infra** — containerize API + worker separately; Terraform for Postgres (primary+replica), Redis, object storage; k8s HPA: API on RPS, workers on queue depth.

## 7. Environment variables (new)
| Var | Purpose |
|---|---|
| `RECUPERO_PLATFORM_JWT_SECRET` | HS256 signing secret for session tokens (required for `/v2` auth) |
| `RECUPERO_PLATFORM_JWT_TTL_SEC` | session lifetime (default 3600) |
| `RECUPERO_DATABASE_URL` | Postgres DSN for the platform DAO (falls back to `DATABASE_URL`) |
