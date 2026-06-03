# Deploying the `recupero-api` service (operator console + /v1 API)

The operator console (`/v1/console`) and the whole `/v1/*` API live in the
**FastAPI app**, whose entrypoint is the `recupero-api` console script
(`recupero.api.app:main`). `railway.json`'s default `startCommand` is
**`recupero-worker`** (the background trace processor), which only answers a
health probe at `/` — so a service running the default will **404 `/v1/console`**.

To make the console reachable you need a Railway service whose start command is
`recupero-api`. Two options.

## Option A — fastest: flip the existing service (stops the worker there)

In Railway → open the **`recupero-io`** service → **Settings → Deploy**:

1. **Custom Start Command** → `recupero-api`
2. **Healthcheck Path** → `/v1/health` (or `/healthz` — the API answers both as
   of the `$PORT`/`/healthz` deploy fix).
3. **Variables** (Settings → Variables) must include at least:
   - `RECUPERO_ADMIN_KEY` — the admin secret the console asks for. Without it
     every admin route returns 503; with it, paste the same value into the
     console's key box (stored in `sessionStorage`, sent as
     `X-Recupero-Admin-Key`).
   - `SUPABASE_DB_URL` — Postgres DSN (console stats / DB-backed phases degrade
     to empty when unset, never 500).
   - `RECUPERO_RANDOMIZATION_SECRET` — high-entropy per-case HMAC secret.
4. **Redeploy.**

→ Console: **`https://recupero-io-production.up.railway.app/v1/console`**

Trade-off: that service no longer runs the background worker. Use Option B to
keep both.

## Option B — clean: a dedicated api service (worker + api both run)

1. Railway project → **+ New → GitHub Repo** → select the same repo
   (`Aprostok/recupero-io`). It builds from the same `Dockerfile`.
2. New service → **Settings → Deploy**:
   - **Custom Start Command** → `recupero-api`
   - **Healthcheck Path** → `/v1/health`
3. **Settings → Networking → Generate Domain** (or attach a custom domain, e.g.
   `app.recupero.io`).
4. **Variables** → copy the same vars as Option A (RECUPERO_ADMIN_KEY,
   SUPABASE_DB_URL, RECUPERO_RANDOMIZATION_SECRET, plus any chain API keys the
   API needs).

→ Console: **`https://<generated-domain>/v1/console`**

The cron scheduler is a THIRD service (`startCommand: recupero-cron`) — see the
note in `railway.json`. So the full topology is three services off one
image/repo: `recupero-worker` (default), `recupero-api`, `recupero-cron`.

## Why the deploy fix was needed (already on main)

- `main()` now honors the PaaS-injected `$PORT` (precedence
  `RECUPERO_API_PORT → PORT → 8000`) — Railway routes external traffic to
  `$PORT`, so binding 8000 would fail the healthcheck.
- The API serves `/healthz` (alias of `/v1/health`) so it passes both
  `railway.json`'s `healthcheckPath` and the Dockerfile `HEALTHCHECK` with no
  per-service override.

## Optional hardening (env-gated, default off)

- `RECUPERO_API_ALLOWED_HOSTS` — comma-separated Host allow-list → installs
  TrustedHostMiddleware (set this once on a public domain).
- `RECUPERO_API_CORS_ORIGINS` — comma-separated origins → installs CORS (only
  needed for cross-origin API clients; the console is same-origin).
- The API process also inits structured logging + Sentry (`SENTRY_DSN`) on
  startup, matching the worker.

## Smoke check after deploy

```
curl -s https://<api-domain>/v1/health        # {"status":"ok", "version": ...}
curl -s https://<api-domain>/healthz           # same payload
curl -s -o /dev/null -w '%{http_code}' https://<api-domain>/v1/console   # 200
```

Then open `/v1/console`, paste `RECUPERO_ADMIN_KEY`, and the phase consoles load.
