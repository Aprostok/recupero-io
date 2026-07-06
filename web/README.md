# Recupero Web — customer console

Next.js (App Router) frontend for the Recupero **`/v2`** multi-tenant SaaS API
(`src/recupero/platform/`). It is a thin, stateless client: all data lives in the
FastAPI service; this app only holds the session token.

## What's here

```
web/
├─ src/
│  ├─ lib/
│  │  ├─ api.ts         # typed client for every /v2 endpoint (+ ApiError)
│  │  └─ auth.tsx       # AuthProvider / useAuth — token in localStorage
│  └─ app/
│     ├─ layout.tsx     # wraps the tree in <AuthProvider>
│     ├─ page.tsx       # → /dashboard or /login
│     ├─ login/         # sign in
│     ├─ signup/        # create org (self-serve, free plan)
│     └─ dashboard/
│        ├─ layout.tsx  # auth guard + nav
│        ├─ page.tsx    # submit a trace + recent-traces table
│        ├─ keys/       # create / list / revoke org API keys
│        └─ billing/    # plan, usage, seats, Stripe upgrade
```

## Endpoints consumed

| UI | API |
| --- | --- |
| login / signup | `POST /v2/auth/login`, `POST /v2/auth/signup` |
| dashboard | `GET /v2/traces`, `POST /v2/traces` (with `Idempotency-Key`) |
| keys | `GET/POST /v2/api-keys`, `DELETE /v2/api-keys/{id}` |
| billing | `GET /v2/billing/usage`, `POST /v2/billing/checkout` |

## Run locally

```bash
cd web
cp .env.example .env.local          # point NEXT_PUBLIC_API_BASE_URL at the API
npm install
npm run dev                         # http://localhost:3000
```

The API must be running (`uvicorn recupero.api.app:app`) with the platform env
set: `RECUPERO_PLATFORM_JWT_SECRET` and `RECUPERO_DATABASE_URL` (see
`docs/ENV_VARS.md`). Enable CORS for the web origin on the API when they are on
different hosts.

## Notes / next

- **Session storage** is `localStorage` (simple, XSS-exposed). For production
  harden to an httpOnly cookie set by a Next.js route handler — the `useAuth`
  surface stays the same.
- **Deploy**: `npm run build` → any Node host / Vercel / a container; it's a
  static-ish SPA talking to the API origin, so it scales independently of the
  backend.
- Trace submission sends a deterministic `Idempotency-Key` so a double-submit
  never enqueues (or bills) twice — matches the server's idempotent enqueue.
