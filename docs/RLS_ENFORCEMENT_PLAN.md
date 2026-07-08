# Genuine RLS Enforcement — Design & Staged Rollout

## Status
Design complete; **not yet implemented**. This documents what "make the
platform's Row-Level Security genuinely enforce" actually requires, discovered
while reviewing the multi-tenant layer (037/039/040/042).

## Today's reality (why RLS is currently inert)
- Policies on `org_api_keys`, `usage_events`, `org_invites`, `watched_addresses`,
  `wallet_alerts` gate on `current_setting('app.current_org')`.
- **The app never sets that GUC** (`deps.db_conn` opens a bare connection).
- No table uses `FORCE ROW LEVEL SECURITY`, so the owning DB role bypasses RLS.
- `organizations` and `memberships` have RLS **enabled with no policy**
  (default-deny under a restricted role).
- Net: tenant isolation rests **entirely** on the app's explicit
  `WHERE org_id = %s` (present and tested everywhere). RLS adds nothing today.

## The core constraint: authentication is inherently cross-tenant
RLS scoped by `org_id` cannot gate the lookups that *determine* the org:
- `signup` **creates** the org + owner membership (no org exists yet).
- `login` reads `memberships` **by user** to discover the org.
- `resolve_api_key` reads `org_api_keys` **by key hash** across all orgs.

So a single org-scoped connection cannot both authenticate and enforce.

## Target design: dual-connection model
| Connection | DB role | Used by | RLS |
|---|---|---|---|
| **auth** | service / `BYPASSRLS` | `signup`, `login`, `resolve_api_key` (in `current_principal`) | bypassed |
| **tenant** | restricted (non-owner, `NOBYPASSRLS`) | every post-auth route; GUC set to the principal's org | enforced |
| **worker** | service / `BYPASSRLS` | `investigations` queue drain, cron, admin | bypassed |

Post-auth, `current_principal` sets `SELECT set_config('app.current_org', <org>, true)`
(transaction-local — **required** so a pgbouncer/transaction-pooled backend can't
leak the setting to the next tenant's request).

## Work items
1. **`deps.py`** — add `auth_db_conn` (env `RECUPERO_AUTH_DATABASE_URL`, defaults
   to `RECUPERO_DATABASE_URL` for dev/back-compat). `current_principal` resolves
   the principal via `auth_db_conn`, then sets `app.current_org` on the tenant
   `db_conn`. FastAPI caches `db_conn` per request, so routes reuse the
   GUC-scoped connection.
2. **`router.py`** — `signup` / `login` switch their `Depends(db_conn)` to
   `auth_db_conn` (they run before a principal exists).
3. **migration 043** — for every org-scoped table
   (`organizations` by `id`; `memberships`, `org_api_keys`, `usage_events`,
   `org_invites`, `audit_log`, `watched_addresses`, `wallet_alerts`,
   `investigations` by `org_id`): create the missing `USING` + `WITH CHECK`
   org-isolation policies, then `FORCE ROW LEVEL SECURITY`. `users` stays global
   (no org column, no RLS).
4. **ops** — provision the restricted API role (`GRANT SELECT/INSERT/UPDATE/
   DELETE`, `NOSUPERUSER NOBYPASSRLS`, not the table owner) and point
   `RECUPERO_DATABASE_URL` at it; keep the worker/cron on the service role.
   Document in `PLATFORM_ARCHITECTURE.md` + `infra/`.

## Critical failure mode — stage the rollout
`investigations` is the engine's job queue (`FOR UPDATE SKIP LOCKED`). Under
`FORCE` RLS, a worker whose role is **not** `BYPASSRLS` sees **zero rows and the
trace pipeline silently stalls.** Roll out in order, verifying at each step:
1. Ship the code (GUC wiring + dual conn) with policies added but **before**
   `FORCE` — behaviour is unchanged (owner still bypasses). Deploy, watch.
2. Provision the restricted role; point the API at it in staging. Verify
   signup/login, tenant reads, and cross-tenant denial.
3. **Confirm the worker role has `BYPASSRLS`** and the queue drains.
4. `FORCE` the low-risk tables first (`watched_addresses`, `wallet_alerts`,
   `usage_events`, `org_invites`), then auth tables, then **`investigations`
   last**, watching queue depth after each.

## Proving test (must pass before any `FORCE` in prod)
Throwaway Postgres, two roles (`svc` BYPASSRLS, `app_rw` restricted):
- `signup`/`login` succeed on the auth (svc) connection.
- Org A's tenant connection (GUC=A) sees only A's rows; setting GUC=B sees only
  B's; unset GUC sees none.
- Cross-tenant `UPDATE`/`DELETE`/`SELECT` affect zero of the other org's rows.
- The `svc` role drains `investigations` across all orgs (worker bypass holds).

## Recommendation
Land this as its own reviewed PR with the staged rollout above — **not** folded
into a feature branch. Until then, the app-level `WHERE org_id` scoping is the
enforcing layer (present + covered by tests); RLS is defense-in-depth that is
currently dormant.
