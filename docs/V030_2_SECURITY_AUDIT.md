# v0.30 Round-2 Security Audit — AuthN/AuthZ + Multi-Tenant Isolation

Read-only audit of customer/exchange/operator boundary surfaces. Scope
limits per the audit charter; correctness-bug surface excluded (handled
by `V030_ROUND_N_AUDIT.md`). Cross-checked against `V029_AUDIT_FINDINGS.md`
and `V030_ROUND_N_AUDIT.md` — every finding below is NEW.

## TIER-1 CRITICAL — data leak / privilege escalation

**T1-A. Duplicate migration numbers 015 and 016 — schema-drift bomb.**
`migrations/015_case_tokens_hmac_constraints.sql` vs
`migrations/015_engagement_double_submit_guard.sql`;
`migrations/016_drop_case_tokens_raw_token.sql` vs
`migrations/016_freeze_letters_unique_hardening.sql`. `scripts/apply_migration.py`
has no tracker table — it relies on the operator to apply files in
order. With two `015_*` and two `016_*` files, glob-sorted order is
`015_case_tokens... → 015_engagement... → 016_drop... → 016_freeze...`,
but a different sort key on a fresh deploy machine (locale, FS), or an
operator who only re-runs "the failing one", will land production with
ONE of each pair applied. The `015_case_tokens_hmac_constraints` ALTER
COLUMN token_hmac SET NOT NULL is gated on the HMAC backfill being
complete — if the wrong 015 is applied first, the constraint hits a
NULL row and rolls back, while `engagement_signatures_one_per_investigation_idx`
silently never lands. The visible consequence is that the engagement
double-submit guard described as "defense-in-depth" in
`portal/server.py:1019-1023` is missing in prod and the lock-then-check
in `_persist_signature` becomes the only barrier. **Fix:** rename
to 015a/015b/017/018 and add a `schema_migrations` tracker table that
records applied filenames; reject re-runs on partial application.

**T1-B. `RECUPERO_TOKEN_PEPPER` rotation silently locks out every
victim with no recovery path mapped.** `src/recupero/portal/tokens.py:122-133,
:224-261`. `verify_token` HMACs the candidate with the active pepper
and looks up by `token_hmac`. Rotating the pepper makes every previously-
issued URL return "link unavailable" (404 shape). The
`V030_ROUND_N_AUDIT.md` already flagged the symptom; the security gap
is that **there is no operator runbook + no DB column recording WHICH
pepper minted a given row**. The active pepper is whatever
`_token_pepper()` returns at request time; the row stores only the
output of `HMAC(pepper, raw_token)`. After a rotation the operator
cannot enumerate "affected victims" (because the hash space is the
permutation of the OLD pepper, not the new one), cannot re-issue
targeted replacements, and cannot tell the difference between
"rotated-out" and "revoked". The "case_tokens.label" column is the
only free-text breadcrumb. **Fix:** add a `pepper_id` column populated
at INSERT-time from a per-pepper short identifier (4-byte hash of the
pepper, stored separately in env as `RECUPERO_TOKEN_PEPPER_ID`); on
rotation, operators can `SELECT case_id FROM case_tokens WHERE
pepper_id = $OLD_ID AND revoked_at IS NULL` to enumerate affected
cases and re-issue.

**T1-C. `_intake_rl_state` rate-limit is process-local and bypassed
on Railway redeploys + multi-replica auto-scale.** `api/app.py:1089,
:1266-1287`. The /v1/intake POST gate (5/min/IP) is a module-global
dict that resets on every cold-start. Railway redeploys (the project's
`memory/MEMORY.md` notes auto-deploys from `main`) flush the dict, so
a bot can hit the form, force a redeploy via any minor change, and
re-flood. More important: nothing in `_intake_rl_check` is keyed on
the case-creation side-effect — the same IP rate-limit is the ONLY
barrier between an unauthenticated POST and a `public.cases` insert
that lands an operator-visible row with attacker-controlled
`client_email`, `client_name`, `description`. An attacker who chains
through 1000 residential proxies (the typical $50/mo botnet) creates
1000 cases per minute steady-state. Operators triaging by date will
either spam-filter real victims OR triage 1000 spam rows daily.
**Fix:** (1) move the budget to a Postgres advisory-lock-keyed
counter table (`intake_rate_state(ip, window_start, count)` with a
UNIQUE on `(ip, window_start)`); (2) ADD a per-`client_email`
secondary gate (1 case per email per hour) — the email is already in
the form and is harder to rotate than IPs.

## TIER-2 HIGH — meaningful weakening of the security posture

**T2-A. `_intake_post_csrf_ok` accepts non-browser callers by
default — bypassing CSRF.** `api/app.py:1180-1181`. The function
returns `True` when both `Origin` and `Referer` are absent ("Non-
browser caller — no Origin, no Referer. Treated as safe; curl/postman
/server-side integrations."). But a malicious browser-side fetch
launched via `fetch(url, {mode: 'no-cors', credentials: 'omit'})`
intentionally suppresses `Origin` on POST — modern browsers DO send
Origin on cross-origin POSTs even in no-cors mode, but `Referrer-Policy:
no-referrer` set on the attacker's page strips Referer, and some old
mobile browsers omit Origin under no-cors. The `RECUPERO_INTAKE_
ALLOWED_ORIGINS` allow-list at line 1183-1185 is unset by default,
which falls back to the host-equality check — which itself returns
True when origin is empty (line 1195-1203). Net effect: a CSRF attack
that suppresses both headers gets through. **Fix:** when `Origin` is
empty AND the request is a POST AND the User-Agent looks like a
browser (e.g. contains "Mozilla"), reject. Documented non-browser
callers (operator scripts, tests) use the recupero-ops CLI directly,
not curl-against-/v1/intake.

**T2-B. `/v1/correlations/{address}` leaks cross-case correlation
data with only a generic API key — no per-key case scoping.**
`api/app.py:281-363`. The endpoint runs `lookup_correlations([address])`
against `public.cases / .investigations / .freeze_letters_sent`
joined data, and returns `total_prior_cases`, `prior_total_usd_flowed`,
`prior_roles_seen`. Any key in `RECUPERO_API_KEYS` (issuer / screening
partner / OSINT user) gets the SAME correlation visibility. An
exchange compliance team allow-listed for screening their own
customers can query an address from a competing exchange and learn
"this address was in 3 prior Recupero cases, $14M flowed." This
breaks the multi-tenant promise even though the rows are aggregated.
The `_is_api_key_authorized_for_case` gate (api/app.py:1092-1149)
exists for /v1/freeze-outcomes — `/v1/correlations` was missed.
**Fix:** add a `RECUPERO_API_KEY_CORRELATIONS=key_name,key2`
allow-list, deny-by-default; or restrict to admin keys only and
require an explicit operator opt-in per partner.

**T2-C. Webhook secrets stored plaintext in
`monitoring_subscriptions.webhook_secret`.** `api/monitoring_api.py:530,
:539, :548-558`. The partner-supplied HMAC secret is `INSERT … VALUES
(%(secret)s, …)` and `UPDATE … webhook_secret = EXCLUDED.webhook_secret`
into a TEXT column with no encryption-at-rest hook. An operator
running `SELECT webhook_secret FROM monitoring_subscriptions` from
psql (or anyone with read-only Supabase access) sees every partner's
HMAC key in cleartext, defeating the entire point of the partner
being able to verify our callbacks. Same shape as the v0.16.12
case_tokens raw-token fix that's already been done (migrations 014→016).
**Fix:** store HMAC-of-secret in DB; keep the raw secret only in
memory for the duration of the worker's claim cycle and pass it
through to the dispatcher via a secret-resolver function that reads
from a vault (or, minimum, `pgp_sym_encrypt` with a server-side key
in `RECUPERO_WEBHOOK_SECRET_KEK`).

**T2-D. `freeze_letters_sent` + `freeze_outcomes` have no tenant
scoping at the row level — single SQL injection compromises all
exchanges' freeze history.** `migrations/013_freeze_outcomes.sql:24-68`.
Schema has `case_id`, `issuer`, `target_address`, `chain` but no
`api_key_owner` / `partner_id`. The `is_authorized_to_record_outcome`
check at `api/auth.py:207-229` is an APPLICATION-LAYER gate. There
are zero Postgres RLS policies in the entire migrations directory
(verified: `grep -i "row.level.security\|policy"` returns zero
hits across `migrations/*.sql`). Any future SQL-injection in the
correlation/screening/dashboard code path bypasses every multi-
tenant guard — the DB layer cannot reject a cross-tenant read.
**Fix:** add an `api_key_owner TEXT` column (or `tenant_id UUID`)
to `freeze_outcomes`, `freeze_letters_sent`, `monitoring_subscriptions`
+ a `payments` `created_by` column. Then `ALTER TABLE … ENABLE ROW
LEVEL SECURITY` + a per-tenant SELECT/INSERT policy keyed on a
session-set `app.current_api_key_name`. The application can set
that GUC at connection-borrow time.

## TIER-3 MEDIUM — hardening

**T3-A. `engagement_signatures.user_agent` stored unredacted —
PII leak in operator views.** `portal/server.py:623, :1077`. The
UA string is stripped of CR/LF/control chars but otherwise stored
verbatim, including any auto-injected `X-Forwarded-User` / company-
identifier headers some corporate proxies bake into UA. Operator
dashboards that render this field can leak the victim's employer
(e.g., `Mozilla/5.0 ... Acme Corp Browser/1.0`). **Fix:** truncate
to the first parenthesized clause; strip patterns matching
`/[A-Z][a-z]+ Corp(oration)?/`.

**T3-B. `_resolve_health_bind_host` defaults to `0.0.0.0` whenever
`PORT` is set, exposing `/metrics` un-authenticated to any Railway
sibling service.** `worker/_health_server.py:54-60, :140-147`. `/metrics`
is documented as "operators expect /metrics to be scrapable without
auth (it's the Prometheus convention and the payload carries no
PII)." But the metrics include per-case counters (`recupero_cases_
total`, etc. — see `observability/metrics.py`); under sustained
multi-tenant scale these become a side-channel for "is competing
exchange X submitting cases?" via counter inflection. **Fix:**
when `PORT` is set, bind metrics+healthz to 0.0.0.0 (Railway needs
this) but gate `/metrics` behind a separate `RECUPERO_METRICS_KEY`
header — same pattern as `/dashboard.json`.

**T3-C. Stripe-event payload persisted raw in `public.payments.raw_event`
JSONB.** `payments/dispatcher.py:138-152`. The `event.payload` blob
contains `customer_details.email`, `customer_details.name`,
`customer_details.address`, `payment_method_details.card.last4` per
the Stripe Checkout schema. Verbatim INSERT into JSONB. The same
gap was flagged by `V030_ROUND_N_AUDIT.md` T3-E for the `notes_jsonb`
column — this is the broader `raw_event` column on the same table,
also unredacted. **Fix:** before insert, walk the payload dict and
strip `customer_details.{email,name,phone,address}`,
`payment_method_details`, `billing_details`, retaining only fields
the dispatcher reads back.

**T3-D. `api/app.py:_load_api_keys` keyed by SECRET — env-var dump
in a heap snapshot reveals every key in one read.** `api/auth.py:91-97`.
The map is `{secret: name}`, populated from `RECUPERO_API_KEYS` and
cached in module-globals. A worker-process core dump (Sentry's
`with_locals=True`, Python `faulthandler`, gdb attach) gives the
attacker the full key inventory. The `_keys_cache` value lives
forever in the process. **Fix:** keep only `{hmac(secret): name}`
in the cached map; recompute the HMAC at request time. Doubles
the constant-time-compare cost but bounds heap-dump exposure.

## Surfaces examined with NO findings

- `src/recupero/payments/webhook.py` Stripe signature verification —
  signature header parsed + size-capped (8KB header, 256KB body),
  v1 entries capped at 5, hex-validated + length-equals-64 before
  hmac.compare_digest, replay tolerance 300s. Closed-loop verified.
- `src/recupero/api/monitoring_api.py` SSRF defense — strict
  `ipaddress.ip_address` + `socket.inet_aton` libc-fallback path
  + DNS-rebinding check at dispatch, https-only enforced, allowlist
  env opt-out only. No bypass surface found.
- `src/recupero/portal/server.py` CSRF + token-rotation flow — Origin
  check anchored to `RECUPERO_PORTAL_PUBLIC_ORIGIN` (localhost
  fallback gated), token rotated on successful /sign POST,
  closed-engagement replay blocked, artifact filename whitelist
  + `_safe_bucket_filename` regex rejects path traversal. Cross-
  case enumeration (substituting another token in URL) requires
  guessing 32 bytes of `secrets.token_urlsafe` — infeasible.
- `src/recupero/storage/case_store.py::_validate_case_id` — Windows
  reserved-name + trailing-dot/space rejection + control-char +
  resolved-path containment is comprehensive. Symlink rejection
  at both lstat and resolved-parent layers closes the cross-case
  symlink escape.
- `src/recupero/storage/supabase_case_store.py::_validate_relpath`
  + `_DOWNLOAD_HARD_CAP_BYTES` + `_LIST_MAX_PAGES` + `_WALK_MAX_DEPTH`
  — every external-data-sink boundary is bounded; investigation_id
  UUID gate + base-path concatenation safe.
- `src/recupero/observability/sentry.py::_before_send` — `_redact_in_place`
  walks the event dict + breadcrumbs and applies the
  `logging_setup._redact` patterns to DSN/secret strings before
  upload. `send_default_pii=False`. Tag values sanitized for
  CR/LF/NUL/bidi.
- `src/recupero/worker/_health_server.py` `/investigations` +
  `/dashboard.json` admin gate — `X-Recupero-Admin-Key` header
  only (query-param removed v0.16.7), `hmac.compare_digest`,
  fail-closed when env unset.
- `src/recupero/api/app.py::_is_api_key_authorized_for_case` — the
  S-1 case-scope gate is correctly indistinguishable-from-404 on
  denial, matching the LetterNotFoundError shape.
- `src/recupero/portal/intake.py::create_case_from_intake` — 3-retry
  UniqueViolation loop on case_number; case_number prefix is 8-hex
  per year (birthday-safe to ~100k).
