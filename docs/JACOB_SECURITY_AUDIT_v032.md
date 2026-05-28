# JACOB-style security audit — Recupero v0.32.0

**Audit window:** 2026-05-27 → 2026-05-28
**Branch / HEAD:** `pdf-deliverables` (working tree on top of main `7613281`)
**Surface in scope:** v0.32 additions — review API, label-candidates API,
cron HA + webhook, recovery-disclosure portal, per-case budget tracker.
**Stance:** brutal. The goal is to find holes before a pentester
(Trail of Bits, NCC, h1 triage) does. Findings are ranked by exploitability
and blast radius, not by how embarrassing they are to fix.

---

## TL;DR

| Severity | Count |
| -------- | ----- |
| CRIT     | 2 |
| HIGH     | 5 |
| MED      | 6 |
| LOW      | 5 |

**Top exploitable holes (worst → least):**

1. **CRIT-1** — Label-promote endpoint writes attacker-controlled JSON to
   version-controlled seeds via `_append_to_seed_file` with NO address-shape,
   chain-allow-list, or name-charset validation. Admin-key compromise →
   inject `{"address": "0xLegitCoinbase…", "category": "mixer"}` → next
   day's freeze letters mis-target Coinbase as a mixer.
2. **CRIT-2** — Cron error-webhook redactor `_safe_error_text`
   (`worker/cron_scheduler.py:334-364`) only redacts `api[_-]?key|token|
   secret|password|bearer`. It MISSES every named API-key env-var that
   doesn't contain the substring "key/token/secret/password/bearer" —
   `RESEND_API_KEY=...`, `STRIPE_SECRET=...`, `SUPABASE_SERVICE_ROLE_KEY=...`
   when surfaced as raw value WITHOUT the `KEY=` prefix (e.g. embedded in a
   stack-trace `f"failed to call {sk_live_xxxxx}"`). Any cron exception that
   pickles up a bare key value is shipped to Slack/Discord/etc.
3. **HIGH-1** — Auto-ingest follows HTTP redirects implicitly. `httpx`
   default is `follow_redirects=False`, so this is mostly fine, BUT the
   `_safe_http_get_json` runs against operator-influenceable URLs
   (DeFiLlama, Tronscan, Solscan, Etherscan) with no IP-allow-list, no
   private-IP block, no scheme check. A DNS-rebinding or cache-poisoning
   attack against any of the four upstreams could pivot a Recupero cron
   into an SSRF probe of the Railway internal network.
4. **HIGH-2** — Review-API `_require_admin_auth` calls `.strip()` on the
   provided header before `hmac.compare_digest`. Empty / whitespace are
   correctly rejected, BUT compare_digest now operates on stripped bytes,
   meaning a leaked-key fingerprint test (e.g. WAF / log greps) that looks
   for the EXACT secret won't match `" SECRET\t"`. This is the symmetric
   issue the v0.20.2 audit closed on `require_api_key` — and the new
   admin-key path silently regressed it.
5. **HIGH-3** — `_intake_post_csrf_ok` is bypassed by any request with
   NO Origin AND NO Referer header (line 1207-1208). Curl-from-anywhere
   sails through. A bot that strips both headers (every HTTP client other
   than a browser) creates as many `cases` rows as the IP rate-limit
   permits (5/min/IP, but bots rotate IPs).

---

## 1. Threat model per surface

### 1.1 Review API (`src/recupero/dispatcher/review_api.py`)

| Asset | Attacker goal |
| ----- | ------------- |
| `RECUPERO_ADMIN_KEY` | Approve / override mandatory-review gate; ship false brief |
| `brief_reviews` rows | Tamper with case-history audit trail |
| `reviewer_email` field | Plant attribution for malicious approvals |

**Threat surface:**
- Single shared `X-Recupero-Admin-Key` for ALL admin operations
  (reviews, labels, /dashboard.json, /investigations). Single point of
  failure — if it leaks ONCE, the attacker can approve every pending
  brief AND promote arbitrary labels AND read every investigation row.
- No 2FA / per-action approval. No audit channel writes elsewhere — the
  only record of an override is the `brief_reviews.override_reason`
  field, which the same admin key can rewrite via a new UPDATE call.
- No rate limit. Brute-forcing the admin key against `_require_admin_auth`
  is constant-time-resistant (`hmac.compare_digest`) — assuming the key
  is high-entropy. But: nothing in the codebase enforces minimum entropy
  on the env var.

### 1.2 Labels API (`src/recupero/labels/api.py` + `auto_ingest.py`)

| Asset | Attacker goal |
| ----- | ------------- |
| `bridges.json` / `cex_deposits.json` (committed to repo) | Inject false labels |
| `label_candidates` row | Plant rejected-then-promoted addresses |

**Threat surface — promote path:**
1. Operator (or attacker with admin key) calls
   `POST /v1/labels/candidates/{id}/promote`.
2. `auto_ingest.promote_candidate` reads the row.
3. `_append_to_seed_file` appends entry to bridges.json / cex_deposits.json.
4. Worker reloads seeds at next boot.
5. Briefs now use the planted label.

**Defects:**
- **CRIT-1** — `_append_to_seed_file` does NO address-shape validation,
  NO chain-membership check, NO name-content sanitization. The
  `proposed_name` traverses from upstream tag → DB → seed file unmodified
  (modulo a `[:200]` slice). An attacker who plants a candidate row OR
  controls upstream tags can land arbitrary content in a version-controlled
  JSON file.
- The promotion runs even when the candidate row has transitioned out of
  `pending_review` between read and write (race window between
  `_read_candidate` and the UPDATE on line 580-591). Promotion logs a
  WARN but does NOT roll back the seed-file append. Two-promoter race →
  two duplicate appended entries, the JSON list now grows unboundedly.
- Seed-file path is `Path(__file__).parent / "seeds" / seed_file`. The
  `seed_file` is hardcoded from a static dict, so path-traversal is not
  directly exploitable here — but ANY future change that maps the file
  from a DB column or user input becomes one. Worth a defense-in-depth
  realpath check.

**Threat surface — ingest path:**
- Sources: DeFiLlama, Tronscan, Solscan, Etherscan.
- All fetched via `httpx.Client(timeout=10)` with default settings.
- No allowed-host check after redirect (httpx default
  `follow_redirects=False`, so OK by default — but operator can opt in
  globally via env, and there's no guard against that).
- No JSON-schema validation on the response shape — relies on `isinstance`
  checks on each field. An upstream that returns a Python eval-able
  string (e.g., `__class__`) won't break us because we never `eval`, but
  the `raw_metadata` is JSON-encoded directly into Postgres `jsonb`,
  carrying through arbitrary attacker-controlled data into the audit
  trail.
- `_safe_http_get_json` swallows ALL exceptions. A persistent SSL-failure
  upstream looks identical to "no new labels today" — no alerting on
  silent ingest failure.

### 1.3 Cron scheduler (`src/recupero/worker/cron_scheduler.py`)

| Asset | Attacker goal |
| ----- | ------------- |
| `RECUPERO_CRON_ALERT_WEBHOOK_URL` value | SSRF, log-poisoning, secret-exfil |
| `cron_jobs_lock` row | Sit on the lock indefinitely, suppress alerts |

**Defects:**
- **CRIT-2** — `_safe_error_text` regex `(api[_-]?key|token|secret|password|bearer)[=:\s]+\S+`
  only matches when the secret has a labeled prefix. The `RESEND_API_KEY`
  value embedded in a stack frame like `httpx.RequestError("re_xxxx")`
  carries through unredacted. The DSN-redaction part is OK, but only for
  `postgres(?:ql)?://`; `redis://`, `mongodb+srv://`, `mysql://`,
  `amqp://`, `https://user:pass@host` are NOT covered.
- **HIGH-4** — Webhook URL is unvalidated. An operator typo
  `RECUPERO_CRON_ALERT_WEBHOOK_URL=http://169.254.169.254/...` would
  POST the entire error payload to AWS metadata (or Railway's internal
  metadata service), leaking everything in the payload to whoever can
  observe Railway egress. No scheme allow-list (http vs https), no
  private-IP rejection.
- **MED-1** — `_resolve_leader_id` trusts `HOSTNAME` and
  `RAILWAY_REPLICA_ID` env vars verbatim. An attacker with code-exec on
  one cron replica can rewrite their leader_id to spoof another replica
  and steal locks (this is "post-compromise" so MED, but the
  `consecutive_failures` accounting depends on stable IDs).
- **MED-2** — The lock-acquire fail-CLOSED path (line 263-267) returns
  False on ANY DB error. A persistent DB connectivity blip would silently
  skip every cron job indefinitely, and the alerting webhook ALSO needs
  the DB to record the failure count (`_record_job_failure`). Result:
  cron stops working AND no alert fires.

### 1.4 Recovery-rate disclosure (`src/recupero/monitoring/recovery_rate.py`)

| Asset | Attacker goal |
| ----- | ------------- |
| `recovery_disclosures` row | Suppress legal audit trail |
| Rendered Wilson CI text | XSS in intake form |

**Defects:**
- **MED-3** — The 60-second cache (`_CACHE_TTL_SECONDS = 60.0`) is keyed
  by DSN. If an attacker can write to `freeze_outcomes` (via the
  authenticated `/v1/freeze-outcomes` endpoint, which uses
  per-API-key authorization), they can inflate `n_full_recovery` and
  the next intake form shows an inflated rate. Window of effect: until
  the operator notices. Mitigation: outcome-intake is per-issuer
  scoped, so the attack requires partner-key compromise.
- **LOW-1** — Cache is process-local and never invalidated on operator
  case-close. A customer who pays at 12:00 sees the 11:59 rate (cached
  for up to 60s). For a fraud disclosure this is OK; just noted.
- **LOW-2** — XSS surface in `intake.html.j2:243`: the Wilson CI floats
  are formatted via `"%.0f"|format(...)`. Jinja autoescape is on
  (`select_autoescape(["html","j2"])`), the Decimal is coerced through
  `float()` in `log_disclosure`, and the renderer NEVER puts user
  input into the disclosure block. Verified clean. Documenting as
  "checked".

### 1.5 Intake POST (`src/recupero/api/app.py`)

**Defects:**
- **HIGH-3** — `_intake_post_csrf_ok` returns True when BOTH Origin AND
  Referer are absent (line 1207-1208). A bot using requests/curl with
  no headers passes the CSRF gate. The IP rate-limit (5/min) bounds this
  but doesn't eliminate it. Recommendation: require at least one of
  Origin/Referer in production mode (env-gated).
- **MED-4** — `acknowledge_disclosure != "yes"` check is exact-string,
  but the comparison is case-sensitive AND requires NO whitespace
  trim. A form-encoded `acknowledge_disclosure=Yes` or
  `acknowledge_disclosure=yes%20` fails the gate, which is good. But
  if the customer's browser sends `yes\n` (some old IE behaviors),
  legitimate submissions fail. Bigger concern: `log_disclosure` is
  called AFTER the case is created but failure is swallowed — a DB-
  unreachable moment between case-create and disclosure-write leaves
  the `cases` row WITHOUT a `recovery_disclosures` row, which is the
  exact legal-audit gap the feature was meant to close.
- **LOW-3** — `_intake_rl_check` uses `time.time()` (wall clock), not
  `time.monotonic()`. NTP corrections could let an attacker briefly
  bypass the rate limit.

### 1.6 API budget (`src/recupero/observability/api_budget.py`)

**Defects:**
- **MED-5** — `_COST_MODEL` is hardcoded. CoinGecko raises Pro tier from
  $129/mo to $300/mo (real-world example from Q3 2025) and Recupero
  silently keeps charging $0.00026 to its budget tracker, burning the
  real budget while showing 50% utilization.
- **LOW-4** — `record()` raises BudgetExceededError inside the lock
  (line 287-299). The lock is released as the function unwinds, but
  the snapshot is captured INSIDE the lock — correct. Documenting for
  posterity.

### 1.7 /cron/healthz on `_health_server.py`

**Defects:**
- **HIGH-5** — `/cron/healthz` (line 140-165) is UNAUTHENTICATED. The
  payload includes `last_error_message` from `cron_jobs_lock`, which
  is the output of `_safe_error_text` — i.e., whatever leaked through
  the redactor in CRIT-2. An attacker hitting `/cron/healthz` from
  the internet sees ANY secrets that escaped redaction. Bind-host
  defaults to 0.0.0.0 when PORT is set (`_resolve_health_bind_host`
  line 58-60), which on Railway means the whole internet.
- **MED-6** — The health server's `_Handler.do_POST` accepts
  `/portal/...` and `/webhooks/stripe`. No CSRF gate on /portal POSTs
  (mitigated by token-in-URL). No rate-limit on the portal POST.

### 1.8 Cross-cutting

- **LOW-5** — Pydantic `_validate_email` checks only for `@` literal.
  `reviewer_email="@@@"` passes. Acceptable for an admin-only API where
  the email is for log attribution, not for sending — but it's worth a
  comment so future maintainers don't push email-validation logic onto
  this gate.

---

## 2. OWASP Top 10 mapping

| OWASP | Status |
| ----- | ------ |
| A01 Broken Access Control | HIGH-2 (admin-key stripping), HIGH-5 (cron/healthz unauth) |
| A02 Cryptographic Failures | Webhook is plaintext HTTP if operator misconfigures. CRIT-2 |
| A03 Injection | SQL is parametrized throughout. CRIT-1 is JSON-injection on seed file. |
| A04 Insecure Design | HIGH-3 (CSRF bypass via no headers). MED-4 (audit-row best-effort). |
| A05 Security Misconfiguration | _safe_error_text default coverage too narrow (CRIT-2). |
| A06 Vulnerable Components | httpx >= 0.27.0 / fastapi >= 0.104 in pyproject — current. No CVE matches as of 2026-05. |
| A07 Authentication Failures | Single shared admin key for ALL admin surfaces. No 2FA, no rotation policy. |
| A08 Software/Data Integrity | Review-gate SHA-256 pin is solid (collision impractical). Seed-file append-only — no integrity check on existing entries. |
| A09 Logging/Monitoring | Webhook failure is logged but NEVER paged. If Slack itself is down, alerts are silently lost. |
| A10 SSRF | HIGH-1 (auto-ingest fetches), HIGH-4 (webhook URL unvalidated). |

---

## 3. Secrets-handling audit

| Path | DSN redacted? | API-key redacted? | JWT redacted? |
| ---- | ------------- | ----------------- | ------------- |
| `_common.db_connect` exception path | YES (via `_DSN_REDACT_RE`) | NO | NO |
| `cron_scheduler._safe_error_text` | YES (only postgres://) | PARTIAL (only `api_key=` prefix) | NO |
| `webhook payload` | YES (via `_safe_error_text`) | PARTIAL | NO |
| `/cron/healthz` payload | depends on `_safe_error_text` | PARTIAL | NO |

**Gaps:**
- No `redis://`, `mongodb+srv://`, `amqp://`, `mysql://` redaction.
- No bare-token detection (a 32-char base64 substring with no labeling
  prefix walks through).
- No JWT detection (`eyJ...` is a common giveaway).
- Test fixtures: spot-checked `tests/`, no obvious real-looking secrets
  in source-controlled files. Adversarial input fixtures use
  `0xdeadbeef`-style placeholders.

---

## 4. Fix sketches

### CRIT-1 — label-promote injection
1. In `auto_ingest.promote_candidate`, validate `row["address"]` against
   a per-chain shape regex BEFORE calling `_append_to_seed_file`. Add
   the same `_TEXT_TROJAN_CHARS` reject set used by
   `portal/intake._reject_unicode_trojans` to `proposed_name`.
2. Compute a `realpath` for `seed_path` and assert it is contained in
   `_SEEDS_DIR.resolve()`.
3. Add a unit test that a promoted candidate with a malformed address
   raises a `ValueError` BEFORE any disk write happens.

### CRIT-2 — webhook redaction coverage
1. Replace the regex in `_safe_error_text` with a multi-pattern
   approach:
   - `postgres(?:ql)?|redis|mongodb(?:\+srv)?|amqp|mysql|https?://[^:/@\s]+:[^@\s]+@` → redact creds in any URI.
   - Greedy match: `eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}` (JWT) → `<jwt>`.
   - `sk_live_[A-Za-z0-9]{20,}`, `sk_test_[A-Za-z0-9]{20,}`, `pk_live_…` (Stripe) → redact.
   - `re_[A-Za-z0-9]{20,}` (Resend) → redact.
   - `AKIA[0-9A-Z]{16}` / `ASIA[0-9A-Z]{16}` (AWS access key ID) → redact.
   - `[A-Za-z0-9_\-]{40,}` (catch-all generic high-entropy ID) — opt-in via env, may over-redact.
2. Add a unit test for each of the above patterns ending up in an
   exception text passed through `_safe_error_text`.

### HIGH-1 — Auto-ingest SSRF defense
1. Add `_ALLOWED_HOSTS = {"api.llama.fi", "apilist.tronscanapi.com",
   "public-api.solscan.io", "api.etherscan.io"}` and assert
   `urlsplit(url).hostname in _ALLOWED_HOSTS` in `_safe_http_get_json`.
2. Use `httpx.Client(follow_redirects=False)` explicitly.
3. Reject `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
   `169.254.0.0/16`, `::1/128`, `fc00::/7` via `ipaddress.ip_address`
   after DNS resolve (TOCTOU window remains, but the bar is high).

### HIGH-2 — Admin-key strip
Remove the `.strip()` calls on the inbound header in
`review_api._require_admin_auth` and `labels/api._require_admin_auth`.
Keep `.strip()` on the EXPECTED key (so trailing newline in `.env` files
doesn't break auth). Mirrors the v0.20.2 fix.

### HIGH-3 — CSRF on intake
Add an env-gated production-mode check: when `RAILWAY_ENVIRONMENT=production`
(or similar), require AT LEAST ONE of Origin/Referer to be present.

### HIGH-4 — Webhook URL validation
At server boot, parse `RECUPERO_CRON_ALERT_WEBHOOK_URL` and:
- Reject non-https schemes outside local-dev.
- Reject private/loopback/link-local IPs after DNS resolve.
- Log the parsed hostname so operators can confirm it.

### HIGH-5 — /cron/healthz unauth
Either:
- Lock /cron/healthz behind admin key (require the same
  `X-Recupero-Admin-Key`); accept the trade-off that external uptime
  monitors need a shared secret.
- OR strip `last_error_message` from the public payload (return
  `last_success_utc`, `consecutive_failures`, `status`, but NOT the
  redacted error text — defense in depth: even a partial redactor leak
  is contained).

### MED-1..5
- MED-1: Hash `leader_id` with a server-side salt before comparison.
- MED-2: Add a second-channel alert (e.g., a stdout marker that the
  log-shipping pipeline pages on) when lock-acquire fails for >5min.
- MED-3: Add an outlier-rejection on `compute_recovery_stats` —
  reject any single-day inflation >2× the 7-day rolling rate before
  publishing.
- MED-4: Open a transaction wrapping case-create + disclosure-write so
  either both land or neither does.
- MED-5: Quarterly cron job that fetches each provider's pricing page
  and warns if the cost-per-call estimate is off by >2×.

---

## 5. Honest assessment — would Recupero survive a Trail of Bits pentest today?

**No.** A Trail of Bits engagement (5-day scoped pen test) would land
CRIT-1 and CRIT-2 in the executive summary on day 1. The label-promote
injection is the kind of finding that ends up on a public blog post six
weeks later — "How we made Recupero send freeze letters against
Coinbase" — and the webhook-redactor gap is the kind of finding that
auditors love because it's a one-line regex fix that nobody had a unit
test for. HIGH-1 (SSRF in auto-ingest) and HIGH-5 (cron/healthz public)
together give the auditor a clean post-exploitation chain: SSRF →
Railway metadata → environment dump → admin key → label injection.

The v0.31.x cycles closed the obvious holes (path-traversal, XXE,
DSN-in-error-message, Windows junctions). v0.32 introduces a NEW class
of risk: admin endpoints that WRITE to version-controlled state
(seed files) and external integrations that PULL from untrusted sources.
The right next move is a dedicated v0.32.1 "admin-key surface hardening"
pass — CRIT-1, CRIT-2, HIGH-1..5 are all 1–2 hour fixes individually,
and the whole batch is shippable in a day.

**Recommended go/no-go for paying customers:**
- CRIT-1, CRIT-2 must close before the first non-friend-of-the-team
  customer pays.
- HIGH-1..5 must close before a public bug-bounty surface opens.
- MED-1..6 + LOW-1..5 are acceptable backlog items for v0.33.

— end of audit —
