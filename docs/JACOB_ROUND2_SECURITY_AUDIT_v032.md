# JACOB-style security audit — round 2, post v0.32.1 — Recupero

**Audit window:** 2026-05-28
**Branch / HEAD:** `pdf-deliverables` @ `e0ce7d8`
**Scope:** verify round-1 close-outs from
`docs/JACOB_SECURITY_AUDIT_v032.md` and audit the NEW attack surface
introduced by v0.32.1 (commit `bb6d350`):
`cron_admin_api.py`, `per_case_randomization.py`,
`multi_source_confirm.py`, `safe_ownership_detector.py`,
`review_gate.html`, intake CSRF gate, vendor-key redactor expansion.
**Stance:** brutal. Read-only.

---

## TL;DR

| Severity | Count | vs round-1 |
| -------- | ----- | ---------- |
| CRIT     | 2 | (round-1: 2) |
| HIGH     | 4 | (round-1: 5) |
| MED      | 6 | (round-1: 6) |
| LOW      | 5 | (round-1: 5) |

**Round-1 close-out scorecard** (claimed in commit `bb6d350`):

| Round-1 finding | Status | Verdict |
| --- | --- | --- |
| CRIT-1 label-promote JSON injection | **PARTIAL** | Validator + confirm-hash function exist (`auto_ingest.py:115-225`), but the `confirm_sha256` kwarg is **never wired into the API layer** (`labels/api.py:86-109` — `PromoteRequest` has no header / field for it), AND the multi-source-confirm gate (`multi_source_confirm.py`) is **dead code, not called from `promote_candidate`**. Static field validation closed; defense-in-depth half-built. |
| CRIT-2 cron `_safe_error_text` coverage | **CLOSED** | `cron_scheduler.py:350-452` adds URI-scheme expansion, JWT, Slack webhook URLs, 16 vendor-prefix patterns, and a generic 32+ char high-entropy catcher with UUID / 0x-address allow-list. Solid. |
| HIGH-1 auto-ingest SSRF | **NOT CLOSED** | `auto_ingest._safe_http_get_json` (`auto_ingest.py:321-342`) is **unchanged from round-1**: no host allow-list, no scheme check, no private-IP block, no `follow_redirects=False`, no body cap. The new test file `test_v032_1_security_fixes.py:354-419` imports `_ssrf_validate_url` which does not exist — **tests will ImportError**. **Regression: this is the headline claim of v0.32.1**. |
| HIGH-2 admin-key `.strip()` regression | **CLOSED** | `review_api._require_admin_auth:64`, `labels/api._require_admin_auth:64`, `cron_admin_api._require_admin_auth:61` all call `hmac.compare_digest(provided, expected)` against the **raw** header. The `.strip()` is only used for emptiness check (line 59 / 56), not in the comparison. |
| HIGH-3 intake CSRF headerless bypass | **CLOSED** | `api/app.py:1214-1219` now rejects POSTs with neither Origin nor Referer unless `RECUPERO_INTAKE_ALLOW_HEADERLESS` opts in. |
| HIGH-5 `/cron/healthz` leaks `last_error_message` | **PARTIAL** | Public payload (`cron_scheduler.build_cron_healthz_payload:631-641`) correctly OMITS the field. BUT the admin-gated replacement `/v1/cron/jobs` (`cron_admin_api.py`) **calls `build_cron_healthz_payload(include_error_message=True)` which is NOT a parameter the function accepts** — it will `TypeError` at runtime. AND the router is **not registered** with the FastAPI app (`api/app.py:75-107` includes only review + labels routers). The admin endpoint returns 404 in production. Public leak is closed; admin replacement is broken. |

**Verdict on v0.32.1 close-out:** ~55% real, ~45% claimed-but-broken.
The headline SSRF and admin-cron-jobs fixes are both effectively
no-ops because they shipped without the wiring that backs them.

**Top exploitable holes (worst → least):**

1. **CRIT-3 (new)** — `cron_admin_api.router` is never registered;
   `build_cron_healthz_payload(include_error_message=True)` will
   `TypeError`. Net effect: `/v1/cron/jobs` returns 404, operators
   have NO way to see redacted error text after the v0.32.1 split,
   and the test suite is dead on arrival.
2. **CRIT-1 (carried forward)** — Confirm-hash pin and multi-source
   gate exist as DEAD CODE. The promote endpoint accepts a candidate
   ID and writes to the seed file without ever calling
   `_compute_promote_confirm_sha256` (no header) or
   `requires_multi_source_confirm`. Single-key compromise still
   ships a labeled "Coinbase Hot Wallet" entry for an attacker EOA.
3. **HIGH-1 (carried forward)** — `_safe_http_get_json` SSRF defense
   is documented in the audit doc and tested in the test file but
   **never implemented in the source**. Trail of Bits would find this
   in five minutes.
4. **HIGH-6 (new)** — `RECUPERO_RANDOMIZATION_SECRET` accepts any
   non-empty string. `"x"` (1 byte, ~3 bits of entropy) passes the
   check; the HMAC keyspace collapses to a coin flip. No minimum
   length / entropy gate.
5. **HIGH-7 (new)** — multi-source-confirm module exists but is not
   wired into `promote_candidate`. The audit's M-1 mitigation is
   text-only; the seed-file write path is unchanged.

---

## 1. Round-1 close-out verification

### 1.1 CRIT-1 — Label-promote JSON injection — PARTIAL ❌

`auto_ingest._validate_promote_fields` (`labels/auto_ingest.py:115-199`):
* Chain enum allow-list — ✅ (21 chains, line 69-75)
* Chain-aware address regex — ✅ EVM, Tron, Solana, Bitcoin
* Category enum allow-list — ✅ (12 categories, line 78-83)
* Name control-char + invisible-Unicode reject — ✅ (line 178-190)
* Source identifier regex — ✅ (`_VALID_SOURCE_RE` line 112)

`_compute_promote_confirm_sha256` (`labels/auto_ingest.py:202-225`):
* Function exists — ✅
* Called from `promote_candidate(confirm_sha256=...)` — ✅
  (`auto_ingest.py:736-744`)
* **Wired into the API layer** — ❌
  (`labels/api.py:86-93` `PromoteRequest` has only `reviewer_email`
  + `confidence`; no field or header for `confirm_sha256`. Line
  165-213 `promote_label_candidate` never reads the header and
  never passes it to `auto_ingest.promote_candidate`. The kwarg
  defaults to `None`, which skips the check entirely.)

`multi_source_confirm.py`:
* `requires_multi_source_confirm` + `confirm_via_secondary_sources` —
  ✅ (sound logic)
* **Called from `promote_candidate`** — ❌ (grep finds zero call
  sites; only the module itself references those names)

Net: the static-shape validation is real and the seed-write path is
hardened against malformed EVM hex / unknown chains / control-char
names. But the two "defense-in-depth" gates the v0.32.1 changelog
takes credit for — confirm-hash pin and multi-source-confirm — are
both **unreachable from the production codepath**. An attacker who
controls the `label_candidates` row content (DB write, or
admin-key compromise) lands the row in the seed file as long as
the address shape is valid for the chain. **CRIT-1 carries forward
at reduced severity.**

### 1.2 CRIT-2 — `_safe_error_text` coverage — CLOSED ✅

`cron_scheduler._safe_error_text` (`cron_scheduler.py:350-452`):
* Multi-scheme credentialed-URI redaction (postgres, redis, mongodb,
  amqp, sftp, ftp, mysql, smtp, https-with-basic-auth) — ✅ line 381-387
* Labeled secrets (api_key, token, secret, password, bearer,
  authorization) — ✅ line 390-396
* JWT pattern — ✅ line 399-403
* Slack webhook URLs — ✅ line 406-410
* Vendor prefixes (Stripe sk_live/sk_test/rk_live/pk_live, Resend re_,
  Anthropic sk-ant-/sk-proj-, GitHub ghp_/ghs_/gho_, AWS AKIA/ASIA,
  Vercel vc_, Slack xoxb-/xoxp-/xapp-, generic whsec_) — ✅ line 413-433
* Generic 32+ char high-entropy catcher with UUID + EVM-address
  allow-list — ✅ line 446-450

Minor gaps (LOW): vendor regexes are case-sensitive. A future
provider keyed in uppercase (very rare in practice) would bypass.
The JWT regex requires three ≥8-char segments — a hand-crafted
3-segment short JWT could fall under that floor. Both are
defensibly chosen.

### 1.3 HIGH-1 — Auto-ingest SSRF — NOT CLOSED ❌

`labels/auto_ingest.py:321-342` `_safe_http_get_json`:
```python
def _safe_http_get_json(url: str, *, source_name: str) -> Any:
    try:
        import httpx
        with httpx.Client(timeout=_HTTP_TIMEOUT_SEC) as client:
            resp = client.get(url)
        ...
```
No host allow-list, no scheme check (file:// / http:// would proceed),
no `follow_redirects=False`, no DNS-resolved private-IP block, no
body cap. Identical to round-1 except the `source_name` kwarg.

`tests/test_v032_1_security_fixes.py:354-419` exercises a
`_ssrf_validate_url` symbol and a body-cap branch that **do not exist
in `auto_ingest.py`**. Running these tests will raise `ImportError`
on line 371 (`from recupero.labels.auto_ingest import ...,
_ssrf_validate_url`).

This is the single most embarrassing v0.32.1 gap: the changelog
claims SSRF defense AND the test suite asserts it, but the source
code change was apparently lost between branches. Trail of Bits will
land this on day one.

### 1.4 HIGH-2 — Admin-key `.strip()` regression — CLOSED ✅

Three admin-key gates verified:
* `dispatcher/review_api.py:64` `hmac.compare_digest(provided, expected)`
* `labels/api.py:64` same
* `api/cron_admin_api.py:61` same

In every case `.strip()` is used ONLY for the emptiness pre-check
on line 59 / 56. The compare operates on the raw provided header.
Symmetric to the v0.20.2 fix.

### 1.5 HIGH-3 — Intake CSRF gate — CLOSED ✅

`api/app.py:1205-1219`:
```python
if not origin and not referer:
    allow_headerless = (
        _os.environ.get("RECUPERO_INTAKE_ALLOW_HEADERLESS", "")
        .strip().lower() in ("1", "true", "yes", "on")
    )
    return allow_headerless
```
Default deny. The opt-in env var preserves the curl-from-script
integration path without compromising the default.

### 1.6 HIGH-5 — `/cron/healthz` payload — PARTIAL ❌

Public endpoint:
* `cron_scheduler.build_cron_healthz_payload:631-641` constructs
  `job_states` with only `last_success_utc`,
  `hours_since_last_success`, `consecutive_failures`, `status` —
  `last_error_message` is omitted. ✅
* `worker/_health_server.py:140-165` `/cron/healthz` serves that
  payload. ✅

Admin replacement (HIGH-5 close-out per the changelog):
* `api/cron_admin_api.py:39` defines `router = APIRouter(prefix="/v1/cron")`
  and a `GET /jobs` endpoint with `_require_admin_auth`. ✅ shape
* **`api/cron_admin_api.py:81` calls
  `build_cron_healthz_payload(include_error_message=True)` — but
  `build_cron_healthz_payload` (`cron_scheduler.py:542-651`) accepts
  only `dsn`.** Calling the endpoint raises
  `TypeError: build_cron_healthz_payload() got an unexpected keyword
  argument 'include_error_message'`. The outer `except Exception`
  swallows it into a 503. ❌
* **The router is never registered.** `api/app.py:75-107` includes
  the review-router and labels-router; no `app.include_router(
  cron_admin_api.router)`. Hitting `GET /v1/cron/jobs` returns 404. ❌

The public leak is closed (defense-in-depth wins) but operators have
NO way to see redacted error text. Round-1 HIGH-5 substituted one
gap for another.

---

## 2. New attack surface — v0.32.1 modules

### 2.1 `api/cron_admin_api.py` — wiring CRITs

`src/recupero/api/cron_admin_api.py`:
* **CRIT-3 (new)** — Router not registered. See §1.6 above.
  `api/app.py:75-107` is the inclusion site; the cron-admin import
  is absent. Fix: add the same try/except wrapper used for review
  and labels routers.
* **CRIT-3-b** — `build_cron_healthz_payload(include_error_message=True)`
  call (`cron_admin_api.py:81`) does not match the function
  signature in `cron_scheduler.py:542`. The kwarg must be plumbed
  through `build_cron_healthz_payload` AND the `job_states` builder
  must conditionally include `last_error_message` /
  `last_error_utc`. Currently they're stripped unconditionally in
  the `job_states` constructor (`cron_scheduler.py:631-641`).
* Rate limit: none. Same admin key as the review surface. If an
  attacker has the admin key, they have everything anyway.
  Acceptable.
* Auth: 503 on unset admin key (deny-by-default), 401 on missing
  header, `hmac.compare_digest` for the comparison. Solid.

### 2.2 `security/per_case_randomization.py`

`src/recupero/security/per_case_randomization.py`:
* **HIGH-6 (new)** — `_resolve_secret` (line 76-98) accepts ANY
  non-empty string. `RECUPERO_RANDOMIZATION_SECRET=x` (1 byte,
  ~3 bits) passes and the dev-fallback path is NOT triggered.
  An adversary who knows the operator typo'd a 1-char key can
  brute-force all per-case thresholds in 256 tries. Fix: reject
  any secret < 16 bytes (or fall back to the dev sentinel with a
  WARN). Document a minimum-length / `secrets.token_hex(32)`
  requirement in the .env.example comment block.
* WARN-once flag (line 73) is module-global; reset hook exposed
  for tests (line 101). Correct. Threading-safe enough — the
  flip-flop happens once.
* HMAC operates on `f"{case_id}:{threshold_name}"` (line 124).
  `threshold_name` values are source-controlled identifiers (e.g.
  `"dust_min_fanout"`); they are NOT operator- or attacker-
  influenceable through any API surface. The colon separator is
  a minor edge case — a `case_id` containing `":foo"` could collide
  with a future `threshold_name`, but that's a model bug, not a
  security gap.
* Determinism: HMAC-SHA256, 8 bytes mapped to `[0, 1)`, linear
  jitter map. Correct cryptographic construction.
* `.env.example:124` documents the var with a generation command
  but does NOT mark it `REQUIRED` for production. The dev fallback
  is loudly named (`DEV_FALLBACK_NOT_FOR_PRODUCTION`) — acceptable
  for a release runbook to enforce, but a startup-time hard check
  (refuse to boot in `RAILWAY_ENVIRONMENT=production` without the
  var) would close the misconfigured-deploy gap entirely.

### 2.3 `labels/multi_source_confirm.py`

`src/recupero/labels/multi_source_confirm.py`:
* **HIGH-7 (new)** — Dead code. `requires_multi_source_confirm`
  and `confirm_via_secondary_sources` are exported but never
  imported / called by any other production module. Grep confirms:
  the only file mentioning either symbol is the module itself
  (see ToolSearch results). The audit's M-1 mitigation against
  poisoning attacks P1-P4 is text-only.
* HIGH-IMPACT category set (line 44-52): authoritative — includes
  `exchange_hot_wallet`, `bridge`, `mixer`, `sanctioned`, `ofac`,
  `custodian`, `exchange_deposit`. The check uses
  `category.strip().lower()`; an attacker can't easily flip the
  category to a non-impactful one and bypass — though the input is
  attacker-controlled, the seed-file writer ALSO enforces a
  category enum, so the category they pick still has to be in the
  category allow-list. The risk would only materialize once this
  module is wired in.
* Source-tier table (line 66-83): high-trust tier includes
  `defillama_*` and `etherscan_contract_source` and OFAC/Chainalysis.
  Low-trust includes Tronscan + Solscan tags. Unknown sources
  default to `low_trust` (line 95, fail-closed). Correct shape.
* Tron + high-impact + only low-trust sources: explicit reject
  (line 247-259). Matches the audit's P3 attack signature.
* "Independence" check counts distinct tiers (line 262-272), not
  distinct sources within a tier. Defends against the
  Tronscan+Solscan+Etherscan-public-tag spam pattern.
* When wired up, this module looks sound. The hole is that it
  ISN'T wired.

### 2.4 `trace/safe_ownership_detector.py`

`src/recupero/trace/safe_ownership_detector.py`:
* The four Safe ownership-management selectors are correct constants
  (line 47-52). Stable across Safe 1.0.0 - 1.4.x as documented.
* `_slot_to_address` (line 115-137) correctly extracts right-aligned
  20-byte slots from a 32-byte calldata word. Zero-address rejection
  (line 133-136) prevents false positives from the `address(0)`
  sentinel.
* **LOW-6 (new)** — Selector-only matches are returned with
  `verified_via_get_owners=False` (line 290-300). The brief renderer
  must treat low-verified Safe ownership-changes as a SUGGESTIVE
  signal, NOT a confirmed one — a non-Safe contract that happens
  to expose a `0xe318b52b` selector (extremely rare; 4-byte
  collision space ≈ 2³²) would fire a false-positive
  "CUSTODIAL CONTROL CHANGE" warning. The module correctly returns
  the flag; the BURDEN is on the integration site (not in this
  module) to render verification status in the brief. Document in
  the integration ticket so this isn't lost.
* `_try_verify_is_safe` (line 153-182): duck-typed adapter access
  via `getattr(evm_adapter, "call_view", None)`. If a future
  attacker controls the EVM adapter (unlikely in our threat model)
  they could spoof `getOwners()` returning a non-empty list — but
  the adapter is server-controlled. OK.
* No spoofing of the calldata: even a malicious contract that
  exposes `swapOwner(...)` and is called via that selector IS by
  definition emitting a "swapOwner-shaped" call. Whether that's a
  REAL Safe is verified via `getOwners()`. Conservative.

### 2.5 `web/templates/review_gate.html` + `/review-gate` route

`src/recupero/web/templates/review_gate.html`:
* **MED-7 (new)** — Innate XSS surface. Lines 219-241 build the
  table HTML via string concatenation and assign to `.innerHTML`.
  The fields injected raw are `r.artifact_sha256`, `r.case_id`,
  `r.artifact_kind`, `r.created_at_utc`, `r.id`. These come from
  the server's `/v1/reviews/queue` payload — currently server-
  controlled (UUID, hex digest, enum strings, ISO timestamps).
  **Today** the surface is clean. If any future field that crosses
  this template carries operator-or-user-provided text (e.g.
  `case.title`, `reviewer_notes`), it will execute as HTML.
  Mitigate now: switch to `textContent` / `createElement` for the
  per-row cells, OR add a `escapeHtml(s)` helper and pass every
  injected value through it. Cheap, future-proofs the surface.
* Admin-key handling: `keyInput` is a `type="password"` field;
  `adminHeaders()` reads `keyInput.value.trim()` (line 180) on
  every fetch. **Held in memory only** — no localStorage, no
  cookie, no URL param. ✅
* CSRF: every state-changing request goes via `fetch()` with a
  custom `X-Recupero-Admin-Key` header (line 182) — browsers
  CANNOT set a custom header on a cross-origin form POST, so the
  state-change surface is implicitly CSRF-immune for the
  attacker-controlled-page case.
* The page itself (`GET /review-gate` at `api/app.py:1646-1694`)
  is **unauthenticated** — by design, per the comment block on
  line 1640. Acceptable: it's a static HTML asset that exposes
  NO data; every dynamic fetch requires the admin key.
* The "prompt()" UX for reviewer email + notes (line 253-257) is
  fragile but not a security issue.

### 2.6 `auto_ingest._safe_http_get_json` — round-1 carryforward

Already covered in §1.3. Worth restating: `tests/
test_v032_1_security_fixes.py:354-419` will fail with `ImportError`
because the symbols it asserts (`_ssrf_validate_url`, body cap,
host allow-list) don't exist. Either the source was lost between
branches or the test was written speculatively against an unmerged
diff.

---

## 3. Defects-by-area summary

| # | Sev | Area | File:line | One-liner |
| - | --- | ---- | --------- | --------- |
| CRIT-1 | CRIT | labels promote | `labels/api.py:86-213` | Confirm-hash + multi-source gates are dead code; promote API never invokes them |
| CRIT-3 | CRIT | cron-admin | `api/cron_admin_api.py:81`, `api/app.py:75-107` | Router unregistered + calls a kwarg the underlying function doesn't accept; endpoint is 404 in production, TypeError in tests |
| HIGH-1 | HIGH | auto-ingest | `labels/auto_ingest.py:321-342` | SSRF defense not implemented; tests at `test_v032_1_security_fixes.py:371` ImportError because the symbol they assert doesn't exist |
| HIGH-4 | HIGH | cron webhook | `worker/cron_scheduler.py:485` | `RECUPERO_CRON_ALERT_WEBHOOK_URL` still unvalidated (carry-forward from round-1) |
| HIGH-6 | HIGH | randomization | `security/per_case_randomization.py:83-98` | Accepts 1-char `RECUPERO_RANDOMIZATION_SECRET`; no min-length / entropy gate |
| HIGH-7 | HIGH | label confirmation | `labels/multi_source_confirm.py` (entire file) | Module is dead code — never imported by the promote path |
| MED-1 | MED | safe-detector | `trace/safe_ownership_detector.py:290-300` | Selector-only matches return verified=False; downstream brief renderer must surface that flag, or false-positive "CUSTODIAL CONTROL CHANGE" |
| MED-2 | MED | cron leader | `worker/cron_scheduler.py:167-185` | `_resolve_leader_id` trusts `HOSTNAME` / `RAILWAY_REPLICA_ID` verbatim (carry-forward round-1 MED-1) |
| MED-3 | MED | review-gate XSS | `web/templates/review_gate.html:218-241` | innerHTML string-concat over `r.*` fields; clean today, future-fragile |
| MED-4 | MED | randomization prod-guard | `security/per_case_randomization.py:76-98` | No startup hard-fail when `RAILWAY_ENVIRONMENT=production` and var unset; dev-fallback proceeds silently after the one WARN |
| MED-5 | MED | api-budget | `observability/api_budget.py` | Hardcoded cost model (carry-forward round-1 MED-5) |
| MED-6 | MED | health-server | `worker/_health_server.py` | `/portal` POSTs unauthenticated (carry-forward round-1 MED-6) |
| LOW-1 | LOW | redactor | `worker/cron_scheduler.py:413-433` | Vendor regexes case-sensitive — would miss `SK_LIVE_…` (theoretical) |
| LOW-2 | LOW | JWT-redact | `worker/cron_scheduler.py:399-403` | Requires 3 ≥8-char chunks; hand-crafted shorter JWT could bypass |
| LOW-3 | LOW | safe-detector | `trace/safe_ownership_detector.py:262` | 4-byte selector collision space ≈ 2³² — extremely rare FP |
| LOW-4 | LOW | rate-limit clock | `api/app.py:_intake_rl_check` | Uses `time.time()` not `time.monotonic()` (carry-forward round-1 LOW-3) |
| LOW-5 | LOW | email validation | `dispatcher/review_api.py:94-99`, `labels/api.py:95-100` | `@` literal check only — `"@@@"` passes (carry-forward round-1 LOW-5) |

---

## 4. OWASP Top 10 mapping (post-v0.32.1)

| OWASP | Status |
| ----- | ------ |
| A01 Broken Access Control | HIGH-5 admin replacement broken (CRIT-3); `/cron/healthz` public leak closed |
| A02 Cryptographic Failures | HIGH-6 randomization secret has no min-entropy gate |
| A03 Injection | CRIT-1 partially closed — static shape gates added, dynamic gates dead-coded |
| A04 Insecure Design | HIGH-7 (multi-source confirm exists but uninstalled); CRIT-3 (test/source drift in v0.32.1) |
| A05 Security Misconfiguration | MED-4 (no prod hard-fail on unset randomization secret); HIGH-4 (webhook URL unvalidated) |
| A06 Vulnerable Components | No CVE matches as of 2026-05-28; pyproject pins look current |
| A07 Authentication Failures | HIGH-2 verified closed; single-key surface persists (design choice) |
| A08 Software/Data Integrity | CRIT-1 PARTIAL — seed-file integrity gated by static validator only |
| A09 Logging/Monitoring | Webhook payload redaction CLOSED (CRIT-2); JWT/vendor-key coverage solid |
| A10 SSRF | HIGH-1 **not closed** (regression-of-claim); HIGH-4 (webhook URL) carry-forward |

---

## 5. Fix sketches (only NEW or NEW-state findings; carry-forwards refer to round-1 §4)

### CRIT-3 — cron-admin wiring

1. Add to `api/app.py` near line 107:
   ```python
   try:
       from recupero.api.cron_admin_api import router as _cron_admin_router
       app.include_router(_cron_admin_router)
   except Exception as _exc:
       log.warning("cron admin API not registered: %s", _exc)
   ```
2. In `cron_scheduler.build_cron_healthz_payload`, add the kwarg:
   ```python
   def build_cron_healthz_payload(
       *, dsn: str | None = None,
       include_error_message: bool = False,
   ) -> dict:
   ```
   and conditionally include `last_error_message` /
   `last_error_utc` in the per-job state.
3. Add an integration test that boots the FastAPI app + calls
   `GET /v1/cron/jobs` with the admin key and asserts the payload
   carries the error text. Mirror `test_v032_1_security_fixes.py:593-666`
   which already expects that behavior.

### CRIT-1 — wire the confirm-hash + multi-source gates

1. In `labels/api.py`, add a `confirm_sha256` field to
   `PromoteRequest` (or a `X-Recupero-Promote-Confirm` header,
   per the audit's stated design), and pass it through to
   `auto_ingest.promote_candidate`.
2. In `auto_ingest.promote_candidate`, BEFORE the seed-write,
   call `multi_source_confirm.requires_multi_source_confirm(row)`
   and `multi_source_confirm.confirm_via_secondary_sources(...)`
   when applicable. Reject (raise ValueError) when `accepted=False`.
3. Surface the `ConfirmationResult.reason` in the API response
   so an operator hitting a Tron+exchange_hot_wallet candidate
   sees WHY their promote was held.

### HIGH-1 — actually implement the SSRF defense

1. Add:
   ```python
   _ALLOWED_HOSTS = frozenset({
       "api.llama.fi", "apilist.tronscanapi.com",
       "public-api.solscan.io", "api.etherscan.io",
   })
   _MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB
   ```
2. Write `_ssrf_validate_url(url) -> tuple[bool, str]`:
   * scheme must be `https`
   * `urlsplit(url).hostname` must be in `_ALLOWED_HOSTS`
   * `socket.getaddrinfo(host, 443)` results must not contain any
     IP matching `ipaddress.ip_address(ip).is_private |
     .is_loopback | .is_link_local | .is_reserved`
3. In `_safe_http_get_json`, call `_ssrf_validate_url` up front
   (None if bad), construct `httpx.Client(follow_redirects=False)`,
   read at most `_MAX_BODY_BYTES` of the body before `json.loads`.
4. The existing test file (`test_v032_1_security_fixes.py:354-419`)
   already pins the expected behavior — just make the implementation
   catch up.

### HIGH-4 — webhook URL validation

(unchanged from round-1 §4) Parse the env var at boot; reject
non-https schemes outside dev; reject private / loopback /
link-local IPs after DNS resolve; log the parsed hostname.

### HIGH-6 — minimum-entropy on randomization secret

In `_resolve_secret`:
```python
raw = (os.environ.get(_SECRET_ENV_VAR, "") or "").strip()
if raw and len(raw) < 16:
    log.error(
        "%s is set but too short (%d bytes; need >= 16) — "
        "falling back to dev sentinel for safety",
        _SECRET_ENV_VAR, len(raw),
    )
    raw = ""   # force the dev-fallback branch
if raw:
    return raw.encode("utf-8"), False
```
Add a startup hard-fail in `cron_scheduler.main` and
`api.app.main` that checks the var when
`RAILWAY_ENVIRONMENT == "production"`.

### HIGH-7 — wire multi_source_confirm

See CRIT-1 fix sketch step 2. Same wiring closes both.

### MED-3 — review-gate XSS defense in depth

Replace innerHTML string-concat with `document.createElement` +
`.textContent` for every per-row cell. Or add:
```js
function esc(s) {
  return String(s ?? "—").replace(/[&<>"'/]/g,
    c => "&#" + c.charCodeAt(0) + ";");
}
```
and pass every interpolated value through it.

---

## 6. Honest assessment — would Recupero survive a Trail of Bits pentest today?

**Marginally better than round-1, but still no.** Score against
the v0.32.1 target of ≥ 90% close-out:

* CRIT-1: ~50% (validator landed, dynamic gates ship as dead code)
* CRIT-2: 100% (clean close)
* HIGH-1: 0% (regression of claim — source change lost between branches)
* HIGH-2: 100%
* HIGH-3: 100%
* HIGH-5: ~50% (public leak closed; admin replacement broken in two
  places)

Average: ~67%, well short of the 90% target. The qualitative gap
is more concerning than the number: the broken HIGH-1 and HIGH-5
both ship with tests that "prove" they work, against source that
doesn't implement them. A diligent reviewer would catch this in a
single test-suite run; a less-diligent one would see green CI and
sign off.

The new modules (`per_case_randomization`, `multi_source_confirm`,
`safe_ownership_detector`, `review_gate.html`) are individually
well-shaped — the design is sound. The integration gap is the
issue: `multi_source_confirm` is never called, the
`per_case_randomization` secret has no minimum-bar gate, the
cron-admin router was never wired.

**Recommended go/no-go for paying customers:**
* CRIT-1 (full close), CRIT-3, HIGH-1 MUST close before the next
  customer pays.
* HIGH-4, HIGH-6, HIGH-7 should close before the bug-bounty
  surface opens.
* All MED / LOW items remain acceptable for the v0.33 backlog.

**Net delta from round-1:** 2 CRIT + 5 HIGH → 2 CRIT + 4 HIGH.
One HIGH closed (HIGH-2); HIGH-3 closed; HIGH-5 mostly closed at
the public surface. But HIGH-1 carried forward AND CRIT-3 newly
introduced — so the count of EXPLOITABLE-NOW issues actually rose
by one (HIGH-6) and the headline claim of the release (SSRF +
admin-cron-jobs) is broken-on-arrival.

— end of round-2 audit —
