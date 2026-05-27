# Recupero Environment Variables — Canonical Reference

This file is the single source of truth for every `RECUPERO_*` env var
the application reads at runtime. Third-party secret env vars
(`HELIUS_API_KEY`, `ETHERSCAN_API_KEY`, …) are listed at the bottom in
their own section.

## Policy

1. **Every `RECUPERO_*` env var read in `src/recupero/**/*.py` MUST
   appear in this file.** The reverse also holds — the doc must not
   list env vars that no longer exist in source. Both directions are
   enforced by `tests/test_v031_4_env_vars_doc.py`, which scans the
   source with `ast` + regex at test time and asserts parity.

2. **Adding a new env var requires a doc update in the same PR.** The
   regression test fails on `git push` if a new `os.environ.get(...)`
   call lands without a row in the index table below.

3. **Operators view this doc inside the terminal via**
   `recupero-ops envvars` — the CLI prints the tabular index so the
   canonical list is reachable without browsing GitHub.

4. **Defaults are chosen to be production-safe.** Any var marked
   `REQUIRED` must be explicitly set in the deploy environment; the
   worker / API / CLI refuses to start (or degrades visibly) when it
   is missing.

5. **All numeric env vars used by the trace / cross-chain / dust /
   CEX-continuity stack reject NaN / ±Inf / negative values** and fall
   back to the documented default with a `log.warning`. This is the
   v0.31.1 "Jacob-style adversarial input" pattern — operators who
   typo a value get a loud warning, never a silently-poisoned trace.

---

## Index

| Name | Default | Type | Range / Format | Introduced | Purpose |
| ---- | ------- | ---- | -------------- | ---------- | ------- |
| **Trace tuning** | | | | | |
| `RECUPERO_TRACE_MAX_HOPS` | `config.trace.max_depth` (2) | int | `[1, 8]` | v0.16.x | BFS depth cap; raise for deep-laundering paths. |
| `RECUPERO_TRACE_DUST_USD` | `config.trace.dust_threshold_usd` (10) | float | `[0, 1_000_000]`, finite | v0.16.x | Per-transfer USD floor; below this is dropped as noise. |
| `RECUPERO_TRACE_TIMEOUT_SEC` | `540` | int | `>= 0` | v0.16.11 | Wall-clock deadline before BFS exits with `trace_status=partial_deadline_hit`. |
| `RECUPERO_MAX_TRANSFERS_PER_CASE` | `50000` | int | `>= 0` | v0.16.11 | OOM defense — trace stops once this many transfers accumulate. |
| `RECUPERO_TRACE_CONCURRENCY` | `5` | int | `>= 1` | v0.16.x | Thread-pool size for parallel per-wave fetches. |
| `RECUPERO_MAX_CONTINUATION_SEEDS` | `25` | int | `>= 0` | v0.16.x | Cap on same-chain bridge / DEX continuation seeds per case. |
| `RECUPERO_MAX_CROSS_CHAIN_SEEDS` | `10` | int | `>= 0` | v0.16.13 | Cap on cross-chain destination seeds across all chains. |
| `RECUPERO_DISABLE_PASS2` | unset | bool | `=1` to disable | v0.20.x | Kill switch for the perpetrator-trace pass-2 stage. |
| `RECUPERO_PASS2_RATIO_THRESHOLD` | `100` | float | `> 0` | v0.20.x | Outflow/inflow ratio threshold for pass-2 candidate identification. |
| `RECUPERO_PASS2_BALANCE_THRESHOLD_USD` | `5000` | Decimal | `>= 0` | v0.20.x | Min current-balance USD for a pass-2 candidate. |
| `RECUPERO_PASS2_MAX_TRACES` | `3` | int | `>= 0` | v0.20.x | Max pass-2 traces per investigation. |
| `RECUPERO_INDIRECT_DECAY` | `0.5` | float | `(0, 1]` | v0.31.0 | Per-hop decay factor for indirect-exposure scoring (MVP). |
| `RECUPERO_INDIRECT_MAX_HOPS` | `3` | int | `>= 1` | v0.31.0 | Max BFS depth for MVP indirect-exposure scorer. |
| **Cross-chain** | | | | | |
| `RECUPERO_CROSS_CHAIN_CONTINUATION` | `1` (on) | bool | opt-out via `0/false/no/off` | v0.28.0 | Master switch for cross-chain BFS continuation. |
| `RECUPERO_CROSSCHAIN_WINDOW_HOURS` | `24` | float | `[0, 720]`, finite | v0.31.0 | Time window past source-bridge tx to accept dst transfers; 0 disables filter. |
| **Dust / CEX-continuity heuristics** | | | | | |
| `RECUPERO_DUST_ATTACK_FILTER` | unset (off) | bool | `1/true/yes/on` to enable | v0.31.2 | Strip dust-shower fan-out destinations from the brief. |
| `RECUPERO_DUST_ATTACK_THRESHOLD_USD` | `1.00` | Decimal | `[0, 100]`, finite | v0.31.2 | Per-destination USD ceiling for the dust-attack filter. |
| `RECUPERO_DUST_ATTACK_MIN_FANOUT` | `10` | int | `[3, 1000]` | v0.31.2 | Min distinct sub-threshold destinations from one source to qualify as a dust attack. |
| `RECUPERO_CEX_CONTINUITY` | unset (off) | bool | `1/true/yes/on` to enable | v0.31.2 | Opt-in CEX-continuity lead surfacing (extra adapter cost). |
| `RECUPERO_CEX_CONTINUITY_WINDOW_HOURS` | `6` | float | `[0.5, 168]`, finite | v0.31.2 | Time window to match CEX-deposit ↔ CEX-withdrawal pairs. |
| `RECUPERO_CEX_CONTINUITY_MIN_USD` | `100000` | Decimal | `>= 1000`, finite | v0.31.2 | Min match USD to surface as a continuity lead. |
| `RECUPERO_DESTINATION_DUST_USD` | `1000.00` | Decimal | `>= 0`, finite | v0.20.x | Per-destination USD floor on the brief's DESTINATIONS table. |
| **Output / rendering** | | | | | |
| `RECUPERO_DISABLE_PDF_RENDER` | unset (off) | bool | `=1` to disable | v0.16.x | Kill switch — skip WeasyPrint PDF render (ship HTML only) on OOM. |
| `RECUPERO_ENABLE_LINK_PATCH` | unset (off) | bool | `=1` to enable | v0.20.x | Opt-in PDF link-annotation patcher (Railway hang under diagnosis). |
| `RECUPERO_PDF_VARIANT` | unset | str | free-form | v0.20.x | PDF render variant flag for A/B comparison. |
| `RECUPERO_INVESTIGATOR_NAME` | unset | str | non-empty | v0.20.0 | Operator's real name in the §9 Investigator Attestation. Briefs render `(operator name not configured)` if unset. |
| `RECUPERO_INVESTIGATOR_EMAIL` | `compliance@recupero.io` | str | RFC 5322 | v0.20.0 | Operator contact email rendered in deliverables. |
| `RECUPERO_INVESTIGATOR_ENTITY` | `Recupero LLC` | str | free-form | v0.20.0 | Legal entity name on signed deliverables. |
| `RECUPERO_INVESTIGATOR_ENTITY_FULL` | `Recupero LLC, a Delaware limited liability company` | str | free-form | v0.20.0 | Full legal entity line. |
| `RECUPERO_INVESTIGATOR_WEB` | `recupero.io` | str | URL host | v0.20.0 | Operator website rendered in deliverables. |
| `RECUPERO_INVESTIGATOR_PHONE` | unset | str | phone | v0.20.0 | Optional operator phone number. |
| `RECUPERO_DESTINATION_DUST_USD` | `1000.00` | Decimal | `>= 0`, finite | v0.20.x | See "dust / CEX-continuity". |
| `RECUPERO_AI_MAX_USD_PER_CALL` | `2.00` | Decimal | `> 0` | v0.17.8 | Per-call USD ceiling on AI editorial calls; `0` disables (logged WARN). |
| `RECUPERO_P_ANY_CALIBRATION_JSON` | unset | JSON | object | v0.21.x | Override default p_any calibration constants (recovery scorer). |
| **Worker / scheduler** | | | | | |
| `RECUPERO_HEARTBEAT_INTERVAL_SEC` | `30` | float | `> 0`, finite | v0.18.x | Per-row heartbeat cadence for worker liveness. |
| `RECUPERO_STALE_AFTER_SEC` | `300` | int | `> 0` | v0.18.x | Reaper threshold — claim is considered stale after this many seconds. |
| `RECUPERO_POLL_IDLE_SEC` | `2.0` | float | `> 0`, finite | v0.18.x | Initial poll backoff when no rows pending. |
| `RECUPERO_POLL_MAX_SEC` | `30.0` | float | `> 0`, finite | v0.18.x | Max poll backoff (jittered). |
| `RECUPERO_LOG_LEVEL` | `INFO` | str | `DEBUG/INFO/WARNING/...` | v0.16.x | Python logging level for worker + ops CLI. |
| `RECUPERO_LOG_FORMAT` | unset | str | `json` to force JSON | v0.16.x | Force JSON log output (default auto-detects TTY vs Railway). |
| `RECUPERO_DB_POOL_SIZE` | unset | int | _deprecated_ | (removed v0.17.8) | Setting it triggers a deprecation WARN — no effect. |
| `RECUPERO_SUPABASE_POOLER_HOST` | `aws-1-us-east-1.pooler.supabase.com` | str | hostname | v0.19.0 | Override Supabase pooler host when project lives outside us-east-1. |
| `RECUPERO_DORMANT_CONCURRENCY` | `5` | int | `>= 1` | v0.16.x | Thread-pool size for dormancy finder. |
| `RECUPERO_WALLET_TRACE_LOOKBACK_DAYS` | (see pipeline default) | int | `>= 1` | v0.20.x | Per-chain wallet-trace lookback window. |
| `RECUPERO_BLOCK_TAG` | `finalized` | str | `finalized/latest/safe` | v0.19.x | EVM eth_call block tag for current-balance snapshots. |
| `RECUPERO_DATA_DIR` | `./data` | path | writable dir | v0.31.4 | Data-output root for the cron scheduler's stale-label report and any other on-disk artifacts. Defaults to the working directory's `./data` when unset. |
| **Watch / monitor / digest cron** | | | | | |
| `RECUPERO_WATCH_DELTA_USD_THRESHOLD` | `100` | Decimal | `>= 0` | v0.16.x | Min USD delta between snapshots to record as a material change. |
| `RECUPERO_WATCH_MIN_INTERVAL_SEC` | `43200` (12h) | int | `>= 0` | v0.16.x | Cooldown between snapshots of the same standard-tier wallet. |
| `RECUPERO_WATCH_HOT_INTERVAL_SEC` | `3600` (1h) | int | `>= 0` | v0.16.x | Cooldown for hot-tier wallets. |
| `RECUPERO_WATCH_PARALLELISM` | `4` | int | `>= 1` | v0.16.x | Per-chain thread-pool size for the watch tick. |
| `RECUPERO_STALE_REVIEW_THRESHOLD_HOURS` | `24` | int | `>= 0` | v0.16.x | Hours after which a `status=awaiting_review` row surfaces on the dashboard. |
| `RECUPERO_STALE_ENGAGEMENT_THRESHOLD_DAYS` | `30` | int | `>= 0` | v0.21.x | Days after which an unclosed engagement surfaces as overdue. |
| `RECUPERO_MONITOR_MAX_SUBS_PER_TICK` | `50` | int | `> 0` | v0.27.x | Subscription rows polled per monitor tick. |
| `RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB` | `25` | int | `> 0` | v0.27.x | Activity events evaluated per subscription per tick. |
| `RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY` | `5` | int | `> 0` | v0.27.x | Per-subscription daily email-alert quota. |
| `RECUPERO_DIGEST_RECIPIENTS` | unset | str | comma-sep emails | v0.16.x | Recipients of the nightly digest email. Empty → digest email disabled. |
| `RECUPERO_DIGEST_FROM` | `Recupero Digest <digest@recupero.io>` | str | RFC 5322 | v0.16.x | From header for digest email. |
| `RECUPERO_DIGEST_ALWAYS_SEND` | unset | bool | truthy | v0.19.2 | Force-send digest even when there are 0 material changes. |
| `RECUPERO_SMTP_HOST` | unset | str | hostname | v0.16.x | SMTP host for digest delivery. Required to enable email. |
| `RECUPERO_SMTP_PORT` | `587` | int | `[1, 65535]` | v0.16.x | SMTP port. |
| `RECUPERO_SMTP_USER` | unset | str | login | v0.16.x | SMTP login user. |
| `RECUPERO_SMTP_PASSWORD` | unset | str | secret | v0.16.x | SMTP login password. |
| `RECUPERO_EMAIL_FROM` | unset | str | email or `Name <email>` | v0.16.x | From-address for Resend-channel emails (freeze letters, LE handoff). |
| `RECUPERO_EMAIL_FROM_NAME` | `Recupero Investigation Services` | str | free-form | v0.18.4 | From-name for Resend-channel emails. |
| `RECUPERO_DISABLE_EMAIL` | unset | bool | truthy | v0.19.2 | Kill switch for outbound email (follow-ups skip; counted under skipped_disabled). |
| `RECUPERO_OPS_ALERT_EMAIL` | unset | str | email | v0.27.x | Ops alert recipient (dispatch failures, quota breaches). |
| `RECUPERO_OPS_OPERATOR` | unset | str | free-form | v0.18.9 | Operator name written into audit trails for ops-CLI actions. |
| `RECUPERO_OPS_ASSUME_YES` | unset | bool | truthy | v0.19.2 | Skip interactive y/N prompts in ops CLI (for cron / scripted ops). |
| `RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE` | unset | bool | `=1` | v0.15.2 | Emit the UNRECOVERABLE variant of the victim summary (gated for safety). |
| `RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE` | unset | str | file path | v0.28.x | Path to JSON file overriding the bundled CEX subpoena recipients map. |
| **Deploy / environment markers** | | | | | |
| `RECUPERO_ENV` | `dev` | str | `dev/prod/production` | v0.17.x | Environment name shown in Sentry + used to detect prod for auth bypass refusal. |
| `RECUPERO_RELEASE` | unset | str | semver | v0.17.x | Release tag forwarded to Sentry. |
| `RECUPERO_GIT_SHA` | unset | str | git sha | v0.18.x | Deploy-time commit sha rendered in `/v1/health`. |
| **API + portal** | | | | | |
| `RECUPERO_API_KEYS` | unset | str | `name1:secret1,name2:secret2` | v0.18.2 | Cached map of API key secrets → partner names. |
| `RECUPERO_API_KEY_ISSUERS` | unset | str | `key:Issuer1\|Issuer2,...` | v0.28.0 | Per-key whitelist of issuers the partner can write `freeze_outcomes` for. |
| `RECUPERO_API_KEY_ADMINS` | unset | str | comma-sep key names | v0.28.0 | Operator key names with universal write access (deny-by-default for everything else). |
| `RECUPERO_API_KEY_CASES` | unset | str | `key:uuid\|uuid,...` | v0.27.x | Per-key case-UUID restriction. |
| `RECUPERO_API_RATE_LIMITS` | unset | str | `name:rps,...` | v0.18.x | Override per-key rate-limit RPS. |
| `RECUPERO_API_AUTH_OPTIONAL` | unset | bool | `=1` (local-dev only) | v0.17.6 | Local-dev bypass — REFUSED when a production marker is present. |
| `RECUPERO_API_HOST` | `0.0.0.0` | str | bind host | v0.18.x | API uvicorn bind host. |
| `RECUPERO_API_PORT` | (uvicorn default) | int | TCP port | v0.18.x | API uvicorn bind port. |
| `RECUPERO_API_DOCS_PUBLIC` | unset | bool | `=1` | v0.18.9 | Expose `/docs`, `/openapi.json`, `/redoc` in prod (default locked). |
| `RECUPERO_INTAKE_ALLOWED_ORIGINS` | unset | str | comma-sep origins | v0.25.x | CSRF allow-list for the unauthenticated POST `/v1/intake`. |
| `RECUPERO_TRUSTED_PROXY_HOPS` | `0` | int | `>= 0` | v0.18.2 / S-3b | Number of trusted reverse proxies in front of the worker / API (XFF parsing). |
| `RECUPERO_ADMIN_KEY` | unset | str | secret | v0.16.6 | Shared secret for the admin UI `X-Recupero-Admin-Key` header. Endpoint denies all when unset. |
| `RECUPERO_PORTAL_BASE_URL` | unset | str | URL prefix | v0.18.x | Portal base URL used when generating customer links. |
| `RECUPERO_PORTAL_PUBLIC_ORIGIN` | unset | str | URL origin | v0.18.x | Public origin allowed for portal CSRF. |
| `RECUPERO_TOKEN_PEPPER` | unset | bytes | 64-char hex / 44-char b64url | v0.20.2 | HMAC pepper for portal-token hashing; unset triggers legacy raw-token comparison. |
| `RECUPERO_WEBHOOK_ALLOWLIST_HOSTS` | unset | str | comma-sep hosts | v0.27.x | SSRF allow-list for outbound monitoring webhooks (empty = no host bypasses deny list). |
| **Custody / chain-of-custody** | | | | | |
| `RECUPERO_CUSTODY_KEY_PATH` | `~/.recupero/custody_key` | str | file path | v0.17.x | Override path to the Ed25519 private key used for custody attestation. |
| **Metrics / health** | | | | | |
| `RECUPERO_METRICS_BIND_HOST` | `127.0.0.1` | str | bind host | v0.27.x | Prometheus exporter bind host. |
| **Hack tracker** | | | | | |
| `RECUPERO_HACK_TRACKER_ENABLED` | unset | bool | `=1` | v0.20.0 | Feature flag for the hack-tracker pipeline. |
| `RECUPERO_HACK_TRACKER_OFFLINE` | unset | bool | `=1` | v0.20.0 | Run hack-tracker against bundled fixtures (no live HTTP). |
| `RECUPERO_X_BEARER_TOKEN` | unset | str | secret | v0.20.0 | X (Twitter) v2 API bearer token for the hack-tracker feed source. |
| **Payments (Stripe)** | | | | | |
| `RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK` | unset | str | Stripe URL | v0.16.x | Stripe Payment Link for the $499 diagnostic. |
| `RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK` | unset | str | Stripe URL | v0.16.x | Stripe Payment Link for the $10K engagement. |

---

## Per-variable detail

### Trace tuning

#### `RECUPERO_TRACE_MAX_HOPS`

BFS depth cap for the primary trace walk. Read at trace start
(`src/recupero/trace/tracer.py:125`), clamped to `[1, 8]`, and falls
back to `config.trace.max_depth` on parse failure with a
`log.warning`.

* **Failure modes:** a non-int value triggers a WARN and the trace
  uses the YAML default (2). Setting it to 0 or negative clamps to 1.
  Above 8 is rejected — 8 hops already explores tens of thousands of
  counterparties and risks API quota exhaustion.
* **When to override:** raise to 4-6 for deep-laundering cases that
  hop through consolidation hubs (Zigha-shape). Leave at default for
  routine diagnostics.

#### `RECUPERO_TRACE_DUST_USD`

Per-transfer USD floor. Anything below this is dropped from the BFS
queue. Read at `src/recupero/trace/tracer.py:135`; NaN / ±Inf /
negative values are rejected with a WARN.

* **Failure modes:** NaN would silently break the dust filter (NaN
  comparisons return False, so EVERY transfer slips the gate). The
  guard at `tracer.py:144` rejects non-finite + negative explicitly.
* **When to override:** lower to `0.01` for dust-attack research;
  raise to `100` for whale-volume cases where $10 noise is overwhelming.

#### `RECUPERO_TRACE_TIMEOUT_SEC`

Wall-clock deadline for the BFS. When the deadline elapses between
waves the trace exits gracefully with `case.config_used.trace_status =
"partial_deadline_hit"` and the brief renders a "trace incomplete"
banner. Default `540` is under Railway's 600s reaper window.

* **Failure modes:** non-int triggers WARN + fall back to 540. Setting
  it too low produces partial traces; too high lets the reaper kill
  the worker mid-stage.

#### `RECUPERO_MAX_TRANSFERS_PER_CASE`

OOM defense. Above this many transfers, BFS exits with
`trace_status="partial_transfer_cap"`. Default 50k is well above any
real theft case but under the 8GB Railway container's safe ceiling.

#### `RECUPERO_TRACE_CONCURRENCY`

Per-wave thread-pool size. Higher counts give diminishing returns
once the Etherscan / CoinGecko rate-limiter is the bottleneck. Read
at `src/recupero/trace/tracer.py:228`, clamped to `>= 1`.

#### `RECUPERO_MAX_CONTINUATION_SEEDS`, `RECUPERO_MAX_CROSS_CHAIN_SEEDS`

Per-wave caps on continuation seeds (same-chain bridge / DEX outputs)
and cross-chain destination seeds respectively. Bound additional API
budget. Defaults 25 / 10 — real cases rarely produce more.

#### `RECUPERO_DISABLE_PASS2`

Kill switch for pass-2 perpetrator trace
(`src/recupero/trace/perpetrator_trace.py:211`). Set to `1` for batch
re-runs / dev work where the extra adapter cost isn't justified.

#### `RECUPERO_PASS2_RATIO_THRESHOLD`

Outflow/inflow ratio above which an address is treated as a
consolidation-hub candidate for pass-2 traces. Default 100.

#### `RECUPERO_PASS2_BALANCE_THRESHOLD_USD`

Min current-balance USD for a pass-2 candidate. Default $5K.

#### `RECUPERO_PASS2_MAX_TRACES`

Per-investigation cap on pass-2 traces. Default 3.

#### `RECUPERO_INDIRECT_DECAY` / `RECUPERO_INDIRECT_MAX_HOPS`

MVP indirect-exposure scorer knobs
(`src/recupero/trace/indirect_exposure.py`). Decay factor per hop
(default 0.5) and max BFS depth (default 3).

### Cross-chain

#### `RECUPERO_CROSS_CHAIN_CONTINUATION`

Master switch for cross-chain BFS continuation. Default ON; any of
`0/false/no/off` (case-insensitive) opts out. Empty / unset keeps it
ON.

* **Failure modes:** none — any unrecognized value is treated as ON.
* **When to override:** turn OFF during local dev runs that don't
  need destination-chain RPC quota.

#### `RECUPERO_CROSSCHAIN_WINDOW_HOURS`

Time window (in hours past the source-bridge tx) to accept dst-chain
transfers. Read at `src/recupero/trace/tracer.py:570`, clamped to
`[0, 720]` (30 days max), rejecting NaN / ±Inf via `math.isfinite`.
Setting to 0 disables the filter (legacy behavior).

* **Failure modes:** non-finite values are rejected with a WARN.
  Pre-v0.31.1 a `-Infinity` slipped through `max(0, -inf)=0`,
  silently disabling the filter — fixed by the `isfinite` check.
* **When to override:** raise to 168 (1 week) for slow consolidation
  paths; lower to 6 for fast-moving bridge sweeps.

### Dust / CEX heuristics

#### `RECUPERO_DUST_ATTACK_FILTER`

Opt-in filter that removes dust-shower destinations
(distinct sub-threshold fan-outs from one source) from the brief's
unlabeled-counterparty list. Off by default. Accepts
`1/true/yes/on`.

* **Failure modes:** none — anything else (including unset) keeps it
  off.

#### `RECUPERO_DUST_ATTACK_THRESHOLD_USD`

Per-destination USD ceiling for the dust-attack filter. Read at
`src/recupero/trace/tracer.py:1197`; clamped to `[0, 100]`,
rejecting NaN / ±Inf / negative values. Default $1.00.

* **Failure modes:** invalid values fall back to default with a WARN
  banner identifying the bad input.
* **When to override:** raise to `$10` if dust attacks in the case use
  $1-10 transfers to evade the default filter.

#### `RECUPERO_DUST_ATTACK_MIN_FANOUT`

Min distinct sub-threshold destinations from one source to qualify as
a dust attack. Clamped to `[3, 1000]`. Below 3 fires on legitimate
change-back patterns; above 1000 misses modestly-sized attacks.

#### `RECUPERO_CEX_CONTINUITY`

Opt-in CEX-continuity-lead surfacing. Adapter calls cost money so
this is gated behind an explicit `1/true/yes/on` (case-insensitive)
toggle.

#### `RECUPERO_CEX_CONTINUITY_WINDOW_HOURS`

Time window for matching CEX-deposit ↔ CEX-withdrawal pairs. Read at
`src/recupero/trace/cex_continuity.py:530`, clamped to `[0.5, 168]`.
Lower bound 30 minutes because anything tighter is below typical CEX
hot-wallet sweep cadence; upper bound 1 week because price drift
breaks the amount-tolerance check beyond that.

#### `RECUPERO_CEX_CONTINUITY_MIN_USD`

Min match USD to surface as a continuity lead. Default $100K, refused
below $1K (statistical noise).

#### `RECUPERO_DESTINATION_DUST_USD`

Per-destination USD floor on the brief's DESTINATIONS table. Read at
emit time (`src/recupero/reports/emit_brief.py:297`), with NaN / Inf /
negative all rejected (Decimal `is_finite()`).

* **Failure modes:** invalid → fall back to default $1000 with a
  WARN.
* **When to override:** lower to $100 for granular small-claim cases;
  raise to $5000 for whale cases where $1K is noise.

### Output / rendering

#### `RECUPERO_DISABLE_PDF_RENDER`

Kill switch — when `=1`, skip WeasyPrint PDF rendering entirely and
ship the HTML deliverables alone. Used on OOM-constrained Railway
containers.

#### `RECUPERO_ENABLE_LINK_PATCH`

Opt-in PDF link-annotation patcher. Default OFF because a Railway-side
hang is still under investigation; production runs with WeasyPrint's
native ~54% link coverage.

#### `RECUPERO_PDF_VARIANT`

Free-form string used by the worker's PDF render variant subprocess
for A/B comparison.

#### `RECUPERO_INVESTIGATOR_NAME`

Operator's real name. Briefs that ship without this set carry the
literal `(operator name not configured)` in §9 Investigator
Attestation — legally useless. Set this before running a real
customer brief. The `require_investigator_configured()` helper raises
when unset; the API / worker preflight can gate on it via
`RECUPERO_REQUIRE_INVESTIGATOR=1`.

#### `RECUPERO_INVESTIGATOR_EMAIL` / `_ENTITY` / `_ENTITY_FULL` / `_WEB` / `_PHONE`

Operator contact / legal-entity strings rendered in deliverables.
Read at call time (never module-load) so a deploy that rotates them
picks up new values without a worker restart.

#### `RECUPERO_AI_MAX_USD_PER_CALL`

Per-call USD ceiling on AI editorial calls. Default $2.00. Set to 0
to disable (logged as WARN — runaway retries will burn real budget).

#### `RECUPERO_P_ANY_CALIBRATION_JSON`

JSON object overriding the documented `p_any` calibration constants
used by the recovery scorer. Missing keys fall back to defaults;
NaN/Inf values are rejected per-key with a debug log.

### Worker / scheduler

#### `RECUPERO_DATA_DIR`

v0.31.4. Filesystem root for cron-generated artifacts that aren't
case-scoped. Today the only writer is the `recupero-cron` stale-label
job (`src/recupero/worker/cron_scheduler.py`), which emits
`<RECUPERO_DATA_DIR>/stale_labels.json` weekly. Default `./data`
(relative to the working directory). The directory is created on
first write — `Path.mkdir(parents=True, exist_ok=True)`. Operators
that mount a persistent volume should point this at the mount point
so the stale-label report survives container restarts.

Routed through `_common.atomic_write_text`, which honors the v0.31.3
`is_link_like` guard — junctions and symlinks at the output path are
rejected loud rather than silently dereferenced.

#### `RECUPERO_HEARTBEAT_INTERVAL_SEC`, `RECUPERO_STALE_AFTER_SEC`, `RECUPERO_POLL_IDLE_SEC`, `RECUPERO_POLL_MAX_SEC`

Worker scheduler knobs. All go through `_resolve_float_env` /
`_resolve_int_env` in `src/recupero/worker/main.py:86-124` which
reject non-positive / non-finite values with a WARN and fall back to
the documented default. Heartbeat must fire well inside
`STALE_AFTER_SEC / 2` so the reaper doesn't steal an active row.

#### `RECUPERO_LOG_LEVEL`

Python logging level for the worker + ops CLI. Default `INFO`.

#### `RECUPERO_LOG_FORMAT`

Set to `json` to force JSON-formatted log output (default
auto-detects TTY vs Railway).

#### `RECUPERO_DB_POOL_SIZE`

DEPRECATED — setting it triggers a WARN
(`src/recupero/worker/db.py:276`). Client-side pooling was removed in
v0.17.8; rely on Supabase's transaction-mode pooler at port 6543.

#### `RECUPERO_SUPABASE_POOLER_HOST`

Override the Supabase transaction-pooler hostname when the project
lives outside us-east-1 (e.g.
`aws-1-eu-central-1.pooler.supabase.com`).

#### `RECUPERO_DORMANT_CONCURRENCY`

Thread-pool size for the dormancy finder. Clamped to `>= 1`.

#### `RECUPERO_WALLET_TRACE_LOOKBACK_DAYS`

Per-chain wallet-trace lookback window (in days). Read at call-time
so cron operators can rotate the value without restarting the worker.

#### `RECUPERO_BLOCK_TAG`

EVM block tag used for current-balance snapshots
(`finalized` / `latest` / `safe`). Default `finalized`.

### Watch / monitor / digest cron

#### `RECUPERO_WATCH_DELTA_USD_THRESHOLD`

Min USD delta between snapshots to log a material change. Read by
`_env_decimal` (`src/recupero/worker/watch_tick.py:139`).

#### `RECUPERO_WATCH_MIN_INTERVAL_SEC` / `RECUPERO_WATCH_HOT_INTERVAL_SEC`

Cooldowns between snapshots — standard wallets every 12h (default),
hot-tier wallets every 1h.

#### `RECUPERO_WATCH_PARALLELISM`

Per-chain thread-pool size for the watch tick. Default 4.

#### `RECUPERO_STALE_REVIEW_THRESHOLD_HOURS` / `RECUPERO_STALE_ENGAGEMENT_THRESHOLD_DAYS`

Dashboard widgets surface investigations / engagements that have
aged past these thresholds.

#### `RECUPERO_MONITOR_MAX_SUBS_PER_TICK`, `RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB`

Per-tick guardrails on monitor-feed processing. Bad / non-positive
values fall back to defaults with a WARN.

#### `RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY`

Per-subscription email-alert quota. Above this the dispatcher drops
into a "quota exhausted" branch and logs.

#### `RECUPERO_DIGEST_*`, `RECUPERO_SMTP_*`, `RECUPERO_EMAIL_*`

Email cron settings. `DIGEST_RECIPIENTS` empty → digest email path
disabled. `SMTP_HOST` / `USER` / `PASSWORD` must all be set for SMTP
delivery to attempt at all. `DISABLE_EMAIL` truthy short-circuits the
follow-up mail loop (skipped rows counted as `skipped_disabled`, not
failures).

#### `RECUPERO_OPS_*`

Operator identity + UX knobs for the ops CLI.
`RECUPERO_OPS_ASSUME_YES` truthy skips all interactive prompts (for
cron / scripted ops).

#### `RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE`

Safety gate — must be `=1` for the UNRECOVERABLE variant of the
victim summary to emit. False positives there carry customer-harm
risk so the gate is required.

#### `RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE`

Path to a JSON file overriding the bundled CEX subpoena recipients
map. Used to add new exchanges or refresh contacts without a code
deploy.

### Deploy / environment markers

#### `RECUPERO_ENV`

Environment name. `prod` / `production` (case-insensitive) marks the
deploy as production, which triggers `RECUPERO_API_AUTH_OPTIONAL`
refusal + `.env` skip behavior.

#### `RECUPERO_RELEASE`

Sentry release tag, also used in `/v1/health`.

#### `RECUPERO_GIT_SHA`

Deploy-time commit sha, set by the Railway / CI build, surfaced via
`/v1/health`.

### API + portal

#### `RECUPERO_API_KEYS`

Cached map of API-key secrets to partner names. Format:
`name1:secret1,name2:secret2` (whitespace stripped, empty pairs
skipped). The parser caches on a SHA-256 fingerprint of the raw value
so subsequent calls don't reparse until the env changes.

#### `RECUPERO_API_KEY_ISSUERS` / `RECUPERO_API_KEY_ADMINS`

Per-key access controls for `POST /v1/freeze-outcomes`. A key MUST
appear in either the issuers list (with the issuer in its
pipe-separated allow-list) OR the admins list — otherwise the request
is denied. **Deny-by-default.**

#### `RECUPERO_API_KEY_CASES`

Per-key case-UUID scoping. Empty → no scoping (legacy behavior).

#### `RECUPERO_API_RATE_LIMITS`

Override per-key requests-per-second. Format `name:rps,...`.

#### `RECUPERO_API_AUTH_OPTIONAL`

Local-dev bypass. **REFUSED in production**: when any production
marker (`RAILWAY_ENVIRONMENT=production`, `ENVIRONMENT=production`,
`RECUPERO_ENV=production`, etc.) is detected the bypass logs a loud
WARN and the auth check stays mandatory.

#### `RECUPERO_API_HOST` / `RECUPERO_API_PORT`

uvicorn bind host/port.

#### `RECUPERO_API_DOCS_PUBLIC`

Set to `1` to expose `/docs`, `/openapi.json`, `/redoc` in
production. Default locked.

#### `RECUPERO_INTAKE_ALLOWED_ORIGINS`

CSRF allow-list for the unauthenticated `POST /v1/intake`. Empty /
unset falls back to same-origin check against the request `Host`
header.

#### `RECUPERO_TRUSTED_PROXY_HOPS`

Number of trusted reverse proxies between the client and the worker /
API. The trusted-hop X-Forwarded-For element is `xff_chain[-N]`. The
RIGOR-S-3b hardening fails closed when the actual chain is shorter
than `N` (operator misconfig) — falls through to `x-real-ip` /
socket peer.

#### `RECUPERO_ADMIN_KEY`

Shared secret for the admin UI's `X-Recupero-Admin-Key` header. When
unset, `/investigations*` and `/dashboard.json` deny everything
(fail-closed).

#### `RECUPERO_PORTAL_BASE_URL` / `RECUPERO_PORTAL_PUBLIC_ORIGIN`

Portal URL prefix and public origin (CSRF / signed-link domain).

#### `RECUPERO_TOKEN_PEPPER`

HMAC pepper for portal-token hashing. Accepts 64-char hex (32 bytes)
or 44-char base64-url (32 bytes). Unset → legacy raw-token
comparison with a one-time WARN log. Rotation invalidates every
active token.

#### `RECUPERO_WEBHOOK_ALLOWLIST_HOSTS`

SSRF allow-list for outbound monitoring webhooks. Empty in production
(no host bypasses the deny list).

### Custody / chain-of-custody

#### `RECUPERO_CUSTODY_KEY_PATH`

Override path to the Ed25519 private key used for chain-of-custody
signing. Generated by `recupero-ops custody-keygen`.

### Metrics / health

#### `RECUPERO_METRICS_BIND_HOST`

Prometheus exporter bind host. Default `127.0.0.1` (localhost-only).

### Hack tracker

#### `RECUPERO_HACK_TRACKER_ENABLED` / `RECUPERO_HACK_TRACKER_OFFLINE`

Feature flags. `_OFFLINE=1` exercises bundled fixtures without
hitting any live HTTP source.

#### `RECUPERO_X_BEARER_TOKEN`

X (Twitter) v2 API bearer token. Unset → x_feed source logs an INFO
and returns no events.

### Payments (Stripe)

#### `RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK` / `RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK`

Stripe Payment Link URLs for the $499 diagnostic and the $10K
engagement. `recupero-ops stripe-mode` cross-checks them against
`STRIPE_WEBHOOK_SECRET` and flags test↔live mismatch.

---

## Third-party secrets

These env vars are NOT prefixed `RECUPERO_*` but the application
reads them directly. Operators must set them in any production deploy
that uses the corresponding integration. They are also surveyed by
`tests/test_v031_4_env_vars_doc.py` so the list stays in sync.

| Name | Read at | Purpose |
| ---- | ------- | ------- |
| `SUPABASE_URL` | many (see below) | Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | many | Supabase service-role key for server-side writes. |
| `SUPABASE_DB_URL` | many | Direct Postgres DSN (rewritten via `pooled_dsn` for the transaction pooler). |
| `ETHERSCAN_API_KEY` | `worker/watch_tick.py`, `chains/ethereum/etherscan.py` | Etherscan v2 multichain key. |
| `HELIUS_API_KEY` | `worker/watch_tick.py`, `chains/solana/helius.py` | Helius (Solana) API key. |
| `TRON_PRO_API_KEY` | `chains/tron/adapter.py` | TronGrid API key. |
| `COINGECKO_API_KEY` | `pricing/coingecko.py` (required in `_REQUIRED_ENV_VARS`) | CoinGecko Pro API key. |
| `ANTHROPIC_API_KEY` | `reports/ai_editorial.py`, nightly-audit LLM review | Claude API key for editorial + nightly audit. |
| `SENTRY_DSN` | `observability/sentry.py` | Sentry DSN; unset disables Sentry init. |
| `SENTRY_ENVIRONMENT` | `observability/sentry.py`, prod-marker detection | Sentry environment name. |
| `SENTRY_TRACES_SAMPLE_RATE` | `observability/sentry.py` | Sentry transaction sampling rate. |
| `STRIPE_WEBHOOK_SECRET` | `payments/webhook.py`, `payments/stripe_mode.py` | Stripe webhook signing secret. |
| `RESEND_API_KEY` | `worker/_email.py` | Resend transactional-email API key. |
| `RAILWAY_PUBLIC_DOMAIN` | `portal/tokens.py` | Railway-supplied public domain used as portal base URL fallback. |
| `RAILWAY_ENVIRONMENT` | prod-marker detection | Railway environment (`production`/`preview`/`development`). |
| `ENVIRONMENT` / `ENV` / `NODE_ENV` | prod-marker detection | Generic environment markers. |
| `SOURCE_DATE_EPOCH` | `_common.resolve_render_time`, `reports/emit_brief.py` | Reproducible-builds timestamp pin. |
| `HEALTH_BIND_HOST` | `worker/_health_server.py` | Override health-endpoint bind host (default 127.0.0.1, or 0.0.0.0 when `PORT` is set). |
| `PORT` | `worker/_health_server.py` | PaaS-supplied health-endpoint port (default 8080). |

---

## Adding a new env var

1. Add the `os.environ.get(...)` call in source.
2. Add a row to the index table above. Include `name`, default,
   type, range, version introduced, and one-sentence purpose.
3. Write a per-variable section below covering description, failure
   modes, and operator guidance.
4. Re-run `pytest tests/test_v031_4_env_vars_doc.py -v` to confirm
   the parity gate passes.
5. (Optional but encouraged) extend the relevant section in
   `docs/OPERATOR_RUNBOOK.md` with the operational story for the new
   var.
