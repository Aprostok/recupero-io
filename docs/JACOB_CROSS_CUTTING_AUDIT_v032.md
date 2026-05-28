# Jacob Cross-Cutting Audit — v0.32.0

**Auditor:** cross-cutting (everything the trace / LE / freeze / validator / security agents don't cover)
**Commit:** `7613281` (v0.32.0 docs runbook on top of `af7cf0f`)
**Branch:** `pdf-deliverables`
**Date:** 2026-05-28
**Stance:** brutal. If something would make a senior law-firm partner wince, it gets called out.

---

## 0. Executive scorecard

| Category | Count | Worst offender |
|---|---|---|
| Operator-UX friction points | 11 | README's Quickstart references files / scripts that no longer drive the production flow |
| Real-world edge cases that break/degrade | 8 | Cross-origin Stripe webhook arriving before intake creates an orphan investigation; future-dated incident_time accepted by `recupero trace` CLI |
| Polish gaps (formatting / pluralization) | 7 | Address-truncation drift: `_common.short_addr` is 6+4, but 17 modules + templates use 10+6 or 10+ellipsis |
| Documentation drift | 6 | `.env.example` line 94 advertises a "$1,500 engagement" — `_pricing.py` ships $10,000 |
| Test-coverage gaps | 5 | `worker/cron_scheduler.py` is brand-new HA leader-election but has no dedicated unit test file |
| 30→90% feature gaps | 8 | "Mandatory human review" — the gate exists but there is NO operator UI for `/v1/reviews/queue` (curl only) |

---

## 1. Operator UX friction (STEP 2 walk-through)

### Flow 1 — clone → first case (target: under 1 hour)

The README's "Quickstart" (lines 108–134) shows:

```
python scripts/trace_address.py \
    --chain ethereum \
    --address 0x… \
    --incident-time "2025-10-09T00:00:00Z" \
    --case-id ZIGHA-001
```

**Friction-1 (HIGH):** the production CLI is `recupero trace` (typer-based, installed by `pip install -e .`), NOT `scripts/trace_address.py`. The README script path still exists but is a Phase-1-era shim. A new operator will copy-paste the README, get errors when `data/cases/` doesn't exist, then try `recupero trace --help` and find a completely different option surface (`--address` is actually `--address` here too but `--incident-time` is `--incident-time` not `--incident_time` — close, but the example given in the README's tail differs from `recupero --help` output).

**Friction-2 (HIGH):** the README says "What to read before writing code" → `PHASE1_SPEC.md`, `DATA_MODEL.md`, `TRACE_ALGORITHM.md`, `ZIGHA_TEST_HARNESS.md`. Three of those are Phase-1 docs from 8 months ago. The current architecture lives in `docs/ARCHITECTURE.md` (mentioned NOWHERE in the README). New-operator first-hour onboarding is reading Phase-1 spec docs that describe a single-process Ethereum tracer when the production system has 9 chains, a portal, a review gate, a cron HA scheduler, and an admin API.

**Friction-3 (MEDIUM):** README's "Out of scope" list (line 36–40) includes "Bitcoin, Hyperliquid, BSC, Arbitrum" — all four ARE in scope today (`chains/bitcoin/adapter.py`, `chains/hyperliquid/`, `_common.ADDRESS_EXPLORER_BY_CHAIN` lists all 22 chains). The README has not been touched since Phase 1.

**Friction-4 (MEDIUM):** the README does not mention `recupero-ops`, `recupero-worker`, `recupero-api` console scripts at all. `recupero --help` (CLI) DOES mention them (cli.py:48–51) but the operator doesn't get there until ~30 minutes in.

**Friction-5 (LOW):** `RECUPERO_TOKEN_PEPPER` is REQUIRED. `.env.example` says "Required" (line 50) but the README's Quickstart only mentions `ETHERSCAN_API_KEY` and `COINGECKO_API_KEY`. A new operator following the README runs the worker, sees `RuntimeError: token mint requires RECUPERO_TOKEN_PEPPER`, and has to dig into `.env.example` to discover the pepper requirement.

### Flow 2 — `recupero trace ...` end-to-end

**Friction-6 (HIGH):** `recupero trace` accepts a future `--incident-time` without complaint. The portal intake rejects future dates with a friendly message (intake.py:316–322 — bounds incident_date to `[today - 10 years, today]`), but the CLI path does not. An operator running a CLI re-trace with a typo (`2027-01-01T12:00:00Z`) gets a trace bounded by future blocks — depending on chain, this is either no-ops or undefined behavior in the Etherscan block-number lookup. NO error surfaces.

**Friction-7 (MEDIUM):** `recupero trace` does not validate that the seed address matches the supplied `--chain`. A Tron base58 address `Txxxxx...` with `--chain ethereum` produces an empty trace (no error, no warning — the seed just doesn't appear in Ethereum block range). The portal intake DOES validate this per-chain (intake.py:282–297). CLI gap = real silent failure mode.

### Flow 3 — `curl /v1/reviews/queue`

**Friction-8 (HIGH):** the response is raw JSON — no operator UI exists. `review_api.py:188` returns `{"reviews": [...], "count": N}`. A new operator hired this week is expected to:

1. Know the admin key (`RECUPERO_ADMIN_KEY`) is in the password manager, not in any onboarding doc I can find under `docs/`.
2. Run curl with the right `X-Recupero-Admin-Key` header.
3. Parse the JSON visually to find which `id` to approve.
4. Run a SECOND curl with `POST /v1/reviews/{id}/approve` and a JSON body containing `reviewer_email` + optional `review_notes`.

There is no `recupero-ops review-queue` / `recupero-ops review-approve` wrapper. Every other operator action has a CLI wrapper. The single most-frequent operator action (approving a brief before send) has none.

### Flow 4 — approve a brief

**Friction-9 (MEDIUM):** the success response from `/v1/reviews/{id}/approve` echoes back the full row state, but does NOT tell the operator what happens next ("the brief will now ship on the next worker tick" / "estimated send time: 30s"). The operator approves, then has to manually check Resend or the audit log to know it actually went out.

**Friction-10 (LOW):** on failure (wrong key) the response is `401 {"detail": "invalid X-Recupero-Admin-Key"}` (review_api.py:67). That's actionable. Good. But on a network blip the curl just hangs — no client-side retry hint, no `Retry-After` header.

### Flow 5 — `recupero-ops retrace-scan`

**Friction-11 (LOW):** the output is `retrace-scan: N candidate(s) → data/retrace_candidates.json` (cli.py:881). The operator now has a JSON file. There is NO follow-up "next-action" — no "run `recupero-ops retrace --case X` to re-trace candidate Y". The operator must manually open the JSON and figure out what to do.

### Flow 6 — `recupero-ops close-case`

**Good news:** `close-case` is gated on `--outcome` ∈ {full_recovery, partial_recovery, no_recovery, dropped} and argparse enforces the choice (cli.py:158). A typo errors cleanly. **But:** there is NO confirmation prompt. `recupero-ops close-case --case X --outcome dropped` silently flips the case to `status='closed'` (close_case.py:264–272) and writes an audit row. For a case-state change with permanent disclosure impact, lack of a `_confirm` prompt is a known anti-pattern (see `send-freeze-letters` which DOES use `_confirm`). Listed as Friction-12 (MEDIUM).

---

## 2. Real-world edge cases that break or degrade (STEP 3)

### Edge case 1 — wrong chain on intake form
**Portal:** REJECTED at intake validation per-chain (intake.py:282–297). 
**CLI:** ACCEPTED. `recupero trace --chain ethereum --address Tabc…` runs empty.

### Edge case 2 — future-dated incident_time
**Portal:** REJECTED (intake.py:316–322).
**CLI:** ACCEPTED. No bound on `recupero trace --incident-time`.
**Worker:** also no bound (datetime.fromisoformat in worker's trace driver path).
This is a real footgun and pollutes downstream timelines.

### Edge case 3 — seed address is a contract
**Tracer DOES** check whether destinations are contracts (tracer.py:380–387, `is_contract_cache`) and skips them in stop-at-contract mode. But it does NOT check whether the **seed itself** is a contract. If an operator pastes the 1inch router as the seed, the trace will explode the BFS at the contract's outflows (thousands of unrelated outbound transfers). No error, no warning. Risk: blows the per-case transfer cap (`RECUPERO_MAX_TRANSFERS_PER_CASE=50000`) and the API budget cap with no useful output.

### Edge case 4 — checksum vs lowercase address
The portal lowercases EVM addresses through `canonical_address_key` (_common.py:286–291). The CLI's `recupero trace --address 0xABC…` does NOT pre-canonicalize. Whether this matters depends on the downstream `canonical_address_key` calls in screen/screener/correlation — those DO canonicalize. So in practice this is **OK** but the layering is non-obvious. A future change that drops one of those internal canonicalizations would silently fork the trace.

### Edge case 5 — Stripe webhook before intake form
The intake form creates the `cases` row with `status='intake'` (intake.py:353). The dispatcher's `client_reference_id=diag:<case>:<chain>:<seed>` requires that `<case>` already exist. If a webhook arrives whose `client_reference_id` references a case_id that doesn't exist yet (e.g. malformed link, replay attack, or genuine race with Stripe outage retries), `payments/dispatcher.py` will fail the foreign-key INSERT into `investigations`. The dispatcher does log this and the payment row still gets recorded — but the orphan-payment surface has no automated recovery; an operator must read the audit log. **Not a bug — but a documentation gap.**

### Edge case 6 — Resend API down
`worker/_email.py` retries 4 attempts with backoff (lines 217, 262–315). If all retries fail, the artifact is still written to disk + Supabase Storage (the worker's send is the LAST step after deliverables are written). Operator sees the failure via:
- `emails_sent` row with `error_message` populated
- Sentry trace
But there is NO automatic re-send retry beyond the 4 in-process attempts. An operator must manually trigger via `recupero-ops followup-now` or eat the email-loss. **This is acceptable for follow-ups but is a real failure mode for the engagement-letter email** (the legal-defensibility audit-trail says "we emailed you the engagement letter" — if Resend's outage exceeds 4×30s ≈ 2min, the email never lands and the operator must follow up out-of-band).

### Edge case 7 — disk full
The worker writes case artifacts via `atomic_write_text` (_common.py:360) which uses `tempfile.mkstemp` + `os.replace`. On a full disk, the `mkstemp` itself raises `OSError [Errno 28]`. This bubbles up through `build_all_deliverables` and the worker's claim handler catches it generically — the case goes back to `state='claimed'` and gets retried. **But:** every retry burns the API budget (`RECUPERO_API_BUDGET_USD_PER_CASE=0.50`) on re-traces. If the disk stays full, the case eats its full budget in retries before surfacing the actual problem. No "disk-full" diagnostic in the worker's health-check.

### Edge case 8 — concurrent intakes from same victim email
The intake form has NO per-email duplicate check. Same email → N intake rows. The rate-limiter is IP-based (5/60s per IP, app.py:1114). A victim on mobile with a flaky connection who refreshes-submits 6 times in 60 seconds will get throttled on the 6th attempt — but the first 5 ALL create separate cases in the DB. The operator inbox now has 5 separate `case_number=RCP-INTAKE-2026-xxxxxxxx` rows to triage, each with the same victim_email + seed_address.

**Verdict:** at scale this is a real op-time waste. The fix is cheap: in `create_case_from_intake`, before INSERT, check for a same-`client_email` + same-`seed_address` row created within the last 60 seconds and return the existing case_id. Not done.

---

## 3. Polish gaps (STEP 4)

### 3.1 Address-truncation drift
`_common.short_addr` is the canonical 6+ellipsis+4 helper (line 295), documented as the single source of truth post-v0.16.10. But:

| Module | Pattern | Diverges? |
|---|---|---|
| `_common.short_addr` | `addr[:6]…addr[-4:]` | canonical |
| `worker/_pdf_links.py:185` | `addr[:6]…addr[-4:]` | matches |
| `ops/commands/correlation_stats.py:127` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `monitoring/dispatcher.py:373` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `freeze/asks.py:242–243` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `trace/cex_continuity.py:500` | `addr[:10]...` (no tail) | **drift** (prefix only) |
| `reports/investigator_export.py:448, 817` | `addr[:10]...` (no tail) | **drift** (prefix only) |
| `validators/output_integrity.py:1220` | `addr[:10]...` | **drift** |
| `trace/tracer.py:1166` | `addr[:10] + "..."` | **drift** |
| `reports/templates/exchange_subpoena_request.html.j2` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `reports/templates/le.html.j2:756` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `reports/templates/cluster_handoff.html.j2:157` | `addr[:10]…addr[-6:]` | **drift** (10+6) |
| `reports/templates/trace_report.html.j2:293` | `addr[:10]…` | **drift** |

**Verdict:** SAME stolen-funds case generates a brief with `0xABCDEF…1234` (6+4 in `_pdf_links.py`) and an LE handoff with `0xABCDEF1234…5678AB` (10+6 in the le.html.j2 template). An operator cross-referencing the two artifacts cannot diff addresses by eye. This is **exactly the drift `_common.short_addr` was introduced to prevent in v0.16.10**, and the templates have NEVER adopted it.

### 3.2 Currency formatting
`_pricing.fmt_usd` is the canonical `$X,XXX.XX` formatter — uses `:,.2f`. All 73 occurrences of `${...}` in src/recupero/ route through one of `fmt_usd` / `fmt_usd_short` / `fmt_usd_or` / `fmt_usd_bare_or`. **Consistent.** Negative values render as `-$X,XXX.XX` (sign before currency, line 109). NaN/Inf clamp to `$0.00`. **GOOD.**

One nit: `fmt_usd_short` drops cents when integer; `fmt_usd` always has cents. The two are used inconsistently in the brief — sometimes `$10,000` and sometimes `$10,000.00`. Low priority.

### 3.3 Date formatting
The portal renders dates as `%B %d, %Y` ("May 28, 2026") in `_fmt_dt` (portal/server.py:981). The CLI's `_print_summary` calls `case.incident_time.isoformat()` ("2026-05-28T00:00:00+00:00"). The LE template uses yet another format. No canonical helper — three formats live in production. Operators see different date formats in the portal email vs. the trace_report CSV.

### 3.4 Pluralization
The LE template DOES pluralize via Jinja conditionals (`"wallet" if count == 1 else "wallets"`). I spot-checked le.html.j2:90, 93, 146, 155, etc. — consistent. No "1 transfers" bugs found in templates.

**BUT:** `ops/commands/list_payments.py` and `reports/cooperation_dashboard.py` print things like `f"{n} letters"` with no plural guard. A case with a single letter renders "1 letters" in the dashboard digest. Low impact, looks unpolished.

### 3.5 HTTP error response shape
The API endpoints uniformly use FastAPI `HTTPException(detail="...")` which renders as `{"detail": "..."}`. **43 occurrences** of `detail=` in api/. Consistent. No competing `{"error": "..."}` shape.

The DISPATCHER router (`dispatcher/review_api.py`) returns explicit dict responses on success (`{"id": ..., "case_id": ..., "status": ...}`) but error responses still go through `HTTPException(detail=...)`. **Consistent.**

### 3.6 CSV / JSON exports
`investigator_export.py` writes CSVs with quoted/labeled headers. Spot-check passes. The `transfers.csv` from `recupero trace` has headers (case_store.py writes them). Good.

### 3.7 README ↔ code drift on prices
`.env.example` line 94: `# Two separate links — one $499 diagnostic, one $1,500 engagement.`
`_pricing.py` line 53: `ENGAGEMENT_FEE_USD: Decimal = Decimal("10000")`.

The .env.example STILL says $1,500. The engagement fee was bumped to $10,000 in v0.7.0. The .env.example has been stale for ≥ 9 versions.

---

## 4. Documentation drift (STEP 5)

I spot-checked 5 docs:

### 4.1 `README.md`
- **DRIFT:** Phase-1 layout listing (Ethereum-only). Production supports 22 chains.
- **DRIFT:** Quickstart references `scripts/trace_address.py` and `scripts/verify_zigha.py`. The Phase 1 path still exists, but no operator should onboard via it in v0.32.
- **DRIFT:** "What to read before writing code" → 4 Phase-1 docs. No mention of `docs/ARCHITECTURE.md`, `docs/ENV_VARS.md`, `docs/GO_LIVE_RUNBOOK.md`, `docs/DEPLOY_v0_32_0_RUNBOOK.md`.
- **DRIFT:** Out-of-scope claims Bitcoin/Arbitrum/BSC/Hyperliquid aren't supported. All four are in production.

### 4.2 `docs/ARCHITECTURE.md`
- Accurately describes the v0.32 pipeline (intake → trace → enrich → emit_brief → review-gate → dispatch → outcome-tracking).
- Correctly cites `recovery_disclosures` (migration 027), `brief_reviews` (028), `cron_jobs_lock` (029), `label_candidates` (030).
- The "intake CSRF allow-list" claim (line 64) matches `_intake_post_csrf_ok` in app.py. **No drift.**

### 4.3 `docs/ENV_VARS.md`
- Parity is mechanically enforced by `tests/test_v031_4_env_vars_doc.py`. Spot-check confirms each `RECUPERO_*` env var I looked at appears in the doc's index.
- The doc's "Range / Format" column for `RECUPERO_API_BUDGET_USD_PER_CASE` says `[0.01, 100.0], finite`. Confirmed: `config.py` enforces this.
- **Minor drift:** `RECUPERO_OPS_ALERT_EMAIL` is referenced in `.env.example` but I don't see it in the v0.32 ENV_VARS index. (Need full file check; not catching it in head -80.)

### 4.4 `docs/DEPLOY_v0_32_0_RUNBOOK.md`
- Lists 4 new migrations (027–030) and 7 new env vars. Migration scripts exist; env vars all appear in `ENV_VARS.md`. **Accurate.**
- The pre-flight step lists `pytest tests/ --ignore=tests/integration -q --tb=line` expected `4598 passed, 10 skipped, 0 failed`. I did not run this. Trust-but-verify.

### 4.5 `docs/GO_LIVE_RUNBOOK.md`
- File header says **v0.30.1 Go-Live Runbook**. We are on v0.32.0. The pre-merge gate references `scripts/deploy_preflight.py` which DOES exist (33 gates). The runbook lists 11 env vars in the "must be set" table — `RECUPERO_ADMIN_KEY`, `RECUPERO_CRON_ALERT_WEBHOOK_URL`, and the v0.32 review-gate vars are NOT in this list.
- **STALE.** The v0.32 deploy runbook is the canonical doc now (`DEPLOY_v0_32_0_RUNBOOK.md`), and `GO_LIVE_RUNBOOK.md` should either be deleted or have a banner pointing at the newer file.

### 4.6 `.env.example`
- Stale price ($1,500 engagement; actually $10K).
- Missing `RECUPERO_ADMIN_KEY` (admin API gate is REQUIRED to expose the review queue).
- Missing `RECUPERO_CRON_ALERT_WEBHOOK_URL` (v0.32 HA cron alerting).
- Missing all v0.32 Tier-0 / Tier-1 env vars added in `af7cf0f`.

---

## 5. Test coverage gaps (STEP 6)

I could not run coverage (sandboxed bash). From the test directory structure:

- **`worker/cron_scheduler.py`** — v0.32 NEW HA leader-election module. No dedicated `tests/test_cron_scheduler.py` file in the listing. The module is ~hundreds of lines with `_acquire_lease` / `_renew_lease` / SIGTERM handling. Coverage risk: HIGH.
- **`dispatcher/review_api.py`** — v0.32 NEW admin-key gated review surface. Listed test files include `test_v031_*` and `test_round*`. I do not see `test_review_api.py`. The status-transition state machine (`awaiting_review` → `approved` / `rejected` / `overridden_unreviewed`) is a brand-new public surface with NO visible dedicated test file. Coverage risk: HIGH.
- **`dispatcher/review_gate.py`** — the gate function `require_review_approved` is invoked from `worker/_email.py` (line 429). I see no `test_review_gate.py`. Coverage risk: HIGH.
- **`monitoring/recovery_rate.py`** — Wilson-CI math + DB aggregation + 60s cache. Brand new in v0.32. I see no `test_recovery_rate.py`. The intake portal renders against this every GET / second. Coverage risk: HIGH.
- **`labels/api.py`** — the label auto-ingest admin surface (registered in app.py:103). No `test_labels_api.py` visible. Coverage risk: MEDIUM.

The `tests/test_v031_4_env_vars_doc.py` enforces that env-var docs match source — that test will likely catch any v0.32 env-var drift, but doesn't catch behavioral drift in the modules above.

---

## 6. 30%→90% feature gaps (STEP 7)

### 6.1 "Mandatory human-review gate" — UI gap
We have the `brief_reviews` table, the `BriefNotReviewedError`, the admin API at `/v1/reviews/queue`, `/v1/reviews/{id}/approve`, `/v1/reviews/{id}/reject`, `/v1/reviews/{id}/override`. What we **don't** have:

- An operator dashboard / web UI.
- `recupero-ops review-queue` / `recupero-ops review-approve` CLI wrappers.
- Email notification when a new review lands in the queue.
- SLA tracking ("this review has been pending 6h, ping reviewer").

The gate IS the right architectural pattern. But operators today must `curl -H "X-Recupero-Admin-Key: ..." | jq .reviews` and then a second curl to approve. At 1 case/day this is annoying. At 50 cases/day this is infeasible. **30% → 90%:** ship a thin operator UI (the worker already serves HTML at `/portal`; one more route to `/admin/reviews` is straightforward).

### 6.2 "Recovery-rate disclosure" — only computes our rate at n≥30
`MIN_SAMPLE_FOR_OUR_RATE = 30` (recovery_rate.py:83). With n=30 closed cases, the intake portal flips from "industry baseline ~3%" to "our actual rate." The intake disclosure language and the Wilson CI logic are sound. **But:** at n=29 the disclosure says industry baseline. At n=30 it suddenly says "our rate is 12.5% (95% CI [4.2%, 28.7%])." That CI is so wide it's barely meaningful — a discontinuous jump from a stable industry number to a noisy estimate. **30% → 90%:** smooth the transition (Bayesian shrinkage prior toward the industry rate until n is large) so the customer-facing number doesn't jump.

### 6.3 "Cross-case correlation" — only published if exposure > 0.1
The brief includes indirect_exposure for downstream addresses only when at least one score exceeds `0.1`. For >50% of real cases (small-value theft, single-hop trace) the score never reaches 0.1, so the brief publishes nothing under "indirect exposure" — even when meaningful smaller signals exist. **30% → 90%:** publish a `top_5` even if all five are <0.1, gated on a different threshold.

### 6.4 "Wallet clustering" — common-funding heuristic too conservative
`trace/clustering.py` uses common-funding-source as the H3 heuristic. TRM Labs publicly claims 5–7 addresses per cluster on similar data; Recupero typically produces 2-address clusters in the test fixtures. **30% → 90%:** layer in time-window clustering ("addresses funded within 10 min of each other from the same source" → likely related) and CEX-deposit clustering ("addresses depositing to the same exchange-deposit address" → likely one entity).

### 6.5 "MEV detection" — high false-positive rate on legitimate trading
`trace/mev_detection.py` fires on swap patterns that match a sandwich-attack template. Legitimate arbitrage bots produce the same shape. The brief flags both. **30% → 90%:** add a confidence score and only flag MEV when the swap was within ±2 blocks of the victim's transfer AND the profit exceeds a threshold.

### 6.6 "Bridge decoding" — 8 protocols supported, dozens more in the wild
v0.31.0 added Connext, Axelar, LiFi. Combined with pre-v0.31.0 (Wormhole, Stargate, Hop, Across, deBridge) we cover 8 bridges. `RECUPERO_VS_TRM_GAP.md` reports TRM covers ~20. Real-world thefts route through bridges we don't decode — the trace dead-ends. **30% → 90%:** the `recupero-ops bridge-sync` cron job exists (cli.py:257–276) but is REPORT-ONLY. Operator must manually add decoder code. Time-to-decoder for a new bridge is days.

### 6.7 "Issuer cooperation intelligence" — black-hole at n=3
`monitoring/cooperation_intelligence.py:93` defines `_BLACK_HOLE_MIN_LETTERS = 3`. Recommending a grand-jury subpoena based on n=3 silent letters is statistically thin. A real subpoena costs an AUSA's time + court schedule. **30% → 90%:** raise to n=10 OR weight by elapsed time (3 silent letters over 6 weeks ≠ 3 silent letters over 6 months).

### 6.8 "Intake rate limiter" — in-memory, per-replica
`_intake_rl_state` is a process-local dict (app.py:1116). With N API replicas behind a load balancer, the effective limit is `N × 5/60s` per source IP. Today the deploy is single-replica (per the architecture doc) so 5/60 holds. **30% → 90%:** as soon as we scale to 2+ replicas, the limit silently doubles. Move to Redis or to a Postgres counter.

---

## 7. Top 5 cross-cutting issues (the wince factors)

1. **README is a Phase-1 artifact.** A new hire spends their first hour reading docs that describe a single-chain Ethereum tracer when the production system has 22 chains, a portal, a review gate, an admin API, and an HA cron scheduler. The current architecture lives in `docs/ARCHITECTURE.md`, mentioned NOWHERE in the README. **Fix:** rewrite the README's first 50 lines to point at ARCHITECTURE.md + DEPLOY_v0_32_0_RUNBOOK.md.

2. **No operator UI for the most-frequent operator action (review-approve).** The review gate is the single biggest legal-defensibility feature added in v0.32. Operators must curl raw JSON. Without a UI, the gate will be bypassed (`override_acknowledged_legal_risk=true`) in practice because the curl flow is too slow. **Fix:** `recupero-ops review-queue` and `recupero-ops review-approve <id> --reviewer-email X --notes Y` CLI wrappers. Cheap. Ship today.

3. **`recupero trace` CLI lacks the intake portal's input validation.** Future dates, wrong-chain addresses, contract seeds — the portal catches them all, the CLI catches none. Production traces fired from the CLI (re-traces, manual operator runs) are doing untrusted-input work. **Fix:** factor `validate_intake_payload` shape checks into a shared helper and invoke from both surfaces.

4. **Address-truncation drift across 17 modules and templates.** v0.16.10 introduced `_common.short_addr` (6+4) as the canonical helper. The templates and 7 modules use a different convention (10+6 or 10+ellipsis). Same address renders differently in the brief vs. the LE handoff. **Fix:** retrofit every truncation site through `short_addr`. ~17 file touches.

5. **Duplicate-intake floor is missing.** A refresh-spamming victim creates N cases. The IP-based rate limiter blocks the 6th+ submission per minute but the first 5 land separately. **Fix:** in `create_case_from_intake`, do `SELECT 1 FROM cases WHERE client_email = $1 AND seed_address = $2 AND created_at > NOW() - INTERVAL '60 seconds'` and return the existing case_id on match.

---

## 8. Honest one-paragraph assessment

A senior law-firm partner watching an operator demo Recupero today would smile at the briefs (the LE-handoff template is genuinely good, the chain-of-custody story holds up, the cooperation-intelligence panel is the kind of compounding-moat capability outside the reach of any single-case forensic tool), nod approvingly at the new v0.32 review gate (mandatory human approval before any artifact ships externally is exactly the right legal-defensibility architecture), then visibly wince twice: once when the operator opens a terminal to `curl` the review queue (and types the admin key from memory because there's no UI), and once when they look up a stolen address in the brief PDF, then in the LE handoff PDF, and the truncation prefix doesn't match across the two documents. The wincing isn't fatal; it signals "this product is still operator-hostile around the edges, but the substance is real." Six weeks of UI work — the curl flow → `recupero-ops review-*` wrappers, README rewrite, truncation harmonization, duplicate-intake guard — would close the gap between "smart engineering team" and "this is ready to demo to LE / firms."

---

*End of audit.*
