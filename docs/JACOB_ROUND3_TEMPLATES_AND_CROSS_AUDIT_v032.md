# Round-3 templates + cross-cutting audit — v0.32.1 wave 6

**Auditor:** round-3 fresh-eye verification (READ-ONLY)
**Round-2 docs:** `JACOB_ROUND2_TEMPLATES_AUDIT_v032.md` (LE 91 + freeze 92),
`JACOB_ROUND2_CROSS_CUTTING_AUDIT_v032.md` (14/19 ≥ 90%)
**Branch:** `pdf-deliverables` @ `d0648f0`
**Commits since round-2:** `e9a5a66` (wave 4 — round-2 audits + template
closures), `a02030f` (wave 5 — API budget $10K), `d0648f0` (wave 6 —
industry-best mode: budget $0/$1M, hop ceiling 64, adaptive depth, dust
attack + clustering randomization, confirm_sha256 end-to-end, multi-source
confirm wired into label promote)
**Date:** 2026-05-28
**Stance:** brutal; READ-ONLY; static-analysis only.

---

## 0. Executive scorecard

| Doc | Round-2 | Round-3 | Target | Δ |
|---|---|---|---|---|
| LE handoff | 91/100 | **92/100** | ≥ 95 | +1 (HIGH-8 closed, all 6 round-2 NEW open) |
| Freeze letter | 92/100 | **92/100** | ≥ 95 | 0 (no round-2 NEW closed) |
| Cross-cutting | 14/19 ≥ 90% | **15/19 ≥ 90%** | 19/19 | +1 (F-NEW-6 closed) |

Wave 4 landed the round-2 audit *documents* (`JACOB_ROUND2_*`) but did
NOT close any of the round-2 NEW findings they enumerated. Wave 5 fixed
api_budget defaults; wave 6 then re-opened them as a new finding. Wave 6
wired previously dead code (per-case randomization, adaptive depth,
confirm_sha256, multi-source confirm) but introduced 3 undocumented env
vars and made `docs/ENV_VARS.md` actively stale on `RECUPERO_API_BUDGET_USD_PER_CASE`.

---

## 1. LE handoff round-2 NEW closures

| Finding | Status | Evidence |
|---|---|---|
| NF-1 (HIGH) — Freeze letter hardcodes `USD {{ X }}` while LE uses `$X,YYY.ZZ` | NOT CLOSED | `issuer_freeze_request.html.j2:120, 161, 176, 200, 221, 301, 303` — all seven sites still render `USD {{ asset.total_usd_value_at_theft ... }}` with a hardcoded `USD ` prefix and no `usd_prefix` filter. LE template `le.html.j2:96,107,140,…` uses `\| usd_prefix`. Same-case cross-doc divergence persists. |
| NF-2 (MED) — Engagement letter omits gross stolen amount | NOT CLOSED | `engagement_letter.html.j2:65, 72, 78` still surface only `{{ total_freezable_usd }}`. No `total_stolen_usd` field in `_engagement_letter.py:_build_context`; grep for `total_stolen_usd` across `worker/` returns zero. |
| NF-3 (LOW) — Terse Section-6 prose for non-Midas issuers | NOT CLOSED | `_deliverables.py` still threads `regulatory_framework = jurisdiction` directly. No `regulatory_framework_prose` seed field added to `issuers.json`. |
| NF-4 (MED) — `subpoena_target` lacks `[TO BE COMPLETED BY AUSA]` block | NOT CLOSED | grep `TO BE COMPLETED BY AUSA` in `subpoena_target.html.j2` returns zero hits. The DRAFT banner remains but no Name/Office/Address/Phone/Email recipient block at top, matching `subpoena_request.html.j2:181-189`. |
| NF-5 (LOW) — `.placeholder-line` signature width too narrow | NOT CLOSED | `_styles.html.j2:173-180` unchanged. `le.html.j2:1342-1344` still renders `Signature: <span class="placeholder-line">&nbsp;</span>`. |
| NF-6 (LOW) — Hardcoded investigator alias frozenset | NOT CLOSED | `brief.py:1900-1904` still hardcodes `_INVESTIGATOR_EMAIL_ALIASES = {compliance, legal, info @recupero.io}` with no env-var override. |
| HIGH-8 (deferred) — AI editorial token-cost truncation WARN | **CLOSED** | `reports/ai_editorial.py:1182-1237, 1459-1496` — `EDITORIAL_TRUNCATION_SENTINEL` + `_annotate_truncated_editorial(...)` + `stop_reason == "max_tokens"` branch logs WARN and stamps `_EDITORIAL_TRUNCATED_AT_BUDGET=True` on the AI dict. No automatic re-render, but the audit asked for "warning + sentinel" and that's shipped. |

**LE handoff round-2 NEW closure: 1 of 7 (HIGH-8 only).**

LE handoff score: **92/100** (+1 over round-2 from HIGH-8 only). Six of
the seven round-2 NEW findings remain open; the highest-impact one
(NF-1, lawyer-visible cross-doc USD format) is still live and would still
be the first wince a partner notices flipping between the freeze letter
and LE cover. Target ≥ 95 not hit.

---

## 2. Freeze letter round-2 NEW closures

| CRIT verification | Status | Evidence |
|---|---|---|
| CRIT-FR-1 — salutation + subject + reference-quote | STILL CLOSED | `issuer_freeze_request.html.j2:135-149` — subject + `Dear {{ issuer.short_name }} Compliance Team,` + "Please quote reference … on any reply" paragraph all intact. |
| CRIT-FR-2 — corporate legal entity on cover | STILL CLOSED | `IssuerInfo.name = legal_name or short_name` path verified via `_deliverables.py:1683-1815` import chain. `issuers.json` still carries `legal_name`. Tether → "Tether Operations Limited" etc. |
| CRIT-FR-3 — § 3486 → FRCrimP 17(c) | STILL CLOSED | `subpoena_target.html.j2:162-194` — FRCrimP 17(c) default for `grand_jury_subpoena`; § 3486 retained only with caveat for `administrative_subpoena`. |
| CRIT-FR-4 — freeze_notes surfaced | STILL CLOSED | `issuer_freeze_request.html.j2:601-616` — `{% if issuer.freeze_notes or issuer.regulatory_framework %}` § 6 block + nested `{% if issuer.freeze_notes %}` quoted paragraph. |

| Round-2 NEW | Status | Evidence |
|---|---|---|
| NF-1, NF-2, NF-3, NF-4, NF-5, NF-6 | all NOT CLOSED (see table §1) | same evidence — `_engagement_letter.py`, `subpoena_target.html.j2`, `issuer_freeze_request.html.j2`, `brief.py` untouched on these sites in waves 4-6. |

Freeze letter score: **92/100** (unchanged from round-2). All 4 CRITs
still closed (no regression). None of the round-2 NEW items closed. Target
≥ 95 not hit.

---

## 3. Cross-cutting round-2 closures + NEW

### Round-2 still-open friction (closures verified)

| Item | Status | Evidence |
|---|---|---|
| F-6 — `recupero trace` future-date validation | NOT CLOSED | `cli.py:217-221` still `datetime.fromisoformat(...)` only; no `when > datetime.now(timezone.utc)` guard. |
| F-7 — `recupero trace` chain-vs-address validation | NOT CLOSED | `cli.py:206` narrows `chain_enum_early` from the enum but no per-chain regex on `--address`. Tron base58 + `--chain ethereum` still silently produces an empty trace. |
| `.env.example` "$1,500" | NOT CLOSED | `.env.example:94` still reads `# Two separate links — one $499 diagnostic, one $1,500 engagement.` |
| `GO_LIVE_RUNBOOK.md` v0.30.1 banner | NOT CLOSED | `docs/GO_LIVE_RUNBOOK.md:1` still says "v0.30.1 Go-Live Runbook"; no v0.32 banner. |
| `test_recovery_rate.py` / `test_labels_api.py` | NOT CLOSED | Glob `tests/test_recovery_rate*.py` and `tests/test_labels_api*.py` both empty. `monitoring/recovery_rate.py` + `labels/api.py` remain without dedicated tests. |
| Raw `[:10]` truncation: `correlation_stats.py:127` | NOT CLOSED | `addr[:10] + "…" + addr[-6:]` unchanged. |
| Raw `[:10]`: `cex_continuity.py:594` | NOT CLOSED | grep now finds 5 raw `[:10]` hits (711, 716, 728, 739, 743) — line numbers shifted because of wave-4 cross-token parity additions but pattern is intact (and increased from one to five sites). |
| Raw `[:10]`: `output_integrity.py:1332` | NOT CLOSED | Still at `validators/output_integrity.py:1331-1332` (shifted from 1332 → 1331 due to wave-4 INVARIANTS-G/H/I insertions); also a new raw `[:10]` site at line 1626. |
| Raw `[:10]`: `drainer_detection.py:405, 424` | NOT CLOSED | Now at lines 582, 585, 601 — same patterns, `contract_addr[:10]`, `forwarded_to[:10]`. Same drift, same root cause. |
| Raw `[:10]`: `tracer.py:1180` | NOT CLOSED | Shifted to `trace/tracer.py:1270` (`transfer.to_address[:10] + "..."`) due to wave-6 adaptive_depth additions. |

### Round-2 NEW friction (closures verified)

| Item | Status | Evidence |
|---|---|---|
| F-NEW-1 — `RECUPERO_RANDOMIZATION_SECRET` soft-WARN vs hard-required docs | NOT CLOSED | `security/per_case_randomization.py:76-98` — `_resolve_secret` still returns `(_DEV_FALLBACK_SECRET.encode(...), True)` on unset env. No `RuntimeError`. The contradiction with DEV_ONBOARDING.md persists. |
| F-NEW-2 — 5 rollup-canonical bridges missing `_audit_status` | NOT CLOSED | `bridges.json:213-282` — RootChainManager, ERC20Predicate, Arbitrum Inbox, Arbitrum DelayedInbox, zkSync L1ERC20Bridge all carry `confidence:"high"` + `source/notes` but no `_audit_status` line. Pattern mismatch with v0.28.4 audit entries. |
| F-NEW-3 — `/v1/cron/jobs` operator how-to | NOT CLOSED | grep across `docs/` finds `/v1/cron/jobs` only in `DEPLOY_v0_32_0_RUNBOOK.md` + round-2 audit docs. No mention in `README.md`, `DEV_ONBOARDING.md`, no `recupero-ops cron-status` CLI wrapper in `src/recupero/ops/commands/`. |
| F-NEW-4 — `confirm_sha256` how-to-compute | NOT CLOSED | grep `confirm_sha256` across `docs/` shows only `DEPLOY_v0_32_0_RUNBOOK.md` + audit docs. The wave-6 wave-message added `confirm_sha256` to `labels/api.py + labels/auto_ingest.py` but the operator-doc gap is unchanged. |
| F-NEW-5 — `/review-gate` UI `window.prompt()` UX | NOT CLOSED | `web/templates/review_gate.html:253, 256, 257` still calls `prompt(...)` for reviewer email + notes. No inline form, no session-cached reviewer email. |
| F-NEW-6 — `RECUPERO_OPS_ALERT_EMAIL` missing from ENV_VARS.md | **CLOSED** | `docs/ENV_VARS.md:120` now lists the var with `unset` default + `email` validation + v0.27.x added-in stamp. |

### Cross-cutting closure summary

Round-2 had 14 of 19 items at ≥ 90%. Round-3 adds F-NEW-6 closed → **15
of 19 ≥ 90%**. No regressions on the 14 previously closed items
(verified the README rewrite, dev-onboarding doc, operator UI, console
scripts table are all still present). Target 19/19 not hit.

---

## 4. NEW issues from waves 4-6

### F-NEW-7 — `docs/ENV_VARS.md` actively stale on `RECUPERO_API_BUDGET_USD_PER_CASE`

- **Where:** `docs/ENV_VARS.md:78, 370-377`
- **Issue:** Wave 5 → wave 6 changed `_DEFAULT_BUDGET_USD = $0`, `_BUDGET_MAX = $1,000,000` (`observability/api_budget.py:136-138`). ENV_VARS.md still claims default `$0.50`, range `[$0.01, $100.0]`. An operator reading the doc to size their budget sets `RECUPERO_API_BUDGET_USD_PER_CASE=5` thinking "5× the default to cover a deep trace"; under the new code that's still well below `_BUDGET_MAX` so it doesn't get clamped, but the operator's mental model is now wrong by two orders of magnitude on what the default is.
- **Severity:** **HIGH** (active documentation drift on a published env var with operational impact). The .env.example update in wave 6 (line touched but only by appending — verified by grep) does not back-fill `docs/ENV_VARS.md`.

### F-NEW-8 — Wave 6 added 3 env vars (`RECUPERO_TRACE_MAX_HOPS_HARD_CEILING`, `RECUPERO_ADAPTIVE_DEPTH`, `RECUPERO_CASE_THEFT_USD`) without ENV_VARS.md / .env.example entries

- **Where:** `trace/tracer.py:178-220` reads all three; grep across `docs/ENV_VARS.md` and `.env.example` finds zero hits for any of them. `INDUSTRY_BEST_MODE.md` does mention them.
- **Issue:** Round-1 established the pattern: every `RECUPERO_*` env var documented in ENV_VARS.md alphabetical table and reflected in `.env.example`. `test_v031_4_env_vars_doc.py` parity test was put in place to enforce this. Wave 6 went around the parity test (the new vars don't reach `config.py` so the test doesn't flag them — same pattern that masked `RECUPERO_OPS_ALERT_EMAIL` in round-2).
- **Severity:** **MEDIUM** (3 new env vars, one (`RECUPERO_TRACE_MAX_HOPS_HARD_CEILING`) controls a load-bearing safety ceiling).

### F-NEW-9 — Wave 6 `_DEFAULT_BUDGET_USD = $0` removes Tier-1 anti-DoS gate

- **Where:** `observability/api_budget.py:136`
- **Issue:** Pre-wave-6, the per-case budget was the documented Tier-1 anti-DoS gate (`WHY_RECUPERO_WOULD_FAIL.md §1.4` per the file-top docstring claim). Wave 6 disables it by default with rationale "industry-best mode runs without a cap." That's defensible for a $50M case but flips the default failure mode: a runaway tracer on a misbehaving case now burns paid-tier credits silently. An operator who *thought* they had budget tracking now needs to explicitly set `RECUPERO_API_BUDGET_USD_PER_CASE=10000` to get back to wave-5 behavior. The cert checklist + pre-mortem doc still treat budget tracking as the Tier-1 gate.
- **Severity:** **MEDIUM** — defensible architectural choice but unannounced flip of a documented safety default. The mitigation is `RECUPERO_API_BUDGET_USD_PER_CASE=<positive>` in Railway Variables, but that's not yet in the deploy runbook v0.32.1 deltas.

### F-NEW-10 — Wave-4 `test_v032_1_trace_crit_fixes.py` deleted-and-re-added shows -608/+ net

- **Where:** `git log --stat e9a5a66` shows `tests/test_v032_1_trace_crit_fixes.py | 608 ----` (deleted) while `git status` shows the file as `??` (untracked, present on disk).
- **Issue:** Wave 4 deleted the test file in its commit but `git status` shows it's still on disk as an untracked addition. Either the commit was structured incorrectly (file deleted then re-added in a separate uncommitted change), or there's a real test-coverage regression hiding here. Either way the test surface is in a confusing state mid-wave. Same observation for `tests/test_addr_format.py`, `tests/test_bridge_calldata_canonical.py`, `tests/test_cex_continuity_parity.py`, `tests/test_output_integrity_g_h_i.py`, `tests/test_v032_1_security_fixes.py` — all in `git status` as untracked.
- **Severity:** **LOW** (process / hygiene), but the round-1/round-2 narrative cited these tests as evidence for wave closure. If they're untracked at HEAD `d0648f0`, the deploy will not include them unless they're committed before the merge to main.

### F-NEW-11 — `cex_continuity.py` raw `[:10]` count went from 1 → 5

- **Where:** `trace/cex_continuity.py:711, 716, 728, 739, 743` (round-2 only flagged `:594`)
- **Issue:** Wave 4 added new cross-token parity log paths (in the same file) and each new log line copied the existing `addr[:10] + "..."` pattern instead of using the v0.32.1 `short_address` canonical helper. The drift the round-1 cross-cut explicitly called out as the #2 30→90% item is now WORSE than at round-2.
- **Severity:** **LOW** (log strings, not lawyer-visible) but a pattern regression.

---

## 5. Scores

- **LE handoff: 92/100** (round-2: 91). HIGH-8 closed; six round-2 NEW
  open. Target ≥ 95 NOT hit.
- **Freeze letter: 92/100** (round-2: 92). All 4 CRITs still closed; six
  round-2 NEW open. Target ≥ 95 NOT hit.
- **Cross-cutting: 15/19 at ≥ 90%** (round-2: 14/19). F-NEW-6 closed.
  Five new findings (F-NEW-7 HIGH, F-NEW-8 MED, F-NEW-9 MED, F-NEW-10
  LOW, F-NEW-11 LOW) introduced by waves 4-6. Target 19/19 NOT hit.

---

## 6. Honest one-paragraph assessment

Waves 4-6 wrote the round-2 audits but did not close the round-2 NEW
findings the audits surfaced — the highest-impact remaining issue
(NF-1, freeze letter `USD {{ X }}` vs LE `$X,YYY.ZZ` cross-doc
divergence) is a five-minute Jinja-filter migration that has now sat
across three waves without action. Wave 6's "industry-best mode" is the
right architectural call for a $50M-case tracer but it flipped the
documented Tier-1 anti-DoS default to OFF (F-NEW-9) and introduced 3
new env vars without ENV_VARS.md entries (F-NEW-8) and made the
existing ENV_VARS.md docstring on `RECUPERO_API_BUDGET_USD_PER_CASE`
actively wrong (F-NEW-7 — claims $0.50 default / $100 max; reality is
$0 default / $1M max). The template CRITs are all still closed, no
regressions there. F-NEW-6 (env-vars-doc parity for
`RECUPERO_OPS_ALERT_EMAIL`) closed cleanly. The lawyer-credibility
threshold is met for both audited documents; the polish gap that round-2
named is unchanged. A round-4 pass that does (a) the NF-1 freeze-letter
filter migration, (b) F-NEW-7 + F-NEW-8 env-vars doc back-fill, (c) F-NEW-10
test-file commit, would close 6 of the 11 outstanding items in under an
hour of work.

---

*End of round-3 audit. Static-analysis pass; no dynamic render or test
execution.*
