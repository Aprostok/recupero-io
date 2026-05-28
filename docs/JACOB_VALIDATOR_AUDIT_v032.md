# JACOB-style validator audit — output_integrity v0.32.0

**Branch:** `pdf-deliverables` (HEAD `c43be19` on `main`)
**File audited:** `src/recupero/validators/output_integrity.py` (4437 LOC, 41 checks)
**Tests audited:** `tests/test_output_integrity_validator.py` (1004 LOC), `tests/test_output_integrity_deeper.py` (293 LOC), `tests/test_validator_manifest_shape_hardening.py`, `tests/test_validator_safe_load_json_cap.py`

---

## TL;DR — coverage estimate

The validator catches **structural / shape** bugs at high fidelity. It catches **semantic correctness** bugs at low fidelity. Rough coverage of real-world "bad brief" scenarios shipped against an external recipient:

| Category                              | Coverage |
| ------------------------------------- | :------: |
| File-shape / write-path / SHA bugs    |   ~90%   |
| Template cross-fill (issuer routing)  |   ~85%   |
| Cross-issuer-letter consistency       |   ~75%   |
| Recoverable / unrecoverable variant   |   ~80%   |
| **Intra-artifact cross-section sum coherence** |  **~0%** |
| **Brief ↔ freeze-letter token/amount/recipient consistency** | **~10%** |
| **Address ↔ chain ↔ explorer URL coherence**     |  **~0%** |
| **Time-window coherence (incident_time vs transfer.block_time)** | **~0%** |
| **Stale-label / point-in-time render verification** | **~0%** |
| **AI-editorial-claim grounding (prose ↔ structured data)** | **~5%** |
| **Missing required parent-link / disclosure metadata** | **~0%** |

**Bottom-line coverage estimate against the "bad brief that LOOKS fine" failure class: ~30%.** The validator is excellent at "we wrote the wrong bytes to a file"; it is blind to "we wrote bytes that look fine but disagree with each other or with the source case data".

---

## 1. Current INVARIANTS A–F (per-INVARIANT verdict)

The validator runs **41 named checks**. The Jacob-named "INVARIANT" group is checks A–F + F-v0.31 (F–J) + F-v0.32 (review-gate). Each is audited below.

### Check 1 — `filename_content_consistency`
- **Contract:** every `freeze_request_<issuer>_*.html` must contain markers proving it's addressed to that issuer (seed-db email OR domain email OR issuer name in a heading or `Attn:`/`To:` block); LE handoff must mention the issuer name SOMEWHERE.
- **Catches:** the v0.20.15 Midas/Circle template-routing pattern. Good.
- **Misses:**
  - LE-handoff check is a weak substring (`issuer_name in content`) — will pass when a Section 4.2 inventory incidentally lists the issuer even though Section 1 is addressed to a different one. This is intentional per the comment but documented coverage is overstated.
  - No verification that the freeze ask LIST INSIDE the letter matches the brief's `freeze_asks.json` for that issuer (token, amount, chain).

### Check 2 — `html_files_contain_html`
- Strict whitelist of first-token tags. Catches JSON/SVG/CSV being written to `.html` paths. Solid.

### Check 3 — `json_files_parse_as_json`
- Just `json.loads`. Catches `.json` files that contain HTML. Solid.

### Check 4 — `no_duplicate_file_contents`
- byte-identical sha256 collision across `briefs/`. Catches the silent-overwrite pattern. Solid.

### Check 5 — `manifest_sha_matches_disk`
- Constant-time compare of declared `output_sha256` vs disk content. Solid.

### Check 6 — `every_freezable_issuer_has_letters`
- For each `freeze_capability='yes'|'limited'` (or any actionable holding) issuer, BOTH `freeze_request_*` AND `le_handoff_*` must exist.
- **Misses:** issuer-name slug normalization is single source-of-truth via `_normalize_issuer_key`, but the seed-db lookup that resolves slug→issuer name will silently fail on issuers added recently to the brief but not to the issuer DB. Spurious "missing letter" violations possible.

### Check 7 — `total_freezable_usd_reconciles`
- Engagement letter contains the same `${TOTAL_FREEZABLE_USD}` string as the brief.
- **MAJOR MISS:** only checks engagement letter. **Does NOT check LE handoff Section 3 totals vs Section 4 destinations table vs Section 5 freeze asks** — the canonical "the three USD figures in the same artifact don't agree" symptom. The user's example ("$3.6M drained / $3.55M destinations / $4.1M asks") is invisible.

### Check 8 — `stolen_vs_target_issuer_distinct`
- Catches the v0.19.3 "USDT issued by Circle" residual in LE handoff Section 1 ¶1. Solid for the exact pattern; depends on the `<h2>1. Executive Summary` literal text.

### Check 9 — `recoverable_variant_matches_state`
- victim_summary variant (recoverable vs unrecoverable) must match `MAX_RECOVERABLE_USD > 0`. Solid.

### Check 10 — `no_unrendered_jinja_placeholders`
- `{{ ... }}` and `{% ... %}` survival check. Solid.

### Check 11 — `unrecoverable_addresses_not_in_freezable`
- **DOWNGRADED TO WARNING.** Heuristic-only — flags any UNRECOVERABLE address that appears anywhere in a freeze letter (not specifically in the freeze-target block). High false-positive rate by design. **In practice this check never blocks publication** because warnings don't gate `result.ok`.

### Check 12 — `dai_sky_consistency`
- Warning-only. Acceptable as a hint, not a gate.

### Checks 13–27 (Part 5)
- Per-issuer letter title/h1, no foreign-issuer emails, Section 4.2 issuer enumeration, TOTAL_LOSS_USD citation, trace_report marker-leak, engagement_letter biconditional, victim/asset/case_id consistency, recovery_snapshot biconditional.
- Solid for what each claims. None of them check **values** beyond the headline figures. None check freeze-ask token/amount per letter.

### Checks 28–30 (Wave 2)
- Per-artifact size caps, manifest schema lock, orphan detection (info-only). Good defensive layer.

### `unrecoverable_total_matches_holdings`
- Jacob v0.21.x residual — `TOTAL_UNRECOVERABLE_USD` must equal sum of UNRECOVERABLE holdings across `ALL_ISSUER_HOLDINGS`. **This is the kind of cross-section check that should exist for FREEZABLE too, and doesn't.**

### INVARIANT A — `freeze_ask_targets_not_investigate_tagged`
- Zigha 0x52Aa bleed fix. Solid.

### `issuer_letter_backed_by_freezable_row`
- Every freeze_request and le_handoff must have at least one `<span>FREEZABLE</span>` inside a `<tbody>`. Solid; literal-text-dependent.

### INVARIANT B — `destinations_superset_of_ground_truth`
- Opt-in ground_truth.json. Powerful canary when present. **In practice almost never present in production cases** — opt-in fixture not enforced by build_all_deliverables. Confirmed by grep: no shipped `ground_truth.json` files in fixtures other than test fixtures.

### `perpetrator_holdings_reconcile_across_artifacts`
- Trace_report headline = `TOTAL_FREEZABLE_USD + TOTAL_UNRECOVERABLE_USD` within 1% / $100. Solid.

### INVARIANTS C/D/E — `subpoena_targets_*`
- C is `warning` by default (escalates to `high` above $100K). C misses the same intra-artifact sum-coherence issue: it counts coverage but never asks "does the subpoena pdf's '$X total in subpoenas' figure equal the sum of the per-target subpoena amounts?".
- D includes cycle detection (good).
- E correlates files by recipient_slug substring.

### `subpoena_targets_extraction_succeeded`
- v0.28.1 hardening — catches the silent-swallow class.

### INVARIANTS F–J (v0.31.4) — `mev_signals_well_formed`, `indirect_exposure_v031_scores_in_range`, `wallet_clusters_contract`, `cex_continuity_leads_framed`, `decoded_handoffs_consistent`
- All operate on `freeze_brief.json` only — not on rendered HTML.
- All are present-but-malformed checks (missing section = silent skip).
- **Coverage gap:** they validate `freeze_brief.json` shape but do NOT verify that the values flow correctly INTO the rendered artifact. e.g. CEX_CONTINUITY_LEADS is correctly framed `lead_only=True` in the JSON, but a renderer bug could still publish it as "the perpetrator deposited to Binance" prose in the LE handoff — and nothing checks the prose.

### INVARIANT F (v0.32) — `review_gate_approvals_present`
- Mandatory human-review gate. Production-grade.
- **Bypasses (all intentional):**
  - DSN unset → silent skip (local dev).
  - Non-UUID case_id → silent skip (V-CFI01 fixture).
  - Dispatcher module import failure → warning, not critical.
  - DB connection failure → single high (not critical) finding — fails open at the validator layer, but the dispatcher's own gate fails closed at send time.

---

## 2. SEMANTIC GAPS (the things the validator misses)

These are the categories the audit prompt asked me to enumerate. Each is real and can ship today.

### Gap 1 — Intra-artifact cross-section sum coherence
The single biggest hole. The LE handoff can ship with three different USD totals in three sections (Section 3 narrative claim, Section 4 destinations table sum, Section 5 freeze-ask sum) and the validator catches none of them. Same applies to the freeze brief's own TOTAL_FREEZABLE_USD vs `sum(FREEZABLE[*].total_usd)`. The latter is partially checked by `perpetrator_holdings_reconcile_across_artifacts` only for the brief→trace_report path, not within the LE handoff.

### Gap 2 — Brief ↔ per-issuer-letter consistency (token + amount + chain + address)
Check 6 verifies the FILE EXISTS for each freezable issuer. Check 1 verifies it's addressed to that issuer. Nothing verifies:
- Token symbol on the row matches `freeze_brief.FREEZABLE[issuer].holdings[*].token` (e.g. brief says USDC, letter renders USDT).
- Amount matches the brief's holding amount.
- Recipient address in the letter's primary-targets table matches the brief's `holdings[*].address`.
- Chain matches (e.g. brief says Arbitrum, letter renders `etherscan.io` URL — Gap 3 below).

### Gap 3 — Address ↔ chain ↔ explorer URL coherence
The `holdings[*].chain` field per v0.17.4 lets the renderer write the correct explorer URL per chain. **Nothing verifies the rendered URL host matches the declared chain.** A regression that emits `etherscan.io` for an Arbitrum holding ships silently. A handful of templates also hard-code "etherscan" in fallback paths.

### Gap 4 — Stale-data tells (point-in-time labels)
v0.31.2 added `point_in_time` to label lookups, but the validator does not verify that labels rendered into HTML carry a `_resolved_at` timestamp ≤ the case's incident window (or that there's a `pit_at` recorded in the manifest). A brief regenerated six months later with a fresh label cache renders TODAY's labels — and the validator can't tell. Migration 028 (`brief_reviews`) catches the human-approval staleness, but not the label-data staleness.

### Gap 5 — AI-editorial hallucination grounding
`ai_editorial._validate_ai_output` (in `src/recupero/reports/ai_editorial.py`) checks: schema, length caps, forbidden hedging phrases, suspicious HTML, confidence enum. It DOES NOT check:
- Claims-in-prose against structured data. e.g. the AI can write "Coinbase confirmed receipt" in `INCIDENT_NARRATIVE_RECUPERO` and the validator won't notice that no Coinbase letter exists in `briefs/` and no Coinbase row appears in `FREEZABLE`.
- Address mentions in prose against the brief's address set (catches the "AI invented a destination" failure mode).
- Currency / amount mentions in prose against the brief's totals (catches the "AI wrote $3.7M but brief says $3.55M" failure mode).

### Gap 6 — Missing-but-required parent disclosure / metadata link
v0.32 introduced parent recovery-disclosure metadata. The validator has no invariant equivalent to "this brief must reference its parent disclosure ID" — a brief rendered without that linkage ships silently.

### Gap 7 — Freeze ask token-swap / truncation
The brief context's `freeze_asks` and the rendered freeze letter HTML share no enforced contract. A renderer bug that swaps `USDT` for `USDC` (or truncates `1,200,000` to `1,200`) ships silently. The closest existing check (`asset_symbol_consistent_across_artifacts`) only checks brief.asset.symbol against the trace_report + LE handoff, not the per-issuer freeze letter's row token vs the brief's per-holding token.

### Gap 8 — Time-window coherence
`case.transfers` carries `block_time`. `case.incident_at` (or equivalent) defines the incident window. Nothing checks that every transfer the brief reports is AFTER the incident time (or explicitly flagged as pre-incident context). A BFS look-back bug or a wrong-window seed can ship transfers from before the theft.

### Gap 9 — AI-injected JSON malformations
If the model emits malformed JSON the prompt-loop retries (`_call_messages_with_retry`). If the JSON is valid but missing `VICTIM_SUMMARY`, `_validate_ai_output` flags it. **But:** the orchestrator can ALSO fall back to fixture defaults if the AI is configured off. In that case `is_unreviewed_ai_editorial(editorial)` returns True but no integrity invariant fires — the brief ships with a fixture template the operator may have meant to review.

### Gap 10 — Cross-letter address bleed
A perpetrator's address can legitimately appear in multiple per-issuer letters when they hold tokens from multiple issuers. But the validator has no check that the FREEZABLE rows of letter A and letter B aren't byte-identical (duplicate rows across issuers — a real Zigha-shape bug class). `no_duplicate_file_contents` only catches whole-file duplicates.

### Gap 11 — Decoded handoff vs trace narrative
INVARIANT J (`decoded_handoffs_consistent`) validates the JSON shape of CROSS_CHAIN_HANDOFFS. Nothing checks the LE-handoff narrative against it: if the brief says "decoded destination on Solana" but the LE-handoff prose says "we believe the funds went to Tron", the validator is silent.

---

## 3. Proposed new invariants (G, H, …)

In priority order. Each carries a real bug-class motivation and a clear implementation site.

### INVARIANT G (v0.33): `intra_artifact_sum_coherence` — HIGH IMPACT
For every LE handoff and freeze brief, parse the USD figures present in each major section and assert that they reconcile within 1% / $100 absolute (same tolerance as `perpetrator_holdings_reconcile_across_artifacts`). Specifically:
- LE handoff §3 "total drained" ≈ §4 destinations-table-sum ≈ §5 freeze-asks-sum.
- `freeze_brief.TOTAL_FREEZABLE_USD` ≈ `sum(freeze_brief.FREEZABLE[*].total_usd)`.
- Severity: high. Mis-stated totals are the canonical "looks fine, isn't" failure.
- Cost: ~80 LoC + 4 tests.

### INVARIANT H (v0.33): `freeze_ask_brief_letter_token_match` — HIGH IMPACT
For every `freeze_request_<issuer>_*.html`:
1. Extract the FREEZABLE rows (the existing `_FREEZABLE_ROW_RE` already does most of this work).
2. For each row, parse out (address, token-symbol, USD-amount).
3. Match each tuple to `freeze_brief.FREEZABLE[issuer].holdings[*]` and assert the brief's `(address, token, usd)` agrees within tolerance.
- Catches token-swap regressions + amount-truncation + cross-issuer row bleed.
- Severity: critical. Wrong token / wrong amount in a freeze letter is fatal.
- Cost: ~120 LoC + 6 tests.

### INVARIANT I (v0.33): `address_chain_explorer_url_coherence` — MEDIUM-HIGH
Parse every `<a href="https://X/address/0xABC..." >` in every rendered HTML artifact. Map `X` to a chain via a built-in registry (`etherscan.io`→ethereum, `arbiscan.io`→arbitrum, `basescan.org`→base, `bscscan.com`→bsc, `polygonscan.com`→polygon, `optimistic.etherscan.io`→optimism, `tronscan.org`→tron, `solscan.io`→solana, etc.). Cross-check against the brief's `holdings[*].chain` for that address.
- Catches the "Arbitrum USDC rendered with Etherscan URL" cross-chain wiring bug.
- Severity: high.
- Cost: ~60 LoC + chain→host registry + 4 tests.

### INVARIANT J (v0.33): `time_window_coherence` — MEDIUM
Walk `case.transfers` (load from `case.json` if present). For each, require `block_time >= case.incident_at` OR `is_pre_incident_context=True` flag on the transfer. Surface a HIGH violation listing the N pre-incident transfers if any are present without the flag.
- Catches BFS look-back regressions and wrong-window seeds.
- Severity: high.
- Cost: ~40 LoC + 3 tests. Requires `case.json` schema confirmation.

### INVARIANT K (v0.33): `ai_editorial_prose_grounding` — MEDIUM (high false-positive risk; ship as WARNING first)
Scan the AI-drafted narrative fields (`INCIDENT_NARRATIVE_RECUPERO`, `INCIDENT_NARRATIVE_FIRST_PERSON`, `VICTIM_SUMMARY`). For each:
- Extract every 0x-prefix address mention → assert it's in the brief's address set.
- Extract every `$<n>` USD mention → assert it's within 5% of either `TOTAL_FREEZABLE_USD`, `TOTAL_LOSS_USD`, `MAX_RECOVERABLE_USD`, or any `FREEZABLE[*].total_usd` / `holdings[*].usd`.
- Extract every named issuer mention → assert it appears in `ALL_ISSUER_HOLDINGS`.
- Severity: warning at first (will have false positives — "the perpetrator received approximately $3.6M" is legitimately fuzzy). Promote to high after one release cycle of false-positive triage.
- Cost: ~150 LoC + 8 tests.

### INVARIANT L (v0.33): `parent_disclosure_link_present` — LOW-MEDIUM
Every customer-facing artifact (HTML+PDF) emitted under v0.32+ must reference the parent recovery-disclosure case in the manifest (`manifest.recovery_disclosure_id` or `manifest.case_lineage`). Skip when the brief case lacks the disclosure model (legacy cases).
- Catches the "brief rendered without the v0.32 disclosure metadata" omission.
- Severity: high.
- Cost: ~30 LoC + 2 tests. Requires manifest schema bump.

### INVARIANT M (v0.33): `label_pit_consistency` — MEDIUM
Every rendered artifact that quotes an address label (compliance contact, exchange-deposit tag, mixer flag) must derive from a label whose `valid_at <= case.incident_window_end`. Implementation: emit a `_resolved_at` timestamp per rendered label into a sidecar `briefs/label_pit_audit.json`; validator asserts every timestamp ≤ incident window.
- Catches the "brief regenerated six months later picks up updated labels" pattern.
- Severity: warning (initially) — label drift is sometimes desirable (an exchange was misclassified, now correctly tagged).
- Cost: ~70 LoC + sidecar emit + 4 tests.

### INVARIANT N (v0.33): `cross_letter_row_dedup` — LOW
Hash each `(address, token, amount)` FREEZABLE-row tuple across ALL freeze letters. If the same tuple appears in letters for >1 distinct issuer, that's the same perpetrator address routed to multiple issuer letters incorrectly — surface as high.
- Catches a narrow Zigha-shape bleed pattern not covered by INVARIANT A.
- Severity: high.
- Cost: ~30 LoC + 2 tests.

**Recommended ship-order:** G → H → I → J → L. (K and M ship as warning-only; N is small and can ride along.)

---

## 4. Bypass audit — gaps in the existing INVARIANTS

### 4.1 — Catch-all `except Exception` in the check loop
`validate_case_output()` lines 433–443 wraps each check in `try/except Exception` → converts to a WARNING violation. **This means any check whose body raises ALWAYS downgrades to warning, regardless of its declared severity.** A regression that causes `_check_filename_content_consistency` to raise on every case would emit a non-blocking warning and the brief would ship.

- **Intentional?** Yes per the comment "Crashes are caught + reported as violations so a check bug never breaks the whole report."
- **Recommendation:** ACCEPT for most checks (the design rationale holds). But for the v0.32 INVARIANT F (review-gate) the crash-becomes-warning path is a real bypass — a programming error in the dispatcher import would silently disable the mandatory human-review gate. Recommend a small carve-out: review-gate crashes promote to critical.

### 4.2 — INVARIANT F skip paths (review-gate)
Three intentional skips:
1. `SUPABASE_DB_URL` unset → skip with `log.info`. **Bypassable** by an operator running `validate_case_output` in a forgotten shell with the env var unset. The dispatcher itself uses the same skip pattern, so the gate is genuinely off in dev.
2. Non-UUID case_id → skip. Test fixtures like `V-CFI01` use this. **Bypassable** by a malformed production case_id. Severity of false-negative: medium (case won't reach production with a non-UUID id because the worker requires UUID coercion upstream).
3. Dispatcher import failure → single WARNING violation. **Bypassable** by a corrupt install. Severity: low (an install corrupt enough to break this would fail elsewhere louder).
4. DB connection failure → single HIGH (not critical) violation. `result.ok` requires no critical/high violations, so this DOES block. Acceptable.

### 4.3 — `_safe_load_json` returns None on wrong top-level shape
Lines 458–483. A `freeze_brief.json` whose top-level is a list (not dict) silently returns None → all downstream checks that gate `if not freeze_brief` skip. **The brief itself is hosed but the validator reports nothing.**
- Intentional? Partially. The validator can't sensibly run checks on a list.
- Recommendation: emit a single CRITICAL `freeze_brief_wrong_shape` violation when `freeze_brief.json` exists but loads to non-dict. Currently no such violation surfaces.

### 4.4 — `_check_recoverable_variant_matches_state` falls back to `TOTAL_FREEZABLE_USD`
Line 1101: `_parse_usd_string(freeze_brief.get("MAX_RECOVERABLE_USD") or freeze_brief.get("max_recoverable_usd") or freeze_brief.get("TOTAL_FREEZABLE_USD") or "0")`. **A case with no `MAX_RECOVERABLE_USD` defined but a `TOTAL_FREEZABLE_USD` value will be treated as recoverable.** This is a Jacob v0.15.1-shape inverse: misuse of the freezable-pool figure as if it were the recoverable figure. The check itself can mis-classify the variant.
- Severity: medium-high.
- Recommendation: drop the fallback. A brief without `MAX_RECOVERABLE_USD` should violate, not silently coerce.

### 4.5 — `_check_total_freezable_usd_reconciles` only checks engagement letter
Line 1015–1031. The most powerful cross-artifact reconciliation only checks one artifact. The LE handoff is exempt. The trace report is exempt. The freeze brief vs `sum(FREEZABLE[*].total_usd)` is exempt.
- Severity: high.
- Recommendation: this becomes INVARIANT G.

### 4.6 — Check 11 downgraded to WARNING
`_check_unrecoverable_not_in_freezable` is warning-only. Never blocks publication.
- Intentional (heuristic). Accept.

### 4.7 — Subpoena INVARIANT C downgraded to warning below $100K
Below the threshold a Zigha-shape silently-empty subpoena coverage gap surfaces only as a warning. Above $100K it's a high.
- Recommendation: in production cases the threshold is reasonable but consider promoting to high above $10K instead of $100K. A $50K dormant DAI gap is still externally embarrassing.

### 4.8 — INVARIANT E correlation uses substring prefix-match
Line 3216–3225. `subpoena_target_*.html` files are matched to brief targets by `recipient_slug` substring prefix (first 40 chars). **Two targets with similar slugs** (e.g. `coinbase-prime` and `coinbase-prime-eu`) where one file is missing and another has a hash-suffix variant could falsely match.
- Severity: low (narrow corner case).

### 4.9 — Ground-truth fixture is opt-in
INVARIANT B fires only when `case_dir/ground_truth.json` exists. No production case has this fixture; almost no operator workflow creates one.
- Recommendation: auto-generate a minimal ground_truth.json for every case from the worker's `expected_destinations` field (if present) so INVARIANT B is on by default for cases that have any expectations curated upstream.

### 4.10 — INVARIANTS F–J skip silently on missing sections
By design — every v0.31.x section is optional. **But:** a regression that causes `emit_brief` to drop the MEV_SIGNALS section silently would land as "no violations" rather than "MEV section unexpectedly absent."
- Recommendation: add a v0.31.x "section was expected but is missing" check that fires when `case.json` indicates MEV/clustering ran but the corresponding brief section is absent.

---

## 5. Top 5 by impact (recommended ship order)

| Rank | Invariant | Catches | Cost |
| ---: | --------- | ------- | ---- |
| 1 | **G — intra_artifact_sum_coherence** | The user's example case ($3.6M / $3.55M / $4.1M disagreement). Single biggest semantic blind spot. | ~80 LoC + 4 tests |
| 2 | **H — freeze_ask_brief_letter_token_match** | Token swap, amount truncation, cross-issuer row bleed. Highest fatal-bug surface. | ~120 LoC + 6 tests |
| 3 | **I — address_chain_explorer_url_coherence** | Arbitrum-USDC rendered with Etherscan URL family. | ~60 LoC + 4 tests |
| 4 | **G' — `_safe_load_json` wrong-shape critical** (bypass fix 4.3) | The "freeze_brief.json is a list" silent skip. | ~15 LoC + 1 test |
| 5 | **L — parent_disclosure_link_present** | v0.32 disclosure-link omission. | ~30 LoC + 2 tests |

---

## 6. Honest stance

The validator's first 30 checks are excellent at structural integrity. They are also Jacob-style "we already shipped this bug once, never again" tests — every named check has a specific bug it was added to catch. That makes the validator a great regression guard for the bugs we know about.

It is **not** a great guard against the bugs we DON'T know about, because every existing check is shape-based. The classes of bugs the audit prompt asks about (cross-section sum disagreement, brief↔letter consistency, chain↔URL coherence, AI hallucination) are semantic-correctness classes the validator was never designed for.

**Two specific bypasses worry me more than the others:**
1. **Bypass 4.3** (`_safe_load_json` returns None on a list-shaped brief, then every downstream check silently skips) is a real production-shipping bypass. A corrupted brief ships with zero validator findings. Fix is trivial.
2. **Check 7** only checking the engagement letter is a category mistake — the test name is `total_freezable_usd_reconciles` but the implementation is `_only_checks_one_artifact_for_one_format_of_the_number`. Fix is INVARIANT G.

INVARIANT D (`subpoena_targets_depends_on_resolves`) does fire in practice — production cases have non-trivial subpoena DAGs and the cycle-detection added in v0.28.3 found a real cycle once in the test fixtures. INVARIANT B is the one that "technically present but never actually fires" — no production case ships a `ground_truth.json` today.

**Coverage estimate against the "bad brief that looks fine" failure class: ~30%.** Adding INVARIANTS G, H, I, J brings that to ~70%. K and M (AI grounding, point-in-time labels) get the next ~10-15%. The last ~15% is genuinely hard (semantic prose correctness) and probably requires LLM-as-judge or a stronger structured-data contract from the AI editorial layer.

---

## Files referenced

Absolute paths on this worktree:

- Validator source: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\validators\output_integrity.py`
- Primary tests: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\tests\test_output_integrity_validator.py`
- Deeper tests: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\tests\test_output_integrity_deeper.py`
- Manifest hardening tests: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\tests\test_validator_manifest_shape_hardening.py`
- JSON-cap tests: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\tests\test_validator_safe_load_json_cap.py`
- AI editorial validator: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\reports\ai_editorial.py` (`_validate_ai_output`, line 938)
- Dispatcher review-gate: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\dispatcher\review_gate.py`
- Freeze brief emitter: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\reports\emit_brief.py` (per-holding shape at line 772)
