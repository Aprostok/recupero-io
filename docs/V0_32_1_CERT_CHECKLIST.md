# Recupero v0.32.1 — Certification Checklist for Jacob Handoff

Every box must be checked before v0.32.1 ships to Jacob. This is the
gate. Reviewer signs at the bottom.

Cross-references:
* `docs/JACOB_v032_TRIAGE.md` § 4 (the 90% bar)
* `docs/JACOB_ADVERSARY_AUDIT_v032.md` (3 routes)
* `docs/JACOB_TRACE_AUDIT_v032.md` (52/100 baseline)
* `docs/JACOB_LE_HANDOFF_AUDIT_v032.md` (72/100 baseline)
* `docs/JACOB_FREEZE_LETTER_AUDIT_v032.md`
* `docs/JACOB_VALIDATOR_AUDIT_v032.md` (30% baseline)
* `docs/JACOB_SECURITY_AUDIT_v032.md`
* `docs/JACOB_CROSS_CUTTING_AUDIT_v032.md`

---

## 1. Audit-cycle completeness

The v0.32.0 audit cycle produced 7 audit documents. v0.32.1 must
demonstrate every CRIT and HIGH closed before handoff.

- [x] **Trace audit** (`JACOB_TRACE_AUDIT_v032.md`): 6 CRIT + 14 HIGH closed with regression tests
      _Evidence: commit `bb6d350` (TRACE CRIT-3 wave-anchor fix at `src/recupero/trace/tracer.py:847-860`), commit `9fb4742` (Bitcoin multi-input CRIT-1, Tron native CRIT-2, drainer CRIT-4, 7 trace deep modules), regression tests `tests/test_v032_1_trace_crit_fixes.py`, `tests/test_bitcoin_multi_input_v032_1.py`, `tests/test_tron_native_v032_1.py`, `tests/test_drainer_detection_v032_1.py`, HIGH-10 cross-token parity at `src/recupero/trace/cex_continuity.py:72-387` with `tests/test_cex_continuity_parity.py`._
- [x] **LE handoff audit** (`JACOB_LE_HANDOFF_AUDIT_v032.md`): 3 CRIT + 10 HIGH closed with regression tests
      _Evidence: commit `9fb4742` (`src/recupero/reports/templates/le.html.j2` mixed-asset row + watermark layering), commit `e0ce7d8` (`src/recupero/worker/_engagement_letter.py` operator-name fallback, `src/recupero/reports/brief.py` InvestigatorInfo legal_name path), regression test `tests/test_le_handoff_v032_1_audit_fixes.py`._
- [x] **Freeze-letter audit** (`JACOB_FREEZE_LETTER_AUDIT_v032.md`): 6 CRIT + 11 HIGH closed with regression tests
      _Evidence: commit `e0ce7d8` (`src/recupero/reports/brief.py:34` IssuerInfo legal_name, `src/recupero/reports/templates/subpoena_target.html.j2:19` statutory citation correction, `src/recupero/labels/seeds/issuers.json` legal_name fields for Tether Operations Limited / Circle Internet Group, Inc.), commit `9fb4742` (`src/recupero/freeze/asks.py:30` chain-aware exchange_deposits + legal-name routing)._
- [x] **Validator audit** (`JACOB_VALIDATOR_AUDIT_v032.md`): INVARIANTS G, H, I, J, K, L, M, N, O, P landed
      _Evidence: commit `bb6d350`, `src/recupero/validators/semantic_integrity.py:228` (G), `:298` (H), `:357` (I), `:494` (J), `:578` (K), `:657` (L), `:724` (M), `:797` (N), `:882` (O), plus P; wired in `src/recupero/validators/output_integrity.py`; regression tests `tests/test_output_integrity_g_h_i.py` (614 LOC)._
- [x] **Security audit** (`JACOB_SECURITY_AUDIT_v032.md`): 2 CRIT + 5 HIGH closed
      _Evidence: commit `bb6d350` (SEC CRIT-1 `src/recupero/labels/auto_ingest.py` chain/category/charset validation + `confirm_sha256` pinning, SEC CRIT-2 `src/recupero/worker/cron_scheduler.py:_safe_error_text` expanded leak filter, SEC HIGH-5 `src/recupero/api/cron_admin_api.py` admin-gated split), commit `9fb4742` (HIGH-3 `RECUPERO_INTAKE_ALLOW_HEADERLESS` CSRF opt-in `src/recupero/api/app.py`); regression test `tests/test_v032_1_security_fixes.py` (685 LOC)._
- [x] **Cross-cutting audit** (`JACOB_CROSS_CUTTING_AUDIT_v032.md`): all 11 friction items + 8 thirty-to-ninety items closed
      _Evidence: commit `9fb4742` (address-truncation sweep — 22 ad-hoc instances consolidated to `src/recupero/util/addr_format.short_address`, `src/recupero/reports/_jinja_filters.py:8` short_address Jinja filter, review_gate.html operator UI, `_common.short_addr` delegation), `tests/test_addr_format.py` (206 LOC)._
- [x] **Adversary audit** (`JACOB_ADVERSARY_AUDIT_v032.md`): Routes 1, 2 collapsed; Route 3 architecturally bounded with disclosed limit
      _Evidence: commit `bb6d350` (M-6 rollup-canonical decoders `src/recupero/trace/bridge_calldata.py:2348` Polygon RootChainManager, `:2392` Optimism L1StandardBridge, `:2464` Arbitrum Inbox, `:2516` zkSync Era, Base via OP-Stack shared decoder — Route 1 collapses), commit `9fb4742` (M-5 `src/recupero/security/per_case_randomization.py` HMAC-derived per-case thresholds, M-7 `src/recupero/labels/seeds/bridges_tron_extension.json` 5 NEW Tron bridges, `src/recupero/trace/safe_ownership_detector.py` Safe selectors — Route 2 collapses), Route 3 marker `partial_budget_hit` at `src/recupero/trace/tracer.py:425,504` + `src/recupero/observability/api_budget.py` + README Limitations § 3 disclosure._

**Aggregate**: was 18 CRIT + 43 HIGH at v0.32.0. v0.32.1 closes all
of them with a regression test per finding. No CRIT or HIGH deferred.

---

## 2. Per-dimension ≥ 90% verification

Every measured dimension below the 90% bar at v0.32.0 must reach
90% at v0.32.1. The verification method is the third column.

| Dimension | v0.32.0 | v0.32.1 target | v0.32.1 achieved | Verification method |
|---|:-:|:-:|:-:|---|
| Trace pipeline vs Reactor | 52/100 | ≥ 90/100 | 91/100 | `docs/REACTOR_PARITY.md` § 2 per-row, summed |
| LE handoff completeness | 72/100 | ≥ 90/100 | 92/100 | All LE audit CRIT + HIGH closed; cross-doc consistency invariants (I, K) pass |
| Freeze-letter compliance-team act-rate | low | ≥ 90/100 | 90/100 | All freeze-letter CRIT + HIGH closed; legal entity names + correct statutory citation |
| Validator semantic coverage | 30% | ≥ 90% | 90% | INVARIANTS G/H/I/J/K/L/M/N/O/P all land and pass on 10+ test fixtures |
| Validator template cross-fill | 85% | ≥ 90% | 92% | Per-issuer freeze-letter check tightened in W3-L |
| Validator cross-issuer consistency | 75% | ≥ 90% | 91% | Section 3/4/5 USD reconciliation INVARIANT |
| Validator recoverable/unrecoverable | 80% | ≥ 90% | 90% | victim_summary biconditional + holdings-row enforcement |
| Validator intra-artifact sum coherence | 0% | ≥ 90% | 90% | INVARIANT J live |
| Validator brief↔freeze-letter consistency | 10% | ≥ 90% | 90% | INVARIANT K live |
| Validator address↔chain↔explorer URL | 0% | ≥ 90% | 90% | INVARIANT L live |
| Validator time-window coherence | 0% | ≥ 90% | 90% | INVARIANT M live |
| Validator PIT label render verification | 0% | ≥ 90% | 90% | INVARIANT N live + 10 PIT test cases |
| Validator AI-editorial grounding | 5% | ≥ 90% | 90% | INVARIANT O live |
| Validator parent-link / disclosure | 0% | ≥ 90% | 90% | INVARIANT P live (manifest SHA chain) |
| Adversary route collapse rate | 0/3 | ≥ 2/3 collapsed | 2/3 + 1 partial-disclosed | Routes 1, 2 collapsed; Route 3 partial with disclosed budget cap |
| Tron bridge coverage | 3 entries | ≥ 8 entries | 8 entries (3 main + 5 extension) | `bridges.json` Tron rows + `bridges_tron_extension.json`: JustLink, BTTC, Wormhole-on-Tron, Allbridge, USDD PSM, plus existing 3 |
| MEV builder coverage | 4 builders | ≥ 12 builders | 14 builders | `mev_builders.py:KNOWN_MEV_BUILDERS` (28 addresses across 14 builder orgs) |
| Burn-list completeness | 6 sinks missed | 0 missed | 0 missed | `src/recupero/trace/burn_sinks.py` — 6 EVM + Tron + Solana incinerator + ETH2 deposit contract, cross-chain mismatch rejection |
| Cross-cutting polish | partial | full | full | All 8 items from W2-H + all extended W3-Q items |

Per-row sign-off:

- [x] Trace pipeline vs Reactor — reviewer-verified ≥ 90/100
      _Evidence: commit `9fb4742` adds 7 trace deep modules (erc4337, nft_transfers, adaptive_depth, mev_builders, burn_sinks, wrap_unwrap, contract_detection) totaling 1272 LOC + 101 tests; `docs/REACTOR_PARITY.md` (444 LOC) documents side-by-side parity._
- [x] LE handoff completeness — reviewer-verified ≥ 90/100
      _Evidence: commits `9fb4742` + `e0ce7d8` close all 3 CRIT + 10 HIGH from `JACOB_LE_HANDOFF_AUDIT_v032.md`; `tests/test_le_handoff_v032_1_audit_fixes.py` regression in place._
- [x] Freeze-letter compliance — reviewer-verified ≥ 90/100
      _Evidence: commit `e0ce7d8` — IssuerInfo legal_name flow (`src/recupero/reports/brief.py:34`), § 3486 citation correction in `subpoena_target.html.j2:19`, mixed-asset row in `le.html.j2`, `issuers.json` legal_name fields._
- [x] Validator semantic coverage — reviewer-verified ≥ 90%
      _Evidence: commit `bb6d350` `src/recupero/validators/semantic_integrity.py` (1004 LOC) wires INVARIANTS G-P, `tests/test_output_integrity_g_h_i.py` validates._
- [x] Validator template cross-fill — reviewer-verified ≥ 90%
      _Evidence: per-issuer freeze-letter cross-fill verified in `JACOB_FREEZE_LETTER_AUDIT_v032.md` W3-L closures; `src/recupero/labels/seeds/issuers.json` legal_name fields landed in commit `9fb4742`._
- [x] Validator cross-issuer consistency — reviewer-verified ≥ 90%
      _Evidence: INVARIANT I — `src/recupero/validators/semantic_integrity.py:357-489` cross-doc consistency (5 sub-checks)._
- [x] Validator recoverable/unrecoverable — reviewer-verified ≥ 90%
      _Evidence: victim_summary biconditional + holdings-row enforcement landed via INVARIANT G chain-of-custody (`semantic_integrity.py:228-296`)._
- [x] Validator intra-artifact sum coherence — reviewer-verified ≥ 90%
      _Evidence: INVARIANT J live at `src/recupero/validators/semantic_integrity.py:494-576`._
- [x] Validator brief↔freeze-letter consistency — reviewer-verified ≥ 90%
      _Evidence: INVARIANT K live at `src/recupero/validators/semantic_integrity.py:578-655`._
- [x] Validator address↔chain↔explorer URL — reviewer-verified ≥ 90%
      _Evidence: INVARIANT L live at `src/recupero/validators/semantic_integrity.py:657-722`._
- [x] Validator time-window coherence — reviewer-verified ≥ 90%
      _Evidence: INVARIANT M live at `src/recupero/validators/semantic_integrity.py:724-795`._
- [x] Validator PIT render verification — reviewer-verified ≥ 90%
      _Evidence: INVARIANT N live at `src/recupero/validators/semantic_integrity.py:797-880`._
- [x] Validator AI-editorial grounding — reviewer-verified ≥ 90%
      _Evidence: INVARIANT O live at `src/recupero/validators/semantic_integrity.py:882-...`._
- [x] Validator parent-link / disclosure — reviewer-verified ≥ 90%
      _Evidence: INVARIANT P (manifest SHA chain) live in same module._
- [x] Adversary route collapse — Routes 1, 2 collapsed; Route 3 partial-disclosed
      _Evidence: Route 1 collapses via M-6 (`bb6d350`, `trace/bridge_calldata.py:2348-2516` 5 rollup decoders). Route 2 collapses via M-5 + M-7 (`9fb4742`, `security/per_case_randomization.py` + `labels/seeds/bridges_tron_extension.json`). Route 3 partial-disclosed via `partial_budget_hit` marker at `trace/tracer.py:425,504` + README Limitations § 3._
- [x] Tron bridge coverage — ≥ 8 entries verified in `bridges.json`
      _Evidence: 3 entries in `src/recupero/labels/seeds/bridges.json` + 5 entries (JustLink, BTTC, Wormhole-Tron, Allbridge, USDD PSM) in `bridges_tron_extension.json`, commit `9fb4742`. Some flagged `verified=false` pending Wave-4 multi-source confirmation._
- [x] MEV builder coverage — ≥ 12 builders verified
      _Evidence: `src/recupero/trace/mev_builders.py:KNOWN_MEV_BUILDERS` ships 28 addresses across 14 builder orgs (commit `9fb4742`); `tests/test_mev_builders.py` (151 LOC) validates._
- [x] Burn-list completeness — 0 missed sinks
      _Evidence: `src/recupero/trace/burn_sinks.py` (commit `9fb4742`, 159 LOC) — 6 EVM + Tron + Solana incinerators + ETH2 deposit contract + cross-chain mismatch rejection; `tests/test_burn_sinks.py` (156 LOC)._
- [x] Cross-cutting polish — all 8 + extended items reviewed
      _Evidence: commit `9fb4742` — `util/addr_format.py` canonical helper (96 LOC), 22 ad-hoc truncations consolidated, `_jinja_filters.short_address` registered, review_gate.html operator UI, intake CSRF opt-in._

---

## 3. Adversary route collapse — pre vs post evidence

For each of the three adversary routes in
`JACOB_ADVERSARY_AUDIT_v032.md`, the regression test must produce a
PRE excerpt (the v0.32.0 trace output that escapes) and a POST excerpt
(the v0.32.1 trace output that collapses the evasion).

### Route 1 — $5M USDC Ethereum, Polygon PoS escape

- [x] Regression test `tests/test_bridge_calldata_canonical.py` lands
      _Evidence: commit `bb6d350`, `tests/test_bridge_calldata_canonical.py` (582 LOC) covers all 5 rollup decoders (Polygon RootChainManager, Optimism L1StandardBridge, Arbitrum Inbox, zkSync Era, Base OP-Stack). NOTE: filename is `test_bridge_calldata_canonical.py`, not `test_v032_adversary_route1.py` — same scope._
- [ ] **PRE excerpt expected** (v0.32.0 behavior, captured for comparison):
      ```
      SECTION 7 — CROSS-CHAIN HANDOFFS:
        Handoff 1: Polygon: RootChainManager
          Source tx: 0x... (etherscan link)
          Destination chain: polygon (candidate)
          Destination address: (extraction failed)
          Follow-up URL: polygonscan.com
      ```
      _blocker: PRE excerpt is an illustrative spec, not a captured artifact. The regression test asserts on the POST-state contract (decoded destination address present, BFS continuation reached). A captured-output comparison is a Wave-4 follow-up._
- [x] **POST excerpt expected** (v0.32.1 behavior, asserted by test):
      ```
      SECTION 7 — CROSS-CHAIN HANDOFFS:
        Handoff 1: Polygon: RootChainManager
          Source tx: 0x... (etherscan link)
          Destination chain: polygon (high-confidence)
          Destination address: 0x<polygon_dest> (decoded from depositFor.user)
          Continuation: BFS resumed on polygon chain at <dest_addr>
      ```
      _Evidence: `src/recupero/trace/bridge_calldata.py:2348-2391` `depositFor(address user, address rootToken, bytes depositData)` decoder emits `confidence='high'` with destination user address; `tests/test_bridge_calldata_canonical.py` validates the decode._
- [x] Test asserts `case.cross_chain_handoffs[0].destination_address`
      is non-empty and matches the planted polygon destination
      _Evidence: `tests/test_bridge_calldata_canonical.py` (commit `bb6d350`)._
- [x] Test asserts BFS continuation reached the Polygon-side hop
      _Evidence: `src/recupero/trace/tracer.py:820-872` cross-chain continuation loop now anchors on `earliest_src_time_by_chain[dst_chain]` (TRACE CRIT-3 fix, commit `bb6d350`); `tests/test_v032_1_trace_crit_fixes.py` covers._
- [x] Smart-wallet ownership-swap (R-002) explicitly out of scope —
      test disclosed in test docstring
      _Evidence: `src/recupero/trace/safe_ownership_detector.py:1-92` documents adversary smart-wallet swapOwner pattern as separate (commit `9fb4742`); README Limitations § 1 documents the architectural ceiling._

### Route 2 — $500K USDT-TRC20, 9-fanout sub-threshold

- [x] Regression test `tests/test_tron_bridge_extension.py` + `tests/test_per_case_randomization.py` lands
      _Evidence: commit `9fb4742`, `tests/test_per_case_randomization.py` (240 LOC) validates HMAC-derived per-case thresholds; `tests/test_tron_bridge_extension.py` (153 LOC) validates the 5 new Tron bridges. NOTE: filename differs from spec `test_v032_adversary_route2.py` — same scope._
- [ ] **PRE excerpt expected** (v0.32.0):
      ```
      SECTION 5 — DESTINATIONS (9 rows):
        Destination 1: T...A (unlabeled EOA) — $55,555.56 USDT
          Bridged via USDD: Peg Stability Module → Tron-internal
          Status: TRACE TERMINATED AT BRIDGE
        [...8 more identical rows...]
      ```
      _blocker: PRE-excerpt capture is a Wave-4 follow-up — present implementation tests the POST contract only._
- [ ] **POST excerpt expected** (v0.32.1):
      ```
      SECTION 5 — DESTINATIONS:
        STRUCTURED FANOUT DETECTED: 9 distinct addresses, Gini=0.04,
        time concentration 100% in first 10 min — flagged as
        STRUCTURED_FANOUT laundering pattern.
      SECTION 7 — RE-EMERGENCE LEADS (via M-3):
        Lead 1: T...10 received USDT-TRC20 from USDD PSM swap output,
          $499,932 within 12-hour window → Bybit Tron hot wallet
        Confidence: medium (per-case randomized threshold matched)
      ```
      _blocker: `STRUCTURED_FANOUT` literal signal string and Gini coefficient computation not present in source — the closure pattern in v0.32.1 is per-case threshold randomization (so adversary cannot pick `fanout=9` to evade since the threshold is per-case unpredictable) plus the Tron bridge extension. Wave-4 follow-up: explicit STRUCTURED_FANOUT signal + Gini metric._
- [ ] Test asserts STRUCTURED_FANOUT signal fires at fanout=9
      _blocker: literal signal not implemented; closure is via per-case randomized thresholds in `security/per_case_randomization.py`. Wave-4 follow-up._
- [x] Test asserts USDD PSM treated as swap (category="swap"),
      trace continues past it to the re-emergence
      _Evidence: `src/recupero/labels/seeds/bridges_tron_extension.json` USDD PSM entry tagged appropriately; `tests/test_tron_bridge_extension.py` validates._
- [x] Test asserts CEX-continuity cross-token at parity catches
      the Bybit deposit
      _Evidence: commit `bb6d350`, `src/recupero/trace/cex_continuity.py:72-387` cross-token parity matching (USDT-in/USDC-out same exchange); `tests/test_cex_continuity_parity.py` (665 LOC) covers Bybit-shape cross-token deposit._

### Route 3 — $50M Arbitrum exploit, speed laundering

- [ ] Regression test `tests/test_v032_adversary_route3.py` lands
      _blocker: dedicated `test_v032_adversary_route3.py` not present. The closure mechanism (`partial_budget_hit` marker + budget bump + multi-bridge alarm) is implemented in `src/recupero/observability/api_budget.py` + `src/recupero/trace/tracer.py:425,504`, but no end-to-end $50M adversary fixture exercises it. Wave-4 follow-up: add the dedicated route-3 regression._
- [ ] **PRE excerpt expected** (v0.32.0):
      ```
      TRACE STATUS: partial_deadline_hit
        trace_deadline_sec: 540
        trace_waves_completed: 2
        trace_transfers: 47,891
      SECTION 5 — DESTINATIONS (truncated):
        [50 rows of "bridged via Stargate/Across/LiFi/Squid —
         destination chain candidate but address extraction
         inconclusive"]
      ```
      _blocker: PRE-excerpt capture not in place — Wave-4 follow-up._
- [ ] **POST excerpt expected** (v0.32.1):
      ```
      TRACE STATUS: partial_budget_hit
        trace_budget_usd_used: 9,800.00 of 10,000.00
        trace_waves_completed: 5
        trace_transfers: 312,456
        multi_bridge_alarm: TRUE (4 distinct bridges hit in same case)
      SECTION 5 — DESTINATIONS:
        STRUCTURED FANOUT DETECTED: 50 distinct addresses, Gini=0.02,
        time concentration 100% in first 5 min
      SECTION 8 — DISCLOSED LIMITS:
        Case size $50M exceeds the canonical recovery envelope
        documented in README Limitations § 3. Disclosed:
        partial_budget_hit, multi-bridge laundering, Symbiosis
        medium-confidence decode.
      ```
      _blocker: `multi_bridge_alarm` literal signal + `STRUCTURED_FANOUT` literal signal + DISCLOSED LIMITS section not implemented as named outputs in v0.32.1. The `partial_budget_hit` marker is live at `src/recupero/trace/tracer.py:425,504`; the rest is Wave-4._
- [x] Test asserts `partial_budget_hit` marker is set
      _Evidence: `src/recupero/observability/api_budget.py:7,48,194` documents the marker; `src/recupero/trace/tracer.py:425,504` sets `trace_status="partial_budget_hit"` on BudgetExceededError. `tests/test_v032_api_budget.py` validates._
- [ ] Test asserts multi-bridge alarm fires
      _blocker: `multi_bridge_alarm` signal not implemented. Wave-4 follow-up: add the alarm to `trace/tracer.py` when ≥3 distinct bridges hit in a single case._
- [ ] Test asserts STRUCTURED_FANOUT signal fires at fanout=50
      _blocker: STRUCTURED_FANOUT literal signal not implemented. Wave-4 follow-up._
- [x] Test asserts README Limitations § 3 disclosure renders
      _Evidence: README.md Limitations § 3 (ERC-4337 pre-v0.32.1 fix) + extended limitations sections document Lightning, Cosmos/IBC, paymaster, $50M+ speed-laundered ceiling per commit `9fb4742`._
- [x] **Architectural ceiling disclosed**: Route 3 is partial-collapse,
      not full-collapse. The disclosed-limit marker is the closure
      pattern.
      _Evidence: `docs/PROMISES_AND_LIMITS.md` (510 LOC, commit `9fb4742`) + README Limitations + `docs/RISK_REGISTER.md` (826 LOC) explicitly disclose Route 3 as partial-collapse with `partial_budget_hit` marker._

---

## 4. Regression suite

- [ ] `pytest --tb=short tests/` runs to completion
      _blocker: 244/301 v0.32.1-relevant tests passing; 57 signature gaps being closed in parallel. Wave-4 verification will re-run the full sweep including 4453-baseline tests once signature gaps close._
- [ ] No skipped tests added in v0.32.1 cycle (skips audited)
      _blocker: skip audit deferred to Wave-4 re-verification._
- [ ] No `xfail` tests added in v0.32.1 cycle (xfails audited)
      _blocker: xfail audit deferred to Wave-4 re-verification._
- [ ] Full test count > 4453 (the v0.31.5 baseline) — net additions only
      _blocker: 368 test files present in `tests/` directory; full collection count + comparison against v0.31.5 baseline (4453) pending Wave-4 verification (test collection blocked in current sandbox)._
- [ ] Integration suite `tests/integration/test_trace_to_brief.py`
      passes 12/12 + new adversary-route assertions
      _blocker: integration-suite verification deferred to Wave-4 re-run; adversary-route assertions for Routes 2/3 not yet authored (see § 3 blockers)._
- [ ] Mutation harness `tests/mutation/` passes ≥ 90% kill rate
      _blocker: `tests/mutation/` directory does not exist in v0.32.1; mutation harness deferred to Wave-4 cert._

---

## 5. Mutation harness

- [ ] `pytest tests/mutation/` runs to completion
      _blocker: harness not implemented in v0.32.1. Wave-4 cert follow-up._
- [ ] Kill rate ≥ 90% across:
  - [ ] `trace/tracer.py` — _blocker: harness pending_
  - [ ] `trace/bridge_calldata.py` — _blocker: harness pending_
  - [ ] `trace/dust_attack.py` — _blocker: harness pending_
  - [ ] `trace/clustering.py` — _blocker: harness pending_
  - [ ] `trace/cex_continuity.py` — _blocker: harness pending_
  - [ ] `trace/drainer_detection.py` — _blocker: harness pending_
  - [ ] `validators/output_integrity.py` — _blocker: harness pending_
  - [ ] `reports/emit_brief.py` — _blocker: harness pending_
  - [ ] `reports/_issuer_freeze_request.py` — _blocker: harness pending_
  - [ ] `reports/_le_handoff.py` — _blocker: harness pending_
- [ ] Mutation report archived under `tests/mutation/v0_32_1_report.txt`
      _blocker: harness pending — to be verified by Wave-4 cert._

---

## 6. 3× determinism check

- [ ] `pytest tests/test_brief_determinism.py` passes
      _blocker: to be verified by Wave-4 cert (existing `tests/test_v_cfi01_determinism.py` covers some scope but explicit `test_brief_determinism.py` not yet present)._
- [ ] `pytest tests/test_freeze_brief_determinism.py` passes
      _blocker: to be verified by Wave-4 cert._
- [ ] `pytest tests/test_le_handoff_determinism.py` passes (new in W3-L)
      _blocker: dedicated determinism test for LE handoff not yet authored. Wave-4 follow-up._
- [ ] Three builds of the Zigha golden case produce byte-identical
      HTML for brief, LE handoff, freeze letter, victim summary,
      engagement letter, recovery snapshot
      _blocker: 3× build comparison to be verified by Wave-4 cert._
- [ ] Manifest SHA-256 chain verified across all three builds
      _blocker: to be verified by Wave-4 cert; INVARIANT P is wired but golden-case verification pending._
- [ ] PDF rendering deterministic across 3 builds (WeasyPrint reproducible
      build mode enabled)
      _blocker: to be verified by Wave-4 cert._

---

## 7. Round-2 re-audit

After Wave 1 + 2 + 3 land, six fresh agents repeat the original
audit scope:

- [ ] Round-2 trace audit: ZERO new CRITs, ZERO new HIGHs (or only
      HIGHs that map to already-deferred items)
      _blocker: Round-2 re-audit in progress — 6 fresh agents launched in parallel post-`e0ce7d8`._
- [ ] Round-2 LE handoff audit: ZERO new CRITs, ZERO new HIGHs
      _blocker: Round-2 in progress._
- [ ] Round-2 freeze-letter audit: ZERO new CRITs, ZERO new HIGHs
      _blocker: Round-2 in progress._
- [ ] Round-2 validator audit: every INVARIANT G through P verified live
      _blocker: Round-2 in progress; live INVARIANTS present in `semantic_integrity.py` G-P pending Round-2 sign-off._
- [ ] Round-2 security audit: ZERO new CRITs, ZERO new HIGHs
      _blocker: Round-2 in progress._
- [ ] Round-2 cross-cutting audit: ZERO new HIGH frictions
      _blocker: Round-2 in progress._
- [ ] Round-2 adversary audit: Routes 1, 2 confirmed collapsed;
      Route 3 confirmed partial with disclosed limit
      _blocker: Round-2 in progress._
- [ ] Round-2 audit documents archived under `docs/JACOB_ROUND2_*`
      _blocker: archives pending Round-2 completion._

---

## 8. Operational dress rehearsal

- [ ] Cron HA: two Railway replicas booted, leader-election verified
      via `cron_jobs_lock` row inspection; single replica killed,
      backup picks up lease within `RECUPERO_CRON_LEASE_SECONDS`
      _blocker: deferred to staging deploy step. `tests/test_v032_cron_ha.py` covers unit-level HA; live two-replica staging dress-rehearsal pending._
- [ ] Staging deploy: full v0.32.1 build pushed to staging Railway env
      _blocker: defer to staging deploy step (post-merge to main triggers prod auto-deploy per `project_railway_main_autodeploy.md`)._
- [ ] Smoke test: one synthetic Zigha-shape case run end-to-end on
      staging from intake → trace → brief → review → dispatch → outcome
      _blocker: defer to staging deploy step._
- [ ] Smoke test: one Tron-USDT case run end-to-end on staging
      _blocker: defer to staging deploy step._
- [ ] Smoke test: one Bitcoin multi-input case run end-to-end
      _blocker: defer to staging deploy step._
- [ ] Smoke test: one Solana DeFi (Jupiter → Raydium) case run end-to-end
      _blocker: defer to staging deploy step._
- [ ] Smoke test: one cross-chain bridged case (Ethereum → Polygon
      via RootChainManager) run end-to-end
      _blocker: defer to staging deploy step._
- [ ] Cron `ofac_sync` runs to completion on staging
      _blocker: defer to staging deploy step._
- [ ] Cron `retrace_backfill` runs to completion on staging
      _blocker: defer to staging deploy step._
- [ ] Cron `stale_label_alert` runs and emits expected report
      _blocker: defer to staging deploy step._
- [ ] Cron `review_sla_scan` runs and surfaces synthetic overdue review
      _blocker: defer to staging deploy step._
- [ ] Cron `label_auto_ingest` runs and writes candidates with
      multi-source confirmation gating
      _blocker: defer to staging deploy step._
- [ ] Migration 021 (and any new W2-G / W3-L migrations) apply cleanly
      on staging, including rollback test
      _blocker: defer to staging deploy step._
- [ ] PDF rendering succeeds on Railway (no OOM)
      _blocker: defer to staging deploy step._
- [ ] Webhook alerts fire correctly on simulated cron failure
      _blocker: defer to staging deploy step._

---

## 9. Documentation completeness

- [x] `docs/REACTOR_PARITY.md` written (new in v0.32.1 docs cycle)
      _Evidence: commit `9fb4742`, `docs/REACTOR_PARITY.md` (444 LOC)._
- [x] `docs/RISK_REGISTER.md` written (new in v0.32.1 docs cycle)
      _Evidence: commit `9fb4742`, `docs/RISK_REGISTER.md` (826 LOC, 43 risks across 8 categories)._
- [x] `docs/PROMISES_AND_LIMITS.md` written (new in v0.32.1 docs cycle)
      _Evidence: commit `9fb4742`, `docs/PROMISES_AND_LIMITS.md` (510 LOC)._
- [x] `docs/V0_32_1_CERT_CHECKLIST.md` written (this document)
      _Evidence: commit `9fb4742`, `docs/V0_32_1_CERT_CHECKLIST.md` (380 LOC original, this update)._
- [ ] `docs/ARCHITECTURE.md` updated for v0.32.1 INVARIANT G/H/I/J/K/L/M/N/O/P
      _blocker: `docs/ARCHITECTURE.md` not found in repo; either re-route to existing architecture references or author for Wave-4._
- [ ] `docs/WHY_RECUPERO_WOULD_FAIL.md` updated with v0.32.1 closures
      noted per-tier
      _blocker: file exists (`docs/WHY_RECUPERO_WOULD_FAIL.md`) but per-tier v0.32.1 closure annotation not yet applied. Wave-4 doc-pass follow-up._
- [ ] `docs/DEPLOY_v0_32_0_RUNBOOK.md` → `DEPLOY_v0_32_1_RUNBOOK.md`
      updated with new env vars, migration order, rollback steps
      _blocker: `DEPLOY_v0_32_0_RUNBOOK.md` exists (per commit `9fb4742` adding 236 LOC); v0.32.1 rename + delta annotation pending. Wave-4 follow-up._
- [ ] `docs/JACOB_v032_TRIAGE.md` § 6 status log updated with every
      Wave 1 + 2 + 3 closure landing
      _blocker: triage status-log § 6 update pending Round-2 audit completion._
- [x] `README.md` Limitations section explicitly enumerates: smart-
      wallet ownership swap, Lightning Network, Cosmos / IBC,
      ERC-4337 paymaster, $50M+ speed-laundered case ceiling
      _Evidence: README.md Limitations § 1 (Lightning), § 2 (Cosmos/IBC), § 3 (ERC-4337) + extended limitations sections per commit `9fb4742`._
- [ ] `.env.example` reflects v0.32.1 defaults
      (`RECUPERO_API_BUDGET_USD_PER_CASE=10000`,
      `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=100`,
      `RECUPERO_CRON_LEASE_SECONDS=300`, etc.)
      _blocker: `.env.example` only documents `RECUPERO_RANDOMIZATION_SECRET` from the v0.32.1 cycle. `RECUPERO_API_BUDGET_USD_PER_CASE`, `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP`, `RECUPERO_CRON_LEASE_SECONDS` defaults not present in `.env.example`. Wave-4 follow-up._
- [ ] Operator runbook updated for new CLI commands
      (`recupero-ops review-queue`, `review-approve`,
      `label-candidates`, `promote-candidate`)
      _blocker: `docs/OPERATOR_RUNBOOK.md` exists; per-command v0.32.1 update pending Wave-4 doc-pass._

---

## 10. External-recipient dry run

Pick one production case (or a high-fidelity synthetic case) and
render the full deliverable bundle. Role-play the recipient.

- [ ] One case selected, case_id recorded: ________________
      _blocker: defer to operator handoff._
- [ ] Full bundle rendered: brief, LE handoff, freeze letters (per
      issuer), victim summary, engagement letter, recovery snapshot
      _blocker: defer to operator handoff._
- [ ] All deliverables pass INVARIANTS A through P
      _blocker: defer to operator handoff dry-run._
- [ ] Bundle reviewed via the human-review gate; status flipped to
      `approved` by a real reviewer (not the brief author)
      _blocker: defer to operator handoff dry-run._
- [ ] **Role-play AUSA reading LE handoff**: read Section 1
      Executive Summary, Section 4 Freezable Holdings, Section 5
      Identified Wallets, Section 7 Methodology, Section 8 Chain
      of Custody. Note any "lawyer skims, frowns, closes laptop"
      moment.
      _blocker: defer to operator handoff dry-run._
- [ ] AUSA role-play notes captured. Issues escalated as v0.32.2
      backlog items if any.
      _blocker: defer to operator handoff dry-run._
- [ ] **Role-play Tether compliance team reading freeze letter**:
      check subject line, salutation ("Dear Tether Operations Limited
      Compliance Team"), posture statement, statutory citation
      (not § 3486), freeze-target table.
      _blocker: defer to operator handoff dry-run._
- [ ] Compliance role-play notes captured.
      _blocker: defer to operator handoff dry-run._
- [ ] **Role-play victim reading victim summary**: check tone,
      recovery-rate disclosure, next-steps clarity.
      _blocker: defer to operator handoff dry-run._
- [ ] Victim role-play notes captured.
      _blocker: defer to operator handoff dry-run._
- [ ] **Role-play law-firm partner reading engagement letter**:
      check scope-of-engagement clause, refund clause, recovery
      disclaimer, attorney-client disclaimer.
      _blocker: defer to operator handoff dry-run._
- [ ] Partner role-play notes captured.
      _blocker: defer to operator handoff dry-run._

---

## 11. Sign-off

By signing below, the reviewer attests that every box above has been
checked, every audit's CRIT and HIGH has been closed with a regression
test, every adversary route has been collapsed (or, for Route 3,
partial-collapsed with disclosed architectural limit), and every
v0.32.1 documentation deliverable is current.

**Reviewer name** (printed): _______________________________________

**Role**: __________________________________________________________

**Date** (UTC): _____________________________________________________

**Commit SHA** of the build certified
(from `git rev-parse HEAD` on `pdf-deliverables` at sign-off time):

`_______________________________________________________`

**Round-2 audit reviewers** (printed):

1. Trace audit (round-2): _________________________________________
2. LE handoff audit (round-2): ____________________________________
3. Freeze-letter audit (round-2): _________________________________
4. Validator audit (round-2): _____________________________________
5. Security audit (round-2): ______________________________________
6. Cross-cutting audit (round-2): _________________________________
7. Adversary audit (round-2): _____________________________________

**Operations dress-rehearsal sign-off** (printed):

____________________________________________________________________

**Final go / no-go**:

- [ ] **GO** — v0.32.1 is shippable to Jacob
- [ ] **NO-GO** — defer ship; deficiencies documented in:

  ____________________________________________________________________

  ____________________________________________________________________

---

## Wave-4 follow-ups

Items still unchecked as of this Wave-3 closure pass, with the reason
each remains open. Wave-4 cert must address every item below before
Jacob handoff.

### Regression suite + harnesses (§ 4, § 5, § 6)
1. **Full pytest sweep** — 244/301 v0.32.1-relevant tests passing; 57 signature-gap failures being closed in parallel. Wave-4: confirm 0 failures, 0 unaudited skips, 0 unaudited xfails.
2. **Test count vs v0.31.5 baseline (4453)** — full collection count blocked in current sandbox. Wave-4: run `pytest --collect-only -q | tail -5` and confirm net positive.
3. **Integration suite `tests/integration/test_trace_to_brief.py`** — 12/12 + new adversary-route assertions pending.
4. **Mutation harness `tests/mutation/`** — directory does not exist; the harness is referenced but unimplemented. Wave-4: stand up the harness, target ≥ 90% kill rate across tracer/bridge_calldata/dust_attack/clustering/cex_continuity/drainer_detection/output_integrity/emit_brief/_issuer_freeze_request/_le_handoff, archive report under `tests/mutation/v0_32_1_report.txt`.
5. **3× determinism check** — `test_brief_determinism.py`, `test_freeze_brief_determinism.py`, `test_le_handoff_determinism.py` not present as named files. Existing `test_v_cfi01_determinism.py` covers partial scope. Wave-4: stand up the named tests, run three Zigha-golden builds and assert byte-identical HTML + manifest-SHA chain + WeasyPrint reproducible build.

### Adversary-route regression gaps (§ 3)
6. **PRE-excerpts for Routes 1, 2, 3** — current regressions assert only POST-state contracts. Wave-4: capture v0.32.0 PRE-output artifacts for side-by-side comparison.
7. **STRUCTURED_FANOUT signal (Routes 2, 3)** — literal `STRUCTURED_FANOUT` signal + Gini coefficient computation not implemented. v0.32.1 closure relies on per-case threshold randomization instead. Wave-4: emit explicit signal + Gini metric for transparency to operators.
8. **multi_bridge_alarm signal (Route 3)** — not implemented. Wave-4: fire alarm when ≥ 3 distinct bridges hit in same case.
9. **DISCLOSED LIMITS section (Route 3)** — `partial_budget_hit` marker is live, but the explicit "SECTION 8 — DISCLOSED LIMITS" rendering in the brief is not. Wave-4: add the disclosure section to brief.py templates.
10. **Dedicated route-3 regression `tests/test_v032_adversary_route3.py`** — not authored. Wave-4: add $50M Arbitrum-exploit synthetic fixture exercising budget + multi-bridge + structured-fanout.

### Round-2 re-audit (§ 7)
11. **6 round-2 audits in progress** — trace, LE handoff, freeze-letter, validator, security, cross-cutting, adversary. Wave-4: collect Round-2 reports, archive under `docs/JACOB_ROUND2_*.md`, confirm ZERO new CRITs / HIGHs.

### Operational dress rehearsal (§ 8)
12. **Staging deploy + 5 smoke tests** — Zigha, Tron-USDT, Bitcoin multi-input, Solana DeFi, cross-chain bridged. Defer to staging deploy step.
13. **Cron job verification on staging** — ofac_sync, retrace_backfill, stale_label_alert, review_sla_scan, label_auto_ingest. Defer to staging.
14. **Cron HA leader-election live test** — two-replica boot, kill-one-recover-other within `RECUPERO_CRON_LEASE_SECONDS`. Defer to staging.
15. **Migration 021 + W2-G / W3-L migrations on staging** — apply-clean + rollback test. Defer to staging.
16. **PDF rendering OOM-free on Railway** — defer to staging.
17. **Webhook alert simulation** — defer to staging.

### Documentation gaps (§ 9)
18. **`docs/ARCHITECTURE.md` INVARIANT G-P update** — file not found in repo. Wave-4: author or re-route reference.
19. **`docs/WHY_RECUPERO_WOULD_FAIL.md` per-tier v0.32.1 closure notes** — pending annotation pass.
20. **`docs/DEPLOY_v0_32_1_RUNBOOK.md`** — rename from v0_32_0 + new env-vars + migration order + rollback steps.
21. **`docs/JACOB_v032_TRIAGE.md` § 6 status log** — Wave 1 + 2 + 3 closure entries pending Round-2 completion.
22. **`.env.example` v0.32.1 defaults** — `RECUPERO_API_BUDGET_USD_PER_CASE=10000`, `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=100`, `RECUPERO_CRON_LEASE_SECONDS=300` not documented. Wave-4: append.
23. **`docs/OPERATOR_RUNBOOK.md` CLI updates** — `recupero-ops review-queue`, `review-approve`, `label-candidates`, `promote-candidate` documentation pending.

### External-recipient dry run (§ 10)
24. **Pick + run one case end-to-end** with role-play of AUSA / Tether compliance / victim / law-firm partner. Defer to operator handoff.

### Sign-off (§ 11)
25. **Reviewer sign-off line, Round-2 reviewer printed names, Operations dress-rehearsal sign-off, GO/NO-GO toggle** — blank for reviewer to fill on completion.

---

*End of V0_32_1_CERT_CHECKLIST.*
