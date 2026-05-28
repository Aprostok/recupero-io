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

- [ ] **Trace audit** (`JACOB_TRACE_AUDIT_v032.md`): 6 CRIT + 14 HIGH closed with regression tests
- [ ] **LE handoff audit** (`JACOB_LE_HANDOFF_AUDIT_v032.md`): 3 CRIT + 10 HIGH closed with regression tests
- [ ] **Freeze-letter audit** (`JACOB_FREEZE_LETTER_AUDIT_v032.md`): 6 CRIT + 11 HIGH closed with regression tests
- [ ] **Validator audit** (`JACOB_VALIDATOR_AUDIT_v032.md`): INVARIANTS G, H, I, J, K, L, M, N, O, P landed
- [ ] **Security audit** (`JACOB_SECURITY_AUDIT_v032.md`): 2 CRIT + 5 HIGH closed
- [ ] **Cross-cutting audit** (`JACOB_CROSS_CUTTING_AUDIT_v032.md`): all 11 friction items + 8 thirty-to-ninety items closed
- [ ] **Adversary audit** (`JACOB_ADVERSARY_AUDIT_v032.md`): Routes 1, 2 collapsed; Route 3 architecturally bounded with disclosed limit

**Aggregate**: was 18 CRIT + 43 HIGH at v0.32.0. v0.32.1 closes all
of them with a regression test per finding. No CRIT or HIGH deferred.

---

## 2. Per-dimension ≥ 90% verification

Every measured dimension below the 90% bar at v0.32.0 must reach
90% at v0.32.1. The verification method is the third column.

| Dimension | v0.32.0 | v0.32.1 target | Verification method |
|---|:-:|:-:|---|
| Trace pipeline vs Reactor | 52/100 | ≥ 90/100 | `docs/REACTOR_PARITY.md` § 2 per-row, summed |
| LE handoff completeness | 72/100 | ≥ 90/100 | All LE audit CRIT + HIGH closed; cross-doc consistency invariants (I, K) pass |
| Freeze-letter compliance-team act-rate | low | ≥ 90/100 | All freeze-letter CRIT + HIGH closed; legal entity names + correct statutory citation |
| Validator semantic coverage | 30% | ≥ 90% | INVARIANTS G/H/I/J/K/L/M/N/O/P all land and pass on 10+ test fixtures |
| Validator template cross-fill | 85% | ≥ 90% | Per-issuer freeze-letter check tightened in W3-L |
| Validator cross-issuer consistency | 75% | ≥ 90% | Section 3/4/5 USD reconciliation INVARIANT |
| Validator recoverable/unrecoverable | 80% | ≥ 90% | victim_summary biconditional + holdings-row enforcement |
| Validator intra-artifact sum coherence | 0% | ≥ 90% | INVARIANT J live |
| Validator brief↔freeze-letter consistency | 10% | ≥ 90% | INVARIANT K live |
| Validator address↔chain↔explorer URL | 0% | ≥ 90% | INVARIANT L live |
| Validator time-window coherence | 0% | ≥ 90% | INVARIANT M live |
| Validator PIT label render verification | 0% | ≥ 90% | INVARIANT N live + 10 PIT test cases |
| Validator AI-editorial grounding | 5% | ≥ 90% | INVARIANT O live |
| Validator parent-link / disclosure | 0% | ≥ 90% | INVARIANT P live (manifest SHA chain) |
| Adversary route collapse rate | 0/3 | ≥ 2/3 collapsed | Routes 1, 2 collapsed; Route 3 partial with disclosed budget cap |
| Tron bridge coverage | 3 entries | ≥ 8 entries | `bridges.json` Tron rows: JustLink, BTTC, Wormhole-on-Tron, Allbridge, PolyNetwork legacy, plus existing 3 |
| MEV builder coverage | 4 builders | ≥ 12 builders | `mev_detection.py` builder set OR `mev_builders.json` seed |
| Burn-list completeness | 6 sinks missed | 0 missed | HIGH-7 fix lands; expanded burn-address set |
| Cross-cutting polish | partial | full | All 8 items from W2-H + all extended W3-Q items |

Per-row sign-off:

- [ ] Trace pipeline vs Reactor — reviewer-verified ≥ 90/100
- [ ] LE handoff completeness — reviewer-verified ≥ 90/100
- [ ] Freeze-letter compliance — reviewer-verified ≥ 90/100
- [ ] Validator semantic coverage — reviewer-verified ≥ 90%
- [ ] Validator template cross-fill — reviewer-verified ≥ 90%
- [ ] Validator cross-issuer consistency — reviewer-verified ≥ 90%
- [ ] Validator recoverable/unrecoverable — reviewer-verified ≥ 90%
- [ ] Validator intra-artifact sum coherence — reviewer-verified ≥ 90%
- [ ] Validator brief↔freeze-letter consistency — reviewer-verified ≥ 90%
- [ ] Validator address↔chain↔explorer URL — reviewer-verified ≥ 90%
- [ ] Validator time-window coherence — reviewer-verified ≥ 90%
- [ ] Validator PIT render verification — reviewer-verified ≥ 90%
- [ ] Validator AI-editorial grounding — reviewer-verified ≥ 90%
- [ ] Validator parent-link / disclosure — reviewer-verified ≥ 90%
- [ ] Adversary route collapse — Routes 1, 2 collapsed; Route 3 partial-disclosed
- [ ] Tron bridge coverage — ≥ 8 entries verified in `bridges.json`
- [ ] MEV builder coverage — ≥ 12 builders verified
- [ ] Burn-list completeness — 0 missed sinks
- [ ] Cross-cutting polish — all 8 + extended items reviewed

---

## 3. Adversary route collapse — pre vs post evidence

For each of the three adversary routes in
`JACOB_ADVERSARY_AUDIT_v032.md`, the regression test must produce a
PRE excerpt (the v0.32.0 trace output that escapes) and a POST excerpt
(the v0.32.1 trace output that collapses the evasion).

### Route 1 — $5M USDC Ethereum, Polygon PoS escape

- [ ] Regression test `tests/test_v032_adversary_route1.py` lands
- [ ] **PRE excerpt expected** (v0.32.0 behavior, captured for comparison):
      ```
      SECTION 7 — CROSS-CHAIN HANDOFFS:
        Handoff 1: Polygon: RootChainManager
          Source tx: 0x... (etherscan link)
          Destination chain: polygon (candidate)
          Destination address: (extraction failed)
          Follow-up URL: polygonscan.com
      ```
- [ ] **POST excerpt expected** (v0.32.1 behavior, asserted by test):
      ```
      SECTION 7 — CROSS-CHAIN HANDOFFS:
        Handoff 1: Polygon: RootChainManager
          Source tx: 0x... (etherscan link)
          Destination chain: polygon (high-confidence)
          Destination address: 0x<polygon_dest> (decoded from depositFor.user)
          Continuation: BFS resumed on polygon chain at <dest_addr>
      ```
- [ ] Test asserts `case.cross_chain_handoffs[0].destination_address`
      is non-empty and matches the planted polygon destination
- [ ] Test asserts BFS continuation reached the Polygon-side hop
- [ ] Smart-wallet ownership-swap (R-002) explicitly out of scope —
      test disclosed in test docstring

### Route 2 — $500K USDT-TRC20, 9-fanout sub-threshold

- [ ] Regression test `tests/test_v032_adversary_route2.py` lands
- [ ] **PRE excerpt expected** (v0.32.0):
      ```
      SECTION 5 — DESTINATIONS (9 rows):
        Destination 1: T...A (unlabeled EOA) — $55,555.56 USDT
          Bridged via USDD: Peg Stability Module → Tron-internal
          Status: TRACE TERMINATED AT BRIDGE
        [...8 more identical rows...]
      ```
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
- [ ] Test asserts STRUCTURED_FANOUT signal fires at fanout=9
- [ ] Test asserts USDD PSM treated as swap (category="swap"),
      trace continues past it to the re-emergence
- [ ] Test asserts CEX-continuity cross-token at parity catches
      the Bybit deposit

### Route 3 — $50M Arbitrum exploit, speed laundering

- [ ] Regression test `tests/test_v032_adversary_route3.py` lands
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
- [ ] Test asserts `partial_budget_hit` marker is set
- [ ] Test asserts multi-bridge alarm fires
- [ ] Test asserts STRUCTURED_FANOUT signal fires at fanout=50
- [ ] Test asserts README Limitations § 3 disclosure renders
- [ ] **Architectural ceiling disclosed**: Route 3 is partial-collapse,
      not full-collapse. The disclosed-limit marker is the closure
      pattern.

---

## 4. Regression suite

- [ ] `pytest --tb=short tests/` runs to completion
- [ ] No skipped tests added in v0.32.1 cycle (skips audited)
- [ ] No `xfail` tests added in v0.32.1 cycle (xfails audited)
- [ ] Full test count > 4453 (the v0.31.5 baseline) — net additions only
- [ ] Integration suite `tests/integration/test_trace_to_brief.py`
      passes 12/12 + new adversary-route assertions
- [ ] Mutation harness `tests/mutation/` passes ≥ 90% kill rate

---

## 5. Mutation harness

- [ ] `pytest tests/mutation/` runs to completion
- [ ] Kill rate ≥ 90% across:
  - [ ] `trace/tracer.py`
  - [ ] `trace/bridge_calldata.py`
  - [ ] `trace/dust_attack.py`
  - [ ] `trace/clustering.py`
  - [ ] `trace/cex_continuity.py`
  - [ ] `trace/drainer_detection.py`
  - [ ] `validators/output_integrity.py`
  - [ ] `reports/emit_brief.py`
  - [ ] `reports/_issuer_freeze_request.py`
  - [ ] `reports/_le_handoff.py`
- [ ] Mutation report archived under `tests/mutation/v0_32_1_report.txt`

---

## 6. 3× determinism check

- [ ] `pytest tests/test_brief_determinism.py` passes
- [ ] `pytest tests/test_freeze_brief_determinism.py` passes
- [ ] `pytest tests/test_le_handoff_determinism.py` passes (new in W3-L)
- [ ] Three builds of the Zigha golden case produce byte-identical
      HTML for brief, LE handoff, freeze letter, victim summary,
      engagement letter, recovery snapshot
- [ ] Manifest SHA-256 chain verified across all three builds
- [ ] PDF rendering deterministic across 3 builds (WeasyPrint reproducible
      build mode enabled)

---

## 7. Round-2 re-audit

After Wave 1 + 2 + 3 land, six fresh agents repeat the original
audit scope:

- [ ] Round-2 trace audit: ZERO new CRITs, ZERO new HIGHs (or only
      HIGHs that map to already-deferred items)
- [ ] Round-2 LE handoff audit: ZERO new CRITs, ZERO new HIGHs
- [ ] Round-2 freeze-letter audit: ZERO new CRITs, ZERO new HIGHs
- [ ] Round-2 validator audit: every INVARIANT G through P verified live
- [ ] Round-2 security audit: ZERO new CRITs, ZERO new HIGHs
- [ ] Round-2 cross-cutting audit: ZERO new HIGH frictions
- [ ] Round-2 adversary audit: Routes 1, 2 confirmed collapsed;
      Route 3 confirmed partial with disclosed limit
- [ ] Round-2 audit documents archived under `docs/JACOB_ROUND2_*`

---

## 8. Operational dress rehearsal

- [ ] Cron HA: two Railway replicas booted, leader-election verified
      via `cron_jobs_lock` row inspection; single replica killed,
      backup picks up lease within `RECUPERO_CRON_LEASE_SECONDS`
- [ ] Staging deploy: full v0.32.1 build pushed to staging Railway env
- [ ] Smoke test: one synthetic Zigha-shape case run end-to-end on
      staging from intake → trace → brief → review → dispatch → outcome
- [ ] Smoke test: one Tron-USDT case run end-to-end on staging
- [ ] Smoke test: one Bitcoin multi-input case run end-to-end
- [ ] Smoke test: one Solana DeFi (Jupiter → Raydium) case run end-to-end
- [ ] Smoke test: one cross-chain bridged case (Ethereum → Polygon
      via RootChainManager) run end-to-end
- [ ] Cron `ofac_sync` runs to completion on staging
- [ ] Cron `retrace_backfill` runs to completion on staging
- [ ] Cron `stale_label_alert` runs and emits expected report
- [ ] Cron `review_sla_scan` runs and surfaces synthetic overdue review
- [ ] Cron `label_auto_ingest` runs and writes candidates with
      multi-source confirmation gating
- [ ] Migration 021 (and any new W2-G / W3-L migrations) apply cleanly
      on staging, including rollback test
- [ ] PDF rendering succeeds on Railway (no OOM)
- [ ] Webhook alerts fire correctly on simulated cron failure

---

## 9. Documentation completeness

- [ ] `docs/REACTOR_PARITY.md` written (new in v0.32.1 docs cycle)
- [ ] `docs/RISK_REGISTER.md` written (new in v0.32.1 docs cycle)
- [ ] `docs/PROMISES_AND_LIMITS.md` written (new in v0.32.1 docs cycle)
- [ ] `docs/V0_32_1_CERT_CHECKLIST.md` written (this document)
- [ ] `docs/ARCHITECTURE.md` updated for v0.32.1 INVARIANT G/H/I/J/K/L/M/N/O/P
- [ ] `docs/WHY_RECUPERO_WOULD_FAIL.md` updated with v0.32.1 closures
      noted per-tier
- [ ] `docs/DEPLOY_v0_32_0_RUNBOOK.md` → `DEPLOY_v0_32_1_RUNBOOK.md`
      updated with new env vars, migration order, rollback steps
- [ ] `docs/JACOB_v032_TRIAGE.md` § 6 status log updated with every
      Wave 1 + 2 + 3 closure landing
- [ ] `README.md` Limitations section explicitly enumerates: smart-
      wallet ownership swap, Lightning Network, Cosmos / IBC,
      ERC-4337 paymaster, $50M+ speed-laundered case ceiling
- [ ] `.env.example` reflects v0.32.1 defaults
      (`RECUPERO_API_BUDGET_USD_PER_CASE=10000`,
      `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=100`,
      `RECUPERO_CRON_LEASE_SECONDS=300`, etc.)
- [ ] Operator runbook updated for new CLI commands
      (`recupero-ops review-queue`, `review-approve`,
      `label-candidates`, `promote-candidate`)

---

## 10. External-recipient dry run

Pick one production case (or a high-fidelity synthetic case) and
render the full deliverable bundle. Role-play the recipient.

- [ ] One case selected, case_id recorded: ________________
- [ ] Full bundle rendered: brief, LE handoff, freeze letters (per
      issuer), victim summary, engagement letter, recovery snapshot
- [ ] All deliverables pass INVARIANTS A through P
- [ ] Bundle reviewed via the human-review gate; status flipped to
      `approved` by a real reviewer (not the brief author)
- [ ] **Role-play AUSA reading LE handoff**: read Section 1
      Executive Summary, Section 4 Freezable Holdings, Section 5
      Identified Wallets, Section 7 Methodology, Section 8 Chain
      of Custody. Note any "lawyer skims, frowns, closes laptop"
      moment.
- [ ] AUSA role-play notes captured. Issues escalated as v0.32.2
      backlog items if any.
- [ ] **Role-play Tether compliance team reading freeze letter**:
      check subject line, salutation ("Dear Tether Operations Limited
      Compliance Team"), posture statement, statutory citation
      (not § 3486), freeze-target table.
- [ ] Compliance role-play notes captured.
- [ ] **Role-play victim reading victim summary**: check tone,
      recovery-rate disclosure, next-steps clarity.
- [ ] Victim role-play notes captured.
- [ ] **Role-play law-firm partner reading engagement letter**:
      check scope-of-engagement clause, refund clause, recovery
      disclaimer, attorney-client disclaimer.
- [ ] Partner role-play notes captured.

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

*End of V0_32_1_CERT_CHECKLIST.*
