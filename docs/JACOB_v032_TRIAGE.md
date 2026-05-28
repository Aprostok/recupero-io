# Jacob v0.32.0 — Aggregate Triage + v0.32.1 Remediation Plan

**Branch:** `pdf-deliverables` (worktree `cranky-fermat-54fcfb`)
**Audit cycle:** 2026-05-27 → 2026-05-28
**Stance:** brutal. Every "30%" gap moves to "90%+" before Jacob handoff.

This document aggregates the **6 parallel Jacob-style audits** + tracks the
**remediation status** for v0.32.1.

---

## 1. Audit cycle outcome (6 audits)

| Audit | File | CRIT | HIGH | Verdict |
|---|---|:-:|:-:|---|
| Trace pipeline | `JACOB_TRACE_AUDIT_v032.md` | 6 | 14 | ~52/100 vs Reactor |
| LE handoff | `JACOB_LE_HANDOFF_AUDIT_v032.md` | 3 | 10 | ~72/100 — 2 lawyer-visible cross-ref bugs |
| Freeze letters | `JACOB_FREEZE_LETTER_AUDIT_v032.md` | 6 | 11 | Would NOT be acted on by compliance as-is |
| Validator | `JACOB_VALIDATOR_AUDIT_v032.md` | — | — | ~30% semantic coverage; needs G/H/I |
| Security (v0.32 surface) | `JACOB_SECURITY_AUDIT_v032.md` | 2 | 5 | Label injection + bare-key leak |
| Cross-cutting | `JACOB_CROSS_CUTTING_AUDIT_v032.md` | — | — | 11 friction + 8 30→90% gaps |
| Adversary (red-team) | `JACOB_ADVERSARY_AUDIT_v032.md` | 1 mega | 3 | **3 of 3 evasion routes succeed** |

**Aggregate**: 18 CRIT, 43 HIGH across all audits.

**Honest verdict at v0.32.0**: shippable against unsophisticated thieves;
NOT shippable against a Lazarus-tier APT that has read the source code.

---

## 2. Top remediation priorities — v0.32.1

These are launched as parallel fix agents on `cranky-fermat-54fcfb`:

### Wave 1 (in progress)

| ID | Scope | Closes |
|---|---|---|
| W1-A | Fix LE handoff 3 CRITs + HIGHs | LE-CRIT-1 mixed-asset row, LE-CRIT-2 operator-name fallback, LE-CRIT-3 watermark-under-signature, plus HIGHs |
| W1-B | Fix freeze-letter CRITs + § 3486 | FR-CRIT-1 missing salutation, FR-CRIT-2 issuer.name bare tag, FR-CRIT-3 wrong USC § 3486 citation, FR-CRIT-4/5/6 |
| W1-C | Fix trace CRITs (Bitcoin + Tron + drainer) | TR-CRIT-1 BTC multi-input collapse, TR-CRIT-2 Tron TRX dropped, TR-CRIT-4 drainer detection `if False`, plus HIGHs |
| W1-D | Fix security CRIT-1 + HIGHs 1/3/5 | SEC-CRIT-1 label-promote JSON injection, SEC-HIGH-1 SSRF, SEC-HIGH-3 CSRF gate bypass, SEC-HIGH-5 unauth `/cron/healthz` |

### Wave 2 (in progress — launched after Wave 1 background-started)

| ID | Scope | Closes |
|---|---|---|
| W2-E | Rollup-canonical bridge decoders | **Adversary M-6** (highest-leverage): Polygon PoS, Optimism, Arbitrum, zkSync Era, Base — collapses Route 1 |
| W2-F | CEX continuity cross-token at parity | TR-HIGH-10: deposit USDT → withdraw USDC same exchange → tier-2 lead |
| W2-G | Validator INVARIANTS G/H/I | Brings validator from ~30% semantic coverage to ~70%+ |
| W2-H | Cross-cutting polish | 8× 30→90% items: `.env.example` budget, address-truncation drift, README, GO_LIVE, missing tests, operator UI for review gate, dev onboarding, log noise |

### Wave 3 (planned post-Wave-1/2 completion)

| ID | Scope | Closes |
|---|---|---|
| W3-I | Adversary route closures (multi-source label confirm + per-case randomized thresholds) | Adversary M-1, M-3, M-5 — collapses Routes 2 & 3 |
| W3-J | Trace CRIT-3 max_depth=4 → adaptive | TR-CRIT-5: deep laundering past 4 hops |
| W3-K | Bitcoin peel-chain + CoinJoin | Reactor-parity for BTC |
| W3-L | Solana CPI inner-instruction transfers | Reactor-parity for SOL |

---

## 3. Adversary-route status

Route 1 ($5M USDC Ethereum, Polygon PoS escape): **CLOSED in W2-E** (rollup-canonical decoders extract destination).

Route 2 ($500K USDT-TRC20, 9-fanout + USDD PSM): **PARTIAL via W3-I** (multi-source label confirm + per-case randomized fanout threshold). Architectural escape via offshore stablecoin PSM is harder; track separately.

Route 3 ($50M Arbitrum exploit, 50-fanout + 4 bridges + privacy pools + Symbiosis): operator already gets `partial_deadline_hit` marker. Mitigated via budget bump from $0.50 → $10,000 (W2-H item 1). Architectural ceiling on $50M+ cases acknowledged in README's "Limitations" section (W2-H item 3).

---

## 4. Definition of "done" for v0.32.1 — **EVERYTHING BELOW 90% MUST REACH 90%**

User directive 2026-05-28: do not stop at the 30%-to-90% list. **Every measured
dimension under 90% must be raised to at least 90% before Jacob handoff.**

Cert required for Jacob handoff:

- [ ] All 18 CRIT closed with regression test
- [ ] All 43 HIGH closed (NOT deferred — closed with a regression test)
- [ ] **All 3 adversary routes collapse** (M-6 + M-1 + M-3 + M-5 all landed; Routes 1, 2, 3 all closed end-to-end)
- [ ] **Trace pipeline ≥ 90/100 vs Reactor** (currently 52). Requires Bitcoin peel + CoinJoin, Solana CPI, ERC-4337, NFT 721/1155, adaptive max_depth, MEV expansion, contract-internal traversal.
- [ ] **LE handoff ≥ 90/100** (currently 72). Requires every HIGH closed, cross-ref consistency invariant, mixed-currency format fix, signature-block polish.
- [ ] **Freeze letters ≥ 90/100** (compliance-team would-act score). Requires all 6 CRIT + all 11 HIGH from freeze-letter audit closed, including § 3486 → correct citation.
- [ ] **Validator semantic coverage ≥ 90%** (currently 30%). Requires INVARIANTS G/H/I + J/K/L/M/N covering: intra-artifact cross-section sum coherence (0%→90%), address ↔ chain ↔ explorer URL coherence (0%→90%), time-window coherence (0%→90%), stale-label/PIT render verification (0%→90%), AI-editorial-claim grounding (5%→90%), brief↔freeze-letter token/amount/recipient consistency (10%→90%), parent-link/disclosure metadata (0%→90%).
- [ ] **Adversary fail rate ≤ 10%** (currently 100% — 3 of 3 routes succeed). Routes 1, 2, 3 must collapse.
- [ ] Full regression suite passes (no skips, no xfails added)
- [ ] Mutation harness ≥ 90% kill rate maintained
- [ ] 3× determinism check (byte-identical builds)
- [ ] Round-2 re-audit by fresh agents finds zero new CRITs AND every dimension scores ≥ 90/100

### Below-90% dimensions tracked

| Dimension | Current | Target | Closing in |
|---|:-:|:-:|---|
| Trace vs Reactor | 52/100 | ≥90/100 | W3-I, W3-N (BTC, SOL, ERC-4337, NFT, depth, MEV) |
| LE handoff | 72/100 | ≥90/100 | W1-A (CRITs) + W3-J (all HIGHs) |
| Freeze-letter act-rate | low | ≥90/100 | W1-B (CRITs) + W3-K (all HIGHs) |
| Validator semantic coverage | 30% | ≥90% | W2-G (G/H/I) + W3-L (J/K/L/M/N) |
| Validator template cross-fill | 85% | ≥90% | W3-L (tighten check 1) |
| Validator cross-issuer consistency | 75% | ≥90% | W3-L (tighten check 7 to cover LE Section 3/4/5 USD reconciliation) |
| Validator recoverable/unrecoverable | 80% | ≥90% | W3-L |
| Validator intra-artifact sum coherence | 0% | ≥90% | W3-L INVARIANT J |
| Validator brief↔freeze-letter consistency | 10% | ≥90% | W3-L INVARIANT K |
| Validator address↔chain↔explorer | 0% | ≥90% | W3-L INVARIANT L |
| Validator time-window coherence | 0% | ≥90% | W3-L INVARIANT M |
| Validator PIT render verification | 0% | ≥90% | W3-L INVARIANT N |
| Validator AI-editorial grounding | 5% | ≥90% | W3-L INVARIANT O |
| Validator parent-link/disclosure | 0% | ≥90% | W3-L INVARIANT P |
| Adversary route collapse rate | 0/3 | ≥90% (3/3) | W2-E + W3-M (label confirm + randomized thresholds + Tron bridges + Safe-swap detection) |
| Tron bridge coverage | 3 entries | ≥8 entries | W3-M Tron expansion |
| MEV builder coverage | 4 builders | ≥12 builders | W3-I MEV expansion |
| Burn-list completeness | 6 sinks missed | 0 missed | W3-I burn list |
| Cross-cutting polish | partial | full | W2-H (8 items) + W3-Q (extended) |

---

## 5. Risk register at v0.32.1 ship

Items deliberately deferred (with explicit rationale in README "Limitations"):

1. **Lazarus-tier APT vs $50M+ exploits with privacy-pool exit**: budget cap and BFS scaling limits hit before route-completion. Mitigation: brief carries `partial_deadline_hit` marker so operator knows.
2. **Smart-wallet ownership swap with no ERC-20 Transfer event**: `policy.stop_at_contract=True` terminates BFS. Detection requires watching `swapOwner` / `addOwner` calls on Safe-pattern contracts. Track as v0.33 item.
3. **Bitcoin Lightning-channel exits**: out of scope. Forensics community generally treats this as a known dead end.
4. **Cosmos / IBC**: 0 chains supported. v0.33+.
5. **ERC-4337 user-op decomposition**: 0% coverage. v0.33+.

---

## 6. Status log

(Updated as fix agents return.)

- **2026-05-28 09:xx UTC**: 6 audits complete. 8 fix agents launched in parallel.
- _(append completions here)_

