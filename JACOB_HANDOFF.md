# Recupero — Handoff to Jacob (v0.34.4)

**Date:** 2026-06-01 → 2026-06-02
**Prod HEAD:** `ac8d0b2` on `main` (Railway auto-deploys `main`)
**Status:** ✅ Shipped + deployed. Full suite **5409 passed**, exit 0, zero new ruff.
**Companion:** `JACOB_TESTING_TONIGHT.md` — the step-by-step test runbook (9 steps).

---

## 1. What shipped this cycle

### A. Cross-chain bridge oracle: 8 → 12 cryptographically-verified protocols
A cross-chain hop is `high` confidence **only** when the protocol's own cross-chain id
matches on BOTH chains (cryptographic proof) — otherwise the engine returns nothing
(never a guess; never a fabricated destination).

| Protocol | Cross-chain id | Notes |
|---|---|---|
| deBridge (DLN) | orderId | **refreshed** — fill event had drifted at the same contract |
| Across | depositId + originChain | |
| Celer cBridge | srcTransferId | |
| Hop | transferId | |
| Synapse (classic) | derived kappa | historical |
| **Synapse RFQ** *(new)* | transactionId | FastBridgeV2 |
| Chainlink CCIP | messageId | |
| Connext | transferId | dormant rail |
| Wormhole | VAA (chain,emitter,seq) | |
| **Stargate V2** *(new)* | LayerZero GUID | eid namespace |
| **LayerZero OFT** *(new)* | LayerZero GUID | catches ALL OFT bridges |
| **Axelar / Squid** *(new)* | payloadHash + sourceTxHash tiebreak | GMP rail |

Each new rail was verified end-to-end against a **real on-chain pair**. **CCTP was
investigated and intentionally NOT added** — v2's `DepositForBurn` omits the on-chain
nonce, so it can't be paired without Circle's attestation API; no half-working spec was
shipped. A **bridge-spec staleness monitor** (`scripts/_v034_bridge_staleness.py`) now
catches drift before prod (it's what caught the DLN refresh).

### B. P0 recovery fix — dormant-aware cross-chain window
**The bug:** a 24-hour cap on cross-chain *onward* hops silently dropped dormant
laundering destinations funded >24h after a bridge. On the Zigha case this dropped
**~$16.9M** of traced-but-recoverable DAI before it ever entered the report.
**The fix:** lower-bound-only (a hop must be *after* the bridge; **no upper cap** by
default) — laundering parks funds and moves them later, so a time cap is forensically
wrong. Value-direction keeps the trace on the laundered money. Result: the full Zigha
trace now reaches **4/4** ground-truth endpoints (was 2/4), deterministically.

### C. TRACKED / watchable category
Identified funds that aren't freezable today but still sit at a known address are now
**🟪 TRACKED** — surfaced with a per-issuer `total_tracked_usd` + a "monitoring for
movement" note, **and auto-enrolled in movement monitoring** so we get alerted if/when
they move and can recover later. **UNRECOVERABLE is now reserved for genuinely-gone
funds** (mixers, burns, unfollowable paths). Bridges traced to a destination → TRACKED,
not written off. Applied consistently across emit_brief, the worker pipeline, the
monitoring subscriber, the LE template, and the AI-editorial guidance.

### D. Code flatten
Behavior-preserving lint cleanup across the codebase, gate-locked.

---

## 2. Why you can trust it — validation evidence

| Check | Result |
|---|---|
| Full test suite | **5409 passed**, 31 skipped, exit 0 |
| Offline E2E golden case (LE + freezes + brief + INVARIANTS A–E + 3× determinism) | **12 passed** |
| Deliverables smoke (LE / freeze letters / victim summary / flow graphic) | clean — no template errors; real graphviz SVG |
| Bridge staleness monitor (12 protocols) | **OK=9**, only acknowledged Synapse/Connext flagged, exit 0 |
| Freeze routing | correct — letters only for issuers with real FREEZABLE holdings; no $0 letters |
| New ruff | zero |

### The Zigha 4/4 is REAL — triple-checked (no fluke, no answer key)
Three **independent** fresh-case-dir traces, each scored **4/4**:

| Run | Reach | ground-truth files in case dir |
|---|---|---|
| ZIGHA-FULL-0601b | 4/4 | 0 |
| ZIGHA-FULL-0601c | 4/4 | 0 |
| ZIGHA-FULL-0601d | 4/4 | 0 |

- **No answer-key leakage:** the trace path (`run_trace` / pivot / cross_chain) reads
  `ground_truth.json` *nowhere*. The only consumer is the opt-in `output_integrity`
  validator, which no-ops unless a `ground_truth.json` is placed *in the case dir* — and
  these CLI runs have none. The scorer compares **post-hoc** against `tests/fixtures/`;
  it never feeds the trace.
- **Deterministic:** the fix removed the only time-based filter, so the trace follows
  value the same way every run — three fresh dirs, identical 4/4.
- **Auditable mechanism (in every run's log):** `confidence=high` DLN decode → fetch
  outflows from landing intermediary `0x37fc5f76…` → the real `2,000,000 / 1,500,000 /
  100,000 DAI` sends to `0x415D8D07…` and `0x3daFC6a8…`. The engine confirms the bridge
  cryptographically and follows the actual money — no fixture involved.

You can re-verify yourself: run the step-8 trace in the runbook with a brand-new
`--case-id` and score it — it must hit 4/4.

---

## 3. The money picture (Zigha case)
- **~$18–20M traced as lost** — 4/4 endpoints reached, every run. (The Arbitrum hub
  ~$18.13M is the same money pre-bridge that lands across the Ethereum endpoints ~$20M;
  they do NOT sum to $38M.)
- **~$3.12M FREEZABLE** — Midas mSyrupUSDp; actionable freeze letter.
- **~$16.9M TRACKED + auto-watched** — the two dormant DAI holders; identified, not
  freezable today, monitored for movement so they're recoverable later. Previously
  silently dropped.

---

## 4. Forensic-correctness posture (unchanged guarantees)
- **No fabrication.** Destinations are real on-chain addresses or nothing.
- **`high` confidence only** for a cryptographic cross-chain id match or a direct
  label-DB hit — never inference.
- **UNRECOVERABLE means genuinely gone** (mixed/burned/unfollowable). Everything
  identified-but-not-freezable-today is TRACKED + watched, not written off.

---

## 5. How to test tonight
Follow **`JACOB_TESTING_TONIGHT.md`** — setup + 9 numbered tests, each with the exact
command, expected output, and a PASS/FAIL bar. Highlights:
1. Full suite → `5409 passed`.
2. Offline E2E golden case → `12 passed`.
3. Generate + eyeball deliverables (LE / freeze letters / flow graphic / TRACKED pills).
4. Bridge staleness monitor → `OK=9`, exit 0.
5. `confirm-bridge` spot-check on any real bridge tx (12 protocols).
6. Score test → `REACHED 4/4`.
7. Optional full live Zigha trace (the 4/4 repeat).
8. **Anti-fluke / no-answer-key proof** — re-run with a fresh `--case-id`, confirm 4/4.

---

## 6. Known / acknowledged (NOT bugs)
- Synapse classic = STALE, Synapse RFQ + Connext = DORMANT — all acknowledged in the
  monitor (volume moved/deprecated; specs still confirm historical cases).
- CCTP intentionally absent (v2 omits the on-chain source nonce).
- ~166 pre-existing `src` style lints (E402/N806/SIM105/SIM108) deliberately left —
  scoped out by prior zero-tolerance sweeps; touching them is churn for no behavior gain.
  Everything changed this cycle is lint-clean.
- PDF rendering needs WeasyPrint+GTK; if absent the pipeline emits HTML (not a defect;
  prod/Linux has it).

---

## 7. Where things live
- Bridge oracle: `src/recupero/trace/bridge_pairings.py`
- Dormant-window fix: `src/recupero/trace/tracer.py::_tx_within_window`
- TRACKED + auto-watch: `src/recupero/reports/emit_brief.py`, `src/recupero/monitoring/subscriber.py`, `src/recupero/worker/pipeline.py`
- Staleness monitor: `scripts/_v034_bridge_staleness.py`
- Ground-truth scorer: `scripts/_v034_score_zigha_reach.py`
- Test runbook: `JACOB_TESTING_TONIGHT.md`

## 8. What I need from you
1. Run the runbook (esp. steps 1–4 + the step-8 anti-fluke re-trace) and confirm green.
2. Eyeball one LE handoff + a freeze letter + the flow graphic.
3. Flag anything that prints a fabricated address, a `high` cross-chain edge without a
   matching dest tx, a NEW STALE/DORMANT bridge, a broken template token, or a fresh-dir
   trace that does NOT score 4/4.

Prod is live at `ac8d0b2`. Migrations (if any) are applied MANUALLY — none required for
this cycle (no schema changes).
