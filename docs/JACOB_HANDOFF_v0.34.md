# Recupero — Jacob Handoff (v0.34)

**Prepared:** 2026-05-30 · updated 2026-06-01 (bridge cycle) · **Prod HEAD:** `main` @ `83e915e` (Railway auto-deploys `main`; bridge cycle pending merge from `pdf-deliverables`)
**Test suite:** 5,392 passed / 0 failed / 31 skipped (full gate, real exit code)

This note is deliberately scoped: it states what is **certified**, what is the **open
frontier**, and the exact **acceptance test** to run. Nothing here overclaims.

---

## TL;DR

Recupero is a correct, honest crypto-forensics deliverable engine. It traces a
victim seed against **live** chain state, identifies the **freezable / actionable**
destinations, labels them correctly, and renders LE + freeze deliverables that pass
50 structural integrity checks. It does **not** fabricate wallets, does not overclaim
confidence, and — new in v0.34 — **refuses to imply a complete trace when it wasn't**
(coverage notice). The open frontier is **deep, aggregator-mediated recall** on
poison-heavy cases, which is throughput-bound (API tier) and now self-disclosing.

---

## CERTIFIED (safe to rely on)

1. **Deliverable correctness.** Given identified end points, the brief / LE-handoff /
   freeze-request / recovery-snapshot render correctly, land each address in the right
   per-issuer freeze file, and pass `validate_case_output` with **0 critical / 0 high**
   across 50 checks. Deterministic (byte-identical re-runs).
2. **No fabricated wallets.** Every bridge decoder requires a right-aligned ABI address
   (top-12-bytes-zero) before surfacing a destination (#228/#229) — a uint256 / non-EVM /
   misaligned slot can never become a "destination." Fabricated/checksum-invalid seed
   addresses were purged; a repo-wide checksum guard prevents recurrence.
3. **Correct labels.** Sanctioned coverage flows from the authoritative OFAC SDN feed
   (not hardcoded guesses); Tornado Cash correctly reflects its 2025-03-21 delisting
   (high-risk mixer, **not** OFAC-sanctioned); screener verdict tiers are correct.
4. **Honest confidence.** "High" only for cryptographic identity or a label-DB hit —
   never inference. CEX-withdrawal clustering splits deposit-address (high) vs shared
   hot-wallet (medium).
5. **Live tracing.** Fetches from the incident block **forward to the current block**
   and reads **current** balances — not a frozen window. Proven against mainnet.

## NEW in v0.34 — coverage honesty (the maturity feature)

`case.config_used["coverage"]` + a `COVERAGE_NOTICE` in the brief now fire whenever a
trace ran reduced: **address-poisoning detected** OR a **per-address fetch cap truncated**
an address. A reduced/poisoned trace can **no longer be silently stamped "complete"** —
the deliverable says "coverage may be incomplete — re-run recall-complete" with the exact
parameters. This is what makes a handoff safe: you will always know when the trace didn't
go all the way.

---

## NEW in v0.34 (bridge cycle) — answer-key-free cross-chain confirmation

The biggest gap a single-chain tracer has is the **bridge**: funds cross a chain and
the trail dead-ends, and every prior source→destination pairing was amount+time
*correlation* ("never proof", capped medium/low). v0.34 closes this with a
**cryptographic** confirmation engine (`src/recupero/trace/bridge_pairings.py`):

- **The oracle.** A bridge stamps a unique cross-chain id (order-id / message-id /
  transferId / kappa / VAA key) on the SOURCE order event; the DESTINATION fill event
  references the SAME id. Matching them is **proof** — no human answer key. This is the
  ONLY basis on which a cross-chain edge may be `high`.
- **8 protocols, all live-verified end-to-end** against a real source+dest pair before
  shipping (the discipline that prevents the wrong-signature class of bug): **deBridge
  DLN, Across, Celer, Hop, Synapse, Chainlink CCIP, Connext (Amarok), Wormhole.** Four
  pairing shapes (32-byte data id, indexed composite key, derived keccak id, VAA
  composite emitterChainId+emitterAddress+sequence).
- **Standalone tool:** `recupero confirm-bridge --chain <src> --tx <hash>` finds the
  on-chain destination of any supported bridge tx (e.g. the Zigha DLN hop →
  `0xc1ee32fa…`, 2,919,869 DAI, confirmed live). Returns `None`, never a guess, when no
  id-matched fill exists.
- **Wired into the trace** (opt-in `RECUPERO_BRIDGE_CONFIRM=1`, default OFF — adds live
  dest-chain queries): the cross-chain continuation prefers a cryptographically-confirmed
  recipient over the heuristic calldata decode and records every confirmation on
  `case.config_used["bridge_confirmations"]`.
- **Self-audit (Phase 2).** `validators/cross_chain_integrity.py` enforces, with no
  answer key: a cross-chain edge may be `high` ONLY with its proof present
  (`cross_chain_edge_confirmed`, critical), and same-asset hops must conserve value
  within the protocol fee bound (`cross_chain_value_conserved`, high). A human-auditable
  per-case report (`render_bridge_confirmation_report`) is the proof a reviewer reads
  instead of an answer key. See `docs/BRIDGE_PAIRING.md`.

Also this cycle: a **pruning deep-dive** fixed a CRITICAL forensic bug — the value-trace
same-asset match compared token SYMBOL only, so a spoof token with a colliding symbol
(fake "USDC") could be matched as the real asset and promoted to medium, *fabricating a
destination*. Now same-asset requires canonical **contract identity** (+ 5 more
correctness/coverage fixes: dust-aware inbound selection, tz-normalize, cap-slice-skip
under the lightweight path, etc.). And the wrong, no-bytecode Ethereum Wormhole Token
Bridge address in the seed DB (`0x3ee18B…E54347AE7C7E4`) was found + removed (verified
`eth_getCode == 0x`); the canonical `0x3ee18B…E7C347E8fa585` entry remains.

## OPEN FRONTIER (not yet certified)

**Deep, aggregator-mediated recall on poison-heavy cases.** On the live Zigha case
(seed `0x0cdC…955`, ~$17M), the tracer reliably reached the **freezable/actionable**
layer but the full trail to the deepest resting addresses is unproven end-to-end:

| Zigha ground-truth end point | Status |
|---|---|
| Consolidation hub `0xf4be227b…` | ✅ reached (live) |
| Midas mSyrupUSDp `0x3e2e66af…` ($3.12M, FREEZABLE) | ✅ reached (live) |
| Dormant DAI `0x3dafc6a8…` ($10.08M, **UNRECOVERABLE** — permissionless DAI) | ⏳ deep-recall: [PENDING acceptance run] |
| Dormant DAI `0x415d8d07…` ($6.91M, **UNRECOVERABLE**) | ⏳ deep-recall: [PENDING acceptance run] |

On-chain investigation (no full trace needed) established the two dormant-DAI addresses
are **real and hold the funds**, but sit **~5–7 hops deep** behind an aggregator
(`0x663dc15d…`, which pools DAI from dozens of sources) **after an asset conversion**
(hub held mSyrupUSDp/ETH; these rest in DAI), with **address-poisoning lookalikes at every
layer**. Reaching them is a depth + throughput + de-poisoning problem, not a correctness
defect — and the coverage notice flags it honestly when a run stops short.

> Note: those two are labeled **UNRECOVERABLE** (permissionless DAI, no issuer freeze) —
> they matter for the *complete forensic trail / seizure picture*, not for freeze targeting.
> The freeze-actionable layer is what the tracer reaches today.

---

## ACCEPTANCE TEST (run this to close the frontier)

Requires a **paid Etherscan tier** (free = 3 calls/s, throttles to ~1 hr/case). On
Standard (10/s) a heavy case is ~15–30 min; uncapped deep traces can approach the
200k/day cap.

```bash
# In the recupero-io repo, with ETHERSCAN_API_KEY (Standard+) + COINGECKO_API_KEY in .env:
RECUPERO_ETHERSCAN_RPS=10 \
RECUPERO_MAX_TRANSFERS_PER_ADDRESS=0 \
RECUPERO_TRACE_MAX_HOPS=7 \
RECUPERO_TRACE_DUST_USD=50 \
python -m recupero.cli trace \
  --chain ethereum --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
  --incident-time 2025-10-09T00:00:00Z --case-id ZIGHA-VERIFY \
  --max-depth 7 --dust-threshold-usd 50 --follow-bridges
```

Then drop `tests/fixtures/zigha_ground_truth.json` into the case dir as
`ground_truth.json` and run `validate_case_output` — INVARIANT B reports exactly which
of the 4 ground-truth addresses were reached. **Pass = all 4 present (or the coverage
notice honestly explains what was capped).**

`RECUPERO_ETHERSCAN_RPS` and the other `RECUPERO_*` knobs are **process/deployment env
vars** (set in Railway for prod), not `.env` — `.env` is secrets-only by design. See
`docs/ENV_VARS.md`.

---

## OPS PREREQS

- **Migration 031** (`freeze_outcomes_one_silence_14d_per_letter`) must be applied to the
  prod Supabase DB (migrations are **manual**: `python scripts/apply_migration.py
  migrations/031_freeze_outcomes_silence_dedup.sql`). The deployed worker's silence_14d
  `ON CONFLICT` requires it. Verify:
  `SELECT 1 FROM pg_indexes WHERE indexname='freeze_outcomes_one_silence_14d_per_letter';`
- Version string in `pyproject` is stale ("0.32.0", never bumped) — identify builds by git SHA.

---

## KNOWN DEFERRED (flagged, not blocking)

- **freeze_outcomes write-dedup** (`record_outcome` / `close_case`): non-silence outcome
  types lack an ON-CONFLICT guard; a retry/concurrent submit could duplicate a row and
  inflate the recovered-USD figure. Proper fix needs a UNIQUE-constraint migration + an
  idempotency-key decision. (The priors pipeline already dedupes per-letter; only the
  recovered-$ sum is exposed.)
- **Poison-edge pruning**: a heuristic to drop zero-value / homoglyph / known-spam edges
  before fetch would make deep recall-honest traces tractable without a blunt dust floor —
  the highest-ROI next engineering step, pairs with a paid API tier.
