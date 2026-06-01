# Jacob — testing note for tonight (v0.34.3, 2026-06-01)

**TL;DR:** The cross-chain bridge oracle went from 8 → **12 cryptographically-verified
protocols**, plus a durable staleness monitor that catches spec drift before prod.
Everything is **merged to `main` and deployed** (Railway auto-deploys main; prod HEAD
= `73c576b`). Full suite **5407 passed / 31 skipped / exit 0**, zero new ruff. Below
is what changed, what I verified, and exactly how to re-run each check.

---

## What shipped this round

A "bridge hop is CONFIRMED iff the protocol's OWN cross-chain id appears on BOTH
chains" — cryptographic proof, no answer key. `high` cross-chain confidence is ONLY
ever granted on such a match; otherwise the engine returns `None` (never a guess).

**Oracle now covers 12 protocols** (each verified against a REAL on-chain pair and
confirmed end-to-end through `identify_source` + `confirm_bridge_destination`):

| Protocol | Cross-chain id | Notes |
|---|---|---|
| deBridge (DLN) | orderId | **refreshed** — fill event changed at same contract post-Zigha |
| Across | depositId + originChain | composite key |
| Celer cBridge | srcTransferId | |
| Hop | transferId | dest wildcard |
| Synapse (classic) | kappa (derived) | historical only — current volume moved to RFQ |
| **Synapse RFQ** *(new)* | transactionId | FastBridgeV2 0x5523… |
| Chainlink CCIP | messageId | success-state gated |
| Connext | transferId | dormant (Amarok→Everclear) |
| Wormhole | VAA (emitterChainId,addr,seq) | |
| **Stargate V2** *(new)* | LayerZero GUID | eid namespace |
| **LayerZero OFT (generic)** *(new)* | LayerZero GUID | catches ALL OFT bridges, not just Stargate |
| **Axelar / Squid** *(new)* | payloadHash + sourceTxHash tiebreak | GMP rail |

**Not added (deliberately): Circle CCTP.** Investigated and found NOT on-chain-pairable
in 2026 — v1 EVM↔EVM volume migrated to v2, and CCTP v2's `DepositForBurn` omits the
nonce (assigned later by Circle's off-chain attestation), so v2 can't be paired from
source events without Circle's API. No half/wrong spec was shipped.

**New durable guard:** `scripts/_v034_bridge_staleness.py` — audits all 12 specs over a
wide on-chain window with a 3-way OK / STALE / DORMANT classification, and fails only on
NEW (unacknowledged) drift. This is what caught the DLN event change. Run it whenever a
bridge "stops confirming."

---

## How to re-run every check (the ones you asked about)

> All commands from the repo root. Use `RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret`
> for the gate. Non-ASCII output needs `PYTHONIOENCODING=utf-8` on Windows.

### 1. Full test suite (the "does the code work" gate)
```bash
RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret python -m pytest -q -p no:cacheprovider
```
**Verified:** `5407 passed, 31 skipped, 16 deselected, exit 0`.

### 2. End-to-end golden case (LE + freezes + brief + invariants + determinism, OFFLINE)
```bash
RECUPERO_RUN_INTEGRATION=1 RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret \
SOURCE_DATE_EPOCH=1747785600 \
python -m pytest tests/integration/test_trace_to_brief.py -q -p no:cacheprovider
```
**Verified:** `12 passed`. Covers the full pipeline (emit_brief + build_all_deliverables
+ validate_case_output), multi-issuer freeze routing (Midas/Tether/Circle/Coinbase),
mixer exposure, INVARIANTS A–E = 0 violations, and 3× byte-identical determinism.

### 3. Real deliverable generation (LE files, freeze letters, brief, graphics)
```bash
RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret python scripts/smoke_deliverables.py
# output → scripts/_smoke_deliverables_out/ALEC-TEST-2026/briefs/
```
**Verified:** 12 artifacts written (trace report, victim summary, engagement letter,
per-issuer `freeze_request_*` + `le_handoff_*`, manifests, investigator findings) PLUS
`flow_<hash>.svg`. All HTML scanned clean — no unrendered Jinja / Undefined / NaN / None.
- **LE handoff**: correct issuer (Circle/USDC), FREEZABLE holdings, IC3 reference.
- **Freeze routing is correct**: Circle + Tether (HIGH, 4 FREEZABLE holdings each) get
  letters; **Lido stETH (LOW, 0 FREEZABLE-status holdings) correctly gets NO letter** —
  the "no $0 freeze letter" guard works.
- **Graphics**: `flow_*.svg` is a real graphviz fund-flow diagram (103 node groups, 60
  edges, 88 labels). Needs the `dot` binary (graphviz) — present on the prod image.

### 4. PDF rendering — environment note (NOT a code bug)
On this Windows box WeasyPrint can't load GTK (`libgobject-2.0-0`), so the PDF stage is
skipped and HTML is emitted instead. **On the Linux prod/Jacob image WeasyPrint + GTK +
graphviz are present, so PDFs (with the embedded flow graphic) render.** To force-skip
PDFs anywhere: `RECUPERO_DISABLE_PDF_RENDER=1`.

### 5. Score test (ground-truth reach)
```bash
PYTHONIOENCODING=utf-8 python scripts/_v034_score_zigha_reach.py <CASE_ID>
# e.g. ZIGHA-VERIFY-VT5
```
Scores addresses reached in `data/cases/<CASE_ID>/case.json` against the 4 expected
endpoints in `tests/fixtures/zigha_ground_truth.json`. The **full depth-7 multichain
case reaches 4/4** (incl. the Midas FREEZABLE endpoint); the small capped local
fixtures (VT4/VT5, 8–9 transfers) reach 1–2/4 because they only contain a slice of the
graph. Always prints; exit 0 (reports misses without failing).

### 6. Spot-check ANY bridge tx (cryptographic confirmation, standalone)
```bash
recupero confirm-bridge --chain <src> --tx <hash>     # gated behind RECUPERO_BRIDGE_CONFIRM
```
Prints the confirmed destination (chain, tx, recipient, order-id) or nothing if there's
no cryptographic match — never a guess.

### 7. Bridge-spec staleness monitor (run if a bridge "stops confirming")
```bash
PYTHONIOENCODING=utf-8 python scripts/_v034_bridge_staleness.py   # reads ETHERSCAN_API_KEY from .env
```
**Verified:** `OK=9` (DeBridge, Across, Celer, Hop, CCIP, Wormhole, Stargate, LayerZero
OFT, Axelar). STALE=Synapse (acknowledged: classic rail, historical). DORMANT=Synapse
RFQ + Connext (acknowledged: low/no current volume). Exit 0.

---

## Known / acknowledged (not bugs)
- **Synapse classic = STALE, Synapse RFQ + Connext = DORMANT** — all acknowledged in the
  monitor + spec notes (volume moved/deprecated; specs stay correct for historical cases).
- **CCTP intentionally absent** (see above — v2 omits the on-chain source nonce).
- **Pre-existing src lints (~202, mostly SIM105/E402/N806)** are the deliberately-tolerated
  style items from prior zero-tolerance sweeps; left untouched to avoid churning the green
  suite. All files changed this round are ruff-clean; zero new lint introduced.

## What to hammer tonight
1. Run #1 + #2 + #3 above — confirm green + eyeball a freeze letter and the LE handoff.
2. If you have a fresh real bridge tx (any of the 12 protocols), try #6 `confirm-bridge`.
3. If anything bridge-related looks off, run #7 — it'll tell you if a spec drifted.

Prod HEAD: `73c576b` (main). Bridge oracle source: `src/recupero/trace/bridge_pairings.py`.
