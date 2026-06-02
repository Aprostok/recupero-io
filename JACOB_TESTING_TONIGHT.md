# Recupero — Jacob testing runbook (v0.34.4, 2026-06-01)

Step-by-step for tonight. Each step has the **command**, the **expected result**, and
a **PASS/FAIL bar**. Everything below is verified green on my box except where noted.
Prod is already deployed (Railway auto-deploys `main`; prod HEAD = the v0.34.4 merge).

---

## 0. What changed this round (the thing to test)
1. **Cross-chain bridge oracle: 8 → 12 cryptographically-verified protocols** + a
   bridge-spec **staleness monitor**. A cross-chain hop is only ever `high` confidence
   when the protocol's OWN id matches on BOTH chains — otherwise the engine returns
   nothing (never a guess).
   - New rails: **Synapse RFQ/FastBridgeV2**, **Stargate V2**, **generic LayerZero OFT**
     (catches all OFT bridges), **Axelar/Squid GMP**. Refreshed: **deBridge DLN**.
   - Each was verified end-to-end against a REAL on-chain pair.
   - **CCTP intentionally NOT added** (v2 omits the on-chain source nonce → unpairable
     without Circle's API; no half-working spec shipped).
2. **v0.34.4 — dormant-aware cross-chain window (P0 recovery fix).** A 24h upper cap on
   cross-chain ONWARD hops was silently dropping dormant laundering destinations funded
   >24h after the bridge (the Zigha ~$16.9M DAI miss). Now lower-bound-only (a hop must
   be AFTER the bridge; **no upper cap by default**). The full Zigha trace now reaches
   **4/4** ground-truth endpoints (was 2/4) — deterministically, from on-chain data
   (NOT a fixture/answer key — verified by fresh-case-dir repeats; see step 9).
3. **v0.34.4 — TRACKED / watchable category.** Identified funds that aren't freezable
   today but still sit at a known address (dormant DAI, bridge-landed funds) are now
   **🟪 TRACKED** — surfaced with a per-issuer `total_tracked_usd` + a "monitoring for
   movement" note, AND **auto-enrolled in movement monitoring** so we get alerted if/when
   they move and can recover later. **UNRECOVERABLE is now reserved for genuinely-gone
   funds** (mixers, burns, unfollowable). Bridges traced to a destination → TRACKED.
4. **Code flatten**: behavior-preserving lint cleanup (gate-locked).

Full protocol list: DLN, Across, Celer, Hop, Synapse (classic), Synapse RFQ, CCIP,
Connext, Wormhole, Stargate, LayerZero OFT, Axelar.

---

## 1. Setup (once)
```bash
git checkout main && git pull origin main      # prod HEAD should be the v0.34.3 merge
pip install -e .                                # or your usual env bootstrap
```
**System deps for PDFs + flow graphics** (only needed for steps 3/8's PDF rendering):
- **graphviz** (`dot` on PATH) — for the fund-flow diagram. `dot -V` should print a version.
- **WeasyPrint + GTK** — for HTML→PDF. On Linux this is `libpango/libgobject` via the
  distro packages; on macOS `brew install weasyprint`. If absent, the pipeline **skips
  PDFs and still writes the HTML** (set `RECUPERO_DISABLE_PDF_RENDER=1` to force-skip).
- **.env**: `ETHERSCAN_API_KEY` (required for live trace + bridge spot-checks),
  `HELIUS_API_KEY` (only for Solana). `.env` is gitignored — never commit it.

> On every test command below: prefix `RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret`
> and, on Windows, `PYTHONIOENCODING=utf-8` for non-ASCII output.

---

## 2. Full test suite  ← start here
```bash
RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret python -m pytest -q -p no:cacheprovider
```
**Expected:** `5409 passed, 31 skipped, 16 deselected` (the 31 skips are live-API/Win32
symlink tests — fine to skip).
**PASS:** exit code 0, zero failures.

## 3. Offline end-to-end golden case (LE + freezes + brief + invariants + determinism)
```bash
RECUPERO_RUN_INTEGRATION=1 RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret \
SOURCE_DATE_EPOCH=1747785600 \
python -m pytest tests/integration/test_trace_to_brief.py -q -p no:cacheprovider
```
**Expected:** `12 passed`. This exercises the WHOLE pipeline offline — emit_brief +
build_all_deliverables + validate_case_output, multi-issuer freeze routing
(Midas/Tether/Circle/Coinbase), mixer exposure, **INVARIANTS A–E = 0 violations**, and
**3× byte-identical determinism**.
**PASS:** 12 passed, exit 0.

## 4. Generate the real deliverables and eyeball them
```bash
RECUPERO_RANDOMIZATION_SECRET=ci-smoke-secret python scripts/smoke_deliverables.py
# → scripts/_smoke_deliverables_out/ALEC-TEST-2026/briefs/
```
**Expected files:** trace report, victim summary, engagement letter, per-issuer
`freeze_request_*.html` + `le_handoff_*.html`, manifests, `investigator_findings.{csv,json}`,
and **`flow_<hash>.svg`** (the fund-flow graphic).
**Eyeball checklist (PASS bar):**
- **LE handoff** opens, shows victim/IC3/issuer, lists FREEZABLE holdings, no broken
  template tokens (no `{{ }}`, `Undefined`, `NaN`, `>None<`).
- **Freeze routing is correct**: a letter exists for each issuer that has a real
  FREEZABLE holding (Circle, Tether), and **NO letter** for an issuer with `$0`/zero
  FREEZABLE holdings (Lido) — the "no empty freeze letter" guard.
- **Flow graphic** (`flow_*.svg`) opens in a browser and shows nodes/edges/labels.
- **TRACKED funds visible (v0.34.4):** identified non-freezable holders (dormant DAI etc.)
  show a 🟪 **TRACKED** pill + "monitoring for movement" note — NOT written off as
  UNRECOVERABLE. (UNRECOVERABLE should appear only for mixers/burns.)
- (If WeasyPrint installed) matching `.pdf` files render with the graphic embedded.

## 5. Bridge staleness monitor (all 12 protocols)
```bash
PYTHONIOENCODING=utf-8 python scripts/_v034_bridge_staleness.py   # reads ETHERSCAN_API_KEY
```
**Expected:** `OK=9`; `STALE=['Synapse']` (acknowledged: classic rail, historical);
`DORMANT=['Synapse RFQ','Connext']` (acknowledged: low/no current volume); **exit 0**.
**PASS:** exit 0, and any STALE/DORMANT is in the acknowledged set (the script says so).
If a NEW protocol shows STALE/DORMANT and exit != 0, that's real drift — tell me.

## 6. Spot-check a bridge cryptographically (the headline feature)
```bash
RECUPERO_BRIDGE_CONFIRM=1 python -c "from recupero.cli import app; app()" \
  confirm-bridge --chain <src_chain> --tx <source_bridge_tx_hash>
```
Pick any recent bridge tx for one of the 12 protocols (e.g. a Stargate, Axelar, or DLN
source tx). **Expected:** it prints the confirmed destination (dest chain, dest tx,
recipient, the matched protocol id) — or **nothing/none** if there is no cryptographic
match (it never guesses). **PASS:** a real bridged tx confirms; a non-bridge tx returns
nothing.

## 7. Score test (ground-truth reach)
```bash
PYTHONIOENCODING=utf-8 python scripts/_v034_score_zigha_reach.py <CASE_ID>
```
Scores addresses reached in `data/cases/<CASE_ID>/case.json` vs the 4 expected Zigha
endpoints. Always exits 0 (reports misses without failing). See step 8 for what reach
to expect.

## 8. (Optional, ~10–40 min, API-heavy) Full live Zigha trace
```bash
RECUPERO_PIVOT_MULTICHAIN=1 RECUPERO_BRIDGE_CONFIRM=1 RECUPERO_VALUE_TRACE=1 \
RECUPERO_CROSS_CHAIN_CONTINUATION=1 RECUPERO_MAX_TRANSFERS_PER_ADDRESS=50000 \
python -c "from recupero.cli import app; app()" trace \
  --chain ethereum --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
  --incident-time 2025-10-09T00:00:00Z --case-id ZIGHA-TEST --max-depth 8
# then: python scripts/_v034_score_zigha_reach.py ZIGHA-TEST
```
**What to expect (v0.34.4):** the primary Ethereum trace completes, then the multi-chain
**pivot** identifies the Arbitrum consolidation hub `0xF4bE…` and re-traces it across
chains; the cross-chain continuation decodes the DLN ARB→ETH handoff, follows the landing
intermediary's onward DAI sends, and (with the dormant-window fix) **reaches all 4/4
ground-truth endpoints**: the hub, both dormant DAI holders (~$9.98M + $6.91M, now 🟪
TRACKED + watched), and the Midas FREEZABLE endpoint (~$3.12M). `python
scripts/_v034_score_zigha_reach.py ZIGHA-TEST` → `REACHED 4/4`.
**PASS:** trace completes (exit 0) and scores **4/4**, with the DAI holders showing as
TRACKED (not fabricated, not written off). No `high` cross-chain edge without a
cryptographic match.

## 9. Anti-fluke / no-answer-key proof (why 4/4 is REAL)
The trace reaches 4/4 from **on-chain data alone** — it does NOT read the answer key:
- The trace path (`run_trace`/pivot/`cross_chain`) reads `ground_truth.json` **nowhere**
  (grep it). The only consumer is the opt-in `output_integrity` validator, which no-ops
  unless a `ground_truth.json` is placed IN the case dir; the CLI runs above don't have
  one. The scorer reads `tests/fixtures/zigha_ground_truth.json` **post-hoc** to compare
  against an already-written `case.json` — it never feeds the trace.
- **Determinism:** run the step-8 trace with a FRESH `--case-id` (e.g. `ZIGHA-RECHECK-1`,
  then `ZIGHA-RECHECK-2`). Fresh case dirs have no fixture near them. Each must still
  score **4/4**. I ran three independent fresh dirs (0601b/c/d) — all 4/4. If yours
  differs, that's a real signal — tell me.
- **Mechanism (auditable in the trace log):** look for `cross-chain handoff decoded:
  bridge=deBridge DLN Source on Arbitrum → chain=ethereum … (confidence=high)` followed by
  `fetching outflows from=0x37fc5f76…` then `kept tx=… to=0x415D8D07…/0x3daFC6a8… 2000000
  DAI`. That's the engine cryptographically confirming the bridge and following the real
  money — no fixture involved.

---

## The money picture (Zigha case)
- **~$18–20M total traced as lost (4/4 endpoints reached).** The Arbitrum hub (~$18.13M)
  is the funds consolidated *before* bridging; they land on Ethereum across the endpoints
  (~$20M). Same money pre/post-bridge — do NOT sum to $38M.
- **~$3.12M is FREEZABLE** (Midas mSyrupUSDp — Midas can freeze).
- **~$16.9M (the two dormant DAI holders) is now 🟪 TRACKED + auto-watched** — identified,
  not freezable today, monitored for movement so it's recoverable later (no longer
  silently dropped or written off as UNRECOVERABLE).

## Known / acknowledged (NOT bugs)
- Synapse classic = STALE, Synapse RFQ + Connext = DORMANT — all acknowledged in the
  monitor (volume moved/deprecated; specs still correct for historical cases).
- CCTP intentionally absent (v2 design omits the on-chain source nonce).
- ~166 pre-existing `src` style lints (E402/N806/SIM105/SIM108) deliberately left — they
  were scoped out by prior zero-tolerance sweeps; touching them risks churn for no
  behavior gain. All code changed this round is lint-clean.
- PDF rendering needs WeasyPrint+GTK; if absent the pipeline emits HTML (not a defect).

## How to report back
For each step: the command, exit code, and the headline line (e.g. "5409 passed",
"OK=9 exit 0", "REACHED 4/4"). For step 4, attach or screenshot the LE handoff + a
freeze letter + the flow SVG. Flag anything that prints a fabricated address, a `high`
cross-chain edge without a matching dest tx, a NEW STALE/DORMANT bridge, a broken
template token, or a trace that does NOT score 4/4 on a fresh case dir.

Prod HEAD: the v0.34.4 merge on `main`. Bridge oracle: `src/recupero/trace/bridge_pairings.py`.
Dormant-window fix: `src/recupero/trace/tracer.py::_tx_within_window`. TRACKED + auto-watch:
`reports/emit_brief.py` + `monitoring/subscriber.py`. Monitor:
`scripts/_v034_bridge_staleness.py`. Score: `scripts/_v034_score_zigha_reach.py`.
