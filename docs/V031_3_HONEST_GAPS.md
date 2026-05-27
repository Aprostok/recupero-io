# v0.31.3 Honest Gaps — Independent Audit

HEAD: `cc91d8d` (v0.31.3). Audit method: read the code, ignore the "DONE" labels.
Verified each claim against the actual source (paths cited inline).

---

## 1. Real gaps still open (forensic correctness / completeness)

### 1a. Point-in-time labels are implemented but never called with `at=`
The biggest correctness gap of v0.31.x.

- `LabelStore.lookup(point_in_time=...)` is implemented in `src/recupero/labels/store.py:85-137`.
- Tests in `tests/test_v031_2_point_in_time_labels.py` exercise the API in isolation only.
- **Zero production call sites pass `point_in_time=`.** Verified via grep:
  - `src/recupero/inspect/inspector.py:51, 144`
  - `src/recupero/freeze/asks.py:314, 876`
  - `src/recupero/trace/tracer.py:1039`
  - `src/recupero/trace/indirect_exposure.py:457, 461`
  - `src/recupero/trace/clustering.py:571, 705, 815, 819`
  - `src/recupero/trace/cex_continuity.py:126`
  - `src/recupero/reports/brief.py:1348`

Every one of these resolves labels at *current* time, not `case.incident_time`. The forensic claim is "this address was a known mixer at the time of the theft" — today the brief actually claims "this address is currently a known mixer." That distinction matters in court for any case older than the last label-DB refresh.

### 1b. Bridge protocols with seed entries but NO decoder
Read of `bridge_calldata.py` enumerates decoders for: Wormhole, Across, Stargate, DeBridge (recognition-only), 1inch (recognition-only), Connext/Everclear, Axelar, LiFi, Hop, Squid, Celer, Synapse, Symbiosis (partial). Seeds counted with `python -c "json.load(...)"`:

| Protocol         | Seed entries | Decoder?                      | Forensic priority |
|------------------|--------------|-------------------------------|-------------------|
| Stargate         | 38           | yes (full)                    | -                 |
| Wormhole         | 20           | yes (full)                    | -                 |
| Hop              | 14 + 3       | yes (v0.31.1)                 | -                 |
| Axelar           | 12           | yes (v0.31.0)                 | -                 |
| Symbiosis        | 9            | partial (recipient only, no chain) | **HIGH** — 2024-25 drainer scene |
| Synapse / LiFi   | 9 each       | yes (v0.31.2 / v0.31.0)       | -                 |
| Celer / Squid    | 8 each       | yes                           | -                 |
| Connext          | 8            | yes (v0.31.0)                 | -                 |
| **LayerZero**    | **7**        | **NO** — only Stargate routes are decoded | **HIGH** — raw LZ endpoint txs are silently dropped |
| DeBridge         | 5 + 3        | **recognition-only** (no destination)   | **HIGH** — DLN orders frequently named in OFAC actions |
| Across V3        | 5            | yes                           | -                 |
| **Chainlink CCIP** | **2**      | **NO**                        | **HIGH** — institutional bridge, becoming common |
| **Chainflip**    | 1            | **NO**                        | MEDIUM — used in 2025 BTC laundering paths |
| **Socket**       | 1            | **NO**                        | MEDIUM — aggregator, may wrap unknown bridges |
| **Allbridge**    | 1            | **NO**                        | MEDIUM — Solana ↔ EVM, ransomware-adjacent |
| **Multichain (Anyswap)** | 1    | **NO**                        | HIGH — exit-scam history; legacy contracts still see transit |
| **Stargate V2**  | 1            | **NO** (v1 decoder may match selectors) | MEDIUM |

The bare-chain labels ("Polygon: bridge", "Arbitrum: bridge", "Base: bridge", "zkSync Era: bridge", "Avalanche: bridge", "Optimism: bridge", "Gnosis Chain: bridge") are L1↔L2 canonical bridges with no calldata decoder. Lower priority than Multichain/CCIP/DeBridge but absent.

DeBridge is the most painful: `_decode_debridge` returns `confidence='low'` with no destination, so the BFS never auto-continues despite DLN being a top-5 protocol for stolen-fund movement.

### 1c. Symbiosis decoder is half-built
`_decode_symbiosis` extracts the relay recipient via a fixed slot offset but only *heuristically* scans for the destination chain ID inside `otherSideCalldata`. The code admits this (lines 1532-1564: "we follow the LiFi conservative-scan approach"). No test fixture validates the chain extraction against a real mainnet tx.

### 1d. Hyperliquid `unknown_destination` placeholder is permanent
`src/recupero/chains/hyperliquid/scraper.py:183` emits `hyperliquid:unknown_destination` when `delta.destination` is missing. No resolution path exists — these counterparties are dead-ends in the trace.

### 1e. Multichain (Anyswap) re-listing
Multichain exit-scammed in 2023 but legacy router contracts still receive transit traffic. One seed entry, no decoder. If a 2022-2023 incident is traced today, the Multichain handoff renders as a generic "bridge" with no destination chain.

---

## 2. Integration gaps (features that exist but don't flow into operator output)

### 2a. Retrace backfill cron is not scheduled anywhere
- `scripts/retrace_backfill_scan.py` and `scripts/retrace_on_label_update.py` exist.
- `railway.json` ships ONLY `recupero-worker`. No `.github/workflows/` directory exists. No `cron`/`schedule`/`k8s CronJob` config in repo (grep returned only doc files).
- Verdict: the v0.31.2 backfill feature can only be run manually. Operators have no schedule.

### 2b. CEX continuity is opt-in and default-OFF
`src/recupero/trace/cex_continuity.py:30` — gated on `RECUPERO_CEX_CONTINUITY=1`. The brief section never renders unless an operator sets the env var. Combined with no documentation (see 5b), this feature is invisible in production today.

### 2c. Dust-attack filter is opt-in and default-OFF
`src/recupero/trace/tracer.py:1190-1192` — gated on `RECUPERO_DUST_ATTACK_FILTER` ∈ `{"1","true","yes","on"}`. Comment on line 433 explicitly says "OFF by default to avoid changing existing case-rendering tests." The real-case improvement is therefore zero unless an operator opts in.

### 2d. output_integrity validators do not cover v0.31.x sections
Grep of `src/recupero/validators/output_integrity.py` for the new context keys (`CEX_CONTINUITY_LEADS`, `MEV_SIGNALS`, `INDIRECT_EXPOSURE_V031`, decoded `cross_chain_handoffs.new_handoffs`) returned zero matches. INVARIANTS A-E cover the v0.27/v0.28 surfaces; v0.31 sections render unvalidated.

### 2e. MEV / clustering / indirect-exposure ARE wired (give credit)
`emit_brief.py` does import and call `detect_mev_signals` (line 1559), `compute_clusters_with_metadata` (line 1357), `compute_indirect_exposure` (line 1435), and `identify_cex_continuity_leads` (line 1726). Only the env-gated ones (CEX continuity, dust filter) fail to render under defaults.

---

## 3. Default-value gaps (operator footguns)

| Tunable | Default | Risk | Fix |
|---|---|---|---|
| `TraceParams.max_depth` | **2** | A 10-hop laundering chain through dust-scatter terminates at hop 2. The env-var allows up to 8 (`tracer.py:126`). Original "Hop-limit default 4" closure claim does not match the code. | Bump default to 3 or 4 for production. |
| `TraceParams.dust_threshold_usd` | **10.0** | Sophisticated showers stay at $9.99 — the attack-style dust filter at $1.00 is what would catch them, but it's OFF. | Either lower this to $1, or set `RECUPERO_DUST_ATTACK_FILTER=1` in the deployment env. |
| `RECUPERO_DUST_ATTACK_FILTER` | OFF | See 2c. | Default ON for production, OFF in tests. |
| `RECUPERO_CEX_CONTINUITY` | OFF | See 2b. | Default ON (with `requests_per_second` budget guard already present). |
| `RECUPERO_CROSS_CHAIN_CONTINUATION` | ON (opt-out, v0.28.0) | This one is correct. | — |

---

## 4. Quality gaps (untested code paths, mutation gaps, fuzz gaps)

### 4a. Mutation harness has not been extended for v0.31.x
`scripts/mutation_smoke.py` is hand-rolled (mutmut/cosmic-ray are Windows-incompatible on Py3.14). It targets 10 mutations across dispatcher, XFF, SSRF, canonical_address_key, PII redactor, subscriber helper, auth strip, ReDoS cap, and manifest schema. **Zero mutations** target:
- the 7 new bridge decoders (Hop, Squid, Celer, Synapse, Symbiosis, plus the already-shipped Connext/Axelar/LiFi)
- `dust_attack.identify_dust_attack_destinations` (the 2x ratio guard is a one-line mutation point)
- `cex_continuity.identify_cex_continuity_leads` (the ±5% tolerance + 6h window thresholds)
- `LabelStore.lookup` point-in-time filtering branches

### 4b. No property-based tests for new decoders
Grep of `tests/` for `@given` returns 13 files; none are the v0.31.x decoder tests. The new decoders parse hex-encoded calldata — a textbook hypothesis target. The existing `test_v031_*_decoders.py` tests use fixed sample calldata, not strategies.

### 4c. No golden-case end-to-end fixture
No `tests/integration/test_trace_to_brief.py`. Verified via Glob — no `tests/integration/` directory exists. The closest is `tests/test_v030_4_finish.py` (regression spot-checks). A canonical "Zigha trace → brief → freeze letter" fixture that exercises the full pipeline does not exist; each subsystem is tested in isolation.

### 4d. Symbiosis decoder has no real-mainnet fixture
See 1c. The "candidate-scan" extraction is unverified against on-chain data.

---

## 5. Operational gaps (cron not scheduled, env vars not documented, data freshness)

### 5a. No scheduled cron infrastructure
- No `.github/workflows/`, no `crontab`, no k8s manifests. Only `railway.json` with a single web-worker entrypoint.
- `scripts/retrace_backfill_scan.py`, `scripts/retrace_on_label_update.py`, `scripts/nightly_audit.py`, `scripts/prewarm_pricing_cache.py`, `scripts/check_stale_reviews.py` all exist but are not scheduled. They can only run when an operator SSHes in.

### 5b. v0.31.x env vars are essentially undocumented
Of 11 new v0.31.x env vars, only 1 (`RECUPERO_CROSS_CHAIN_CONTINUATION`) appears in the docs, and only because of v0.28.0:

```
0 docs hits: RECUPERO_DUST_ATTACK_FILTER
0 docs hits: RECUPERO_CEX_CONTINUITY
0 docs hits: RECUPERO_TRACE_MAX_HOPS
0 docs hits: RECUPERO_TRACE_DUST_USD
0 docs hits: RECUPERO_CROSSCHAIN_WINDOW_HOURS
0 docs hits: RECUPERO_DUST_ATTACK_THRESHOLD_USD
0 docs hits: RECUPERO_DUST_ATTACK_MIN_FANOUT
0 docs hits: RECUPERO_CEX_CONTINUITY_MIN_USD
0 docs hits: RECUPERO_CEX_CONTINUITY_WINDOW_HOURS
1 docs hits: RECUPERO_DESTINATION_DUST_USD
2 docs hits: RECUPERO_CROSS_CHAIN_CONTINUATION
```

No `docs/ENV_VARS.md`. The only canonical surface is the source-code docstrings.

### 5c. OFAC sync has no scheduled refresh
`src/recupero/trace/ofac_sync.py` and `src/recupero/ops/commands/ofac_sync_cmd.py` exist, but neither is invoked from `src/recupero/worker/`. No scheduler triggers them. Whatever freshness OFAC has is whatever was last manually run.

### 5d. CEX hot-wallet rotation has no refresh process
`labels/seeds/cex_deposits.json` Tron/Solana entries all bear `added_at: 2026-05-26T00:00:00Z` — they ARE fresh today. But there is no documented quarterly refresh process or alert when entries pass 90 days old. Binance/Coinbase rotate hot wallets quarterly; in 90 days these will be stale and the trace will silently miss new CEX deposits.

### 5e. Pricing failure mode is "(unpriced)" only
`src/recupero/pricing/coingecko.py:479` — when CoinGecko returns null, `usd_value_at_tx` becomes None. The brief renders these as "(unpriced)" (already hardened against NaN). There is no secondary provider (Coinbase, DeFiLlama) wired in. If CoinGecko rate-limits during a high-traffic incident, the entire Section 4 USD column reads as "(unpriced)" with no degraded-but-useful fallback.

---

## 6. What's actually done — don't undersell

These are real wins and should not be relitigated:

- **13 bridge decoders shipped** (Wormhole, Across V3 + legacy, Stargate, DeBridge recognition, 1inch recognition, Connext, Axelar, LiFi, Hop, Squid, Celer, Synapse, Symbiosis partial). That's substantial coverage.
- **Wallet clustering (`compute_clusters_with_metadata`)** is wired into the brief at `emit_brief.py:1357`.
- **Indirect exposure (v0.31)** has BOTH the legacy and v0.31 sections rendered (`_build_indirect_exposure_section` + `_build_indirect_exposure_v031_section`).
- **MEV detection** is detect-and-report-only, wired at `emit_brief.py:1559`, rendered as a "MEV-obfuscated transfers" panel.
- **Cross-chain BFS continuation** flipped to opt-OUT in v0.28.0 — correct decision.
- **Bridge label DB** went from ~30 entries (pre-v0.29) to 183 entries with structured `supports_to_chains` and `follow_up_url` fields. The label DB itself is high quality.
- **Address sanitization, NaN guards, path-traversal hardening** across ingest layers — verified present in `bridge_calldata.py`, `dust_attack.py`, `cex_continuity.py`. The Jacob RIGOR sweep work is real.
- **Output integrity invariants A-E** are present and tested. They just don't yet cover v0.31.x sections.
- **v0.31.x dust-attack filter is well-built code** (NaN-safe, threshold-clamped, 2x ratio guard). It's just default-off.

---

## Top 5 gaps ranked by forensic impact

1. **Point-in-time labels never called with `at=`** — every "this was a known mixer at time of theft" claim in every brief is actually "this is currently a known mixer." Code exists, integration missing. (1a)
2. **Default `max_depth=2`** — laundering chains beyond 2 hops get truncated. The 8-hop cap in env-var math is theoretical; nothing sets it. (3)
3. **DeBridge / Multichain / LayerZero / Chainlink CCIP have no destination decoder** — these are in seeds, get recognized, but BFS cannot follow. Real 2024-2025 cases route through them. (1b)
4. **Dust-attack filter is default OFF + undocumented** — the feature exists, works, would help real cases, and the runbook doesn't tell operators it exists. (2c, 5b)
5. **No scheduled cron in production** — retrace backfill, OFAC sync, label-update retrace, stale-review checks, pricing prewarm all exist as `scripts/*.py` but `railway.json` only runs `recupero-worker`. (5a, 5c)
