# Recupero Environment Variables — Canonical Reference

This file is the single source of truth for every `RECUPERO_*` env var
the application reads at runtime. Third-party secret env vars
(`HELIUS_API_KEY`, `ETHERSCAN_API_KEY`, …) are listed at the bottom in
their own section.

## Policy

1. **Every `RECUPERO_*` env var read in `src/recupero/**/*.py` MUST
   appear in this file.** The reverse also holds — the doc must not
   list env vars that no longer exist in source. Both directions are
   enforced by `tests/test_v031_4_env_vars_doc.py`, which scans the
   source with `ast` + regex at test time and asserts parity.

2. **Adding a new env var requires a doc update in the same PR.** The
   regression test fails on `git push` if a new `os.environ.get(...)`
   call lands without a row in the index table below.

3. **Operators view this doc inside the terminal via**
   `recupero-ops envvars` — the CLI prints the tabular index so the
   canonical list is reachable without browsing GitHub.

4. **Defaults are chosen to be production-safe.** Any var marked
   `REQUIRED` must be explicitly set in the deploy environment; the
   worker / API / CLI refuses to start (or degrades visibly) when it
   is missing.

5. **All numeric env vars used by the trace / cross-chain / dust /
   CEX-continuity stack reject NaN / ±Inf / negative values** and fall
   back to the documented default with a `log.warning`. This is the
   v0.31.1 "Jacob-style adversarial input" pattern — operators who
   typo a value get a loud warning, never a silently-poisoned trace.

---

## Index

| Name | Default | Type | Range / Format | Introduced | Purpose |
| ---- | ------- | ---- | -------------- | ---------- | ------- |
| **Trace tuning** | | | | | |
| `RECUPERO_TRACE_MAX_HOPS` | `config.trace.max_depth` (4) | int | `[1, RECUPERO_TRACE_MAX_HOPS_HARD_CEILING]` | v0.16.x | BFS depth cap; raise for deep-laundering paths. Industry-best ceiling 64 in v0.32.1+. |
| `RECUPERO_TRACE_MAX_HOPS_HARD_CEILING` | `64` | int | `[1, 1024]` | v0.32.1 | Upper bound on `RECUPERO_TRACE_MAX_HOPS`. v0.32.1+ industry-best raised from 8 → 64 so the tracer can chase 30-50 hop APT laundering chains. Operators on quota-constrained API plans set this lower. |
| `RECUPERO_MAX_TRANSFERS_PER_ADDRESS` | `config.trace.max_transfers_per_address` (50000) | int | `>= 0`; 0 disables | v0.32.1 | Per-address fetch cap. Industry-best default bumped from 500 → 50000 so whale-wallet activity histories are followed in full. Set 0 to disable — pair with `RECUPERO_POISON_PRUNE=1` (the default) so an uncapped trace doesn't drown in address-poisoning spam. NOTE: this cap is a *blunt* defense — it keeps the FIRST N outflows and drops the tail, which can silently hide a real onward hop on a chatty/poisoned address. Prefer `0` (uncapped) + poison-pruning for elite recall. |
| `RECUPERO_POISON_PRUNE` | `1` (on) | bool | `{0,false,no,off}` to disable | v0.34 | Drop UNAMBIGUOUS poison edges (zero-value transfers — the canonical address-poisoning primitive) BEFORE pricing/following. Lets the tracer run UNCAPPED without (a) paying a CoinGecko contract-resolution call per throwaway poison token, or (b) ever truncating a real onward hop. NOISE removal only — never drops a value-bearing transfer — so it does NOT reduce coverage. Surfaced as informational `coverage.poison_edges_pruned`. |
| `RECUPERO_TRACE_DUST_USD` | `config.trace.dust_threshold_usd` (10) | float | `[0, 1_000_000]`, finite | v0.16.x | Per-transfer USD floor; below this is dropped as noise. |
| `RECUPERO_ETHERSCAN_RPS` | `4.0` (free-tier-safe) | float | `(0, 50]` | v0.34 | Etherscan V2 client requests/second — the combined per-chain rate, shared across the wave-thread pool. Default deliberately NOT raised: 4.0 already saturates the free tier (triggers 429 backoffs), so a higher default would only add retry-waits and slow free-tier traces. Set 15-20 on a paid tier to use the throughput you pay for. Run ~10-20% UNDER the plan's per-second cap (e.g. 9 on a 10/s plan) — sitting exactly at the ceiling triggers 429s. |
| `RECUPERO_COINGECKO_RPS` | `config.pricing.requests_per_second` | float | `(0, 100]` | v0.34 | CoinGecko price client requests/second. The demo tier self-paces to ~0.5/s and SILENTLY sleeps — the historical "freeze" where pricing thousands of transfers crawled with no error logged. On a paid plan set `COINGECKO_TIER=pro` AND this knob to ~10-20% under the plan's per-second cap (e.g. 4 on a 300/min = 5/s Basic plan). |
| `RECUPERO_TRACE_TIMEOUT_SEC` | `540` | int | `>= 0` | v0.16.11 | Wall-clock deadline before BFS exits with `trace_status=partial_deadline_hit`. |
| `RECUPERO_MAX_TRANSFERS_PER_CASE` | `50000` | int | `>= 0` | v0.16.11 | OOM defense — trace stops once this many transfers accumulate. |
| `RECUPERO_TRACE_CONCURRENCY` | `5` | int | `>= 1` | v0.16.x | Thread-pool size for parallel per-wave fetches. |
| `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` | `config.trace.service_wallet_outflow_threshold` (200) | int | `>= 1` | v0.34 | A wallet emitting more outflows than this is treated as a service/distributor: its transfers are kept but BFS traversal STOPS there (children not followed). Default 200 halts at exchange hot wallets / token distributors — but ALSO at a high-throughput DeFi aggregator/pool that sits ON the laundering path, silently missing everything past it. Raise (e.g. 25000) for a deep recall-complete run so the trace crosses the aggregator while still stopping at true mega-services. Bad/blank/non-positive keeps the resolved default. |
| `RECUPERO_SEED_FOLLOW_TOPN` | `50` | int | `>= 0` (0 = legacy skip) | v0.34.5 | When the SEED itself is high-fan-out (a perpetrator splitter emitting more than `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` outflows — e.g. the Lazarus/Ronin seed with 8,827), do NOT dead-end the whole trace: enqueue the top-N outflows BY VALUE (USD desc, then raw amount) so the investigation follows the largest dispersal legs. The enqueued children gain an inbound reference and trace value-DIRECTED from there, so branching stays finite (visited-set + `stop_at_exchange` + `max_depth` + per-case budget bound the rest). **Only active under `RECUPERO_VALUE_TRACE`** (the directed mode that keeps children bounded); ignored otherwise. `0` restores the legacy "skip a high-fan-out seed entirely" behavior. Bad/blank/negative keeps the default. |
| `RECUPERO_SERVICE_WALLET_FOLLOW_TOPN` | `8` | int | `>= 0` (0 = legacy skip) | v0.34.5 | Same as `RECUPERO_SEED_FOLLOW_TOPN` but for high-fan-out nodes encountered DEEPER than depth 0 (mid-route splitters / aggregators on the laundering path). A tighter N than the seed's because deep fan-out compounds; the value-direction of the enqueued children keeps the trace on the money. **Only active under `RECUPERO_VALUE_TRACE`.** `0` restores the legacy skip. Bad/blank/negative keeps the default. |
| `RECUPERO_VALUE_TRACE` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34 | Value-directed tracing. At a high-fan-out node (service wallet / aggregator / pool) — instead of stopping or following every edge — follow ONLY the outflow(s) whose **amount matches** the inbound funds (same-asset forwarding) or whose **USD value matches** across an asset conversion (swap), within a 72h window. This isolates the real onward hop behind a commingling node. Matches are INFERENCE: confidence is calibrated `medium` (sole same-asset amount match) or `low` (ambiguous / cross-asset) — **never `high`** — and surfaced under `coverage.value_matched_hops` with the match basis. Pair with `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` (raise it so the node is *reached*) for deep recall. |
| `RECUPERO_VALUE_TRACE_ENRICH_CEILING` | `50` | int | `>= 0` (0 disables) | v0.34 | Under value-trace, any non-seed node with MORE than this many outflows is built CHEAPLY (skip per-token CoinGecko contract-resolution + per-dest `is_contract` RPC + per-tx evidence fetch) — the wave aggregation value-matches the cheap set and re-does the expensive ops for ONLY the matched onward hop(s). Prevents the multi-hour wall where a high-fan-out node sits just under `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` and gets ~3 Etherscan RPCs per outflow. Lower for faster/cheaper runs; `0` disables the count trigger (only true service wallets get the cheap path). The seed (depth 0) is always fully enriched. |
| `RECUPERO_VALUE_TRACE_FOLLOW_SPLITS` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34.6 | Under value-trace, when a directed node has NO 1:1 onward match, try to recover a **1:N same-asset SPLIT/peel** — the node forwarded the inbound funds as many smaller same-token sends whose SUM is within ~3% of the inbound — and follow ALL its legs. Conservative: same on-chain token only (contract identity), greedy largest-first, must reach the sum within tolerance using ≤25 legs or it bails (honest dead-end, never a guess); a single over-large leg is excluded. Every followed leg is `low` confidence (a SET inference — which recipients are laundered funds vs. the node's own change isn't provable) and flagged `ambiguous` when the node had same-asset outflows outside the matched subset. Default OFF preserves every existing trace (incl. Zigha 4/4) byte-identically. Turn ON for deep peel-chain reach (e.g. Lazarus/Ronin consolidation wallets that peel into mixer-denomination chunks). Surfaced under `coverage.value_matched_hops` with `kind=same_asset_split`. |
| `RECUPERO_DEEP_REACH` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.35.4 | **Master switch** for cold-case "go as deep as possible" tracing — turns on the whole deep-reach recipe at once instead of 4 separate knobs: value-trace + 1:N split/peel follow + labeled mixer/exchange/bridge terminals + dormancy-aware window (=0). Only fills knobs that are NOT individually set — any explicit per-knob env var (or the `value_trace` arg) still wins, so you can `RECUPERO_DEEP_REACH=1` but pin one knob off (e.g. `RECUPERO_VALUE_TRACE_WINDOW_HOURS=168`). Default OFF ⇒ every existing trace (incl. Zigha 4/4) is byte-identical. Recommended for Lazarus/Ronin-class dormant multi-hop laundering. |
| `RECUPERO_VALUE_TRACE_WINDOW_HOURS` | `72` | int | `>= 0` (0 = no upper cap) | v0.35.2 | The time window, after an inbound, within which the value-matcher (1:1 same-asset / USD) AND the 1:N split detector accept an onward hop. **Dormancy-aware:** `0` = LOWER-BOUND-ONLY (a hop must be *after* the inbound; **no upper cap**) — laundering parks funds and moves them weeks/months later, so a fixed cap drops the real onward hop (same principle as `RECUPERO_CROSSCHAIN_WINDOW_HOURS`). Default `72` is conservative and preserves every existing trace (incl. Zigha 4/4) byte-identically; set `0` (or a large value) for deep cold-case reach (e.g. Ronin consolidation wallets forwarding past 72h before a mixer deposit). Bad/blank/negative keeps `0` semantics via the int parser (clamped `>=0`). |
| `RECUPERO_VALUE_TRACE_LABELED_TERMINALS` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34.7 | Under value-trace, STOP-AND-FLAG at a labeled terminal: at a directed node, same-asset outflows that land at a **labeled mixer / exchange / bridge** are the traced money's end state — record them (the brief then classifies the destination from its existing label: mixer→**UNRECOVERABLE**, exchange→**EXCHANGE**/subpoena, bridge→cross-chain handoff) but do NOT traverse. Mirrors how TRM/Chainalysis stop-and-flag at a mixer instead of chasing every pool deposit (e.g. Ronin peeled ~21,629 ETH into Tornado's 100-ETH pool ≈ 216 deposits → one truthful "→ Tornado Cash → UNRECOVERABLE", not 216 hops). Same-asset = same on-chain token (contract identity) as the inbound. Never fabricates (only real, already-label-enriched outflows). Surfaced under `coverage.labeled_terminals` (node, terminal, label, status, aggregate amount/USD, tx count, sample tx hashes). Default OFF preserves every existing trace (incl. Zigha 4/4) byte-identically. |
| `RECUPERO_PIVOT_MULTICHAIN` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34 | Multi-chain perpetrator pivot. After the victim trace, identify the consolidation **hub** (largest-USD unlabeled EOA recipient) and **re-trace it on every pivot chain** (value-directed), merging the findings. A victim trace on one chain can't see funds the perp split across chains (e.g. Arbitrum-bridged → Ethereum-DAI); pivoting on the hub surfaces them. OPT-IN — multiplies API cost by the number of pivot chains. |
| `RECUPERO_PIVOT_CHAINS` | `ethereum,arbitrum,base,optimism,polygon,bsc` | csv | `Chain` enum names | v0.34 | Comma-separated chains the multi-chain pivot re-traces the hub on (one Etherscan V2 key covers all EVM via chain_id). Unknown names skipped; the hub's discovery chain is auto-excluded. |
| `RECUPERO_PIVOT_MIN_USD` | `50000` | Decimal | `>= 0` | v0.34 | Minimum inbound USD for an address to qualify as a pivot hub — avoids burning N-chain traces on a dust counterparty. |
| `RECUPERO_MAX_CONTINUATION_SEEDS` | `25` | int | `>= 0` | v0.16.x | Cap on same-chain bridge / DEX continuation seeds per case. |
| `RECUPERO_MAX_CROSS_CHAIN_SEEDS` | `10` | int | `>= 0` | v0.16.13 | Cap on cross-chain destination seeds across all chains. |
| `RECUPERO_DISABLE_PASS2` | unset | bool | `=1` to disable | v0.20.x | Kill switch for the perpetrator-trace pass-2 stage. |
| `RECUPERO_PASS2_RATIO_THRESHOLD` | `100` | float | `> 0` | v0.20.x | Outflow/inflow ratio threshold for pass-2 candidate identification. |
| `RECUPERO_PASS2_BALANCE_THRESHOLD_USD` | `5000` | Decimal | `>= 0` | v0.20.x | Min current-balance USD for a pass-2 candidate. |
| `RECUPERO_PASS2_MAX_TRACES` | `3` | int | `>= 0` | v0.20.x | Max pass-2 traces per investigation. |
| `RECUPERO_INDIRECT_DECAY` | `0.5` | float | `(0, 1]` | v0.31.0 | Per-hop decay factor for indirect-exposure scoring (MVP). |
| `RECUPERO_INDIRECT_MAX_HOPS` | `3` | int | `>= 1` | v0.31.0 | Max BFS depth for MVP indirect-exposure scorer. |
| `RECUPERO_ADAPTIVE_DEPTH` | unset (off) | bool | `1/true/yes/on` to enable | v0.32.1 | Opt-in adaptive BFS depth: severity (theft USD) + API-budget headroom raise the depth ceiling for big cases. When off, depth is the static `RECUPERO_TRACE_MAX_HOPS`/config value. |
| `RECUPERO_CASE_THEFT_USD` | unset | float | `>= 0`, finite | v0.32.1 | Theft-amount override (USD) fed to the adaptive-depth severity bump when `RECUPERO_ADAPTIVE_DEPTH=1`. Best-effort; ignored if unparseable. |
| `RECUPERO_DRAINER_W7_PREFETCH` | `1` (on) | bool | opt-out via `0/false/no/off` | v0.32.1 | Prefetch drainer-contract outflows in the trace `finally` block (before the adapter closes) so `emit_brief` can consume cached drainer findings. Best-effort — failure logs and continues. |
| **Cross-chain** | | | | | |
| `RECUPERO_CROSS_CHAIN_CONTINUATION` | `1` (on) | bool | opt-out via `0/false/no/off` | v0.28.0 | Master switch for cross-chain BFS continuation. |
| `RECUPERO_CROSSCHAIN_WINDOW_HOURS` | `24` | float | `[0, 720]`, finite | v0.31.0 | Time window past source-bridge tx to accept dst transfers; 0 disables filter. |
| `RECUPERO_DEST_CONTINUATION_WAVES` | `2` | int | `>= 0` | v0.34 | Extra swap-decode waves run on a cross-chain DESTINATION adapter so a bridge→swap (e.g. 0x→DAI) composes instead of dead-ending at the settler. 0 disables; each wave follows the prior wave's resolved swap outputs one hop deeper. |
| `RECUPERO_LOCKMINT_MATCH` | `0` (off) | bool | opt-in via `1/true/yes/on` | v0.32.1 | Opt-in lock-and-mint cross-chain matching: for bridge handoffs with no decoded destination (Celer/Orbiter/Multichain), correlate the perpetrator's inbound transfers on each candidate chain by amount+time and continue the trail. Inferential (correlation, never proof — medium/low confidence) and costs extra inbound fetches, hence default OFF. |
| `RECUPERO_BRIDGE_CONFIRM` | `0` (off) | bool | opt-in via `1/true/yes/on` | v0.34 | Opt-in CRYPTOGRAPHIC bridge-destination confirmation: for each cross-chain handoff with a verified pairing spec (DLN/Across/Celer/Hop/Synapse/CCIP), ask the bridge-pairing oracle to confirm the destination by the protocol's own cross-chain id matched on BOTH chains (`high` — genuine proof, not correlation). A confirmed destination is preferred over the heuristic calldata decode, seeded for continuation, and recorded on `case.config_used["bridge_confirmations"]` for the brief + validator. Makes live destination-chain log queries, hence default OFF. See `docs/BRIDGE_PAIRING.md`. |
| `RECUPERO_ENDPOINT_DIVERSITY_PROBE` | `0` (off) | bool | opt-in via `1/true/yes/on` | v0.32.1 | Opt-in behavioral recognition of UNLABELED exchange/service infrastructure: probes the broader in/out activity of the top unlabeled terminal endpoints and flags those with high counterparty diversity as likely infrastructure (a subpoena lead the label DB missed). Inferential (medium/low confidence, never proof); low/asymmetric diversity is left unclassified so a perpetrator's own consolidation hub is never mislabeled. Costs extra fetches, hence default OFF. |
| **Dust / CEX-continuity heuristics** | | | | | |
| `RECUPERO_DUST_ATTACK_FILTER` | unset (off) | bool | `1/true/yes/on` to enable | v0.31.2 | Strip dust-shower fan-out destinations from the brief. |
| `RECUPERO_DUST_ATTACK_THRESHOLD_USD` | `1.00` | Decimal | `[0, 100]`, finite | v0.31.2 | Per-destination USD ceiling for the dust-attack filter. |
| `RECUPERO_DUST_ATTACK_MIN_FANOUT` | `10` | int | `[3, 1000]` | v0.31.2 | Min distinct sub-threshold destinations from one source to qualify as a dust attack. |
| `RECUPERO_CEX_CONTINUITY` | unset (off) | bool | `1/true/yes/on` to enable | v0.31.2 | Opt-in CEX-continuity lead surfacing (extra adapter cost). |
| `RECUPERO_CEX_CONTINUITY_WINDOW_HOURS` | `6` | float | `[0.5, 168]`, finite | v0.31.2 | Time window to match CEX-deposit ↔ CEX-withdrawal pairs. |
| `RECUPERO_CEX_CONTINUITY_MIN_USD` | `100000` | Decimal | `>= 1000`, finite | v0.31.2 | Min match USD to surface as a continuity lead. |
| `RECUPERO_DESTINATION_DUST_USD` | `1000.00` | Decimal | `>= 0`, finite | v0.20.x | Per-destination USD floor on the brief's DESTINATIONS table. |
| **Output / rendering** | | | | | |
| `RECUPERO_DISABLE_PDF_RENDER` | unset (off) | bool | `=1` to disable | v0.16.x | Kill switch — skip WeasyPrint PDF render (ship HTML only) on OOM. |
| `RECUPERO_ENABLE_LINK_PATCH` | unset (off) | bool | `=1` to enable | v0.20.x | Opt-in PDF link-annotation patcher (Railway hang under diagnosis). |
| `RECUPERO_PDF_VARIANT` | unset | str | free-form | v0.20.x | PDF render variant flag for A/B comparison. |
| `RECUPERO_INVESTIGATOR_NAME` | unset | str | non-empty | v0.20.0 | Operator's real name in the §9 Investigator Attestation. Briefs render `(operator name not configured)` if unset. |
| `RECUPERO_INVESTIGATOR_EMAIL` | `compliance@recupero.io` | str | RFC 5322 | v0.20.0 | Operator contact email rendered in deliverables. |
| `RECUPERO_INVESTIGATOR_ENTITY` | `Recupero LLC` | str | free-form | v0.20.0 | Legal entity name on signed deliverables. |
| `RECUPERO_INVESTIGATOR_ENTITY_FULL` | `Recupero LLC, a Delaware limited liability company` | str | free-form | v0.20.0 | Full legal entity line. |
| `RECUPERO_INVESTIGATOR_WEB` | `recupero.io` | str | URL host | v0.20.0 | Operator website rendered in deliverables. |
| `RECUPERO_INVESTIGATOR_PHONE` | unset | str | phone | v0.20.0 | Optional operator phone number. |
| `RECUPERO_DESTINATION_DUST_USD` | `1000.00` | Decimal | `>= 0`, finite | v0.20.x | See "dust / CEX-continuity". |
| `RECUPERO_AI_MAX_USD_PER_CALL` | `2.00` | Decimal | `> 0` | v0.17.8 | Per-call USD ceiling on AI editorial + AI triage calls; `0` disables (logged WARN). |
| `RECUPERO_AI_TRIAGE` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.35.7 | Enables *automatic* (worker-driven) AI case triage. The `recupero ai-triage` CLI command always runs regardless (operator opt-in). |
| `RECUPERO_API_BUDGET_USD_PER_CASE` | `0` (disabled) | Decimal | `[0.01, 1_000_000.0]`, finite | v0.32 | Per-case API spend cap across all providers. v0.32.1+ industry-best mode: default DISABLED so the tracker can reach deep destinations without an artificial dollar gate. Operators on shared free-tier API keys opt in with a positive USD value. |
| `RECUPERO_P_ANY_CALIBRATION_JSON` | unset | JSON | object | v0.21.x | Override default p_any calibration constants (recovery scorer). |
| `RECUPERO_PRICING_FALLBACK` | `defillama` | str | `defillama` / `none` | v0.31.5 | Secondary historical-price provider. `none` disables the fallback chain (CoinGecko only). |
| **Worker / scheduler** | | | | | |
| `RECUPERO_HEARTBEAT_INTERVAL_SEC` | `30` | float | `> 0`, finite | v0.18.x | Per-row heartbeat cadence for worker liveness. |
| `RECUPERO_STALE_AFTER_SEC` | `300` | int | `> 0` | v0.18.x | Reaper threshold — claim is considered stale after this many seconds. |
| `RECUPERO_POLL_IDLE_SEC` | `2.0` | float | `> 0`, finite | v0.18.x | Initial poll backoff when no rows pending. |
| `RECUPERO_POLL_MAX_SEC` | `30.0` | float | `> 0`, finite | v0.18.x | Max poll backoff (jittered). |
| `RECUPERO_LOG_LEVEL` | `INFO` | str | `DEBUG/INFO/WARNING/...` | v0.16.x | Python logging level for worker + ops CLI. |
| `RECUPERO_LOG_FORMAT` | unset | str | `json` to force JSON | v0.16.x | Force JSON log output (default auto-detects TTY vs Railway). |
| `RECUPERO_DB_POOL_SIZE` | unset | int | _deprecated_ | (removed v0.17.8) | Setting it triggers a deprecation WARN — no effect. |
| `RECUPERO_SUPABASE_POOLER_HOST` | `aws-1-us-east-1.pooler.supabase.com` | str | hostname | v0.19.0 | Override Supabase pooler host when project lives outside us-east-1. |
| `RECUPERO_DORMANT_CONCURRENCY` | `5` | int | `>= 1` | v0.16.x | Thread-pool size for dormancy finder. |
| `RECUPERO_WALLET_TRACE_LOOKBACK_DAYS` | (see pipeline default) | int | `>= 1` | v0.20.x | Per-chain wallet-trace lookback window. |
| `RECUPERO_BLOCK_TAG` | `finalized` | str | `finalized/latest/safe` | v0.19.x | EVM eth_call block tag for current-balance snapshots. |
| `RECUPERO_DATA_DIR` | `./data` | path | writable dir | v0.31.4 | Data-output root for the cron scheduler's stale-label report and any other on-disk artifacts. Defaults to the working directory's `./data` when unset. |
| `RECUPERO_CRON_ALERT_WEBHOOK_URL` | unset | str | URL | v0.32 | Slack-shape webhook URL the cron scheduler POSTs to when a job hits `consecutive_failures >= 2`. Unset → silent (operators still see /cron/healthz). Accepts Discord/PagerDuty/OpsGenie that consume the same payload shape. |
| `RECUPERO_CRON_LEASE_SECONDS` | `300` | int | `> 0` | v0.32 | Postgres lock lease duration for cron leader election. Way longer than any expected job runtime; raising past 600 risks a dead replica hogging a job after SIGKILL until the lease expires. |
| `RECUPERO_CRON_HEALTHZ_STALE_HOURS` | `25` | float | `> 0`, finite | v0.32 | Hours since `last_success_utc` before /cron/healthz marks a job "stale" (degraded). Default 25 gives the 24h jobs a 1h grace window. >168h is hard-down regardless. |
| `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP` | `100` | int | `[1, 10000]` | v0.32 | Max number of candidate labels the daily auto-ingest cron will persist per run. Hard cap protects the operator review queue from upstream tag-API flushes. |
| `RECUPERO_MULTI_SOURCE_CONFIRM` | unset (off) | bool | `1/true/yes/on` to enable | v0.32 | Gate label auto-ingest on multi-source confirmation: when on, a candidate label is only promoted if ≥2 independent sources agree. Default off preserves single-source backward-compatible ingest. |
| `RECUPERO_LABEL_DECAY_DAYS` | `180` | int | `[1, 3650]` | v0.32 | Confidence-decay window (days). A `high` label un-refreshed for this many days is effectively `medium` at lookup time; one tier per window, floored at `low`. Stored value never mutates. |
| **Watch / monitor / digest cron** | | | | | |
| `RECUPERO_WATCH_DELTA_USD_THRESHOLD` | `100` | Decimal | `>= 0` | v0.16.x | Min USD delta between snapshots to record as a material change. |
| `RECUPERO_WATCH_MIN_INTERVAL_SEC` | `43200` (12h) | int | `>= 0` | v0.16.x | Cooldown between snapshots of the same standard-tier wallet. |
| `RECUPERO_WATCH_HOT_INTERVAL_SEC` | `3600` (1h) | int | `>= 0` | v0.16.x | Cooldown for hot-tier wallets. |
| `RECUPERO_WATCH_PARALLELISM` | `4` | int | `>= 1` | v0.16.x | Per-chain thread-pool size for the watch tick. |
| `RECUPERO_STALE_REVIEW_THRESHOLD_HOURS` | `24` | int | `>= 0` | v0.16.x | Hours after which a `status=awaiting_review` row surfaces on the dashboard. |
| `RECUPERO_REVIEW_SLA_HOURS` | `24` | int | `[1, 720]` | v0.32 | SLA hours after which an `awaiting_review` brief is flagged overdue by the hourly review-SLA cron job. Falls back to 24h on parse failure / out-of-range. |
| `RECUPERO_STALE_ENGAGEMENT_THRESHOLD_DAYS` | `30` | int | `>= 0` | v0.21.x | Days after which an unclosed engagement surfaces as overdue. |
| `RECUPERO_MONITOR_MAX_SUBS_PER_TICK` | `50` | int | `> 0` | v0.27.x | Subscription rows polled per monitor tick. |
| `RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB` | `25` | int | `> 0` | v0.27.x | Activity events evaluated per subscription per tick. |
| `RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY` | `5` | int | `> 0` | v0.27.x | Per-subscription daily email-alert quota. |
| `RECUPERO_DIGEST_RECIPIENTS` | unset | str | comma-sep emails | v0.16.x | Recipients of the nightly digest email. Empty → digest email disabled. |
| `RECUPERO_DIGEST_FROM` | `Recupero Digest <digest@recupero.io>` | str | RFC 5322 | v0.16.x | From header for digest email. |
| `RECUPERO_DIGEST_ALWAYS_SEND` | unset | bool | truthy | v0.19.2 | Force-send digest even when there are 0 material changes. |
| `RECUPERO_SMTP_HOST` | unset | str | hostname | v0.16.x | SMTP host for digest delivery. Required to enable email. |
| `RECUPERO_SMTP_PORT` | `587` | int | `[1, 65535]` | v0.16.x | SMTP port. |
| `RECUPERO_SMTP_USER` | unset | str | login | v0.16.x | SMTP login user. |
| `RECUPERO_SMTP_PASSWORD` | unset | str | secret | v0.16.x | SMTP login password. |
| `RECUPERO_EMAIL_FROM` | unset | str | email or `Name <email>` | v0.16.x | From-address for Resend-channel emails (freeze letters, LE handoff). |
| `RECUPERO_EMAIL_FROM_NAME` | `Recupero Investigation Services` | str | free-form | v0.18.4 | From-name for Resend-channel emails. |
| `RECUPERO_DISABLE_EMAIL` | unset | bool | truthy | v0.19.2 | Kill switch for outbound email (follow-ups skip; counted under skipped_disabled). |
| `RECUPERO_OPS_ALERT_EMAIL` | unset | str | email | v0.27.x | Ops alert recipient (dispatch failures, quota breaches). |
| `RECUPERO_OPS_OPERATOR` | unset | str | free-form | v0.18.9 | Operator name written into audit trails for ops-CLI actions. |
| `RECUPERO_OPS_ASSUME_YES` | unset | bool | truthy | v0.19.2 | Skip interactive y/N prompts in ops CLI (for cron / scripted ops). |
| `RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE` | unset | bool | `=1` | v0.15.2 | Emit the UNRECOVERABLE variant of the victim summary (gated for safety). |
| `RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE` | unset | str | file path | v0.28.x | Path to JSON file overriding the bundled CEX subpoena recipients map. |
| **Deploy / environment markers** | | | | | |
| `RECUPERO_ENV` | `dev` | str | `dev/prod/production` | v0.17.x | Environment name shown in Sentry + used to detect prod for auth bypass refusal. |
| `RECUPERO_RELEASE` | unset | str | semver | v0.17.x | Release tag forwarded to Sentry. |
| `RECUPERO_GIT_SHA` | unset | str | git sha | v0.18.x | Deploy-time commit sha rendered in `/v1/health`. |
| **API + portal** | | | | | |
| `RECUPERO_API_KEYS` | unset | str | `name1:secret1,name2:secret2` | v0.18.2 | Cached map of API key secrets → partner names. |
| `RECUPERO_API_KEY_ISSUERS` | unset | str | `key:Issuer1\|Issuer2,...` | v0.28.0 | Per-key whitelist of issuers the partner can write `freeze_outcomes` for. |
| `RECUPERO_API_KEY_ADMINS` | unset | str | comma-sep key names | v0.28.0 | Operator key names with universal write access (deny-by-default for everything else). |
| `RECUPERO_API_KEY_CASES` | unset | str | `key:uuid\|uuid,...` | v0.27.x | Per-key case-UUID restriction. |
| `RECUPERO_API_RATE_LIMITS` | unset | str | `name:rps,...` | v0.18.x | Override per-key rate-limit RPS. |
| `RECUPERO_API_AUTH_OPTIONAL` | unset | bool | `=1` (local-dev only) | v0.17.6 | Local-dev bypass — REFUSED when a production marker is present. |
| `RECUPERO_API_HOST` | `0.0.0.0` | str | bind host | v0.18.x | API uvicorn bind host. |
| `RECUPERO_API_PORT` | (uvicorn default) | int | TCP port | v0.18.x | API uvicorn bind port. |
| `RECUPERO_API_DOCS_PUBLIC` | unset | bool | `=1` | v0.18.9 | Expose `/docs`, `/openapi.json`, `/redoc` in prod (default locked). |
| `RECUPERO_INTAKE_ALLOWED_ORIGINS` | unset | str | comma-sep origins | v0.25.x | CSRF allow-list for the unauthenticated POST `/v1/intake`. |
| `RECUPERO_INTAKE_REQUIRE_ORIGIN` | unset (off) | bool | `1/true/yes/on` to enable | v0.32.1 | Strict-CSRF mode for POST `/v1/intake`: when on, reject header-less requests (no Origin AND no Referer). Default OFF — header-less callers (curl, server-side integrations, tests) are allowed and bot abuse is handled by the per-IP rate limiter keyed on the rightmost trusted XFF hop. |
| `RECUPERO_TRUSTED_PROXY_HOPS` | `0` | int | `>= 0` | v0.18.2 / S-3b | Number of trusted reverse proxies in front of the worker / API (XFF parsing). |
| `RECUPERO_ADMIN_KEY` | unset | str | secret | v0.16.6 | Shared secret for the admin UI `X-Recupero-Admin-Key` header. Endpoint denies all when unset. |
| `RECUPERO_PORTAL_BASE_URL` | unset | str | URL prefix | v0.18.x | Portal base URL used when generating customer links. |
| `RECUPERO_PORTAL_PUBLIC_ORIGIN` | unset | str | URL origin | v0.18.x | Public origin allowed for portal CSRF. |
| `RECUPERO_TOKEN_PEPPER` | unset | bytes | 64-char hex / 44-char b64url | v0.20.2 | HMAC pepper for portal-token hashing; unset triggers legacy raw-token comparison. |
| `RECUPERO_WEBHOOK_ALLOWLIST_HOSTS` | unset | str | comma-sep hosts | v0.27.x | SSRF allow-list for outbound monitoring webhooks (empty = no host bypasses deny list). |
| **Custody / chain-of-custody** | | | | | |
| `RECUPERO_CUSTODY_KEY_PATH` | `~/.recupero/custody_key` | str | file path | v0.17.x | Override path to the Ed25519 private key used for custody attestation. |
| `RECUPERO_RANDOMIZATION_SECRET` | unset | str (secret) | high-entropy | v0.31.2 | Server-held secret keying the per-case HMAC randomization (e.g. dust-attack salt in `security/per_case_randomization.py`). Unset → deterministic local-dev/CI fallback (NOT for prod — set a real secret so per-case salts are unguessable). |
| **Metrics / health** | | | | | |
| `RECUPERO_METRICS_BIND_HOST` | `127.0.0.1` | str | bind host | v0.27.x | Prometheus exporter bind host. |
| **Hack tracker** | | | | | |
| `RECUPERO_HACK_TRACKER_ENABLED` | unset | bool | `=1` | v0.20.0 | Feature flag for the hack-tracker pipeline. |
| `RECUPERO_HACK_TRACKER_OFFLINE` | unset | bool | `=1` | v0.20.0 | Run hack-tracker against bundled fixtures (no live HTTP). |
| `RECUPERO_X_BEARER_TOKEN` | unset | str | secret | v0.20.0 | X (Twitter) v2 API bearer token for the hack-tracker feed source. |
| **Payments (Stripe)** | | | | | |
| `RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK` | unset | str | Stripe URL | v0.16.x | Stripe Payment Link for the $499 diagnostic. |
| `RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK` | unset | str | Stripe URL | v0.16.x | Stripe Payment Link for the $10K engagement. |

---

## Per-variable detail

### Trace tuning

#### `RECUPERO_TRACE_MAX_HOPS`

BFS depth cap for the primary trace walk. Read at trace start
(`src/recupero/trace/tracer.py:125`), clamped to
`[1, RECUPERO_TRACE_MAX_HOPS_HARD_CEILING]` (default 64 in v0.32.1+
industry-best mode), and falls back to `config.trace.max_depth` on
parse failure with a `log.warning`.

* **Failure modes:** a non-int value triggers a WARN and the trace
  uses the YAML default (4). Setting it to 0 or negative clamps to 1.
  Above the hard ceiling clamps DOWN to the ceiling.
* **When to override:** raise to 8-16 for deep-laundering cases that
  hop through consolidation hubs (Zigha-shape). For APT-style cases
  with 30-50 hop chains, raise to 32 or 64. Leave at default for
  routine diagnostics.

#### `RECUPERO_TRACE_MAX_HOPS_HARD_CEILING`

Upper bound on `RECUPERO_TRACE_MAX_HOPS`. v0.32.1+ industry-best
mode raised from 8 → 64 so Recupero can reach destinations Reactor
caps around 12. Operators on quota-constrained API plans lower this
to whatever they can fund.

* **Failure modes:** non-int falls back to 64 with a WARN. Clamped
  to `[1, 1024]` (above 1024 is almost certainly a typo).
* **When to override:** lower to 8 to restore legacy v0.31.x
  behavior on shared free-tier API keys.

#### `RECUPERO_MAX_TRANSFERS_PER_ADDRESS`

Per-address transfer fetch cap (raw + sliced). Read at
`src/recupero/trace/tracer.py` `_trace_one_hop`. Overrides
`config.trace.max_transfers_per_address` per-case. Set to 0 to
disable the cap entirely.

* **Failure modes:** non-int falls back to config with a WARN.
* **When to override:** set 0 on a whale-wallet trace where the
  full activity history matters (still bounded by `max_depth`,
  the trace deadline, and the per-case transfer cap). Set lower
  (e.g. 500) to restore legacy v0.31.x behavior.

#### `RECUPERO_TRACE_DUST_USD`

Per-transfer USD floor. Anything below this is dropped from the BFS
queue. Read at `src/recupero/trace/tracer.py:135`; NaN / ±Inf /
negative values are rejected with a WARN.

* **Failure modes:** NaN would silently break the dust filter (NaN
  comparisons return False, so EVERY transfer slips the gate). The
  guard at `tracer.py:144` rejects non-finite + negative explicitly.
* **When to override:** lower to `0.01` for dust-attack research;
  raise to `100` for whale-volume cases where $10 noise is overwhelming.

#### `RECUPERO_TRACE_TIMEOUT_SEC`

Wall-clock deadline for the BFS. When the deadline elapses between
waves the trace exits gracefully with `case.config_used.trace_status =
"partial_deadline_hit"` and the brief renders a "trace incomplete"
banner. Default `540` is under Railway's 600s reaper window.

* **Failure modes:** non-int triggers WARN + fall back to 540. Setting
  it too low produces partial traces; too high lets the reaper kill
  the worker mid-stage.

#### `RECUPERO_MAX_TRANSFERS_PER_CASE`

OOM defense. Above this many transfers, BFS exits with
`trace_status="partial_transfer_cap"`. Default 50k is well above any
real theft case but under the 8GB Railway container's safe ceiling.

#### `RECUPERO_TRACE_CONCURRENCY`

Per-wave thread-pool size. Higher counts give diminishing returns
once the Etherscan / CoinGecko rate-limiter is the bottleneck. Read
at `src/recupero/trace/tracer.py:228`, clamped to `>= 1`.

#### `RECUPERO_MAX_CONTINUATION_SEEDS`, `RECUPERO_MAX_CROSS_CHAIN_SEEDS`

Per-wave caps on continuation seeds (same-chain bridge / DEX outputs)
and cross-chain destination seeds respectively. Bound additional API
budget. Defaults 25 / 10 — real cases rarely produce more.

#### `RECUPERO_DISABLE_PASS2`

Kill switch for pass-2 perpetrator trace
(`src/recupero/trace/perpetrator_trace.py:211`). Set to `1` for batch
re-runs / dev work where the extra adapter cost isn't justified.

#### `RECUPERO_PASS2_RATIO_THRESHOLD`

Outflow/inflow ratio above which an address is treated as a
consolidation-hub candidate for pass-2 traces. Default 100.

#### `RECUPERO_PASS2_BALANCE_THRESHOLD_USD`

Min current-balance USD for a pass-2 candidate. Default $5K.

#### `RECUPERO_PASS2_MAX_TRACES`

Per-investigation cap on pass-2 traces. Default 3.

#### `RECUPERO_INDIRECT_DECAY` / `RECUPERO_INDIRECT_MAX_HOPS`

MVP indirect-exposure scorer knobs
(`src/recupero/trace/indirect_exposure.py`). Decay factor per hop
(default 0.5) and max BFS depth (default 3).

### Cross-chain

#### `RECUPERO_CROSS_CHAIN_CONTINUATION`

Master switch for cross-chain BFS continuation. Default ON; any of
`0/false/no/off` (case-insensitive) opts out. Empty / unset keeps it
ON.

* **Failure modes:** none — any unrecognized value is treated as ON.
* **When to override:** turn OFF during local dev runs that don't
  need destination-chain RPC quota.

#### `RECUPERO_CROSSCHAIN_WINDOW_HOURS`

Time window (in hours past the source-bridge tx) to accept dst-chain
transfers. Read at `src/recupero/trace/tracer.py:570`, clamped to
`[0, 720]` (30 days max), rejecting NaN / ±Inf via `math.isfinite`.
Setting to 0 disables the filter (legacy behavior).

* **Failure modes:** non-finite values are rejected with a WARN.
  Pre-v0.31.1 a `-Infinity` slipped through `max(0, -inf)=0`,
  silently disabling the filter — fixed by the `isfinite` check.
* **When to override:** raise to 168 (1 week) for slow consolidation
  paths; lower to 6 for fast-moving bridge sweeps.

#### `RECUPERO_DEST_CONTINUATION_WAVES`

How many ADDITIONAL swap-resolution waves to run on a cross-chain
*destination* adapter after the shallow handoff hop
(`src/recupero/trace/tracer.py`, `_continue_past_dex_and_bridges`). The
cross-chain continuation lands the bridged funds on the destination
chain in a single hop, but a 0x / Matcha settler pays the converted
token (e.g. DAI) from its own balance — an outflow recoverable only
from the *destination* tx's receipt logs. Without a destination-side
swap pass the trace dead-ends at the settler (the Zigha gap: Arbitrum
hub → DeBridge → Ethereum receiver → 0x swap → DAI). Each wave resolves
swap outputs among the prior wave's transfers (via the destination
adapter's receipt logs) and follows them one hop deeper. Default 2;
`0` restores the pre-v0.34 single-hop-only behavior.

* **Failure modes:** none — a non-int value falls back to 2; a wave
  whose `_process_wave` raises is logged and breaks the loop. Bounded
  to the one destination chain (no further cross-chain recursion) and
  to the per-case transfer budget + `visited` set already in force.
* **When to override:** raise for laundering paths with several
  post-bridge swap hops; set `0` to reproduce pre-v0.34 traces exactly.

### Dust / CEX heuristics

#### `RECUPERO_DUST_ATTACK_FILTER`

Opt-in filter that removes dust-shower destinations
(distinct sub-threshold fan-outs from one source) from the brief's
unlabeled-counterparty list. Off by default. Accepts
`1/true/yes/on`.

* **Failure modes:** none — anything else (including unset) keeps it
  off.

#### `RECUPERO_DUST_ATTACK_THRESHOLD_USD`

Per-destination USD ceiling for the dust-attack filter. Read at
`src/recupero/trace/tracer.py:1197`; clamped to `[0, 100]`,
rejecting NaN / ±Inf / negative values. Default $1.00.

* **Failure modes:** invalid values fall back to default with a WARN
  banner identifying the bad input.
* **When to override:** raise to `$10` if dust attacks in the case use
  $1-10 transfers to evade the default filter.

#### `RECUPERO_DUST_ATTACK_MIN_FANOUT`

Min distinct sub-threshold destinations from one source to qualify as
a dust attack. Clamped to `[3, 1000]`. Below 3 fires on legitimate
change-back patterns; above 1000 misses modestly-sized attacks.

#### `RECUPERO_CEX_CONTINUITY`

Opt-in CEX-continuity-lead surfacing. Adapter calls cost money so
this is gated behind an explicit `1/true/yes/on` (case-insensitive)
toggle.

#### `RECUPERO_CEX_CONTINUITY_WINDOW_HOURS`

Time window for matching CEX-deposit ↔ CEX-withdrawal pairs. Read at
`src/recupero/trace/cex_continuity.py:530`, clamped to `[0.5, 168]`.
Lower bound 30 minutes because anything tighter is below typical CEX
hot-wallet sweep cadence; upper bound 1 week because price drift
breaks the amount-tolerance check beyond that.

#### `RECUPERO_CEX_CONTINUITY_MIN_USD`

Min match USD to surface as a continuity lead. Default $100K, refused
below $1K (statistical noise).

#### `RECUPERO_DESTINATION_DUST_USD`

Per-destination USD floor on the brief's DESTINATIONS table. Read at
emit time (`src/recupero/reports/emit_brief.py:297`), with NaN / Inf /
negative all rejected (Decimal `is_finite()`).

* **Failure modes:** invalid → fall back to default $1000 with a
  WARN.
* **When to override:** lower to $100 for granular small-claim cases;
  raise to $5000 for whale cases where $1K is noise.

### Output / rendering

#### `RECUPERO_DISABLE_PDF_RENDER`

Kill switch — when `=1`, skip WeasyPrint PDF rendering entirely and
ship the HTML deliverables alone. Used on OOM-constrained Railway
containers.

#### `RECUPERO_ENABLE_LINK_PATCH`

Opt-in PDF link-annotation patcher. Default OFF because a Railway-side
hang is still under investigation; production runs with WeasyPrint's
native ~54% link coverage.

#### `RECUPERO_PDF_VARIANT`

Free-form string used by the worker's PDF render variant subprocess
for A/B comparison.

#### `RECUPERO_INVESTIGATOR_NAME`

Operator's real name. Briefs that ship without this set carry the
literal `(operator name not configured)` in §9 Investigator
Attestation — legally useless. Set this before running a real
customer brief. The `require_investigator_configured()` helper raises
when unset; the API / worker preflight can gate on it via
`RECUPERO_REQUIRE_INVESTIGATOR=1`.

#### `RECUPERO_INVESTIGATOR_EMAIL` / `_ENTITY` / `_ENTITY_FULL` / `_WEB` / `_PHONE`

Operator contact / legal-entity strings rendered in deliverables.
Read at call time (never module-load) so a deploy that rotates them
picks up new values without a worker restart.

#### `RECUPERO_AI_MAX_USD_PER_CALL`

Per-call USD ceiling on AI editorial **and AI triage** calls. Default
$2.00. Set to 0 to disable (logged as WARN — runaway retries will burn
real budget). Read by both `reports/ai_editorial.py` and
`reports/ai_triage.py` via the shared `_resolve_max_usd_per_call`.

#### `RECUPERO_AI_TRIAGE`

v0.35.7 (roadmap G1). Gates *automatic* AI case triage — the
plain-English summary + recommended-next-steps + completeness-gaps
briefing produced by `reports/ai_triage.py` (parity with Chainalysis
"Rapid" / TRM auto-narrative). **Default OFF**: AI triage costs an
Anthropic API call, so worker-driven invocation must be opted into
explicitly. The interactive `recupero ai-triage <case>` command always
runs (the operator invoking it IS the opt-in) and is unaffected by this
flag. Truthy values: `1`, `true`, `yes`, `on` (case-insensitive).

#### `RECUPERO_API_BUDGET_USD_PER_CASE`

v0.32 (Tier-1 gap #4 from `docs/WHY_RECUPERO_WOULD_FAIL.md` §1.4),
relaxed to "industry-best mode" in v0.32.1+. Per-case API spend cap
across all upstream providers (Etherscan, Helius, TronGrid, Alchemy,
CoinGecko, DeFiLlama). Read at the top of the tracer
(`src/recupero/observability/api_budget.py`,
`src/recupero/trace/tracer.py`).

**Default: `0` (DISABLED).** v0.32.1+ ships in industry-best mode
where the tracker burns whatever API quota the case needs to reach
destinations Reactor would. Operators opt in to per-case spend
tracking by setting a positive USD value. When set, the cap is
clamped to `[$0.01, $1,000,000.0]`.

The cost model is pessimistic by design — each provider's per-call
cost is rounded UP to the nearest order of magnitude so we cap
BEFORE real overage charges hit. See `_COST_MODEL` in
`api_budget.py` for the exact figures.

When the cap is exceeded, the next adapter call raises
`BudgetExceededError`. The tracer catches that and marks the case
`trace_status=partial_budget_hit` with the per-provider breakdown
recorded under `case.config_used["api_budget"]`. The brief renders a
"trace incomplete — budget exhausted" banner (same shape as the
deadline-hit path).

* **Failure modes:** non-finite (NaN / Inf), non-numeric, or
  out-of-range values reject with a WARN and fall back to default
  (disabled). Negative values are rejected loud. Zero matches the
  default and is honored without a warning.
* **When to override:** set $5.00-$50.00 for cost-controlled
  deployments on shared free-tier API keys; set $1000+ on
  whale-case diagnostic runs where deep BFS is worth the spend.
  Leave unset for the industry-best default (no cap).

#### `RECUPERO_P_ANY_CALIBRATION_JSON`

JSON object overriding the documented `p_any` calibration constants
used by the recovery scorer. Missing keys fall back to defaults;
NaN/Inf values are rejected per-key with a debug log.

#### `RECUPERO_PRICING_FALLBACK`

v0.31.5. Selector for the secondary historical-price provider used
when CoinGecko returns no price (rate-limited, token unsupported, or
network error). Default `defillama` — the only supported alternate
provider today. Set to `none` (case-insensitive) to disable the
fallback entirely; in that case a CoinGecko miss falls straight
through to `(unpriced)` in the brief.

* **Failure modes:** any value other than `none` is treated as
  `defillama`. Unset / empty also defaults to `defillama`. A
  misconfigured DeFiLlama URL or runtime construction error logs a
  DEBUG and the pricing path silently falls back to "(unpriced)" —
  the fallback layer must never crash the trace.
* **When to override:** set `none` when running an air-gapped trace
  (no outbound HTTP) or when the CoinGecko Pro key already covers
  every token in the case (no fallback budget needed). The
  `source` column on each transfer in `case.json` records which
  provider actually answered.

### Worker / scheduler

#### `RECUPERO_DATA_DIR`

v0.31.4. Filesystem root for cron-generated artifacts that aren't
case-scoped. Today the only writer is the `recupero-cron` stale-label
job (`src/recupero/worker/cron_scheduler.py`), which emits
`<RECUPERO_DATA_DIR>/stale_labels.json` weekly. Default `./data`
(relative to the working directory). The directory is created on
first write — `Path.mkdir(parents=True, exist_ok=True)`. Operators
that mount a persistent volume should point this at the mount point
so the stale-label report survives container restarts.

Routed through `_common.atomic_write_text`, which honors the v0.31.3
`is_link_like` guard — junctions and symlinks at the output path are
rejected loud rather than silently dereferenced.

#### `RECUPERO_CRON_ALERT_WEBHOOK_URL`

v0.32 (Tier-1 gap #3 from `docs/WHY_RECUPERO_WOULD_FAIL.md` §1.3).
Slack-shape incoming-webhook URL the cron scheduler POSTs to when a
job's `consecutive_failures` counter (tracked in
`public.cron_jobs_lock`) reaches 2 or more. The payload is a generic
`text` + `attachments[].fields[]` shape that Discord, PagerDuty, and
OpsGenie incoming webhooks also accept verbatim.

* **Failure modes:** unset → no webhook is fired; failures are still
  journaled in `cron_jobs_lock` and surfaced by `/cron/healthz`. A
  bad URL (DNS failure / 5xx / timeout) logs a WARN and is otherwise
  silent — the alerting mechanism must never crash the scheduler.
* **What we DON'T send:** the payload runs through `_safe_error_text`
  which scrubs `postgres://user:pass@host` credentials and any
  `api_key=…` / `token=…` / `bearer …` token-shaped substrings.

#### `RECUPERO_CRON_LEASE_SECONDS`

v0.32 cron HA. How long the leader holds the lock on a job_name row
in `public.cron_jobs_lock` before a peer can steal it via the
expiry path. Default 300s — well above the longest expected
single-job runtime (OFAC sync, ~60s). Setting it too low risks two
replicas firing the same job back-to-back; too high makes a dead
leader hold the job for longer than necessary.

* **Failure modes:** non-int / <= 0 → fall back to 300 with a WARN.

#### `RECUPERO_CRON_HEALTHZ_STALE_HOURS`

v0.32 cron HA. Hours since `last_success_utc` before
`GET /cron/healthz` flips a job's `status` from `"ok"` to `"stale"`.
Default 25 — gives the 24h daily jobs a 1h grace window past their
expected cadence. Jobs > 168h fresh are reported `"down"`
regardless.

* **Failure modes:** non-finite / <= 0 → fall back to 25 with a WARN.
* **When to override:** lower to ~12 for ops teams running every job
  every 6h who want a tight alarm window; raise past 168 only for
  jobs that legitimately run weekly with no grace expected.

#### `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP`

v0.32 (Tier-1 gaps #1 + #2 from `docs/WHY_RECUPERO_WOULD_FAIL.md`
§1.1 + §1.2). Maximum number of candidate labels persisted per daily
auto-ingest run by the `recupero-cron` `label_auto_ingest` job. The
cap is applied AFTER de-duplication so already-reviewed addresses
don't waste the budget.

* **Failure modes:** non-int / out-of-range → fall back to 100 with a
  WARN.
* **When to override:** raise when an operator is actively burning
  down a backlog (250 is sane); lower to 25 if a fresh deploy needs a
  smaller review surface while the team gets used to the workflow.

#### `RECUPERO_LABEL_DECAY_DAYS`

v0.32 (Tier-1 gap #2). Confidence-decay window in days. A label with
`stored confidence='high'` that hasn't been refreshed for this many
days is reported by `LabelStore.lookup` with effective
`confidence='medium'`; another window → `low`; floor at `low`. The
seed file is NEVER mutated — decay happens at lookup time so the
operator's git diffs stay quiet.

* **Failure modes:** non-int / out-of-range → fall back to 180 with a
  WARN.
* **When to override:** lower to 90 in high-rotation environments
  where CEX hot wallets cycle quarterly; raise past 365 if your seed
  file is hand-curated weekly and the decay is just noise.

#### `RECUPERO_HEARTBEAT_INTERVAL_SEC`, `RECUPERO_STALE_AFTER_SEC`, `RECUPERO_POLL_IDLE_SEC`, `RECUPERO_POLL_MAX_SEC`

Worker scheduler knobs. All go through `_resolve_float_env` /
`_resolve_int_env` in `src/recupero/worker/main.py:86-124` which
reject non-positive / non-finite values with a WARN and fall back to
the documented default. Heartbeat must fire well inside
`STALE_AFTER_SEC / 2` so the reaper doesn't steal an active row.

#### `RECUPERO_LOG_LEVEL`

Python logging level for the worker + ops CLI. Default `INFO`.

#### `RECUPERO_LOG_FORMAT`

Set to `json` to force JSON-formatted log output (default
auto-detects TTY vs Railway).

#### `RECUPERO_DB_POOL_SIZE`

DEPRECATED — setting it triggers a WARN
(`src/recupero/worker/db.py:276`). Client-side pooling was removed in
v0.17.8; rely on Supabase's transaction-mode pooler at port 6543.

#### `RECUPERO_SUPABASE_POOLER_HOST`

Override the Supabase transaction-pooler hostname when the project
lives outside us-east-1 (e.g.
`aws-1-eu-central-1.pooler.supabase.com`).

#### `RECUPERO_DORMANT_CONCURRENCY`

Thread-pool size for the dormancy finder. Clamped to `>= 1`.

#### `RECUPERO_WALLET_TRACE_LOOKBACK_DAYS`

Per-chain wallet-trace lookback window (in days). Read at call-time
so cron operators can rotate the value without restarting the worker.

#### `RECUPERO_BLOCK_TAG`

EVM block tag used for current-balance snapshots
(`finalized` / `latest` / `safe`). Default `finalized`.

### Watch / monitor / digest cron

#### `RECUPERO_WATCH_DELTA_USD_THRESHOLD`

Min USD delta between snapshots to log a material change. Read by
`_env_decimal` (`src/recupero/worker/watch_tick.py:139`).

#### `RECUPERO_WATCH_MIN_INTERVAL_SEC` / `RECUPERO_WATCH_HOT_INTERVAL_SEC`

Cooldowns between snapshots — standard wallets every 12h (default),
hot-tier wallets every 1h.

#### `RECUPERO_WATCH_PARALLELISM`

Per-chain thread-pool size for the watch tick. Default 4.

#### `RECUPERO_STALE_REVIEW_THRESHOLD_HOURS` / `RECUPERO_STALE_ENGAGEMENT_THRESHOLD_DAYS`

Dashboard widgets surface investigations / engagements that have
aged past these thresholds.

#### `RECUPERO_MONITOR_MAX_SUBS_PER_TICK`, `RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB`

Per-tick guardrails on monitor-feed processing. Bad / non-positive
values fall back to defaults with a WARN.

#### `RECUPERO_MONITOR_EMAIL_QUOTA_PER_DAY`

Per-subscription email-alert quota. Above this the dispatcher drops
into a "quota exhausted" branch and logs.

#### `RECUPERO_DIGEST_*`, `RECUPERO_SMTP_*`, `RECUPERO_EMAIL_*`

Email cron settings. `DIGEST_RECIPIENTS` empty → digest email path
disabled. `SMTP_HOST` / `USER` / `PASSWORD` must all be set for SMTP
delivery to attempt at all. `DISABLE_EMAIL` truthy short-circuits the
follow-up mail loop (skipped rows counted as `skipped_disabled`, not
failures).

#### `RECUPERO_OPS_*`

Operator identity + UX knobs for the ops CLI.
`RECUPERO_OPS_ASSUME_YES` truthy skips all interactive prompts (for
cron / scripted ops).

#### `RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE`

Safety gate — must be `=1` for the UNRECOVERABLE variant of the
victim summary to emit. False positives there carry customer-harm
risk so the gate is required.

#### `RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE`

Path to a JSON file overriding the bundled CEX subpoena recipients
map. Used to add new exchanges or refresh contacts without a code
deploy.

### Deploy / environment markers

#### `RECUPERO_ENV`

Environment name. `prod` / `production` (case-insensitive) marks the
deploy as production, which triggers `RECUPERO_API_AUTH_OPTIONAL`
refusal + `.env` skip behavior.

#### `RECUPERO_RELEASE`

Sentry release tag, also used in `/v1/health`.

#### `RECUPERO_GIT_SHA`

Deploy-time commit sha, set by the Railway / CI build, surfaced via
`/v1/health`.

### API + portal

#### `RECUPERO_API_KEYS`

Cached map of API-key secrets to partner names. Format:
`name1:secret1,name2:secret2` (whitespace stripped, empty pairs
skipped). The parser caches on a SHA-256 fingerprint of the raw value
so subsequent calls don't reparse until the env changes.

#### `RECUPERO_API_KEY_ISSUERS` / `RECUPERO_API_KEY_ADMINS`

Per-key access controls for `POST /v1/freeze-outcomes`. A key MUST
appear in either the issuers list (with the issuer in its
pipe-separated allow-list) OR the admins list — otherwise the request
is denied. **Deny-by-default.**

#### `RECUPERO_API_KEY_CASES`

Per-key case-UUID scoping. Empty → no scoping (legacy behavior).

#### `RECUPERO_API_RATE_LIMITS`

Override per-key requests-per-second. Format `name:rps,...`.

#### `RECUPERO_API_AUTH_OPTIONAL`

Local-dev bypass. **REFUSED in production**: when any production
marker (`RAILWAY_ENVIRONMENT=production`, `ENVIRONMENT=production`,
`RECUPERO_ENV=production`, etc.) is detected the bypass logs a loud
WARN and the auth check stays mandatory.

#### `RECUPERO_API_HOST` / `RECUPERO_API_PORT`

uvicorn bind host/port.

#### `RECUPERO_API_DOCS_PUBLIC`

Set to `1` to expose `/docs`, `/openapi.json`, `/redoc` in
production. Default locked.

#### `RECUPERO_INTAKE_ALLOWED_ORIGINS`

CSRF allow-list for the unauthenticated `POST /v1/intake`. Empty /
unset falls back to same-origin check against the request `Host`
header.

#### `RECUPERO_TRUSTED_PROXY_HOPS`

Number of trusted reverse proxies between the client and the worker /
API. The trusted-hop X-Forwarded-For element is `xff_chain[-N]`. The
RIGOR-S-3b hardening fails closed when the actual chain is shorter
than `N` (operator misconfig) — falls through to `x-real-ip` /
socket peer.

#### `RECUPERO_ADMIN_KEY`

Shared secret for the admin UI's `X-Recupero-Admin-Key` header. When
unset, `/investigations*` and `/dashboard.json` deny everything
(fail-closed).

#### `RECUPERO_PORTAL_BASE_URL` / `RECUPERO_PORTAL_PUBLIC_ORIGIN`

Portal URL prefix and public origin (CSRF / signed-link domain).

#### `RECUPERO_TOKEN_PEPPER`

HMAC pepper for portal-token hashing. Accepts 64-char hex (32 bytes)
or 44-char base64-url (32 bytes). Unset → legacy raw-token
comparison with a one-time WARN log. Rotation invalidates every
active token.

#### `RECUPERO_WEBHOOK_ALLOWLIST_HOSTS`

SSRF allow-list for outbound monitoring webhooks. Empty in production
(no host bypasses the deny list).

### Custody / chain-of-custody

#### `RECUPERO_CUSTODY_KEY_PATH`

Override path to the Ed25519 private key used for chain-of-custody
signing. Generated by `recupero-ops custody-keygen`.

### Metrics / health

#### `RECUPERO_METRICS_BIND_HOST`

Prometheus exporter bind host. Default `127.0.0.1` (localhost-only).

### Hack tracker

#### `RECUPERO_HACK_TRACKER_ENABLED` / `RECUPERO_HACK_TRACKER_OFFLINE`

Feature flags. `_OFFLINE=1` exercises bundled fixtures without
hitting any live HTTP source.

#### `RECUPERO_X_BEARER_TOKEN`

X (Twitter) v2 API bearer token. Unset → x_feed source logs an INFO
and returns no events.

### Payments (Stripe)

#### `RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK` / `RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK`

Stripe Payment Link URLs for the $499 diagnostic and the $10K
engagement. `recupero-ops stripe-mode` cross-checks them against
`STRIPE_WEBHOOK_SECRET` and flags test↔live mismatch.

---

## Third-party secrets

These env vars are NOT prefixed `RECUPERO_*` but the application
reads them directly. Operators must set them in any production deploy
that uses the corresponding integration. They are also surveyed by
`tests/test_v031_4_env_vars_doc.py` so the list stays in sync.

| Name | Read at | Purpose |
| ---- | ------- | ------- |
| `SUPABASE_URL` | many (see below) | Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | many | Supabase service-role key for server-side writes. |
| `SUPABASE_DB_URL` | many | Direct Postgres DSN (rewritten via `pooled_dsn` for the transaction pooler). |
| `ETHERSCAN_API_KEY` | `worker/watch_tick.py`, `chains/ethereum/etherscan.py` | Etherscan v2 multichain key. |
| `HELIUS_API_KEY` | `worker/watch_tick.py`, `chains/solana/helius.py` | Helius (Solana) API key. |
| `TRON_PRO_API_KEY` | `chains/tron/adapter.py` | TronGrid API key. |
| `COINGECKO_API_KEY` | `pricing/coingecko.py` (required in `_REQUIRED_ENV_VARS`) | CoinGecko Pro API key. |
| `ANTHROPIC_API_KEY` | `reports/ai_editorial.py`, nightly-audit LLM review | Claude API key for editorial + nightly audit. |
| `SENTRY_DSN` | `observability/sentry.py` | Sentry DSN; unset disables Sentry init. |
| `SENTRY_ENVIRONMENT` | `observability/sentry.py`, prod-marker detection | Sentry environment name. |
| `SENTRY_TRACES_SAMPLE_RATE` | `observability/sentry.py` | Sentry transaction sampling rate. |
| `STRIPE_WEBHOOK_SECRET` | `payments/webhook.py`, `payments/stripe_mode.py` | Stripe webhook signing secret. |
| `RESEND_API_KEY` | `worker/_email.py` | Resend transactional-email API key. |
| `RAILWAY_PUBLIC_DOMAIN` | `portal/tokens.py` | Railway-supplied public domain used as portal base URL fallback. |
| `RAILWAY_ENVIRONMENT` | prod-marker detection | Railway environment (`production`/`preview`/`development`). |
| `ENVIRONMENT` / `ENV` / `NODE_ENV` | prod-marker detection | Generic environment markers. |
| `SOURCE_DATE_EPOCH` | `_common.resolve_render_time`, `reports/emit_brief.py` | Reproducible-builds timestamp pin. |
| `HEALTH_BIND_HOST` | `worker/_health_server.py` | Override health-endpoint bind host (default 127.0.0.1, or 0.0.0.0 when `PORT` is set). |
| `PORT` | `worker/_health_server.py` | PaaS-supplied health-endpoint port (default 8080). |

---

## Adding a new env var

1. Add the `os.environ.get(...)` call in source.
2. Add a row to the index table above. Include `name`, default,
   type, range, version introduced, and one-sentence purpose.
3. Write a per-variable section below covering description, failure
   modes, and operator guidance.
4. Re-run `pytest tests/test_v031_4_env_vars_doc.py -v` to confirm
   the parity gate passes.
5. (Optional but encouraged) extend the relevant section in
   `docs/OPERATOR_RUNBOOK.md` with the operational story for the new
   var.
