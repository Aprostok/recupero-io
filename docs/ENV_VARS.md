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
| `RECUPERO_TRACE_TIMEOUT_SEC` | `1800` under deep-reach, else `540` | int | `>= 0` | v0.16.11 | Wall-clock deadline before BFS exits with `trace_status=partial_deadline_hit`. **v0.37.5:** the default is deep-reach-aware — 1800s (30 min) under the deep-reach default (deep + cross-chain + multi-bridge legitimately needs more wall-clock; a fixed 540s would stamp deep multi-chain traces incomplete), 540s on the legacy shallow path. The worker's heartbeat thread keeps the claimed row fresh throughout (the legacy 540 already exceeds the 300s stale window), so the longer ceiling is safe. Explicit value always wins. |
| `RECUPERO_MAX_TRANSFERS_PER_CASE` | `50000` | int | `>= 0` | v0.16.11 | OOM defense — trace stops once this many transfers accumulate. |
| `RECUPERO_TRACE_CONCURRENCY` | `5` | int | `>= 1` | v0.16.x | Thread-pool size for parallel per-wave fetches. |
| `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` | `config.trace.service_wallet_outflow_threshold` (200) | int | `>= 1` | v0.34 | A wallet emitting more outflows than this is treated as a service/distributor: its transfers are kept but BFS traversal STOPS there (children not followed). Default 200 halts at exchange hot wallets / token distributors — but ALSO at a high-throughput DeFi aggregator/pool that sits ON the laundering path, silently missing everything past it. Raise (e.g. 25000) for a deep recall-complete run so the trace crosses the aggregator while still stopping at true mega-services. Bad/blank/non-positive keeps the resolved default. |
| `RECUPERO_SEED_FOLLOW_TOPN` | `50` | int | `>= 0` (0 = legacy skip) | v0.34.5 | When the SEED itself is high-fan-out (a perpetrator splitter emitting more than `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` outflows — e.g. the Lazarus/Ronin seed with 8,827), do NOT dead-end the whole trace: enqueue the top-N outflows BY VALUE (USD desc, then raw amount) so the investigation follows the largest dispersal legs. The enqueued children gain an inbound reference and trace value-DIRECTED from there, so branching stays finite (visited-set + `stop_at_exchange` + `max_depth` + per-case budget bound the rest). **Only active under `RECUPERO_VALUE_TRACE`** (the directed mode that keeps children bounded); ignored otherwise. `0` restores the legacy "skip a high-fan-out seed entirely" behavior. Bad/blank/negative keeps the default. |
| `RECUPERO_SERVICE_WALLET_FOLLOW_TOPN` | `8` | int | `>= 0` (0 = legacy skip) | v0.34.5 | Same as `RECUPERO_SEED_FOLLOW_TOPN` but for high-fan-out nodes encountered DEEPER than depth 0 (mid-route splitters / aggregators on the laundering path). A tighter N than the seed's because deep fan-out compounds; the value-direction of the enqueued children keeps the trace on the money. **Only active under `RECUPERO_VALUE_TRACE`.** `0` restores the legacy skip. Bad/blank/negative keeps the default. |
| `RECUPERO_VALUE_TRACE` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34 | Value-directed tracing. At a high-fan-out node (service wallet / aggregator / pool) — instead of stopping or following every edge — follow ONLY the outflow(s) whose **amount matches** the inbound funds (same-asset forwarding) or whose **USD value matches** across an asset conversion (swap), within a 72h window. This isolates the real onward hop behind a commingling node. Matches are INFERENCE: confidence is calibrated `medium` (sole same-asset amount match) or `low` (ambiguous / cross-asset) — **never `high`** — and surfaced under `coverage.value_matched_hops` with the match basis. Pair with `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` (raise it so the node is *reached*) for deep recall. |
| `RECUPERO_VALUE_TRACE_ENRICH_CEILING` | `50` | int | `>= 0` (0 disables) | v0.34 | Under value-trace, any non-seed node with MORE than this many outflows is built CHEAPLY (skip per-token CoinGecko contract-resolution + per-dest `is_contract` RPC + per-tx evidence fetch) — the wave aggregation value-matches the cheap set and re-does the expensive ops for ONLY the matched onward hop(s). Prevents the multi-hour wall where a high-fan-out node sits just under `RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD` and gets ~3 Etherscan RPCs per outflow. Lower for faster/cheaper runs; `0` disables the count trigger (only true service wallets get the cheap path). The seed (depth 0) is always fully enriched. |
| `RECUPERO_VALUE_TRACE_FOLLOW_SPLITS` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34.6 | Under value-trace, when a directed node has NO 1:1 onward match, try to recover a **1:N same-asset SPLIT/peel** — the node forwarded the inbound funds as many smaller same-token sends whose SUM is within ~3% of the inbound — and follow ALL its legs. Conservative: same on-chain token only (contract identity), greedy largest-first, must reach the sum within tolerance using ≤25 legs or it bails (honest dead-end, never a guess); a single over-large leg is excluded. Every followed leg is `low` confidence (a SET inference — which recipients are laundered funds vs. the node's own change isn't provable) and flagged `ambiguous` when the node had same-asset outflows outside the matched subset. Default OFF preserves every existing trace (incl. Zigha 4/4) byte-identically. Turn ON for deep peel-chain reach (e.g. Lazarus/Ronin consolidation wallets that peel into mixer-denomination chunks). Surfaced under `coverage.value_matched_hops` with `kind=same_asset_split`. |
| `RECUPERO_PLATFORM_JWT_SECRET` | unset | str | non-empty in prod | SaaS | HS256 signing secret for the multi-tenant `/v2` session tokens. The auth layer FAILS CLOSED (503) if unset, so an unconfigured deploy can't mint/verify tokens. PROD: rotate + migrate to asymmetric ES256 (verifiers shouldn't hold the signing key). Only the `/v2` surface needs it; `/v1` is unaffected. |
| `RECUPERO_PLATFORM_JWT_TTL_SEC` | `3600` | int | `> 0` | SaaS | Lifetime of a `/v2` session JWT in seconds (default 1h). |
| `RECUPERO_DATABASE_URL` | unset (falls back to `DATABASE_URL`) | str | psycopg DSN | SaaS | Postgres DSN the `/v2` platform DAO connects with (orgs/users/keys/usage + the tenant-scoped queue). Rides the Supabase transaction pooler; a process-wide `psycopg_pool` is the drop-in scale upgrade. |
| `RECUPERO_STRIPE_WEBHOOK_SECRET` | unset | str | `whsec_…` | SaaS | Stripe endpoint signing secret. `POST /v2/webhooks/stripe` verifies the `Stripe-Signature` header (HMAC-SHA256 over `"{t}.{body}"` + timestamp-tolerance replay guard) and FAILS CLOSED (400) if unset/invalid — an unconfigured deploy can't be spoofed into flipping a plan. |
| `RECUPERO_STRIPE_SECRET_KEY` | unset | str | `sk_…` | SaaS | Stripe secret key for creating Checkout Sessions (`POST /v2/billing/checkout`). Unset → that endpoint returns 501 (checkout disabled); the webhook state machine works independently. |
| `RECUPERO_STRIPE_PRICE_PRO` | unset | str | `price_…` | SaaS | Stripe Price ID mapped to the `pro` plan — drives checkout line-items AND webhook price→plan resolution (unmapped price → falls back to `free`). No Stripe ids hardcoded in source. |
| `RECUPERO_STRIPE_PRICE_ENTERPRISE` | unset | str | `price_…` | SaaS | Stripe Price ID mapped to the `enterprise` plan (see `RECUPERO_STRIPE_PRICE_PRO`). |
| `RECUPERO_APP_BASE_URL` | `https://app.recupero.io` | str | URL | SaaS | Base URL for Stripe Checkout success/cancel redirects. |
| `RECUPERO_REDIS_URL` | unset | str | `redis://…` | SaaS | Redis DSN for the SHARED per-org rate-limit token bucket (`platform.ratelimit`). Unset → the in-process limiter (correct for ONE API replica only). Set it once you run >1 replica so the limit holds across all of them; the bucket is atomic (server-side Lua). If set but the `redis` package is missing or the server is unreachable, the limiter FAILS OPEN to the in-process bucket (rate limiting is best-effort, never a hard-fail). |
| `RECUPERO_ARTIFACT_BUCKET` | unset | str | S3 bucket | SaaS | Object-storage bucket for case artifacts (`platform.objectstore`). With it + AWS creds set, `GET /v2/traces/{id}/artifacts/{name}` returns a short-lived **presigned** S3 GET URL (pure-stdlib SigV4, no boto3) for the per-org key `orgs/{org_id}/investigations/{id}/{name}`. Unset → that endpoint returns 501. |
| `RECUPERO_ARTIFACT_REGION` | `us-east-1` | str | AWS region | SaaS | Region for artifact-URL SigV4 signing + host (`{bucket}.s3.{region}.amazonaws.com`; `us-east-1` → `{bucket}.s3.amazonaws.com`). |
| `RECUPERO_S3_ENDPOINT` | unset | str | URL | SaaS | Override the S3 host for an S3-compatible provider (R2 / MinIO / GCS-XML). Unset → AWS S3. |
| `RECUPERO_ARTIFACT_URL_TTL_SEC` | `900` | int | `> 0` | SaaS | Lifetime (seconds) of a presigned artifact URL (default 15 min). |
| `RECUPERO_APIKEY_CACHE_TTL_SEC` | `60` | int | `> 0` | SaaS | TTL (seconds) for the optional Redis cache of API-key→principal resolution (`platform.keycache`), active only when `RECUPERO_REDIS_URL` is set. Positive-only + revoke-invalidated + fails open to the DB; short by design so a plan/status change propagates quickly. |
| `RECUPERO_PASSWORD_ARGON2` | unset (off) | bool | `1/true/yes/on` | SaaS | Opt in to **argon2id** for NEW password hashes (requires `argon2-cffi`; otherwise silently stays on scrypt). `verify_password` reads both formats and `login` **rehashes on next login**, so enabling it is a zero-downtime upgrade. Default install stays dependency-free (scrypt). |
| `RECUPERO_MAX_REQUEST_BYTES` | `262144` | int | `>= 1024` | SaaS | Max `/v2` request body size (bytes), enforced router-wide as a 413 guard via the Content-Length header (default 256 KiB — generous for JSON + Stripe webhooks). |
| `RECUPERO_OTEL_ENABLED` | unset (off) | bool | `1/true/yes/on` | SaaS | Enable OpenTelemetry request tracing on the API (`platform.tracing`). Requires the `[otel]` extra (`pip install .[otel]`); a no-op that never raises when off or the packages are absent. Exports OTLP/HTTP to the standard `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `RECUPERO_OTEL_SERVICE_NAME` | `recupero-api` | str | service name | SaaS | `service.name` resource attribute for exported spans. |
| `RECUPERO_PLATFORM_REQUEST_LOG` | unset (off) | bool | `1` | SaaS | Emit ONE structured JSON log line per `/v2` request (`platform.reqlog`, logger `recupero.platform.request`) keyed by the resolving tenant — `{event, method, path, status, duration_ms, org_id, plan, role}` — so multi-tenant traffic can be sliced by org in a log aggregator (Datadog / Loki / CloudWatch). Off by default (the ASGI middleware isn't even installed); set `1` to enable. The tenant fields are read from `request.state` where the auth dependency records them; an unauthenticated/rejected request logs `org_id=null`. |
| `RECUPERO_SPAM_TOKEN_FILTER` | **ON (default)** | bool | opt out via `0/false/no/off` | #253 | Drop address-poisoning **airdrop-spam token** edges at wave aggregation, BEFORE they are recorded / value-matched / enqueued. A famous or OFAC-sanctioned seed gets flooded with unpriceable spam-token Transfers spoofing `from` (a real Ronin-exploiter trace: ONE "Dream Cash"/CASH contract was 5,980 of 6,000 sampled rows). These bypass the zero-value poison prune (non-zero amount) AND the USD dust floor (`usd=None` can't be compared) — left in, they bloat the case, burn `RECUPERO_MAX_TRANSFERS_PER_CASE`, and flood the next wave with junk recipients before the laundering path is reached. A contract is flagged when it is an UNPRICEABLE ERC-20 (non-native, no coingecko id) AND either appears ≥ `RECUPERO_SPAM_TOKEN_MIN_TRANSFERS` times for one address (a broadcaster) or its symbol carries a phishing marker (URL / claim / airdrop wording). NOISE removal, not coverage loss — a real unpriced stolen leg (e.g. msyrupUSDp) appears too few times to trip the threshold, so the follow-the-largest-unpriced-leg doctrine is preserved. Surfaced as `coverage.airdrop_spam_pruned`. Opt out with `0` for fixture-build / deterministic runs. |
| `RECUPERO_SPAM_TOKEN_MIN_TRANSFERS` | `25` | int | `>= 2` | #253 | Per-contract broadcaster threshold for `RECUPERO_SPAM_TOKEN_FILTER`: an unpriceable ERC-20 appearing this many times in one address's outflow set is airdrop spam. Set high above any plausible same-token laundering count (a peel/split is a handful of legs) yet far below a spam flood (thousands). Bad/blank/below-2 keeps the default. |
| `RECUPERO_DEEP_REACH` | **ON (default, v0.37.0)** | bool | opt out via `0/false/no/off` | v0.35.4 | **Master switch — deep is now the DEFAULT.** Recupero goes as deep as possible on every trace: value-directed tracing through aggregators/service wallets + 1:N split/peel follow + labeled mixer/exchange/bridge terminals + dormancy-aware window (=0, no upper cap) + cryptographic cross-chain **bridge confirmation** (`RECUPERO_BRIDGE_CONFIRM`) + lock-and-mint **pool-bridge matching** (`RECUPERO_LOCKMINT_MATCH`). Only fills knobs that are NOT individually set — any explicit per-knob env var (or the `value_trace` arg) still wins, so you can pin one knob off (e.g. `RECUPERO_VALUE_TRACE_WINDOW_HOURS=168`, or `RECUPERO_BRIDGE_CONFIRM=0` for a cheaper same-chain-only deep pass). **Opt OUT with `RECUPERO_DEEP_REACH=0`** for fixture-build / deterministic R&D runs (restores the legacy shallow behavior — stop at the first service wallet, never cross a bridge). v0.37.0 flipped this from opt-in to default after the V-CFI02 review: "halfway" tracing aimed freeze letters at the first hop instead of where the money rests. Pair with a raised `RECUPERO_TRACE_TIMEOUT_SEC` + a paid explorer rate (deep is API-heavy). |
| `RECUPERO_VALUE_TRACE_WINDOW_HOURS` | `72` | int | `>= 0` (0 = no upper cap) | v0.35.2 | The time window, after an inbound, within which the value-matcher (1:1 same-asset / USD) AND the 1:N split detector accept an onward hop. **Dormancy-aware:** `0` = LOWER-BOUND-ONLY (a hop must be *after* the inbound; **no upper cap**) — laundering parks funds and moves them weeks/months later, so a fixed cap drops the real onward hop (same principle as `RECUPERO_CROSSCHAIN_WINDOW_HOURS`). Default `72` is conservative and preserves every existing trace (incl. Zigha 4/4) byte-identically; set `0` (or a large value) for deep cold-case reach (e.g. Ronin consolidation wallets forwarding past 72h before a mixer deposit). Bad/blank/negative keeps `0` semantics via the int parser (clamped `>=0`). |
| `RECUPERO_VALUE_TRACE_LABELED_TERMINALS` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34.7 | Under value-trace, STOP-AND-FLAG at a labeled terminal: at a directed node, same-asset outflows that land at a **labeled mixer / exchange / bridge** are the traced money's end state — record them (the brief then classifies the destination from its existing label: mixer→**UNRECOVERABLE**, exchange→**EXCHANGE**/subpoena, bridge→cross-chain handoff) but do NOT traverse. Mirrors how TRM/Chainalysis stop-and-flag at a mixer instead of chasing every pool deposit (e.g. Ronin peeled ~21,629 ETH into Tornado's 100-ETH pool ≈ 216 deposits → one truthful "→ Tornado Cash → UNRECOVERABLE", not 216 hops). Same-asset = same on-chain token (contract identity) as the inbound. Never fabricates (only real, already-label-enriched outflows). Surfaced under `coverage.labeled_terminals` (node, terminal, label, status, aggregate amount/USD, tx count, sample tx hashes). Default OFF preserves every existing trace (incl. Zigha 4/4) byte-identically. |
| `RECUPERO_PIVOT_MULTICHAIN` | unset (off) | bool | `{1,true,yes,on}` to enable | v0.34 | Multi-chain perpetrator pivot. After the victim trace, identify the consolidation **hub** (largest-USD unlabeled EOA recipient) and **re-trace it on every pivot chain** (value-directed), merging the findings. A victim trace on one chain can't see funds the perp split across chains (e.g. Arbitrum-bridged → Ethereum-DAI); pivoting on the hub surfaces them. OPT-IN — multiplies API cost by the number of pivot chains. |
| `RECUPERO_PIVOT_CHAINS` | `ethereum,arbitrum,base,optimism,polygon,bsc` | csv | `Chain` enum names | v0.34 | Comma-separated chains the multi-chain pivot re-traces the hub on (one Etherscan V2 key covers all EVM via chain_id). Unknown names skipped; the hub's discovery chain is auto-excluded. |
| `RECUPERO_PIVOT_MIN_USD` | `50000` | Decimal | `>= 0` | v0.34 | Minimum inbound USD for an address to qualify as a pivot hub — avoids burning N-chain traces on a dust counterparty. |
| `RECUPERO_MAX_CONTINUATION_SEEDS` | `25` | int | `>= 0` | v0.16.x | Cap on same-chain bridge / DEX continuation seeds per case. |
| `RECUPERO_MAX_CROSS_CHAIN_SEEDS` | `10` | int | `>= 0` | v0.16.13 | Cap on cross-chain destination seeds across all chains. |
| `RECUPERO_DEX_SWAP_MAX_ROUNDS` | `1` | int | `[1, 8]` | v0.39 | Iterative DEX-swap-chain continuation rounds (roadmap #8): follow a chain of consecutive same-chain swaps (USDT->WBTC->ETH->...) by re-collecting swap-output seeds each round. `1` = legacy single-pass (byte-identical). Bounded by `RECUPERO_MAX_CONTINUATION_SEEDS` per round + the visited dedup. |
| `RECUPERO_DISABLE_PASS2` | unset | bool | `=1` to disable | v0.20.x | Kill switch for the perpetrator-trace pass-2 stage. |
| `RECUPERO_PASS2_RATIO_THRESHOLD` | `100` | float | `> 0` | v0.20.x | Outflow/inflow ratio threshold for pass-2 candidate identification. |
| `RECUPERO_GRAPH_EVENTS_BRIDGE` | unset (off) | bool | `{1,true,True}` to enable | v0.35 | Operator graph real-time (Phase 4.13). When enabled, the API starts a Postgres `LISTEN graph_events` bridge (daemon thread) on the first SSE connection, so the worker's watch-tick `NOTIFY`s reach operators streaming `/v1/operator/graph/{id}/stream`. Off by default so tests / non-streaming deploys don't open a DB listener. Requires `SUPABASE_DB_URL`. |
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
| `RECUPERO_DEST_CONTINUATION_WAVES` | `8` under deep-reach, else `2` | int | `>= 0` | v0.34 | Depth of the cross-chain DESTINATION-chain continuation. **v0.37.1:** each wave now follows BOTH swap outputs (e.g. 0x→DAI settler payout) AND generic value-bearing onward hops (a plain receiver→wallet→…→exchange trail), so the destination-chain trace goes to depth instead of dead-ending after one hop. Service-wallet sources are excluded (don't fan out at a commingling node) and each hop is window/visited/`should_traverse`/contract-gated. Default is deep-reach-aware (8 deep vs 2); an explicit value always wins, `0` disables the dest continuation entirely. |
| `RECUPERO_CROSSCHAIN_MAX_BRIDGE_HOPS` | `4` under deep-reach, else `1` | int | `>= 1` | v0.37.1 | Max number of CONSECUTIVE bridge crossings the cross-chain continuation follows (A→bridge→B→bridge→C). v0.37.1 multi-bridge recursion: each round re-detects bridges among the prior round's destination-chain transfers (HIGH-confidence calldata-decoded destinations only) and seeds the next, deduped via the cross-chain visited set and bounded by the per-case transfer cap / API budget / deadline. Default deep-reach-aware (4 vs 1 = legacy single crossing); explicit value wins (clamped `>=1`), bad value falls back to the deep-reach default. |
| `RECUPERO_LOCKMINT_MATCH` | `0` (off; **on under `RECUPERO_DEEP_REACH`**, v0.37.0) | bool | `1/true/yes/on` / opt-out `0/false/no/off` | v0.32.1 | Lock-and-mint cross-chain matching for POOL bridges (Celer/Orbiter/THORChain/Allbridge/Multichain) whose recipient is NOT in the source calldata — so the cryptographic order-id oracle cannot pair them. Correlates the perpetrator's inbound transfers on each candidate chain by amount+time and continues the trail. Inferential (correlation, never proof — medium/low confidence) and costs extra inbound fetches, hence a standalone default of OFF. **v0.37.0:** when unset it inherits `RECUPERO_DEEP_REACH` (now ON by default), so deep traces also cover pool bridges. The brief classifies these inferred destinations as INVESTIGATE leads, never freeze targets, so coverage widens without billing an inferred edge as freezable. Explicit value wins (`RECUPERO_LOCKMINT_MATCH=0` to deep-reach without it). |
| `RECUPERO_BRIDGE_CONFIRM` | `0` (off; **on under `RECUPERO_DEEP_REACH`**) | bool | opt-in via `1/true/yes/on`, opt-out via `0/false/no/off` | v0.34 | CRYPTOGRAPHIC bridge-destination confirmation: for each cross-chain handoff with a verified pairing spec (DLN/Across/Celer/Hop/Synapse/CCIP/Connext/Wormhole), ask the bridge-pairing oracle to confirm the destination by the protocol's own cross-chain id matched on BOTH chains (`high` — genuine proof, not correlation). A confirmed destination is preferred over the heuristic calldata decode, seeded for continuation, and recorded on `case.config_used["bridge_confirmations"]` for the brief + validator. Makes live destination-chain log queries, hence a standalone default of OFF. **v0.36.0:** when unset, this now inherits `RECUPERO_DEEP_REACH` — so the recommended production `RECUPERO_DEEP_REACH=1` turns the oracle on as part of the full forensic recipe. An explicit value here always wins (set `RECUPERO_BRIDGE_CONFIRM=0` to deep-reach with the oracle pinned off). See `docs/BRIDGE_PAIRING.md`. |
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
| `RECUPERO_SEED_DEMO_CASE` | unset (on-when-empty) | bool | `=0` to disable | v0.35.x | The `recupero-api` entrypoint seeds a clearly-labeled DEMO/SAMPLE case into an EMPTY case store at startup so a fresh deploy's operator console is populated + clickable. No-op when real cases exist; set `=0/false/no/off` to never seed. Startup-only (not a FastAPI event) so it never runs in tests. |
| `RECUPERO_CASE_STORE` | `local` | str | `local` / `supabase` | v0.36 | Backing store for the Case-Index operator console (`/v1/cases`). Default `local` scans the on-disk case dir. Set `=supabase` (with `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`) to list + browse real investigations from the Supabase Storage bucket the worker writes to — so a fresh `recupero-api` deploy shows real cases, not just the demo. Any value other than `supabase`, or missing creds, stays local. |
| `RECUPERO_SUPABASE_BUCKET` | `investigation-files` | str | bucket name | v0.36 | Supabase Storage bucket the Case-Index console reads when `RECUPERO_CASE_STORE=supabase`. Must match the bucket the worker writes investigations to. |
| `RECUPERO_INTERNAL_BLACKLIST_PATH` | `{data_dir}/intel/internal_blacklist.json` | path | file path | v0.39 | Where `recupero-ops harvest-blacklist` writes (and `load_high_risk_db` reads) the internal known-bad blacklist harvested from the case corpus. Only ARMED entries (real illicit-role sightings — never test fixtures / victims / services) are merged into risk-scoring so the screener + tracer fire a `high` verdict on a hit. Absent file → no-op. |
| `RECUPERO_INTERNAL_BLACKLIST_MANUAL_PATH` | sibling `internal_blacklist_manual.json` | path | file path | v0.39 | Operator-curated manual arms (`recupero-ops blacklist-arm/-disarm`). A separate file so re-harvesting never clobbers hand-attributed known-bad wallets (e.g. an exploiter seed, a Tornado deposit). Every manual entry is armed. |
| `RECUPERO_DEMIX_LEADS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.39 | Opt-in mixer-demixing leads (`trace.demix_runner.run_demix_leads`). When set, a finished trace's deposits into a known Tornado pool trigger an extra `Withdrawal`-event getLogs fetch + probabilistic same-pool candidate scoring (address-reuse / relayer / FIFO). Default off — kept out of the hot trace path (same discipline as `RECUPERO_BRIDGE_CONFIRM`). Leads are ALWAYS low-confidence, never a followed destination. The `recupero-ops demix-leads` CLI runs it regardless (explicit invocation = opt-in). |
| `RECUPERO_NFT_FLOWS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in observed-NFT-flow artifact (`trace.nft_runner.collect_nft_flows`). When set, a finished trace fetches each traced wallet's ERC-721/1155 transfers (Etherscan tokennfttx + token1155tx, both directions, capped 25 wallets x 200 rows) and writes `nft_flows.json` + a guarded trace-report section so NFT-sale laundering / mint-and-flip moves stop vanishing from the case record. OBSERVATIONS only - no value claims, NFT recipients are never followed, recoverable total unchanged. Default off = zero cost (no adapter calls). |
| `RECUPERO_LP_LEADS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in Uniswap V3 park-and-withdraw leads (`trace.lp_runner.run_lp_leads`). When set, each traced-wallet deposit into the verified NonfungiblePositionManager resolves to its position tokenId (deposit receipt) and every later `Collect` exit on the SAME position becomes a lead in `lp_leads.json` + a guarded trace-report section. Position link = protocol identity (high); actor attribution high only when the exit recipient is the parking wallet, else medium. Leads are never a followed destination; recoverable total unchanged. Default off = zero cost. |
| `RECUPERO_LENDING_LEADS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in lending cross-address withdrawal leads (`trace.lending_runner.run_lending_leads`) — Aave V3 (indexed-user topic filter) + Compound III / Comet (indexed-src, queried only against PINNED verified markets since its 3-arg Withdraw signature is generic). When set, each traced wallet's Withdraw events are fetched and every withdrawal sent DIRECTLY to a different address - an exit emitted by the protocol contract, invisible to outflow enumeration - becomes a lead in `lending_leads.json` + a guarded trace-report section. Both addresses are protocol-stamped indexed topics (high confidence). Back-to-self withdrawals are context only. Leads are never a followed destination; recoverable total unchanged. Default off = zero cost. |
| `RECUPERO_VAULT_LEADS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in ERC-4626 vault cross-address withdrawal leads (`trace.vault_runner.run_vault_leads`). When set, each traced wallet's ERC-4626 `Withdraw` events (owner = the wallet, across ALL vaults - Morpho/Yearn/Spark/etc. - via one address-less owner-topic getLogs) where the receiver differs become leads in `vault_leads.json` + a guarded trace-report section. HIGH when a deposit by the same wallet into the same vault confirms a round-trip; else MEDIUM (emitter not pre-verified). Two getLogs per traced wallet. Leads are never a followed destination; recoverable total unchanged. Default off = zero cost. |
| `RECUPERO_IBC_LEADS` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in IBC (ICS-20) continuation-out leads (`trace.ibc_runner.run_ibc_leads`), Cosmos zones only. When set, each traced wallet's outbound `send_packet` events are decoded into `ibc_leads.json` + a guarded trace-report section - where funds LEFT the zone (dest chain + receiver + denom + amount), the hop the BFS died at. The decoded hop is an on-chain protocol fact (high); `(src_channel, dst_channel, sequence)` confirms it end-to-end vs the dest zone's recv_packet; the dest CHAIN NAME comes from a pinned verified channel registry (unknown channels surface dest_chain=null). Osmosis/Noble USDC exits flagged Circle-freezable. Leads are never a followed destination; recoverable total unchanged. Default off = zero cost. |
| `RECUPERO_CRON_ALERT_WEBHOOK_URL` | unset | str | URL | v0.32 | Slack-shape webhook URL the cron scheduler POSTs to when a job hits `consecutive_failures >= 2`. Unset → silent (operators still see /cron/healthz). Accepts Discord/PagerDuty/OpsGenie that consume the same payload shape. |
| `RECUPERO_CRON_LEASE_SECONDS` | `300` | int | `> 0` | v0.32 | Postgres lock lease duration for cron leader election. Way longer than any expected job runtime; raising past 600 risks a dead replica hogging a job after SIGKILL until the lease expires. |
| `RECUPERO_CRON_HEALTHZ_STALE_HOURS` | `25` | float | `> 0`, finite | v0.32 | Hours since `last_success_utc` before /cron/healthz marks a job "stale" (degraded). Default 25 gives the 24h jobs a 1h grace window. >168h is hard-down regardless. |
| `RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP` | `100` | int | `[1, 10000]` | v0.32 | Max number of candidate labels the daily auto-ingest cron will persist per run. Hard cap protects the operator review queue from upstream tag-API flushes. |
| `RECUPERO_MULTI_SOURCE_CONFIRM` | unset (off) | bool | `1/true/yes/on` to enable | v0.32 | Gate label auto-ingest on multi-source confirmation: when on, a candidate label is only promoted if ≥2 independent sources agree. Default off preserves single-source backward-compatible ingest. |
| `RECUPERO_LABEL_DECAY_DAYS` | `180` | int | `[1, 3650]` | v0.32 | Confidence-decay window (days). A `high` label un-refreshed for this many days is effectively `medium` at lookup time; one tier per window, floored at `low`. Stored value never mutates. |
| `RECUPERO_OFAC_ALLOW_MASS_DELIST` | unset (off) | bool | `1`/`true` | v0.42 | Override for the OFAC sync anti-mass-delist guard. By default `ofac-sync` REFUSES a feed that parses to zero crypto entries, or collapses below 50% of the previous live population (≥10 prior live entries) — a 200-OK schema-drifted/placeholder document would otherwise mark every sanctioned address `removed_at_utc` in one sync and they'd all screen clean. Set `=1` only to accept a verified deliberate upstream contraction, then unset. |
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
| `RECUPERO_API_KEY_ROLES` | unset | str | `name:role,...` (role ∈ viewer/analyst/admin) | v0.38 | RBAC role per API key. Unmapped keys default to `analyst` (backward-compatible); admins (above) are always `admin`. Enforced by `require_role()`. |
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
| `RECUPERO_API_ALLOWED_HOSTS` | unset | str | comma-sep hosts | v0.35.x | When set, the API installs TrustedHostMiddleware with this Host allow-list (rejects spoofed Host headers). Unset = serve any Host (current behavior). |
| `RECUPERO_API_CORS_ORIGINS` | unset | str | comma-sep origins | v0.35.x | When set, the API installs CORSMiddleware for these origins. Unset = no CORS (the operator console is same-origin). |
| **Custody / chain-of-custody** | | | | | |
| `RECUPERO_CUSTODY_KEY_PATH` | `~/.recupero/custody_key` | str | file path | v0.17.x | Override path to the Ed25519 private key used for custody attestation. |
| `RECUPERO_AUTO_LITIGATION_ARTIFACTS` | `1` (on) | bool | `=0` to disable | v0.35.x (default-on v0.39 #7) | At deliverables build, also emit the court exhibit pack + SAR/STR + MLAT/314(b) + exchange-freeze letters + time-sensitivity advisory, and (when a custody key is configured) a signed Ed25519 chain-of-custody over every artifact. DEFAULT-ON as of v0.39 (#7) so every real case ships the full litigation pack; opt OUT with `=0` for fixture/golden/byte-identical determinism runs. |
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

#### `RECUPERO_AUTO_LITIGATION_ARTIFACTS`

`build_all_deliverables` additionally emits court-grade litigation
artifacts after the primary deliverables:

* the **exhibit pack** (`exhibit_pack/exhibit_pack.html`) — SHA-256
  exhibit index + Daubert methodology appendix + 28 U.S.C. § 1746
  declaration (no signing key required);
* the **SAR/STR draft** (`regulatory_filing/us_fincen_sar.html`) + **MLAT
  / FinCEN 314(b) drafts** + **exchange-freeze letters** (one per CEX that
  received funds) + a **time-sensitivity advisory** (`legal_requests/`);
  and
* a **signed Ed25519 chain-of-custody** attestation over every
  deliverable, appended to `custody/chain.jsonl` — produced ONLY when a
  custody key is configured (`RECUPERO_CUSTODY_KEY_PATH` or the default
  `~/.recupero/custody_key`; run `recupero-ops custody-keygen`). Absent a
  key the signing step is skipped (the unsigned per-case SHA-256
  manifests remain the integrity record).

DEFAULT-ON as of v0.39 (Activation Sprint #7) so every real case ships
the full litigation pack automatically — set
`RECUPERO_AUTO_LITIGATION_ARTIFACTS=0` to opt out (fixture-build /
golden / byte-identical determinism runs). Every step is best-effort and
never blocks a freeze letter or LE handoff.

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
| `RECUPERO_TRON_WATCH` | unset (off) | bool | `1`/`true`/`yes`/`on` | v0.41 | Opt-in gate for any AUTO-SCHEDULED Tron settled-outbound freeze-race scan (`monitoring.tron_watch`). Tron carries ~half of USDT laundering but had no near-real-time outbound watch (mempool_watch is EVM-only; Tron has no public pending mempool). When on, scheduled scans poll watched Tron wallets' recently-confirmed outbound USDT-TRC20 and flag transfers to a known exchange deposit as FREEZABLE (race a freeze). The `recupero-ops tron-watch --address ...` CLI runs regardless (explicit invocation). Public TronGrid API, no key required (TRON_PRO_API_KEY lifts rate limits). Default off. |
| `TONCENTER_API_KEY` | `chains/ton/client.py` | TON Center API key (optional; lifts the free-tier rate limit for TON native + Jetton fetches). |
| `MISTTRACK_API_KEY` | `labels/providers/misttrack.py` | MistTrack (SlowMist) API key (optional; enables paid by-address attribution enrichment — Tron/USDT/scam coverage. Inert when unset). |
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
