# Industry-best mode (v0.32.1+)

**Recupero v0.32.1+ ships in "industry-best mode" by default.** The tracker
is configured to reach destinations Reactor/TRM/Chainalysis would, even on
50-hop laundering chains. The defaults are tuned for forensic completeness,
not for cost containment.

If you're running on shared free-tier API keys and need the legacy
cost-bounded behavior, every limit below is reachable via an env var.
This document spells out the new defaults, the trade-offs, and the
ops-side checklist for running them at scale.

---

## What changed at the default layer

| Knob | Pre-v0.32.1 | v0.32.1+ industry-best |
|------|------------|-----------------------|
| `RECUPERO_API_BUDGET_USD_PER_CASE` default | $0.50 → $10,000 | **$0 (disabled)** |
| API budget ceiling | $100 → $50,000 | **$1,000,000** |
| `RECUPERO_TRACE_MAX_HOPS` hard ceiling | 8 | **64** |
| `config.trace.max_depth` (default) | 4 | 4 (unchanged) |
| `config.trace.max_transfers_per_address` | 500 | **50,000** |
| `adaptive_depth.HARD_CEILING` | 16 | **64** |
| `adaptive_depth.FRONTIER_REFUSE_AT_DEPTH` | 8 | **16** |
| `adaptive_depth.FRONTIER_REFUSE_SIZE` | 10,000 | **100,000** |
| `adaptive_depth.BUDGET_STARVATION_FLOOR_DEPTH` | 4 | **16** |
| Cross-chain BFS bridges per case | (n/a — capped indirectly) | unlimited |

---

## The headline claims

* **API budget tracking: DISABLED by default.** Set
  `RECUPERO_API_BUDGET_USD_PER_CASE` to a positive USD value to opt in.
  When disabled, `record()` is a no-op fast-path so the tracker has zero
  per-call overhead.

* **Max trace depth: 64 hops.** Reactor caps around 12. We go deeper. The
  config default of `max_depth=4` is conservative — operators bump
  `RECUPERO_TRACE_MAX_HOPS` per case (or set
  `RECUPERO_ADAPTIVE_DEPTH=1` to let the adaptive policy choose based on
  case severity, which now floors at 16 for industry-best deployments).

* **Max frontier per depth level: 100,000 addresses.** Reactor caps
  around 5,000. Past depth 16, if the frontier is still under 100k
  addresses, BFS keeps expanding. The guard exists so a single ecosystem-
  wide CEX address doesn't blow the heap; below the threshold the tracer
  follows everything.

* **Max transfers fetched per wallet: 50,000.** Full activity history
  for whale wallets. Reactor caps around 5,000. Operators set
  `RECUPERO_MAX_TRANSFERS_PER_ADDRESS=0` to disable the cap entirely.

* **Cross-chain BFS continuation: unlimited bridges per case.** The
  `RECUPERO_MAX_CROSS_CHAIN_SEEDS` env var still exists (default 10)
  for operators who want a cap, but the default flow chases every
  decoded bridge handoff.

---

## Trade-offs

These defaults trade per-case API quota for forensic completeness. They
are the right choice for paid investigations on a $499+ price point.
They are the wrong choice for a free-tier deployment running 100 cases
a day across shared keys.

* **Longer per-case runtime.** A 64-hop trace on a deep-laundering chain
  can run for minutes rather than seconds. The 540s tracer deadline
  (`RECUPERO_TRACE_TIMEOUT_SEC`) still bounds the worst case.
* **Higher API quota usage on Etherscan / Alchemy / Helius.** A whale
  case can burn 10k–50k API calls. The free tiers are 100k req/day
  per provider; one whale wallet can eat a quarter of that.
* **More memory.** 50,000 transfers per wallet × N wallets per wave
  can hold tens of thousands of `Transfer` Pydantic models in memory.
  The per-case transfer cap (`RECUPERO_MAX_TRANSFERS_PER_CASE`,
  default 50,000) is still in place and the BFS bails out gracefully
  on hit.

---

## Recommended ops checklist before flipping the switch

Before turning industry-best mode loose on a production worker, walk
through this:

1. **Scale your Helius plan.** Free tier is 100k credits/month. Whale
   cases on Solana burn 5k–10k credits per case. Bump to Builder
   ($99/mo, 10M credits) or Professional ($299/mo, 50M credits) at
   minimum.
2. **Scale your Alchemy plan.** Default `requests_per_second=2.5` per
   chain is conservative; the Growth tier (Free → $49/mo) raises the
   compute-unit cap by 5x.
3. **Verify your Etherscan key is V2 multichain.** Single-chain V1 keys
   silently 401 on Arbitrum/BSC/Polygon traces. The tracker logs the
   401 but continues with partial results — operators who don't check
   logs miss it.
4. **Monitor `case.config_used["api_budget"]` even with tracking
   disabled.** The snapshot is still emitted (with `enabled=false`)
   so operators can post-hoc see per-provider call counts. The brief
   renderer skips the section when `enabled=false`.
5. **Re-enable budget tracking on cost-controlled deployments.** Free-
   tier operators running many cases set
   `RECUPERO_API_BUDGET_USD_PER_CASE=5.00` or similar. The tracer
   then exits with `trace_status=partial_budget_hit` when the case
   exceeds the cap — same graceful-degradation shape as the deadline.

---

## Safety guards still active

Industry-best mode does NOT remove the forensic-correctness guards.
Specifically:

* **Per-case randomized thresholds.** Dust-attack `min_fanout` and the
  clustering minimums are still HMAC-randomized per case under
  `RECUPERO_RANDOMIZATION_SECRET`. An adversary reading the source can't
  pick "fanout - 1" to evade — the actual cutoff varies per case.
* **Cross-chain time-window filter.** Default 24-hour window past each
  bridge handoff. Post-incident-window noise on the destination chain
  is still dropped. Disable with `RECUPERO_CROSSCHAIN_WINDOW_HOURS=0`.
* **Service-wallet skip.** Wallets emitting more outflows than
  `service_wallet_outflow_threshold` (default 200) are still terminal
  for the BFS — their transfers land in the audit trail but BFS doesn't
  follow them into the next wave.
* **Stop-at-exchange / -contract / -bridge.** Still on by default. The
  DEX-swap + bridge-handoff continuation re-resolves the next hop with
  high-confidence decoding before queueing — same path as v0.31.x.
* **Per-transfer sanity ceiling.** Any single transfer claiming more than
  $100M USD is rejected as a likely spoofed-token / bad-decimals
  artifact. The transfer lands without a USD value rather than
  poisoning the total.

---

## How operators opt OUT

If you want the legacy v0.31.x bounded behavior:

```bash
# Re-enable budget tracking at $0.50/case (legacy default)
export RECUPERO_API_BUDGET_USD_PER_CASE=0.50

# Cap max hops at the legacy ceiling
export RECUPERO_TRACE_MAX_HOPS_HARD_CEILING=8
export RECUPERO_TRACE_MAX_HOPS=4

# Cap per-wallet transfer fetches at the legacy 500
export RECUPERO_MAX_TRANSFERS_PER_ADDRESS=500
```

This restores the pre-v0.32.1 envelope without touching code.

---

## Why we made the change

The `JACOB_ROUND2_ADVERSARY_AUDIT_v032.md` adversary review showed
that every artificial cap was a evasion surface: an adversary who
spends $5K+ on consultant fees to design the laundering path can
trivially stay under a $0.50 budget cap by routing through one extra
hop, or stay above an 8-hop ceiling by adding two more consolidation
wallets. The right defense isn't a smaller cap; it's removing the cap
and competing on forensic depth.

Reactor / TRM / Chainalysis don't have these caps. Recupero is
priced as a peer of those tools; the defaults should match.

Operators who need the budget gate (cost-controlled deployments, free-
tier API keys, etc.) opt in via the env vars above. Everyone else
gets the industry-best behavior with no configuration.
