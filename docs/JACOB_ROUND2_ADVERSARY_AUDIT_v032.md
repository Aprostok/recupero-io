# Round-2 adversary audit — v0.32.1

Prepared 2026-05-28. Branch `pdf-deliverables`, worktree
`cranky-fermat-54fcfb`. Scope: the same adversary as round-1, who has
now **also** read commits `bb6d350`, `9fb4742`, `e0ce7d8` (the v0.32.1
mitigations) and redesigns the laundering routes to defeat the new
defenses.

**Bottom line up top**: round-1 found 3/3 routes evading. Round-2
finds **2/3 routes still evade** end-to-end. The closure of Route 1
(Polygon PoS) is **partial**: the decoder is wired and good for that
specific bridge, but the adversary now picks one of the seven L2
canonical bridges that DID NOT get a decoder (Polygon zkEVM, Linea,
Scroll, Blast, opBNB, Mantle native bridge, Manta) — or sticks with
Polygon PoS but routes via a bridge aggregator (LiFi/Squid) that
hides the inner rollup-canonical hop.

Two of v0.32.1's headline mitigations turn out to be **dead code** —
the module exists with full implementation and tests, but is **not
imported by any caller**:

* `src/recupero/security/per_case_randomization.py` — defines
  `case_threshold` / `get_case_thresholds`, exported through
  `recupero.security.__init__`, but `dust_attack.py`, `clustering.py`,
  `cex_continuity.py`, `tracer.py` all still read fixed module-level
  defaults. `min_fanout=10` is still hardcoded at
  `dust_attack.py:98`. Adversary still picks 9.
* `src/recupero/labels/multi_source_confirm.py` — defines
  `requires_multi_source_confirm` + `confirm_via_secondary_sources`,
  but `labels/api.py:177` (`promote_label_candidate`) and
  `labels/auto_ingest.py:681` (`promote_candidate`) never call
  either. P1-P4 poisoning attacks are NOT mitigated.

A third headline claim — that the API budget was bumped $0.50 → $10K —
is **not in the code**. `observability/api_budget.py:120` still has
`_DEFAULT_BUDGET_USD = Decimal("0.50")` and the env-var path **clamps
values above `_BUDGET_MAX=100.0` back to the $0.50 default with a
WARN** (`api_budget.py:176-181`). The `V0_32_1_CERT_CHECKLIST.md`
target of `RECUPERO_API_BUDGET_USD_PER_CASE=10000` is rejected by the
resolver. Route 3 ($50M speed-laundered) is unchanged from round-1.

---

## Round-1 route closure verification

| Route | Status | Notes |
|---|---|---|
| Route 1 (Polygon PoS) | **partial** | Polygon PoS / Optimism / Arbitrum / zkSync / Base rollup-canonical decoders ARE wired (`bridge_calldata.py:2348-2580` + dispatcher at `:550-590`). Polygon zkEVM, Linea, Scroll, Blast, opBNB, Mantle native bridges still not in `bridges.json` AT ALL. Adversary route shifts to any one of these. LiFi decoder still has only 6 selectors; LiFi Diamond has 40+ facets. Safe-ownership-swap (R-002) still open. |
| Route 2 (Tron 9-fanout) | **open** | `per_case_randomization.py` exists as a complete module + tests; **not called from any consumer**. `dust_attack.identify_dust_attack_destinations` still uses default `min_fanout: int = 10` (`dust_attack.py:98`). USDD PSM still listed as `category="bridge"`, not `"swap"`. Tron native TRX fetch IS now implemented (`chains/tron/adapter.py:202-230`) — that's a real closure for TR-CRIT-2, NOT Route-2 itself. |
| Route 3 ($50M speed) | **open** | `_DEFAULT_BUDGET_USD = Decimal("0.50")` unchanged (`api_budget.py:120`). `_BUDGET_MAX = Decimal("100.0")` clamps any operator override of $10K back to $0.50 default. `partial_deadline_hit` / `partial_budget_hit` markers DO render in `tracer.py:408,425,504` — that part of the claim is true. `adaptive_depth.py` defines a `HARD_CEILING = 16`, but `compute_max_depth` is annotated `TODO(wave-4-integration): wire into trace.tracer entry point` (`adaptive_depth.py:15-17`) — it's not actually called either; `tracer.py:166` clamps to `min(8, env_max_hops)`. |

### Round-1 poisoning vector verification

| Vector | Status | Notes |
|---|---|---|
| P1 DeFiLlama fake-bridge | **open** | `multi_source_confirm.confirm_via_secondary_sources` exists with `HIGH_IMPACT_CATEGORIES` including `"bridge"`. Not called from `promote_candidate`. Operator still single-source-promotes. |
| P3 Tronscan tag spoofing | **open** | Same: `confirm_via_secondary_sources` has a Tron-specific deny path requiring `has_high_trust`, but never called. |
| P5 Promote-endpoint key compromise | **partial** | `_compute_promote_confirm_sha256` IS defined (`auto_ingest.py:202`) and `promote_candidate(confirm_sha256=...)` checks it (`auto_ingest.py:736-744`). But the API endpoint `labels/api.py:177` does not forward `confirm_sha256` from the request body, so the pin is unreachable over HTTP. The "admin-only audit log" claim points to `api/cron_admin_api.py`, which is a **cron healthz redactor**, not a label-promote audit log. |

---

## NEW v0.32.1 evasion routes

Three new routes designed against v0.32.1 specifically. Each assumes
the adversary has read the v0.32.1 source and noted the dead-code
mitigations above.

### Route 1' — Polygon zkEVM canonical bridge escape ($8M USDC)

**Premise**: adversary read the v0.32.1 decoder list. The five
rollup-canonical bridges with decoders are Polygon PoS, Optimism,
Arbitrum, zkSync, Base. Polygon zkEVM has a SEPARATE canonical bridge
(`PolygonZkEVMBridge` at `0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe`)
which is NOT in `bridges.json` and not in the dispatch in
`bridge_calldata.py:565-590`.

**T+0**: $8M USDC drained from Ethereum victim `V` to attacker EOA
`S1` via standard `transferFrom`.

**Hop 1**: `S1` → `PolygonZkEVMBridge.bridgeAsset(destinationNetwork=1,
destinationAddress=attacker_pZkEvm, amount=8e12, token=USDC,
forceUpdateGlobalExitRoot=true, permitData="0x")`.

* **What Recupero sees**: `S1` made a Transfer to
  `0x2a3DD3EB832aF982ec71669E178424b10Dca2EDe`, which is unlabeled in
  `bridges.json`. So either:
  1. It looks like an unlabeled contract; `stop_at_contract=True`
     terminates the trace. Section 5 shows: "Destination: unlabeled
     contract, trace terminated."
  2. Or, if `stop_at_contract` was relaxed for this case, the BFS
     continues — but Polygon zkEVM is **not in the `Chain` enum**
     (`models.py:29-87` lists 22 chains; polygon_zkevm is absent
     even though `labels/auto_ingest.py:74,142` lists it as an
     ingestable chain). The continuation pass at `tracer.py:478-493`
     would fail to instantiate the destination adapter and silently
     produce no continuation.

* **What actually happened**: $8M is now sitting at `attacker_pZkEvm`
  on Polygon zkEVM, fully visible on the zkEVM explorer, but not in
  the brief.

**Hop 2**: On Polygon zkEVM, swap USDC → USDT via QuickSwap-on-zkEVM.
Recupero never opened the case on this chain.

**Hop 3**: Bridge USDT from zkEVM → BNB Smart Chain via the Multichain
remnant deployment (or Allbridge zkEVM deployment, also unlabeled).

**Hop 4**: On BSC, deposit to Binance hot wallet under a KYC-fraud
account.

* **Final destination**: Binance BSC, never surfaced in Recupero's
  brief.
* **Brief output**: "Destination: 0x2a3D…2EDe (unlabeled contract).
  Trace terminated."

**Variants** (each as effective as Route 1'):

- Linea: bridge contract `0xd19d4B5d358258f05D7B411E21A1460D11B0876F`,
  not in `bridges.json`, no decoder.
- Scroll: bridge `0xF8B1378579659D8F7EE5f3C929c2f3E332E41Fd6` — same
  status.
- Blast: bridge `0x697402166Fbf2F22E970df8a6486Ef171dbfc524` — same.
- opBNB: bridge — same.
- Mantle: native bridge `0x95fC37A27a2f68e3A647CDc081F0A89bb47c3012` — same.
- Manta: similar.

The adversary picks the L2 with the highest current USDC liquidity at
laundering time. **Recupero loses the case regardless of which one.**

### Route 2' — Bridge-aggregator obscuration of the inner rollup hop ($3M USDC)

**Premise**: adversary read `bridge_calldata.py:325-335` and noted
that `_LIFI_METHODS` has only 6 selectors. LiFi Diamond has 40+
facets; the adversary picks a facet selector NOT in the dict, and the
decoder returns "confidence='low' / no destination."

**T+0**: $3M USDC at victim wallet `V` drained to `S1`.

**Hop 1**: `S1` → LiFi Diamond (`0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE`,
which IS in `bridges.json` as a labeled bridge). The adversary calls
a LiFi facet selector NOT in `_LIFI_METHODS` — e.g.
`startBridgeTokensViaSymbiosis` (`0xa9bb01f3`) or one of the 30+ other
facets. The calldata internally instructs LiFi to call the
Polygon PoS RootChainManager.

* **What Recupero sees**: Transfer hits LiFi Diamond. The bridge IS
  labeled, but the LiFi decoder returns `confidence='low'` because
  the facet selector isn't in `_LIFI_METHODS`. Per
  `bridge_calldata.py:323-324`: "unrecognized facets fall back to
  confidence='low' recognition." The destination address falls out as
  None.
* The dispatcher in `bridge_calldata.py:566-590` checks
  `"polygon" in proto_compact AND ("pos" OR "rootchainmanager" OR
  "erc20predicate")`. The bridge protocol string at the LiFi entry is
  `"LiFi: Diamond (Ethereum)"`, not anything containing "polygon" or
  "rootchainmanager". The rollup-canonical Polygon decoder is never
  reached — the call is dispatched to `_decode_lifi` instead.
* The continuation pass in `tracer.py` requires
  `destination_address` to be populated. LiFi returns None for
  unknown facets. No continuation.

* **What actually happened**: The funds went through LiFi → Polygon
  PoS RootChainManager → adversary's Polygon address. Brief shows "LiFi
  bridge — destination unknown."

**Hop 2**: On Polygon, deposit to Tornado Cash (Polygon deployment,
NOT in `mixers.json` per audit's G-S3 — Tornado on Polygon is absent
from the seed file). Even if it were labeled, the BFS isn't running
on Polygon because the cross-chain handoff never resolved.

**Hop 3**: Withdraw to fresh Polygon address. Bridge again via Squid
Router (`_SQUID_METHODS` has only 2 selectors: `0x84d2bb4d`,
`0x32fb1360`). Pick a Squid selector not in the dict — same
medium-confidence-no-destination outcome.

**Hop 4**: On the second-destination chain (Polygon → BSC via
Squid), deposit to OKX hot wallet. Recupero's brief continues to
show "LiFi bridge handoff — destination unknown."

* **Brief output**: Section 7: "Cross-chain handoff via LiFi Diamond.
  Destination chain: candidate list. Destination address: extraction
  failed. Follow-up URL: lifiexplorer.com" — exactly the round-1
  failure mode, but now achieved through a LABELED bridge.

**Why this beats W2-E (rollup-canonical decoder)**: the v0.32.1
decoder works only when the bridge protocol string MATCHES the
dispatcher's substring check. The dispatcher checks the LABEL string
from `bridges.json`, not the actual underlying ABI being called. An
aggregator's calldata internally invokes the same selectors but
through a layer of indirection that the dispatcher can't see.

### Route 3' — Per-case-randomization bypass via dead-code mitigation ($600K USDT)

**Premise**: adversary cloned the repo, ran a search across the
codebase for `case_threshold` and `get_case_thresholds`, and found
that no production code path imports them. The fixed defaults remain.

**T+0**: $600K USDT-TRC20 at victim wallet `V_T` drained to `S1_T`.

**Hop 1**: `S1_T` → 9 destinations of $66,666 each. Same pattern as
round-1 Route 2 — `dust_attack.identify_dust_attack_destinations`
default `min_fanout=10` (`dust_attack.py:98`) still hardcoded;
adversary picks 9.

* **What Recupero sees**: 9 BFS branches; no dust-attack fire (fanout
  9 < 10, AND value $66K not <$1).
* **What the round-1 fix was supposed to do**: per-case randomization
  HMAC's the threshold to a per-case integer in `[7, 13]`. If
  it were wired, the adversary at fanout=9 would hit the detector ~50%
  of the time and would have to drop to fanout=6 to be safe. At
  fanout=6 the per-case band could go as low as 4. The adversary
  cannot pick a single safe number — the architecture is sound, only
  the integration is missing.
* **What's actually shipped**: `dust_attack.py` imports nothing from
  `recupero.security`. `min_fanout=10` is a default keyword arg.

**Hop 2**: Each of the 9 fanout addresses calls USDD PSM (still
labeled `category="bridge"` in `bridges.json:3887`; `category="swap"`
relabeling from M-7 was deferred per `RISK_REGISTER.md` R-013).
`stop_at_bridge=True` terminates the BFS at each. **9 dead ends.**

**Hop 3** (invisible): adversary controls a 10th wallet on the other
side of the USDD PSM, swaps USDD → USDT.

**Hop 4** (invisible): the 10th wallet splits via Tron native TRX
(now actually fetched per `chains/tron/adapter.py:202-230` — W1-C
fix). But the BFS is no longer in this case because trace ended at
the USDD PSM. The W1-C fix only matters in cases that REACH the
relevant address; this address is never reached.

**Hop 5** (invisible): consolidate to Kraken Tron hot wallet
(labeled but with stale confidence post-180d decay per
`labels/confidence_decay.py`; renders with low-confidence footnote
operators routinely skip).

* **Brief output**: 9 rows of "$66,667 → USDD PSM, trace terminated
  at bridge."

**Why this beats M-5**: M-5 was specified, designed, implemented at
module level, tested, exported through `__init__.py` — and then
never wired into the consumers. The dead-code mitigation gives a
false sense of closure to anyone who only reads the test names or the
module docstrings.

---

## NEW gaps surfaced

These are gaps in v0.32.1 that v0.32.0's adversary audit missed (or
that v0.32.1 introduced):

| ID | Gap | File | Severity |
|---|---|---|---|
| G2-1 | Per-case randomization implemented but not wired into consumers | `security/per_case_randomization.py` defined; `dust_attack.py:98` / `clustering.py` / `cex_continuity.py` / `tracer.py` all still use fixed defaults | **CRIT** |
| G2-2 | Multi-source confirmation implemented but not called from promote path | `labels/multi_source_confirm.py` defined; `labels/api.py:177` and `labels/auto_ingest.py:681` never call it | **CRIT** |
| G2-3 | API budget claimed bumped to $10K, code still defaults $0.50 + clamps overrides to $100 max | `observability/api_budget.py:120,122,176-181` | **CRIT** |
| G2-4 | `confirm_sha256` pin defined in `promote_candidate` but not plumbed from `PromoteRequest` body / header | `labels/api.py:86-109` PromoteRequest has no `confirm_sha256`; `api.py:177-181` doesn't pass one | **HIGH** |
| G2-5 | 7 L2 canonical bridges still unlabeled and undecodable (Polygon zkEVM, Linea, Scroll, Blast, opBNB, Mantle, Manta) | `labels/seeds/bridges.json` — no `chain: polygon_zkevm` entries; Chain enum doesn't include `polygon_zkevm` or `opbnb` (`models.py:29-87`) | **CRIT** |
| G2-6 | Bridge-aggregator dispatcher matches on LABEL string from bridges.json, not on the actual ABI being called — LiFi/Squid wrappers hide inner rollup-canonical calldata | `bridge_calldata.py:543-591` dispatcher logic | **HIGH** |
| G2-7 | LiFi decoder still has 6 selectors against LiFi's 40+ facets | `bridge_calldata.py:325-335` | **HIGH** |
| G2-8 | Squid decoder has 2 selectors of N | `bridge_calldata.py:310-313` | **MED** |
| G2-9 | `adaptive_depth.compute_max_depth` exists with HARD_CEILING=16 but is annotated TODO and not called from tracer; `tracer.py:166` clamps to `min(8, env_max_hops)` | `trace/adaptive_depth.py:15-17`, `tracer.py:165-166` | **HIGH** |
| G2-10 | Smart-wallet ownership swap (Safe `swapOwner`) detection — open per `RISK_REGISTER.md` R-002 | n/a | **CRIT** (carryover) |
| G2-11 | USDD PSM still labeled as `category="bridge"`; trace stops there instead of treating it as a swap and continuing past | `labels/seeds/bridges.json:3887` | **HIGH** (carryover) |
| G2-12 | CEX-continuity noisy-token list still excludes USDT/USDC/DAI/ETH/WETH — the off-ramp tokens — meaning continuity NEVER fires when adversary uses these | `cex_continuity.py:63-65` | **HIGH** (carryover) |

---

## Severity ranking

| Route | Severity | Likelihood of exploit | Fix difficulty |
|---|---|---|---|
| Route 1' (Polygon zkEVM / 7 L2 bridges) | **CRIT** | high — every L2 launch produces a new canonical bridge | LOW per chain (decoder is the same shape as W2-E's 5) but requires ongoing seed maintenance + 2 chain enum additions |
| Route 2' (LiFi/Squid aggregator obscuration) | **HIGH** | high — LiFi adds new facets monthly; adversary picks any non-listed selector | MEDIUM — would require either ABI-walking aggregator calldata or treating aggregator outputs as "destination chain unknown but address from aggregator's emit events" |
| Route 3' (per-case randomization dead code) | **CRIT** | very high — adversary just reads the same source code v0.32.0 already exposed; picks fanout=9; fix is trivial for them | LOW — wire `get_case_thresholds(case_id)` into the 4-5 consumer call sites |

### Auto-ingest poisoning severity

| Vector | Severity | Notes |
|---|---|---|
| P1 DeFiLlama fake-bridge | **CRIT** | Multi-source confirm dead code. Single-source promote unchanged. |
| P3 Tronscan tag spoof | **CRIT** | Multi-source confirm dead code; Tron-specific deny path never reached. |
| P5 Admin-key compromise | **HIGH** | `confirm_sha256` pin exists in the function but isn't reachable over the HTTP endpoint. |

---

## Score: 2/3 routes evade (round-1: 3/3)

* Route 1: **partial closure**. The five rollup-canonical decoders are
  real, wired, and good against the exact round-1 attack. The
  adversary trivially shifts to one of seven other L2 canonical
  bridges still missing from `bridges.json` and the Chain enum.
* Route 2: **open**. Per-case randomization is dead code; adversary
  picks fanout=9 same as before.
* Route 3: **open**. Budget bump claim is unsubstantiated in source;
  defaults unchanged.

**Honest framing**: the v0.32.1 audit cycle correctly identified the
right mitigations (the audit document `JACOB_ADVERSARY_AUDIT_v032.md`
lays them out clearly). The implementation cycle landed the modules
but **didn't land the integration**. Three of the four highest-value
mitigations (M-1 multi-source, M-5 per-case randomization, the budget
bump implied by R-014's "budget $0.50 → $10000") are not actually
operational.

The audit's marketing-claim guardrails (`PROMISES_AND_LIMITS.md` § 2.4)
are correctly conservative — they say "we are not shippable as a sole
defense against a Lazarus-tier APT." Round-2 confirms this. The risk
register entries R-012/R-013/R-014 claim "low residual / partial
v0.32.1" — round-2 finds these claims are aspirational, not actual.

---

## Recommended next-cycle fixes (highest leverage first)

1. **Wire `get_case_thresholds(case_id)` into the four consumers**
   (`dust_attack.identify_dust_attack_destinations`,
   `clustering._cluster_by_*`, `cex_continuity` window resolution,
   `tracer` policy construction). Smallest LOC change, largest
   adversary-cost increase. Roughly 50-100 LOC across 4 files.
2. **Wire `confirm_via_secondary_sources` into
   `promote_candidate`** — call it BEFORE the seed-file append; raise
   `ValueError("requires multi-source confirmation")` if
   `accepted=False`. Roughly 30 LOC + a sources-aggregation query.
3. **Add `confirm_sha256` field to `PromoteRequest`** and pass through
   to `promote_candidate`. Roughly 5 LOC.
4. **Either raise `_BUDGET_MAX` to a higher value (e.g. 10000) or
   replace the cap with a structured override** that requires an
   explicit operator flag. The current default + clamp combination
   makes Route 3 architecturally guaranteed to escape on cases
   > $25M. Update `.env.example` with the new default and document
   in `ENV_VARS.md`.
5. **Add Polygon zkEVM, Linea, Scroll, Blast, opBNB, Mantle, Manta
   canonical bridge addresses to `bridges.json`** AND add decoders
   following the same template as `_decode_polygon_pos`. Roughly
   400 LOC. Also: add `polygon_zkevm` and `opbnb` to the `Chain`
   enum + wire chain IDs in `worker/watch_tick._CHAIN_ID_BY_NAME`.
6. **Move LiFi/Squid dispatch to inspect the inner-bridge calldata**
   instead of returning low-confidence at unknown facets. When LiFi
   facet is unknown but the calldata contains a known inner selector
   (depositFor, depositERC20To, etc.), dispatch through to the
   underlying decoder.
7. **Relabel USDD PSM** as `category="swap"` and make `stop_at_bridge`
   ignore swap-category entries; continue BFS to the other side of
   the swap.
8. **Smart-wallet ownership-swap detection** (R-002) — index
   `AddedOwner` / `RemovedOwner` / `swapOwner` calls on
   Safe-pattern contracts. Out of scope for "round-2 fix" but
   noted for the next cycle.

After (1)-(3), Route 2 and Route 3 collapse to "open at architectural
ceiling" (still Route-3-style at $50M+ scale, but at least the
operator-visible signal is the budget hitting its cap, not a silent
under-report). After (5)-(6), Route 1' collapses too. End state:
**0/3 routes evade for the canonical attack patterns**, 1/3 escape
at the architectural ceiling (R-014: $50M+ cases hit the budget
unless the operator authorizes a higher cap), which is the calibrated
position in `PROMISES_AND_LIMITS.md` § 2.4.

---

*— end of round-2 adversary audit*
