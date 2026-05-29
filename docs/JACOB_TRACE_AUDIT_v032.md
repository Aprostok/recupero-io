# Jacob-style trace-pipeline audit — v0.32.0 (HEAD c43be19)

Prepared 2026-05-28. Scope: **trace pipeline only** (BFS, policies, cross-chain,
bridge decoders, chain adapters, dust/clustering/CEX-continuity/indirect/MEV/coinjoin).
Brief, freeze letters, LE handoff are out of scope.

The integration suite (`tests/integration/test_trace_to_brief.py`) passes 12/12.
The unit suite does not catch the issues below because every gap is a **silent-
loss-of-coverage** gap, not a "crash on bad input" gap. They are exactly the
shape of finding Jacob writes back about after the case ships.

---

## Summary by severity

| Severity | Count | Examples |
| --- | --- | --- |
| **CRIT**  | 6  | UTXO common-input collapse, Tron native dropped, time anchor wrong on dst chain, drainer-detection is stubbed off, max_depth=4 truncates real laundering, JSON `sort_keys` of `freeze_brief` will explode on tuple |
| **HIGH**  | 14 | Service-wallet threshold tunable by adversary, dust-attack confidence guard inverts on whale, peel-chain assumes 1 input addr per BTC tx, Solana CPI nested transfers lost, label-store P-I-T applied only to brief sections that go through `lookup_pit_safe`, etc. |
| **MED**   | 11 | Burn-list misses 6 known sinks, wrap/unwrap filter chain-incomplete, contract-detection cache poisoned by ‘assume contract on failure’ default, MEV builder list has 4 entries (industry uses 12+), `_decode_symbiosis` still half-heuristic, etc. |
| **LOW**   | 6  | Cluster `_looks_round` rejects ≥1M-token amounts, `_SHARED_INFRA_PARTNER_THRESHOLD` = 5 is too tight, cluster set lookup uses `>` not `>=` in places, etc. |

**Honest ship gate**: there are **6 CRIT** findings and **14 HIGH** findings.
This is not a “polish for a few hours” list. CRIT-1 and CRIT-2 alone would
cause Jacob to write back saying the trace is incomplete for any
Bitcoin-touching case and any TRX-laundering case.

---

## Where we are on the 0–100 scale (Chainalysis Reactor as ground-truth)

**~52/100.** Honest assessment:

* What we do well (≈70–80% of Reactor): bridge calldata decoding across 13
  protocols, point-in-time labels, EVM service-wallet detection, dust-attack
  pattern detection, deterministic output, 3× byte-identical builds, MEV bundle
  detection (basic), cross-chain BFS continuation with window filter.
* Where we will visibly lose to Reactor (≈30–40%): Bitcoin coverage (UTXO
  multi-input collapse + CoinJoin coverage), Solana CPI / inner-instruction
  transfers, full Tron coverage (native TRX is `return []`), entity clustering
  across multiple wallets per perp (we cluster but the heuristics miss the
  common Reactor patterns), approval-exploit drainer detection (literally
  gated behind `if False`), and any case requiring depth > 4 hops.
* What we don’t have at all (≈20% gap that Jacob WILL notice): NFT/ERC-721/1155
  endpoint, contract internal-call traversal beyond simple `internal` rows,
  ERC-4337 user-op decomposition, Cosmos/IBC, multisig signer surfacing,
  rollup canonical bridge events (Optimism/Arbitrum L1↔L2 deposit/withdraw),
  Lightning network exits, address-poisoning attack detection (separate from
  dust-shower).

If we showed this trace to a Reactor-pilled analyst, the case would survive
the cross-chain handoffs, the labeled-CEX rows, and the MEV banner. The
analyst would IMMEDIATELY notice:
1. Approval drainer-attribution column is always blank.
2. Bitcoin chains-of-custody show only the first input address per tx.
3. Any case touching a Solana program with inner-instruction transfers
   shows the SOL movements but misses the SPL-token CPI inside the same tx.

---

## CRIT findings

### CRIT-1 — Bitcoin adapter discards all but FIRST input address per tx
**Where:** `src/recupero/chains/bitcoin/adapter.py:333` (`first_input_addr = input_addresses[0]`)
and the Transfer build at L401-411 (uses only `first_input_addr` as `from`).
**Today:** Multi-input Bitcoin txs (the *normal* shape for any wallet that has
fragmented UTXOs) emit transfers keyed to ONE input address. The other inputs
look like they never moved funds. For any case where the perp has > 1 UTXO,
the trace silently under-reports outflows from N-1 of their addresses.
**Should:** Either emit N Transfer records (one per input addr, with
amount_raw = that input’s share of `value`) or — at minimum — surface the
full input-address set in the Transfer.parent_transfer_id/metadata so
downstream clustering H1 (co-spending) can fire on the FULL input list,
not just the random-first one. `trace/clustering.py:670-696` already
notes this constraint and partly works around it, but the underlying
adapter loss is forensic.
**Fix sketch:** In `_normalize_utxo_tx` return one Transfer per (input_addr,
output_addr) pair OR carry `all_input_addresses` on every Transfer dict. The
peel-chain heuristic stays as-is; the new field unlocks co-spending without
re-fetching.
**Blocks ship.** Jacob will find this on the first BTC case.

### CRIT-2 — Tron native (TRX) outflows return `[]` always
**Where:** `src/recupero/chains/tron/adapter.py:165-184` (`fetch_native_outflows`
literally `return []` with a `TODO(v0.12.x)` comment).
**Today:** Any case where a perp holds funds in TRX (gas reserve, native
swap, JustLend stake, large pool collateral) silently shows zero native
outflow. This is the WHOLE point of TRX bandwidth-fee mechanics — perpetrators
holding meaningful TRX is the norm in the Tron stablecoin laundering pipeline.
**Should:** Implement via `/v1/accounts/{addr}/transactions` filtered to
`type=TransferContract`. The TronGrid client already exists; the parser is
~50 lines.
**Fix sketch:** Mirror `_normalize_trc20` but read `raw_data.contract[0].parameter.value.{owner_address, to_address, amount}` instead.
**Jacob will find this on the first Tron-native case** (e.g., the perp consolidates
TRX into a SunSwap pool — we currently report it as the perp doing nothing).

### CRIT-3 — Cross-chain BFS uses SOURCE incident_time as start anchor for DESTINATION trace
**Where:** `src/recupero/trace/tracer.py:854` and `:1002` —
`_process_wave(...incident_time=incident_time...)` for the dst-chain wave passes
the original `incident_time` to `_trace_one_hop`, which then computes
`start_time = incident_time - incident_buffer_minutes` and fetches from
`block_at_or_before(start_time)` on the destination chain.
**Today:** If the bridge tx is days/weeks after incident_time (which it often
is — the perp lets funds rest), the BFS fetches dest-chain outflows from
`incident_time - 60min` forward, including any unrelated activity at that
destination address BEFORE the bridge ever delivered funds. The
`xchain_window_h` post-filter then drops most of them, but:
* It burns API budget against the cap (`max_transfers_per_address=500`)
* If the destination address is a busy address that existed pre-bridge, the
  500-cap fills with pre-bridge irrelevant rows; legitimate post-bridge
  outflows get truncated.
**Should:** Use `src_bridge_time` (already computed at L743-749, already
threaded into `earliest_src_time_by_chain` at L823) as the `incident_time`
substitute for the destination wave. The post-filter then becomes redundant
guard rather than primary defense.
**Fix sketch:** Plumb `src_block_time` through `_process_wave` → `_trace_one_hop`
so the dst-chain `start_time` is `src_block_time - small_buffer`.
**Blocks ship for any Stargate/Across/Connext-routed Zigha-shape case.**

### CRIT-4 — Drainer-detection signal 2 (approval → unknown contract) is hard-gated `if False`
**Where:** `src/recupero/trace/drainer_detection.py:208`.
**Today:** The most common 2024–2026 attack vector — drainer kit signs
`approve(maxUint256, drainerContract)` then `transferFrom`s out — is detected
ONLY if the drainer contract address itself appears in `high_risk.json`. Any
new drainer (Inferno, Pink, Angel, MS) emerges, lands a victim, and we mis-classify
the case as "victim sent funds to some contract" with no attribution. The
brief shows nothing in the DRAINER_ATTRIBUTION column.
`detect_approval_signatures` at L241-259 explicitly returns `[]` because
"the current case-data shape doesn't include Approval events". This is the
SINGLE most important detection-shape gap.
**Should:** EVM adapter `fetch_erc20_outflows` should ALSO fetch
`tokentx` rows where `logIndex` corresponds to an `Approval(address,address,uint256)`
event (separate Etherscan call: `&action=getLogs&topic0=0x8c5be...`) OR
parse the receipt logs we already fetch in `fetch_evidence_receipt`.
Surface as a separate `case.approvals: list[ApprovalEvent]` collection.
**Fix sketch:** New `Approval` model + Etherscan getLogs query with the
ERC-20 `Approval` topic + new adapter method `fetch_approval_events`.
~150 lines. Pre-requisite for `drainer_detection` to actually function.
**Jacob will find this on any drainer-kit case** (= 60%+ of incoming volume).

### CRIT-5 — `max_depth=4` is the default; sophisticated laundering uses 6–10 hops
**Where:** `src/recupero/config.py:47` and `tracer.py:165` (`RECUPERO_TRACE_MAX_HOPS`
clamped to `[1, 8]`).
**Today:** The defaults limit BFS to 4 hops. The Zigha-shape pattern that the
golden case exercises is depth 2; real Lazarus / Hyperdrive cases go through
6+ consolidation hubs before the off-ramp. Operator override exists
(`RECUPERO_TRACE_MAX_HOPS`) but the CLAMP MAX is 8 and there's no per-case
auto-bumping logic.
**Should:** Either raise the default to 6, OR add a "trace appears
truncated" signal (last wave hit the depth cap AND > N% of leaves were
still EOA non-terminal) that re-runs with bumped depth automatically.
**Fix sketch:** Add `case.config_used["trace_status"] = "depth_cap_hit"` when
`policy.max_depth` was reached AND the last wave produced > 0 traversable
transfers. Surface in the brief.
**Operator will notice** the first time a known case with documented depth-7
laundering shows up as "trace complete" but stops at hop 4.

### CRIT-6 — `freeze_brief.json` serialization uses `default=str` with `sort_keys=True` AND `allow_nan=False`; a tuple field will crash
**Where:** `tests/integration/test_trace_to_brief.py:754` and the symmetric
production write path that this test exercises.
**Today:** Several dataclasses in the trace pipeline carry `tuple` fields
(`CrossChainHandoff.destination_chain_candidates: tuple[str, ...]`,
`IndirectPath.path_addresses: tuple[str, ...]`). The brief consumer turns
those into lists explicitly in some paths (`handoffs_to_brief_section`
L342) and NOT in others (any new field added that forgets to convert).
The next time someone adds a tuple-typed field to a dataclass that lands
in the brief, JSON serialization will call `default=str` on it, render the
tuple as `"('a', 'b')"` rather than `["a","b"]`, and downstream consumers
expecting a JSON array will crash.
**Should:** Centralize the brief serializer to use a single helper that
recursively maps tuple→list, frozenset→list, Decimal→str-with-finite-check.
Today it's open-coded per section.
**Fix sketch:** `recupero/_common.py:as_json_safe(obj)` recursive converter,
called once at the brief boundary.
**Polish, but the kind of polish that becomes a P0 the day it breaks.**

---

## HIGH findings

### HIGH-1 — Service-wallet threshold (200 outflows) is adversary-tunable
**Where:** `src/recupero/trace/policies.py:102` (default 200) +
`tracer.py:1052` (`is_service_wallet = len(raw_outflows) > threshold`).
**Today:** A perpetrator who wants to evade BFS continuation just emits
≤200 distinct outflows from the consolidation hub. The cap is OFF by 1
(`> 200` not `>= 200`), so exactly 200 is fine. 200 itself is far higher
than any documented "real perp" cap mentioned in the comment ("~30 per
hop") but lower than ANY actual unlabeled exchange (typically 500+ for
KuCoin / OKX deposit pools). A perp who sets up 199 throwaway destinations
turns off our BFS continuation on themselves.
**Should:** Combine the cap with a TIME-WINDOWED signal — "≥ N outflows
in ≤ T minutes" is service-wallet-like; "200 outflows over 2 weeks" is
not. AND lower the absolute cap to 50 since the legitimate perp pattern
is ≤ 30.
**Fix sketch:** New `is_service_wallet = (raw_count > 50)` AND (`elapsed_seconds < 3600 * 24`). Test that the 199-outflow adversary case becomes service-flagged.
**Jacob will find this on a sophisticated case.**

### HIGH-2 — Cross-chain destinations on chains not in the Chain enum are silently dropped after a WARN log
**Where:** `tracer.py:717-731`. Decoded destination_chain values like
`"oasis"`, `"klaytn"`, `"karura"` (real Wormhole destinations) hit
`Chain(decoded_chain_str)` → KeyError → log.warning + `continue`.
**Today:** The handoff is detected, surfaced in the brief candidate list,
but BFS does NOT continue. The brief reader sees "destination_chain: oasis"
without any continuation data. For these chains we have no adapter, but
the LE handoff section calls them "candidates" — they're not candidates,
they're DETECTED destinations.
**Should:** Surface the un-followed-due-to-no-adapter destinations in a
distinct brief section ("detected_but_unsupported_chain") so operators
know to manually pursue on the destination block explorer.
**Fix sketch:** Track `unsupported_chain_destinations` separately and pass
to the brief.
**Operator will notice** the first time a Wormhole-to-Oasis tx lands.

### HIGH-3 — `_apply_dust_attack_filter` confidence guard inverts on whale cases
**Where:** `src/recupero/trace/dust_attack.py:199` (`if len(dust_dests) < 2 * len(non_dust_dests): continue`).
**Today:** A perpetrator with one consolidation hub that legitimately fans
to 30 high-value destinations (post-laundering exit liquidity) AND
incidentally has 50 dust shower destinations gets the dust shower entirely
through the filter because `50 < 2 * 30 = 60`. The dust pollutes the brief.
Conversely: a small case where the dust shower is the ONLY thing happening
(10 dust to 10 distinct addrs, zero non-dust) trivially passes.
**Should:** Use the ABSOLUTE count of dust destinations (already gated by
`min_fanout=10`) and weight the ratio less heavily. A 50-dust 30-non-dust
shape IS a dust shower even if the perp also did legitimate moves.
**Fix sketch:** Drop the ratio guard; rely on `min_fanout=10` + the
sub-threshold USD filter. Or weight by USD (sum of dust dest USDs ≪ sum
of non-dust dest USDs is the real legitimacy signal).
**Adversary-tunable; Jacob will find it.**

### HIGH-4 — Solana adapter loses CPI / inner-instruction transfers
**Where:** `src/recupero/chains/solana/adapter.py:148-165` reads `nativeTransfers`
and `tokenTransfers` from Helius parsed-tx response. These are the
TOP-LEVEL transfers; CPI calls into other programs (the bread-and-butter
of Solana DeFi — Jupiter → Raydium → Orca chain) emit transfers inside
`innerInstructions` that the parsed-tx surface DOES include but our code
doesn't walk.
**Today:** A perp who routes USDC → Jupiter → Drift Protocol shows the
USDC transfer from the perp to Jupiter (which is a program account, gets
stopped by `is_contract`), and we miss the eventual USDC arrival at the
drift program-owned token account. Trace dead-ends at Jupiter.
**Should:** Walk `innerInstructions` for additional `nativeTransfers` /
`tokenTransfers` shapes, OR upgrade to Helius `enhancedTransactions`
endpoint which collapses CPI into top-level.
**Fix sketch:** ~30 lines added to `_fetch_all` to merge inner-instruction
transfers in.
**Jacob will find this on any Solana-DeFi-touching case.**

### HIGH-5 — Bridge calldata decoder confidence "medium" is silently rejected by BFS continuation
**Where:** `tracer.py:689` `if decoded_conf != "high" or not decoded_addr: continue`.
**Today:** Decoders return `medium` confidence when chain extraction
succeeded but address didn't (or vice versa). The brief surfaces these via
the handoffs section. But the BFS treats them identically to unknown —
no continuation. A `medium`-confidence dst chain + `high`-confidence dst
addr is identical to an unknown destination for trace purposes.
**Should:** Run the continuation when EITHER chain OR address is
high-confidence (with the missing piece reconstructed via candidate list,
or by querying the destination across all candidate chains for the
specific address).
**Fix sketch:** Tier the continuation: high → auto-pursue; medium → opt-in
via env var; with explicit log "BFS continuation skipped: medium-confidence
decode".

### HIGH-6 — `is_contract_cache` defaults to **True** on lookup failure (silent BFS truncation)
**Where:** `tracer.py:382-386`.
```
except Exception as e:
    ...
    is_contract_cache[dest_key] = True   # be conservative: skip
```
**Today:** Etherscan rate-limited mid-trace? Every destination address
checked during that rate-limit window gets cached as `is_contract = True`
for the rest of the trace, and `stop_at_contract` then prevents BFS
continuation. A flaky network event silently truncates the trace for
the rest of the case. The case file gives no indication this happened
(no `trace_status` mutation).
**Should:** Don't CACHE the failure verdict — re-probe on next encounter,
OR surface a per-case `contract_check_failures: int` counter that the
brief renders ("trace may be incomplete: 12 contract-check failures
during fetch").
**Fix sketch:** Use a sentinel `None` for "unknown" and don't cache;
re-probe on next encounter (the wave-aggregation step that uses this is
single-threaded so no race).

### HIGH-7 — `policies._BURN_OR_ZERO_ADDRESSES` misses 6 known sinks
**Where:** `policies.py:30-36`. Has 4 entries (`0x...0`, `0x...dead`,
`0x...4206942069`, Solana system program).
**Today:** Missing variants:
* `0x000000000000000000000000000000000000dEaD` (mixed case may already be
  caught via `.lower()`, but EIP-55 checksum form bypasses if a different
  hash construction happens — defensible).
* `0xFfFfFfffFFffFFFFFfFFfFFfffFffFfffffFfFFf` (uint160-max — used by some
  bridges as sentinel).
* Tron blackhole `T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb`.
* Bitcoin null-data outputs (`OP_RETURN` — already handled implicitly via
  "no scriptpubkey_address" branch).
* `0x000000000000000000000000000000000000ff` (a few drainer kits use this).
* `0x0000000000000000000000000000000000001111` (some testnet derivatives
  appear on mainnet from fake-airdrop spoofs).
**Should:** Expand the set; consider any address with ≥ 36 leading zeros
in hex form as burn-candidate (after EVM checksum normalization).
**Fix sketch:** New `_is_burn_or_zero_address` checks hex-prefix patterns
in addition to set lookup.
**LOW-impact functionally; HIGH-impact narrative-correctness when Jacob
sees "Trace continued at 0x...ff after burn-to-dead" in the brief.**

### HIGH-8 — EVM adapter `_WRAPPED_NATIVE_CONTRACTS` set is INCOMPLETE for L2s
**Where:** `chains/evm/adapter.py:205-213`. Has 7 entries.
**Today:** Missing canonical wrapped-native for: Linea (WETH at
`0xe5D7C2a44FfDDf6b295A15c148167daaAf5Cf34f`), Blast, Scroll, Mantle,
Fantom (WFTM at `0x21be370D5312f44cB42ce377BC9b8a0cEF1A4C83`), Celo
(CELO is native there, no wrap), Gnosis (WXDAI), Avalanche (WAVAX has
two addresses — older one missing). On these chains the wrap-deposit
filter doesn't fire, so every WETH-deposit on Linea is treated as a real
outflow and inflates `total_usd_out`.
**Should:** Pull the canonical wrapper from `EvmChainProfile` per chain
instead of a global frozenset.
**Fix sketch:** Add `wrapped_native_contract` field to `EvmChainProfile`
and use `(self.profile.wrapped_native_contract or "")` in the check.

### HIGH-9 — Clustering H2 (CEX withdrawal) window=1h is the TIGHTEST of any system
**Where:** `clustering.py:517` (`_CEX_WITHDRAWAL_WINDOW = timedelta(hours=1)`).
**Today:** Real perp pattern: stage one CEX withdrawal at T+0, second at T+15min
(works); but mid-laundering they often pause 2-6 hours between deposit and
the second wallet's withdrawal to avoid same-block clustering. 1h is too
tight for cases where the perp deliberately staggered.
**Should:** Default to 4h, with confidence tiering (high < 1h, medium 1-4h).
**Fix sketch:** Two thresholds + a confidence field on the cluster.

### HIGH-10 — `cex_continuity` requires same-token symbol match
**Where:** `cex_continuity.py:362`
`if row_token_symbol != deposit_token: continue`.
**Today:** Deposit USDT, withdraw USDC at parity (the most common CEX
re-emergence pattern) returns ZERO leads. Cross-token re-emergence —
which is THE point of using a CEX as an obfuscation layer — is silently
unsupported. The module's docstring at L329-332 acknowledges this gap
as "acceptable", but it's actually the dominant attack pattern.
**Should:** When `deposit_token` is USDT/USDC/DAI, expand the candidate
set to all stable-symbol matches AND compare on USD (using the deposit's
USD per dollar of stable as the conversion factor — ≈1.0 for stables).
**Operator will notice immediately** since the LE handoff section will be
empty for nearly every stablecoin laundering case.

### HIGH-11 — Cluster H1 (co-spending) only fires when the SAME txid appears via multiple seeds
**Where:** `clustering.py:670-696` — depends on the Bitcoin adapter
returning the same tx_hash from multiple BFS seeds in the same case.
**Today:** Because the Bitcoin adapter only emits transfers under the FIRST
input address (CRIT-1), the canonical co-spending heuristic (the strongest
clustering signal in all of blockchain forensics) almost never fires. The
brief shows "no clusters" on cases where co-spending would have identified
3-5 wallets immediately.
**Should:** Fix downstream from CRIT-1.
**Direct dependent of CRIT-1.**

### HIGH-12 — MEV builder list has 4 entries; industry tracks 12+
**Where:** `mev_detection.py:24-29`.
**Today:** 4 builders are listed (Flashbots, beaverbuild, Titan, rsync).
Missing: bobthebuilder, builder0x69, manta, lokibuilder, eigenphi, ETHbuilder,
boba_builder, plus several MEV-pool service addresses.
**Should:** Pull from a curated `mev_builders.json` seed file that operators
can update.
**Polish; Jacob may or may not notice (low cost to fix).**

### HIGH-13 — Brief MEV detection on the Zigha fixture surfaces exactly 4 signals; the assertion at `test_zigha_mev_signals_section_well_shaped:1108` PINS exact 4
**Where:** `tests/integration/test_trace_to_brief.py:1108`.
**Today:** Hard-pinned `assert mev["signal_count"] == 4` against a fixture
where the trigger is "common origin to 7 destinations including Tornado"
— but the detector at `mev_detection.py:139-167` is a SANDWICH detector.
A sandwich is "outer pair share from_address, middle is seed_addr" — none
of those conditions match the Zigha hub fan-out. Either:
* (a) The detector is firing on something OTHER than sandwich and the
  test author got the explanation wrong.
* (b) The test passes by coincidence and a future change to fixture
  asserts will flip it.
Either way the test pins a NUMBER without explaining the mechanism.
**Should:** Audit which heuristic fires; document. If `_detect_jit_lp` is
the actual source, the assertion should explain that. Otherwise the
detector may be returning false positives on legit fan-out.
**LIKELY false positive that we'll be reporting to Jacob with confidence
0.5**.

### HIGH-14 — Cross-chain handoff time `block_time_iso` parser silently falls back to incident_time
**Where:** `tracer.py:743-749`.
```python
try:
    src_iso = handoff.block_time_iso.replace("Z", "+00:00")
    src_block_time = datetime.fromisoformat(src_iso)
except (TypeError, ValueError, AttributeError):
    src_block_time = incident_time
```
**Today:** If a handoff's `block_time_iso` is malformed for any reason
(adapter returns empty string, future timezone format, etc.), the dst-chain
window filter uses `incident_time` instead — defeating the entire purpose
of the per-handoff time anchor (and tying back into CRIT-3).
**Should:** Skip the cross-chain seed entirely on parse failure with a
WARN log + surface in the brief.
**Fix sketch:** `if parse fails: log.warning + continue`.

---

## MED findings

### MED-1 — Self-transfer filter is in EVM adapter only
**Where:** `chains/evm/adapter.py:290`. Tron / Solana / Bitcoin adapters
have NO self-transfer filter (a perp who shuffles within their own wallet
emits transfers with `from == to`).
**Should:** Centralize self-transfer drop at the tracer level OR replicate
in each adapter.

### MED-2 — Burn-or-zero check is post-pricing
**Where:** `policies.py:155`. We price every transfer (Coingecko call!)
BEFORE we ask "is the destination a burn address." Burn destinations
should never be priced — wastes API budget.
**Should:** Move burn-check into `_trace_one_hop` before the pricing call.

### MED-3 — `policy.stop_at_contract` is applied at next-wave dest-check only
**Where:** `tracer.py:379-388`.
**Today:** A transfer FROM a contract address is included in the case
(good — that's the contract's outflow), but the contract-detection only
runs on `to_address`. Detecting contract sources matters when the perp
has deployed a custom proxy whose code is the laundering logic.
**Should:** Also mark transfers where `from_address` was a contract
as a separate category in the case (e.g., `Transfer.from_is_contract: bool`).

### MED-4 — `should_include` rejects unpriced transfers < 10 token units
**Where:** `policies.py:134-139`. Cutoff is 10 units of ANY token without
USD price. A 9.5-unit WETH transfer would be rejected — that's $25K of
real value.
**Should:** Couple the unit-floor to the token's typical decimals — a
6-decimal stable at 10 units is $10; an 18-decimal token at 10 units could
be $100K+. Use a separate threshold per known-decimals bucket.

### MED-5 — `_decode_symbiosis` is heuristic on nested calldata; 50% of mainnet payloads will miss
**Where:** `bridge_calldata.py:1670-1885`.
**Today:** The Symbiosis decoder explicitly scans a "small set of candidate
offsets" inside `otherSideCalldata`. Real Symbiosis payloads have
documented selector + arg layout — fully decodable, not heuristic. The
50/50 hit-rate the heuristic produces is fine for legacy fixtures but
WRONG for real cases — and we have NO way to tell when it false-positives
("found chainID 10 = Optimism!" when it was actually a `slippage` field
equal to 10 wei somewhere in the blob).
**Should:** Parse the nested selector + the documented
`metaMintSwap`/`burnSyntheticToken` ABI; abort with `confidence=low` if
no recognized inner selector.

### MED-6 — `_decode_1inch` returns `low` confidence with no destination, but is still emitted as a "bridge handoff"
**Where:** `bridge_calldata.py:1021-1052`.
**Today:** 1inch is primarily same-chain DEX aggregation — calling it a
"bridge" surfaces it in the cross-chain handoffs section of the brief,
which is wrong narrative. The decoder honestly returns low confidence /
no destination, but the brief section name implies "money crossed chains".
**Should:** Distinguish `bridge_protocol` vs `dex_aggregator` in the seed
file; same-chain aggregators get a different brief section.

### MED-7 — `_collect_unlabeled` does case-sensitive set keying for non-EVM
**Where:** `tracer.py:1266-1273`. Uses `t.to_address` raw — for Tron's
mixed-case base58 outputs from different paginations, the same address
could appear twice in `unlabeled_counterparties` if one path normalized
and another didn't.
**Should:** Use `_ck` canonical-key (already imported elsewhere).

### MED-8 — `_compute_exchange_endpoints` aggregation key normalization is correct but `_collect_unlabeled` is NOT (asymmetry)
**Where:** `tracer.py:1214-1262` correctly uses `canonical_address_key`
(L1223), but L1266-1273 doesn't.
**Should:** Same fix as MED-7.

### MED-9 — Indirect-exposure max_hops=3 means a 4-hop sanctioned origin is invisible
**Where:** `trace/indirect_exposure.py:109` (`_DEFAULT_MAX_HOPS = 3`).
**Today:** Same complaint as max_depth=4. A perp 4 hops from a Lazarus
address shows zero indirect exposure even though the funds are absolutely
attributable. Industry standard (Reactor) goes 5-7 hops with decay.
**Should:** Bump default to 5 with steeper decay (`0.4` instead of `0.5`).

### MED-10 — CoinJoin unwrap unwraps Wasabi 1.0 / Whirlpool but Wasabi 2.0 (WabiSabi) returns shape-only signal
**Where:** `trace/coinjoin_unwrap.py` (full file).
**Today:** This is OPENLY a limitation in the docstring (L18-24). Wasabi
2.0 = "no equal-output cluster", so the unwrap heuristic can't fire and
the trace dead-ends with "possible Wasabi 2.0 hop, no unwrap possible".
**Should:** Add a WabiSabi-coordinator anonymity-set lookup (off-chain
API), or surface the cluster-of-input-addresses with very-low confidence.
**Realistically: Jacob will accept this gap. Industry can't unwrap WabiSabi
either.** Listing as MED only because we should document the gap in the
brief footer explicitly.

### MED-11 — `_apply_dust_attack_filter` removes from `unlabeled_counterparties` but NOT from `exchange_endpoints`
**Where:** `tracer.py:1353-1356`.
**Today:** If a labeled CEX-deposit address received a dust shower from
another address in the case, it still shows up in `exchange_endpoints`
even though it's now flagged as dust-shower-victim. The brief renders the
endpoint without the dust flag.
**Should:** Filter both sections OR add a `dust_attack_destination: bool`
on every counterparty so downstream renderers can decide.

---

## LOW findings

### LOW-1 — `_looks_round` cluster heuristic caps at 1,000,000 token-units
**Where:** `trace/clustering.py:469-477`. A 2,000,000 USDT transfer
(realistic for the perp consolidation hub) isn't in the `round_set` so
H3 (direct self-fund) doesn't fire.
**Should:** Extend the set to 2.5M, 5M, 10M.

### LOW-2 — `_SHARED_INFRA_PARTNER_THRESHOLD = 5` is tight
**Where:** `clustering.py:130`. An address with 5 distinct interaction
partners is flagged as shared-infrastructure. That's *normal* for a
small perp wallet (sends to 5 destinations as part of laundering).
**Should:** Raise to 10; combine with USD-volume signal.

### LOW-3 — Hyperliquid scraper sets `Case.chain = Chain.ethereum` (per docstring) even though Chain.hyperliquid exists
**Where:** `chains/hyperliquid/scraper.py:50-53`. Now stale — `Chain.hyperliquid`
exists in the enum (v0.20.0). Setting chain=ethereum means downstream
brief/freeze pipelines mis-attribute Hyperliquid cases.
**Should:** Use `Chain.hyperliquid` and verify all downstream pipelines.

### LOW-4 — `_decode_axelar` accepts UTF-8 strings of arbitrary content for `destinationAddress`
**Where:** `bridge_calldata.py:1218-1220` accepts any string between
10-100 chars as an address. A malformed bridge transaction with garbage
in the address field is propagated through verbatim into the brief.
**Should:** Validate format-by-chain (Cosmos bech32 vs EVM 0xhex vs etc).

### LOW-5 — `_unwrap_coinjoin_to_transfers` emits synthetic transfers with `amount_raw = total / len(outputs)`
**Where:** `chains/bitcoin/adapter.py:504`.
**Today:** Confidence score makes it into metadata but the AMOUNT is
spread evenly, which is wrong for unequal-denomination CoinJoins (Wasabi
2.0 — but the unwrap doesn't fire on those anyway, so this is a Wasabi
1.0 / Whirlpool path where it IS roughly correct). Still, the synthetic
amount is a fiction.
**Should:** Mark the amount as `null` for synthetic-unwrap rows; downstream
USD math drops them via the existing unpriced-transfer path.

### LOW-6 — `_decode_stargate` only decodes `swap` (not `swapETH`) for the destination address path
**Where:** `bridge_calldata.py:794` (`if method_name == "swap"`).
**Today:** `swapETH` carries the same `to` bytes field but with shifted
offsets; the decoder doesn't attempt it. swapETH txs return
`confidence='medium'` (chain only).
**Should:** Add the `swapETH` layout (one less arg, slot offsets shifted
by 32 bytes).

---

## Categorization

### Blocks ship (must fix before next Jacob review):
* CRIT-1, CRIT-2, CRIT-3, CRIT-4, CRIT-5

### Jacob will find this:
* CRIT-6, HIGH-1, HIGH-2, HIGH-3, HIGH-4, HIGH-5, HIGH-9, HIGH-10, HIGH-11, HIGH-13

### Operator will notice:
* HIGH-6, HIGH-7, HIGH-8, HIGH-12, HIGH-14, MED-1, MED-3, MED-9, MED-10, MED-11

### Polish:
* All LOW; MED-2, MED-4, MED-5, MED-6, MED-7, MED-8

---

## Top 5 by forensic impact (= "what makes the trace lie to the analyst")

1. **CRIT-4 (drainer-detection gated off)** — every drainer-kit case has
   blank attribution. We're delivering "$3.6M was stolen by an unknown
   actor" when the answer is "by Inferno Drainer" and the evidence is
   sitting in the receipt logs we already fetch.
2. **CRIT-1 (Bitcoin multi-input collapse)** — co-spending heuristic
   doesn't work, BTC clustering surfaces zero useful entities, the
   trace silently under-reports outflows for any perp using > 1 UTXO.
3. **CRIT-2 (Tron native dropped)** — TRX-laundering cases (largest
   USDT laundering surface in crypto, per Chainalysis 2024) silently
   show no TRX activity.
4. **HIGH-4 (Solana CPI lost)** — any DeFi-routed Solana laundering
   path dead-ends at Jupiter/Raydium.
5. **CRIT-3 (cross-chain time anchor wrong)** — for any case where the
   bridge tx is > 6 hours after incident_time, the dst-chain window
   fetch is mis-aligned, BFS truncates with `max_transfers_per_address`
   filled by pre-bridge irrelevant rows.

---

## Honest one-paragraph: would this trace survive Chainalysis Reactor as ground truth?

**On a 0–100 scale: ~52.**

We win on the bridge-decoder breadth (13 protocols, real destination-address
extraction), point-in-time labels (we do this, Reactor does not), MEV bundle
detection at the protocol-aware level, and the determinism / reproducibility
contract (Reactor's output drifts between reads; ours is byte-identical 3×).
We lose hard on UTXO common-input collapse (Reactor walks all inputs; we
take the first), Tron native (we return `[]`; Reactor has full coverage),
Solana CPI / inner instructions (we walk top-level only; Reactor walks
the full instruction tree via Geyser plugin), approval-exploit drainer
attribution (gated `if False` in our code; the entire Reactor product
revolves around this for the wallet-drainer caseload), and trace depth
beyond 4 hops (we cap; Reactor defaults to 8 with adaptive decay).

The case we ship today will look reasonable for an EVM-only Zigha-shape
laundering through one bridge. It will look DEFICIENT against any
Bitcoin-heavy ransomware case, any Tron-USDT laundering case, any Solana
drainer case, and any approval-exploit drainer kit case (= ≥ 60% of incoming
volume in 2025–2026). The path from 52 to 75 is ~3 weeks of focused work
on CRIT-1 through CRIT-5. The path from 75 to 90 (matching Reactor on the
above) is months of work and is a viable v0.40 milestone — but should not
gate the v0.32 ship.

— end —
