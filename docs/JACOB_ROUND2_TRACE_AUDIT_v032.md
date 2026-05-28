# Round-2 trace audit — v0.32.1 (HEAD e0ce7d8)

Prepared 2026-05-28. Scope: re-audit trace pipeline AFTER v0.32.1 fixes.
This pass takes the round-1 findings (`docs/JACOB_TRACE_AUDIT_v032.md`,
6 CRIT + 14 HIGH, score 52/100) and verifies which actually landed, then
adds findings round-1 didn't see — primarily the **dangling-library**
problem with the new modules added in waves 1–2.

The bottom-line headline finding of round-2 is the dangling-library
problem: **8 new "trace gap" modules ship at HEAD but NONE are wired
into the BFS or brief renderer.** They have docstrings explicitly
saying `# TODO(wave-4-integration)` or "Trace integration is
intentionally NOT done here." The tests pass against them in isolation;
the production tracer never calls them. From an operator's brief
perspective the case looks identical to v0.32.0.

The second-most-important finding is **CRIT-NEW-1**: the v0.32.1
drainer-detector reopens the `if False`-gated branch (closing CRIT-4
on paper) but its detection algorithm reads `transfers_from.get(
contract_addr, [])` to find the drainer's outflow — and BFS still
`stop_at_contract=True` at the suspect contract, so the contract's
outflows are NOT in `case.transfers` in the first place. The signal
fires by ACCIDENT (when another seed in the case happens to have
visited the contract), not by DESIGN. For the typical single-seed
drainer case, the signal silently produces zero events.

---

## Summary by severity

| Severity | Count | Examples |
| --- | --- | --- |
| **CRIT**  | 3  | Drainer detector reads transfers that BFS prevented from existing; max-depth/contract-cache/JSON-safe fixes shipped as DANGLING libraries; Tron-bridge-extension JSON shape silently dropped by label loader |
| **HIGH**  | 7  | Bitcoin inputs_registry leaks across cases in worker; Synthetic-CoinJoin extra metadata silently stripped by Transfer model; HIGH-3/HIGH-1/HIGH-6/HIGH-7/HIGH-12 from round-1 unfixed despite new modules existing |
| **MED**   | 5  | drainer_findings_to_brief_section return type uses lowercase `any`; per-case-randomization secret defaults to constant in dev; multi-source-confirm dangling; etc. |
| **LOW**   | 3  | block_number defaults to 0 in Tron native (was 0 in TRC20 too); explorer_url ordering |

**Honest assessment**: the v0.32.1 commit description claims "close all
Tier-0 + Tier-1 pre-mortem gaps" — but on the trace surface the closures
are partial. **3 of 6 round-1 CRITs actually closed end-to-end** (CRIT-1
Bitcoin, CRIT-2 Tron TRX, CRIT-3 dst-anchor time, M-6 rollup-canonical
bridges). The other three (CRIT-4 drainer, CRIT-5 max_depth, CRIT-6
JSON sort_keys safety) are addressed in name only: a new module exists
on disk but production code paths don't import it.

---

## Round-1 closures verified

| Finding | Fix landed? | Fix complete? | Wire-up complete? | Notes |
|---|---|---|---|---|
| CRIT-1 Bitcoin multi-input | YES | YES | PARTIAL | adapter pro-rates ✓; `inputs_registry` populated ✓; clustering reads it ✓; `clear_for_case()` NOT called by tracer (leak across cases in long-running worker) |
| CRIT-2 Tron TRX | YES | YES | YES | `fetch_native_outflows` real, `_normalize_native_trx` filters TransferContract correctly |
| CRIT-3 dst-anchor time | YES | YES | YES | `tracer.py:858` uses `earliest_src_time_by_chain.get(dst_chain, incident_time)` |
| CRIT-4 drainer detection | PARTIAL | NO (see CRIT-NEW-1) | YES (in brief) | Branch un-gated; detection logic relies on transfers BFS won't enumerate |
| CRIT-5 max_depth | NO | NO | NO | `adaptive_depth.py` exists as DANGLING; `config.py:47` still `max_depth=4`; `# TODO(wave-4-integration)` in module docstring |
| CRIT-6 JSON tuple safety | NO | NO | NO | `as_json_safe` helper not added to `_common.py`; cross_chain.py:342 still hand-rolls `list(...)` per field |
| Adversary M-6 (rollup bridges) | YES | YES | YES | 5 decoders dispatched at `bridge_calldata.py:566-590`; tests verify keccak selectors |
| Adversary M-7 (Tron bridges) | PARTIAL | NO | NO | `bridges_tron_extension.json` exists but label_store globs all `*.json` and the file is shaped `{"entries": [...]}`, not a list — silently skipped by `store.py:172-180` |
| HIGH-10 CEX cross-token | YES | YES | YES | `cex_continuity.py:416-431` adds `parity_match` via `_are_at_parity` |

Per-CRIT detail follows.

### CRIT-1 (Bitcoin multi-input) — closed end-to-end

* **Adapter**: `src/recupero/chains/bitcoin/adapter.py:316-489`. Multi-input
  txs now emit one Transfer per send-output with `from=expected_from`
  and `amount_raw` pro-rated by input value share. Single-input case
  preserved byte-identically (`is_single_input_owner` short-circuit at
  L455-463).
* **Registry**: `src/recupero/chains/bitcoin/inputs_registry.py:56-77`
  records the full input-address set, thread-safe via a module-level
  `threading.Lock`.
* **Clustering**: `src/recupero/trace/clustering.py:666-696` reads the
  registry and constructs C(N,2) edges across the full input set.
* **Wire-up gap (HIGH-NEW)**: `clear_for_case()` exists in the registry
  (L90-98) but is **only called by tests**; the production `trace_case`
  entry point does NOT call it. The module's own docstring at L37-43
  acknowledges this: "*Currently called only by tests; the production
  tracer is owned by another agent for v0.32.1.*" In a long-running
  worker process the registry accumulates across cases — for the
  reported caseload of ~10k txs per case at 100s of cases per day the
  growth is bounded but the leak IS real and is one regression away
  from cross-case input bleed (a transfer in case B that touches a tx
  visited in case A would inherit case A's input set).

### CRIT-2 (Tron TRX) — closed

`src/recupero/chains/tron/adapter.py:173-230` (`fetch_native_outflows`)
and L470-588 (`_normalize_native_trx`). The implementation:

* Calls TronGrid `/v1/accounts/{addr}/transactions?only_from=true` with
  `min_timestamp` correctly converted to ms.
* Filters `raw_data.contract[0].type == "TransferContract"`, skips all
  TriggerSmartContract / FreezeBalanceContract / TransferAssetContract.
* Hex→base58 normalization of owner / to addresses via
  `normalize_tron_address`.
* Drops self-transfers (L536-537).
* Returns the normalized dict shape consumed by `_build_transfer`.

No NaN-propagation introduced; `block_number` defaults to 0 when
TronGrid omits it (LOW-1) but `block_time` is authoritative for window
math.

### CRIT-3 (dst-anchor time) — closed

`tracer.py:858` passes `dst_anchor_time = earliest_src_time_by_chain.get(
dst_chain, incident_time)` into `_process_wave(incident_time=
dst_anchor_time, ...)` for the cross-chain wave. The earlier `src_block_time`
parsing at L743-749 still falls back to `incident_time` on
`block_time_iso` parse failure — that's HIGH-14 from round-1, NOT
closed by this fix. So a malformed bridge tx timestamp still defeats
the dst-chain window.

### CRIT-4 (drainer detection) — partial closure with a hidden architectural gap

The hard-gated `if False` is REMOVED:
`src/recupero/trace/drainer_detection.py:235-433`. The new detection
algorithm:

1. Iterate `case.transfers` for victim→contract transfers.
2. For each, look up `transfers_from.get(contract_addr, [])` to find
   the contract's outbound transfer.
3. Require: same token, ≥80% of victim's amount, within
   `same_block_window_blocks=5`, no return flow to the victim.

**The hidden flaw** (CRIT-NEW-1 below): step 2 reads transfers that the
victim-seeded BFS NEVER ENUMERATED. The tracer at `tracer.py:379-388`
has `policy.stop_at_contract=True` (default), so when BFS reaches
the suspect contract it does NOT walk the contract's outflows. Those
outflows are missing from `case.transfers`, so `transfers_from[
contract_addr]` is the empty list. The detector loops through
`contract_outflows = []`, sets `forwarded_to = None`, and the
`if forwarded_to is None: continue` at L342 silently skips the
signal.

The signal can fire ONLY when:
* Another seed in the case (multi-seed cases via the dispatcher
  `additional_seeds` path) happened to visit the contract, OR
* `policy.stop_at_contract=False` (which is not the default).

For single-seed cases — the dominant shape — the closure is paper-only.

The brief consumer wire-up DOES work though:
`reports/emit_brief.py:1546-1550` calls `detect_drainer_pattern` +
`drainer_findings_to_brief_section`. The brief WILL surface the
attacker EOA correctly **when** a signal does fire. So the fix isn't
useless, it just rarely-fires.

### CRIT-5 (max_depth) — NOT closed

`src/recupero/trace/adaptive_depth.py` exists (160 LOC). The module
docstring at L15-17 says:
> `# TODO(wave-4-integration): wire ``compute_max_depth`` into
> trace.tracer entry point; pass case.theft_amount_usd and the
> rate-limiter budget state. Replace the hardcoded depth.`

Grep confirms: `adaptive_depth` / `compute_max_depth` is imported by
`tests/test_adaptive_depth.py` and **no other file**. `config.py:47`
still has `max_depth: int = 4`. The tracer's clamp at
`tracer.py:165-170` still uses `[1, 8]`. Operator-overrideable via
env, but no auto-adaptive logic.

### CRIT-6 (JSON tuple safety) — NOT closed

Grep for `as_json_safe`: zero hits in source (only in
`docs/JACOB_TRACE_AUDIT_v032.md:173` where the fix sketch was
documented). The brief renderer still hand-rolls
`list(handoff.destination_chain_candidates)` at
`trace/cross_chain.py:342`. No central serializer. The risk remains
latent: any new tuple field on `CrossChainHandoff` /
`IndirectPath` / a v0.32.2 dataclass will explode the next time a
new section is added without remembering to convert.

### Adversary M-6 (rollup canonical bridges) — closed

`src/recupero/trace/bridge_calldata.py:2348-2580` adds 5 decoders:
Polygon PoS, Optimism L1, Arbitrum L1, zkSync L1, Base L1. Dispatcher
at L550-590 matches `proto_compact` against the bridges.json `name`
field. The `bridges.json` seed (round-1 noted this) already labels
these bridges; the new decoders extract the destination address from
the appropriate calldata slot. `tests/test_bridge_calldata_canonical.py`
verifies every selector against `keccak256(signature)[:4]`.

Cross-chain BFS continuation at `tracer.py:714-750` consumes the
result correctly: when `decoded_chain_str` is e.g. `"polygon"` and the
extracted address is non-None and high-confidence, the cross-chain
seed is added.

**Subtle edge case (LOW-1 NEW)**: the `_extract_addr_slot` helper
checks `if hex_addr == "0" * 40` to reject zero addresses. This catches
the zero address but NOT a sentinel like `0x...000000000000000000ff`
that some drainer kits use. The `_BURN_OR_ZERO_ADDRESSES` set in
`policies.py:30-36` still has only 4 entries (HIGH-7 from round-1, NOT
fixed). New `burn_sinks.py` module has 11 entries but is dangling.

### Adversary M-7 (Tron bridges) — claimed-but-not-loaded

`src/recupero/labels/seeds/bridges_tron_extension.json` contains 5
Tron-side canonical bridges. **BUG**: the file is shaped as a dict
`{"__schema_note__": ..., "__merge_target__": ..., "entries": [...]}`,
not a flat list. `labels/store.py:164-180` globs all `*.json` in the
seeds directory and at `:172-180` runs:

```python
if not isinstance(data, list):
    log.debug("skipping non-array seed file %s ...")
    return
```

So `bridges_tron_extension.json` is silently dropped at load time. The
bridges are NOT in the label store; the Tron-coverage gap from
round-1's adversary Route 2 remains open. The file's own
`_audit_status` field at L21 says "needs Tronscan / JUST Foundation
docs re-verification before merge into bridges.json", but until
either (a) it's restructured into a flat list, or (b) a loader is
extended to handle the dict shape with `__merge_target__` resolution,
the extension is non-functional.

---

## New findings introduced by v0.32.1 or missed by round-1

### CRIT-NEW-1 — drainer-pattern detector cannot fire on victim-seeded BFS due to `stop_at_contract`

* **Where**: `src/recupero/trace/drainer_detection.py:285-343`. The
  detector iterates `case.transfers` for victim→contract transfers,
  then looks up `transfers_from.get(contract_addr, [])` to find the
  drainer's outflow. But `policy.stop_at_contract=True` (default,
  `policies.py`) is enforced in `tracer.py:379-388`, so the BFS NEVER
  walks the contract's outflows. `transfers_from[contract_addr]` is
  the empty list for the contract the victim sent to.
* **Today**: The `if forwarded_to is None: continue` at L342 fires for
  every victim→unknown-contract transfer. `findings.events` stays
  empty. Signal 2 silently produces zero output for single-seed
  drainer cases (= the dominant shape).
* **Should**: Either (a) explicitly fetch the drainer contract's
  outbound transfers in a bounded window when a victim→unknown-contract
  edge is detected (one extra Etherscan call per candidate); or (b)
  for non-labeled `to_address` that's a contract, lift
  `stop_at_contract` for ONE hop to capture the forward; or (c)
  thread an `approval_events: list[ApprovalEvent]` collection into
  the case shape (already declared at L83-114 as a dataclass, but
  never populated) and detect the drainer via the
  `approve(...,maxUint256)` log directly.
* **Fix sketch**: Wire option (a) — when signal-2 sees a
  victim→unknown-contract transfer, call `adapter.fetch_native_outflows(
  contract_addr, start_block=victim_tx.block_number)` /
  `fetch_erc20_outflows(...)` with a hop-budget limit. This is ~20
  LOC inside `detect_drainer_pattern`.

**Blocks ship for drainer-kit cases.** Round-1 said CRIT-4 was a
"blocks ship" finding; v0.32.1 closed the `if False` gate but the
new detection algorithm doesn't actually find anything in the
typical case shape.

### CRIT-NEW-2 — `adaptive_depth.py`, `contract_detection.py`, `wrap_unwrap.py`, `nft_transfers.py`, `erc4337.py`, `burn_sinks.py`, `mev_builders.py`, `safe_ownership_detector.py`, `per_case_randomization.py`, `multi_source_confirm.py` ALL dangling

* **Where**:
  - `src/recupero/trace/adaptive_depth.py` (docstring L15-17 `# TODO(wave-4-integration)`)
  - `src/recupero/trace/contract_detection.py` (docstring L26-29 same)
  - `src/recupero/trace/wrap_unwrap.py` (docstring L14-16 same)
  - `src/recupero/trace/nft_transfers.py` (docstring L18-20 same)
  - `src/recupero/trace/erc4337.py`
  - `src/recupero/trace/burn_sinks.py` (docstring L20-22 same)
  - `src/recupero/trace/mev_builders.py` (docstring L19-21 same)
  - `src/recupero/trace/safe_ownership_detector.py` (docstring L21-24
    "Trace integration is intentionally NOT done here")
  - `src/recupero/security/per_case_randomization.py`
  - `src/recupero/labels/multi_source_confirm.py`
* **Today**: `grep -r "from recupero.trace.adaptive_depth"` / `import
  adaptive_depth` returns ONLY the module file itself + its test.
  Same pattern for all 10 modules. Each module has comprehensive
  tests (`tests/test_*.py`), each test passes in isolation, but **the
  production tracer never imports them.**
* **Impact**: From the operator's brief perspective the case looks
  identical to v0.32.0. Round-1 CRIT-5 (max_depth) round-1 HIGH-6
  (contract cache poisoning) round-1 HIGH-7 (burn sinks) round-1
  HIGH-12 (MEV builder list) adversary M-2 (Safe ownership) adversary
  M-5 (per-case randomization) adversary M-1 (multi-source confirm)
  are all still open at the integration layer.
* **Fix sketch**: For each module, either (a) wire into the production
  call-path with the `# TODO(wave-4-integration)` removed, OR (b)
  delete the file and reopen the round-1 finding. The current state —
  shipping the file plus passing tests — creates false confidence
  that the gap is closed.
* **Why round-1 didn't catch this**: round-1 was an audit of v0.32.0;
  these modules were added in v0.32.1 wave-2 (commit `9fb4742`). The
  wave-2 commit description claims "close all Tier-0 + Tier-1
  pre-mortem gaps" — the modules exist but the closures are paper-only.

### CRIT-NEW-3 — Bitcoin synthetic-CoinJoin `_synthetic_coinjoin_unwrap` metadata silently stripped at `_build_transfer`

* **Where**: `src/recupero/chains/bitcoin/adapter.py:572-589` emits
  Transfer-shaped dicts with `_synthetic_coinjoin_unwrap`,
  `_unwrap_confidence_score`, `_unwrap_rationale` keys.
  `tracer.py:1190-1226` (`_build_transfer`) reads only explicit keys
  via `raw["..."]` — the synthetic flags are dropped on the floor.
  The `Transfer` model has `extra="forbid"` so they couldn't be
  passed through anyway.
* **Today**: The brief's CoinJoin-unwrap rows are indistinguishable
  from real on-chain transfers. An operator reading the brief sees
  `peer_addr` receiving funds from the victim with the same trust
  level as a directly-observed transfer. Per the round-1 finding
  LOW-5 these synthetic amounts are `total / len(outputs)` — a
  fiction — but downstream the brief cannot mark them as such.
* **Should**: Either (a) add a `provenance: Literal["onchain",
  "synthetic_coinjoin_unwrap"]` field to `Transfer`; or (b) thread
  the unwrap hypotheses through a separate `case.coinjoin_unwraps`
  collection (parallel to `case.transfers`) so the brief can render
  them with a "PROBABILISTIC — confidence 0.4" badge.
* **Fix sketch**: Option (a) — add `provenance` to the Transfer model
  (touches `models.py` + every adapter's normalizer for backward
  compat). Option (b) is non-disruptive but disrupts the unified
  case.transfers iterator.

### HIGH-NEW-1 — Bitcoin `inputs_registry` not cleared between cases in production tracer

* **Where**: `src/recupero/chains/bitcoin/inputs_registry.py:39-43`
  and the module's `clear_for_case()` at L90-98.
* **Today**: The registry is module-level and `_BTC_INPUTS_BY_TX`
  accumulates across cases. The docstring acknowledges this and
  defers the fix: "*the production tracer is owned by another agent
  for v0.32.1*." A new transfer in case B touching a tx_hash that
  case A also touched would inherit case A's input set.
* **Should**: Wire `inputs_registry.clear_for_case()` at the entry
  point of `trace.trace_case()` so per-case isolation is enforced.
* **Fix sketch**: One line at the top of `trace_case`.
* **Why round-1 didn't catch**: registry didn't exist in v0.32.0.

### HIGH-NEW-2 — `cex_continuity` parity_match correctness — `deposit_amount_decimal == row_amount_decimal` is required but parity tokens can have different decimals

* **Where**: `src/recupero/trace/cex_continuity.py:443-470`. The USD
  approximation is `(row_amount_decimal / deposit_amount_decimal) *
  deposit_usd`. For USDT (6 decimals) → DAI (18 decimals) at parity
  (~$1 each), the row_amount_decimal of $100k DAI is `100000.0`
  (post-decimals conversion) and the deposit's USDT amount is
  `100000.0` too — so the ratio is 1.0. **This actually works** for
  pure stable-to-stable, but for ETH ↔ stETH (1:1 economically but
  with rebase-induced drift of <1%) the ratio shows e.g. 1.002 and
  the USD math is approximately right.
* **Today**: For BTC ↔ WBTC (both 8 decimals on EVM but BTC is on
  Bitcoin where the comparison wouldn't be invoked anyway —
  cex_continuity is EVM-only) the parity group works. For ETH (18
  dec) ↔ stETH (18 dec) ↔ wstETH (18 dec) the parity group accepts
  them but wstETH/stETH ratio is ~1.05 (rebase factor), so a $100k
  ETH deposit comparing against $100k of wstETH (which is
  ~95k-95.5k stETH worth) would mis-match on the amount-tolerance
  check (default ±10%). The implementation may silently drop valid
  leads for the ETH-staked-derivative pair.
* **Should**: When parity_match fires, use a per-parity-group
  conversion factor instead of raw amount ratio.
* **Fix sketch**: A small `_parity_factor(deposit_symbol, row_symbol)`
  table mapping ETH→stETH = 1.0, ETH→wstETH = 1.04 (approximate Dec
  2025 rate), etc. Acceptable to leave the default 1.0 and emit
  with `confidence="medium"` per the existing parity flag.

### HIGH-NEW-3 — `drainer_findings_to_brief_section` declares return type `dict[str, any]` (lowercase `any` = built-in `any()` function, not `typing.Any`)

* **Where**: `src/recupero/trace/drainer_detection.py:457-494`.
* **Today**: At runtime annotations are not enforced; the dict is
  returned correctly. But: (a) static type-checkers (mypy/pyright)
  will flag this as a type error or silently treat `any` as the
  function reference type; (b) any tool that introspects via
  `typing.get_type_hints` will misinterpret. A grep across the
  codebase for similar lowercase `any` mistakes would be worth
  doing.
* **Should**: Replace with `dict[str, Any]` and import `from typing
  import Any`.
* **Fix sketch**: One-line change.

### HIGH-NEW-4 — `_decode_op_stack_l1` (HEAD version, before in-flight diff) silently returns ethereum dest for `withdrawTo` selector that's NOT in `_OP_STACK_METHODS` at HEAD

At HEAD `e0ce7d8`, the `_OP_STACK_METHODS` dict (`bridge_calldata.py:2393-2409`)
contains the 4 deposit selectors. `withdrawTo` is in the table at HEAD
(`"0xa3a79548": ("withdrawTo", 1)` at L2408). The chain override for
`withdrawTo` → `"ethereum"` is correctly applied at L2434-2435. **No
bug at HEAD**; calling this out because the in-flight diff (not at
HEAD) modifies this exact area, and reviewers tracing the diff might
see the comment block change and assume a regression.

### HIGH-NEW-5 — `_extract_addr_slot` rejects only the all-zeros address, not other burn sentinels

* **Where**: `bridge_calldata.py:2358` `if hex_addr == "0" * 40`.
* **Today**: An adversary controlling a bridge-decoder evasion can
  set the destination address to `0x...000000000000000000ff` or
  `0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead` and the decoder
  returns it as a valid 0x-form address. Downstream BFS then
  treats this as a real destination — but the funds are economically
  burned. The brief renders "destination: 0x...dead" with no
  burn flag.
* **Should**: After extracting the slot, run it through
  `policies._is_burn_or_zero_address` and reject as
  `destination_address=None` with `confidence="medium"`.
* **Fix sketch**: One import + one check at L2360.

### HIGH-NEW-6 — `cex_continuity` `_DEFAULT_NOISY_TOKENS` still excludes USDT/USDC/DAI (adversary audit Route 1 step 6 unmitigated)

* **Where**: `src/recupero/trace/cex_continuity.py` `_DEFAULT_NOISY_TOKENS`
  at the module top.
* **Today**: The HIGH-10 close-out added parity_match for cross-token
  re-emergence — but the noisy-tokens exclusion still drops the most
  common stable-token off-ramp shape. The parity_match logic helps
  WITHIN the matching pass; the noisy-tokens filter runs BEFORE it.
* **Should**: Either (a) lift USDT/USDC/DAI from the noisy list and
  rely on tighter amount-match + window thresholds; or (b) make the
  noisy filter chain-conditional — USDT is noisy on Ethereum (where
  Tether is the most common DeFi unit-of-account) but is the entire
  point of the trace on Tron.
* **Fix sketch**: Chain-conditional `_NOISY_TOKENS_BY_CHAIN` table.

### HIGH-NEW-7 — `per_case_randomization` dev-fallback secret is a constant string

* **Where**: `src/recupero/security/per_case_randomization.py:65`
  `_DEV_FALLBACK_SECRET = "DEV_FALLBACK_NOT_FOR_PRODUCTION"`.
* **Today**: Module is dangling (CRIT-NEW-2), so this is moot for
  now. But if/when wired: a dev deploy that forgets to set
  `RECUPERO_RANDOMIZATION_SECRET` falls back to a constant — meaning
  the "per-case randomized threshold" is universally predictable.
  An adversary reading the code knows this constant and can predict
  every threshold for any case run against an unset-secret deploy.
  The module logs a WARN once per process, but in containerized
  envs (Railway/Render) that log line is buried in 30k other
  startup lines.
* **Should**: Make absence of the env var a hard startup failure in
  production mode (`RECUPERO_ENV=production`). Already-present
  `require_*_configured()` patterns in `_common.py` set the precedent.
* **Fix sketch**: At module load when `RECUPERO_ENV == "production"`
  and `RECUPERO_RANDOMIZATION_SECRET` unset, raise `RuntimeError`.

### MED-NEW-1 — drainer detector's `transfers_from` / `transfers_to` indexes use canonical-key lowering for keys but iterate `case.transfers` linearly per outer loop

* **Where**: `drainer_detection.py:275-283`.
* **Today**: Functional. O(N) build, O(N) outer loop. For N=10k
  transfers (large case) this is 100M dict lookups — fine but not
  great. Not a correctness issue.
* **Should**: No change required for ship.

### MED-NEW-2 — `bridge_calldata.decode_bridge_calldata` `proto_compact` matching is substring-based, so a bridge named `"My Polygon Inc"` would match Polygon PoS

* **Where**: `bridge_calldata.py:566-590`. Matches `"polygon" in
  proto_compact and "pos" in proto_compact`. A malicious or
  mis-labeled `bridges.json` entry called `"polygon pos-fake"` would
  invoke the polygon decoder on arbitrary calldata.
* **Today**: bridges.json is operator-curated, so this requires
  insider attack or a successful auto-ingest poisoning (which round-1's
  Adversary audit covered as P1-P4). Defense in depth would tighten
  this to whitelist match.
* **Should**: Replace substring match with exact-name lookup against
  a curated map.
* **Fix sketch**: A `_PROTO_TO_DECODER` dict; the dispatcher falls
  through to "no decoder" on miss.

### MED-NEW-3 — `nft_transfers.NFTTransfer.token_id` is `str`, but ERC-1155 batches with token_id > 2^256 are silently truncated by `int()`

* **Where**: `src/recupero/trace/nft_transfers.py:45` declares
  `token_id: str` (correct for storage). The implementation that
  parses provider responses (later in the file) coerces via
  `_to_int` then back to `str` — but `_to_int` returns Python int
  which has unbounded precision, so the round-trip preserves the
  value. **No correctness bug, but** the `_to_int` helper at L58-76
  returns `None` on parse failure and downstream code at line ~150
  may not handle the None correctly. Will verify when module is
  wired — currently dangling so moot.

### MED-NEW-4 — `safe_ownership_detector` exposes 4 selectors but `_decode_polygon_pos` and other M-6 decoders don't proactively reject calldata that's actually a Safe `execTransaction` wrapper

* **Where**: `bridge_calldata.py` rollup-canonical decoders.
* **Today**: A Safe wallet calling a rollup bridge via `execTransaction`
  wraps the underlying calldata. The dispatcher sees the Safe's
  selector (`execTransaction = 0x6a761202`), doesn't match any
  bridge_protocol pattern, returns None. **No bug** — the Safe call
  ISN'T mistakenly attributed to a bridge — but the rollup-canonical
  decoder also can't pierce the Safe wrapper to see the inner bridge
  call. Adversary Route 1 Hop 2 (Safe ownership change) + Hop 3
  (Safe-wrapped Polygon PoS deposit) both succeed: ownership change
  is undetected (CRIT-NEW-2), and the bridge call is wrapped in a
  Safe `execTransaction` so the rollup decoder doesn't see the
  payload.
* **Should**: Either (a) the M-6 decoders need a `_decode_safe_wrapped`
  preprocessing pass that unwraps `execTransaction(to, value,
  data, ...)` to extract the inner calldata; or (b) accept the gap
  and document.
* **Fix sketch**: Option (a) is ~30 LOC of calldata unwrapping. The
  Safe ABI is stable.

### MED-NEW-5 — `cex_continuity` runs all CEX hot wallet outflow fetches per case but doesn't share between CEX continuity, BFS proper, and CEX endpoint computation — triple-counted RPC budget

* **Where**: `cex_continuity.py:355-378`. `fetch_native_outflows` and
  `fetch_erc20_outflows` are called per CEX hot wallet found in
  case.transfers. The BFS-proper also calls these against the same
  addresses during its primary wave. No shared cache.
* **Today**: For a case touching 10 CEX hot wallets the same RPC
  endpoint is hit ~30 times for outflows that BFS already cached.
* **Should**: Cache fetches by `(adapter, addr, start_block)` for the
  case lifetime.

### LOW-NEW-1 — Tron `_normalize_native_trx` sets `block_number=0` when TronGrid omits it

* **Where**: `chains/tron/adapter.py:563-567`.
* **Today**: Comparisons by block_number in clustering / dust-attack
  detector treat 0 as "earliest" — so a Tron native outflow with
  unknown block_number would sort to the case start. The block_time
  is preserved.
* **Should**: Either fetch the block by ts (one extra RPC), or carry
  a sentinel `block_number=None` (which downstream consumers must
  handle). Current impact is cosmetic on Tron-native cases.

### LOW-NEW-2 — `bridge_calldata.py` rollup-canonical decoders return `confidence="medium"` when address slot is missing, but `tracer.py:689` requires `confidence != "high"` to bail

* **Where**: `tracer.py:689` `if decoded_conf != "high" or not decoded_addr: continue`.
* **Today**: A Polygon PoS `depositEtherFor(user)` decode with the
  user address successfully extracted returns `confidence="high"` —
  good. A `depositERC20()` Optimism call returns `confidence="medium"`
  with destination_address=None (because the recipient is
  `msg.sender`, not in calldata). The tracer at L689 silently
  skips it as "no continuation". This is the round-1 HIGH-5 finding,
  reopened by the M-6 closure widening the medium-confidence
  surface area. Now a sizeable fraction of Optimism/Base/Arbitrum
  `depositETH`/`depositERC20` (msg.sender = recipient) calls
  emit medium-confidence with no continuation. The brief renders
  "destination chain candidate: optimism" with no concrete
  destination, identical to v0.32.0.
* **Should**: For these `msg.sender`-recipient cases, pull
  the transaction's `from_address` as the destination (it's the
  same address that called the bridge — the bridge then mints L2
  tokens to that same address by design). The tracer
  already has the source-chain tx's from_address available.
* **Fix sketch**: At `tracer.py:714-750`, when `decoded_chain_str
  and not decoded_addr and decoded_conf == "medium"` and
  `bridge_method` is one of the msg.sender variants, use
  `handoff.source_tx_from_address` as the dst address.

### LOW-NEW-3 — `_BURN_OR_ZERO_ADDRESSES` in `policies.py` still has 4 entries despite `burn_sinks.py` shipping with 11

* This is round-1 HIGH-7 unchanged. New `burn_sinks.py` module has
  a richer set but is dangling.

---

## Score: 64/100 (round-1: 52/100; target ≥ 90)

The 12-point bump reflects:

* +6 for the 3 CRITs that ACTUALLY closed end-to-end (CRIT-1 Bitcoin,
  CRIT-2 Tron TRX, CRIT-3 dst-anchor time) and the adversary M-6
  rollup-canonical bridges, all of which materially improve trace
  fidelity against the round-1 attack scenarios.
* +4 for HIGH-10 cross-token CEX continuity parity_match, which is
  the single most-impactful HIGH from round-1 (Route 1 off-ramp
  evasion).
* +2 for the new modules shipping with comprehensive tests even
  though dangling — the algorithms are right, the wire-up is just
  pending.

The 26-point gap to 90 reflects:

* -8 for CRIT-NEW-1 (drainer detector unable to fire due to
  stop_at_contract). This is the equivalent of round-1 CRIT-4
  reopening with a different mechanism. Until fixed, drainer-kit
  cases (60%+ of incoming volume per round-1) still ship with
  blank attribution.
* -6 for CRIT-NEW-2 (10 modules dangling). Each is a paper-closed
  finding from round-1 (CRIT-5, HIGH-6, HIGH-7, HIGH-12) or adversary
  audit (M-1, M-2, M-5) that the v0.32.1 release notes claim closed.
* -4 for CRIT-NEW-3 (Bitcoin synthetic CoinJoin metadata silently
  stripped). Brief renders fictional amounts indistinguishably from
  real ones.
* -4 for HIGH-NEW-1 (inputs_registry leak), HIGH-NEW-3 (lowercase
  `any` typo), HIGH-NEW-5 (extract_addr_slot accepts dead-address
  sentinels), HIGH-NEW-6 (CEX cross-token noisy filter still drops
  USDT).
* -4 for MED-NEW-4 (Safe-wrapped bridge call invisible — round-1
  adversary Route 1 Hop 2+3 still works).

### What it would take to reach 90

1. **Close CRIT-NEW-1** (drainer detector): one of the three
   sketched options. ~1 week.
2. **Wire all 10 dangling modules** OR remove them and reopen the
   round-1 findings. ~2 weeks for full wire-up.
3. **Close CRIT-NEW-3** (synthetic CoinJoin provenance): add
   `provenance` field to Transfer model; threads through models +
   adapters + brief. ~3 days.
4. **Close HIGH-NEW-1** (inputs_registry per-case clear): 1 line in
   tracer.
5. **Close HIGH-NEW-3** (`dict[str, any]` typo): 1 line.
6. **Close HIGH-NEW-5** (burn-sentinel reject in `_extract_addr_slot`):
   import + 1 check.
7. **Close HIGH-NEW-6** (chain-conditional noisy tokens): ~30 LOC
   + tests.
8. **Close MED-NEW-4** (Safe-wrapped bridge): ~30 LOC for execTransaction
   unwrap + tests.

After those 8 fixes the trace pipeline score is ~88. The remaining
gap to 90 is the legitimate v0.40 milestone (Solana CPI traversal,
WabiSabi unwrap, Cosmos/IBC) called out in round-1's honest
assessment.

### What MUST be fixed before next ship

1. CRIT-NEW-1 (drainer detector can't fire).
2. CRIT-NEW-3 (synthetic CoinJoin metadata stripped — actively
   misleading the operator).
3. HIGH-NEW-1 (inputs_registry leak — Jacob WILL find this if a
   long-running worker hits the same tx_hash across two cases).
4. The dangling modules either get wired OR the v0.32.1 release
   notes get corrected to stop claiming the closures. Shipping with
   the current language ("close all Tier-0 + Tier-1 pre-mortem
   gaps") is the kind of overclaim that makes Jacob give up on the
   process.

— end of round-2 audit —
