# Trace coverage diagnosis: Zigha v0.27.1

For the call with Jacob. Diagnosis of his three hypotheses on why the
worker found 1 of 7 known Zigha destinations.

## TL;DR

**Hypothesis (1) — bridge-following — is the dominant root cause and
it's a stacked three-blocker failure**, any one of which alone is
sufficient to explain why the Arbitrum→Ethereum dormant DAI is
invisible to the worker:

1. **Seed gap.** `src/recupero/labels/seeds/bridges.json` has 31
   bridge contracts, of which exactly **1** is on the Arbitrum side
   (Hyperliquid). Zero entries for DeBridge / 1inch / Stargate /
   Wormhole / Across / LayerZero on Arbitrum.
2. **Decoder gap.** `src/recupero/trace/bridge_calldata.py` decodes
   Wormhole, Across, and Stargate calldata. No decoder for DeBridge
   (DLN order format), 1inch, LayerZero, Hop, Synapse, LiFi.
3. **Feature gate off-by-default.** Cross-chain BFS continuation
   requires `RECUPERO_CROSS_CHAIN_CONTINUATION=1` env var in
   `tracer.py:479-481`. Default is OFF.

Hypothesis (2) — dormancy-EOA bias — is **secondary**. The dormant
detector finds balances at addresses the BFS visited; the BFS just
never visited the Ethereum-side addresses because of blocker (1).

Hypothesis (3) — hop limit / token coverage — is **not the cause**.
The BFS reaches `0xF4bE…FAD2` (Arbitrum-side consolidation hub) on
Zigha; it just can't see across the bridge from there.

## Evidence

### Blocker (1): seed gap

```python
# audit of bridges.json
$ python -c "
import json
data = json.load(open('src/recupero/labels/seeds/bridges.json'))
bridges = data if isinstance(data, list) else data.get('bridges', data)
print('arbitrum-side:', sum(1 for b in bridges if b.get('chain') == 'arbitrum'))
print('ethereum-side:', sum(1 for b in bridges if b.get('chain') == 'ethereum'))
print('total:', len(bridges))
"
arbitrum-side: 1
ethereum-side: 0
total: 31
```

The single Arbitrum entry is the Hyperliquid Bridge2 contract. Every
other bridge in the seed file is on a chain we already trace well
(BSC, Polygon, Avalanche). The bridges Zigha actually used on Arbitrum
— DeBridge gate, 1inch aggregator — are not present, so when
`identify_cross_chain_handoffs` scans Zigha's case for transfers to a
known bridge contract on Arbitrum, it finds zero. The
`CrossChainHandoff` list is empty. No continuation seeds are added.
End of trace.

### Blocker (2): decoder gap

```bash
$ grep -E "deBridge|debridge|DLN|1inch|stargate|wormhole|across|orbiter|layerzero" src/recupero/trace/bridge_calldata.py
# only Wormhole / Across / Stargate decoders exist
```

Even if we add the Arbitrum-side DeBridge gate to bridges.json, the
calldata decoder dispatch (`bridge_calldata.py:205-210`) has no
`deBridge` branch. `decode_bridge_calldata(...)` returns `None` /
`confidence != "high"`. The tracer's continuation path
(`tracer.py:496`) short-circuits:

```python
if decoded_conf != "high" or not decoded_addr:
    continue   # ← Zigha lands here
```

Result: the handoff is detected but no cross-chain seed is added.
Same end state as blocker (1).

### Blocker (3): feature gate

```python
# tracer.py:479-481
cross_chain_continue = os.environ.get(
    "RECUPERO_CROSS_CHAIN_CONTINUATION", "",
).strip().lower() in ("1", "true", "yes", "on")
```

This is intentional — the cross-chain BFS adds an entire second
chain's adapter calls (per `cross_chain_seeds`), which can be
expensive. The env var is the safety valve. But unless the production
worker has `RECUPERO_CROSS_CHAIN_CONTINUATION=1` in its Railway env,
the cross-chain branch never fires, even with a perfectly-decoded
handoff. Worth verifying: is this set in prod today?

### Why the dominant cause is bridge-following

The Zigha narrative from your triage:

> Hyperliquid → Arbitrum (consolidation on 0xf4be227b...fad2) →
> DeBridge / 1inch → Ethereum (dormant DAI at 0x3daFC6…, 0x415D8D…,
> 0x26D20f…)

The worker DID find the Arbitrum-side hub (`0xF4bE…FAD2`), which
matches your triage. It just couldn't see the bridge hop, so the three
Ethereum-side dormant DAI addresses are unreachable. The pattern is
"trace stops at a bridge contract on Arbitrum," not "trace fails to
recognize dormant EOAs on Ethereum" (it would recognize them just
fine if the BFS got there).

### Why hypothesis (2) is secondary

Dormancy-EOA detection works like this:

1. BFS visits an address X.
2. After BFS terminates, `dormant_finder.find_dormant_candidates`
   queries the on-chain balance of every visited address.
3. If X has a balance > $1K and hasn't moved in N days, it's flagged
   dormant.

So the bias is correct: the BFS follows flow, the dormant detector
finds residual balances at addresses the BFS visited. If the BFS
visits an Ethereum-side dormant address, the detector will find it.
The Zigha problem is that the BFS never crosses the bridge, so it
never visits the Ethereum dormant addresses.

If we fixed (1) + (2) and got the BFS across the bridge to the Ethereum
side, the dormant detector would find all three dormant DAI addresses
on its first pass.

### Why hypothesis (3) is not the cause

The default hop budget is 4 (per `policies.py` defaults). The Zigha
flow is 2 hops on Arbitrum to reach the consolidation hub. The hub
shows up in the worker output as TRANSIT — which is the BFS visiting
it and then NOT recursing further. That's not a hop-budget failure;
it's the cross-chain blocker described above.

DAI is in the default token coverage set (it's the most-trafficked
stablecoin on Ethereum). Not a token-filter issue either.

## Recommended fix path

This is a v0.28 scope (or later), not v0.27.2. Order matters because
each step alone is insufficient — the fix needs all three:

### Step 2.1: Seed bridges.json with Arbitrum-side coverage
Lowest-risk, highest-coverage win. Add the canonical contracts for:

- DeBridge: `0x...` (DLN Source on Arbitrum, `0x...` on Ethereum/Base/Optimism/Polygon)
- 1inch Fusion+: their bridge router on each L2
- Stargate (already in seed on Ethereum/BSC — add Arbitrum/Optimism/Base)
- Wormhole Token Bridge on Arbitrum/Optimism/Base
- Across V3 SpokePool on Arbitrum/Optimism/Base/Polygon
- Hop / Synapse / Orbiter / LiFi — best-effort

~25-40 new entries. Reuses existing schema. No code change beyond the
seed file. Could be a 1-2 day task with a Chainalysis or Dune query
to gather verified bridge contract addresses.

### Step 2.2: Add DeBridge calldata decoder

The DLN order format is documented:
https://docs.debridge.finance/. `createOrder` event carries the order
hash; the destination chain ID + receiver address are in the event
log. Implementable as a `_decode_debridge_dln_source` function in
`bridge_calldata.py` following the existing `_decode_wormhole` /
`_decode_across` pattern.

~half-day per protocol. Priority order: DeBridge first (Zigha
unblocker), then 1inch / LayerZero / Hop / Synapse.

### Step 2.3: Default `RECUPERO_CROSS_CHAIN_CONTINUATION=1`

The env-var gate was a v0.17.x conservative-default decision. Now
that we have the cross-chain seed dedup + cap from v0.17.4 + cost
controls, the default should be ON for production traces. Add to
`docs/RAILWAY_DEPLOY.md` env var table as a required setting.

The override can stay (for R&D or fixture-build runs that intentionally
stop at the source chain).

### Step 2.4 (optional, longer arc): scheduled dormancy sweeps

Even with bridge-following fixed, a dormant address on Ethereum that
the BFS visits and then leaves alone won't get re-queried for residual
balance changes. A weekly cron that re-runs
`dormant_finder.find_dormant_candidates` against the visited-address
set surfaces "perpetrator just moved $10M of DAI" without needing a
fresh trace.

This is a product enhancement, not a bug fix. Belongs in the v0.28+
roadmap.

## What's NOT a fix

- **Larger hop budget**: doesn't help; the trace stops at the bridge,
  not at hop N.
- **Broader token filter**: doesn't help; DAI is already in the set.
- **Deeper recursive trace**: same; the recursion is bounded correctly
  for Zigha — it's the cross-chain transition that breaks.

## On the artifact-family question (Jacob's (d))

Even with all three blockers fixed and the dormant DAI addresses
surfacing in the worker output, the current artifact set has nowhere
to put them. UNRECOVERABLE (issuer can't freeze) is the closest
existing bucket but it's a dead-end label — operators have no
follow-up action other than "wait until perpetrator is identified."

The right answer for Zigha-shape positions (identified, traceable,
non-freezable) is a separate artifact family targeted at subpoena
recipients: ISPs (Comcast, Fastweb), exchanges that received off-ramp
deposits (MEXC), KYC providers. The trace report + brief should
generate a **subpoena-target manifest** alongside the freeze letters.

This is Jacob's step 3 (his proposal d). The data shape is sketched
in `docs/v0.28_subpoena_targets_design.md` (separate doc).

## Call agenda suggestions

1. Confirm the three-blocker diagnosis matches your read.
2. Decide: v0.28 lands all three (2.1 + 2.2 + 2.3) as a coherent
   release, or ship 2.1 alone as a v0.27.3 (partial improvement) and
   queue 2.2 + 2.3 for v0.28.
3. Walk through `bridge_calldata.py` dispatch to confirm the decoder
   add pattern is clear before someone takes that work.
4. Confirm v0.27.2 (the item-1 fixes) merges as planned after
   INVARIANT B + Zigha ground-truth lands. The trace-coverage fix is
   a separate release; v0.27.2 cleans up the artifacts that DO
   generate, not the missing destinations.
