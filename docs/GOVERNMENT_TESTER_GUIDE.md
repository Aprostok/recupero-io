# Recupero — guide for the government tester

> Prepared for an FBI / IRS-CI / OFAC / state-LE analyst
> evaluating Recupero as an on-chain investigation tool.
> Covers what the tool produces, how to read it, and how it
> compares to TRM / Chainalysis for the specific workflows
> we believe it complements.

---

## What Recupero is

A forensic on-chain investigation pipeline for crypto-theft
cases. Takes a victim's wallet address + incident time → walks
the on-chain graph → produces:

  * A **trace_report.pdf** for the victim/operator (1–4 pages of
    HTML rendered to PDF).
  * An **investigator_findings.csv** + **.json** for downstream
    analyst tools (Excel, Splunk, case management).
  * Per-issuer **freeze request letters** for stablecoin
    compliance teams (Circle, Tether, Paxos, Maple, etc.).
  * An **LE handoff package** for filing with IC3 / FBI / state.

Built for the Tier-2 crypto-recovery service model: $499
diagnostic + $10,000 active engagement (if recoverable) + 15%
contingency on funds returned. The diagnostic alone runs in
~14 minutes against a typical Ethereum case and costs ~$0.50 in
RPC + AI API fees.

## What it does that's relevant to your workflow

For the analyst-facing capabilities (not the customer-facing
prose), version 0.9.2 ships:

### 1. Cross-chain handoff detection

Detects perpetrator funds bridging off the source chain via a
known cross-chain bridge (Wormhole, Stargate, deBridge, Across,
Synapse, Hop, Celer, Socket, Allbridge, plus canonical L1→L2
bridges for Arbitrum/Optimism/Polygon/Base/zkSync/Avalanche).
Currently 28 bridge contracts in the seed file.

For each detected handoff, the brief carries:

  * Source-chain tx hash + explorer URL (for evidence)
  * Bridge name + protocol family
  * Amount in USD + token symbol
  * **Destination-chain candidates** (chains the bridge typically
    routes to)
  * **Follow-up URL** — the bridge's own explorer (Wormholescan,
    LayerZeroScan, Across explorer) where you can correlate the
    destination-chain tx
  * **Investigator note**: one-line action item ("Query
    <destination chain> for transfers received at the perpetrator's
    known addresses near <block_time> ± a few blocks")

This is the gap that surfaces multi-chain laundering paths the
victim-forward trace alone can't follow. v0.7.x stopped at the
bridge contract; v0.8.1 surfaces the handoff as structured data
your team can pick up.

### 2. Entity clustering

Groups addresses that appear to belong to the same actor based
on three heuristics:

  * **H1 common_funding** (high confidence) — Two addresses both
    receiving first material inflow from the same source EOA
    within 24 hours.
  * **H2 common_withdrawal** (high confidence) — Two addresses
    both sending material outflows to the same destination
    within 12 hours.
  * **H3 direct_transfer** (low confidence) — Address A → B
    with a round-number USD amount when both have other case
    activity.

**Shared-infrastructure suppression**: addresses with 5+
distinct interaction partners (CEX hot wallets, popular DEX
routers, large protocols) are treated as shared infrastructure
and NEVER used as a clustering signal. Prevents false-positive
merges (Binance hot wallet does not cluster all its withdrawal
destinations into one entity).

Each cluster carries evidence — heuristic + confidence + details
+ related_address — so you can verify the heuristic fired
correctly before acting.

Use case: subpoena scope expansion. "Subpoena exchange X for
deposits from any of these 6 addresses, not just the one the
victim's funds touched."

### 3. Risk scoring (OFAC / mixer / darknet)

Per-address risk assessment computing direct counterparty
exposure. **OFAC SDN List exposure is dispositive**: any direct
transaction with a sanctioned address triggers the SANCTIONED
verdict regardless of numeric score (Treasury's 50% Rule view).

Seed coverage:
  * **OFAC SDN List**: Lazarus Group (DPRK) addresses from
    Ronin, Harmony Horizon, Atomic Wallet hacks; Hydra
    Marketplace; Garantex; Blender.io; Sinbad.io
  * **Sanctioned mixers**: Tornado Cash pool contracts (.1/1/10/
    100 ETH + extended pools, BUSD/DAI/cDAI pools)
  * **Non-sanctioned mixers**: Railgun + others flagged as
    high-risk by behavior, severity=3
  * **Scam/drainer services**: Pink Drainer, Inferno Drainer

Output (per address):

```
0xabc...:
  score: 12
  verdict: "SANCTIONED — direct exposure to OFAC SDN List"
  exposures: [
    {counterparty: "0xdef...",
     counterparty_name: "Lazarus Group (DPRK) — Ronin Bridge",
     risk_category: "ofac_sanctioned",
     severity: 4,
     direction: "outflow",
     tx_count: 3,
     total_usd: "$150,000.00"},
    ...
  ]
```

Summary block at the top of the section:

```
addresses_assessed: 7
ofac_exposed_count: 2    ← the number you act on first
mixer_exposed_count: 1
highest_score: 12
highest_score_address: 0xabc...
```

### 4. Freezability classification

For each destination address, classifies the freeze potential by
issuer:
  * **HIGH** — issuer has documented direct freeze (Circle USDC,
    Tether USDT, Paxos USDP/PYUSD, BitGo WBTC, Maple
    syrupUSDC/T/P, Coinbase cbBTC, First Digital FDUSD)
  * **MEDIUM** — issuer has freeze with friction (Frax via
    governance vote)
  * **LOW** — technically possible but unprecedented
  * **NOT FREEZABLE** — DAI, ETH, stETH, rETH (no individual-
    address freeze function)

`delegates_to` chain-through: Aave aTokens have no individual
freeze, but their underlying (USDC/USDT) does. The brief
surfaces the underlying issuer's contact for aToken positions.

Issuer DB has 26 entries across Ethereum, Arbitrum, Solana.

## What it does NOT do (be aware before testing)

  * **Cross-chain trace continuation**: we DETECT bridges but
    don't follow funds onto the destination chain. The brief
    gives you destination-chain candidates + follow-up URLs;
    actual continuation requires manual follow-up or a tool
    like Chainalysis Reactor.
  * **Indirect exposure scoring** (1-2 hops removed from
    sanctioned address): v0.9.1 is direct-counterparty only.
    Chainalysis-style multi-hop exposure attribution requires a
    more sophisticated graph analytics layer.
  * **ML-based behavioral fingerprinting** (gas-price patterns,
    timing distributions): out of scope. Real signal but needs
    a trained model.
  * **Bitcoin / UTXO chains**: v0.9.x is account-model only
    (Ethereum, EVM L2s, Solana). UTXO clustering uses different
    heuristics (common-input-ownership) that don't apply here.
  * **Live OFAC SDN List sync**: we ship a curated snapshot;
    refresh from treasury.gov/ofac/downloads/sdn.xml periodically
    if precise compliance is the use case.

## How to test V-CFI01 (the Zigha case)

We have a synthetic test case based on Ibrahim Zigha's
CFI-00265 forensics report (publicly published as a
multi-chain crypto-theft case totaling ~$24.28M across
Hyperliquid, Arbitrum, Ethereum, and Solana). This is the
test case we tuned v0.7.x → v0.9.2 against.

To run:
```
recupero-ops retrigger 74f2acf9-db52-471c-ae8b-0d5c1473e53f
```

Expected output (in the case's
`investigations/<id>/briefs/` folder on Supabase Storage):

  * `trace_report_<hash>.pdf` — should show 7 sections including
    cross-chain handoffs (1 Solana bridge detected), entity
    clusters (1+ clusters likely), risk assessment (depends on
    OFAC overlap in the trace).
  * `freeze_request_*.pdf` — one per detected issuer; Maple
    Finance gets one for the $3.27M mSyrupUSDp position.
  * `le_handoff_*.pdf` — packaged for IC3 filing.
  * `victim_summary_recoverable_<hash>.pdf` — customer-facing.
  * `investigator_findings.csv` — government-tester-facing. THIS
    is the file we want your feedback on most.
  * `investigator_findings.json` — same data, JSON shape.

## What to look at first (recommended evaluation order)

1. **investigator_findings.csv** — open in Excel. Read top-to-
   bottom. Critical findings first.
2. **trace_report.pdf** — section 1 (headline) + section 6 (risk
   assessment) are the highest-leverage reads.
3. **freeze_brief.json** (raw data) — under
   `investigations/<id>/freeze_brief.json` on Storage. This is
   the structured source-of-truth all the renderers read from.
   If a finding doesn't show up in the PDF, check freeze_brief
   to confirm whether it's a renderer bug or actually missing
   from the data.

## What we'd specifically appreciate feedback on

1. **Are the cross-chain handoff records actionable enough?**
   Specifically: does the destination_chain_candidates +
   follow_up_url + investigator_note format give you enough to
   continue the trace on the destination chain, or do you need
   the actual destination address parsed from the bridge
   calldata?
2. **Is the OFAC SANCTIONED detection trustworthy?** We use the
   public SDN List snapshot. Do you trust this enough to act on
   it, or do you need a live treasury.gov sync?
3. **Are the entity-cluster heuristics producing useful groups?**
   Specifically: false positive rate. We tightened thresholds
   (5+ partner shared-infra suppression, $100 USD floor, 24h /
   12h time windows) to avoid the "clustering everything that
   touched Binance" failure mode — does our calibration look
   right against your ground-truth cases?
4. **What's the investigator_findings CSV missing?** We optimized
   for what we think your tools want; you'd know better what's
   actually consumed.
5. **What's the right comparison to TRM / Chainalysis?** Where
   are we materially worse, materially better, or about the
   same? We're not trying to replace them — we're trying to
   serve the cases they're too expensive for.

## How to send feedback

Reply to alec@recupero.io with any observations, even partial.
We'd especially appreciate:
  * A specific case where the brief was right vs. where it
    missed something obvious
  * Quotes from the CSV/PDF that need different wording for a
    government audience
  * Features we lack that you'd use if we built them

Github repo: https://github.com/Aprostok/recupero-io

Run as of: v0.9.2 (2026-05-17).
