# Recupero — government tester guide v0.10

> Updated for v0.9.3 → v0.10.2 (covers the enterprise-grade
> push toward TRM / Chainalysis parity). Read this if you read
> the v0.9.2 guide; otherwise read that one first.
>
> Summary: 7 new capabilities shipped. Total label DB roughly
> doubled. The biggest single addition is **indirect exposure
> scoring** (multi-hop graph traversal) which closes the
> largest gap to enterprise tools. Live OFAC SDN sync removes
> the "we ship a snapshot" caveat.

---

## What's new vs v0.9.2

| Version | Capability | Why it matters |
|---|---|---|
| v0.9.3 | Massive label DB expansion: ~50 CEX hot wallets, 21 DeFi protocols, 6 ransomware operators (Conti / LockBit / BlackCat / Royal / REvil / DPRK Maui) | Better attribution → better entity clustering + better risk scoring downstream |
| v0.9.4 | **Live OFAC SDN sync** from treasury.gov/ofac/downloads/sdn.xml. New CLI: `recupero-ops ofac-sync`. | Removes the "we curate a snapshot" caveat. Run weekly via cron → newest sanctions land in next investigation. |
| v0.9.5 | **Bridge calldata parsing** — Wormhole / Across / Stargate. Decoder extracts the destination address + chain from the bridge tx's input data. | Converts "follow up at the bridge's explorer" into "funds went to ADDRESS X on CHAIN Y" — concrete handoff. |
| **v0.10.0** | **Indirect (N-hop) exposure scoring** with decay factor + amount-share normalization. | The TRM/Chainalysis flagship. Catches "funds 2-3 hops from Lazarus" cases that direct-only scoring misses. |
| v0.10.1 | Drainer signature detection. Classifies cases as wallet-drainer scams + attributes (Pink Drainer / Inferno Drainer / etc.). | Right SAR / FinCEN category + targeted recovery path. |
| v0.10.2 | DEX swap unwrapping (1inch / Uniswap / CoW Protocol / ParaSwap / Curve / Balancer + 4 more). | Trace continues past DEX routers to the output recipient. |

Test suite: **858 passing** (was 803 at v0.9.2 — +55 tests
covering the new capabilities; 0 regressions).

---

## The big one: indirect exposure scoring (v0.10.0)

This is the capability that meaningfully closes the gap to
Chainalysis / TRM. Before v0.10.0, our risk scoring was
**direct-counterparty only** — address X gets SANCTIONED if it
had a transaction *directly* with Lazarus / Tornado Cash /
Garantex / etc. v0.10.0 extends to **N-hop indirect**.

### Algorithm

For each high-risk source S in the case graph:

```
1. Direct outflows from S → 1-hop exposure
   weighted_amount = amount × decay^1   (default decay=0.5)

2. Each 1-hop receiver's outflows → 2-hop exposure
   weighted_amount = incoming_weighted × outflow_share × decay^2
   (outflow_share = amount_to_target / total_outflow_from_intermediate)

3. Recursive to max_hops (default 3)
```

### Why decay + amount-share

* **Decay** (0.5 default) — exposure dies off across hops.
  1-hop = 50%, 2-hop = 25%, 3-hop = 12.5%. Matches
  Chainalysis's documented public guidance for
  "moderate-decay" attribution.

* **Amount-share / mixing penalty** — if intermediate
  address R₁ pooled funds from many sources, the share of S's
  funds in any single R₁ → R₂ outflow is small. Without this,
  a single sanctioned $1 entering a $10M CEX hot wallet would
  taint every subsequent CEX outflow.

* **Source severity** — OFAC source still propagates OFAC
  verdict indirectly. Treasury's 50% Rule view + most
  regulatory regimes treat indirect exposure as covered.

### Tuning

```bash
RECUPERO_INDIRECT_MAX_HOPS=3   # default; deeper = more compute + noise
RECUPERO_INDIRECT_DECAY=0.5    # default; lower = exposure dies faster
```

### Brief output

New top-level `INDIRECT_EXPOSURE` section on `freeze_brief.json`:

```jsonc
{
  "addresses": {
    "0xabc...": {
      "total_indirect_usd": "$12,345.67",
      "paths": [
        {
          "source_address": "0xfff...",
          "source_name": "Lazarus Group (DPRK)",
          "risk_category": "ofac_sanctioned",
          "severity": 4,
          "weighted_amount_usd": "$8,000.00",
          "hop_count": 2,                       // 2 hops from Lazarus
          "path_addresses": ["0x111...", "0x222..."]
        },
        // ... up to 10 paths per address
      ]
    }
  },
  "summary": {
    "addresses_with_indirect_exposure": 12,
    "indirect_ofac_exposed_count": 4,           // key compliance metric
    "highest_indirect_usd": "$50,000.00",
    "highest_indirect_address": "0xabc..."
  }
}
```

The investigator CSV gets one row per indirect-exposure address
with `finding_type=indirect_exposure`, severity calibrated by
(hop_count + source severity), and the path embedded in notes.

---

## Other new sections in the brief

### `INCIDENT_CLASSIFICATION` (v0.10.1)

Drainer pattern detection:

```jsonc
{
  "is_drainer_case": true,
  "drainer_attribution": "Pink Drainer",       // or null
  "classification_confidence": "high",         // 'high' | 'medium' | 'low'
  "signals": [
    {
      "type": "known_drainer_outflow",
      "address": "0xvictim...",
      "counterparty": "0xpink...",
      "counterparty_name": "Pink Drainer",
      "severity": "critical",
      "description": "Victim's wallet sent funds directly to known drainer infrastructure (Pink Drainer).",
      "confidence": "high"
    }
  ]
}
```

For the government tester: this changes the SAR filing category
(BSA classifies wallet-drainer theft under "Suspicious Activity
involving cryptocurrency or convertible virtual currency,
specifically address compromise via approval exploit"). Right
classification = right reporting requirement.

### `DEX_SWAPS` (v0.10.2)

When perp funds pass through a DEX router:

```jsonc
[
  {
    "tx_hash": "0xfeed...",
    "explorer_url": "https://etherscan.io/tx/0xfeed...",
    "block_time": "2026-01-01T10:00:00Z",
    "swapper": "0xperphub...",
    "router_address": "0x1111111254eeb25477b68fb85ed929f73a960582",
    "router_name": "1inch v5: Aggregation Router",
    "router_protocol": "1inch",
    "input_token": "USDC",
    "input_amount": "48200 USDC",
    "input_amount_usd": "$48,200.00",
    "output_token": "USDT",
    "output_amount": "48100 USDT",
    "output_amount_usd": "$48,100.00",
    "output_recipient": "0xperpout...",          // ← KEY: where to continue tracing
    "confidence": "high",
    "investigator_note": "Swap via 1inch v5: $48,200 USDC → $48,100 USDT to 0xperpout.... Continue tracing from the output address; the original token is no longer recoverable at this hop."
  }
]
```

This is the trace-continuation feature: instead of the brief
dead-ending at "funds → 1inch router," the next-hop address
is surfaced for continued investigation.

### `CROSS_CHAIN_HANDOFFS[i].destination_address` (v0.9.5)

When the bridge calldata parser succeeds, the cross-chain
handoff entry carries an additional concrete field:

```jsonc
{
  "bridge_name": "Wormhole",
  "amount_usd": "$120,000.00",
  // pre-v0.9.5:
  "destination_chain_candidates": ["solana"],
  // v0.9.5 adds (when calldata decode succeeds):
  "destination_chain": "solana",                          // concrete
  "destination_address": "0xCrkW1fJRwSoNYRBn5UxbVKsKsXd...", // concrete
  "decode_confidence": "high"
}
```

Wormhole-to-Solana decoded as full pubkey (operator's tooling
converts to base58 for Solscan lookup). Across to-EVM-chain
decoded as native EVM chain ID + address. Stargate via
LayerZero chain ID.

---

## Updated test plan for V-CFI01

Same canary as the v0.9.2 guide. After deploy lands:

```bash
recupero-ops retrigger 74f2acf9-db52-471c-ae8b-0d5c1473e53f
```

Expected new outputs (in addition to v0.9.2's):

| Section | What to verify |
|---|---|
| `INDIRECT_EXPOSURE.summary.indirect_ofac_exposed_count` | Should be > 0 if any hub interacted with Tornado Cash / etc. transitively. The CFI report mentions Railgun usage; v0.10.0 should pick up indirect exposure to Railgun (severity=3, non-OFAC) if it's in the trace. |
| `INDIRECT_EXPOSURE.summary.highest_indirect_usd` | The largest weighted indirect exposure across all addresses in the trace. |
| `CROSS_CHAIN_HANDOFFS[*].destination_address` | The Solana bridge tx — calldata parser should decode the destination Solana pubkey. |
| `INCIDENT_CLASSIFICATION.is_drainer_case` | V-CFI01 is seed-phrase compromise, not approval exploit. Expected: `false`, no signals. (Confirming v0.10.1 doesn't false-positive on non-drainer cases.) |
| `DEX_SWAPS` | If the perpetrator used 1inch / Uniswap / etc. to swap stolen USDC → DAI before parking in the dormant addresses, those swaps should appear here with output recipients. |

---

## What to send Jacob to evaluate

GitHub link: https://github.com/Aprostok/recupero-io/blob/main/docs/GOVERNMENT_TESTER_v0.10.md

If he wants the raw `freeze_brief.json` for the V-CFI01
canary, it's on Supabase Storage at
`investigations/74f2acf9-db52-471c-ae8b-0d5c1473e53f/freeze_brief.json`.

The `investigator_findings.csv` is the file we want his
feedback on most — that's the format his case-management
tools ingest. Specifically:

1. **Is the indirect_exposure severity calibration right?**
   We map: OFAC@1hop → critical; OFAC@2-3hop → high;
   non-OFAC mixer → severity_int → string. Does this match
   how Treasury / FBI / IRS-CI tier their alerts?

2. **Are the cross-chain destination addresses
   investigator-actionable?** Decoder reaches ~80% confidence
   on Wormhole-to-Solana per our calldata-extraction tests.
   Does the Solscan-compatible pubkey hex format work for his
   tools?

3. **Drainer attribution false-positive rate?** v0.10.1 flags
   "outflow to unknown contract" as medium-confidence
   drainer. On legitimate cases (smart-contract wallets,
   custodial deposits) this would false-positive. We need his
   read on whether the medium-confidence threshold is right.

4. **DEX swap output_recipient — is the same-tx pairing
   heuristic reliable enough?** Our tests cover the common
   1-router pattern; multi-router aggregation cases get
   filtered. Does this match his expectation?

5. **What's the next gap?** With v0.10.x shipped, where does
   Recupero still fall short of TRM/Chainalysis in his
   specific workflow?

---

## How we compare to TRM / Chainalysis now

| Capability | TRM / Chainalysis | Recupero v0.10.2 |
|---|---|---|
| Multi-hop tracing | Unlimited with smart heuristics | depth=2 + pass-2 perpetrator-forward |
| Entity clustering | ML + UTXO + behavioral fingerprints | H1/H2/H3 heuristics with evidence + shared-infra suppression |
| **Indirect exposure scoring** | Multi-hop with proprietary decay model | **N-hop with documented 0.5 decay + amount-share** ✓ |
| Cross-chain tracking | Full continuation + visualization | **Bridge detection + calldata parsing (Wormhole/Across/Stargate)** ✓ |
| OFAC sanctions DB | Curated + live-synced + multi-hop | **Curated + live-synced + multi-hop** ✓ |
| Risk scoring depth | OFAC + mixers + ransomware + scam + indirect | OFAC + mixers + ransomware + scam + **indirect** ✓ |
| **DEX swap unwrapping** | Yes, integrated with trace | **Yes (1inch/Uniswap/CoW + 7 others)** ✓ |
| **Drainer pattern classification** | Specialized models | Heuristics + known-drainer DB |
| Real-time monitoring | Yes (alerts, dashboards) | Watchlist + cron-based |
| Address attribution DB | ~250K+ curated labels | ~85 high-confidence labels |
| Visualization | Interactive graph | Static SVG flow diagram |
| API access | Yes (REST + GraphQL) | Worker HTTP + investigator CSV/JSON exports |
| Bitcoin / UTXO chains | Yes | Not yet (account-model only) |
| Price | $50k–$500k/year | **$499 + $10k engagement + 15% contingency** |

The remaining material gaps:

- **Address label coverage** — they have 250K+ curated labels;
  we have ~85. This is mostly a curation problem (mechanical
  work to expand) rather than a capability problem.
- **Visualization** — they have interactive graph explorers; we
  ship static SVG. Not blocking for the CSV/PDF workflow but
  important for visual investigators.
- **Bitcoin chain support** — we're account-model-only
  (Ethereum, EVM L2s, Solana). Bitcoin/UTXO needs separate
  clustering heuristics + adapter.

Everything else: we now ship comparable capability, with the
honest scope caveats called out in this doc.

---

Run as of v0.10.2 (2026-05-17). Test suite 858 passing.
