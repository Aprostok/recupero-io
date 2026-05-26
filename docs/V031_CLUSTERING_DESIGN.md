# v0.31.0 — Minimum-Viable Wallet Clustering (Gap #4)

## Why this exists

Gap #4 of the trace-completeness assessment: TRM / Chainalysis identify
wallet clusters via co-spending / common-input heuristics and present a
perpetrator's many addresses as ONE entity. Recupero pre-v0.31 treated
every address independently. A perpetrator splitting funds across five
wallets appeared in the brief as five unrelated counterparties — the
victim's lawyer drafting subpoenas saw a fan-out instead of a single
operator.

`compute_address_clusters(case, *, label_store)` closes that gap with a
narrow, heuristic-only MVP. No graph DB, no ML, no behavioral
fingerprinting. Pure function. Same input → same output, every time.

The legacy v0.9 `cluster_addresses()` pass (24h common-funding + 12h
common-withdrawal + round-number direct-transfer) is intentionally
kept side-by-side. It surfaces as `ENTITY_CLUSTERS` in the brief.
The new pass surfaces as `WALLET_CLUSTERS`.

## Heuristics

In order of confidence.

### H1 — Co-spending (Bitcoin)
- **Signal**: two addresses appear together as inputs to one Bitcoin tx.
- **Why**: the textbook common-input-ownership heuristic. Spending two
  UTXOs in one tx requires signing with both private keys, so the
  same person controls both.
- **Confidence**: high.
- **Scope**: Bitcoin only. EVM chains don't have multi-input txs.

### H2 — Common CEX withdrawal (EVM, ≤ 1 h)
- **Signal**: two EVM addresses both received from the same labeled
  exchange-deposit / exchange-hot-wallet address within a 1-hour window.
- **Why**: same beneficiary funded both wallets in a single CEX
  withdrawal session.
- **Confidence**: high.
- **Suppression**: if the CEX source has > 20 recipients in this trace,
  treat as shared infrastructure and skip (we'd be conflating
  unrelated users).
- **Scope**: requires `label_store` so we can identify the CEX
  endpoint.

### H3 — Common funding source (≤ 1 h)
- **Signal**: two addresses both received their first material
  inflow (≥ $100 USD) from the same source within a 1-hour window.
- **Why**: an operator funds gas on a fresh set of wallets in one
  session. Tighter than the v0.9 24h window because the wider window
  catches too many false positives.
- **Confidence**: medium.
- **Suppression**: if the source has ≥ 5 distinct first-inflow
  recipients, treat as shared infrastructure and skip.

### H4 — Bridge round-trip
- **Signal**: source-chain address A bridges out; another address C
  receives from a bridge on the same source chain within 6 hours.
- **Why**: operator moves funds out, waits, bridges back to a different
  wallet on the source chain. Surfaces operator-controlled
  destinations the trace can't follow cross-chain.
- **Confidence**: medium.
- **Caveat**: we don't actually verify the round-trip preserves
  ownership — the bridge could have settled to a third party in the
  intervening hop. This is a structural shape, not a fund-flow proof.

## Stable cluster IDs

`cluster_id = "cluster_" + sha256("\n".join(sorted(addresses)))[:8]`

Two pipeline runs over the same case produce identical IDs. The PDF
brief, AI editorial, and investigator notes can cross-reference
`cluster_a1b2c3d4` persistently across re-emits.

## Explicit-label suppression

Pairs where EITHER address has a label of category
`exchange_deposit`, `exchange_hot_wallet`, `bridge`, `mixer`,
`defi_protocol`, or `staking` are NEVER clustered. These are
shared-infrastructure roles. Clustering "Binance Deposit (user 9001)"
with "Coinbase Deposit (user 4242)" because both received from
Tornado within an hour would be a serious false positive — different
exchange users, not the same operator.

## Output shape

`compute_address_clusters(case, *, label_store)` returns
`dict[address, cluster_id]` — only addresses that ended up in a
2+ member cluster.

`compute_clusters_with_metadata(case, *, label_store)` returns the
full per-cluster view:

```python
[
  {
    "cluster_id": "cluster_a1b2c3d4",
    "addresses": ["0x1111...", "0x2222..."],
    "size": 2,
    "confidence": "high",
    "heuristics": ["cex_withdrawal", "common_funding"],
    "evidence": [
      {
        "heuristic": "cex_withdrawal",
        "confidence": "high",
        "details": "Both withdrew from exchange address 0x1234abcd… within 12.5min"
      },
      ...
    ]
  },
  ...
]
```

Brief integration: `_build_wallet_clusters_section` in `emit_brief.py`
wraps this as `{"clusters": [...]}` under the `WALLET_CLUSTERS` key.
The key is OMITTED when no clusters were found, so consumers asserting
on key sets stay happy.

## What this is NOT (yet)

1. **Real co-spending detection**. The current Bitcoin adapter only
   retains the FIRST input address per tx (`chains/bitcoin/adapter.py`
   `_normalize_utxo_tx`). H1 fires only when the same txid is seen
   from multiple expansion seeds. A proper implementation needs
   `Transfer` (or a sibling record) to carry the full input-address
   set; that's a model change that touches the case-schema version
   and storage. TODO for v0.32.
2. **Cross-chain ownership inference**. H4 only catches round-trips
   that return on the same source chain. A real cross-chain cluster
   detector would correlate decoded bridge-call destinations against
   subsequent receives across chains — significant infrastructure
   work. TODO.
3. **Behavioral fingerprinting**. TRM and Chainalysis cluster on
   gas-price patterns, nonce distribution, transaction timing, etc.
   We don't, because the training data + model maintenance burden
   isn't justified at this fidelity tier. Future work if the gap
   becomes a deal-breaker for a specific case.
4. **Off-chain attribution**. CEX subpoena returns are the proper
   way to confirm same-beneficiary clusters at high confidence.
   H2 surfaces the lead; the lawyer's subpoena confirms it.

## What TRM / Chainalysis do differently

- **Full UTXO graph**. Their Bitcoin clustering uses every input/output
  edge across all blocks, not just the txs that touched the seed.
  That's how they cluster Mt. Gox to a tagged address-of-record from
  on-chain shape alone.
- **Off-chain corroboration**. KYT alerts + subpoena-return data
  feed labeled clusters back into the heuristic engine. Recupero
  doesn't have that telemetry loop and probably shouldn't —
  Treasury / FBI fund those subscriptions for a reason.
- **Operator-controlled merging**. TRM analysts can manually merge or
  split clusters. Recupero has no UI for that yet; clusters are
  computed at brief-emit time and consumed read-only.
- **Probabilistic confidence per address**. They emit per-address
  confidence scores. Our `confidence` is per-cluster (high if ANY
  high-confidence edge fired, else medium).

## Files

- `src/recupero/trace/clustering.py` — `compute_address_clusters`,
  `compute_clusters_with_metadata`. Pure function. Single dependency
  is `LabelStore.lookup`, called best-effort (no crashes if absent).
- `src/recupero/reports/emit_brief.py::_build_wallet_clusters_section`
  — brief integration. Loads the `LabelStore` best-effort and inserts
  the `WALLET_CLUSTERS` section only when clusters were found.
- `tests/test_v031_clustering.py` — coverage for the 4 heuristics +
  label suppression + stable IDs + empty-case safety.
