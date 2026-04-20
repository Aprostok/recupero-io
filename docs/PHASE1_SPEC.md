# Phase 1 Specification

**Goal:** From a victim Ethereum address and an incident timestamp, produce a structured `case.json` containing every outbound transfer at the first hop, with counterparty labels, USD values at time of transaction, and per-tx evidence receipts. Flag any transfer landing on a labeled centralized exchange.

This is the *only* thing Phase 1 does. No graphs, no reports, no Solana, no multi-hop, no bridges. Those are explicit non-goals.

## Why this scope

The data model and trace primitives we build here are the foundation for every later phase. If we get them wrong, every subsequent phase inherits the bug. We are deliberately keeping Phase 1 narrow to validate the model against ground truth (the Zigha CFI report) before building anything on top.

---

## Inputs

A single CLI invocation:

```
recupero trace \
    --chain ethereum \
    --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
    --incident-time "2025-01-15T00:00:00Z" \
    --case-id ZIGHA-001 \
    [--max-depth 1] \
    [--dust-threshold-usd 50] \
    [--config path/to/config.yaml]
```

Required arguments:
- `--chain`: chain identifier. Phase 1 supports only `ethereum`.
- `--address`: seed (victim) address. Must be a valid Ethereum address; we checksum-normalize internally.
- `--incident-time`: ISO-8601 UTC timestamp of the suspected hack/theft. Used to filter transfers.
- `--case-id`: human-friendly identifier. Becomes the case folder name.

Optional arguments override values from `config/default.yaml`.

## Outputs

A folder at `data/cases/<case_id>/` containing:

```
data/cases/ZIGHA-001/
├── case.json                # The structured trace data (the canonical artifact)
├── manifest.json            # Run metadata: timestamps, config used, software version, source provenance
├── transfers.csv            # Flat CSV mirror of transfers — handy for spreadsheet review and LE
├── tx_evidence/             # Per-tx evidence receipts, one JSON per tx hash
│   ├── 0xabc123...json
│   └── 0xdef456...json
└── logs/
    └── trace.log            # Full structured log of the trace run
```

`case.json` is the *single source of truth*. Everything else (CSV, evidence receipts, future report renderings) is derived from it.

---

## Trace algorithm (Phase 1, depth = 1)

```
1. Load config and validate inputs.
2. Initialize EthereumAdapter, LabelStore, PriceClient.
3. seed = checksum(--address)
4. incident_block = block at or just before incident_time - buffer_minutes.
5. transfers = []
   For asset_type in [native_eth, erc20]:
       For each outbound transfer from `seed` with block >= incident_block:
           transfer = build_transfer(raw_tx)
           transfer.usd_value = price_at(transfer.token, transfer.block_time)
           if transfer.usd_value < dust_threshold_usd: skip
           transfer.counterparty.label = label_store.lookup(transfer.to)
           transfers.append(transfer)
6. case = Case(seed=seed, incident_time=..., transfers=transfers)
7. For each transfer, write tx_evidence/<tx_hash>.json with the raw chain receipt.
8. Write case.json, transfers.csv, manifest.json.
9. Print summary table: total transfers, total USD out, exchange endpoints found.
```

Detailed pseudocode is in `TRACE_ALGORITHM.md`.

## Stop conditions (Phase 1)

Because depth is 1, the only "stop condition" is the dust threshold. Phase 2+ adds:
- Stop at labeled exchange (set in config, default true)
- Stop at depth N
- Stop when transferred amount falls below percentage threshold of inbound

Build these as policy objects in `trace/policies.py` even in Phase 1, so Phase 2 plugs in cleanly.

---

## Counterparty labeling

For each `to` address in a transfer, the label store tries to resolve it against:

1. **Local seed lists** in `src/recupero/labels/seeds/` — JSON files with addresses we've manually curated:
   - `cex_deposits.json` — known CEX deposit/hot wallet addresses (MEXC, Binance, Coinbase, Kraken, OKX, KuCoin, Bybit, Gate, etc.)
   - `bridges.json` — known bridge contract addresses (DeBridge, Wormhole, Across, Stargate, Symbiosis, 1inch Fusion router)
   - `mixers.json` — Tornado Cash and similar
   - `defi_protocols.json` — Uniswap, 1inch, Curve, Aave router, etc. — useful for context, not freeze targets
2. **User-supplied label files** under `data/labels/local_*.json` — overrides and additions per investigator.

Each label has structure:
```json
{
  "address": "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
  "name": "MEXC Deposit",
  "category": "exchange_deposit",
  "exchange": "MEXC",
  "source": "local_seed",
  "confidence": "high",
  "notes": "Observed in Zigha case 2025-01"
}
```

If no label matches, counterparty is `unlabeled` with `category: unknown`. The report later highlights these as candidates for investigator review.

**Phase 1 ships with seed lists pre-populated from public sources** (Etherscan tags, community lists). We document each entry's source so labels are defensible.

## Pricing

Historical USD pricing for each transfer:
- Native ETH: CoinGecko `coins/ethereum/history?date=DD-MM-YYYY` — daily granularity is acceptable for Phase 1; document the limitation.
- ERC-20: CoinGecko `coins/{token_id}/history?date=DD-MM-YYYY`. We need a contract→coingecko_id map; bootstrap with the top 200 tokens by market cap and add as needed.
- Cache every price lookup to `data/prices_cache/<token>_<date>.json`. Never re-fetch.

If CoinGecko has no record (obscure token, scam token, freshly deployed): write `usd_value: null`, `pricing_error: "no_coingecko_mapping"`. Do not crash. The report later flags these for manual valuation.

## Evidence receipts

For every transfer surfaced, write `tx_evidence/<tx_hash>.json` containing:
- The raw transaction object as returned by Etherscan
- The transaction receipt (status, gas used, logs)
- The block header (timestamp, miner)
- A timestamp of when *we* fetched it (chain-of-custody)
- The Etherscan URL for human verification

This is what makes the output "verifiable for law enforcement." LE staff can take any tx hash from our report, paste it into Etherscan, and confirm the data independently. We're not asking them to trust us; we're showing our work.

---

## Acceptance test

Phase 1 is "done" when:

1. `pytest tests/ -v` passes with all unit tests green.
2. `python scripts/verify_zigha.py` runs end-to-end against the Zigha victim address and:
   - Produces a `case.json` in `data/cases/ZIGHA-VERIFY/`.
   - Identifies the same first-hop outbound destinations CFI documented in their Attachment 08 (or as close as we can manually verify against the Zigha PDF).
   - Correctly labels at least one MEXC deposit address as `category: exchange_deposit, exchange: MEXC`.
   - Produces non-null USD values for all major transfers (ETH, USDT, USDC).
3. The investigator (you) can read `case.json` and the CSV and feel confident handing it to a government contact.

If any of these fails, Phase 1 is not done. Resist the temptation to start Phase 2.

---

## What Phase 1 explicitly does NOT do

- Multi-hop tracing (depth > 1) — Phase 2.
- Solana, Bitcoin, BSC, Arbitrum, etc. — Phase 3+.
- Bridge decoding — Phase 4.
- Cross-case entity database — Phase 5.
- HTML/PDF report generation — Phase 2.
- Graph rendering — Phase 2.
- Real-time monitoring — out of scope entirely.
- A web UI — out of scope for now.

If a feature isn't in this doc, it isn't in Phase 1. When in doubt, leave it out and note it in `docs/BACKLOG.md`.
