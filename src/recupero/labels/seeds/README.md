# Recupero Open Address Labels

**Public-domain address-label database for forensic on-chain investigation.**

This directory contains curated label data identifying addresses across
EVM chains (Ethereum, BSC, Polygon, Arbitrum, Base), Tron, Solana, and
Bitcoin. Released under [CC0 1.0](LICENSE) — public domain, no rights
reserved.

## What's here

| File | Count | What it labels |
|---|---|---|
| `high_risk.json` | ~30 | OFAC-sanctioned wallets + known scam operators with severity ratings |
| `ransomware.json` | 6 | Conti, LockBit, BlackCat, Royal, REvil, DPRK Maui — per CISA/DOJ |
| `mixers.json` | 12 | Tornado Cash deployments, Sinbad.io, Railgun pools, FixedFloat |
| `cex_deposits.json` | ~80 | Binance, Coinbase, Kraken, OKX, Bybit etc. hot wallets |
| `defi_protocols.json` | 21 | 1inch, Uniswap V3, CoW, ParaSwap, Curve, Aave, Lido, Maple, etc. |
| `bridges.json` | ~15 | Wormhole, Stargate, Across, Synapse, deBridge, etc. |
| `issuers.json` | ~25 | Circle (USDC), Tether (USDT), Paxos, Maple Finance, etc. — freeze authority + contacts |
| `ofac_crypto_live.csv` | varies | Auto-synced from treasury.gov via `recupero-ops ofac-sync` (see below) |

Total: ~200 curated entities + the live-synced OFAC SDN list.

## Schema

Each entry is a JSON object. Common fields across files:

```json
{
  "address": "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936",
  "name": "Tornado Cash: 0.1 ETH",
  "category": "mixer",
  "source": "tornado_docs",
  "confidence": "high",
  "notes": "OFAC SANCTIONED — flag for special handling",
  "added_at": "2025-01-01T00:00:00Z"
}
```

File-specific extensions:

- `high_risk.json`: adds `risk_category` (`ofac_sanctioned` /
  `ransomware` / `mixer_sanctioned` / `scam_drainer` / ...),
  `severity` (1-4), `ofac_listing_date`.
- `issuers.json`: adds `freeze_capability` (`yes` / `limited` / `no`),
  `freeze_notes`, `primary_contact`, `secondary_contact`,
  `jurisdiction`, optional `delegates_to` for wrapped-token issuers.
- `ransomware.json`: adds operator-specific operator attribution
  (`operator_name`, `cisa_advisory_id`, `doj_docket_id`).

All addresses are stored in their chain's canonical form (EVM:
lowercase hex with `0x` prefix; Tron: base58check; Bitcoin: native
encoding; Solana: base58).

## How to contribute

We accept additions and corrections via pull request.

### Adding a new label

1. Identify the appropriate file (e.g., `mixers.json` for a new
   mixer; `high_risk.json` for any other scam operator / sanctioned
   wallet).

2. Append your entry. Required fields: `address`, `name`,
   `category`, `source`, `confidence`, `added_at`.

3. Cite your source in `source`. Examples:
   - `tornado_docs` (official protocol documentation)
   - `ofac_2023_11_29` (OFAC press release with date)
   - `cisa_aa23-187a` (CISA advisory ID)
   - `doj_press_release_2024_03_15`
   - `zachxbt_thread_2024_05_22` (independent researcher attribution)
   - `industry_known` (community-known but no specific public source)

4. Set `confidence` honestly:
   - `high`: directly confirmed by issuer / law enforcement / official documentation
   - `medium`: strong inferential evidence (on-chain pattern + ZachXBT-grade attribution)
   - `low`: speculative or pattern-match — should be reviewed

5. Submit a PR with a brief justification in the description.

### Bulk updates

For datasets of 50+ addresses (e.g., new sanctioned-mixer
deployment list), open an issue first so we can coordinate format
and reduce review burden.

### Reporting bad data

If you find an incorrect entry (false positive / wrong category /
stale labels), please open an issue with:
- The address in question
- Why you believe the label is wrong
- A source for the correct interpretation

We treat label-quality bugs with the same severity as code bugs.

## OFAC live sync

`ofac_crypto_live.csv` is NOT hand-curated — it's auto-synced from
[treasury.gov](https://www.treasury.gov/ofac/downloads/sdn.xml) via
the `recupero-ops ofac-sync` command. Recommended cadence: weekly via cron.

The synced data is in the public domain by virtue of being a
government-published list, so it ships under the same CC0 dedication
as the rest of this directory.

## Schema versioning

These files are JSON, not a versioned schema. Field additions are
backward-compatible. Field removals or renames will:
1. Bump the file's `_schema_version` (if/when we add one)
2. Be announced in the commit message
3. Be supported via dual-read in `recupero.labels.store` for at
   least two minor releases

## Quality bar

We aim to be more conservative than TRM/Chainalysis's commercial
products in one specific way: false positives are worse than
false negatives in the recovery context. A false-positive
`mixer_sanctioned` label routed through an OFAC freeze letter
embarrasses both the requestor and the receiving issuer; a
false-negative just means the operator does more legwork.

When in doubt, use `confidence: "medium"` and document the
reasoning in `notes`.

## Versioning + provenance

Every PR that touches these files is signed by the operator's
Ed25519 chain-of-custody key (see `recupero-ops custody-keygen`).
This means downstream consumers can verify exactly which version
of the labels was in use at any given case time — important for
court-admissibility.

## Acknowledgments

Curators of related public databases whose work informed this set:
- ZachXBT — independent on-chain investigation
- TRM Labs Insights blog (citations only; their full labels are proprietary)
- CISA + DOJ press releases
- Treasury OFAC SDN List
- MetaMask `eth-phishing-detect`
- chainabuse.com community reports

If you find your label work uncredited and want attribution, file
an issue and we'll update.

## License

[CC0 1.0 Universal](LICENSE) — public domain.

The CODE that consumes this data (everything outside this directory)
is licensed separately per the repo root's `LICENSE`.
