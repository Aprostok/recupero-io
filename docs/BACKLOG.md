# Backlog

Things that are *not* in Phase 1 but are worth capturing before we forget. Don't build any of these without explicit decision to leave Phase 1.

## Phase 2 (next up)
- Multi-hop tracing (recursive trace, cycle detection, depth/value/exchange stop policies)
- HTML report generator in CFI/Zigha style (printable to PDF)
- Static graph rendering from `case.json` (Graphviz or similar)
- One-page "freeze brief" generator — priority output per detected exchange endpoint

## Phase 3
- Solana adapter via Helius
- Validation that the chain abstraction actually holds

## Phase 4
- DeBridge cross-chain link decoder
- Wormhole VAA decoder
- Across, Stargate, Symbiosis, 1inch Fusion bridge decoders
- Hyperliquid native bridge decoder

## Phase 5
- Cross-case entity database (SQLite to start)
- "This address appeared in case X — see also" cross-references
- Perpetrator-cluster tracking

## Operational / ops-quality
- Web UI (FastAPI + simple frontend) — only if CLI proves limiting
- Docker image for reproducible runs
- Log shipping to S3/GCS for chain-of-custody durability
- Signed evidence packages (sign the case folder with a Recupero key, verifiable later)
- Resumable traces (pick up from last fetched block on crash)

## Data quality / labels
- Pull labels from public sources on a schedule:
  - Etherscan address tags (web scrape with rate limits / TOS check)
  - Solscan labels (Phase 3+)
  - Community-maintained lists (Ofac sanctions list, OFSI, etc.)
- OFAC SDN list integration — flag any sanctioned address loudly
- Token contract → CoinGecko ID auto-mapping (use CoinGecko's `/coins/list` once, store)

## Pricing improvements
- Sub-daily price granularity (CoinGecko paid tier or Pyth historical)
- Stable-coin shortcut: USDT/USDC/DAI ≈ $1, skip API call (with footnote)
- Swap-aware pricing: when a transfer is part of a DEX swap, use the swap's effective rate

## Reporting (later than Phase 2)
- Native DOCX export (use the docx skill)
- Native PDF export with embedded fonts
- Recupero-branded report template
- LE-contact directory: per-exchange, per-jurisdiction handoff info
- Pre-drafted preservation-letter template per exchange

## Things explicitly NOT to build
- Active monitoring / alerting on wallets — different product, different risk profile
- A "this address is bad/good" classifier that auto-labels — too easy to be wrong, too hard to defend in court. Labels stay manually curated.
- Anything that interacts with chain (signing, transactions). We are read-only forever.
