# Chain coverage — what works, what doesn't, and why

Last verified: 2026-04-20, against the Zigha case.

## Status matrix

| Chain        | Adapter     | Tier   | Status         | Verified       | Notes |
|--------------|-------------|--------|----------------|----------------|-------|
| Ethereum     | EvmAdapter  | Free   | ✅ Production  | 25+ live cases | Hundreds of transfers traced cleanly. |
| Arbitrum     | EvmAdapter  | Free   | ✅ Works       | 2 live cases   | Needs the startblock workaround (patch v7). USD pricing incomplete — USDC shows up unpriced. |
| BSC          | EvmAdapter  | **Paid**| ❌ Blocked    | Error verified | Etherscan V2 free tier rejects BSC: `Free API access is not supported for this chain`. Need paid Etherscan plan, alternative API (bscscan free tier, Alchemy), or public RPC. |
| Solana       | SolanaAdapter (Helius) | Free | ✅ Works | 1 live case | USD pricing works for USDC/USDT/SOL/JitoSOL/mSOL/BONK/JUP; other mints fall through unpriced. |
| Hyperliquid  | Scraper (not adapter) | Free | ✅ Works | 2 live cases | Data model maps awkwardly to our Transfer abstraction — ledger events recorded as synthetic Transfers. USDC flows documented; no perp-position reconstruction. |

## Known issues by chain

### Arbitrum
- **USD pricing for tokens other than native ETH is broken.** The CoinGecko `_resolve_cg_id` hardcodes `platform="ethereum"`, so Arbitrum USDC (`0xaf88d065...`) is looked up at the Ethereum platform path and returns 404. Fix: make `_resolve_cg_id` chain-aware (use `platform="arbitrum-one"` for Arbitrum tokens). Tracked as backlog.
- **Block-to-timestamp queries return values that make `startblock` misbehave** on Etherscan V2's Arbitrum endpoint. Worked around by querying with `startblock=0` and filtering client-side. See patch v7.

### BSC
- **Free-tier blocked entirely.** We ship the code path but any real call returns the tier error. The CLI surfaces this cleanly rather than crashing.

### Solana
- **Label lookups case-insensitively.** Base58 is case-sensitive; if you ever label a Solana address and do a lookup with different case, it can miss. Not a problem in practice because labels are stored and looked up through the same normalization.
- **Pricing falls through for unknown SPL tokens.** Static map covers major tokens. Birdeye API would fix this but isn't wired up.

### Hyperliquid
- **"unknown_source" counterparties pollute aggregates.** Hyperliquid deposits come with no origin address on the API. Scraper records them with `from="hyperliquid:unknown_source"`, which then shows up in the aggregate's victim-wallet table. Functional but ugly.
- **Not a full perp analysis.** Only withdrawals, deposits, and account transfers are captured. Fill-level trade reconstruction and liquidation events are not. Sufficient for the Zigha-style "money in, money out" questions; insufficient for "what perp positions did the perpetrator open/close."

### Ethereum
- **Native ETH historical pricing doesn't work** on CoinGecko Demo tier. Every ETH transfer shows `usd=None`. Workaround: use `/market_chart/range` endpoint (not yet implemented).
- **Inspector's first/last seen can be wrong** for high-volume addresses (Etherscan pagination returns oldest 1000 txs).

## Adding a new chain

### For an EVM chain supported by Etherscan V2 free
1. Add a new `<Chain>Params` dataclass to `config.py` with `chain_id`, `api_base`, `explorer_base`, `coingecko_platform`, `coingecko_native_id`.
2. Register it in `RecuperoConfig`.
3. Add a branch to `_profile_for` in `chains/evm/adapter.py`.
4. Add the chain to the `ChainAdapter.for_chain` factory.
5. Add the new enum value to `models.Chain`.
6. If the chain suffers from the Arbitrum startblock quirk, add its chain_id to `_CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS`.
7. Verify with a real trace before claiming support.

### For a non-EVM chain
Decide up front whether the chain's data model fits our `ChainAdapter` interface cleanly (Solana does, barely) or whether it needs a separate scraper pattern (Hyperliquid does). Non-EVM adapters should skip `to_checksum_address` normalization (see tracer.py chain gate).

## What "verified" means

A chain is considered verified when:
1. At least one real trace against a real address has run without Python exceptions.
2. The returned data has been spot-checked against the chain's public block explorer.
3. Tests exist that exercise the adapter with mocked API responses covering the primary flows.

"Supported" in code but not "verified" is a red flag — it means the code compiles and tests pass but no one has actually run it in anger. BSC was in that state until today; the truth is it's not supported on our free tier at all.
