# Chain Coverage Status (v0.20.0)

Generated: 2026-05-20. Audits the 16 chains declared in `recupero.models.Chain`
and recommends additions for the next phase of chain work.

## Executive summary

* **16 chains** declared in `Chain` enum (`src/recupero/models.py:29-73`).
* **Real adapter code** exists for 4 chain "families":
  * `chains/ethereum/adapter.py` (thin wrapper over `EvmAdapter`)
  * `chains/evm/adapter.py` (handles Ethereum + 10 other EVM chains via Etherscan V2 `chainid`)
  * `chains/solana/adapter.py` (Helius)
  * `chains/tron/adapter.py` (TronGrid)
  * `chains/bitcoin/adapter.py` (Esplora)
  * `chains/hyperliquid/scraper.py` (Hyperliquid info-endpoint scraper — **NOT** a ChainAdapter)
* **The 11 EVM chains share one adapter.** Per-chain differences are isolated
  to `EvmChainProfile` (`chains/evm/adapter.py:34-44`) — `chain_id`,
  `native_symbol`, `explorer_base`, `coingecko_native_id`, `coingecko_platform`.
* **Production-verified chains (real-money traces):** Ethereum, Arbitrum,
  Solana, Hyperliquid (per `docs/chain-coverage.md`). All others are
  **untested in production**.
* **The 7 chains added in v0.20.0** (optimism, avalanche, linea, blast,
  zksync, scroll, mantle) are wired into:
  * `Chain` enum
  * `EvmChainProfile` resolver (`_profile_for`)
  * `ADDRESS_EXPLORER_BY_CHAIN`
  * `_CHAIN_ID_BY_NAME` (watch_tick)

  ...and are **missing from**:
  * `_CHAIN_TO_CG_PLATFORM` (pricing/coingecko.py:37) — no contract→USD lookup
  * `_CANONICAL_STABLECOIN_CONTRACTS` — no $1.00 par for USDC/USDT on these chains
  * `_CASE_INSENSITIVE_CHAINS` (pricing) — falls back to base58-exact compare for EVM hex (functionally still works because hex matches lowercase, but semantically wrong)
  * `issuers.json` — no stablecoin freeze targets registered
  * `tests/test_chain_dispatch.py` — only the original 4 EVM chains covered

## Per-chain audit

### Ethereum

* **Adapter:** `chains/ethereum/adapter.py` → wraps `EvmAdapter`. Profile in `config.py:62-68`. chain_id=1.
* **Operations:** native ETH outflows (txlist + internal), ERC-20 outflows (tokentx), `is_contract` via `getsourcecode`, evidence receipts (`eth_getTransactionByHash`, receipt, block). Wrapped-ETH passthrough filter (`_WRAPPED_NATIVE_CONTRACTS`). Reverted-tx filter, contract-creation filter, self-transfer filter, NFT-shaped row rejection.
* **Known gaps:** Native ETH historical pricing fails on CoinGecko Demo tier (per `docs/chain-coverage.md`). Etherscan pagination caps oldest 1000 txs.
* **Pricing:** `Chain.ethereum` → `"ethereum"` platform. Native ETH coingecko id `"ethereum"`. Canonical stables present: USDT/USDC/DAI/BUSD/FDUSD/TUSD/USDP/PYUSD.
* **Labels:** **27 issuer entries** (most of any chain); cex_deposits.json contains ~57 entries (all unmarked but EVM-shaped → effectively Ethereum); bridges.json ~26 entries (Ethereum L1 deployments); mixers.json (Tornado Cash variants, Sinbad, Railgun, FixedFloat); defi_protocols.json ~30 entries.
* **Tests:** `tests/test_ethereum_adapter.py`, plus broad coverage via test_tracer / test_brief / test_evidence / test_etherscan_block_clamp / test_chain_dispatch.
* **Freeze-pathway:** **Complete.** USDT, USDC, DAI, BUSD, PYUSD, USDP, TUSD, FDUSD, syrupUSDC/syrupUSDT, FRAX/sFRAX, WBTC, cbBTC, aUSDC/aUSDT/aDAI delegation chain, msyrupUSDp.

### Solana

* **Adapter:** `chains/solana/adapter.py` (Helius backend). `block_at_or_before` returns unix-ts not slot (Solana has no slot-at-ts API). chain_id n/a.
* **Operations:** SOL outflows (Helius `parsed-transactions` → `nativeTransfers`), SPL outflows (`tokenTransfers`), `is_contract` via `account_info.executable`. Address normalization via `normalize_solana_address` (round-9 CRIT fix). Pre-cached coingecko IDs for USDC/USDT/JUP/BONK/JitoSOL/mSOL/WSOL.
* **Known gaps:** No slot-windowed fetch (uses ts cutoff client-side). Unknown SPL tokens fall through unpriced (Birdeye not wired). Aside from the static mint→coingecko map, contract→id lookup is not implemented.
* **Pricing:** `Chain.solana` → `"solana"`. Canonical stables: USDC (`EPjFW…Dt1v`), USDT (`Es9vM…wNYB`) — case-preserved per round-11 pricing-CRIT-003.
* **Labels:** 2 issuer entries (USDC, USDT). 1 high_risk entry (Lazarus Group DPRK Solana wallet, OFAC SDN 2023-08-22). **Zero cex_deposit entries** — all CEXes in the seed have only their EVM hot wallets, none of their Solana deposit addresses.
* **Tests:** `tests/test_solana_address.py`, `tests/test_solana_helpers.py`.
* **Freeze-pathway:** **Functional but thin.** Circle USDC + Tether USDT freezable; no other tokens registered.

### Tron

* **Adapter:** `chains/tron/adapter.py` (TronGrid backend). chain_id n/a; tron uses unix-ts cutoff like Solana.
* **Operations:** TRC-20 outflows via `/v1/accounts/{addr}/transactions/trc20`. **Native TRX outflows implemented** (v0.32.1 CRIT-2, `fetch_native_outflows` → `get_native_transactions`, filters `raw_data.contract[0].type=="TransferContract"`). `is_contract` via `/v1/accounts/{addr}` `type=="Contract"`. Evidence receipts via `wallet/gettransactionbyid` + `wallet/gettransactioninfobyid` + `wallet/getblockbynum`. `min_timestamp` threading added in v0.18.5 (round-11 CRIT-006) — previously dropped, causing full-history fetches to truncate the oldest 10k rows = incident period.
* **Monitoring:** **watch_tick supported** (#4) — `_run_tron_chain` / `_snapshot_tron_one` value a watched Tron wallet's confirmed native-TRX balance (`account_balances` → `/v1/accounts`) plus priceable TRC-20 balances (`TRC20_TOKEN_META`: USDT/USDC/USDD/JST), each via CoinGecko. Closes the reach↔monitor loop (previously every `tron` row was `skipped_unsupported_chain`).
* **Pricing:** `Chain.tron` → `"tron"`. Canonical stables: USDT (`TR7NHq…6t`), USDC (`TEkxi…dz8`), USDD (`TNUC9…WFR` — round-11 pricing-CRIT-002 fixed case).
* **Labels:** 3 issuer entries (USDT, USDC, USDD) + 7 cex_deposit/hot-wallet entries. No bridge entries that resolve on Tron specifically (bridges.json's `supports_to_chains` includes "tron" for AllBridge Core only).
* **Tests:** `tests/test_tron_address.py`, `tests/test_tron_client.py`, `tests/test_tron_adapter.py`.
* **Freeze-pathway:** **Strong** — USDT-TRC20 is Tether's largest stablecoin deployment; LE-responsive. USDC-Tron + USDD-Tron also covered (USDD `limited`).

### Bitcoin

* **Adapter:** `chains/bitcoin/adapter.py` (Esplora — blockstream/mempool.space free tier). Binary-search `block_at_or_before` (~20 round-trips).
* **Operations:** UTXO→Transfer normalization via peel-chain heuristic (first input = canonical sender; outputs not matching input set = sends). `fetch_erc20_outflows` returns `[]` (no token standard). CoinJoin detection + probabilistic unwrap via `trace/coinjoin_unwrap` (≥4 inputs + ≥3 equal-value outputs → enumerate participant hypotheses; high-confidence emit synthetic transfers).
* **Known gaps:** Multi-input traces are partial (only first input gets a Transfer). `is_contract` always False (BTC has no contracts). Ordinals/BRC-20/Runes not surfaced.
* **Pricing:** `Chain.bitcoin` → not in `_CHAIN_TO_CG_PLATFORM` (BTC has no contracts — pricing is just the native coingecko id `"bitcoin"`).
* **Labels:** **Zero entries across all label files.** No Bitcoin addresses in issuers/cex_deposits/bridges/defi/mixers/high_risk. Bitcoin trace is adapter-only — every counterparty surfaces as unlabeled.
* **Tests:** `tests/test_bitcoin_address.py`, `tests/test_bitcoin_esplora.py`, `tests/test_bitcoin_adapter.py`, `tests/test_coinjoin_unwrap.py`.
* **Freeze-pathway:** N/A (BTC is permissionless — no issuer-level freeze; only exchange-level via deposit-address subpoenas).

### TON (The Open Network)

* **Adapter:** `chains/ton/adapter.py` (TON Center backend). v0.38.0 (Gap#3). Major DPRK/scam off-ramp; USDT-TON (a Jetton) is the dominant stablecoin-laundering rail, mirroring USDT-TRC20 on Tron. `block_at_or_before` returns a unix-ts cutoff (TON has no ts→block index at the free tier); fetches window on `utime`/`transaction_now`.
* **Operations:** Native TON outflows via v2 `getTransactions` (an outflow = an `out_msg` with positive `value`, nanoton/9-dec). Jetton outflows via v3 `jetton/transfers` (already-decoded source/destination/amount — no cell parsing). `is_contract` returns False (TON wallets are contracts but behave as accounts; protocol classification is label-driven).
* **Address codec:** `chains/ton/address.py` — raw `0:hex` ↔ user-friendly base64url (workchain tag + CRC16-CCITT). Everything canonicalizes to raw lower-cased form so v2 (friendly) and v3 (raw) match. Verified against live raw↔friendly vectors.
* **Pricing:** `Chain.ton` → `"the-open-network"` (native TON coingecko id + Jetton contract→id resolution). USDT-TON jetton master `0:b113a9…3621dfe` → tether (6-dec) in `_JETTON_META`.
* **Labels:** Zero TON entries yet (adapter-only; counterparties surface unlabeled). USDT-TON master is the one priceable jetton wired.
* **Known gaps:** watch_tick monitoring not yet wired (like the BTC gap before v0.37.5). Only USDT-TON jetton is priced (other jettons skipped rather than guess decimals). Evidence receipt is explorer-anchored (no by-(lt,hash) raw receipt).
* **Tests:** `tests/test_ton_address.py` (codec vs live vectors), `tests/test_ton_adapter.py` (native + Jetton normalization, injected-client + respx transport).
* **Freeze-pathway:** USDT-TON is Tether-issued → same issuer-freeze pathway as USDT on other chains (subject to issuer contact coverage).

### Arbitrum

* **Adapter:** Shared `EvmAdapter`. chain_id=42161. native=ETH, explorer=arbiscan.io.
* **Operations:** All EvmAdapter ops. In `_CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS` (round-11 chains-MED-001).
* **Pricing:** `Chain.arbitrum` → `"arbitrum-one"`. Native id `"ethereum"`. Canonical stables: USDC (`0xaf88…5831`), USDT (`0xfd086…cbb9`), DAI, USDC.E.
* **Labels:** 2 issuer entries (USDC, USDT). 1 bridge entry (Arbitrum Inbox `0x4dbd…3f`, L1ERC20Gateway `0xa3a7…ec`). CEX hot-wallets shared with Ethereum via address-only store.
* **Tests:** `tests/test_chain_dispatch.py` (profile + dispatch), `tests/test_v6.py`, `tests/test_v7.py`, `tests/test_v12.py` (canonical-stable check), `tests/test_v15.py`.
* **Freeze-pathway:** **Complete** — USDC + USDT both via standard Circle/Tether channels.

### Base

* **Adapter:** Shared `EvmAdapter`. chain_id=8453. native=ETH, explorer=basescan.org. In `_CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS`.
* **Pricing:** `Chain.base` → `"base"`. Native id `"ethereum"`. Canonical stables: USDC (`0x833589…0913`). **No USDT entry** (USDT isn't natively issued on Base — bridge-wrapped variants would route through CoinGecko contract lookup).
* **Labels:** 0 issuer entries explicitly chain-tagged "base". 1 bridge entry (L1 Standard Bridge `0x3154…2c35`).
* **Tests:** `tests/test_chain_dispatch.py` (profile + dispatch). Status per `docs/chain-coverage.md`: "Untested" — code present, no real trace yet.
* **Freeze-pathway:** **Gap.** Need to register Base USDC (`0x833589…0913`, issuer Circle) in `issuers.json`. Per the seed, it's not there.

### BSC

* **Adapter:** Shared `EvmAdapter`. chain_id=56. native=BNB. Per `docs/chain-coverage.md`: **Etherscan V2 free tier rejects BSC** ("Free API access is not supported for this chain"). Real BSC traces require paid Etherscan or bscscan-direct or RPC swap.
* **Pricing:** `Chain.bsc` → `"binance-smart-chain"`. Native id `"binancecoin"`. Canonical stables: USDT (`0x55d…7955`), USDC (`0x8ac7…580d`), BUSD (`0xe9e7…7d56`), DAI.
* **Labels:** 3 issuer entries (USDT, USDC, BUSD). 1 BSC mixer entry (Tornado Cash 40 BNB `0x0768…2730`). Bridge support indirect via Multichain (defunct), Celer, Synapse `supports_to_chains: ["bsc"]`.
* **Tests:** `tests/test_chain_dispatch.py`, `tests/test_v6.py`, `tests/test_v7.py`, `tests/test_v12.py`.
* **Freeze-pathway:** **Complete contract-level**, but **API access is the bottleneck** — operator must upgrade to paid Etherscan or wire bscscan direct.

### Polygon

* **Adapter:** Shared `EvmAdapter`. chain_id=137. native=POL (renamed from MATIC 2024-09-04 — coingecko_native_id now `"polygon-ecosystem-token"`; pre-rebrand cases need config override to `"matic-network"` per round-9 HIGH fix). In `_CLIENT_SIDE_STARTBLOCK_FILTER_CHAIN_IDS`.
* **Pricing:** `Chain.polygon` → `"polygon-pos"`. Canonical stables: USDC (native `0x3c49…3359`), USDT (`0xc213…8e8f`), DAI.
* **Labels:** 2 issuer entries (USDC, USDT). 2 bridge entries (RootChainManager `0xa0c6…c77`, ERC20Predicate `0x40ec…bdf`).
* **Tests:** `tests/test_chain_dispatch.py`. "Untested" per `docs/chain-coverage.md`.
* **Freeze-pathway:** **Complete.**

### Hyperliquid

* **Adapter:** **NOT a ChainAdapter** — `chains/hyperliquid/scraper.py` produces a `Case` directly from the `userNonFundingLedgerUpdates` endpoint. Synthesizes withdrawals/deposits as USDC-on-Arbitrum Transfers (Hyperliquid's native bridge lands USDC on Arbitrum).
* **Operations:** Withdraw + deposit ledger events only. Round-11 chains-MED-009: filters by `delta_type ∈ {"withdraw", "deposit"}` to exclude internal accounting events (position transfers, class transfers). No native `block_at_or_before` / `is_contract` / `fetch_native_outflows` / `fetch_erc20_outflows` / `fetch_evidence_receipt`. No `Chain.hyperliquid` factory entry in `ChainAdapter.for_chain`.
* **Pricing:** USDC pegged to $1.00 in-line (`pricing_source="hyperliquid_native_usdc"`). No CoinGecko platform mapping needed.
* **Labels:** Zero entries (the scraper writes synthetic transfers; counterparty addresses appear as `hyperliquid:unknown_source` / `unknown_destination` placeholders).
* **Tests:** `tests/test_hyperliquid_helpers.py`.
* **Freeze-pathway:** Hyperliquid's own bridge withdraws to Arbitrum USDC — freeze pathway is **Circle Arbitrum-USDC**, identical to Arbitrum.
* **Enum gap closed in v0.20.0:** `Chain.hyperliquid` member added per round-13 type-MED-8. Code paths that previously did `chain="hyperliquid"` string comparison can now use the enum, BUT the scraper still assigns `Case.chain = Chain.ethereum` (line 76-77 of scraper.py) — comment notes this is "now upgradable to Chain.hyperliquid" but not yet upgraded.

### Optimism (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=10. native=ETH, explorer=optimistic.etherscan.io.
* **Pricing:** **GAP** — `Chain.optimism` not in `_CHAIN_TO_CG_PLATFORM`. Profile has `coingecko_platform="optimistic-ethereum"` but no pricing-side mapping. Token contract→USD lookups fall back to per-chain unknown. **No `_CANONICAL_STABLECOIN_CONTRACTS` entries** for USDC (`0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85`) or USDT (`0x94b008aA00579c1307B0EF2c499aD98a8ce58e58`) — any legit USDC-on-Optimism transfer will fall through to contract-lookup and may be flagged as `spoofed_canonical_symbol` if CoinGecko hiccups.
* **Labels:** Zero issuer entries; 1 bridge (L1 Standard Bridge `0x99c9…be1`).
* **Tests:** **None.** Not exercised in `tests/test_chain_dispatch.py`.
* **Freeze-pathway:** **GAP** — Optimism USDC (Circle, native `0x0b2C…Ff85`) and USDT (Tether, native `0x94b0…58`) need issuer entries to surface freeze contacts.

### Avalanche (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=43114. native=AVAX, explorer=snowtrace.io.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. Profile has `coingecko_platform="avalanche"`, `coingecko_native_id="avalanche-2"`. No canonical stables. Notable: WAVAX (`0xb31f66aa…66c7`) is in `_WRAPPED_NATIVE_CONTRACTS` so wrap/unwrap is filtered correctly.
* **Labels:** Zero issuer entries; 1 bridge (Avalanche Bridge `0x8eb8…ab28`).
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — Avalanche USDC (Circle, native `0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E`) and USDT (Tether, native `0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7`) need issuer entries.

### Linea (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=59144. native=ETH, explorer=lineascan.build. `coingecko_platform="linea"`.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. No canonical stables.
* **Labels:** Zero issuer entries; no bridge entries (Linea bridge not present in bridges.json).
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — Linea USDC (Circle, native `0x176211869cA2b568f2A7D4EE941E073a821EE1ff` bridged via Circle CCTP).

### Blast (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=81457. native=ETH, explorer=blastscan.io. `coingecko_platform="blast"`.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. No canonical stables. Blast has its own native USDB stablecoin (rebasing) — not represented.
* **Labels:** Zero entries.
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — USDB is Blast-native, issued via MakerDAO sDAI underneath; partial freeze posture. Worth investigating for completeness.

### zkSync Era (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=324. native=ETH, explorer=explorer.zksync.io. `coingecko_platform="zksync"`.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. No canonical stables.
* **Labels:** Zero issuer entries; 1 bridge (zkSync Bridge `0x3240…0324`).
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — zkSync USDC (Circle native `0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4`) needs registration.

### Scroll (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=534352. native=ETH, explorer=scrollscan.com. `coingecko_platform="scroll"`.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. No canonical stables.
* **Labels:** Zero entries.
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — Scroll USDC (Circle native `0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4`).

### Mantle (v0.20.0)

* **Adapter:** Shared `EvmAdapter`. chain_id=5000. native=MNT, explorer=mantlescan.xyz. `coingecko_platform="mantle"`, `coingecko_native_id="mantle"`.
* **Pricing:** **GAP** — not in `_CHAIN_TO_CG_PLATFORM`. No canonical stables. Note: Mantle is also the only one of the v0.20.0 chains with a non-ETH native gas token.
* **Labels:** Zero entries.
* **Tests:** **None.**
* **Freeze-pathway:** **GAP** — Mantle USDC (`0x09Bc4E0D864854c6aFB6eB9A9cdF58aC190D0dF9`), USDT (`0x201EBa5CC46D216Ce6DC03F6a759e8E766e956aE`).

## Summary tables

### Adapter & pricing & label heatmap

| Chain        | Adapter        | watch_tick | Pricing platform | Canonical stables | Issuer entries | Tests |
|--------------|----------------|------------|------------------|-------------------|----------------|-------|
| ethereum     | EvmAdapter     | yes        | yes              | 8                 | 27             | rich  |
| arbitrum     | EvmAdapter     | yes        | yes              | 4                 | 2              | yes   |
| base         | EvmAdapter     | yes        | yes              | 1                 | 0              | yes (dispatch only) |
| bsc          | EvmAdapter*    | yes        | yes              | 4                 | 3              | yes   |
| polygon      | EvmAdapter     | yes        | yes              | 3                 | 2              | yes (dispatch only) |
| solana       | SolanaAdapter  | yes        | yes              | 2                 | 2              | yes   |
| tron         | TronAdapter    | yes        | yes              | 3                 | 3              | yes   |
| bitcoin      | BitcoinAdapter | yes        | n/a              | n/a               | **0**          | yes   |
| ton          | TonAdapter     | no         | yes              | 1 (USDT)          | **0**          | yes   |
| hyperliquid  | Scraper        | yes        | inline ($1)      | n/a               | 0              | yes (client helpers only) |
| optimism     | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| avalanche    | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| linea        | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| blast        | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| zksync       | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| scroll       | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|
| mantle       | EvmAdapter     | yes        | **NO**           | **0**             | **0**          | **no**|

`*` BSC: code path present; Etherscan V2 free tier rejects it. Needs paid API.

### Chains with ZERO labels (any category)

* **bitcoin** — adapter-only trace, every counterparty is unlabeled.
* **optimism**, **avalanche**, **linea**, **blast**, **zksync**, **scroll**, **mantle** — the seven v0.20.0 EVM chains have no issuer/cex/bridge entries.

The label-store implementation (`labels/store.py`) does NOT discriminate by chain
for the `cex_deposits.json`, `bridges.json`, `defi_protocols.json`,
`mixers.json` files — entries are keyed by address only. This means **for EVM
chains where a contract is deployed at the SAME address across multiple chains**
(common for proxy/router contracts via CREATE2/deterministic deployment), an
Ethereum-only label will incidentally hit. But CEX hot wallets are
per-deployment-chain — there is no overlap, so the v0.20.0 EVM chains are
effectively label-blind on the most important category (exchange deposits).

### Freeze-pathway readiness

| Chain        | USDC freezable | USDT freezable | Other stables | Status |
|--------------|----------------|----------------|---------------|--------|
| ethereum     | yes (Circle)   | yes (Tether)   | DAI/BUSD/PYUSD/USDP/TUSD/FDUSD | complete |
| arbitrum     | yes (Circle)   | yes (Tether)   | DAI           | complete |
| polygon      | yes (Circle)   | yes (Tether)   |               | complete |
| bsc          | yes (Circle)   | yes (Tether)   | BUSD          | complete (API-blocked) |
| base         | **gap — Circle's `0x833589…0913` priced but no issuer entry** |  |     | partial |
| solana       | yes (Circle)   | yes (Tether)   |               | complete |
| tron         | yes (Circle)   | yes (Tether)   | USDD (limited)| complete |
| optimism     | **gap**        | **gap**        |               | none |
| avalanche    | **gap**        | **gap**        |               | none |
| linea        | **gap**        |                |               | none |
| blast        |                |                | USDB-native (gap) | none |
| zksync       | **gap**        |                |               | none |
| scroll       | **gap**        |                |               | none |
| mantle       | **gap**        | **gap**        |               | none |
| bitcoin      | n/a            | n/a            |               | n/a (permissionless) |
| hyperliquid  | via Arbitrum USDC (Circle) | n/a | | inherited |

**Highest-leverage next step:** populate `issuers.json` for the 7 v0.20.0 EVM
chains (Circle USDC native + Tether USDT native per chain where issued). Eight
new JSON entries close eight freeze pathways. Single PR. No code change.

### Tests coverage gap

`tests/test_chain_dispatch.py` covers Ethereum, Arbitrum, BSC, Polygon, Base
only. Adding `test_profile_for_optimism / _avalanche / _linea / _blast /
_zksync / _scroll / _mantle` plus a parameterized dispatch test would close
the regression-test gap from one commit.

## Missing chains worth adding

Industry theft-volume reports (Chainalysis 2024-2025 mid-year, TRM Insights
2025, Elliptic typology analysis 2025-Q3) consistently flag the following as
recurring laundering surfaces beyond the 16 currently supported.

### TON (The Open Network) — **CRIT**

* **Why:** Telegram-native, ~$60M+/month of pig-butchering USDT-TON laundering by mid-2025. The 4-billion-user Telegram funnel makes TON the fastest-growing scam vector. Tether's USDT-TON deployment has issuer freeze capability identical to USDT-ETH/USDT-TRC20.
* **Adapter complexity:** **M.** TON has a fundamentally different VM (TVM, Cells/Bag-of-cells, asynchronous messaging — no synchronous tx-call model). Address format is mixed user/raw with chain bit + workchain. TON Center API (`https://toncenter.com/api/v2/`) is free-tier with optional API key, returns parsed transactions and account states. The address-history endpoint is paginated by `lt` (logical time) + hash — comparable shape to Tron's pagination.
* **Indexer:** **TON Center** (free tier, 1 req/sec unauth, 10 rps with free key), **TON API** by tonkeeper (free tier), **dton.io** (free + paid). All three have JSON REST endpoints suitable for our adapter pattern.
* **Integration plan:** Build `chains/ton/{client,adapter,address}.py` mirroring the Tron module structure — TonClient over TON Center, `block_at_or_before` returns a logical-time unix-ts (TON has masterchain block numbers but no ts→block API at free tier), `fetch_native_outflows` for TON transfers, `fetch_erc20_outflows` for Jetton transfers (TON's fungible-token standard, USDT-TON's underlying). Register issuer entry for Tether USDT-TON (`EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs` master contract). Add `coingecko_platform="the-open-network"` mapping. ~2-3 days of work; high ROI.

### Sui — **HIGH**

* **Why:** Move VM, $26B+ TVL by 2025, recurring DeFi-exploit surface (Cetus $230M Mar 2025). Growing stablecoin surface (Circle launched native USDC-Sui in Mar 2024 with full CCTP). 
* **Adapter complexity:** **M.** Object-centric (not account-centric) — Sui transactions consume + produce typed objects rather than mutating account balances. Address-history requires `suix_queryTransactionBlocks` filtered by sender/recipient. SUI Move call semantics differ enough that the "Transfer" abstraction requires Coin<T> object-transfer events to be mapped.
* **Indexer:** **Sui RPC** (free public nodes via mysten labs/dwallet/nodeReal — generally rate-limited), **BlockVision Sui API** (free + paid), **Blockberry Sui** (paid only). Public RPC suffices for free-tier traces.
* **Integration plan:** Build `chains/sui/{client,adapter,address}.py`. `fetch_native_outflows` queries `suix_queryTransactionBlocks` with `FromAddress` filter; pulls `Coin<0x2::sui::SUI>` transfers. `fetch_erc20_outflows` filters by Coin<T> for non-SUI types (USDC = `0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC`). Register Circle issuer for USDC-Sui. ~3-4 days.

### XRP Ledger — **HIGH**

* **Why:** Issuer-freeze model is uniquely well-defined at the protocol level — `AccountSet TfRequireAuth` + `TrustSet NoFreeze` flags. RLUSD (Ripple stablecoin) launched Dec 2024 with explicit compliance design. USDC-XRPL on the roadmap. Stablecoin freeze pathway potentially the cleanest of any chain.
* **Adapter complexity:** **S–M.** XRPL is a non-Turing-complete ledger with a stable JSON-RPC surface. `account_tx` returns per-address transaction history with `Payment` (native + issued currency), `OfferCreate` (DEX), etc. Address format is `r…` base58.
* **Indexer:** **XRPL Public RPC** (free, multiple nodes: `s1.ripple.com`, `xrplcluster.com`), **Bithomp API** (free + paid), **XRPSCAN API** (free). All free-tier-friendly.
* **Integration plan:** Build `chains/xrpl/{client,adapter,address}.py`. `fetch_native_outflows` calls `account_tx` filtered to Payment-type with native XRP; `fetch_erc20_outflows` filters to issued-currency Payments (RLUSD = currency code "RLUSD" + issuer `rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De`). Register Ripple/RLUSD in issuers.json (freeze via Ripple compliance). Map `coingecko_platform="xrp"`. ~2-3 days.

### Stellar — **MED-HIGH**

* **Why:** Circle issues USDC-Stellar with the same freeze capability as USDC-Ethereum (Issuer authorization revocation). MoneyGram/Anchor partnerships make it a real on-/off-ramp. Less stolen-fund volume than the others on this list but Circle's freeze power gives it asymmetric value.
* **Adapter complexity:** **S.** Stellar Horizon API is extremely well-documented REST. `accounts/{id}/payments` returns paginated payment history with built-in pagination cursors.
* **Indexer:** **Horizon** (free, official Stellar Foundation — `https://horizon.stellar.org`). No auth.
* **Integration plan:** Build `chains/stellar/{client,adapter,address}.py`. `fetch_native_outflows` for XLM payments; `fetch_erc20_outflows` for issued-asset payments (USDC = code "USDC" + issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`). Register Circle USDC-Stellar in issuers.json. Map `coingecko_platform="stellar"`. ~1-2 days.

### Aptos — **MED**

* **Why:** Move VM sister chain to Sui. Smaller but recurring drainer/scam surface; some Lazarus laundering on Aptos in 2024-2025 reports. Native USDC via Circle CCTP since Jul 2024.
* **Adapter complexity:** **M.** Similar shape to Sui (Move-based, resource model) but with account-centric semantics that map slightly cleaner to the Transfer model. Aptos REST API (`/accounts/{addr}/transactions`) is straightforward.
* **Indexer:** **Aptos RPC** (free public nodes by aptoslabs/blockberry), **Blockberry Aptos** (free + paid).
* **Integration plan:** Symmetric to Sui — `chains/aptos/…`. Free-tier RPC. Register Circle USDC-Aptos. ~3 days. Lower priority than Sui because lower theft volume.

### Near — **LOW-MED**

* **Why:** NEAR Foundation operates Rainbow Bridge (NEAR↔ETH); cross-chain endpoint matters for trace continuation. Smaller native scam volume.
* **Adapter complexity:** **M.** NEAR RPC is gRPC-friendly; REST shim available. Account names (`alice.near`) are human-readable strings, not hex/base58 — address normalization is distinct.
* **Indexer:** **NEAR RPC** (free public), **NEAR Indexer** (paid for full history), **NEARBlocks API** (free + paid).
* **Integration plan:** Mostly valuable as a bridge-trace continuation, not as a primary investigation chain. Defer until a real Near case lands.

### Cardano — **LOW**

* **Why:** Low theft volume per industry reports. Native asset standard is permissioned-mintable but not widely used for laundering.
* **Adapter complexity:** **M-L.** UTXO model (like Bitcoin) but with native multi-asset support and a different address format (bech32 with stake-key concatenation). Native peel-chain heuristic needs adaptation.
* **Indexer:** **Blockfrost** (free tier 50k req/day), **Koios** (free decentralized).
* **Integration plan:** Skip until a real Cardano case lands.

### Priority ranking

1. **TON** (CRIT) — highest theft volume of any unsupported chain in 2025-2026; Tether USDT-TON is a clean freeze pathway. **Build first.**
2. **XRP Ledger** (HIGH) — uniquely clean issuer-freeze model; RLUSD stablecoin growth.
3. **Sui** (HIGH) — DeFi exploit surface + native USDC CCTP.
4. **Stellar** (MED-HIGH) — small but strategic; cheapest adapter, complete freeze pathway.
5. **Aptos** (MED) — mirror of Sui's work; do alongside Sui.
6. **Near** (LOW-MED) — defer.
7. **Cardano** (LOW) — defer indefinitely.

## Recommended immediate work (no new chains)

These close existing v0.20.0 gaps before adding chains:

1. **Add 7 entries to `_CHAIN_TO_CG_PLATFORM`** for optimism/avalanche/linea/blast/zksync/scroll/mantle. Five-minute edit; immediately enables contract→USD pricing.
2. **Add `_CANONICAL_STABLECOIN_CONTRACTS` entries** for USDC + USDT native deployments on each of those 7 chains. ~14 entries. Prevents legitimate stablecoin transfers from being flagged as spoof.
3. **Add `issuers.json` entries** for Circle USDC + Tether USDT (where issued) on the 7 v0.20.0 chains. Enables freeze briefs to surface contacts.
4. **Add `_CASE_INSENSITIVE_CHAINS` entries** for the 7 v0.20.0 EVM chains (currently only the original 5 EVM chains + bitcoin are listed; the new ones fall through to base58-exact compare for EVM hex, which works by coincidence but is semantically wrong).
5. **Extend `tests/test_chain_dispatch.py`** with `test_profile_for_*` per new chain + a parameterized dispatch test covering all 11 EVM chains.
6. ~~**Wire Tron + Bitcoin into `watch_tick`**~~ **DONE** — Bitcoin (v0.37.5, `_run_bitcoin_chain`) and Tron (#4, `_run_tron_chain` / `_snapshot_tron_one`) now have non-EVM watch_tick handlers analogous to `_run_solana_chain`.
7. **Upgrade Hyperliquid scraper to use `Chain.hyperliquid`** in `Case.chain` (currently set to `Chain.ethereum` per scraper.py:76-77 with a "now upgradable" comment).
8. ~~**Implement native TRX outflows in `TronAdapter.fetch_native_outflows`**~~ **DONE** (v0.32.1 CRIT-2) — filters `TransferContract` from `get_native_transactions`.

Combined, items 1-8 are sub-1-day-each (1+2+3+4 are ~2 hours of JSON/Python edits) and double the effective coverage of the existing 16 chains before any new chain work begins.

## EVM → Bitcoin reach (deep-reach #4)

**Status (v0.37.4): SHIPPED + VERIFIED — a THORChain EVM→BTC swap is decoded to
its native-Bitcoin destination at `high` confidence and the trace AUTO-CROSSES
onto the Bitcoin chain end-to-end.** Verified against a real on-chain tx
(`0x0e9a9c2e…a721`, THORChain Router v4.1.1, memo
`=:BTC.BTC:bc1q8w2ypqgx39gucxcypqv2m90wz9rvhmmrcnpdjs:117760` →
`destination_chain=bitcoin` + that address); fixture at
`tests/fixtures/thorchain_btc_swap.json`. The current v3.0.1 + v4.1.1 routers
were added to `bridges.json` (the v0.34 seed only had the legacy v2 router, so
present-day THORChain swaps were undetected).

What's in place so the trace reaches Bitcoin end-to-end the moment a destination
is decoded at `high`:

* `Chain.bitcoin` is in the enum; `BitcoinAdapter` (Esplora, UTXO peel-chain
  normalization) is registered in the chain factory.
* The **THORChain Router** is a verified bridge seed (`bridges.json`, v0.34,
  on-chain confirmed, `0xc145…c2ce`).
* **v0.37.3: `_decode_thorchain` (`trace/bridge_calldata.py`)** parses the swap
  MEMO — `<fn>:<CHAIN.ASSET>:<destination>:…` — and extracts the destination
  chain + address. `BTC.BTC` → `destination_chain="bitcoin"` + the bech32/base58
  BTC address; other chains (DOGE/LTC/…) surface raw for the candidates list.
* The cross-chain seed path does `Chain(decoded_destination_chain)` +
  `ChainAdapter.for_chain(...)` — both resolve `bitcoin`. With the v0.37.1
  full-depth + multi-bridge continuation, a `high`-confidence BTC destination is
  followed onto the Bitcoin chain end-to-end.
* Wrapped-BTC at a terminal (tBTC / WBTC / cbBTC) is also classified via the
  issuer DB (Threshold / BitGo / Coinbase) and surfaced as TRACKED/subpoena
  leads — so a redemption candidate is never silently dropped.

Confidence calibration (v0.37.4):

* `high` ONLY for a destination whose SHAPE matches a chain we can continue on —
  BTC bech32 (`bc1…`) / base58 (`1…`/`3…`), or ETH `0x`+40hex — so a THORName or
  a malformed memo can't earn a high-confidence auto-cross. `high` BTC/ETH
  destinations auto-seed the cross-chain continuation.
* `medium` for a raw-surfaced chain we have no adapter for (DOGE/LTC/BCH/…) or an
  unvalidated address shape — surfaced as a handoff candidate, not auto-crossed.
* `low` for an unparseable memo (recognized as THORChain, no destination).

Remaining limitation (honest): **custodial** wrapped-BTC redemption (WBTC/tBTC →
BTC) still settles off-chain — that BTC destination is in the custodian's
records, not the EVM tx, so it stays a subpoena lead (already surfaced via the
issuer DB). THORChain is the on-chain-decodable EVM→BTC path and is now covered.
