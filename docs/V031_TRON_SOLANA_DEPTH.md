# v0.31 Tron USDT + Solana SPL trace-depth audit (Gaps #6 & #7)

Generated 2026-05-26 against the `pdf-deliverables` branch. Companion
to `tests/test_v031_tron_depth.py` and `tests/test_v031_solana_depth.py`.

## Scope

Two chains carry the majority of stablecoin laundering volume yet
have lighter test coverage than the EVM adapters:

* **Tron** — ~half of all USDT circulating supply lives as
  USDT-TRC20. Adapter at `src/recupero/chains/tron/adapter.py`,
  client at `src/recupero/chains/tron/client.py` (the task wording
  refers to `trongrid.py` — the file is `client.py`).
* **Solana** — fastest-growing stablecoin rail post-2024; USDC is
  dominant, USDT presence smaller than EVM/Tron. Adapter at
  `src/recupero/chains/solana/adapter.py`, client at
  `src/recupero/chains/solana/helius.py`.

This audit checks the depth of each adapter through three layers:
the adapter contract itself, the cross-chain handoff seam, and
what would require live network access to verify.

## Tron USDT — what is solid

* **TRC-20 normalization** is correct end-to-end. Adapter wires
  USDT (`TR7NHq…6t`), USDC (`TEkxi…dz8`), USDD (`TPYmH…PDn`), and JST
  to their CoinGecko IDs (`adapter.py` lines 428–437); pricing
  doesn't fall back to slow per-tx lookups.
* **TRX vs TRC-20 distinction** — adapter intentionally returns
  `[]` from `fetch_native_outflows`. The decision is documented
  (USDT laundering is the primary surface; pure-TRX cases are
  rare). Pinned in `test_v031_tron_depth.py::test_native_trx_outflows_returns_empty_by_design`.
* **Time-window threading** — `block_at_or_before` returns
  unix-seconds; `fetch_erc20_outflows` multiplies by 1000 to pass
  TronGrid's millisecond `min_timestamp`. The v0.18.5 round-11
  CRIT-006 fix is locked by `test_min_timestamp_threaded_through_to_trongrid`.
* **Evidence receipts** — v0.17.5 wired
  `gettransactionbyid` + `gettransactioninfobyid` + `getblockbynum`
  into `EvidenceReceipt`. Pre-v0.17.5 every Tron freeze letter
  carried an empty chain-of-custody bundle; round-10 fix verified
  in `test_tron_adapter.py::test_evidence_receipt_assembles_three_endpoint_bundle`.
* **Wormhole EVM→Tron handoff** — `bridge_calldata.py` lines
  407–419 decode the 21-byte Tron payload to a proper base58check
  address starting with `T`. Pinned in
  `test_wormhole_eth_side_recipient_chain_18_decodes_to_tron`.
* **Adversarial defenses** — extreme/negative timestamps clamped
  (`test_tron_adapter_adversarial.py`); TronGrid 5xx is retryable
  (`client.py` line 354); pagination fingerprint stuck-loop guard
  (line 224).

## Tron USDT — concrete gaps

1. **Zero Tron-keyed bridge rows in `bridges.json`.** The seed file
   has 43 Ethereum + 28 Arbitrum + … entries, but no `"chain": "tron"`
   row. Consequence: a USDT-TRC20 transfer landing at a Tron-side
   bridge program (JustBridge, Sun.io, AllBridge-on-Tron, Wormhole's
   Tron portal) is silently undetected by
   `identify_cross_chain_handoffs`. The EVM→Tron side IS decodable;
   it's the Tron→EVM direction that bottlenecks.
   Pinned by `test_tron_keyed_bridge_db_is_empty_today`; the
   forward-compat lock `test_tron_keyed_bridge_db_lookup_works_when_populated`
   confirms ingestion accepts Tron rows once added.
2. **Zero Tron-keyed CEX deposit rows in `cex_deposits.json`.** All
   39 entries are Ethereum-shaped. Binance/OKX/KuCoin Tron hot
   wallets exist (public Tronscan tags), but recupero's labeler has
   nothing to match against — a trace that follows USDT-TRC20 to
   `TJRabP…RTv8` (Binance public Tron hot wallet) shows it as an
   unlabeled EOA. Pinned by `test_cex_deposits_seed_has_no_solana_or_tron_entries_today`
   (shared assertion with Solana).
3. **No native TRX outflow support.** Documented design choice — see
   the "solid" section above. Mentioned here so it's not forgotten.

## Solana SPL — what is solid

* **SPL normalization** for USDC (`EPjFW…Dt1v`), USDT
  (`Es9vM…wNYB`), WSOL (`So111…112`), JitoSOL, mSOL, BONK, JUP all
  carry CoinGecko IDs (`adapter.py` lines 64–77). Unknown mints
  degrade gracefully (`_symbol_from_mint` returns `mint[:4]` or
  `"?"`).
* **Wrapped SOL vs native SOL** — distinct flows. Native SOL via
  `nativeTransfers` produces `TokenRef(contract=None, symbol="SOL",
  decimals=9)`; WSOL via `tokenTransfers` produces
  `TokenRef(contract="So111…112", symbol="WSOL")`. Pinned in
  `test_wrapped_sol_vs_native_sol_distinction`.
* **Token-2022 transparency** — Helius normalizes SPL Token and
  Token-2022 program transfers into the same `tokenTransfers`
  shape; the adapter consumes that shape uniformly without
  inspecting `programId` / `tokenStandard`. This is the desired
  behavior for value-tracing. Pinned in
  `test_token_2022_transfer_normalizes_identically_to_classic_spl`.
* **Wormhole EVM→Solana** — v0.17.5 round-10 fix: the decoder
  base58-encodes the 32-byte pubkey so the downstream Solana
  adapter / Helius can look it up. Pre-fix it surfaced a 0x-hex
  string the adapter rejected. Re-verified at the v0.31 depth
  layer in `test_wormhole_solana_recipient_decodes_to_base58_pubkey`.
* **Adversarial defenses** — extreme/negative timestamps clamped
  (`adapter.py::_safe_unix_to_datetime`); `tokenAmount: "Infinity"`
  silently drops the row instead of crashing the BFS hop; Helius
  5xx is retryable; pagination stuck-cursor guard.

## Solana SPL — concrete gaps

1. **Zero Solana-keyed bridge rows.** Same shape as Tron. The
   `bridge_sync_cmd` snapshot expects Wormhole and deBridge to have
   Solana entries, but bridges.json has none — see
   `_l2beat_expected_pairs` in
   `src/recupero/ops/commands/bridge_sync_cmd.py` lines 146/149. A
   v0.32 patch adding the Wormhole Solana portal program +
   deBridge's Solana program is the minimal fix. Pinned by
   `test_solana_keyed_bridge_db_is_empty_today`.
2. **Zero Solana-keyed CEX deposit rows.** Binance / Coinbase /
   Kraken / OKX / Bybit all run Solana hot wallets (solscan tags
   available); recupero labels none of them. Same gap as Tron, same
   future-work item, same shared assertion.
3. **Token-2022 extension metadata not surfaced.** Token-2022 supports
   transfer fees, default account state, permanent delegate, etc.
   The adapter passes the value transfer through but does not flag
   "this mint has a permanent delegate" — relevant for choosing
   freeze pathways. Acceptable for Phase-1 forensic tracing; tracked
   as future work and documented inline in
   `test_token_2022_transfer_normalizes_identically_to_classic_spl`.

## What live verification would prove

Live tests live in both `test_v031_tron_depth.py` and
`test_v031_solana_depth.py` behind `@pytest.mark.skipif` on
`RECUPERO_LIVE_TRONGRID=1` / `RECUPERO_LIVE_HELIUS=1`. Each test's
docstring spells out what it would baseline:

* USDT-TRC20 contract is still owned by Tether and still has
  `decimals=6` + `type=Contract`.
* A documented Binance Tron hot wallet still produces outflows via
  the TRC-20 endpoint in the documented shape.
* The Solana USDC mint is non-executable (Circle hasn't redeployed).
* A documented Binance Solana hot wallet returns parsed transactions
  in the documented shape.

These tests would also be the natural place to seed a future
`cex_deposits.json` Tron/Solana entry addition — the live data
matches the seed-row content.

## Test counts (delta vs main)

Pre-existing Tron/Solana coverage:

* `tests/test_tron_adapter.py` — 19 tests
* `tests/test_tron_adapter_adversarial.py` — 3 tests
* `tests/test_tron_address.py`, `test_tron_client.py`,
  `test_tron_client_pagination.py`, `test_tron_client_shape.py` —
  combined ~40 tests
* `tests/test_solana_adapter_adversarial.py` — 4 tests
* `tests/test_solana_helpers.py` — 14 tests
* `tests/test_solana_address.py` — ~10 tests

New (v0.31):

* `tests/test_v031_tron_depth.py` — 11 offline tests + 2 live stubs
* `tests/test_v031_solana_depth.py` — 11 offline tests + 2 live stubs

Coverage by line is not measured here (the task budget didn't allow
a full `coverage run`); the assertions favor pinning current
behavior at the BFS-relevant seams over redundant line touches.

## Code changes landed alongside this audit

None. The adapter code looks solid for current scope. The
gaps surfaced are seed-data and label-DB gaps — addressed in a
future patch by populating `bridges.json` and `cex_deposits.json`
with Tron-side and Solana-side rows, not by touching adapter logic.
The visible-gap pin tests will flip when that work lands.
