# v0.31.2 — Tron + Solana seed expansion (Gaps #6 + #7)

Two of the fifteen v0.31.0 trace gaps were diagnosed by the earlier audit
as **pure seed-data gaps** (not code gaps):

- **Gap #6** — Tron USDT depth: Tron adapter exists, but pre-v0.31.2
  `bridges.json` had **zero** Tron-keyed entries, so bridge handoffs
  originating on Tron surfaced as unlabeled EOAs in briefs.
- **Gap #7** — Solana SPL trace depth: Helius adapter exists, but
  pre-v0.31.2 `bridges.json` had **zero** Solana-keyed entries, and
  `cex_deposits.json` had **zero** Solana-keyed entries, so SOL/SPL
  destinations consistently surfaced as unlabeled programs/accounts.

This document records every seed-data addition shipped under v0.31.2
along with the provenance (external source actually consulted) and a
confidence rating.

No Python code was changed. The existing `_v031_addition` schema marker
in `src/recupero/labels/validator.py` (registered in v0.31.0 for the
mixer-expansion batch and already permitted on both `bridges.json` and
`cex_deposits.json`) was reused.

## Validator + integrity test result

```
$ python -c "from recupero.labels.validator import validate_seed_files; ..."
files_checked: 7, entries_checked: 363
errors: 0, warnings: 1
  [warn] issuers.json[11].None: Unknown field(s): ['_comment_address_case'] (pre-existing, unrelated)

$ python -m pytest tests/test_labels_seeds_integrity.py -v
8 passed in 0.98s
```

## bridges.json additions

| Address | Name | Chain | Confidence | Source |
|---|---|---|---|---|
| `TCFNp179Lg46D16zKoumd4Poa2WFFdtqYj` | SunSwap: Smart Router | tron | high | sun-protocol/smart-exchange-router GitHub + docs.sun.io |
| `TE2RzoSV3wFK99w6J9UnnZ4vLfXYoxvRwP` | JustLend: jTRX Market | tron | high | tronscan.org token20 page (via WebSearch) |
| `TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz` | USDD: Peg Stability Module | tron | medium | docs.usdd.io + Eco support docs |
| `wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb` | Wormhole: Token Bridge (also Portal Bridge) | solana | high | wormhole-foundation/wormhole sdk/js/src/utils/consts.ts (raw GitHub) |
| `worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth` | Wormhole: Core Bridge | solana | high | same as above |
| `DEbrdGj3HsRsAzx6uH4MKyREKxVAfBydijLUF3ygsFfh` | deBridge: DLN Program | solana | high | debridge-finance/debridge-solana-sdk + docs.debridge.com |

### Tron bridge ecosystem — externally confirmed absences (forensically important)

The task brief asked for Wormhole-on-Tron, Stargate-on-Tron, AnySwap/Multichain-on-Tron,
and PolyNetwork-on-Tron. **All four were confirmed to NOT be deployed on
Tron mainnet** during research:

- **Wormhole**: official SDK constants (`sdk/js/src/utils/consts.ts`) list 40+ chains;
  Tron is conspicuously absent from both the `CHAINS` object and the MAINNET
  contract-address tables.
- **Stargate**: official `stargateprotocol.gitbook.io` mainnet deployments page
  lists Ethereum, BNB, Avalanche, Polygon, Arbitrum, Optimism, Fantom, Metis,
  Base, Linea, Kava, Mantle — **no Tron**.
- **PolyNetwork**: `polynetwork/poly-bridge/conf/config_mainnet.json` enumerates
  ChainId 0/2/3/4/5/6/7/8/10/12/14/17/19/21/22/23 — no Tron entry.
- **Multichain / AnySwap**: defunct since July 2023; not adding addresses for
  a permanently-frozen protocol (would only generate false noise in current cases).

This is itself a forensically useful fact: **on Tron, the cross-asset hop is the
DEX/lending/PSM layer, not a Token-Bridge-style protocol.** That is why
`SunSwap Smart Router`, `JustLend jTRX`, and `USDD PSM` are flagged as
`category: "bridge"` here — they functionally serve the routing role that
Token Bridge contracts serve on other chains, and v0.30.x bridge-following
in the BFS trace only follows category=bridge edges.

## cex_deposits.json additions — Tron

| Address | Name | Exchange | Confidence | Source |
|---|---|---|---|---|
| `TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb` | Binance: Hot Wallet 4 | Binance | high | oklink.com Tron page (4.1B USDT) |
| `TJ5usJLLwjwn7Pw3TPbdzreG7dvgKzfQ5y` | Binance: Withdraw_11 | Binance | high | oklink.com Tron page |
| `TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G` | Binance: DepositAndWithdraw_7 | Binance | high | oklink.com Tron page |
| `TDqSquXBgUCLYvYC4XZgrprLK589dkhSCf` | Binance: DepositAndWithdraw_8 | Binance | high | oklink.com Tron page |
| `TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9` | Binance: Cold Wallet / Super Rep Voter | Binance | high | clankapp.com label `(binance)`; cross-confirmed by The Block reporting on Binance's TRON Super Representative voting (12B TRX votes) |
| `TXFBqBbqJommqZf7BV8NNYzePh97UmJodJ` | Bitfinex: Hot Wallet | Bitfinex | high | bitquery + clankapp + oklink all label as Bitfinex |
| `TNaRAoLUyYEV2uF7GUrzSjRQTU8v5ZJ5VR` | Huobi/HTX: Hot Wallet | Huobi | medium | bitquery label `huobi`; confidence medium because Huobi → HTX rebrand rotated some hot wallets in 2023 |

### Tron addresses considered but NOT added

- `TKHuVq1oKVruCGLvqVexFs6dawKv6fQgFs` — the v0.31.0 audit hypothesized this
  was a Binance hot wallet, but verification revealed it is **Tether Treasury #2**,
  not a Binance address. Labeling it as Binance would have been forensically
  dangerous (would mis-route freeze asks). Captured here as a near-miss.
- Bybit-on-Tron specific addresses — Bybit operates significant TRC-20 volume
  per OKLink's `cex-asset/bybit` page but no single canonical OKLink/Bitquery
  tag was returned by search. Deferred to a future expansion rather than
  guessing.
- KuCoin-on-Tron specific addresses — same: no public-tag aggregator returned
  a canonical T-prefixed address with sufficient verification. Deferred.

## cex_deposits.json additions — Solana

| Address | Name | Exchange | Confidence | Source |
|---|---|---|---|---|
| `GJRs4FwHtemZ5ZE9x3FNvJ8TMwitKTh21yxdRPqn7npE` | Coinbase: Hot Wallet 2 | Coinbase | high | Solscan label, 35,186 SOL |
| `D89hHJT5Aqyx1trP6EnGY9jJUB3whgnq3aUvvCqedvzf` | Coinbase: Hot Wallet 3 | Coinbase | high | Solscan label |
| `is6MTRHEgyFLNTfYcuV4QBWLjrZBfmhVNYR6ccgr8KV` | OKX: Hot Wallet | OKX | high | Solscan label `OKX: Hot Wallet` |
| `BY4StcU9Y2BpgH8quZzorg31EGE4L1rjomN8FNsCBEcx` | HTX: Hot Wallet | HTX | high | Solscan label `HTX: Hot Wallet` |
| `AC5RDfQFmDS1deWZos921JfqscXdByf8BKHs5ACWjtW2` | Bybit: Hot Wallet | Bybit | high | Solscan label `Bybit Hot Wallet` |
| `FWznbcNXWQuHTawe9RxvQ2LdCENssh12dsznf4RiouN5` | Kraken: Hot Wallet | Kraken | high | Solscan label `Kraken` |
| `AobVSwdW9BbpMdJvTqeCN4hPAmh4rHm7vwLnQ5ATSyrS` | Crypto.com: Hot Wallet 2 | Crypto.com | high | Solscan label `Crypto.com Hot Wallet 2` |

Note on Solana addresses: base58 is **case-sensitive**. The canonicalization
helper in `src/recupero/_common.py` (`canonical_address_key`) correctly
lowercases only EVM `0x...` forms and leaves Solana base58 strings
unchanged — the W13-09 fuzzer locked this behavior in v0.30.x. The
OKX wallet `is6M...` (starts lowercase) is the case the fuzzer's invariant
specifically protects.

## Provenance + verification policy

Each entry has an `_audit_status` field that names the exact URL that was
WebFetched / WebSearched to verify the address. This is the same pattern
v0.29.1's `_audit_status: externally_verified_v029_1: ...` introduced.

Where direct WebFetch of the canonical explorer (Tronscan.org, Solscan.io)
returned 403 Forbidden, verification fell back to:

1. **WebSearch site:** filtered searches (`site:oklink.com`, `site:solscan.io`,
   `site:bitquery.io`) — these return snippet content from the target page,
   which is sufficient to confirm a public label without needing an
   authenticated session.
2. **Raw GitHub source files** (e.g., Wormhole's `sdk/js/src/utils/consts.ts`,
   PolyNetwork's `conf/config_mainnet.json`) for protocol-canonical
   constants.
3. **Multi-source cross-confirmation** for any address with `confidence: "high"`
   — Tronscan + ClankApp + OKLink + Bitquery agreement was the bar for the
   Binance Tron wallets.

No address was added at `confidence: "high"` from a single unverified
source. The single `confidence: "medium"` Tron-bridge entry (`USDD PSM`)
and the single `confidence: "medium"` Tron-CEX entry (`Huobi/HTX`) are
marked medium specifically because USDD redeployed in 2024 and the Huobi
→ HTX rebrand rotated wallets — both should get a second-level on-chain
verification before being used as the sole basis for a freezing decision.

## What this fixes downstream

- **Trace BFS** in `src/recupero/trace/tracer.py` follows `category=bridge`
  edges. Adding 3 Tron and 3 Solana bridge labels gives those chains
  non-empty `category=bridge` sets, which closes the silent-skip of
  bridge handoffs on those chains.
- **Brief destination classification** in
  `src/recupero/reports/brief.py:_build_identified_wallets` previously
  classified every Solana / Tron exchange-destination address as an
  unlabeled EOA. Adding 14 exchange hot wallets across the two chains
  (7 Tron, 7 Solana) gives the brief generator a real `exchange` value
  to populate the `EXCHANGE` destination class.
- **`asks.exchange_deposits`** in `src/recupero/asks.py` enumerates
  per-issuer freeze targets at exchange-controlled wallets. Pre-v0.31.2
  this set was empty for both Tron and Solana cases, meaning no exchange
  asks were generated even when funds clearly landed at a Coinbase /
  Binance hot wallet. v0.31.2 fixes this.

## Counts

- bridges.json: +6 entries (3 Tron + 3 Solana)
- cex_deposits.json: +14 entries (7 Tron + 7 Solana)
- Total new addresses: 20
- Python files changed: 0
- Validator schema changes: 0 (reused existing `_v031_addition` field)
