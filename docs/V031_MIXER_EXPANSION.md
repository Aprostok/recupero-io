# V031 Mixer Label Expansion

**Date:** 2026-05-26
**Branch:** pdf-deliverables
**Scope:** Expand `src/recupero/labels/seeds/mixers.json` beyond Tornado Cash to cover the privacy-protocol landscape a perpetrator will actually reach for in 2026.

## Why

The label DB had 12 mixer entries — mostly Tornado Cash variants plus Sinbad, FixedFloat, and two RAILGUN pools. A perpetrator using RAILGUN on BSC/Polygon/Arbitrum, Aztec, 0xbow Privacy Pools, or Nocturne would not hit the mixer label and the brief would not surface the privacy hop. This is the gap closed by v0.31.0.

## Added (18 new entries, all `_v031_addition: true`)

All addresses were verified via WebFetch against the URL captured in the entry's `source` and `_audit_status` fields. Confidence is `high` for entries with a block-explorer label or protocol-doc confirmation, `medium` where the contract is real but version-drift is plausible.

### RAILGUN (7 entries, 4 chains)
- Ethereum: Relay (`0xfa7093cd…`), Smart Wallet (`0xc0BEF2D3…`), Treasury (`0xe8a8b458…`), Smart Wallet Implementation (`0x2c5b9496…` — shared across all four chains via EIP-1967 proxy pattern)
- BSC: Relay (`0x590162bf…`)
- Polygon: Relay (`0x19b62092…`)
- Arbitrum: Relay (`0xFA7093CD…` — deterministic-deploy same address as Ethereum), RelayAdapt (`0x5ad95c53…`)

### Aztec (5 entries, all Ethereum L1)
- Aztec Connect (`0xff1f2b4a…`) — shut down Mar-2024, $2.7M+ residual escrow
- Private Rollup Bridge (`0x737901be…`) — Aztec 2.0 era
- Connect Rollup Deployment (`0xa173bddf…`) — Jun-2022 v1 deploy, confidence: medium
- Verification Key (`0x8C3B53F4…`)
- Fee Distributor (`0x4cf32670…`)

### Privacy Pools / 0xbow (2 entries, Ethereum)
- Entrypoint (`0x68188099…`) — main user-facing router, Mar-2025 launch
- ETH Pool (`0xf241d57c…`) — per-asset pool; separate USDC/USDT/DAI/wBTC pools exist

### Nocturne (3 entries, Ethereum)
- Teller (`0xA561492d…`)
- Handler (`0x33ab3ceC…`)
- DepositManager (`0x1B33B849…`)

### Penumbra (1 entry, Cosmos)
- Synthetic key `penumbra1-mainnet-zone` (chain `cosmos`). Penumbra is a Cosmos-zone — there is no EVM contract to monitor. Entry exists so the label DB returns "Penumbra" when an IBC inflow to Cosmos Hub originates there, even though we have no EVM adapter to act on it.

## Could NOT verify / aspirational (operator follow-up required)

| Item | Reason skipped | Operator action |
|---|---|---|
| Aztec Alpha Mainnet (Mar-2026 launch) L1 rollup | The Alpha Network launched on Ethereum mainnet 2026-03-31, but no canonical L1 contract address was findable via WebFetch as of 2026-05-26. Aztec docs reference the rollup but not the address. | Resolve from `aztec.network/blog/announcing-the-alpha-network` once the deploy page is public; add as `confidence: high`. |
| RAILGUN per-chain RelayAdapt on Ethereum/BSC/Polygon | Only Arbitrum RelayAdapt was surfaced by WebFetch with a verified explorer label. The other three chains have RelayAdapt contracts but their addresses were not in the search index. | Cross-reference `docs.railgun.org/wiki/learn/helpful-links` for all four explorer links. |
| Privacy Pools USDC/USDT/DAI/wBTC pool contracts | Source confirms per-asset pool contracts exist but only the ETH pool address was surfaced. | Pull from `0xbow.io` deployments page once exposed, or read from privacy-pools-core repo `deployments/` once it ships. |
| Wasabi Wallet 2.0 / WabiSabi coordinator | WabiSabi runs server-side; no on-chain coordinator address. zkSNACKs coordinator shut down May-2024; coordination is now via third-party coordinators with no canonical identifier. | Bitcoin-adapter scope: detect coinjoin tx patterns rather than a single address. Tracked in `BACKLOG.md` against Bitcoin adapter work. |
| Samourai Whirlpool | Coordinator servers seized April 2024 (DOJ prosecution; founders sentenced 2025). No live address to flag. | Historical-only — would need a forensic backfill of pre-seizure coordinator-tx clusters. Out of scope for v0.31. |
| Mercury Layer (CommerceBlock statechain) | Bitcoin statechain — no on-chain contract address; coordinator is off-chain. | Same as Wasabi — Bitcoin-adapter scope. |
| eXch.cx | Service shut down May 2025 after Bybit-hack laundering exposure (~$200M of NK funds). Deposit addresses rotated; no canonical contract. | Defer — historical-only; would need OFAC list pull if/when sanctions land. |
| Sinbad replacements (post-Nov-2023 sanctioning) | No clear single-successor protocol surfaced — landscape fragmented to multiple non-KYC swap services (eXch covered above, FixedFloat already in DB). | Continue to monitor OFAC quarterly updates. |

## Verification

```
python -m recupero.labels.validator
=== Recupero label-data validator ===
  Files checked: 7
  Entries checked: 344

  Errors:   0
  Warnings: 1
```

The single warning is pre-existing (`issuers.json[11]._comment_address_case`) and unrelated to this expansion. Zero errors against the mixer expansion.

## Schema note

`validator.py` was extended to register `_v031_addition` and `_audit_status` as recognized optional fields on `mixers.json` entries — exact same precedent as the `_v028_addition`/`_v029_addition`/`_v029_1_addition`/`_v030_chain_corrected` markers already on the schema. This is the only file outside `mixers.json` and this doc that changed.

## Forensic impact

The Tornado-Cash-only mixer label set caused a known coverage gap: any flow that hopped RAILGUN-on-Polygon, Aztec Connect, or 0xbow Privacy Pools landed in the brief as "transfer to unknown contract" rather than "shielded via privacy pool — trace ends here." With these 18 entries, the brief's mixer-detection layer now surfaces the privacy hop with the protocol name, which is the actionable forensic signal investigators need to (a) describe the limit-of-trace in the report and (b) issue protocol-specific subpoenas (e.g., 0xbow's ASP screening log, which is a real disclosure channel post-Mar-2025).
