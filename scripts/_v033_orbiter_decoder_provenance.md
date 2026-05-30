# Orbiter amount-suffix decoder — provenance & verification (v0.33.0, Wave B)

`src/recupero/trace/orbiter.py` decodes the destination chain Orbiter Finance
encodes in a transfer's amount suffix. Every constant in it is verified; this
file records how, so a reviewer can re-derive it without trusting the code.

## 1. The encoding rule (spec source)

Orbiter-Finance/orbiter-sdk `src/utils/core.ts`, function
`getPTextFromTAmount(chain, amount)` + `SIZE_OP.P_NUMBER == 4`.

- sha256 of the fetched file: `0bbc410dcd48050b1709d35fcbc74a6fbc417e873b28c03663a2df6a2c2c0502`
- For ordinary chains it takes the **last 4 digits** of the integer
  (smallest-unit) amount as the identification code.
- For "limit-number" chains (zksync / immutablex / dydx, capped by `MAX_BITS`)
  the code sits at a `validDigit` offset computed via `removeSidesZero` — a
  JS-regex zero-stripping that does not port to Python cleanly, so the decoder
  **degrades to None** when the SOURCE chain is one of these (no fabrication).

## 2. The `9000` marker (real-chain source)

The +9000 offset is applied UPSTREAM of `core.ts` (core.ts slices the
already-formatted code). It was recovered from real chain data, not guessed:

- 479 inbound deposits to the highest-volume Maker
  `0x80C67432656d59144cEFf962E8fAF8926599bCF8` on Ethereum (via the keyless
  Routescan etherscan-compatible API).
- 454 (95%) carry a 4-digit suffix of the form `9000 + internalId`; the rest
  are `0000` (no flag). Observed: `9002` (Arbitrum ×174), `9021` (Base ×118),
  `9007` (Optimism ×109), `9023` (Linea ×26), `9014` (zkSync Era ×9),
  `9019` (Scroll ×5), `9006`, `9015`, `9010`, `9004`, `9030`.
- Requiring the `9xxx` marker is therefore also a strong false-positive gate.

## 3. code → chain map (two byte-exact sources that AGREE)

- Historical: orbiter-sdk `core.ts` `CHAIN_INDEX` (codes 1–17).
- Current: live Orbiter API `https://api.orbiter.finance/sdk/chains`
  - sha256: `a7eb3315513c0fa79ae21e766ee945f097972d7360c4707967f53f160c95b17e`
  - gives `internalId` + `chainId` + name for 30 chains; `chainId` is mapped to
    our `Chain` enum (e.g. internalId 21 → chainId 8453 → `base`).

The two sources agree on every overlapping code (1→Ethereum, 2→Arbitrum,
6→Polygon, 7→Optimism, 14→zkSync Era, 15→BNB). The API resolved the
high-volume codes the old SDK lacked: **21→Base, 19→Scroll, 23→Linea**.
(internalId 13 was historically `boba`, now `NERO` in the API; both map to
`our_chain=None`, so the relabel is cosmetic.)

## 4. End-to-end real-data validation

Running the FINAL `decode_orbiter_destination` over the same 479 real deposits:
451 decode to a named chain, 3 carry the marker for a code we don't map yet
(returned as a confirmed-but-unnamed Orbiter deposit), 25 have no marker
(`0000`). Histogram: Arbitrum 174, Base 118, Optimism 109, Linea 26,
zkSync Era 9, Scroll 5, Polygon 3, BNB 2, zkSync Lite 2, Metis 1, Starknet 1,
Zora 1 — all genuine Orbiter destinations.

## 5. Forensic posture

A decoded chain is a **medium**-confidence lead (sender intent), never high. It
is wired into `identify_cross_chain_handoffs` to populate
`decoded_destination_chain` only (NOT `decoded_destination_address`), so the
same-address lock-and-mint matcher still pursues the actual continuation and
the high-only auto-continuation pass never fires on an amount decode.
