# Bridge source→destination pairing (answer-key-free correctness)

## Why

Bridges are the dominant way stolen funds are moved between chains, and they are
where a single-chain trace dead-ends. Historically recupero found a bridge
*destination* only by **amount + time correlation** (`bridge_matching`,
`match_lockmint_destination`, `match_pool_bridge_disbursement`) — explicitly
"never proof", capped at `medium`/`low`. That is a guess, and a production tracer
has no answer key to check the guess against.

A bridge protocol, however, stamps a **unique cross-chain identifier**
(order-id / message-hash / transfer-id / nonce) on the SOURCE order event, and
the DESTINATION chain's fill/mint event references the **same** identifier.
Matching the two by that id is **cryptographic proof** of the hop — no human
ground truth needed. This is the one place a cross-chain edge may be `high`
confidence (protocol identity, not inference).

`src/recupero/trace/bridge_pairings.py` implements this:
`confirm_bridge_destination(...)` extracts the source order-id, scans the
destination fill event over a settlement window, and returns a
`ConfirmedDestination` (`high`) on an exact id match — or `None` (never a guess).
`recupero confirm-bridge --chain <src> --tx <hash>` exposes it standalone.

## Verified-core registry

Only protocols whose source order-id offset AND destination fill event have been
confirmed against a **real on-chain source+destination pair** live in
`_REGISTRY`. Two pairing SHAPES are supported:

* **32-byte data id** — **deBridge DLN** (verified vs the Zigha pair: Arbitrum
  `createSaltedOrder`→`CreatedOrder`, Ethereum `FulfilledOrder`, order-id
  `0x57825e7d…`, recipient `0xc1ee32fa…`, 2,919,869 DAI). The id is an
  unforgeable bytes32 scanned for in the fill payload.
* **indexed composite key** — **Across V3** (verified vs a real Base→Ethereum
  pair: `FundsDeposited`→`FilledRelay`, paired on `(depositId, originChainId)`
  in indexed topics, server-filtered; per-chain SpokePool addresses). depositId
  is a small int unique only per origin chain, so it is paired with originChainId.
* **32-byte data id (scan)** — **Celer cBridge** (verified vs a real BSC→Ethereum
  pair: `Send.transferId` (data word 0) == `Relay.srcTransferId` (data word 6);
  Relay's own word-0 id is NOT the cross-chain key). Per-chain cBridge addresses.

* **32-byte indexed id (address-less)** — **Hop** (`TransferSent.transferId`
  (topic1) == `WithdrawalBonded.transferId` (topic1), both indexed bytes32 —
  verified Base→Optimism). Per-token emitters are many, so the dest is found
  address-LESS via `getLogs(topic0=WithdrawalBonded, topic1=transferId)`; the
  source emitters load from `bridges.json`.
* **derived id** — **Synapse** (kappa is NOT emitted on the source; it is
  `keccak256(ascii("0x"+sourceTxHash))` and appears as the destination mint's
  `topics[2]` — verified vs 5 real Eth→BSC pairs). The source `TokenDeposit`/
  `TokenRedeem` event recognizes the tx (so we don't derive for non-Synapse
  txs); destination is matched across the 4 mint/withdraw event topic0s.

All five are live-confirmed end-to-end via `confirm-bridge`.

Protocol + order-id + destination chain are resolved from the source tx's EVENT
LOGS (`identify_source`), not the tx `to` — robust to periphery/multicall
entrypoints (Across deposits route through a periphery contract).

## The recipe — adding a protocol WITHOUT re-introducing wrong-signature bugs

The v0.28 DeBridge decoder shipped three doc-inferred selectors that **never
matched a real order** (the real one was `createSaltedOrder`/`0xb9303701`). Never
ship a signature that hasn't matched a real tx. For each new protocol:

1. **Find one real pair.** Pick a real source bridge tx and locate its
   destination fill (Etherscan v2 across chains — `chainid` param; one Standard
   key covers all EVM). The empirical shortcut used for DLN: start from a *known*
   destination receiver + amount and walk back to the fill tx, then read its logs.
   (See the throwaway `scripts/zigha_bridge_decode_check.py` /
   `scripts/zigha_dln_dest_verify.py` for the pattern.)
2. **Pin the SOURCE order-id.** In the source tx receipt, find the
   order-creation event emitted by the source bridge contract; record its
   `topic0` and the **data-word index** (or topic index) of the order-id. Verify
   the word actually equals the id (don't assume the offset).
3. **Pin the DESTINATION fill event.** In the fill tx receipt, find the event
   (emitted by the destination bridge contract) that carries the SAME order-id;
   record its `topic0`. The engine matches the id by scanning all data words +
   topics, so a fixed dest offset isn't required — but record the emitter address
   (use the deterministic-deploy address if the protocol deploys CREATE2-same
   across chains).
4. **Add a `BridgePairSpec`** to `_REGISTRY` with those verified constants +
   `max_fee_pct` (the protocol's max taker/relayer fee, for the conservation
   bound).
5. **Add a real-data test** (mirror `tests/test_bridge_pairings.py`): synthetic
   logs in the verified shapes for the happy path, a **tampered order-id → None**
   case (false-positive guard), and assert the registry constants. Where a real
   fixture is cheap to capture, pin it too.
6. **Run the gate.** Full pytest green via redirect; zero new ruff.

## Operational notes

* The order-id is in event **data** for DLN (not an indexed topic), so the dest
  scan filters by `topic0` over a block window and matches the id in the
  payload. Keep the window tight: cross-chain fills settle in seconds–minutes,
  so the matching log sits near `from_block` and is returned early (ascending) —
  well within Etherscan's per-call log cap.
* Etherscan logs use `module=logs, action=getLogs` with **decimal** block
  numbers (NOT `proxy/eth_getLogs`, NOT hex) — a live-caught gotcha.
* The recipient is the **terminal** recipient of the fill tx's largest payout
  (in-tx re-senders are skipped) so the engine lands on the resting receiver,
  not a solver's internal swap leg.
* Live destination confirmation is opt-in inside a trace (it adds dest-chain API
  calls); the standalone `confirm-bridge` CLI runs it on demand.

## Candidate protocols to add next (each needs the recipe above)

Stargate/LayerZero, Wormhole, CCIP, Connext, Axelar, Squid, Symbiosis,
Allbridge, Mayan, Orbiter — plus the
canonical rollup bridges (Arbitrum/Optimism/Base/Polygon/zkSync), whose deposits
are deterministic (L2 mint to the depositor) and confirmable by
`(depositor, token, amount, window)`.
