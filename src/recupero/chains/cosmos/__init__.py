"""Cosmos / IBC chain adapter package (v0.32.1+ Cap-C).

Minimal read-only Cosmos support. Closes the largest single chain-coverage
gap in REACTOR_PARITY.md § 3.3 ("Cosmos / IBC — Zero coverage in Recupero
v0.32.1").

What's in scope (v0.32.1):
  * Cosmos Hub (cosmos1...)
  * Osmosis (osmo1...)
  * Injective (inj1...)
  * Generic LCD / Mintscan tx-history fetch for any Cosmos zone.

What's NOT in scope (deferred to wave-7+):
  * IBC packet decode -> cross-chain continuation
  * CosmWasm contract decode
  * Stargate Token Factory follow-the-money
  * Validator slashing / delegation events

Even a basic read-only adapter answers "what transactions did this address
send/receive in window W" — a 0% -> 60% jump vs the v0.32.0 baseline.

TODO(wave-7-integration):
  * Register `CosmosAdapter` in `chains/base.ChainAdapter.for_chain`
    behind `Chain.cosmos`.
  * Add Cosmos chain detection to the BFS frontier when a bridge
    handoff resolves to a cosmos-shape destination address.
"""

from recupero.chains.cosmos.adapter import CosmosAdapter
from recupero.chains.cosmos.client import CosmosLCDClient

__all__ = ["CosmosAdapter", "CosmosLCDClient"]
