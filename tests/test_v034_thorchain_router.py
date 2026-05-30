"""v0.34 — THORChain Router bridge-label coverage (go-deeper #6, partial).

THORChain is a native cross-chain SWAP rail heavily used to break trails
(swap stolen ETH -> BTC etc., to a different recipient named in the swap memo).
The STABLE target is the Router contract (asgard vaults rotate and are
intentionally NOT labeled). Only the Ethereum router is curated here — it is
the one address reachable + on-chain-verifiable from the build env (the
THORNode inbound_addresses API that enumerates BSC/AVAX/Base routers is not
reachable here). Provenance: address from the inbound_addresses endpoint
(cited by the search + Etherscan), confirmed on-chain as a deployed contract.
"""

from __future__ import annotations

from recupero.models import Chain
from recupero.trace.cross_chain import ingest_bridge_seeds

_THOR_ETH_ROUTER = "0xc145990e84155416144c532e31f89b840ca8c2ce"


def test_thorchain_router_ingested_on_ethereum() -> None:
    db = ingest_bridge_seeds()
    info = db.get((Chain.ethereum, _THOR_ETH_ROUTER))
    assert info is not None, "THORChain Router missing on ethereum"
    assert info.protocol == "THORChain"
    assert "thorchain" in info.name.lower()
    assert info.confidence == "high"


def test_thorchain_router_address_is_canonical_lowercase() -> None:
    db = ingest_bridge_seeds()
    thor = {a for (_c, a), i in db.items() if i.protocol == "THORChain"}
    assert thor == {_THOR_ETH_ROUTER}
    assert all(a == a.lower() for a in thor)


def test_thorchain_router_supports_native_swap_destinations() -> None:
    db = ingest_bridge_seeds()
    info = db[(Chain.ethereum, _THOR_ETH_ROUTER)]
    # THORChain swaps to other native chains — destinations exclude self.
    assert info.supports_to_chains
    assert "ethereum" not in info.supports_to_chains
    assert "bitcoin" in info.supports_to_chains
