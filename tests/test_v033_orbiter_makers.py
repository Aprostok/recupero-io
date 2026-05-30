"""v0.33.0 — Orbiter Finance Maker bridge-label coverage (regression lock).

Orbiter Finance is a cross-rollup bridge using an EOA "Maker" model: the
sender transfers directly to a Maker EOA (no contract call), the destination
network is encoded in the final digits of the transfer amount (Orbiter
``internalId``), and the Maker repays the SAME sender address on the
destination chain. Before v0.33.0, recupero had ZERO Orbiter coverage, so a
transfer into a Maker dead-ended as an unknown EOA.

These tests pin that the four verified Maker EOAs are ingested as ``bridge``
endpoints (so the tracer recognizes the handoff and the existing same-address
lock-and-mint matcher can pursue continuation). Provenance for the addresses:
Orbiter-Finance/orbiter-sdk maker_list.mainnet.ts (makerAddress field, parsed
structurally — NOT the token contracts in the same file), confirmed on-chain
as EOAs with bridge-scale nonces; 0x095D…626c9 also on the official
docs.orbiter.finance maker-addresses page. See
scripts/_v033_add_orbiter_makers.py for the full provenance + on-chain nonces.
"""

from __future__ import annotations

from recupero.models import Chain
from recupero.trace.cross_chain import ingest_bridge_seeds

# The four verified Maker EOAs (lowercased canonical keys).
_MAKERS = {
    "0x095d2918b03b2e86d68551dcf11302121fb626c9",
    "0x41d3d33156ae7c62c094aae2995003ae63f587b3",
    "0x80c67432656d59144ceff962e8faf8926599bcf8",
    "0xd7aa9ba6caac7b0436c91396f22ca5a7f31664fc",
}
# Every Maker operates (at least) on these source chains in our Chain enum.
_CORE_CHAINS = (Chain.ethereum, Chain.arbitrum, Chain.optimism, Chain.polygon, Chain.zksync)
# 0x80C6… additionally operates on BSC + Metis.
_MAKER_BSC_METIS = "0x80c67432656d59144ceff962e8faf8926599bcf8"


def test_orbiter_makers_ingested_on_core_chains() -> None:
    """All four Maker EOAs resolve to an Orbiter bridge on each core chain."""
    db = ingest_bridge_seeds()
    for chain in _CORE_CHAINS:
        for addr in _MAKERS:
            info = db.get((chain, addr))
            assert info is not None, f"Orbiter Maker {addr} missing on {chain.value}"
            assert "orbiter" in info.name.lower(), info.name
            assert info.protocol == "Orbiter Finance"


def test_orbiter_maker_label_is_high_confidence_identity() -> None:
    """A bridge IDENTITY label is a label-DB hit → 'high'. (The downstream
    continuation inference stays low/medium in the matcher — not here.)"""
    db = ingest_bridge_seeds()
    for addr in _MAKERS:
        info = db[(Chain.ethereum, addr)]
        assert info.confidence == "high", (addr, info.confidence)
        assert info.follow_up_url and "orbiter.finance" in info.follow_up_url


def test_orbiter_address_keys_are_canonical_lowercase() -> None:
    """EVM bridge keys must be lowercased so a case's case-preserved
    to_address matches (the v0.17.9 canonical-keying contract)."""
    db = ingest_bridge_seeds()
    orb_keys = {
        addr for (chain, addr), info in db.items()
        if info.protocol == "Orbiter Finance"
    }
    assert orb_keys == _MAKERS
    assert all(k == k.lower() for k in orb_keys)


def test_orbiter_bsc_and_metis_only_for_multi_chain_maker() -> None:
    """Only the broad-coverage Maker (0x80C6…) bridges BSC + Metis; the
    other three must NOT be fabricated onto chains they don't serve."""
    db = ingest_bridge_seeds()
    for chain in (Chain.bsc, Chain.metis):
        orb_on_chain = {
            addr for (c, addr), info in db.items()
            if c == chain and info.protocol == "Orbiter Finance"
        }
        assert orb_on_chain == {_MAKER_BSC_METIS}, (chain.value, orb_on_chain)


def test_orbiter_supports_to_chains_excludes_self() -> None:
    """destination candidates are the OTHER chains the Maker serves — never
    the source chain itself."""
    db = ingest_bridge_seeds()
    for (chain, addr), info in db.items():
        if info.protocol != "Orbiter Finance":
            continue
        assert info.supports_to_chains, (chain.value, addr)
        assert chain.value not in info.supports_to_chains


def test_orbiter_coverage_does_not_regress() -> None:
    """Pin the v0.33.0 footprint: 4 distinct Makers, 22 (chain,addr) entries,
    so a seed-file edit that drops Orbiter surfaces here immediately."""
    db = ingest_bridge_seeds()
    orb = [(c, a) for (c, a), info in db.items() if info.protocol == "Orbiter Finance"]
    assert len({a for _, a in orb}) == 4
    assert len(orb) == 22
