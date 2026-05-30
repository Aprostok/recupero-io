"""v0.33.0 Wave D — Allbridge Core + Mayan bridge-label coverage (regression lock).

Two major cross-chain bridges that previously had no usable coverage (a v0.29
"Allbridge Core" entry pointed at a phantom codeless address). These tests pin
that the verified contracts ingest as recognized bridges and that the phantom
is gone. Provenance + on-chain verification: scripts/_v033_add_allbridge_mayan_bridges.py.
"""

from __future__ import annotations

from recupero.models import Chain
from recupero.trace.cross_chain import ingest_bridge_seeds

_ALLBRIDGE_CHAINS = {
    Chain.ethereum, Chain.bsc, Chain.polygon, Chain.arbitrum, Chain.avalanche,
    Chain.optimism, Chain.base, Chain.celo, Chain.linea, Chain.tron, Chain.solana,
}
_PHANTOM = (Chain.ethereum, "0xa8cba66ef4ad65b7f6c97e6d5e58f9b9bfe9ab40")


def test_allbridge_ingested_on_all_verified_chains() -> None:
    db = ingest_bridge_seeds()
    chains = {c for (c, _a), info in db.items() if info.protocol == "Allbridge"}
    assert chains == _ALLBRIDGE_CHAINS, chains ^ _ALLBRIDGE_CHAINS


def test_allbridge_labels_are_high_confidence() -> None:
    db = ingest_bridge_seeds()
    ab = [info for (_c, _a), info in db.items() if info.protocol == "Allbridge"]
    assert ab
    for info in ab:
        assert info.confidence == "high", info
        assert "allbridge" in info.name.lower()


def test_mayan_forwarder_and_swift_ingested() -> None:
    db = ingest_bridge_seeds()
    mayan = [(c, info.name) for (c, _a), info in db.items() if info.protocol == "Mayan"]
    assert len(mayan) == 16, mayan
    assert {n for _c, n in mayan} == {"Mayan Forwarder", "Mayan Swift"}
    # Forwarder + Swift each on 8 chains.
    fwd = {c for c, n in mayan if n == "Mayan Forwarder"}
    swift = {c for c, n in mayan if n == "Mayan Swift"}
    assert len(fwd) == 8 and len(swift) == 8


def test_phantom_allbridge_entry_removed() -> None:
    """The v0.29 codeless phantom (0xa8cba66e…, empty on every chain) must no
    longer ingest — a bridge label on a non-contract is a forensic defect."""
    db = ingest_bridge_seeds()
    assert _PHANTOM not in db
    # And no Allbridge entry should carry that address on any chain.
    assert not any(
        a == _PHANTOM[1] for (_c, a), info in db.items() if info.protocol == "Allbridge"
    )


def test_wave_d_bridge_keys_are_canonical() -> None:
    """EVM keys lowercased; Tron/Solana base58 case-preserved (so a
    case-preserved tracer address matches)."""
    db = ingest_bridge_seeds()
    for (_chain, addr), info in db.items():
        if info.protocol not in ("Allbridge", "Mayan"):
            continue
        if addr.startswith("0x"):
            assert addr == addr.lower()
