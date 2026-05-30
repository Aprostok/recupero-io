"""Unit tests for same-EVM-address-across-chains clustering (v0.34 primitive).

Synthetic, duck-typed transfers (a tiny ``_T`` with a ``chain`` that exposes
``.value``, plus ``from_address`` / ``to_address`` — mirrors
``tests/test_peel_chains.py``'s ``_T`` / ``_Case`` helpers).

Covers: the same EVM address on 3 chains collapsing to ONE high-confidence
cluster, single-chain non-clustering, two independent multichain clusters,
non-EVM (Solana base58) never cross-matched into an EVM cluster, determinism,
the ``to_dict()`` shape, the empty case, and the confidence invariant
(every cluster in {high, medium, low}; same-address clusters are "high").
"""

from __future__ import annotations

from recupero.trace.address_clustering import (
    AddressCluster,
    cluster_addresses,
)


class _Chain:
    """Duck-typed Chain enum member: exposes ``.value`` like the real one."""

    def __init__(self, value: str) -> None:
        self.value = value


class _T:
    def __init__(self, chain: str, frm: str, to: str) -> None:
        self.chain = _Chain(chain)
        self.from_address = frm
        self.to_address = to


class _Case:
    def __init__(self, transfers) -> None:  # noqa: ANN001
        self.transfers = transfers


def _evm(n: int) -> str:
    return "0x" + f"{n:040x}"


# A real Solana-style base58 address (case-sensitive, not 0x-hex).
_SOL_ADDR = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"


def test_same_evm_address_three_chains_one_high_cluster() -> None:
    """One EVM address appearing on ethereum+arbitrum+base → ONE cluster,
    confidence 'high', chains sorted, basis same_evm_address_multichain."""
    actor = _evm(1)
    txs = [
        _T("ethereum", _evm(100), actor),
        _T("arbitrum", actor, _evm(200)),
        _T("base", _evm(300), actor),
    ]
    clusters = cluster_addresses(_Case(txs))
    assert len(clusters) == 1
    c = clusters[0]
    assert c.confidence == "high"
    assert c.basis == "same_evm_address_multichain"
    assert c.addresses == (actor,)
    # chains are the DISTINCT chains, sorted.
    assert c.chains == ("arbitrum", "base", "ethereum")


def test_single_chain_address_not_clustered() -> None:
    """An address that only appears on ONE chain is not a cross-chain
    cluster and must be omitted."""
    actor = _evm(1)
    txs = [
        _T("ethereum", _evm(100), actor),
        _T("ethereum", actor, _evm(200)),
    ]
    assert cluster_addresses(_Case(txs)) == []


def test_two_unrelated_multichain_addresses_two_clusters() -> None:
    """Two distinct EVM addresses, each spanning 2 chains → two separate
    clusters (no merging across unrelated actors)."""
    a, b = _evm(1), _evm(2)
    txs = [
        _T("ethereum", _evm(100), a),
        _T("arbitrum", a, _evm(200)),
        _T("ethereum", _evm(101), b),
        _T("polygon", b, _evm(201)),
    ]
    clusters = cluster_addresses(_Case(txs))
    assert len(clusters) == 2
    addr_sets = {c.addresses for c in clusters}
    assert addr_sets == {(a,), (b,)}
    # Each is its own single-address, 2-chain cluster.
    for c in clusters:
        assert len(c.addresses) == 1
        assert len(c.chains) == 2
        assert c.confidence == "high"


def test_non_evm_address_not_cross_matched() -> None:
    """A non-EVM (Solana base58) address appearing once is never folded into
    an EVM cluster, and a base58 string on two chains is NOT clustered (its
    format is chain-specific; same string != same key)."""
    actor = _evm(1)
    txs = [
        # EVM actor spans two chains → should cluster.
        _T("ethereum", _evm(100), actor),
        _T("arbitrum", actor, _evm(200)),
        # Solana address shows up on solana (and, adversarially, also on a
        # second chain label) — must NOT produce a cluster.
        _T("solana", _SOL_ADDR, _evm(300)),
        _T("ethereum", _SOL_ADDR, _evm(301)),
    ]
    clusters = cluster_addresses(_Case(txs))
    assert len(clusters) == 1
    c = clusters[0]
    assert c.addresses == (actor,)
    # The Solana string never appears in any cluster.
    for cl in clusters:
        assert _SOL_ADDR not in cl.addresses


def test_determinism_identical_ordering_across_calls() -> None:
    """Calling twice on the same case yields identical ordering + contents."""
    a, b, c = _evm(3), _evm(1), _evm(2)
    txs = [
        _T("base", _evm(100), a),
        _T("ethereum", a, _evm(200)),
        _T("ethereum", _evm(101), b),
        _T("arbitrum", b, _evm(201)),
        _T("polygon", _evm(102), c),
        _T("optimism", c, _evm(202)),
    ]
    first = cluster_addresses(_Case(txs))
    second = cluster_addresses(_Case(txs))
    assert first == second
    # Sorted by canonical address: b (0x..01), c (0x..02), a (0x..03).
    assert [cl.addresses for cl in first] == [(b,), (c,), (a,)]


def test_to_dict_shape() -> None:
    actor = _evm(7)
    txs = [
        _T("ethereum", _evm(100), actor),
        _T("base", actor, _evm(200)),
    ]
    d = cluster_addresses(_Case(txs))[0].to_dict()
    assert d["heuristic"] == "address_cluster"
    assert d["basis"] == "same_evm_address_multichain"
    assert d["attribution_confidence"] == "high"
    assert isinstance(d["addresses"], list)
    assert isinstance(d["chains"], list)
    assert d["addresses"] == [actor]
    assert d["chains"] == ["base", "ethereum"]
    assert isinstance(d["note"], str) and d["note"]


def test_empty_case_returns_empty() -> None:
    assert cluster_addresses(_Case([])) == []


def test_none_and_empty_addresses_are_robust() -> None:
    """None / empty endpoints and missing chains don't crash and don't
    spuriously cluster."""
    actor = _evm(1)
    txs = [
        _T("ethereum", None, actor),     # type: ignore[arg-type]
        _T("arbitrum", actor, ""),       # type: ignore[arg-type]
        _T("", actor, _evm(200)),        # empty chain → skipped
    ]
    clusters = cluster_addresses(_Case(txs))
    # actor is on ethereum + arbitrum (the empty-chain row is ignored) → 1.
    assert len(clusters) == 1
    assert clusters[0].chains == ("arbitrum", "ethereum")


def test_checksum_case_variants_collapse_to_one_cluster() -> None:
    """The same address in different EIP-55 checksum casing is canonical-
    keyed to one identity, not two clusters."""
    lower = "0x" + "ab" * 20
    upper = "0x" + "AB" * 20
    txs = [
        _T("ethereum", _evm(100), lower),
        _T("arbitrum", upper, _evm(200)),
    ]
    clusters = cluster_addresses(_Case(txs))
    assert len(clusters) == 1
    assert clusters[0].chains == ("arbitrum", "ethereum")


def test_invariant_confidence_in_allowed_set_and_same_addr_is_high() -> None:
    """No cluster has confidence outside {high, medium, low}; every
    same-address (multichain) cluster is 'high'."""
    a, b = _evm(1), _evm(2)
    txs = [
        _T("ethereum", _evm(100), a),
        _T("arbitrum", a, _evm(200)),
        _T("base", _evm(101), b),
        _T("optimism", b, _evm(201)),
    ]
    clusters = cluster_addresses(_Case(txs))
    assert clusters  # sanity: we built clusterable data
    for c in clusters:
        assert isinstance(c, AddressCluster)
        assert c.confidence in {"high", "medium", "low"}
        if c.basis == "same_evm_address_multichain":
            assert c.confidence == "high"
