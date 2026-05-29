"""Tests for v0.31.0 minimum-viable wallet clustering.

Covers the four MVP heuristics specified in docs/V031_CLUSTERING_DESIGN.md:

  H1 — Co-spending (Bitcoin): two addresses both as inputs to one tx.
  H2 — Common CEX withdrawal (EVM, ≤1h).
  H3 — Common funding source (≤1h).
  H4 — Bridge round-trip.

Plus the safety nets: label-store suppression of shared infrastructure,
stable sha256-derived cluster IDs, empty-case handling.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.clustering import (
    compute_address_clusters,
    compute_clusters_with_metadata,
)

# ----- test helpers ----- #


def _evm_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    block_time: datetime,
    amount: Decimal = Decimal("1000"),
    chain: Chain = Chain.ethereum,
    tx_suffix: str | None = None,
) -> Transfer:
    suffix = tx_suffix or f"{from_addr[-4:]}{to_addr[-4:]}"
    tx_hash = "0x" + (suffix * 16)[:64]
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:{int(block_time.timestamp())}",
        chain=chain,
        tx_hash=tx_hash,
        block_number=int(block_time.timestamp()) % 100_000_000,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=chain,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw=str(int(amount * 10**6)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _btc_transfer(
    *,
    from_addr: str,
    to_addr: str,
    block_time: datetime,
    tx_hash: str,
    log_index: int = 0,
    amount: Decimal = Decimal("0.5"),
    usd: Decimal | None = Decimal("25000"),
) -> Transfer:
    return Transfer(
        transfer_id=f"bitcoin:{tx_hash}:{log_index}",
        chain=Chain.bitcoin,
        tx_hash=tx_hash,
        block_number=800000 + log_index,
        block_time=block_time,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.bitcoin,
            contract=None,
            symbol="BTC",
            decimals=8,
            coingecko_id="bitcoin",
        ),
        amount_raw=str(int(amount * 10**8)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://mempool.space/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _mk_case(
    transfers: list[Transfer],
    seed: str = "0x" + "a" * 40,
    chain: Chain = Chain.ethereum,
) -> Case:
    return Case(
        case_id="test",
        seed_address=seed,
        chain=chain,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


class _FakeLabelStore:
    """Minimal stand-in for LabelStore.lookup() — keyed by lower-cased
    EVM address. Just enough surface for the clustering code path."""

    def __init__(self, mapping: dict[str, Label] | None = None) -> None:
        self._mapping = {k.lower(): v for k, v in (mapping or {}).items()}

    def lookup(self, address: str, chain: Chain = Chain.ethereum) -> Label | None:
        if not isinstance(address, str):
            return None
        key = address.lower() if address.startswith("0x") else address
        return self._mapping.get(key)


def _label(addr: str, category: LabelCategory, *, name: str = "test-label") -> Label:
    return Label(
        address=addr,
        name=name,
        category=category,
        source="test",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


# ----- empty / trivial cases ----- #


def test_empty_case_returns_empty_dict() -> None:
    case = _mk_case([])
    result = compute_address_clusters(case, label_store=None)
    assert result == {}


def test_empty_case_no_crash_with_label_store() -> None:
    case = _mk_case([])
    label_store = _FakeLabelStore({})
    result = compute_address_clusters(case, label_store=label_store)
    assert result == {}


def test_single_transfer_no_cluster() -> None:
    """One transfer can't produce a multi-member cluster."""
    case = _mk_case([
        _evm_transfer(
            from_addr="0x" + "f" * 40,
            to_addr="0x" + "1" * 40,
            usd=Decimal("10000"),
            block_time=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        ),
    ])
    result = compute_address_clusters(case, label_store=None)
    assert result == {}


# ----- H1: Co-spending on Bitcoin ----- #


def test_h1_co_spending_two_btc_inputs_same_tx_cluster() -> None:
    """Two BTC inputs to the same tx → clustered (high confidence)."""
    addr_a = "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    addr_b = "bc1qbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    dest = "bc1qdest0000000000000000000000000000000000"
    same_tx = (
        "abcd1234ef567890abcd1234ef567890"
        "abcd1234ef567890abcd1234ef567890"
    )
    t = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    # Same txid appears twice with two different first-input addrs,
    # which is how the current Bitcoin adapter surfaces multi-input
    # co-spend evidence (see V031_CLUSTERING_DESIGN.md).
    case = _mk_case([
        _btc_transfer(
            from_addr=addr_a, to_addr=dest,
            block_time=t, tx_hash=same_tx, log_index=0,
        ),
        _btc_transfer(
            from_addr=addr_b, to_addr=dest,
            block_time=t, tx_hash=same_tx, log_index=1,
        ),
    ], chain=Chain.bitcoin)
    result = compute_address_clusters(case, label_store=None)
    assert addr_a in result
    assert addr_b in result
    assert result[addr_a] == result[addr_b]

    meta = compute_clusters_with_metadata(case, label_store=None)
    assert len(meta) == 1
    cluster = meta[0]
    assert cluster["confidence"] == "high"
    assert "co_spending" in cluster["heuristics"]


def test_h1_btc_inputs_to_different_txs_not_clustered() -> None:
    """Two BTC inputs to DIFFERENT txs do not satisfy co-spending."""
    addr_a = "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    addr_b = "bc1qbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    dest = "bc1qdest0000000000000000000000000000000000"
    tx1 = "1" * 64
    tx2 = "2" * 64
    t = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _btc_transfer(
            from_addr=addr_a, to_addr=dest,
            block_time=t, tx_hash=tx1, log_index=0,
        ),
        _btc_transfer(
            from_addr=addr_b, to_addr=dest,
            block_time=t + timedelta(hours=1), tx_hash=tx2, log_index=0,
        ),
    ], chain=Chain.bitcoin)
    result = compute_address_clusters(case, label_store=None)
    assert result == {}


# ----- H2: Common CEX withdrawal (EVM, ≤1h) ----- #


def test_h2_two_withdrawals_within_1h_cluster() -> None:
    """Two EVM addresses both receive from the same labeled CEX
    deposit address within 1h → clustered (high)."""
    cex = "0x" + "c" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    label_store = _FakeLabelStore({
        cex: _label(cex, LabelCategory.exchange_hot_wallet, name="Binance Hot 5"),
    })
    case = _mk_case([
        _evm_transfer(
            from_addr=cex, to_addr=addr_a,
            usd=Decimal("50000"), block_time=t0,
            tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=cex, to_addr=addr_b,
            usd=Decimal("50000"),
            block_time=t0 + timedelta(minutes=30),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=label_store)
    assert addr_a in result
    assert addr_b in result
    assert result[addr_a] == result[addr_b]

    meta = compute_clusters_with_metadata(case, label_store=label_store)
    assert any("cex_withdrawal" in c["heuristics"] for c in meta)
    assert meta[0]["confidence"] == "high"


def test_h2_six_hours_apart_NOT_clustered() -> None:
    """Same CEX, but 6h apart → outside the 1h window. NOT clustered."""
    cex = "0x" + "c" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    label_store = _FakeLabelStore({
        cex: _label(cex, LabelCategory.exchange_hot_wallet),
    })
    case = _mk_case([
        _evm_transfer(
            from_addr=cex, to_addr=addr_a,
            usd=Decimal("50000"), block_time=t0,
            tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=cex, to_addr=addr_b,
            usd=Decimal("50000"),
            block_time=t0 + timedelta(hours=6),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=label_store)
    assert result == {}


# ----- Label suppression of shared-infrastructure pairs ----- #


def test_pairs_with_explicit_labels_not_clustered() -> None:
    """Two exchange-deposit-labeled addresses both withdrawing from
    the same CEX within 1h should NOT cluster — they're two
    different exchange deposit addresses, not the same operator."""
    cex = "0x" + "c" * 40
    binance_deposit = "0x" + "1" * 40
    coinbase_deposit = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    label_store = _FakeLabelStore({
        cex: _label(cex, LabelCategory.exchange_hot_wallet),
        binance_deposit: _label(
            binance_deposit, LabelCategory.exchange_deposit,
            name="Binance Deposit (user 9001)",
        ),
        coinbase_deposit: _label(
            coinbase_deposit, LabelCategory.exchange_deposit,
            name="Coinbase Deposit (user 4242)",
        ),
    })
    case = _mk_case([
        _evm_transfer(
            from_addr=cex, to_addr=binance_deposit,
            usd=Decimal("50000"), block_time=t0,
            tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=cex, to_addr=coinbase_deposit,
            usd=Decimal("50000"),
            block_time=t0 + timedelta(minutes=15),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=label_store)
    assert result == {}


def test_bridge_labeled_address_not_clustered_in_funding() -> None:
    """An address labeled as a bridge contract must not be clustered
    as a same-operator wallet via the funding heuristic."""
    funder = "0x" + "f" * 40
    operator_wallet = "0x" + "1" * 40
    bridge_contract = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    label_store = _FakeLabelStore({
        bridge_contract: _label(
            bridge_contract, LabelCategory.bridge, name="Wormhole",
        ),
    })
    case = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=operator_wallet,
            usd=Decimal("50000"), block_time=t0,
            tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=bridge_contract,
            usd=Decimal("50000"),
            block_time=t0 + timedelta(minutes=10),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=label_store)
    # Bridge-labeled address must NOT be in any cluster.
    assert bridge_contract not in result


# ----- H3: Common funding (≤1h) ----- #


def test_h3_common_funding_within_1h_clusters_as_medium() -> None:
    """Two addresses funded by the same source within 1h →
    clustered with medium confidence (the legacy v0.9 pass used
    24h; v0.31 tightens to 1h)."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(minutes=20),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=None)
    assert addr_a in result
    assert addr_b in result
    assert result[addr_a] == result[addr_b]
    meta = compute_clusters_with_metadata(case, label_store=None)
    assert meta[0]["confidence"] == "medium"
    assert "common_funding" in meta[0]["heuristics"]


def test_h3_outside_1h_window_NOT_clustered() -> None:
    """Funding 2h apart → outside the 1h window. NOT clustered."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(hours=2),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=None)
    assert result == {}


# ----- H4: Bridge round-trip ----- #


def test_h4_bridge_round_trip_clusters_as_medium() -> None:
    """A bridges out, then C receives from a bridge on the same
    chain within the round-trip window → clustered (medium)."""
    addr_a = "0x" + "1" * 40
    addr_c = "0x" + "3" * 40
    bridge = "0x" + "b" * 40
    label_store = _FakeLabelStore({
        bridge: _label(bridge, LabelCategory.bridge, name="Stargate"),
    })
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _evm_transfer(
            from_addr=addr_a, to_addr=bridge,
            usd=Decimal("10000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=bridge, to_addr=addr_c,
            usd=Decimal("9800"),
            block_time=t0 + timedelta(hours=2),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=label_store)
    assert addr_a in result
    assert addr_c in result
    assert result[addr_a] == result[addr_c]
    meta = compute_clusters_with_metadata(case, label_store=label_store)
    assert meta[0]["confidence"] == "medium"
    assert "bridge_round_trip" in meta[0]["heuristics"]


# ----- Stable cluster IDs ----- #


def test_cluster_id_is_stable_across_runs() -> None:
    """Same input case → same cluster_id. The brief / AI editorial
    rely on this so cross-references survive re-emit."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(minutes=20),
            tx_suffix="bbbb",
        ),
    ])
    r1 = compute_address_clusters(case, label_store=None)
    r2 = compute_address_clusters(case, label_store=None)
    assert r1 == r2
    cid = next(iter(r1.values()))
    assert cid.startswith("cluster_")
    assert len(cid) == len("cluster_") + 8


def test_cluster_id_changes_with_membership() -> None:
    """Different address set → different cluster_id (membership-derived)."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    addr_c = "0x" + "3" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case_ab = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(minutes=10),
            tx_suffix="bbbb",
        ),
    ])
    case_ac = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_c,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(minutes=10),
            tx_suffix="cccc",
        ),
    ])
    r_ab = compute_address_clusters(case_ab, label_store=None)
    r_ac = compute_address_clusters(case_ac, label_store=None)
    assert r_ab[addr_a] != r_ac[addr_a]


# ----- Defensive: label_store=None is supported ----- #


def test_compute_without_label_store_still_runs() -> None:
    """Funding heuristic doesn't require a label store; the function
    must not crash when label_store is None."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    case = _mk_case([
        _evm_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("5000"), block_time=t0, tx_suffix="aaaa",
        ),
        _evm_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("5000"),
            block_time=t0 + timedelta(minutes=10),
            tx_suffix="bbbb",
        ),
    ])
    result = compute_address_clusters(case, label_store=None)
    assert len(result) == 2
