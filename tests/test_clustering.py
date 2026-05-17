"""Tests for v0.9.0 entity clustering.

Three heuristics:
  H1 common_funding — same source EOA funds two addresses within 24h
  H2 common_withdrawal — two addresses send to same target within 12h
  H3 direct_transfer — A → B with round-number amount (weak signal)

Plus shared-infrastructure detection (CEX hot wallets aren't a
clustering signal).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.clustering import (
    Cluster,
    cluster_addresses,
    clusters_to_brief_section,
)


def _mk_transfer(
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
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw=str(int(amount * 10**6)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _mk_case(transfers: list[Transfer], seed: str = "0x" + "a" * 40) -> Case:
    return Case(
        case_id="test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


# ---- empty / trivial cases ---- #


def test_empty_case_returns_empty() -> None:
    case = _mk_case([])
    clusters, unclustered = cluster_addresses(case)
    assert clusters == []
    assert unclustered == []


def test_single_transfer_no_cluster() -> None:
    """One transfer → no clustering possible (need at least 2
    addresses sharing a signal)."""
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
            usd=Decimal("10000"),
            block_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ),
    ])
    clusters, unclustered = cluster_addresses(case)
    assert clusters == []


# ---- H1: common funding source ---- #


def test_h1_common_funding_clusters_two_addresses() -> None:
    """Two addresses funded by the same source EOA within 24h
    → clustered together."""
    funder = "0x" + "f" * 40  # the perpetrator's funding wallet
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(
            from_addr=funder, to_addr=addr_a,
            usd=Decimal("10000"), block_time=t0,
        ),
        _mk_transfer(
            from_addr=funder, to_addr=addr_b,
            usd=Decimal("10000"),
            block_time=t0 + timedelta(hours=4),
        ),
    ])
    clusters, _ = cluster_addresses(case)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert addr_a in cluster.addresses
    assert addr_b in cluster.addresses
    # Evidence should reference common_funding + the source.
    heuristics = {ev.heuristic for ev in cluster.evidence}
    assert "common_funding" in heuristics
    related = {ev.related_address for ev in cluster.evidence}
    assert funder in related


def test_h1_outside_window_no_cluster() -> None:
    """Same funder, but 48h apart → outside the 24h window.
    Not clustered. The pattern is "operator funds wallets in
    a single session," not "two unrelated victims of the same
    CEX hot wallet."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=funder, to_addr=addr_a,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addr_b,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=48)),
    ])
    clusters, _ = cluster_addresses(case)
    assert clusters == []


def test_h1_three_addresses_same_funder_within_window() -> None:
    """Three addresses funded by the same source within the
    window → one cluster of three."""
    funder = "0x" + "f" * 40
    addrs = ["0x" + str(i) * 40 for i in range(1, 4)]
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=funder, to_addr=addrs[0],
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addrs[1],
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=1)),
        _mk_transfer(from_addr=funder, to_addr=addrs[2],
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=2)),
    ])
    clusters, _ = cluster_addresses(case)
    assert len(clusters) == 1
    assert len(clusters[0].addresses) == 3


# ---- H2: common withdrawal target ---- #


def test_h2_common_withdrawal_clusters() -> None:
    """Two addresses sending to the same target within 12h →
    clustered. The drain-to-hub consolidation pattern."""
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    hub = "0x" + "h" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=addr_a, to_addr=hub,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=addr_b, to_addr=hub,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=3)),
    ])
    clusters, _ = cluster_addresses(case)
    assert len(clusters) == 1
    cluster = clusters[0]
    heuristics = {ev.heuristic for ev in cluster.evidence}
    assert "common_withdrawal" in heuristics


def test_h2_outside_window_no_cluster() -> None:
    """Same hub, but 24h apart → outside the 12h window. Not
    clustered (drain-to-hub is a minutes-to-hours pattern)."""
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    hub = "0x" + "h" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=addr_a, to_addr=hub,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=addr_b, to_addr=hub,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=24)),
    ])
    clusters, _ = cluster_addresses(case)
    assert clusters == []


# ---- Shared-infrastructure suppression ---- #


def test_shared_infra_not_used_as_signal() -> None:
    """An address with many distinct partners (CEX hot wallet,
    popular DEX router) should NOT serve as a clustering signal.
    Otherwise every address that ever received Binance withdrawals
    gets clustered with every other address that did.

    Construct: one 'CEX hot wallet' funds 10 distinct addresses.
    The 10 addresses should NOT all cluster together — the
    shared funder is shared infrastructure."""
    cex = "0x" + "c" * 40
    addrs = ["0x" + f"{i:040x}" for i in range(10)]
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(
            from_addr=cex, to_addr=addr,
            usd=Decimal("10000"),
            block_time=t0 + timedelta(hours=i),
            tx_suffix=f"{i:04x}",
        )
        for i, addr in enumerate(addrs)
    ])
    clusters, unclustered = cluster_addresses(case)
    # cex has 10 partners → flagged as shared infra → no clustering
    # via H1 through it.
    assert clusters == []
    # The 10 addresses appear in unclustered (each is its own).


def test_below_minimum_usd_filtered() -> None:
    """Transfers below $100 don't contribute clustering signal.
    A $5 dust spam from a popular funder shouldn't be enough
    to merge two addresses."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=funder, to_addr=addr_a,
                     usd=Decimal("5"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addr_b,
                     usd=Decimal("5"),
                     block_time=t0 + timedelta(hours=1)),
    ])
    clusters, _ = cluster_addresses(case)
    assert clusters == []


# ---- Multiple heuristics combine ---- #


def test_multiple_heuristics_combine_via_union_find() -> None:
    """A pair clustered via H1 AND a different pair clustered via
    H2 that shares an address with the H1 pair → all three end up
    in one merged cluster (union-find handles transitivity)."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    addr_c = "0x" + "3" * 40
    hub = "0x" + "h" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        # H1: funder funds A and B
        _mk_transfer(from_addr=funder, to_addr=addr_a,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addr_b,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=1)),
        # H2: B and C both withdraw to hub
        _mk_transfer(from_addr=addr_b, to_addr=hub,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=10)),
        _mk_transfer(from_addr=addr_c, to_addr=hub,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=12)),
    ])
    clusters, _ = cluster_addresses(case)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert {addr_a, addr_b, addr_c} <= cluster.addresses


# ---- Brief section serialization ---- #


def test_brief_section_shape() -> None:
    """Locked: the brief JSON shape downstream consumers bind to."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=funder, to_addr=addr_a,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addr_b,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=1)),
    ])
    clusters, unclustered = cluster_addresses(case)
    section = clusters_to_brief_section(clusters, unclustered)
    assert "clusters" in section
    assert "unclustered_addresses" in section
    assert len(section["clusters"]) == 1
    c = section["clusters"][0]
    assert "cluster_id" in c
    assert "addresses" in c
    assert "size" in c
    assert "total_balance_usd" in c
    assert "evidence" in c
    assert c["size"] == 2


def test_brief_section_includes_balances_when_provided() -> None:
    """If the caller passes per-address balances, the cluster's
    total_balance_usd is the sum across cluster members."""
    funder = "0x" + "f" * 40
    addr_a = "0x" + "1" * 40
    addr_b = "0x" + "2" * 40
    t0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    case = _mk_case([
        _mk_transfer(from_addr=funder, to_addr=addr_a,
                     usd=Decimal("10000"), block_time=t0),
        _mk_transfer(from_addr=funder, to_addr=addr_b,
                     usd=Decimal("10000"),
                     block_time=t0 + timedelta(hours=1)),
    ])
    balances = {addr_a: Decimal("500000"), addr_b: Decimal("200000")}
    clusters, _ = cluster_addresses(case, address_balances=balances)
    assert clusters[0].total_balance_usd == Decimal("700000")
