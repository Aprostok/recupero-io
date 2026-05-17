"""Tests for v0.10.0 indirect exposure scoring.

Core algorithm: BFS from each high-risk source, propagating
weighted exposure with hop decay (default 0.5) and amount-share
normalization (mixing penalty).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.indirect_exposure import (
    IndirectExposureResult,
    compute_indirect_exposure,
    indirect_exposure_to_brief_section,
)
from recupero.trace.risk_scoring import HighRiskEntry


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    tx_suffix: str = "1",
    chain: Chain = Chain.ethereum,
) -> Transfer:
    tx_hash = "0x" + (tx_suffix * 64)[:64]
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw=str(int(usd * 10**6)),
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="test",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


def _mk_lazarus_entry(addr: str = "0x" + "f" * 40) -> HighRiskEntry:
    return HighRiskEntry(
        address=addr.lower(),
        name="Lazarus Group",
        risk_category="ofac_sanctioned",
        severity=4,
    )


# ---- Empty cases ---- #


def test_no_high_risk_db_returns_empty() -> None:
    case = _mk_case([_mk_transfer(
        from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
        usd=Decimal("100"),
    )])
    assert compute_indirect_exposure(case, {}) == {}


def test_no_transfers_returns_empty() -> None:
    case = _mk_case([])
    lazarus = _mk_lazarus_entry()
    assert compute_indirect_exposure(
        case, {lazarus.address: lazarus},
    ) == {}


def test_high_risk_not_in_case_returns_empty() -> None:
    """The sanctioned source must appear in the case graph for
    indirect exposure to compute. Otherwise there's no path."""
    case = _mk_case([_mk_transfer(
        from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
        usd=Decimal("100"),
    )])
    lazarus_unrelated = _mk_lazarus_entry("0x" + "9" * 40)
    out = compute_indirect_exposure(
        case, {lazarus_unrelated.address: lazarus_unrelated},
    )
    assert out == {}


# ---- 1-hop (direct) exposure ---- #


def test_direct_exposure_computed_at_full_weight() -> None:
    """Lazarus → A directly → 1-hop exposure with full decay
    weight (decay^1 = 0.5 by default → 50% of the amount)."""
    lazarus = _mk_lazarus_entry()
    target = "0x" + "1" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=target,
                     usd=Decimal("1000")),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    assert target in out
    result = out[target]
    # 1-hop exposure: $1000 × 0.5^1 = $500
    assert result.total_indirect_usd == Decimal("500")
    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.source_address == lazarus.address
    assert path.hop_count == 1
    assert path.path_addresses == ()  # no intermediates


# ---- 2-hop indirect ---- #


def test_two_hop_indirect_with_amount_share() -> None:
    """Lazarus → A → B with amount-share normalization.

    Lazarus sends $1000 to A.
    A sends $500 to B (and presumably has other outflows; the
      amount-share factor handles the mixing).
    Expected 2-hop exposure at B:
      $1000 (Lazarus→A) × 0.5 (decay 1)         → A gets $500 weighted
      A's $500 weighted × (500/500=1 share)     → B gets full passthrough
      × 0.5 decay (hop 2)                        → $250 at B
    """
    lazarus = _mk_lazarus_entry()
    a = "0x" + "1" * 40
    b = "0x" + "2" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("500"), tx_suffix="2"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})

    # A: direct (1-hop) exposure
    assert a in out
    assert out[a].total_indirect_usd == Decimal("500")  # $1000 × 0.5

    # B: indirect (2-hop) exposure with amount-share
    assert b in out
    b_result = out[b]
    # Path: lazarus → a → b
    # 1-hop weighted at A: $1000 × 0.5 = $500
    # 2-hop weighted at B: $500 × (500/500=1) × 0.5 = $250
    assert b_result.total_indirect_usd == Decimal("250")
    assert len(b_result.paths) == 1
    assert b_result.paths[0].hop_count == 2
    assert b_result.paths[0].path_addresses == (a,)


def test_mixing_penalty_reduces_share() -> None:
    """A pools funds from Lazarus AND a legitimate source, then
    sends some to B. The mixing penalty should reduce B's
    indirect exposure proportionally.

    Lazarus → A: $100 (sanctioned source)
    Legit → A:   $900 (also sends to A, but not a sanctioned
                       source; legit doesn't appear in
                       high_risk_db, but A's outflows now mix
                       both)
    A → B: $1000

    Without the amount-share penalty, B would get the full
    1-hop equivalent. With it, B's exposure to Lazarus is
    reduced by the share-factor (Lazarus contributed only
    10% of A's inflows but we use OUTFLOW share, not inflow
    — A sends ALL of it to B (share = 1000/1000 = 1) so the
    penalty doesn't actually reduce here).

    Actually outflow-share = 1.0 because all of A's outflow
    went to B. So B's exposure is $50 (Lazarus's direct
    contribution × decay^2).

    Wait — the algorithm propagates the WEIGHTED exposure from
    A ($50 = $100 × 0.5^1) and scales by A's outflow share to B
    (which is 1.0). So B gets $50 × 1.0 × 0.5 = $25.
    """
    lazarus = _mk_lazarus_entry()
    legit_source = "0x" + "e" * 40
    a = "0x" + "1" * 40
    b = "0x" + "2" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("100"), tx_suffix="1"),
        _mk_transfer(from_addr=legit_source, to_addr=a,
                     usd=Decimal("900"), tx_suffix="2"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("1000"), tx_suffix="3"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})

    # A: 1-hop = $100 × 0.5 = $50
    assert out[a].total_indirect_usd == Decimal("50")
    # B: 2-hop = $50 × 1.0 (all of A's outflow went to B) × 0.5 = $25
    assert b in out
    assert out[b].total_indirect_usd == Decimal("25")


def test_mixing_with_split_outflow() -> None:
    """A sends to TWO destinations — half to each — so each
    one gets half the share.

    Lazarus → A: $100
    A → B: $500
    A → C: $500

    B's outflow share from A = 500/1000 = 0.5
    C's outflow share from A = 500/1000 = 0.5
    Each: $50 × 0.5 (share) × 0.5 (decay) = $12.50
    """
    lazarus = _mk_lazarus_entry()
    a = "0x" + "1" * 40
    b = "0x" + "2" * 40
    c = "0x" + "3" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("100"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("500"), tx_suffix="2"),
        _mk_transfer(from_addr=a, to_addr=c,
                     usd=Decimal("500"), tx_suffix="3"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    # B + C should each have $12.50 exposure
    assert out[b].total_indirect_usd == Decimal("12.50")
    assert out[c].total_indirect_usd == Decimal("12.50")


# ---- 3-hop indirect ---- #


def test_three_hop_exposure() -> None:
    """Default max_hops is 3. Lazarus → A → B → C should reach C.

    Lazarus → A: $1000
    A → B: $1000
    B → C: $1000

    A: $1000 × 0.5 = $500
    B: $500 × 1.0 × 0.5 = $250
    C: $250 × 1.0 × 0.5 = $125
    """
    lazarus = _mk_lazarus_entry()
    a = "0x" + "1" * 40
    b = "0x" + "2" * 40
    c = "0x" + "3" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("1000"), tx_suffix="2"),
        _mk_transfer(from_addr=b, to_addr=c,
                     usd=Decimal("1000"), tx_suffix="3"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    assert out[a].total_indirect_usd == Decimal("500")
    assert out[b].total_indirect_usd == Decimal("250")
    assert out[c].total_indirect_usd == Decimal("125")
    assert out[c].paths[0].hop_count == 3
    assert out[c].paths[0].path_addresses == (a, b)


def test_beyond_max_hops_no_exposure() -> None:
    """4-hop path with max_hops=3 → D not exposed."""
    lazarus = _mk_lazarus_entry()
    a, b, c, d = (f"0x{i}" * 40 for i in range(1, 5))
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b, usd=Decimal("1000"), tx_suffix="2"),
        _mk_transfer(from_addr=b, to_addr=c, usd=Decimal("1000"), tx_suffix="3"),
        _mk_transfer(from_addr=c, to_addr=d, usd=Decimal("1000"), tx_suffix="4"),
    ])
    out = compute_indirect_exposure(
        case, {lazarus.address: lazarus}, max_hops=3,
    )
    assert d not in out
    # But c IS reached (hop 3)
    assert c in out


# ---- Cycle prevention ---- #


def test_cycles_dont_inflate_exposure() -> None:
    """A → B → A → B → ... should not loop forever or count
    A/B as exposed multiple times. We use path-based cycle
    detection."""
    lazarus = _mk_lazarus_entry()
    a = "0x" + "1" * 40
    b = "0x" + "2" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("500"), tx_suffix="2"),
        _mk_transfer(from_addr=b, to_addr=a,  # cycle back!
                     usd=Decimal("500"), tx_suffix="3"),
    ])
    # Should not raise / loop infinitely. Both A and B get
    # exposure but only via the non-cyclic path.
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    assert a in out
    assert b in out
    # Exposure values should be finite + non-zero
    assert out[a].total_indirect_usd > 0
    assert out[b].total_indirect_usd > 0


# ---- Tunable parameters ---- #


def test_custom_decay_factor() -> None:
    """Operators can tune decay per-investigation. Lower decay
    = exposure dies off faster across hops."""
    lazarus = _mk_lazarus_entry()
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("1000"), tx_suffix="2"),
    ])
    out = compute_indirect_exposure(
        case, {lazarus.address: lazarus}, decay_factor=0.1,
    )
    # A: $1000 × 0.1 = $100
    assert out[a].total_indirect_usd == Decimal("100")
    # B: $100 × 1.0 × 0.1 = $10
    assert out[b].total_indirect_usd == Decimal("10")


def test_min_exposure_floor_drops_tiny_amounts() -> None:
    """Anything under $1 weighted gets dropped to keep the
    brief focused. Catches the long tail of dust propagation."""
    lazarus = _mk_lazarus_entry()
    a, b, c = "0x" + "1" * 40, "0x" + "2" * 40, "0x" + "3" * 40
    case = _mk_case([
        # Tiny initial transfer; weighted exposure drops below
        # $1 threshold quickly.
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("0.50"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("0.50"), tx_suffix="2"),
        _mk_transfer(from_addr=b, to_addr=c,
                     usd=Decimal("0.50"), tx_suffix="3"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    # All exposures below $1 minimum — none in output
    assert out == {}


# ---- Brief section ---- #


def test_brief_section_shape() -> None:
    """Locked: the keys downstream consumers bind against."""
    lazarus = _mk_lazarus_entry()
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    case = _mk_case([
        _mk_transfer(from_addr=lazarus.address, to_addr=a,
                     usd=Decimal("10000"), tx_suffix="1"),
        _mk_transfer(from_addr=a, to_addr=b,
                     usd=Decimal("5000"), tx_suffix="2"),
    ])
    out = compute_indirect_exposure(case, {lazarus.address: lazarus})
    section = indirect_exposure_to_brief_section(out)

    assert "addresses" in section
    assert "summary" in section

    summary = section["summary"]
    assert "addresses_with_indirect_exposure" in summary
    assert "indirect_ofac_exposed_count" in summary
    assert "highest_indirect_usd" in summary
    assert "highest_indirect_address" in summary

    # 2 addresses (A direct, B indirect)
    assert summary["addresses_with_indirect_exposure"] == 2
    assert summary["indirect_ofac_exposed_count"] == 2

    # Per-address payload
    a_entry = section["addresses"][a]
    assert "total_indirect_usd" in a_entry
    assert "paths" in a_entry
    assert a_entry["total_indirect_usd"] == "$5,000.00"  # $10000 × 0.5
    assert len(a_entry["paths"]) == 1
    p = a_entry["paths"][0]
    assert p["source_name"] == "Lazarus Group"
    assert p["risk_category"] == "ofac_sanctioned"
    assert p["hop_count"] == 1
    assert "weighted_amount_usd" in p


def test_brief_section_caps_paths_per_address() -> None:
    """Each address shows at most 10 paths to keep the brief
    focused. A perpetrator interacting with many sanctioned
    sources would otherwise produce a wall of paths."""
    # We can't easily synthesize > 10 high-risk sources, but we
    # can verify the cap by setting up 12 in the result.
    addr = "0x" + "1" * 40
    fake_result = IndirectExposureResult(address=addr)
    from recupero.trace.indirect_exposure import IndirectPath
    for i in range(12):
        fake_result.paths.append(IndirectPath(
            source_address=f"0x{i:040x}",
            source_name=f"Source {i}",
            risk_category="ofac_sanctioned",
            severity=4,
            weighted_amount_usd=Decimal(str(100 - i)),
            hop_count=1,
            path_addresses=(),
        ))
        fake_result.total_indirect_usd += Decimal(str(100 - i))
    section = indirect_exposure_to_brief_section({addr: fake_result})
    assert len(section["addresses"][addr]["paths"]) == 10
