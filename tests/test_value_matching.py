"""v0.34 value-directed onward-hop matching (operator-requested "elite recall").

At a high-fan-out node (aggregator/pool/service wallet) the tracer must follow
the outflow that carries OUR funds, not all of them. ``match_onward_transfers``
ranks the node's outflows against the inbound funds by:

  1. same-asset amount match (strongest), and
  2. USD-value match across an asset conversion (weaker).

These tests pin the forensic contract that keeps it from fabricating a path:
  * an exact same-asset forward is found and (when unique) rated ``medium``;
  * a cross-asset USD match is found but capped at ``low``;
  * MULTIPLE matches -> every candidate demoted to ``low`` + ambiguous (we never
    claim to know which edge carried the funds when several qualify);
  * outflows BEFORE the inflow or outside the time window are ignored;
  * nothing within tolerance -> empty list (never guess);
  * confidence is NEVER "high".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.trace.value_matching import (
    Leg,
    leg_from_transfer,
    match_onward_transfers,
)

T0 = datetime(2025, 10, 9, 12, 0, tzinfo=UTC)


def _leg(amount, symbol="DAI", usd=None, to="0xdead", tx="0xtx", when=None, mins=0):
    return Leg(
        to_address=to,
        tx_hash=tx,
        token_symbol=symbol,
        amount=Decimal(str(amount)),
        usd_value=None if usd is None else Decimal(str(usd)),
        when=when or (T0 + timedelta(minutes=mins)),
    )


def _inbound(amount=1000, symbol="DAI", usd=1000):
    return _leg(amount, symbol=symbol, usd=usd, to="0xnode", tx="0xin", mins=0)


# ----------------------- same-asset amount match ----------------------------


def test_sole_same_asset_amount_match_is_medium() -> None:
    inbound = _inbound(amount=1000, symbol="DAI", usd=1000)
    cands = [
        _leg(1000, symbol="DAI", to="0xreal", tx="0xout1", mins=10),   # exact fwd
        _leg(3, symbol="DAI", to="0xnoise", tx="0xout2", mins=12),     # unrelated small
        _leg(50000, symbol="USDC", to="0xother", tx="0xout3", mins=5), # other token
    ]
    matches = match_onward_transfers(inbound, cands)
    assert len(matches) == 1
    m = matches[0]
    assert m.to_address == "0xreal"
    assert m.kind == "same_asset_amount"
    assert m.confidence == "medium"
    assert m.ambiguous is False


def test_within_fee_tolerance_still_matches() -> None:
    """A 0.5% fee haircut on a forward still matches (<= 2% default)."""
    inbound = _inbound(amount=1000, symbol="DAI")
    cands = [_leg("995", symbol="DAI", to="0xreal", tx="0xo", mins=30)]
    matches = match_onward_transfers(inbound, cands)
    assert len(matches) == 1
    assert matches[0].confidence == "medium"


def test_outside_amount_tolerance_no_match() -> None:
    inbound = _inbound(amount=1000, symbol="DAI", usd=None)
    cands = [_leg("800", symbol="DAI", to="0xreal", tx="0xo", mins=10)]  # 20% off
    assert match_onward_transfers(inbound, cands) == []


def test_multiple_amount_matches_are_low_and_ambiguous() -> None:
    """Two outflows both forward ≈the inbound amount -> we cannot know which
    carried our funds, so BOTH are demoted to low + ambiguous."""
    inbound = _inbound(amount=1000, symbol="DAI")
    cands = [
        _leg(1000, symbol="DAI", to="0xa", tx="0xo1", mins=10),
        _leg(1001, symbol="DAI", to="0xb", tx="0xo2", mins=20),
    ]
    matches = match_onward_transfers(inbound, cands)
    assert len(matches) == 2
    assert all(m.confidence == "low" for m in matches)
    assert all(m.ambiguous for m in matches)


# ----------------------- cross-asset USD match ------------------------------


def test_cross_asset_usd_match_is_low() -> None:
    """Hub received $1,000,000 of mSyrupUSDp; emits ≈$1,000,000 of DAI. Amounts
    differ (different tokens) but USD value matches -> low-confidence lead."""
    inbound = _inbound(amount=950, symbol="MSYRUPUSDP", usd=1_000_000)
    cands = [
        _leg(1_002_000, symbol="DAI", usd=1_002_000, to="0xrest", tx="0xo", mins=15),
    ]
    matches = match_onward_transfers(inbound, cands)
    assert len(matches) == 1
    assert matches[0].kind == "usd_value_cross_asset"
    assert matches[0].confidence == "low"
    assert matches[0].to_address == "0xrest"


def test_same_asset_outranks_usd() -> None:
    """When both a same-asset amount match and a USD match exist, the
    same-asset match ranks first."""
    inbound = _inbound(amount=1000, symbol="DAI", usd=1000)
    cands = [
        _leg(1010, symbol="WETH", usd=1000, to="0xusd", tx="0xo1", mins=10),  # usd match
        _leg(1000, symbol="DAI", usd=1000, to="0xamt", tx="0xo2", mins=20),   # amount match
    ]
    matches = match_onward_transfers(inbound, cands)
    assert matches[0].to_address == "0xamt"
    assert matches[0].kind == "same_asset_amount"


# ----------------------- timing / window guards -----------------------------


def test_outflow_before_inflow_ignored() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    cands = [_leg(1000, symbol="DAI", to="0xpre", tx="0xo", mins=-30)]  # BEFORE
    assert match_onward_transfers(inbound, cands) == []


def test_outflow_outside_time_window_ignored() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # 100h later, default window 72h
    cands = [_leg(1000, symbol="DAI", to="0xlate", tx="0xo",
                  when=T0 + timedelta(hours=100))]
    assert match_onward_transfers(inbound, cands) == []


def test_inbound_tx_is_not_self_matched() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    cands = [_leg(1000, symbol="DAI", to="0xself", tx="0xin", mins=0)]  # same tx
    assert match_onward_transfers(inbound, cands) == []


# ----------------------- never-guess / never-high --------------------------


def test_no_candidates_returns_empty() -> None:
    assert match_onward_transfers(_inbound(), []) == []


def test_zero_inbound_value_returns_empty() -> None:
    inbound = _leg(0, symbol="DAI", usd=0, to="0xnode", tx="0xin")
    cands = [_leg(0, symbol="DAI", to="0xa", tx="0xo", mins=10)]
    assert match_onward_transfers(inbound, cands) == []


def test_confidence_is_never_high() -> None:
    inbound = _inbound(amount=1000, symbol="DAI", usd=1000)
    cands = [
        _leg(1000, symbol="DAI", usd=1000, to="0xa", tx="0xo1", mins=10),
        _leg(1000, symbol="WETH", usd=1000, to="0xb", tx="0xo2", mins=11),
    ]
    matches = match_onward_transfers(inbound, cands)
    assert matches  # something matched
    assert all(m.confidence in ("low", "medium") for m in matches)


def test_max_matches_caps_results() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    cands = [_leg(1000, symbol="DAI", to=f"0x{i}", tx=f"0xo{i}", mins=10 + i)
             for i in range(10)]
    matches = match_onward_transfers(inbound, cands, max_matches=3)
    assert len(matches) == 3


# ----------------------- leg_from_transfer adapter --------------------------


def test_leg_from_transfer_dict() -> None:
    leg = leg_from_transfer({
        "to_address": "0xabc",
        "tx_hash": "0xdef",
        "token_symbol": "dai",
        "amount_decimal": "123.4",
        "usd_value_at_tx": "123.4",
        "block_time": T0,
    })
    assert leg is not None
    assert leg.to_address == "0xabc"
    assert leg.token_symbol == "DAI"  # uppercased
    assert leg.amount == Decimal("123.4")


def test_leg_from_transfer_missing_fields_returns_none() -> None:
    assert leg_from_transfer({"tx_hash": "0x1"}) is None  # no to/amount/time


def test_leg_from_transfer_nested_token_object() -> None:
    class _Tok:
        symbol = "USDC"

    class _T:
        to_address = "0xabc"
        tx_hash = "0xdef"
        token = _Tok()
        amount_decimal = Decimal("5")
        usd_value_at_tx = Decimal("5")
        block_time = T0

    leg = leg_from_transfer(_T())
    assert leg is not None
    assert leg.token_symbol == "USDC"
