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
    detect_same_asset_split,
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


# ---------- v0.34 audit fix: token-symbol-spoofing / contract identity --------

_DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"
_SCAM = "0x" + "ba" * 20


def _cleg(amount, *, symbol="DAI", contract=None, usd=None, to="0xout",
          tx="0xout", mins=5):
    return Leg(
        to_address=to, tx_hash=tx, token_symbol=symbol,
        amount=Decimal(str(amount)),
        usd_value=None if usd is None else Decimal(str(usd)),
        when=T0 + timedelta(minutes=mins), token_contract=contract,
    )


def test_spoof_symbol_different_contract_is_not_same_asset() -> None:
    """A scam token with a colliding symbol ("DAI") at a matching amount must
    NOT be treated as a same-asset forward — that would fabricate a destination
    at medium. With no USD it yields NO match at all."""
    inbound = Leg(to_address="0xnode", tx_hash="0xin", token_symbol="DAI",
                  amount=Decimal("1000"), usd_value=None, when=T0,
                  token_contract=_DAI)
    cand = _cleg(1000, symbol="DAI", contract=_SCAM, to="0xscam")
    assert match_onward_transfers(inbound, [cand]) == []


def test_same_contract_same_asset_is_medium() -> None:
    inbound = Leg(to_address="0xnode", tx_hash="0xin", token_symbol="DAI",
                  amount=Decimal("1000"), usd_value=None, when=T0,
                  token_contract=_DAI)
    cand = _cleg(1000, symbol="DAI", contract=_DAI, to="0xreal")
    matches = match_onward_transfers(inbound, [cand])
    assert len(matches) == 1
    assert matches[0].kind == "same_asset_amount"
    assert matches[0].confidence == "medium"
    assert matches[0].to_address == "0xreal"


def test_native_no_contract_both_sides_matches() -> None:
    """Native ETH (no contract on either side) still same-asset matches."""
    inbound = Leg(to_address="0xnode", tx_hash="0xin", token_symbol="ETH",
                  amount=Decimal("50"), usd_value=None, when=T0,
                  token_contract=None)
    cand = _cleg(50, symbol="ETH", contract=None, to="0xreal")
    matches = match_onward_transfers(inbound, [cand])
    assert len(matches) == 1 and matches[0].kind == "same_asset_amount"


def test_spoof_symbol_with_usd_demotes_to_cross_asset_low_not_medium() -> None:
    """When both legs are priced, a colliding-symbol/different-contract pair can
    still match on USD — but only at LOW (cross-asset), never the medium
    same-asset tier."""
    inbound = Leg(to_address="0xnode", tx_hash="0xin", token_symbol="DAI",
                  amount=Decimal("1000"), usd_value=Decimal("1000"), when=T0,
                  token_contract=_DAI)
    cand = _cleg(1000, symbol="DAI", contract=_SCAM, usd=1000, to="0xscam")
    matches = match_onward_transfers(inbound, [cand])
    assert len(matches) == 1
    assert matches[0].kind == "usd_value_cross_asset"
    assert matches[0].confidence == "low"


def test_naive_block_time_is_normalized_and_does_not_crash() -> None:
    """A naive block_time (dict path) must be normalized to UTC so the
    time-window comparison against an aware inbound doesn't raise TypeError
    (which would abort the whole wave aggregation)."""
    from datetime import datetime as _dt
    leg = leg_from_transfer({
        "to_address": "0xout", "tx_hash": "0xy",
        "token": {"symbol": "DAI", "contract": _DAI},
        "amount_decimal": Decimal("1000"),
        "block_time": _dt(2025, 10, 9, 12, 5),  # NAIVE (no tzinfo)
    })
    assert leg is not None and leg.when.tzinfo is not None
    inbound = Leg(to_address="0xnode", tx_hash="0xin", token_symbol="DAI",
                  amount=Decimal("1000"), usd_value=None, when=T0,
                  token_contract=_DAI)
    # must not raise (aware inbound vs normalized candidate)
    matches = match_onward_transfers(inbound, [leg])
    assert len(matches) == 1 and matches[0].kind == "same_asset_amount"


# ---- v0.34.2: homoglyph / address-poisoning token rejection ----


def test_is_confusable_token_symbol() -> None:
    from recupero.trace.value_matching import is_confusable_token_symbol
    # legit ASCII symbols → not confusable
    assert not is_confusable_token_symbol("USDC")
    assert not is_confusable_token_symbol("WETH")
    assert not is_confusable_token_symbol("USDC.e")
    assert not is_confusable_token_symbol("")
    assert not is_confusable_token_symbol(None)
    # homoglyph poison (Lisu "USDC", "₮" glyph, Cyrillic) → confusable
    assert is_confusable_token_symbol("ꓴꓢꓓС")     # Lisu mimic of USDC
    assert is_confusable_token_symbol("USD₮0")     # ₮ = U+20AE
    assert is_confusable_token_symbol("UЅDС")      # Cyrillic S/C


def test_leg_from_transfer_rejects_homoglyph_token() -> None:
    """A homoglyph-poison token must NOT produce a matchable leg — otherwise the
    unpriced-same-asset follow would chase address-poisoning spam."""
    leg = leg_from_transfer({
        "to_address": "0xpoison", "tx_hash": "0xp",
        "token": {"symbol": "ꓴꓢꓓС", "contract": "0xb4094bd2"},
        "amount_decimal": Decimal("349999"),
        "block_time": datetime(2025, 10, 9, 12, 0, tzinfo=UTC),
    })
    assert leg is None


def test_real_usdc_leg_still_built() -> None:
    leg = leg_from_transfer({
        "to_address": "0xreal", "tx_hash": "0xr",
        "token": {"symbol": "USDC", "contract": "0xaf88d065"},
        "amount_decimal": Decimal("349999"),
        "block_time": datetime(2025, 10, 9, 12, 0, tzinfo=UTC),
    })
    assert leg is not None and leg.token_symbol == "USDC"


# ----------------------- 1:N split / peel (v0.34.6) -------------------------
#
# A consolidation wallet receives the loot and forwards it onward as MANY
# smaller same-asset sends (a peel) — the pattern that dead-ended the
# Lazarus/Ronin trace one hop short. The 1:1 matcher finds nothing; the split
# detector recovers the peel, conservatively, at LOW confidence.


def _split_to(amount, to, tx, mins, symbol="DAI"):
    return _leg(amount, symbol=symbol, to=to, tx=tx, mins=mins)


def test_split_peel_found_low_confidence_all_legs() -> None:
    inbound = _inbound(amount=1000, symbol="DAI", usd=1000)
    # 1:1 matcher sees nothing (no single ~1000 outflow). 400+350+260 = 1010
    # (Δ1% ≤ 3%); the tiny 5 DAI leg is left out (greedy reaches the sum first).
    cands = [
        _split_to(400, "0xa", "0xo1", 10),
        _split_to(350, "0xb", "0xo2", 12),
        _split_to(260, "0xc", "0xo3", 15),
        _split_to(5,   "0xd", "0xo4", 20),
    ]
    assert match_onward_transfers(inbound, cands) == []  # 1:1 truly misses it
    legs = detect_same_asset_split(inbound, cands)
    assert {m.to_address for m in legs} == {"0xa", "0xb", "0xc"}
    assert all(m.kind == "same_asset_split" for m in legs)
    assert all(m.confidence == "low" for m in legs)        # never medium/high
    assert all(m.ambiguous for m in legs)                  # the 5 DAI leg remains


def test_split_overshoot_returns_empty() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # 700 + 600 = 1300 > 1030 (the second leg blows past the band) -> no peel.
    cands = [_split_to(700, "0xa", "0xo1", 10), _split_to(600, "0xb", "0xo2", 12)]
    assert detect_same_asset_split(inbound, cands) == []


def test_split_undershoot_returns_empty() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # 300 + 200 + 150 = 650 < 970 -> never reaches the inbound sum.
    cands = [
        _split_to(300, "0xa", "0xo1", 10),
        _split_to(200, "0xb", "0xo2", 12),
        _split_to(150, "0xc", "0xo3", 14),
    ]
    assert detect_same_asset_split(inbound, cands) == []


def test_split_excludes_single_overlarge_leg() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # 5000 alone is > inbound×(1+tol) so it can't be a peel leg and is excluded;
    # 600 + 420 = 1020 (Δ2%) is the recovered peel.
    cands = [
        _split_to(5000, "0xbig", "0xo0", 8),
        _split_to(600, "0xa", "0xo1", 10),
        _split_to(420, "0xb", "0xo2", 12),
        _split_to(10, "0xc", "0xo3", 14),
    ]
    legs = detect_same_asset_split(inbound, cands)
    assert {m.to_address for m in legs} == {"0xa", "0xb"}
    assert "0xbig" not in {m.to_address for m in legs}


def test_split_requires_at_least_two_legs() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # A single ~inbound leg is a 1:1 case, not a split.
    assert detect_same_asset_split(inbound, [_split_to(990, "0xa", "0xo1", 10)]) == []


def test_split_too_many_legs_bails() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # 40 legs of 30 each would be needed to reach 1000 — exceeds the 25-leg cap.
    cands = [_split_to(30, f"0x{i:02x}", f"0xo{i}", 10 + i) for i in range(40)]
    assert detect_same_asset_split(inbound, cands) == []


def test_split_wrong_token_not_summed() -> None:
    inbound = _inbound(amount=1000, symbol="DAI", usd=1000)
    # Same USD ballpark but a DIFFERENT symbol — never summed as same-asset.
    cands = [
        _split_to(500, "0xa", "0xo1", 10, symbol="USDC"),
        _split_to(520, "0xb", "0xo2", 12, symbol="USDC"),
    ]
    assert detect_same_asset_split(inbound, cands) == []


def test_split_spoof_contract_not_summed() -> None:
    # Same SYMBOL ("DAI") but a different on-chain contract = a spoof token.
    inbound = Leg(
        to_address="0xnode", tx_hash="0xin", token_symbol="DAI",
        amount=Decimal("1000"), usd_value=Decimal("1000"), when=T0,
        token_contract="0x6b175474e89094c44da98b954eedeac495271d0f",  # real DAI
    )
    spoof = [
        Leg(to_address="0xa", tx_hash="0xo1", token_symbol="DAI",
            amount=Decimal("600"), usd_value=None, when=T0 + timedelta(minutes=10),
            token_contract="0xdeadbeef"),
        Leg(to_address="0xb", tx_hash="0xo2", token_symbol="DAI",
            amount=Decimal("420"), usd_value=None, when=T0 + timedelta(minutes=12),
            token_contract="0xdeadbeef"),
    ]
    assert detect_same_asset_split(inbound, spoof) == []


def test_split_respects_time_window() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # Both legs sum to 1010 but one is outside the 72h window -> not a peel.
    cands = [
        _split_to(600, "0xa", "0xo1", mins=10),
        _leg(410, symbol="DAI", to="0xb", tx="0xo2",
             when=T0 + timedelta(hours=80)),
    ]
    assert detect_same_asset_split(inbound, cands) == []


def test_split_ignores_pre_inbound_outflow() -> None:
    inbound = _inbound(amount=1000, symbol="DAI")
    # An outflow BEFORE the inbound can't be the onward peel.
    cands = [
        _leg(600, symbol="DAI", to="0xa", tx="0xo1", when=T0 - timedelta(minutes=5)),
        _split_to(420, "0xb", "0xo2", mins=10),
    ]
    assert detect_same_asset_split(inbound, cands) == []
