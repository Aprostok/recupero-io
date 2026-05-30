"""v0.33.0 Wave C — different-address (amount+time-only) bridge matching.

For bridges that mint to a DIFFERENT recipient than the source sender, there
is no same-address link to corroborate a match. ``match_bridge_withdrawal``'s
``amount_time_only=True`` mode is therefore deliberately strict so it surfaces
a different-address lead ONLY when the correlation is genuinely meaningful —
never noise:

  * the source amount must be DISTINCTIVE (>= min_significant_digits) — round
    amounts (1, 100, 0.5) are rejected outright (too coincidence-prone);
  * exactly ONE candidate may qualify — any second qualifier → None;
  * a surviving match is ALWAYS "low" confidence (never medium/high).

The default mode (amount_time_only=False, used by the same-address
lock-and-mint caller) is unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.trace.bridge_matching import (
    BridgeMatchCandidate,
    match_bridge_withdrawal,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _cand(*, amt: str, tx: str = "0xabc", addr: str = "0xrecipient",
          mins: int = 5, sym: str | None = "ETH") -> BridgeMatchCandidate:
    return BridgeMatchCandidate(
        chain="arbitrum", address=addr, tx_hash=tx,
        amount_decimal=Decimal(amt), block_time=_T0 + timedelta(minutes=mins),
        token_symbol=sym,
    )


def test_distinctive_unique_match_is_low_never_medium() -> None:
    # Tight + unique + distinctive amount, but different-address mode -> low.
    r = match_bridge_withdrawal(
        source_amount=Decimal("1.23456"), source_time=_T0,
        candidates=[_cand(amt="1.23456", mins=3)], amount_time_only=True,
    )
    assert r is not None
    assert r.confidence == "low"
    assert "DIFFERENT" in r.reason


def test_round_amount_refused_without_address_link() -> None:
    for amt in ("1.0", "100", "0.5", "10"):
        r = match_bridge_withdrawal(
            source_amount=Decimal(amt), source_time=_T0,
            candidates=[_cand(amt=amt)], amount_time_only=True,
        )
        assert r is None, amt


def test_multiple_qualifiers_refused() -> None:
    cs = [
        _cand(amt="1.23456", tx="0xa", addr="0xA", mins=4),
        _cand(amt="1.23456", tx="0xb", addr="0xB", mins=9),
    ]
    assert match_bridge_withdrawal(
        source_amount=Decimal("1.23456"), source_time=_T0,
        candidates=cs, amount_time_only=True,
    ) is None


def test_same_address_mode_unaffected_by_round_amount() -> None:
    # Default mode (caller guarantees same-address): a round amount still
    # matches and can be medium — the new gates DON'T apply here.
    r = match_bridge_withdrawal(
        source_amount=Decimal("1.0"), source_time=_T0,
        candidates=[_cand(amt="1.0", mins=3)],
    )
    assert r is not None  # not refused
    assert r.confidence in ("medium", "low")


def test_min_significant_digits_is_tunable() -> None:
    src = Decimal("1.23")  # 3 sig digits
    assert match_bridge_withdrawal(
        source_amount=src, source_time=_T0,
        candidates=[_cand(amt="1.23")], amount_time_only=True,
    ) is None  # below default of 5
    r = match_bridge_withdrawal(
        source_amount=src, source_time=_T0,
        candidates=[_cand(amt="1.23")], amount_time_only=True,
        min_significant_digits=3,
    )
    assert r is not None and r.confidence == "low"


def test_no_qualifier_returns_none() -> None:
    # Distinctive + unique window, but amount out of slippage -> no match.
    assert match_bridge_withdrawal(
        source_amount=Decimal("1.23456"), source_time=_T0,
        candidates=[_cand(amt="9.99999")], amount_time_only=True,
    ) is None


def test_never_high_confidence() -> None:
    r = match_bridge_withdrawal(
        source_amount=Decimal("13.37428"), source_time=_T0,
        candidates=[_cand(amt="13.37428", mins=1)], amount_time_only=True,
    )
    assert r is not None
    assert r.confidence != "high"
    assert r.confidence == "low"
