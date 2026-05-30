"""Unit tests for cross-chain lock-and-mint matching (trace-depth #1).

Pure matcher — no network, no clock. Covers: clean unique match → medium,
loose match → low, fee-deducted amount, time-window + direction gates,
asset gate, ambiguity → low+flag, and the no-match cases. Also locks the
forensic invariant: a cross-chain correlation NEVER returns "high".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.trace.bridge_matching import (
    BridgeMatchCandidate,
    candidates_from_transfers,
    match_bridge_withdrawal,
)

_T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _cand(
    *,
    amount: str,
    minutes_after: float,
    chain: str = "arbitrum",
    addr: str = "0x" + "d" * 40,
    tx: str = "0x" + "1" * 64,
    symbol: str | None = "USDC",
) -> BridgeMatchCandidate:
    return BridgeMatchCandidate(
        chain=chain,
        address=addr,
        tx_hash=tx,
        amount_decimal=Decimal(amount),
        block_time=_T0 + timedelta(minutes=minutes_after),
        token_symbol=symbol,
    )


# ---- clean / unique match ---- #


def test_clean_unique_match_is_medium() -> None:
    """A single candidate, exact amount, minutes later → medium (the top
    confidence a circumstantial cross-chain correlation can earn)."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        source_token_symbol="USDC",
        candidates=[_cand(amount="100000", minutes_after=3)],
    )
    assert res is not None
    assert res.confidence == "medium"
    assert res.ambiguous is False
    assert res.candidate.chain == "arbitrum"


def test_fee_deducted_amount_still_matches_medium() -> None:
    """Destination = source minus a ~0.3% bridge fee → still a tight,
    unique match."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        source_token_symbol="USDC",
        candidates=[_cand(amount="99700", minutes_after=5)],  # 0.3% fee
    )
    assert res is not None
    assert res.confidence == "medium"


def test_invariant_never_returns_high() -> None:
    """Hard invariant: no input can make the matcher emit 'high'."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="100000", minutes_after=0)],
    )
    assert res is not None
    assert res.confidence in ("medium", "low")
    assert res.confidence != "high"


# ---- loose match → low ---- #


def test_loose_amount_within_outer_tolerance_is_low() -> None:
    """1.5% off (inside the 2% outer bound but outside the 0.5% tight
    bound) → low confidence."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="98500", minutes_after=10)],  # 1.5% off
    )
    assert res is not None
    assert res.confidence == "low"


def test_late_but_in_window_is_low() -> None:
    """Exact amount but 6 hours later (inside 24h window, outside 2h tight
    window) → low."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="100000", minutes_after=6 * 60)],
    )
    assert res is not None
    assert res.confidence == "low"


# ---- gates that reject ---- #


def test_withdrawal_before_deposit_rejected() -> None:
    """A 'mint' cannot precede the lock — negative delay is rejected."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="100000", minutes_after=-5)],
    )
    assert res is None


def test_outside_window_rejected() -> None:
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        window_hours=24.0,
        candidates=[_cand(amount="100000", minutes_after=25 * 60)],
    )
    assert res is None


def test_amount_too_far_rejected() -> None:
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="80000", minutes_after=3)],  # 20% off
    )
    assert res is None


def test_destination_larger_than_source_rejected() -> None:
    """A payout MORE than slippage above the deposit isn't explained by a
    fee deduction — not matched."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[_cand(amount="105000", minutes_after=3)],  # +5%
    )
    assert res is None


def test_wrong_asset_rejected_when_both_symbols_known() -> None:
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        source_token_symbol="USDC",
        candidates=[_cand(amount="100000", minutes_after=3, symbol="DAI")],
    )
    assert res is None


def test_unknown_candidate_symbol_not_excluded() -> None:
    """A candidate with an unknown symbol can't be confirmed on asset but
    is NOT excluded — we may simply not have identified its token."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        source_token_symbol="USDC",
        candidates=[_cand(amount="100000", minutes_after=3, symbol=None)],
    )
    assert res is not None


# ---- ambiguity ---- #


def test_two_equally_close_candidates_is_ambiguous_low() -> None:
    """Two candidates at the same amount + window → cannot single one out;
    returned as a low-confidence lead flagged ambiguous (not dropped, not
    over-claimed)."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[
            _cand(amount="100000", minutes_after=3, addr="0x" + "a" * 40,
                  tx="0x" + "a" * 64),
            _cand(amount="100000", minutes_after=4, addr="0x" + "b" * 40,
                  tx="0x" + "b" * 64),
        ],
    )
    assert res is not None
    assert res.ambiguous is True
    assert res.confidence == "low"


def test_clear_winner_among_several_not_ambiguous() -> None:
    """One exact match + one far-off (but in-tolerance) candidate → the
    exact one wins cleanly, not ambiguous."""
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        candidates=[
            _cand(amount="100000", minutes_after=2, addr="0x" + "a" * 40,
                  tx="0x" + "a" * 64),                       # exact
            _cand(amount="98200", minutes_after=2, addr="0x" + "b" * 40,
                  tx="0x" + "b" * 64),                       # 1.8% off
        ],
    )
    assert res is not None
    assert res.ambiguous is False
    assert res.confidence == "medium"
    assert res.candidate.address == "0x" + "a" * 40


# ---- empty / degenerate ---- #


def test_no_candidates_returns_none() -> None:
    assert match_bridge_withdrawal(
        source_amount=Decimal("100000"), source_time=_T0, candidates=[],
    ) is None


def test_nonpositive_source_returns_none() -> None:
    assert match_bridge_withdrawal(
        source_amount=Decimal("0"), source_time=_T0,
        candidates=[_cand(amount="100000", minutes_after=1)],
    ) is None


# ---- candidates_from_transfers adapter ---- #


def test_candidates_from_transfers_maps_domain_objects() -> None:
    """The integration seam maps the project's Transfer model (duck-typed)
    into matcher candidates, skipping rows missing amount/time."""
    from recupero.models import Chain, Counterparty, TokenRef, Transfer

    t = Transfer(
        transfer_id="arbitrum:0xabc:0",
        chain=Chain.arbitrum,
        tx_hash="0xabc",
        block_number=1,
        block_time=_T0 + timedelta(minutes=2),
        from_address="0x" + "f" * 40,
        to_address="0x" + "d" * 40,
        counterparty=Counterparty(address="0x" + "d" * 40),
        token=TokenRef(chain=Chain.arbitrum, symbol="USDC", decimals=6),
        amount_raw="100000000000",
        amount_decimal=Decimal("100000"),
        usd_value_at_tx=Decimal("100000"),
        fetched_at=_T0,
        explorer_url="https://arbiscan.io/tx/0xabc",
    )
    cands = candidates_from_transfers([t])
    assert len(cands) == 1
    assert cands[0].chain == "arbitrum"
    assert cands[0].address == "0x" + "d" * 40
    assert cands[0].token_symbol == "USDC"
    assert cands[0].amount_decimal == Decimal("100000")

    # End-to-end: the mapped candidate matches the source deposit.
    res = match_bridge_withdrawal(
        source_amount=Decimal("100000"),
        source_time=_T0,
        source_token_symbol="USDC",
        candidates=cands,
    )
    assert res is not None
    assert res.confidence == "medium"


# ---- match_lockmint_destination (cross_chain integration, fake adapter) ---- #


class _TokenRef:
    def __init__(self, symbol: str, decimals: int) -> None:
        self.symbol = symbol
        self.decimals = decimals


class _FakeChain:
    value = "arbitrum"


class _FakeDstAdapter:
    """Minimal ChainAdapter stand-in: returns canned inbound rows in the
    normalized dict shape the EVM adapter's fetch_*_inflows produce."""

    chain = _FakeChain()

    def __init__(self, native_rows=None, erc20_rows=None) -> None:
        self._native = native_rows or []
        self._erc20 = erc20_rows or []

    def block_at_or_before(self, ts):  # noqa: ANN001
        return 1

    def fetch_native_inflows(self, to_address, start_block, *, max_results=None):  # noqa: ANN001
        return self._native

    def fetch_erc20_inflows(self, to_address, start_block, *, max_results=None):  # noqa: ANN001
        return self._erc20


def _handoff(amount: str = "100000", token: str = "USDC"):
    from recupero.trace.cross_chain import CrossChainHandoff

    from recupero.models import Chain

    return CrossChainHandoff(
        source_address="0x" + "f" * 40,
        source_chain=Chain.ethereum,
        source_tx_hash="0xsrc",
        source_explorer_url="https://etherscan.io/tx/0xsrc",
        bridge_name="Celer cBridge",
        bridge_protocol="celer",
        bridge_address="0x" + "c" * 40,
        amount_decimal=Decimal(amount),
        amount_usd=Decimal(amount),
        token_symbol=token,
        block_time_iso="2026-01-01T12:00:00Z",
        destination_chain_candidates=("arbitrum",),
        follow_up_url=None,
    )


def test_match_lockmint_destination_same_address_inbound_match() -> None:
    """End-to-end: a lock-mint handoff (no decoded recipient) + the perp's
    inbound USDC on the destination chain within the window → matched at
    medium confidence (correlation, never high)."""
    from recupero.trace.cross_chain import match_lockmint_destination

    erc20_rows = [{
        "chain": _FakeChain(),
        "to": "0x" + "f" * 40,
        "tx_hash": "0xmint",
        "amount_raw": 99700000000,            # 99,700 USDC (6 decimals), 0.3% fee
        "block_time": _T0 + timedelta(minutes=4),
        "token": _TokenRef("USDC", 6),
        "explorer_url": "https://arbiscan.io/tx/0xmint",
    }]
    res = match_lockmint_destination(
        _handoff(amount="100000"),
        dst_adapter=_FakeDstAdapter(erc20_rows=erc20_rows),
    )
    assert res is not None
    assert res.confidence in ("medium", "low")
    assert res.confidence != "high"
    assert res.candidate.tx_hash == "0xmint"


def test_match_lockmint_destination_no_inbound_returns_none() -> None:
    """No inbound activity on the candidate chain → no match (trail simply
    isn't on this chain)."""
    from recupero.trace.cross_chain import match_lockmint_destination

    res = match_lockmint_destination(
        _handoff(), dst_adapter=_FakeDstAdapter(),
    )
    assert res is None


def test_match_lockmint_destination_amount_mismatch_returns_none() -> None:
    """Inbound exists but the amount is far off → not our funds, no match."""
    from recupero.trace.cross_chain import match_lockmint_destination

    erc20_rows = [{
        "chain": _FakeChain(), "to": "0x" + "f" * 40, "tx_hash": "0xother",
        "amount_raw": 5000000000,             # 5,000 USDC — unrelated
        "block_time": _T0 + timedelta(minutes=4),
        "token": _TokenRef("USDC", 6),
        "explorer_url": "https://arbiscan.io/tx/0xother",
    }]
    res = match_lockmint_destination(
        _handoff(amount="100000"),
        dst_adapter=_FakeDstAdapter(erc20_rows=erc20_rows),
    )
    assert res is None
