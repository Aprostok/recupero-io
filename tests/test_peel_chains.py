"""Unit tests for peel-chain detection (trace-depth #1, go-deeper).

Synthetic from→to→amount graphs (duck-typed transfers). Covers: a clean
long chain (medium), a short chain (low), below-min (none), a co-equal split
(not a peel), suffix-not-double-reported, cycle safety, amount-only
fallback, and the forensic invariant (never "high").
"""

from __future__ import annotations

from decimal import Decimal

from recupero.trace.peel_chains import detect_peel_chains


class _T:
    def __init__(self, frm: str, to: str, usd=None, amt=None) -> None:  # noqa: ANN001
        self.from_address = frm
        self.to_address = to
        self.usd_value_at_tx = Decimal(usd) if usd is not None else None
        self.amount_decimal = Decimal(amt) if amt is not None else None


class _Case:
    def __init__(self, transfers) -> None:  # noqa: ANN001
        self.transfers = transfers


def _addr(n: int) -> str:
    return "0x" + f"{n:040x}"


def _peel_run(n_hops: int, *, usd: bool = True) -> list[_T]:
    """Build an n_hops peel chain: A0 → A1 → … → A{n}, each An peeling a
    small cashout off the dominant remainder forwarded to A{n+1}."""
    txs: list[_T] = []
    remainder = 100
    for i in range(n_hops):
        a, nxt, peel = _addr(i), _addr(i + 1), _addr(1000 + i)
        if usd:
            txs.append(_T(a, nxt, usd=remainder))
            txs.append(_T(a, peel, usd=max(2, remainder // 12)))
        else:
            txs.append(_T(a, nxt, amt=remainder))
            txs.append(_T(a, peel, amt=max(2, remainder // 12)))
        remainder = int(remainder * 0.9)
    return txs


def test_long_clean_chain_is_medium() -> None:
    chains = detect_peel_chains(_Case(_peel_run(5)))
    assert len(chains) == 1
    c = chains[0]
    assert len(c.hops) == 5
    assert c.confidence == "medium"
    assert c.confidence != "high"
    # remainder chain is the ordered run A0..A5 (n_hops+1 addresses).
    assert c.remainder_chain[0] == _addr(0)
    assert len(c.remainder_chain) == 6
    # peel recipients are the cashout candidates (one per hop).
    assert len(c.peel_recipients) == 5


def test_short_chain_is_low() -> None:
    chains = detect_peel_chains(_Case(_peel_run(3)))
    assert len(chains) == 1
    assert chains[0].confidence == "low"


def test_below_min_hops_not_detected() -> None:
    assert detect_peel_chains(_Case(_peel_run(2))) == []


def test_invariant_never_high() -> None:
    for n in (3, 5, 10):
        for c in detect_peel_chains(_Case(_peel_run(n))):
            assert c.confidence in ("low", "medium")
            assert c.confidence != "high"


def test_co_equal_split_is_not_a_peel() -> None:
    """Two ~50/50 outflows (a split, not a peel) → no dominant remainder →
    not classified as a peel hop, so no chain."""
    txs = []
    for i in range(4):
        a = _addr(i)
        txs.append(_T(a, _addr(i + 1), usd=50))
        txs.append(_T(a, _addr(2000 + i), usd=50))  # co-equal, not a peel
    assert detect_peel_chains(_Case(txs)) == []


def test_suffix_not_double_reported() -> None:
    """A single A→B→C→D→E→F chain must report ONE chain starting at A, not
    also the B…, C… suffixes."""
    chains = detect_peel_chains(_Case(_peel_run(5)))
    assert len(chains) == 1
    assert chains[0].remainder_chain[0] == _addr(0)


def test_cycle_does_not_hang() -> None:
    """A remainder cycle (A→B→A) must terminate, not infinite-loop."""
    txs = [
        _T(_addr(0), _addr(1), usd=100), _T(_addr(0), _addr(900), usd=5),
        _T(_addr(1), _addr(0), usd=90), _T(_addr(1), _addr(901), usd=4),
    ]
    # Should not hang; may or may not produce a (short) chain — just return.
    result = detect_peel_chains(_Case(txs), min_hops=2)
    assert isinstance(result, list)


def test_amount_only_fallback_when_unpriced() -> None:
    """Unpriced transfers still form a peel chain via token-amount basis."""
    chains = detect_peel_chains(_Case(_peel_run(4, usd=False)))
    assert len(chains) == 1
    assert chains[0].valued_in == "amount"
    assert chains[0].confidence == "low"  # 4 hops < medium threshold (5)


def test_empty_case_returns_empty() -> None:
    assert detect_peel_chains(_Case([])) == []


def test_to_dict_shape() -> None:
    c = detect_peel_chains(_Case(_peel_run(5)))[0]
    d = c.to_dict()
    assert d["heuristic"] == "peel_chain"
    assert d["attribution_confidence"] == "medium"
    assert d["hop_count"] == 5
    assert isinstance(d["peel_recipients"], list)
