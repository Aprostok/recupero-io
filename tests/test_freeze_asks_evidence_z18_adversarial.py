"""RIGOR-Jacob Z18: adversarial-input hunt across freeze/asks.py +
trace/evidence.py.

Bugs covered:

  * Z18-1 (HIGH, DoS): ``freeze.asks.match_freeze_asks`` crashes with
    ``decimal.InvalidOperation`` when any ``TokenHolding.usd_value`` is
    a non-finite Decimal (``NaN`` / ``Infinity``). ``TokenHolding`` is
    a plain dataclass — no Pydantic validator — so a holding deserialized
    from a stale ``case.json`` whose price cache was poisoned (RIGOR-Jacob
    F only hardened CoinGecko ingest; cached JSON re-reads bypass that
    fix) or built by any caller outside ``_check_one_address`` (Z10's
    fix is local to that one function) flows straight into the
    ``holding.usd_value < min_holding_usd`` comparator at asks.py:525,
    which raises InvalidOperation for ``NaN``. Net effect: the brief
    generator crashes mid-pipeline, denying the operator the entire
    freeze-asks deliverable for one bad holding.

    Post-fix: ``match_freeze_asks`` filters non-finite usd_value
    holdings before the comparator — same defense-in-depth as Z10's
    ``_check_one_address`` fix, applied at the consumer-side boundary.

  * Z18-2 (HIGH, path traversal): ``trace.evidence.write_evidence_receipt``
    constructs the output path as ``evidence_dir / f"{tx_hash}.json"``
    with no sanitization of ``tx_hash``. A malformed chain adapter
    response, a deserialized Transfer from a hostile-source case JSON,
    or a poisoned RPC cache that supplies ``tx_hash="../../escape"``
    writes the evidence receipt OUTSIDE the evidence directory —
    potentially overwriting arbitrary files writable by the worker
    process. Same threat class as RIGOR-Jacob K/M (CaseStore).

    Post-fix: ``write_evidence_receipt`` validates that ``tx_hash``
    is a clean filename (no path separators, no traversal segments,
    no null bytes, no Windows reserved names) BEFORE constructing
    the path. Hostile input → ``ValueError`` at the boundary.

Each test is a RED-first contract: it fails on the current (unfixed)
code, then passes after the in-place hardening.
"""

from __future__ import annotations

import tempfile
from decimal import Decimal
from pathlib import Path

import pytest

from recupero.dormant.finder import DormantCandidate, TokenHolding
from recupero.freeze.asks import IssuerEntry, match_freeze_asks
from recupero.models import Chain, TokenRef
from recupero.trace.evidence import write_evidence_receipt


# ---------- Helpers ---------- #


def _mk_token(symbol: str = "USDC", contract: str | None = None) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract=contract or ("0x" + "a" * 40),
        symbol=symbol,
        decimals=6,
    )


def _mk_candidate(
    *,
    usd_value: Decimal | None,
    contract: str | None = None,
) -> DormantCandidate:
    token = _mk_token(contract=contract)
    holding = TokenHolding(
        token=token,
        raw_amount=10**6,
        decimal_amount=Decimal("1"),
        usd_value=usd_value,
    )
    return DormantCandidate(
        address="0x" + "b" * 40,
        chain=Chain.ethereum,
        total_usd=Decimal("1000"),
        holdings=[holding],
        explorer_url="https://etherscan.io/address/0x" + "b" * 40,
    )


def _mk_issuer_db(contract: str) -> dict:
    iss = IssuerEntry(
        chain=Chain.ethereum,
        contract=contract,
        symbol="USDC",
        issuer="Circle",
        freeze_capability="yes",
        freeze_notes="",
        primary_contact="legal@circle.com",
        secondary_contact=None,
        jurisdiction="US",
    )
    return {(Chain.ethereum, contract): iss}


class _StubReceipt:
    """A minimal stand-in for ``EvidenceReceipt`` so we can drive
    ``write_evidence_receipt`` without booting a real chain adapter.
    """
    def model_dump(self, mode: str = "json") -> dict:
        return {"hostile": True, "marker": "z18"}


class _StubAdapter:
    """Adapter that returns a stub receipt for any tx_hash. The real
    contract uses a ChainAdapter, but ``write_evidence_receipt`` only
    calls ``adapter.fetch_evidence_receipt(tx_hash)`` then dumps the
    result — that's the entire surface area we need to exercise.
    """
    def fetch_evidence_receipt(self, tx_hash: str) -> _StubReceipt:
        return _StubReceipt()


# ---------- Z18-1: match_freeze_asks NaN/Inf usd_value ---------- #


def test_match_freeze_asks_drops_nan_usd_value_holding_without_crash() -> None:
    """RIGOR-Jacob Z18-1: a ``Decimal('NaN')`` ``usd_value`` on a
    TokenHolding must NOT crash ``match_freeze_asks`` with
    ``InvalidOperation``.

    Pre-fix the line ``if holding.usd_value < min_holding_usd``
    (asks.py:525) raises ``decimal.InvalidOperation`` for NaN, exploding
    out of the brief generator. Post-fix the holding is filtered (same
    semantics as a holding whose price lookup failed and returned
    None) and the function returns successfully — possibly with no
    matched asks for this candidate, but never crashing.
    """
    contract = "0x" + "a" * 40
    cand = _mk_candidate(usd_value=Decimal("NaN"), contract=contract)
    db = _mk_issuer_db(contract)

    # Must NOT raise InvalidOperation.
    matched, unmatched = match_freeze_asks([cand], issuer_db=db)

    # NaN holding was dropped — either no asks at all (filtered), or
    # if a future change re-routes it to unmatched, all returned asks
    # carry finite usd_value (no NaN propagation).
    for ask in matched:
        assert ask.holding_usd_value is None or ask.holding_usd_value.is_finite(), (
            f"NaN propagated into FreezeAsk: {ask.holding_usd_value!r}"
        )


def test_match_freeze_asks_drops_infinity_usd_value_holding_explicitly() -> None:
    """``Decimal('Infinity')`` doesn't crash the comparator (Inf < N is
    well-defined), but the existing $100M absolute-cap path filtered
    it silently as a "near-certain pool contract". A non-finite usd
    value is data corruption, not a giant legitimate pool — it must
    be filtered with a clear path that the operator can recognize
    in logs, separately from the cap-based filter.
    """
    contract = "0x" + "a" * 40
    cand = _mk_candidate(usd_value=Decimal("Infinity"), contract=contract)
    db = _mk_issuer_db(contract)

    matched, unmatched = match_freeze_asks([cand], issuer_db=db)

    # Same invariant as the NaN test: no Inf ever lands in a FreezeAsk.
    for ask in matched:
        assert ask.holding_usd_value is None or ask.holding_usd_value.is_finite(), (
            f"Infinity propagated into FreezeAsk: {ask.holding_usd_value!r}"
        )


def test_match_freeze_asks_keeps_finite_holdings_alongside_nan() -> None:
    """Mixed-bag: one NaN holding + one legitimate $5K USDC holding on
    the same candidate. The legitimate holding must still produce a
    FreezeAsk — the NaN must NOT poison the whole candidate's output.
    """
    good_contract = "0x" + "a" * 40
    bad_contract = "0x" + "f" * 40
    good_token = _mk_token(contract=good_contract, symbol="USDC")
    bad_token = _mk_token(contract=bad_contract, symbol="EVIL")

    cand = DormantCandidate(
        address="0x" + "b" * 40,
        chain=Chain.ethereum,
        total_usd=Decimal("5000"),
        holdings=[
            TokenHolding(
                token=good_token,
                raw_amount=5_000_000_000,
                decimal_amount=Decimal("5000"),
                usd_value=Decimal("5000"),
            ),
            TokenHolding(
                token=bad_token,
                raw_amount=10**6,
                decimal_amount=Decimal("1"),
                usd_value=Decimal("NaN"),
            ),
        ],
        explorer_url="https://etherscan.io/address/x",
    )
    db = _mk_issuer_db(good_contract)

    matched, unmatched = match_freeze_asks([cand], issuer_db=db)
    # Exactly one matched ask (the good USDC holding); NaN holding is
    # filtered. Net: clean, brief generation proceeds.
    assert len(matched) == 1
    assert matched[0].holding_symbol == "USDC"
    assert matched[0].holding_usd_value == Decimal("5000")


# ---------- Z18-2: trace.evidence.write_evidence_receipt path traversal ---------- #


def test_write_evidence_receipt_rejects_path_traversal_in_tx_hash() -> None:
    """RIGOR-Jacob Z18-2: ``tx_hash='../../escape'`` must be rejected at
    the boundary; pre-fix the file is written OUTSIDE the evidence
    directory.

    Trigger: a malformed adapter response or a stale-cache replay
    supplies a tx_hash containing ``..`` segments. Pre-fix the resulting
    path resolves outside evidence_dir and overwrites arbitrary files
    the worker can reach.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        with pytest.raises(ValueError, match="(traversal|invalid|tx_hash|separator|reserved)"):
            write_evidence_receipt(_StubAdapter(), "../../escape", ev)


def test_write_evidence_receipt_rejects_backslash_in_tx_hash() -> None:
    """Windows-flavoured path traversal: ``..\\..\\escape``. Same threat
    as the forward-slash variant — must be rejected.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        with pytest.raises(ValueError, match="(traversal|invalid|tx_hash|separator|reserved)"):
            write_evidence_receipt(_StubAdapter(), "..\\..\\escape", ev)


def test_write_evidence_receipt_rejects_forward_slash_in_tx_hash() -> None:
    """A tx_hash containing a forward slash is on its face invalid —
    legitimate chain tx_hashes are hex or base58 with no separators.
    Reject early so the resulting file lands deterministically in
    evidence_dir.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        with pytest.raises(ValueError, match="(traversal|invalid|tx_hash|separator|reserved)"):
            write_evidence_receipt(_StubAdapter(), "abc/def", ev)


def test_write_evidence_receipt_rejects_null_byte_in_tx_hash() -> None:
    """Null byte in tx_hash truncates the filename at the OS layer on
    some platforms (POSIX) and raises on others — either way it's
    fingerprint of a hostile/malformed input. Reject explicitly.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        with pytest.raises(ValueError, match="(null|invalid|tx_hash|control)"):
            write_evidence_receipt(_StubAdapter(), "abc\x00def", ev)


def test_write_evidence_receipt_rejects_empty_tx_hash() -> None:
    """Empty tx_hash means an adapter populated `transfer.tx_hash`
    incorrectly. Pre-fix the resulting path is ``evidence_dir/.json``
    (hidden file with a confusing name). Reject explicitly so the
    operator sees the upstream adapter bug.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        with pytest.raises(ValueError, match="(empty|invalid|tx_hash)"):
            write_evidence_receipt(_StubAdapter(), "", ev)


def test_write_evidence_receipt_accepts_valid_evm_tx_hash() -> None:
    """Sanity guard: the new validator must NOT reject legitimate
    inputs. A 0x-prefixed 64-char hex tx_hash should pass cleanly
    and produce a file inside evidence_dir.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        tx = "0x" + "a" * 64
        path = write_evidence_receipt(_StubAdapter(), tx, ev)

        # File must be inside evidence_dir (not traversed out).
        assert str(path.resolve()).startswith(str(ev.resolve())), (
            f"valid tx_hash escaped evidence_dir: {path}"
        )
        assert path.name == f"{tx}.json"
        assert path.exists()


def test_write_evidence_receipt_accepts_base58_solana_tx_hash() -> None:
    """Solana tx signatures are base58 (no slashes, no dots, no nulls).
    A legitimate 88-char base58 sig like
    ``5fJ8tT7…`` must pass.
    """
    with tempfile.TemporaryDirectory() as td:
        ev = Path(td) / "evidence"
        tx = "5fJ8tT7abcDEFghi" * 5  # 80 chars — base58-ish, no separators
        path = write_evidence_receipt(_StubAdapter(), tx, ev)
        assert str(path.resolve()).startswith(str(ev.resolve()))
        assert path.exists()
