"""Adversarial regression tests for ``src/recupero/reports/aggregate.py``.

These tests sit alongside ``tests/test_reports_adversarial.py`` (W8-09)
which already locks ``json.dumps(allow_nan=False)`` on the *serialised*
aggregate. That guard turns a poisoned sum into a hard crash — useful,
but the AggregateResult itself is still poisoned by then, and the
markdown formatter (``format_aggregate_markdown``) happily renders
``$nan`` / ``$inf`` into the operator-facing summary BEFORE the JSON
is ever written.

The tests below pin five real defects that survive the W8-09 dump fix:

  1. NaN ``usd_value_at_tx`` poisons every downstream sum
     (``total_usd``, per-asset ``total_usd``, ``by_victim_wallet``).
  2. Infinity ``usd_value_at_tx`` likewise propagates.
  3. NaN ``amount_decimal`` poisons per-asset ``total_amount`` so the
     "By asset" table shows ``NaN`` for the amount column even when
     USD is clean.
  4. ``by_victim_wallet`` keys raw ``from_address`` rather than the
     canonical lower-cased EVM form, so the same wallet shipped in
     mixed case across cases is double-counted as two distinct
     victims.
  5. ``cases_examined`` retains duplicate case-IDs (mixed case)
     without normalisation, so the cover-line "Cases examined" lies
     about how many cases were rolled up.

Each test is RED against the current ``aggregate.py`` and turns GREEN
after the in-commit minimal fix.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.aggregate import (
    aggregate_stolen,
    format_aggregate_markdown,
)

# ---- fixtures ----


def _now() -> datetime:
    return datetime(2026, 5, 22, 0, 0, 0, tzinfo=UTC)


def _token(symbol: str = "USDC", contract: str | None = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=contract, symbol=symbol,
        decimals=6, coingecko_id=None,
    )


def _transfer(
    *,
    from_addr: str,
    to_addr: str,
    amount: Decimal,
    usd: Decimal | None,
    tx_hash: str = "0xaaa",
    symbol: str = "USDC",
    contract: str | None = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
) -> Transfer:
    # Pydantic's Transfer model rejects non-finite Decimals at
    # construction (`finite_number` constraint) — exactly the
    # defense we want at the model boundary. To exercise the
    # aggregate's own NaN/Inf defense-in-depth (which protects
    # against a future model regression or a model_construct path),
    # build with a finite placeholder and then smuggle the poisoned
    # value past validators via `object.__setattr__`.
    safe_usd = usd if (usd is None or usd.is_finite()) else Decimal("0")
    safe_amount = amount if amount.is_finite() else Decimal("0")
    t = Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum, tx_hash=tx_hash, block_number=1,
        block_time=_now(),
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=_token(symbol, contract),
        amount_raw="1000000",
        amount_decimal=safe_amount,
        usd_value_at_tx=safe_usd, hop_depth=0,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )
    if usd is not None and not usd.is_finite():
        object.__setattr__(t, "usd_value_at_tx", usd)
    if not amount.is_finite():
        object.__setattr__(t, "amount_decimal", amount)
    return t


def _case(case_id: str, victim: str, transfers: list[Transfer]) -> Case:
    return Case(
        case_id=case_id, seed_address=victim, chain=Chain.ethereum,
        incident_time=_now(), trace_started_at=_now(),
        trace_completed_at=_now(), transfers=transfers,
    )


PERP = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
VICTIM = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"


# ---- Bug 1: NaN usd_value_at_tx poisons every sum ----


def test_aggregate_rejects_nan_usd_value() -> None:
    """A poisoned ``usd_value_at_tx=Decimal('NaN')`` must NOT propagate
    into ``total_usd`` / per-asset ``total_usd`` / ``by_victim_wallet``.

    Pre-fix the sum becomes ``Decimal('NaN')`` and the markdown
    cover-line reads ``Total USD stolen (priced transfers only): $NaN``.
    The W8-09 guard only catches this on disk write — the operator-
    facing summary is already poisoned.
    """
    case = _case("V-CFI-1", VICTIM, [
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("100"), usd=Decimal("NaN"), tx_hash="0x1"),
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("50"), usd=Decimal("1000"), tx_hash="0x2"),
    ])
    r = aggregate_stolen(cases=[case], perpetrator_addresses=[PERP])
    assert r.total_usd.is_finite(), f"total_usd poisoned: {r.total_usd}"
    assert all(s.total_usd.is_finite() for s in r.by_asset)
    assert all(v.is_finite() for v in r.by_victim_wallet.values())
    md = format_aggregate_markdown(r)
    assert "nan" not in md.lower(), "markdown leaked NaN into operator summary"


# ---- Bug 2: Infinity usd_value_at_tx propagates ----


def test_aggregate_rejects_infinity_usd_value() -> None:
    """Infinity USD value (price-oracle glitch) must not propagate
    into the aggregate. Same defect class as Bug 1; tested separately
    because ``is_finite()`` covers both but a sloppy fix that only
    checked ``isnan`` would slip Inf through.
    """
    case = _case("V-CFI-2", VICTIM, [
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("100"), usd=Decimal("Infinity"), tx_hash="0x3"),
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("50"), usd=Decimal("500"), tx_hash="0x4"),
    ])
    r = aggregate_stolen(cases=[case], perpetrator_addresses=[PERP])
    assert r.total_usd.is_finite(), f"Inf propagated: {r.total_usd}"
    md = format_aggregate_markdown(r)
    assert "inf" not in md.lower()


# ---- Bug 3: NaN amount_decimal poisons per-asset total_amount ----


def test_aggregate_rejects_nan_amount_decimal() -> None:
    """``amount_decimal=Decimal('NaN')`` (parser/RPC glitch) poisons
    ``StolenAssetSummary.total_amount`` even when USD math is clean.
    The "By asset" table then renders ``NaN`` in the amount column.
    """
    case = _case("V-CFI-3", VICTIM, [
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("NaN"), usd=Decimal("100"), tx_hash="0x5"),
        _transfer(from_addr=VICTIM, to_addr=PERP,
                  amount=Decimal("10"), usd=Decimal("100"), tx_hash="0x6"),
    ])
    r = aggregate_stolen(cases=[case], perpetrator_addresses=[PERP])
    assert all(s.total_amount.is_finite() for s in r.by_asset)
    md = format_aggregate_markdown(r)
    assert "nan" not in md.lower()


# ---- Bug 4: by_victim_wallet uses non-canonical address as key ----


def test_aggregate_by_victim_wallet_canonical_address_keying() -> None:
    """The same victim wallet shipped in mixed case across two cases
    (which happens whenever a checksum-cased address from one
    Etherscan response meets a lower-cased one from another) must
    aggregate as ONE wallet, not two.

    Pre-fix the dict is keyed on raw ``t.from_address``, so the same
    wallet appears twice in the "By victim wallet" table, each with
    half the true total.
    """
    victim_checksum = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
    victim_lower = victim_checksum.lower()
    c1 = _case("V-CFI-A", victim_checksum, [
        _transfer(from_addr=victim_checksum, to_addr=PERP,
                  amount=Decimal("10"), usd=Decimal("1000"), tx_hash="0x7"),
    ])
    c2 = _case("V-CFI-B", victim_lower, [
        _transfer(from_addr=victim_lower, to_addr=PERP,
                  amount=Decimal("10"), usd=Decimal("2000"), tx_hash="0x8"),
    ])
    r = aggregate_stolen(cases=[c1, c2], perpetrator_addresses=[PERP])
    assert len(r.by_victim_wallet) == 1, (
        f"same victim wallet keyed twice: {list(r.by_victim_wallet)}"
    )
    only_total = next(iter(r.by_victim_wallet.values()))
    assert only_total == Decimal("3000")


# ---- Bug 5: empty input degrades gracefully ----


def test_aggregate_empty_cases_produces_zero_aggregate() -> None:
    """Zero cases must yield a clean zero-aggregate (not crash on
    Decimal arithmetic, not produce NaN). Lock the safety net so a
    future refactor that, say, divides by transfer_count doesn't
    raise on the empty path.
    """
    r = aggregate_stolen(cases=[], perpetrator_addresses=[PERP])
    assert r.total_usd == Decimal("0")
    assert r.transfer_count == 0
    assert r.by_asset == []
    assert r.by_victim_wallet == {}
    # And the markdown must render cleanly (no NaN/inf, no crash).
    md = format_aggregate_markdown(r)
    assert "$0.00" in md
    assert "nan" not in md.lower()
    assert "inf" not in md.lower()


# ---- Bug 6: cases_examined keeps duplicate case_ids in mixed case ----


def test_aggregate_cases_examined_deduplicates_case_ids() -> None:
    """If two ``Case`` objects with the same logical case_id (mixed
    case, e.g. operator typed "v-cfi-1" once and "V-CFI-1" once at
    the CLI) get rolled up, the cover-line "Cases examined: 2" lies.

    The fix is to normalise + dedupe ``cases_examined`` so the cover
    line reflects the real number of distinct cases.
    """
    c1 = _case("V-CFI-1", VICTIM, [])
    c2 = _case("v-cfi-1", VICTIM, [])
    r = aggregate_stolen(cases=[c1, c2], perpetrator_addresses=[PERP])
    assert len(r.cases_examined) == 1, (
        f"duplicate case_ids retained: {r.cases_examined}"
    )
