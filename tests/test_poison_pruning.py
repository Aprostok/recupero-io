"""v0.34 pre-pricing poison-edge pruning (operator-requested "elite recall").

The per-address fetch cap was a blunt anti-poisoning defense that could drop a
real onward hop. ``prune_poison_outflows`` replaces it with a SAFE, pre-pricing
filter so the tracer can run UNCAPPED: it drops ONLY edges that cannot possibly
carry real value (zero-value transfers — the canonical address-poisoning
primitive) and NEVER a value-bearing edge.

The contract these tests pin:
  * zero-value transfers are pruned (int 0, "0", "0x0", Decimal 0);
  * any value-bearing transfer is KEPT (even tiny dust — the dust floor handles
    that AFTER pricing, never here);
  * unparseable / missing / blank amounts are KEPT (never treat "unknown" as
    "zero" — that would risk dropping a real hop);
  * kept order is preserved.
"""

from __future__ import annotations

from decimal import Decimal

from recupero.trace.poison_pruning import amount_is_zero, prune_poison_outflows


def _row(amount, to="0x00000000000000000000000000000000deadbeef", tx="0xabc"):
    return {"to": to, "tx_hash": tx, "amount_raw": amount}


# --------------------------- amount_is_zero ---------------------------------


def test_zero_forms_are_zero() -> None:
    for z in (0, "0", "  0  ", "0x0", "0x00", Decimal(0), Decimal("0.0")):
        assert amount_is_zero(_row(z)) is True, z


def test_nonzero_forms_are_not_zero() -> None:
    for nz in (1, "1", "1000000000000000000", "0x1", "0xde0b6b3a7640000",
               Decimal("0.000000000000000001"), 9200):
        assert amount_is_zero(_row(nz)) is False, nz


def test_unparseable_or_missing_amount_is_kept() -> None:
    """Conservative: 'I can't read it' must NEVER be treated as zero — that
    would let a malformed-but-real transfer be pruned as poison."""
    assert amount_is_zero(_row(None)) is False
    assert amount_is_zero(_row("")) is False
    assert amount_is_zero(_row("   ")) is False
    assert amount_is_zero(_row("not-a-number")) is False
    assert amount_is_zero(_row("0xZZ")) is False
    assert amount_is_zero({}) is False  # no amount_raw key
    assert amount_is_zero(_row(True)) is False  # bool is not an amount


def test_nan_inf_amount_is_kept() -> None:
    """Non-finite Decimals are not 'zero' — keep (defensive)."""
    assert amount_is_zero(_row(Decimal("NaN"))) is False
    assert amount_is_zero(_row(Decimal("Infinity"))) is False


# ------------------------ prune_poison_outflows -----------------------------


def test_zero_value_pruned_value_bearing_kept() -> None:
    rows = [
        _row(0, to="0xpoison1", tx="0xp1"),               # poison
        _row("1000000000000000000", to="0xreal1", tx="0xr1"),  # 1 ETH real
        _row("0", to="0xpoison2", tx="0xp2"),             # poison
        _row(500, to="0xreal2", tx="0xr2"),               # tiny but real
    ]
    kept, pruned = prune_poison_outflows(rows)
    kept_to = [r["to"] for r in kept]
    pruned_to = [p["to"] for p in pruned]
    assert kept_to == ["0xreal1", "0xreal2"], kept_to
    assert pruned_to == ["0xpoison1", "0xpoison2"], pruned_to
    assert all(p["kind"] == "zero_value_poison" for p in pruned)
    assert pruned[0]["tx_hash"] == "0xp1"


def test_tiny_dust_is_not_pruned_here() -> None:
    """A 1-wei real transfer is value-bearing — pruning must NOT touch it.
    Sub-dust noise is dropped post-pricing by the USD dust floor, not here,
    so we never risk dropping a genuine small hop on the laundering path."""
    rows = [_row(1, to="0xtiny")]
    kept, pruned = prune_poison_outflows(rows)
    assert [r["to"] for r in kept] == ["0xtiny"]
    assert pruned == []


def test_all_value_bearing_nothing_pruned() -> None:
    rows = [_row(10**18), _row(5), _row("42")]
    kept, pruned = prune_poison_outflows(rows)
    assert len(kept) == 3
    assert pruned == []


def test_empty_input() -> None:
    kept, pruned = prune_poison_outflows([])
    assert kept == []
    assert pruned == []


def test_order_preserved() -> None:
    rows = [_row(i + 1, to=f"0x{i:040x}") for i in range(5)]
    kept, _ = prune_poison_outflows(rows)
    assert [r["to"] for r in kept] == [f"0x{i:040x}" for i in range(5)]
