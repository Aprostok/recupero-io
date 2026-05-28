"""v0.30.3 Jacob-style punishing tests for NaN-poisoning of USD aggregations.

Pattern: each test injects a `Decimal("NaN")` `usd_value_at_tx` into a
transfer and asserts the downstream aggregation does NOT propagate the
NaN into the brief / freeze letter / LE handoff. Tests are written FIRST
(before fixes); a regression that drops a guard goes red here.

Documented in `docs/V030_2_CORRECTNESS_AUDIT.md` Tier-1 B and C.

Pre-fix failure modes (what these tests demonstrate):
  * `_extract_perp_hub` returns address with NaN USD → `max()` picks
    a random "largest" perp-hub on the LE cover.
  * `_extract_destinations` per-counterparty USD bucket gets NaN +
    finite → entire bucket is NaN, address sorts arbitrarily.
  * `_compute_total_drained` returns NaN total → cover meta says
    "$NaN" stolen.
  * `_build_identified_wallets` agg["usd_in"] becomes NaN → Section 5
    filter compares NaN >= floor (False) so the row gets DROPPED even
    if it's a legitimate high-volume perp wallet.
  * `recommend_le_routes` with NaN total_loss_usd silently SKIPS FBI
    VAU + Secret Service ECTF escalation on a $1M+ case (NaN >= 1M
    is False).
  * Dust-threshold env var = "NaN" parses successfully, returns
    Decimal("NaN") as threshold → every legitimate destination
    fails `received >= NaN` and the destination list collapses.
  * `handoffs_to_brief_section` formats Decimal("NaN") into the
    cross-chain table as literal "$NaN".
"""
from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import patch

import pytest

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    LabelCategory,
    TokenRef,
    Transfer,
)


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


_SEED = "0x0000000000000000000000000000000000000001"
_DEST_GOOD = "0x000000000000000000000000000000000000000a"
_DEST_NAN = "0x000000000000000000000000000000000000000b"


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal | None,
    amount: Decimal = Decimal("100"),
    block_num: int = 1,
    tx_hash: str = "0xabc",
    log_index: int = 0,
) -> Transfer:
    """Construct a synthetic Transfer with a controlled USD value.

    Uses `model_construct` (bypasses Pydantic validation) for the NaN
    cases. This mirrors the real-world adversarial scenarios where NaN
    reaches the aggregators despite the entry-point validators:

      - Corrupt case.json loaded via `Case.model_validate_json` where a
        prior version's writer emitted NaN before the finite-number
        constraint shipped
      - Future non-Pydantic adapters that hand-construct a Transfer-like
        dict and call `__dict__`-style attribute access on aggregators
      - Hand-edited freeze_asks.json / cache files that downstream code
        reads directly

    The Transfer model's `finite_number` constraint is good defense at
    the input boundary; this test ensures defense-in-depth inside the
    aggregators is ALSO in place.
    """
    fields: dict[str, Any] = {
        "transfer_id": f"{tx_hash}:{log_index}:{from_addr}:{to_addr}",
        "chain": Chain.ethereum,
        "tx_hash": tx_hash,
        "block_number": block_num,
        "block_time": datetime(2026, 1, 1, tzinfo=UTC),
        "log_index": log_index,
        "from_address": from_addr,
        "to_address": to_addr,
        "counterparty": Counterparty(address=to_addr),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
            symbol="USDT",
            decimals=6,
        ),
        "amount_raw": str(int(amount * 10**6)),
        "amount_decimal": amount,
        "usd_value_at_tx": usd,
        "hop_depth": 0,
        "parent_transfer_id": None,
        "pricing_source": None,
        "pricing_error": None,
        "fetched_at": datetime(2026, 1, 2, tzinfo=UTC),
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
    }
    # NaN/Inf bypasses Pydantic's finite_number validator.
    if usd is not None and not usd.is_finite():
        return Transfer.model_construct(**fields)
    return Transfer(**fields)


def _mk_case_with_nan_transfer() -> Case:
    """Two outflows from victim:
      - 100 USDT to DEST_GOOD at $100 (finite)
      - 100 USDT to DEST_NAN at NaN (poisoned)
    """
    return Case(
        case_id="NAN-POISON-TEST",
        seed_address=_SEED,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[
            _mk_transfer(
                from_addr=_SEED, to_addr=_DEST_GOOD,
                usd=Decimal("100"), block_num=1, log_index=0,
            ),
            _mk_transfer(
                from_addr=_SEED, to_addr=_DEST_NAN,
                usd=Decimal("NaN"), block_num=2, log_index=1,
            ),
        ],
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        trace_completed_at=datetime(2026, 1, 2, tzinfo=UTC),
    )


# ──────────────────────────────────────────────────────────────────────
# T1-B: USD aggregation sites
# ──────────────────────────────────────────────────────────────────────


def test_extract_perp_hub_filters_nan_usd() -> None:
    """`_extract_perp_hub` selects the destination with the largest
    inbound USD from the victim. Pre-v0.30.3: NaN poisons one bucket;
    `max()` semantics on NaN are undefined. Fix: skip NaN rows entirely
    so the perp-hub on the LE cover is always a real finite-USD address."""
    from recupero.reports.emit_brief import _extract_perp_hub
    case = _mk_case_with_nan_transfer()
    perp_hub = _extract_perp_hub(case)
    # _extract_perp_hub returns Optional[dict] with 'address' key.
    if perp_hub is not None:
        addr = perp_hub.get("address") if isinstance(perp_hub, dict) else perp_hub
        assert addr != _DEST_NAN, (
            f"_extract_perp_hub returned the NaN-poisoned address as "
            f"the perp-hub. NaN should be filtered before the max() call."
        )


def test_extract_destinations_filters_nan_usd() -> None:
    """`_extract_destinations` aggregates per-destination USD then
    filters by dust threshold. NaN values in the aggregation make the
    `received >= threshold` check unstable."""
    from recupero.reports.emit_brief import _extract_destinations
    case = _mk_case_with_nan_transfer()
    # Use $1 threshold so the $100 address normally clears.
    with patch.dict("os.environ", {"RECUPERO_DESTINATION_DUST_USD": "1"}):
        destinations = _extract_destinations(
            case,
            editorial_notes={},
            freeze_targets_by_addr={},
        )
    # NaN bucket must NOT propagate as a numeric total.
    for dest in destinations:
        usd_val = dest.get("usd_received") or dest.get("received_usd") or dest.get("usd_value")
        if isinstance(usd_val, Decimal):
            assert usd_val.is_finite(), (
                f"Destination {dest!r} carries a non-finite USD "
                f"received value — NaN reached the brief. Filter "
                f"`if not usd_value_at_tx.is_finite()` is missing."
            )


def test_compute_total_drained_excludes_nan() -> None:
    """The headline cover meta says "USD X stolen" — that's
    `_compute_total_drained`. If a single transfer has NaN USD, the
    pre-v0.30.3 code returned NaN total, and the cover renders "$NaN"
    in front of a federal agent."""
    from recupero.reports.emit_brief import _compute_total_drained
    case = _mk_case_with_nan_transfer()
    total = _compute_total_drained(case)
    assert total.is_finite(), (
        f"_compute_total_drained returned non-finite total "
        f"({total!r}) when a transfer had NaN usd_value_at_tx. "
        f"The brief cover would render '$NaN'."
    )
    # The finite contribution is $100.
    assert total == Decimal("100"), (
        f"Expected total = $100 (the only finite transfer); got {total!r}"
    )


def test_le_routing_with_nan_total_loss_does_not_skip_escalation_silently() -> None:
    """`recommend_le_routes` checks `total_loss_usd >= $100K` and
    `>= $1M`. Pre-v0.30.3, Decimal('NaN') >= X returns False per
    IEEE 754, so a NaN loss silently SKIPS both FBI VAU and Secret
    Service ECTF escalation on a high-value case.

    The fix: detect NaN/Inf and either log + skip escalation OR fall
    back to a defensive route. We pin the contract: if total_loss_usd
    is NaN, the function returns a plan whose escalation_routes is
    empty AND the notes list includes a diagnostic about the
    unfinite loss. Neither FBI_VAU nor SECRET_SERVICE_ECTF gets
    appended via the NaN-comparison-fails-True path."""
    from recupero.worker._le_routing import recommend_le_routes
    plan = recommend_le_routes(
        state=None, country="USA", total_loss_usd=Decimal("NaN"),
    )
    # Escalations must NOT be skipped via the silent False path.
    # The fix should leave a breadcrumb in notes.
    note_text = " ".join(plan.notes)
    finite_check_evidence = (
        "non-finite" in note_text.lower()
        or "nan" in note_text.lower()
        or "unspecified" in note_text.lower()
    )
    # Either we get the diagnostic note, or no escalation routes (no
    # silent skip in either case).
    if plan.escalation_routes:
        assert finite_check_evidence, (
            "recommend_le_routes accepted NaN total_loss_usd, added "
            "escalation routes, but provided no diagnostic note. "
            "Pre-v0.30.3 the f-string would render '$NaN' into the "
            "filing-routes note."
        )
    else:
        # No escalations is acceptable; the diagnostic note is required.
        assert finite_check_evidence, (
            "recommend_le_routes silently skipped escalations on "
            "NaN total_loss_usd with no diagnostic note. Pre-v0.30.3 "
            "behavior is fixed by an explicit NaN guard."
        )


def test_le_routing_inf_does_not_render_inf_in_note() -> None:
    """`Decimal("Infinity") >= 1M` returns True per IEEE 754, so the
    threshold-passes branch fires; the f-string then renders 'Loss of
    $Infinity' into the LE handoff note. The fix's defensive guard
    treats Inf the same as NaN."""
    from recupero.worker._le_routing import recommend_le_routes
    plan = recommend_le_routes(
        state=None, country="USA", total_loss_usd=Decimal("Infinity"),
    )
    for note in plan.notes:
        assert "Infinity" not in note, (
            f"LE handoff note rendered raw 'Infinity' in escalation "
            f"text: {note!r}. Pre-v0.30.3 the >= comparison fired "
            f"on Inf and the f-string produced this string. The fix's "
            f"NaN/Inf guard prevents it."
        )
        assert "$Infinity" not in note
        assert "$Inf" not in note


# ──────────────────────────────────────────────────────────────────────
# Dust threshold env var parses NaN (T3-B in audit)
# ──────────────────────────────────────────────────────────────────────


def test_dust_threshold_rejects_nan_env_var() -> None:
    """`RECUPERO_DESTINATION_DUST_USD="NaN"` parses successfully via
    `Decimal("NaN")`; the `val < 0` check is False per IEEE 754, so
    NaN is returned as the threshold. Every legitimate destination
    then fails the `received >= NaN` filter (NaN comparisons always
    False), and the destination list collapses."""
    from recupero.reports.emit_brief import _parse_dust_threshold
    with patch.dict("os.environ", {"RECUPERO_DESTINATION_DUST_USD": "NaN"}):
        val = _parse_dust_threshold()
    assert val.is_finite(), (
        f"dust-threshold env-var parser accepted 'NaN' and returned "
        f"non-finite Decimal {val!r}. This makes every legitimate "
        f"destination fail the `received >= NaN` filter."
    )


def test_dust_threshold_rejects_inf_env_var() -> None:
    """Symmetrical fix: 'Infinity' must also be rejected."""
    from recupero.reports.emit_brief import _parse_dust_threshold
    with patch.dict("os.environ", {"RECUPERO_DESTINATION_DUST_USD": "Infinity"}):
        val = _parse_dust_threshold()
    assert val.is_finite(), (
        f"dust-threshold env-var parser accepted 'Infinity' and "
        f"returned non-finite Decimal {val!r}."
    )


# ──────────────────────────────────────────────────────────────────────
# Adversarial input hunt on v0.30.2 helpers
# ──────────────────────────────────────────────────────────────────────


def test_aggregate_theft_amount_handles_none_amount_decimal() -> None:
    """v0.30.2 introduced `_aggregate_theft_amount_human`. What if a
    theft_event has `amount_decimal=None` (rare but possible if a
    pricing-error transfer slipped through)? The helper must not
    crash and must not include None in the sum."""
    from dataclasses import dataclass
    from recupero.reports.brief import _aggregate_theft_amount_human

    @dataclass
    class _Tok:
        symbol: str

    @dataclass
    class _Tr:
        amount_decimal: Decimal | None
        token: _Tok

    a = _Tr(amount_decimal=Decimal("100"), token=_Tok("USDT"))
    b = _Tr(amount_decimal=None, token=_Tok("USDT"))  # poisoned
    out = _aggregate_theft_amount_human([a, b], a)
    # Must render without crashing and must not include literal "None".
    assert "None" not in out, f"Helper leaked 'None' into output: {out!r}"


def test_aggregate_theft_amount_handles_missing_token() -> None:
    """Defensive: a transfer with token=None or token.symbol=None
    shouldn't crash the mixed-asset detector."""
    from dataclasses import dataclass
    from recupero.reports.brief import _theft_events_mixed_assets

    @dataclass
    class _Tr:
        amount_decimal: Decimal | None
        token: Any

    a = _Tr(amount_decimal=Decimal("100"), token=None)
    b = _Tr(amount_decimal=Decimal("200"), token=None)
    # Must not crash. Should treat as "no symbol info" → not mixed.
    assert _theft_events_mixed_assets([a, b]) is False


def test_aggregate_theft_amount_handles_nan_decimal() -> None:
    """A transfer with `amount_decimal=Decimal('NaN')` is theoretically
    possible if an adversarial chain adapter returns garbage. The
    helper should refuse to add it into a same-symbol sum (else the
    sum becomes NaN)."""
    from dataclasses import dataclass
    from recupero.reports.brief import _aggregate_theft_amount_human

    @dataclass
    class _Tok:
        symbol: str

    @dataclass
    class _Tr:
        amount_decimal: Decimal | None
        token: _Tok

    a = _Tr(amount_decimal=Decimal("100"), token=_Tok("USDT"))
    b = _Tr(amount_decimal=Decimal("NaN"), token=_Tok("USDT"))
    out = _aggregate_theft_amount_human([a, b], a)
    assert "NaN" not in out, f"NaN leaked into output: {out!r}"


# ──────────────────────────────────────────────────────────────────────
# _prod_dsn_guard adversarial input
# ──────────────────────────────────────────────────────────────────────


def test_prod_dsn_guard_handles_garbled_dsn() -> None:
    """Defensive: a `SUPABASE_DB_URL` that's syntactically broken
    (typo, control chars, invalid URL) must not crash the guard."""
    import sys
    from pathlib import Path
    _SCRIPTS = Path(__file__).parent.parent / "scripts"
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    from _prod_dsn_guard import _looks_like_prod_dsn  # type: ignore

    for adversarial in [
        "not a url",
        "postgresql://",  # missing host
        "http://wrong-scheme.com/db",  # wrong scheme but processable
        "postgresql://a@host:not-a-port/db",
        "postgresql://user\x00:pass@host/postgres",  # null byte
        "postgresql://" + "x" * 10000 + "@h/postgres",  # very long
    ]:
        try:
            result = _looks_like_prod_dsn(adversarial)
            # We don't care about the answer — just no crash.
            assert isinstance(result, bool)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"_looks_like_prod_dsn crashed on {adversarial!r}: {exc!r}"
            )
