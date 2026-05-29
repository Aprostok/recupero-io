"""Adversarial tests for Hyperliquid client + scraper.

Hyperliquid's public POST /info endpoint is a fully external,
attacker-influenceable boundary (the API itself is honest, but an
upstream MITM / pinned bad response / cached fixture can carry crafted
payloads). The scraper turns each ledger event into a synthetic
Transfer that lands in case.json and downstream legal documents, so
NaN/Infinity/path-traversal/extreme-timestamps must NOT crash the
pipeline or contaminate the brief.

The class of bug this covers:
  * NaN/Infinity in ``delta.usdc`` propagating into ``int(...)``
    arithmetic and into Pydantic models that don't catch it.
  * Extreme ``time`` ms producing OverflowError on
    ``datetime.fromtimestamp(ms/1000)``.
  * Attacker-controlled ``delta.destination`` injecting CRLF or
    path-traversal segments into transfer_id / explorer_url.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from recupero.chains.hyperliquid.client import (
    HyperliquidLedgerEvent,
    _parse_ledger_event,
)
from recupero.chains.hyperliquid.scraper import _events_to_transfers

# ---- _parse_ledger_event: external-input hardening ---- #


def test_parse_ledger_event_rejects_nan_usdc() -> None:
    """Decimal accepts the string 'NaN' silently. The parser must
    coerce it to Decimal(0) (or otherwise reject), so downstream
    abs() / arithmetic / int() conversions don't blow up."""
    raw = {
        "time": 1700000000000,
        "hash": "0xdeadbeef",
        "delta": {"type": "withdraw", "usdc": "NaN", "destination": "0xabc"},
    }
    evt = _parse_ledger_event(raw)
    assert evt is not None
    assert not evt.usdc_delta.is_nan(), (
        f"Parser accepted NaN as usdc_delta: {evt.usdc_delta!r}. "
        "Downstream arithmetic on NaN crashes the case build."
    )


def test_parse_ledger_event_rejects_infinity_usdc() -> None:
    """Decimal('Infinity') is a legal Decimal value but breaks
    int() conversion in _events_to_transfers. Reject upstream."""
    raw = {
        "time": 1700000000000,
        "hash": "0xdeadbeef",
        "delta": {"type": "withdraw", "usdc": "Infinity", "destination": "0xabc"},
    }
    evt = _parse_ledger_event(raw)
    assert evt is not None
    assert evt.usdc_delta.is_finite(), (
        f"Parser accepted non-finite usdc_delta: {evt.usdc_delta!r}."
    )


def test_parse_ledger_event_rejects_negative_infinity_usdc() -> None:
    raw = {
        "time": 1700000000000,
        "hash": "0xdeadbeef",
        "delta": {"type": "withdraw", "usdc": "-Infinity", "destination": "0xabc"},
    }
    evt = _parse_ledger_event(raw)
    assert evt is not None
    assert evt.usdc_delta.is_finite()


def test_parse_ledger_event_handles_garbage_usdc_string() -> None:
    raw = {
        "time": 1700000000000,
        "hash": "0xdeadbeef",
        "delta": {"type": "withdraw", "usdc": "not-a-number", "destination": "0xabc"},
    }
    evt = _parse_ledger_event(raw)
    # Either parsed as 0 or skipped. Either is acceptable; the
    # important thing is no exception escapes.
    if evt is not None:
        assert evt.usdc_delta == Decimal(0)


def test_parse_ledger_event_handles_missing_delta() -> None:
    """If ``delta`` is missing entirely, parser must not raise."""
    raw = {"time": 1700000000000, "hash": "0xdeadbeef"}
    evt = _parse_ledger_event(raw)
    # Acceptable: parsed with usdc=0 or returned None — but no crash.
    assert evt is None or evt.usdc_delta == Decimal(0)


def test_parse_ledger_event_missing_time_returns_none() -> None:
    """KeyError on 'time' is the existing contract — verify."""
    raw = {"hash": "0xabc", "delta": {"type": "withdraw"}}
    assert _parse_ledger_event(raw) is None


# ---- HyperliquidLedgerEvent.when: timestamp overflow ---- #


def test_when_handles_extreme_positive_timestamp() -> None:
    """``time_ms`` from upstream can be enormous. ``when`` is a
    property used by the scraper to populate Transfer.block_time;
    OverflowError there crashes the entire scrape."""
    evt = HyperliquidLedgerEvent(
        time_ms=99_999_999_999_999_999,   # year ~3_170_979
        hash="0xabc",
        delta_type="withdraw",
        usdc_delta=Decimal("100"),
        destination="0xdef",
        raw={},
    )
    # Must not crash on Windows (OSError) or Linux (OverflowError).
    try:
        dt = evt.when
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"HyperliquidLedgerEvent.when raised {type(e).__name__} "
            f"on extreme time_ms: {e}"
        ) from e
    assert isinstance(dt, datetime)
    # Sanity bound — the fallback should not produce a year > 9999.
    assert dt.year <= 9999


def test_when_handles_extreme_negative_timestamp() -> None:
    evt = HyperliquidLedgerEvent(
        time_ms=-99_999_999_999_999_999,
        hash="0xabc",
        delta_type="withdraw",
        usdc_delta=Decimal("100"),
        destination="0xdef",
        raw={},
    )
    try:
        dt = evt.when
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"HyperliquidLedgerEvent.when raised {type(e).__name__} "
            f"on extreme negative time_ms: {e}"
        ) from e
    assert isinstance(dt, datetime)


# ---- _events_to_transfers: end-to-end propagation ---- #


SEED = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"


def _evt(*, usdc_delta=Decimal("-100"), dt="withdraw", dest="0xabc", time_ms=1700000000000):
    return HyperliquidLedgerEvent(
        time_ms=time_ms,
        hash="0xevt",
        delta_type=dt,
        usdc_delta=usdc_delta,
        destination=dest,
        raw={},
    )


def test_events_to_transfers_skips_nan_delta() -> None:
    """If a NaN somehow slipped past _parse_ledger_event (defense
    in depth), _events_to_transfers must not crash."""
    evt = _evt(usdc_delta=Decimal("NaN"))
    try:
        transfers = _events_to_transfers([evt], SEED)
    except Exception as e:  # noqa: BLE001
        raise AssertionError(
            f"_events_to_transfers raised {type(e).__name__} on NaN "
            f"usdc_delta: {e}. Defense-in-depth required."
        ) from e
    # NaN events should be skipped (not represented as a real money flow).
    assert all(t.amount_decimal.is_finite() for t in transfers)


def test_events_to_transfers_skips_infinity_delta() -> None:
    evt = _evt(usdc_delta=Decimal("-Infinity"))
    try:
        transfers = _events_to_transfers([evt], SEED)
    except (OverflowError, ValueError) as e:
        raise AssertionError(
            f"_events_to_transfers raised {type(e).__name__} on "
            f"Infinity usdc_delta: {e}"
        ) from e
    assert all(t.amount_decimal.is_finite() for t in transfers)


def test_events_to_transfers_skips_event_with_overflow_timestamp() -> None:
    """Extreme time_ms passed all the way through must not crash
    the transfer build (when is used as block_time)."""
    evt = _evt(time_ms=99_999_999_999_999_999)
    try:
        transfers = _events_to_transfers([evt], SEED)
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_events_to_transfers raised on extreme timestamp: {e}"
        ) from e
    # Either the event is silently dropped or produces a Transfer
    # with a sane fallback block_time.
    for t in transfers:
        assert t.block_time.year <= 9999


def test_events_to_transfers_sanitizes_crlf_in_destination() -> None:
    """An upstream-poisoned ``destination`` containing CRLF must not
    inject newlines into the resulting Transfer's address fields
    (which would corrupt log lines / CSV exports / freeze letters)."""
    evt = _evt(dest="0xabc\r\nX-Injected: yes")
    transfers = _events_to_transfers([evt], SEED)
    for t in transfers:
        for field in (t.from_address, t.to_address, t.counterparty.address):
            assert "\r" not in field, f"CRLF leaked into address: {field!r}"
            assert "\n" not in field, f"LF leaked into address: {field!r}"


def test_events_to_transfers_clean_event_still_works() -> None:
    """Regression: the adversarial defenses must NOT break the
    happy-path withdraw event."""
    evt = _evt(usdc_delta=Decimal("-100.5"))
    transfers = _events_to_transfers([evt], SEED)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.amount_decimal == Decimal("100.5")
    assert t.from_address == SEED
    assert t.to_address == "0xabc"
