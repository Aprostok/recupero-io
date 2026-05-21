"""Unit tests for pure Hyperliquid client helpers.

Hyperliquid is structurally different from every other supported
chain: no Etherscan equivalent, no per-tx evidence, just a ledger
API that returns user-scoped events. The adapter is a thin parser
over the API response, so the highest-leverage tests cover:

  * ``_parse_ledger_event`` — turns one raw API event into a typed
    ``HyperliquidLedgerEvent``. Handles malformed input
    defensively (returns None instead of raising), which is
    exactly the kind of code that breaks when the API format
    shifts.
  * ``HyperliquidLedgerEvent`` dataclass — locked shape; the
    scraper + watch-tick path bind to its fields.
  * ``_RateLimiter`` — token-bucket-like throttle. Critical because
    Hyperliquid's free API has aggressive rate limits.
  * Exception classes — ``HyperliquidError`` vs.
    ``HyperliquidRateLimitError`` so the retry logic can
    distinguish.

Tests run in <100ms (one timing-sensitive rate-limiter test runs
in ~0.2s real time). Zero network, zero DB.
"""

from __future__ import annotations

import time
from datetime import UTC
from decimal import Decimal

import pytest

from recupero.chains.hyperliquid.client import (
    HyperliquidError,
    HyperliquidLedgerEvent,
    HyperliquidRateLimitError,
    _parse_ledger_event,
    _RateLimiter,
)

# ---- HyperliquidLedgerEvent dataclass ---- #


def test_ledger_event_immutable() -> None:
    """The dataclass is ``frozen=True`` — events are immutable after
    construction. Prevents accidental mutation in the scraper +
    watch-tick paths that share event references."""
    ev = HyperliquidLedgerEvent(
        time_ms=1700000000000,
        hash="0xabc",
        delta_type="withdraw",
        usdc_delta=Decimal("-500"),
        destination="0xdef",
        raw={"original": "data"},
    )
    with pytest.raises((AttributeError, Exception)):
        ev.usdc_delta = Decimal("0")  # type: ignore[misc]


def test_ledger_event_when_property() -> None:
    """``when`` converts time_ms → tz-aware datetime. Used for the
    flow-diagram's time axis and the trace_report timeline."""
    # 2023-11-14 22:13:20 UTC = 1700000000 unix seconds
    ev = HyperliquidLedgerEvent(
        time_ms=1700000000_000,
        hash="0xabc", delta_type="withdraw",
        usdc_delta=Decimal("0"), destination=None, raw={},
    )
    when = ev.when
    assert when.tzinfo is UTC
    assert when.year == 2023
    assert when.month == 11


# ---- _parse_ledger_event ---- #


def _full_raw_event() -> dict:
    """A canonical-shape Hyperliquid API event."""
    return {
        "time": 1700000000000,
        "hash": "0xabcdef",
        "delta": {
            "type": "withdraw",
            "usdc": "500.25",
            "destination": "0xdeadbeef",
        },
    }


def test_parse_full_event() -> None:
    """Happy path: well-formed raw event parses into a full
    HyperliquidLedgerEvent."""
    out = _parse_ledger_event(_full_raw_event())
    assert out is not None
    assert out.time_ms == 1700000000000
    assert out.hash == "0xabcdef"
    assert out.delta_type == "withdraw"
    assert out.usdc_delta == Decimal("500.25")
    assert out.destination == "0xdeadbeef"


def test_parse_missing_time_returns_none() -> None:
    """Without ``time``, we can't place the event on the timeline —
    skip rather than raise so the surrounding fetch loop continues."""
    raw = _full_raw_event()
    del raw["time"]
    assert _parse_ledger_event(raw) is None


def test_parse_missing_hash_uses_synthetic() -> None:
    """Hyperliquid's API sometimes omits ``hash`` (older events).
    The parser falls back to ``Id`` or a synthetic-time stub so the
    event still has a stable identifier for dedup."""
    raw = _full_raw_event()
    del raw["hash"]
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.hash.startswith("synthetic-")
    assert "1700000000000" in out.hash


def test_parse_missing_delta_handled() -> None:
    """If ``delta`` is missing, we get an "unknown" event type with
    zero USDC delta. Better than crashing — the scraper can decide
    what to do with malformed events downstream."""
    raw = _full_raw_event()
    del raw["delta"]
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.delta_type == "unknown"
    assert out.usdc_delta == Decimal("0")


def test_parse_malformed_usdc_handled() -> None:
    """A non-numeric usdc value falls back to zero rather than
    raising. Defensive against API format changes where the field
    moves to a different shape."""
    raw = _full_raw_event()
    raw["delta"]["usdc"] = "not-a-number"
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.usdc_delta == Decimal("0")


def test_parse_destination_optional() -> None:
    """Non-withdraw events have no destination — usdc_delta
    represents a balance change with no counterparty. Field is
    None, not empty string, so downstream renders can null-check
    cleanly."""
    raw = _full_raw_event()
    raw["delta"]["type"] = "spotTransfer"
    del raw["delta"]["destination"]
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.destination is None


def test_parse_destination_fallback_to_to_field() -> None:
    """Some events use ``to`` instead of ``destination`` — fall back
    so we capture both shapes the API has used historically."""
    raw = _full_raw_event()
    del raw["delta"]["destination"]
    raw["delta"]["to"] = "0xfallback"
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.destination == "0xfallback"


def test_parse_preserves_raw_payload() -> None:
    """The ``raw`` field carries the full original payload — used
    by the evidence writer to ship API-fidelity proof in the freeze
    letter. Locking this so a future refactor doesn't drop fields."""
    raw_in = _full_raw_event()
    raw_in["extra_field"] = "some metadata"
    out = _parse_ledger_event(raw_in)
    assert out is not None
    assert out.raw == raw_in
    assert out.raw["extra_field"] == "some metadata"


def test_parse_completely_garbage_returns_none() -> None:
    """Completely-malformed input (string, list, empty) returns
    None defensively rather than raising."""
    assert _parse_ledger_event({}) is None


def test_parse_negative_usdc_delta() -> None:
    """Withdrawals are negative deltas — locked because the freeze-
    target logic depends on sign to identify outflows vs deposits."""
    raw = _full_raw_event()
    raw["delta"]["usdc"] = "-1000.50"
    out = _parse_ledger_event(raw)
    assert out is not None
    assert out.usdc_delta == Decimal("-1000.50")
    assert out.usdc_delta < 0


# ---- _RateLimiter ---- #


def test_rate_limiter_first_call_no_wait() -> None:
    """The very first call doesn't sleep — limiter starts with the
    'allowed time' in the past."""
    rl = _RateLimiter(rps=10)
    t0 = time.monotonic()
    rl.wait()
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05, f"first call slept {elapsed}s unexpectedly"


def test_rate_limiter_enforces_min_interval() -> None:
    """Two back-to-back calls at 10 rps should be at least 100ms
    apart (1/10s = 0.1s interval). Small tolerance for timer
    jitter on Windows."""
    rl = _RateLimiter(rps=10)
    rl.wait()  # first — no delay
    t0 = time.monotonic()
    rl.wait()  # second — must sleep ~100ms
    elapsed = time.monotonic() - t0
    assert 0.08 <= elapsed <= 0.20, (
        f"expected ~100ms interval at 10rps, got {elapsed:.3f}s"
    )


def test_rate_limiter_zero_rps_no_throttle() -> None:
    """rps=0 means "no rate limit" — sleeps for 0s. Useful for
    tests / local dev that hit a mocked API."""
    rl = _RateLimiter(rps=0)
    rl.wait()
    t0 = time.monotonic()
    rl.wait()
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05


# ---- Exception classes ---- #


def test_hyperliquid_error_is_runtimeerror() -> None:
    """The retry decorator filters on exception type; locking the
    inheritance so the retry policy keeps working."""
    assert issubclass(HyperliquidError, RuntimeError)


def test_rate_limit_error_is_runtimeerror() -> None:
    """Same — the retry policy retries on this type."""
    assert issubclass(HyperliquidRateLimitError, RuntimeError)


def test_error_types_are_distinct() -> None:
    """A HyperliquidError is NOT a HyperliquidRateLimitError —
    keeps the retry policy from accidentally retrying
    non-recoverable errors as if they were 429s."""
    assert not issubclass(HyperliquidError, HyperliquidRateLimitError)
    assert not issubclass(HyperliquidRateLimitError, HyperliquidError)
