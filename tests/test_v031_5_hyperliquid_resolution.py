"""v0.31.5 — best-effort Hyperliquid ``unknown_destination`` resolution.

v0.17.5 introduced ``hyperliquid:unknown_destination`` as a synthetic
sentinel for outflow ledger events where ``delta.destination`` is missing
from the API response. ``_is_synthetic_placeholder`` (in trace/policies.py)
treats every colon-bearing address as terminal for the BFS — correct,
because no adapter can resolve such an address, but it means we lose
EVERY missing-destination event as a trace dead-end.

This patch adds ``resolve_unknown_destination`` — a best-effort re-query
of the Hyperliquid info API that occasionally recovers the destination.
The contract is purely additive: a successful resolution avoids emitting
the placeholder; ANY failure (network, malformed JSON, non-hex result)
falls back to the original placeholder behavior.

These tests cover:
  * Happy path — resolver returns a valid 0x-hex address.
  * Miss — API returns rows but none within the ±10min window.
  * API error — httpx raises → resolver returns None.
  * Invalid shape — API returns dict instead of list → resolver None.
  * Cache — second call with identical args doesn't hit the API.
  * Address validation — API returns non-hex value → resolver None.
  * End-to-end scraper wiring — outflow with missing destination
    AND a happy-path resolver mock results in the resolved address
    landing in the Transfer, NOT the placeholder.
  * End-to-end scraper wiring — outflow with missing destination
    AND a miss-path resolver still emits the placeholder (BFS
    terminal behavior preserved).

The cache is LRU(256) keyed on (user_address.lower(), block_time.isoformat()),
so each test calls ``_resolve_unknown_destination_cached.cache_clear()``
in a fixture to avoid cross-test leakage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest
import respx

from recupero.chains.hyperliquid import client as hl_client
from recupero.chains.hyperliquid.client import (
    HyperliquidLedgerEvent,
    _is_hex_address,
    resolve_unknown_destination,
)
from recupero.chains.hyperliquid.scraper import _events_to_transfers

INFO_URL = "https://api.hyperliquid.xyz/info"
SEED = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
RESOLVED = "0x1234567890abcdef1234567890abcdef12345678"
EVENT_TIME_MS = 1_700_000_000_000  # 2023-11-14 22:13:20 UTC
EVENT_TIME = datetime.fromtimestamp(EVENT_TIME_MS / 1000, tz=UTC)


@pytest.fixture(autouse=True)
def _clear_resolver_cache():
    """LRU cache is process-global — flush before each test so prior
    results can't bleed into the next test's assertions."""
    hl_client._resolve_unknown_destination_cached.cache_clear()
    yield
    hl_client._resolve_unknown_destination_cached.cache_clear()


def _ledger_row(*, time_ms: int, destination: str | None,
                delta_type: str = "withdraw") -> dict:
    """Build one Hyperliquid info-endpoint row in the shape the resolver
    expects. ``destination=None`` omits the field entirely (mirroring
    the bug we're working around)."""
    delta: dict = {"type": delta_type, "usdc": "100"}
    if destination is not None:
        delta["destination"] = destination
    return {
        "time": time_ms,
        "hash": f"0xevt{time_ms}",
        "delta": delta,
    }


# ---- happy path ---- #

@respx.mock
def test_resolve_returns_valid_address() -> None:
    """API returns one row inside the ±10min window carrying a valid
    0x-hex destination → resolver returns the lowercase form."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    out = resolve_unknown_destination(SEED, EVENT_TIME)
    assert out == RESOLVED.lower()
    assert _is_hex_address(out)


# ---- miss: no matching row ---- #

@respx.mock
def test_resolve_returns_none_when_no_row_in_window() -> None:
    """All rows lie OUTSIDE the ±10min window — resolver must return
    None so the scraper falls back to the placeholder."""
    far_past_ms = EVENT_TIME_MS - 60 * 60 * 1000  # -1 hour
    far_future_ms = EVENT_TIME_MS + 60 * 60 * 1000  # +1 hour
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[
            _ledger_row(time_ms=far_past_ms, destination=RESOLVED),
            _ledger_row(time_ms=far_future_ms, destination=RESOLVED),
        ],
    ))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_returns_none_when_empty_response() -> None:
    """Empty list (user has no ledger activity in that window) → None."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


# ---- API error paths ---- #

@respx.mock
def test_resolve_swallows_http_error() -> None:
    """httpx raises (network error, DNS failure, etc.) → resolver
    must NOT propagate; return None and let the caller fall back."""
    respx.post(INFO_URL).mock(side_effect=httpx.ConnectError("boom"))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_returns_none_on_5xx() -> None:
    """Server error → resolver returns None (non-200 = no resolution)."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(500, text="oops"))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_returns_none_on_429() -> None:
    """Rate limit → resolver returns None (defensive — we don't want
    to retry-storm a missing-destination batch)."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(429))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


# ---- invalid response shape ---- #

@respx.mock
def test_resolve_returns_none_on_non_list_response() -> None:
    """API responds with a dict instead of a list (shape drift /
    malicious upstream) → resolver returns None."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200, json={"unexpected": "shape"},
    ))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_returns_none_on_non_json_response() -> None:
    """API responds with non-JSON text → resolver returns None."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200, text="<html>maintenance</html>",
    ))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_returns_none_when_no_destination_in_row() -> None:
    """In-window row exists but its ``delta`` lacks a destination field
    → no candidate, resolver returns None."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=None)],
    ))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_ignores_garbage_rows() -> None:
    """Non-dict rows / rows with missing ``time`` / rows with non-dict
    ``delta`` are silently skipped. A subsequent VALID row in the same
    response still resolves."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[
        "not a dict",
        {"no_time": True},
        {"time": "not-an-int"},
        {"time": EVENT_TIME_MS, "delta": "not-a-dict"},
        _ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED),
    ]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) == RESOLVED.lower()


# ---- address validation ---- #

@respx.mock
def test_resolve_rejects_non_hex_destination() -> None:
    """Row has a destination field but it's not 0x-hex (e.g. plain
    text, ENS-shape, base58, embedded CRLF). Resolver rejects."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[
        _ledger_row(time_ms=EVENT_TIME_MS, destination="not-an-address"),
    ]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_rejects_short_hex() -> None:
    """0x prefix but wrong length (38 hex chars instead of 40) — reject."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[
        _ledger_row(time_ms=EVENT_TIME_MS, destination="0x" + "ab" * 19),
    ]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_rejects_non_hex_chars() -> None:
    """Right length but contains non-hex characters."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[
        _ledger_row(time_ms=EVENT_TIME_MS, destination="0x" + "z" * 40),
    ]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


@respx.mock
def test_resolve_rejects_recupero_placeholder() -> None:
    """A re-emit attack: API returns the placeholder string itself.
    The hex regex rejects ``hyperliquid:unknown_destination`` so the
    resolver returns None (preserving placeholder semantics)."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[
        _ledger_row(time_ms=EVENT_TIME_MS,
                    destination="hyperliquid:unknown_destination"),
    ]))
    assert resolve_unknown_destination(SEED, EVENT_TIME) is None


# ---- cache ---- #

@respx.mock
def test_resolve_caches_per_user_and_time() -> None:
    """Two calls with identical (user, block_time) → exactly one HTTP
    request. LRU(256) is process-global so the cache_clear fixture
    handles cleanup."""
    route = respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    out1 = resolve_unknown_destination(SEED, EVENT_TIME)
    out2 = resolve_unknown_destination(SEED, EVENT_TIME)
    assert out1 == out2 == RESOLVED.lower()
    assert route.call_count == 1, (
        f"expected 1 call (cached); got {route.call_count}"
    )


@respx.mock
def test_resolve_cache_keys_are_distinct_for_different_users() -> None:
    """Different user → different cache key → second HTTP call fires."""
    other_user = "0x" + "ab" * 20
    route = respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    resolve_unknown_destination(SEED, EVENT_TIME)
    resolve_unknown_destination(other_user, EVENT_TIME)
    assert route.call_count == 2


@respx.mock
def test_resolve_cache_keys_are_distinct_for_different_times() -> None:
    """Different block_time → different cache key → second call fires."""
    other_time = datetime.fromtimestamp(
        EVENT_TIME_MS / 1000 + 3600, tz=UTC,
    )
    route = respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    resolve_unknown_destination(SEED, EVENT_TIME)
    resolve_unknown_destination(SEED, other_time)
    assert route.call_count == 2


# ---- input-validation guards ---- #

def test_resolve_rejects_empty_user() -> None:
    """Empty user_address → resolver returns None without any HTTP call."""
    # No respx.mock — if it tried to call the API we'd get a connection error.
    with respx.mock:
        assert resolve_unknown_destination("", EVENT_TIME) is None


def test_resolve_rejects_non_datetime_block_time() -> None:
    """Non-datetime block_time → resolver returns None."""
    with respx.mock:
        assert resolve_unknown_destination(SEED, "not-a-datetime") is None  # type: ignore[arg-type]


@respx.mock
def test_resolve_accepts_naive_datetime() -> None:
    """A naive (tz-less) datetime is coerced to UTC — same end-to-end
    behavior as the scraper's primary path. Use a naive datetime whose
    wall-clock components match EVENT_TIME in UTC so the resolver's
    naive-as-UTC coercion lands inside the ±10min window."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    # EVENT_TIME is 2023-11-14 22:13:20 UTC; mirror those components naively.
    naive = datetime(
        EVENT_TIME.year, EVENT_TIME.month, EVENT_TIME.day,
        EVENT_TIME.hour, EVENT_TIME.minute, EVENT_TIME.second,
    )
    assert naive.tzinfo is None
    out = resolve_unknown_destination(SEED, naive)
    assert out == RESOLVED.lower()


# ---- end-to-end scraper wiring ---- #

@respx.mock
def test_scraper_uses_resolved_destination_when_available() -> None:
    """An outflow event with destination=None + a resolver that finds
    a valid address should produce a Transfer whose to_address is the
    RESOLVED address — NOT ``hyperliquid:unknown_destination``."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    evt = HyperliquidLedgerEvent(
        time_ms=EVENT_TIME_MS,
        hash="0xoutflow",
        delta_type="withdraw",
        usdc_delta=Decimal("-500"),
        destination=None,            # the bug: scraper observed no destination
        raw={},
    )
    transfers = _events_to_transfers([evt], SEED)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.to_address == RESOLVED.lower()
    assert ":" not in t.to_address, (
        "placeholder should NOT be emitted when resolution succeeds"
    )


@respx.mock
def test_scraper_falls_back_to_placeholder_when_resolution_misses() -> None:
    """An outflow event with destination=None + a resolver that returns
    None (no matching row) must still produce the synthetic placeholder
    — preserving the v0.17.5 BFS-terminal contract."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(200, json=[]))
    evt = HyperliquidLedgerEvent(
        time_ms=EVENT_TIME_MS,
        hash="0xoutflow",
        delta_type="withdraw",
        usdc_delta=Decimal("-500"),
        destination=None,
        raw={},
    )
    transfers = _events_to_transfers([evt], SEED)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.to_address == "hyperliquid:unknown_destination"


@respx.mock
def test_scraper_skips_resolution_when_destination_already_present() -> None:
    """If the primary path already saw a valid destination, the resolver
    must NOT be called (waste of API budget). respx route call_count
    confirms zero hits."""
    route = respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    evt = HyperliquidLedgerEvent(
        time_ms=EVENT_TIME_MS,
        hash="0xoutflow",
        delta_type="withdraw",
        usdc_delta=Decimal("-500"),
        destination="0xabcdef0123456789abcdef0123456789abcdef01",
        raw={},
    )
    transfers = _events_to_transfers([evt], SEED)
    assert route.call_count == 0
    assert len(transfers) == 1
    assert transfers[0].to_address.startswith("0xabcdef")


@respx.mock
def test_scraper_skips_resolution_for_deposit_events() -> None:
    """Inflow events have ``unknown_source`` semantics, not
    ``unknown_destination`` — the resolver is only meaningful for
    outflows and must NOT be called for deposits."""
    route = respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS, destination=RESOLVED)],
    ))
    evt = HyperliquidLedgerEvent(
        time_ms=EVENT_TIME_MS,
        hash="0xinflow",
        delta_type="deposit",
        usdc_delta=Decimal("500"),
        destination=None,
        raw={},
    )
    transfers = _events_to_transfers([evt], SEED)
    assert route.call_count == 0
    assert len(transfers) == 1
    assert transfers[0].from_address == "hyperliquid:unknown_source"


@respx.mock
def test_scraper_falls_back_when_resolver_returns_invalid_hex() -> None:
    """Defense-in-depth: even if (somehow) the resolver returns a
    non-hex string, the scraper re-validates with ``_is_hex_address``
    before using it. Tested by spiking the API with non-hex value —
    resolver should already reject, but if validation drifted, the
    scraper still falls back."""
    respx.post(INFO_URL).mock(return_value=httpx.Response(
        200,
        json=[_ledger_row(time_ms=EVENT_TIME_MS,
                          destination="garbage-not-hex")],
    ))
    evt = HyperliquidLedgerEvent(
        time_ms=EVENT_TIME_MS,
        hash="0xoutflow",
        delta_type="withdraw",
        usdc_delta=Decimal("-500"),
        destination=None,
        raw={},
    )
    transfers = _events_to_transfers([evt], SEED)
    assert len(transfers) == 1
    assert transfers[0].to_address == "hyperliquid:unknown_destination"


# ---- hex-address validator unit tests ---- #

@pytest.mark.parametrize("value,expected", [
    ("0x" + "ab" * 20, True),
    ("0x" + "AB" * 20, True),         # uppercase hex
    ("0x" + "ab" * 20 + "ab", False),  # too long
    ("0x" + "ab" * 19, False),         # too short
    ("ab" * 20, False),                # missing 0x
    ("0xZ" + "a" * 39, False),         # non-hex
    ("hyperliquid:unknown_destination", False),
    ("", False),
    (None, False),
    (12345, False),                    # non-string
    ({"address": "0xab" * 20}, False), # non-string
])
def test_is_hex_address(value, expected) -> None:
    assert _is_hex_address(value) is expected
