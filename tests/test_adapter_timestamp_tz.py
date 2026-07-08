"""Regression: Aptos/Stellar timestamp parsing must normalize to aware-UTC.

Both adapters historically used ``fromisoformat`` in a way that mishandled
timezone offsets, silently corrupting chain-of-custody / evidence timestamps and
the trace start-block cutoff:

* ``aptos._parse_ts`` did ``fromisoformat(...).replace(tzinfo=UTC)`` — which
  OVERWRITES a parsed non-UTC offset instead of converting it, shifting the
  instant by the offset (e.g. a ``+05:00`` timestamp read 5h late).
* ``stellar._parse_created_at`` returned the raw ``fromisoformat`` result, which
  is *naive* for an offset-less input; ``.timestamp()`` on a naive datetime then
  uses the HOST's local timezone (wrong cutoff on any non-UTC host).

The correct contract (matches the Cosmos adapter): always return an aware-UTC
datetime — stamp UTC when naive, convert when an offset is present.
"""

from __future__ import annotations

from datetime import UTC, datetime

from recupero.chains.aptos.adapter import _parse_ts
from recupero.chains.stellar.adapter import _parse_created_at

# 2024-01-01T00:00:00 UTC, expressed three different ways.
_EXPECTED = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
_EQUIVALENT_INPUTS = [
    "2024-01-01T00:00:00Z",            # Z suffix
    "2024-01-01T00:00:00+00:00",       # explicit UTC offset
    "2024-01-01T00:00:00",             # naive (Aptos/Stellar emit UTC)
    "2024-01-01T05:00:00+05:00",       # non-UTC offset == 00:00 UTC  <- the bug
    "2023-12-31T19:00:00-05:00",       # non-UTC offset == 00:00 UTC  <- the bug
]


def test_aptos_parse_ts_normalizes_all_forms_to_same_utc_instant() -> None:
    for raw in _EQUIVALENT_INPUTS:
        dt = _parse_ts(raw)
        assert dt.tzinfo is not None, f"{raw!r} -> naive datetime"
        assert dt == _EXPECTED, f"{raw!r} -> {dt.isoformat()} (expected {_EXPECTED.isoformat()})"
        assert int(dt.timestamp()) == int(_EXPECTED.timestamp())


def test_stellar_parse_created_at_normalizes_all_forms_to_same_utc_instant() -> None:
    for raw in _EQUIVALENT_INPUTS:
        dt = _parse_created_at(raw)
        assert dt.tzinfo is not None, f"{raw!r} -> naive datetime"
        assert dt == _EXPECTED, f"{raw!r} -> {dt.isoformat()} (expected {_EXPECTED.isoformat()})"
        assert int(dt.timestamp()) == int(_EXPECTED.timestamp())


def test_aptos_parse_ts_offset_does_not_overwrite() -> None:
    # The precise regression: a +05:00 wall-clock of 05:00 is 00:00 UTC, NOT
    # 05:00 UTC. The old .replace(tzinfo=UTC) produced 05:00 UTC (5h drift).
    assert _parse_ts("2024-01-01T05:00:00+05:00").hour == 0


def test_bad_and_empty_inputs_fall_back_to_epoch_utc() -> None:
    for bad in ["", "not-a-date", None, 12345]:
        for fn in (_parse_ts, _parse_created_at):
            dt = fn(bad)  # type: ignore[arg-type]
            assert dt.tzinfo is not None
            assert dt == datetime.fromtimestamp(0, tz=UTC)
