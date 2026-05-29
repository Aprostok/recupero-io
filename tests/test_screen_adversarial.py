"""RIGOR-Jacob Z1: adversarial input hardening for src/recupero/screen/screener.py

Each test pairs an adversarial input with a code path where the bug
surfaces today (or would surface without the guard). These lock the
hardening so a future refactor can't silently re-open the crash class.

Bugs covered:

* Z1-1 (HIGH) — `_lookup_correlation_for_address` crashes when the DB
  row returns non-numeric strings (e.g., `'NaN'`, `'abc'`) for the
  counter columns: `int('NaN')` raises `ValueError`, propagating out
  of the screener instead of degrading gracefully.

* Z1-2 (HIGH) — `_lookup_correlation_for_address` accepts an
  unconstrained `prior_total_usd_flowed` from the DB. A corrupted
  string like `'NaN'` becomes `Decimal('NaN')` which silently poisons
  every downstream comparison (NaN compares false against everything),
  and negative values pass through unfiltered.

* Z1-3 (CRIT) — `_compute_score` trusts `entry.severity` from the
  caller-supplied high_risk_db. A non-int (None / str) raises
  `TypeError` on `severity * 2`. An out-of-range int (e.g. 100)
  silently returns a score > 10, violating the documented `0..10`
  contract and inflating downstream verdict logic that branches on
  score thresholds.

* Z1-4 (HIGH) — `screen_address` accepts an address with embedded
  NUL bytes / unicode bidi-override controls. These slip through
  `_normalize_for_lookup` (which only `.strip()`s ASCII whitespace),
  get stored in the SQL %(addr)s param and the ScreeningResult.address
  field. NUL bytes are a Postgres-level error (`UntranslatableCharacter`)
  and bidi controls in audit logs can mis-render the address that an
  operator approves.

* Z1-5 (MEDIUM) — `screen_address` accepts arbitrarily-long addresses.
  A 1MB string passes through to the DB query parameter and the SQL
  text params; even though the query is parameterized (no SQLi),
  it wastes a round-trip and lets a caller DoS the lookup. EVM/Tron/
  BTC/Solana addresses are all <= 64 chars.

* Z1-6 (HIGH) — `screen_address` calls `db.get(addr_norm)` without
  type-checking `db`. A caller mistakenly passing a list or other
  non-dict gets `AttributeError: 'list' object has no attribute 'get'`
  inside the screener instead of a clean `TypeError` at the boundary.
"""

from __future__ import annotations

from typing import Any

import pytest

from recupero.screen.screener import (
    ScreeningCorrelation,
    _compute_score,
    _lookup_correlation_for_address,
    _normalize_for_lookup,
    screen_address,
)
from recupero.trace.risk_scoring import HighRiskEntry

# ---- Z1-1: correlation lookup tolerates non-numeric DB rows ---- #


class _FakeCursor:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def execute(self, *args: Any, **kwargs: Any) -> None:
        pass

    def fetchone(self) -> dict[str, Any] | None:
        return self._row

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *exc: Any) -> None:
        pass


class _FakeConn:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._row)

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: Any) -> None:
        pass


def test_correlation_lookup_tolerates_garbage_counter_strings(monkeypatch: Any) -> None:
    """Z1-1: a corrupted/migrated DB column may return 'NaN' or 'abc'
    instead of a number. The screener must degrade to an empty
    correlation rather than crash the whole screening call."""
    bad_row = {
        "prior_case_count": "NaN",  # not an int — int('NaN') raises
        "prior_ofac_exposed_count": "abc",
        "prior_mixer_exposed_count": None,
        "prior_drainer_attributed_count": 0,
        "prior_total_usd_flowed": "0",
        "roles_seen": [],
    }

    def fake_db_connect(dsn: str, **kw: Any) -> _FakeConn:
        return _FakeConn(bad_row)

    monkeypatch.setattr(
        "recupero.screen.screener.db_connect", fake_db_connect,
    )

    # Must NOT raise — graceful degradation.
    result = _lookup_correlation_for_address(
        "0x" + "a" * 40, chain="ethereum", dsn="postgres://stub",
    )
    # Garbage → all-zero / safe defaults.
    assert isinstance(result, ScreeningCorrelation)
    assert result.prior_case_count == 0
    assert result.prior_ofac_exposed_count == 0


# ---- Z1-2: NaN / negative usd_flowed rejected ---- #


def test_correlation_lookup_rejects_nan_usd_flowed(monkeypatch: Any) -> None:
    """Z1-2: a DB row with usd_flowed='NaN' must NOT yield a
    ScreeningCorrelation with Decimal('NaN') (which would break every
    downstream comparison: `NaN > 0` is False). Replace with 0."""
    bad_row = {
        "prior_case_count": 0,
        "prior_ofac_exposed_count": 0,
        "prior_mixer_exposed_count": 0,
        "prior_drainer_attributed_count": 0,
        "prior_total_usd_flowed": "NaN",
        "roles_seen": [],
    }

    def fake_db_connect(dsn: str, **kw: Any) -> _FakeConn:
        return _FakeConn(bad_row)

    monkeypatch.setattr(
        "recupero.screen.screener.db_connect", fake_db_connect,
    )

    result = _lookup_correlation_for_address(
        "0x" + "a" * 40, chain="ethereum", dsn="postgres://stub",
    )
    # Must be a finite, non-negative Decimal.
    assert result.prior_total_usd_flowed.is_finite()
    assert result.prior_total_usd_flowed >= 0


def test_correlation_lookup_rejects_negative_usd_flowed(monkeypatch: Any) -> None:
    """Z1-2: negative SUM(usd_flowed) is corruption — must floor to 0
    rather than propagate a negative total that breaks downstream
    `usd > 0` triage thresholds."""
    bad_row = {
        "prior_case_count": 1,
        "prior_ofac_exposed_count": 0,
        "prior_mixer_exposed_count": 0,
        "prior_drainer_attributed_count": 0,
        "prior_total_usd_flowed": "-9999999",
        "roles_seen": [],
    }

    def fake_db_connect(dsn: str, **kw: Any) -> _FakeConn:
        return _FakeConn(bad_row)

    monkeypatch.setattr(
        "recupero.screen.screener.db_connect", fake_db_connect,
    )

    result = _lookup_correlation_for_address(
        "0x" + "a" * 40, chain="ethereum", dsn="postgres://stub",
    )
    assert result.prior_total_usd_flowed >= 0


# ---- Z1-3: _compute_score clamps severity from untrusted entry ---- #


def test_compute_score_rejects_oversize_severity() -> None:
    """Z1-3: an attacker-controlled HighRiskEntry with severity=100
    must not produce a score > 10. The dataclass documents 0..10 and
    downstream verdict logic compares against fixed thresholds — a
    score of 200 silently makes everything 'high' even when the
    underlying category doesn't warrant it."""
    entry = HighRiskEntry(
        address="0x" + "a" * 40,
        name="Malformed",
        risk_category="other",  # falls through to severity*2 branch
        severity=100,
    )
    score = _compute_score(entry=entry, correlation=ScreeningCorrelation())
    assert 0 <= score <= 10, f"score must be clamped to 0..10, got {score}"


def test_compute_score_rejects_non_int_severity() -> None:
    """Z1-3: severity=None or a str must not crash. Some legacy DB
    rows may load with a missing severity (legacy mixer seed pre-v0.9
    had no severity field)."""

    class BadEntry:
        # Mirror just enough of HighRiskEntry without dataclass
        # type-enforcement to feed a junk severity through.
        address = "0x" + "a" * 40
        name = "Bad"
        risk_category = "other"
        severity = None  # not an int
        notes = None
        confidence = "high"
        ofac_listing_date = None

    score = _compute_score(entry=BadEntry(), correlation=ScreeningCorrelation())
    assert isinstance(score, int)
    assert 0 <= score <= 10


# ---- Z1-4: NUL bytes / unicode controls in address ---- #


def test_normalize_for_lookup_rejects_nul_byte() -> None:
    """Z1-4: an address with an embedded NUL byte cannot be a real
    on-chain address. Postgres rejects it with UntranslatableCharacter
    and audit logs render it incorrectly. Reject at the boundary."""
    with pytest.raises(ValueError, match="control|invalid|nul"):
        _normalize_for_lookup("0x" + "a" * 20 + "\x00" + "b" * 19, chain="ethereum")


def test_normalize_for_lookup_rejects_bidi_override() -> None:
    """Z1-4: a Unicode RIGHT-TO-LEFT-OVERRIDE (U+202E) embedded in
    an address spoofs the rendered address in audit logs and screening
    reports. Reject at the boundary."""
    sneaky = "0x" + "a" * 19 + "‮" + "b" * 20
    with pytest.raises(ValueError, match="control|invalid|bidi"):
        _normalize_for_lookup(sneaky, chain="ethereum")


def test_screen_address_rejects_nul_byte() -> None:
    """Z1-4 surface check: the public entrypoint must reject these
    too — not just the internal helper."""
    with pytest.raises(ValueError):
        screen_address(
            "0x" + "a" * 20 + "\x00" + "b" * 19,
            chain="ethereum",
            use_correlation_db=False,
            high_risk_db={},
        )


# ---- Z1-5: unbounded address length ---- #


def test_normalize_for_lookup_rejects_huge_address() -> None:
    """Z1-5: no real address exceeds ~128 chars. A 1MB string must
    not be forwarded to the DB query."""
    huge = "0x" + "a" * (1024 * 1024)
    with pytest.raises(ValueError, match="too long|length"):
        _normalize_for_lookup(huge, chain="ethereum")


def test_screen_address_rejects_huge_address() -> None:
    """Z1-5 surface check."""
    huge = "0x" + "a" * (1024 * 1024)
    with pytest.raises(ValueError):
        screen_address(
            huge, chain="ethereum",
            use_correlation_db=False, high_risk_db={},
        )


# ---- Z1-6: non-dict high_risk_db ---- #


def test_screen_address_rejects_non_dict_high_risk_db() -> None:
    """Z1-6: callers can mistakenly pass a list (e.g., the loaded
    JSON before being keyed into a dict). The screener does
    `db.get(addr_norm)` which raises AttributeError on a list. Catch
    at the boundary with a clean TypeError."""
    with pytest.raises(TypeError, match="dict|mapping"):
        screen_address(
            "0x" + "a" * 40,
            chain="ethereum",
            use_correlation_db=False,
            high_risk_db=["not", "a", "dict"],  # type: ignore[arg-type]
        )
