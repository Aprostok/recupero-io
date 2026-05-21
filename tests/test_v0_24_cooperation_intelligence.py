"""v0.24.0 — Exchange Cooperation Intelligence tests.

Covers:
  * IssuerCooperationProfile aggregation from freeze_outcomes (mocked DB)
  * recommend_legal_instrument logic across all 6 precedence levels
  * Black-hole detection threshold
  * Confident-profile threshold
  * Empty / DB-failure paths return safe defaults
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest

from recupero.monitoring.cooperation_intelligence import (
    INSTRUMENT_DIRECT_REQUEST,
    INSTRUMENT_FINCEN_314B,
    INSTRUMENT_GRAND_JURY_SUBPOENA,
    INSTRUMENT_LE_BACKED,
    INSTRUMENT_MLAT,
    IssuerCooperationProfile,
    build_all_profiles,
    build_cooperation_profile,
    recommend_legal_instrument,
)


# ─────────────────────────────────────────────────────────────────────────────
# recommend_legal_instrument — precedence chain
# ─────────────────────────────────────────────────────────────────────────────


def _profile(
    *,
    issuer: str = "TestIssuer",
    n_letters: int = 0,
    response_rate: float = 0.0,
    median_hours: float | None = None,
    is_black_hole: bool = False,
    has_confident_profile: bool = False,
) -> IssuerCooperationProfile:
    return IssuerCooperationProfile(
        issuer=issuer,
        n_letters_sent=n_letters,
        response_rate=response_rate,
        median_response_hours=median_hours,
        is_black_hole=is_black_hole,
        has_confident_profile=has_confident_profile,
    )


def test_recommend_ofac_overrides_everything_else():
    """v0.24.0 precedence #1: OFAC exposure → grand jury subpoena
    even when cooperation history would otherwise suggest a direct
    request. Compliance teams can't act on sanctioned counterparties
    without a court order."""
    profile = _profile(
        n_letters=20, response_rate=0.95,
        median_hours=24, has_confident_profile=True,
    )
    rec = recommend_legal_instrument(profile, ofac_exposed=True)
    assert rec.instrument == INSTRUMENT_GRAND_JURY_SUBPOENA
    assert "OFAC" in rec.reason


def test_recommend_black_hole_routes_to_subpoena():
    """v0.24.0 precedence #2: zero responses across ≥3 letters → skip
    informal channel, go to grand jury subpoena. Direct letters
    demonstrably don't work for this issuer."""
    profile = _profile(
        issuer="Binance", n_letters=12,
        response_rate=0.0, is_black_hole=True,
    )
    rec = recommend_legal_instrument(profile)
    assert rec.instrument == INSTRUMENT_GRAND_JURY_SUBPOENA
    assert "Binance" in rec.reason
    assert "12" in rec.reason
    assert "zero responses" in rec.reason.lower()


def test_recommend_non_us_low_response_routes_to_mlat():
    """v0.24.0 precedence #3: non-US jurisdiction + low response_rate
    → MLAT via DOJ-OIA. Direct + 314(b) both require US jurisdiction
    over the issuer; MLAT is the only viable channel."""
    profile = _profile(
        issuer="OffshoreExchange", n_letters=5,
        response_rate=0.20, has_confident_profile=True,
    )
    rec = recommend_legal_instrument(profile, jurisdiction="Cayman Islands")
    assert rec.instrument == INSTRUMENT_MLAT
    assert "Cayman Islands" in rec.reason
    assert "MLAT" in rec.reason


def test_recommend_us_low_response_routes_to_314b():
    """v0.24.0 precedence #4: US jurisdiction + low response_rate →
    FinCEN 314(b) information-sharing request. Authority comes from
    the Patriot Act, not the issuer's compliance team's willingness."""
    profile = _profile(
        issuer="USExchange", n_letters=8,
        response_rate=0.10, has_confident_profile=True,
    )
    rec = recommend_legal_instrument(profile, jurisdiction="United States")
    assert rec.instrument == INSTRUMENT_FINCEN_314B
    assert "314(b)" in rec.reason
    assert "Patriot Act" in rec.reason


def test_recommend_good_cooperation_with_ic3_routes_to_le_backed():
    """v0.24.0 precedence #5: ≥50% response rate AND IC3 case ID on
    file → LE-backed letter (lands faster than standard)."""
    profile = _profile(
        issuer="Tether", n_letters=20,
        response_rate=0.85, median_hours=31.0,
        has_confident_profile=True,
    )
    rec = recommend_legal_instrument(
        profile, jurisdiction="BVI",
        ic3_case_id="I-2026-12345",
    )
    assert rec.instrument == INSTRUMENT_LE_BACKED
    assert "Tether" in rec.reason
    assert "85%" in rec.reason
    assert "31" in rec.reason  # median hours


def test_recommend_good_cooperation_without_ic3_routes_to_direct():
    """v0.24.0 precedence #5 (cont): same as above but no IC3 → still
    direct, just not LE-backed."""
    profile = _profile(
        issuer="Tether", n_letters=20,
        response_rate=0.85, median_hours=31.0,
        has_confident_profile=True,
    )
    rec = recommend_legal_instrument(profile, jurisdiction="BVI")
    assert rec.instrument == INSTRUMENT_DIRECT_REQUEST
    assert "85%" in rec.reason


def test_recommend_no_confident_profile_routes_to_direct_with_caveat():
    """v0.24.0 precedence #6: <3 letters → no confident profile →
    direct request as default + reason notes insufficient sample."""
    profile = _profile(
        issuer="NewIssuer", n_letters=1,
        response_rate=1.0, has_confident_profile=False,
    )
    rec = recommend_legal_instrument(profile)
    assert rec.instrument == INSTRUMENT_DIRECT_REQUEST
    assert "insufficient sample" in rec.reason.lower()
    assert "≥3 required" in rec.reason


def test_recommend_zero_letters_returns_direct_default():
    """Issuer with zero letter history → direct request default."""
    profile = _profile(issuer="NeverSentTo", n_letters=0)
    rec = recommend_legal_instrument(profile)
    assert rec.instrument == INSTRUMENT_DIRECT_REQUEST


# ─────────────────────────────────────────────────────────────────────────────
# build_cooperation_profile — DB-mocked aggregation
# ─────────────────────────────────────────────────────────────────────────────


def test_build_profile_no_dsn_returns_empty():
    """Local CLI path (no DSN) → empty profile (LE Section 5.7 renders
    'insufficient data' branch)."""
    profile = build_cooperation_profile("Tether", dsn=None)
    assert profile.issuer == "Tether"
    assert profile.n_letters_sent == 0
    assert profile.response_rate == 0.0
    assert profile.is_black_hole is False


def test_build_profile_db_error_returns_empty():
    """DB error during aggregation must NOT raise — returns empty
    profile so the LE handoff renders cleanly."""
    with patch(
        "recupero._common.db_connect",
        side_effect=RuntimeError("simulated DB outage"),
    ):
        profile = build_cooperation_profile("Tether", dsn="postgres://fake")
    assert profile.n_letters_sent == 0


def test_build_profile_no_letters_returns_empty():
    """Issuer with no freeze_letters_sent rows → empty profile."""

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchall(self):
            return []
        def fetchone(self):
            return None
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch("recupero._common.db_connect", return_value=_StubConn()):
        profile = build_cooperation_profile("UnknownIssuer", dsn="postgres://fake")
    assert profile.n_letters_sent == 0
    assert profile.is_black_hole is False  # zero letters → not a black hole


def test_build_profile_aggregates_response_and_freeze_rates():
    """Happy-path aggregation: 4 letters, 3 responded (1 full_freeze,
    1 partial_freeze, 1 declined), 1 silent. Expected rates:
    response_rate=0.75, full_freeze_rate=0.25, declined_rate=0.25,
    silence_rate=0.25."""
    now = datetime.now(UTC)
    fake_rows = [
        # Letter 1: full_freeze after 24h
        {
            "letter_id": "L1",
            "sent_at": now - timedelta(days=10),
            "outcomes": [
                ("acknowledged", now - timedelta(days=10) + timedelta(hours=12), None),
                ("full_freeze", now - timedelta(days=10) + timedelta(hours=24), Decimal("100000")),
            ],
        },
        # Letter 2: partial_freeze after 48h
        {
            "letter_id": "L2",
            "sent_at": now - timedelta(days=8),
            "outcomes": [
                ("partial_freeze", now - timedelta(days=8) + timedelta(hours=48), Decimal("50000")),
            ],
        },
        # Letter 3: declined after 72h
        {
            "letter_id": "L3",
            "sent_at": now - timedelta(days=6),
            "outcomes": [
                ("declined", now - timedelta(days=6) + timedelta(hours=72), None),
            ],
        },
        # Letter 4: silent (only silence_30d outcome — counts as silent)
        {
            "letter_id": "L4",
            "sent_at": now - timedelta(days=35),
            "outcomes": [
                ("silence_30d", now - timedelta(days=5), None),
            ],
        },
    ]

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchall(self):
            return fake_rows
        def fetchone(self):
            return None
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch("recupero._common.db_connect", return_value=_StubConn()):
        profile = build_cooperation_profile("Tether", dsn="postgres://fake")

    assert profile.n_letters_sent == 4
    assert profile.n_responded == 3
    assert profile.n_silent == 1
    assert profile.response_rate == 0.75
    assert profile.full_freeze_rate == 0.25
    assert profile.partial_freeze_rate == 0.25
    assert profile.declined_rate == 0.25
    assert profile.silence_rate == 0.25
    # Total frozen: 100000 (full) + 50000 (partial) = 150000
    assert profile.total_frozen_usd == Decimal("150000")
    # Median of response hours [24, 48, 72] = 48
    assert profile.median_response_hours == 48.0
    assert profile.has_confident_profile is True   # n_letters >= 3
    assert profile.is_black_hole is False           # had responses


def test_build_profile_black_hole_detection():
    """3 letters, 0 responses → is_black_hole=True."""
    now = datetime.now(UTC)
    fake_rows = [
        {
            "letter_id": f"L{i}",
            "sent_at": now - timedelta(days=30 + i),
            "outcomes": [],  # zero outcomes
        }
        for i in range(3)
    ]

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchall(self):
            return fake_rows
        def fetchone(self):
            return None
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch("recupero._common.db_connect", return_value=_StubConn()):
        profile = build_cooperation_profile("Binance", dsn="postgres://fake")

    assert profile.is_black_hole is True
    assert profile.n_letters_sent == 3
    assert profile.n_responded == 0


def test_build_profile_below_threshold_no_black_hole():
    """2 letters with zero responses → NOT black hole (sample too small).
    Defends against tagging a new issuer as a black hole after one bad
    week."""
    now = datetime.now(UTC)
    fake_rows = [
        {"letter_id": "L1", "sent_at": now, "outcomes": []},
        {"letter_id": "L2", "sent_at": now, "outcomes": []},
    ]

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchall(self):
            return fake_rows
        def fetchone(self):
            return None
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch("recupero._common.db_connect", return_value=_StubConn()):
        profile = build_cooperation_profile("NewIssuer", dsn="postgres://fake")

    assert profile.is_black_hole is False
    assert profile.has_confident_profile is False


# ─────────────────────────────────────────────────────────────────────────────
# build_all_profiles
# ─────────────────────────────────────────────────────────────────────────────


def test_build_all_profiles_returns_empty_without_dsn():
    """No DSN → empty dict."""
    assert build_all_profiles(dsn=None) == {}


def test_build_all_profiles_db_error_returns_empty():
    """DB error on the distinct-issuer query → empty dict."""
    with patch(
        "recupero._common.db_connect",
        side_effect=RuntimeError("simulated DB outage"),
    ):
        assert build_all_profiles(dsn="postgres://fake") == {}
