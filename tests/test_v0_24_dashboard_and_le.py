"""v0.24.0 — Section 5.7 LE template + cooperation_dashboard renderer.

Covers:
  * render_cooperation_dashboard happy path with synthetic profiles
  * Empty profiles → returns None (operator gets clean error)
  * No DSN → returns None
  * LE Section 5.7 renders for populated cooperation_profiles
  * LE Section 5.7 hidden when cooperation_profiles is empty / None
"""

from __future__ import annotations

import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from recupero.monitoring.cooperation_intelligence import (
    IssuerCooperationProfile,
)

# ─────────────────────────────────────────────────────────────────────────────
# Standalone cooperation_dashboard renderer
# ─────────────────────────────────────────────────────────────────────────────


def test_dashboard_no_dsn_returns_none():
    from recupero.reports.cooperation_dashboard import (
        render_cooperation_dashboard,
    )
    with tempfile.TemporaryDirectory() as tmp:
        assert render_cooperation_dashboard(
            output_dir=Path(tmp), dsn=None,
        ) is None


def test_dashboard_empty_profiles_returns_none():
    """No issuer history yet → renderer returns None, CLI surfaces a
    clean message rather than producing a misleading blank page."""
    from recupero.reports.cooperation_dashboard import (
        render_cooperation_dashboard,
    )
    with patch(
        "recupero.monitoring.cooperation_intelligence.build_all_profiles",
        return_value={},
    ), tempfile.TemporaryDirectory() as tmp:
        result = render_cooperation_dashboard(
            output_dir=Path(tmp), dsn="postgres://fake",
        )
    assert result is None


def test_dashboard_renders_full_document_with_profiles():
    """Happy path — three issuers with varied histories render into
    one HTML document with stats panel + per-issuer table + black-hole
    section."""
    from recupero.reports.cooperation_dashboard import (
        render_cooperation_dashboard,
    )

    fake_profiles = {
        "Tether": IssuerCooperationProfile(
            issuer="Tether",
            n_letters_sent=20,
            n_responded=17,
            n_silent=3,
            response_rate=0.85,
            full_freeze_rate=0.60,
            partial_freeze_rate=0.10,
            declined_rate=0.05,
            silence_rate=0.15,
            median_response_hours=31.0,
            avg_response_hours=42.0,
            total_frozen_usd=Decimal("12500000"),
            is_black_hole=False,
            has_confident_profile=True,
            latest_letter_sent_at="2026-05-01T12:00:00+00:00",
        ),
        "Binance": IssuerCooperationProfile(
            issuer="Binance",
            n_letters_sent=12,
            n_responded=0,
            n_silent=12,
            response_rate=0.0,
            full_freeze_rate=0.0,
            silence_rate=1.0,
            is_black_hole=True,
            has_confident_profile=True,
            total_frozen_usd=Decimal(0),
            latest_letter_sent_at="2026-04-15T08:00:00+00:00",
        ),
        "NewIssuer": IssuerCooperationProfile(
            issuer="NewIssuer",
            n_letters_sent=1,
            n_responded=1,
            response_rate=1.0,
            full_freeze_rate=1.0,
            has_confident_profile=False,
            total_frozen_usd=Decimal("100000"),
        ),
    }

    with patch(
        "recupero.monitoring.cooperation_intelligence.build_all_profiles",
        return_value=fake_profiles,
    ), tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        path = render_cooperation_dashboard(
            output_dir=out_dir, dsn="postgres://fake",
        )
        assert path is not None
        assert path.exists()
        assert path.name == "cooperation_dashboard.html"
        html = path.read_text(encoding="utf-8")

    # Stats panel
    assert "Issuers tracked" in html
    assert "Black-hole issuers" in html
    # Tether row: full numbers
    assert "Tether" in html
    assert "85%" in html  # response rate
    assert "31h" in html  # median response
    assert "60%" in html  # full freeze rate
    assert "$12,500,000.00" in html
    # Binance row: black-hole marker
    assert "Binance" in html
    assert "BLACK HOLE" in html
    # NewIssuer row: insufficient sample
    assert "NewIssuer" in html
    assert "n/a" in html  # below confidence threshold
    # Methodology section
    assert "Response rate" in html
    assert "confidence threshold" in html


# ─────────────────────────────────────────────────────────────────────────────
# LE Section 5.7 rendering (via generate_briefs)
# ─────────────────────────────────────────────────────────────────────────────


def _render_le_with_cooperation(cooperation_profiles):
    """Render the LE handoff on the V-CFI01 fixture with a given
    cooperation_profiles dict."""
    from recupero.reports.brief import InvestigatorInfo, generate_briefs
    from recupero.reports.victim import VictimInfo
    from tests.test_v_cfi01_full_render import VICTIM, _build_v_cfi01_case

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test", organization="Recupero", email="t@example.com",
    )
    with tempfile.TemporaryDirectory(prefix="v24_le_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            cooperation_profiles=cooperation_profiles,
        )
        return bundle.le_path.read_text(encoding="utf-8")


def test_le_renders_section_5_7_for_populated_profiles():
    """When cooperation_profiles has entries, Section 5.7 renders with
    the issuer table + black-hole warning + methodology note."""
    profiles = {
        "Tether": {
            "issuer": "Tether",
            "n_letters_sent": 20,
            "response_rate": 0.85,
            "full_freeze_rate": 0.60,
            "median_response_hours": 31.0,
            "is_black_hole": False,
            "has_confident_profile": True,
            "recommended_instrument": "le_backed",
            "recommended_instrument_reason": (
                "Tether responds to direct freeze requests 85% of the time."
            ),
        },
        "Binance": {
            "issuer": "Binance",
            "n_letters_sent": 12,
            "response_rate": 0.0,
            "full_freeze_rate": 0.0,
            "median_response_hours": None,
            "is_black_hole": True,
            "has_confident_profile": True,
            "recommended_instrument": "subpoena",
            "recommended_instrument_reason": (
                "Binance has received 12 informal freeze requests across "
                "prior cases with zero responses of any kind."
            ),
        },
    }
    html = _render_le_with_cooperation(profiles)
    assert "Issuer Cooperation Profile" in html
    assert "Tether" in html
    assert "85%" in html
    assert "31h" in html
    assert "Binance" in html
    assert "BLACK HOLE" in html
    assert "subpoena" in html
    assert "le_backed" in html
    # Methodology footnote about the BLACK HOLE definition
    assert "three or more informal freeze requests" in html


def test_le_hides_section_5_7_when_profiles_empty():
    """Empty cooperation_profiles → Section 5.7 omitted (LE renders
    cleanly even when DSN unset)."""
    html = _render_le_with_cooperation({})
    assert "Issuer Cooperation Profile" not in html
    assert "5.7" not in html


def test_le_hides_section_5_7_when_profiles_none():
    """None cooperation_profiles → ctx defaults to empty dict via
    `cooperation_profiles or {}` in brief.py, Section 5.7 omitted."""
    html = _render_le_with_cooperation(None)
    assert "Issuer Cooperation Profile" not in html
