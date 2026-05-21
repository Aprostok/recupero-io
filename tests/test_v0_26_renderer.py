"""v0.26.0 — Law-firm dashboard RENDERER tests.

Pure-template tests: build a LawFirmPortfolio directly (skipping
the DB builder) and feed it to render_law_firm_dashboard via a
patched build_firm_portfolio. Verifies the Jinja template renders
without StrictUndefined errors + the rendered HTML contains the
expected stats / sections.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import UUID


FIRM_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
FIRM_SLUG = "demo-firm"


def _make_portfolio_confident():
    """A portfolio with full confidence — throughput card unlocks,
    every issuer enriched with cooperation rates."""
    from recupero.monitoring.law_firm_dashboard import (
        FirmIssuerSummary, LawFirmPortfolio,
    )
    return LawFirmPortfolio(
        firm_id=FIRM_ID,
        firm_slug=FIRM_SLUG,
        firm_name="Demo Firm LLP",
        firm_status="active",
        n_referred_cases=12,
        n_completed_traces=8,
        n_in_queue=4,
        n_with_letters_sent=7,
        total_loss_usd=Decimal("12500000.00"),
        total_frozen_usd=Decimal("3400000.00"),
        total_returned_to_victim_usd=Decimal("1100000.00"),
        median_hours_intake_to_first_letter=23.5,
        median_hours_letter_to_first_freeze=37.0,
        has_confident_throughput=True,
        top_issuers=[
            FirmIssuerSummary(
                issuer="Tether", n_letters_sent=5, n_freezes_observed=4,
                total_frozen_usd=Decimal("2500000.00"),
                cross_firm_response_rate=0.78,
                cross_firm_full_freeze_rate=0.61,
            ),
            FirmIssuerSummary(
                issuer="Circle", n_letters_sent=2, n_freezes_observed=1,
                total_frozen_usd=Decimal("900000.00"),
                cross_firm_response_rate=None,
                cross_firm_full_freeze_rate=None,
            ),
        ],
        latest_referral_at="2026-04-15T12:00:00Z",
        latest_letter_sent_at="2026-04-18T09:00:00Z",
    )


def _make_portfolio_empty():
    """A new firm with zero referrals — every card should render the
    'insufficient data' branch without StrictUndefined errors."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    return LawFirmPortfolio(
        firm_id=FIRM_ID,
        firm_slug=FIRM_SLUG,
        firm_name="Brand-New Firm LLP",
        firm_status="active",
        # All defaults — zero referrals, no throughput, no issuers.
    )


def test_renderer_writes_file_with_expected_filename(tmp_path):
    """File written to <output_dir>/law_firm_dashboard_<slug>.html."""
    from recupero.reports import law_firm_dashboard as renderer
    portfolio = _make_portfolio_confident()

    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=portfolio,
    ):
        out_path = renderer.render_law_firm_dashboard(
            FIRM_SLUG, output_dir=tmp_path, dsn="postgres://fake",
        )

    assert out_path is not None
    assert out_path.exists()
    assert out_path.name == f"law_firm_dashboard_{FIRM_SLUG}.html"


def test_renderer_returns_none_when_firm_not_found(tmp_path):
    """build_firm_portfolio returns empty (firm_id None) → renderer
    returns None instead of writing an empty file."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    from recupero.reports import law_firm_dashboard as renderer

    empty = LawFirmPortfolio()  # firm_id stays None
    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=empty,
    ):
        out_path = renderer.render_law_firm_dashboard(
            "ghost-firm", output_dir=tmp_path, dsn="postgres://fake",
        )
    assert out_path is None
    assert list(tmp_path.iterdir()) == []


def test_renderer_returns_none_when_dsn_unset(tmp_path):
    from recupero.reports.law_firm_dashboard import render_law_firm_dashboard
    out = render_law_firm_dashboard(
        FIRM_SLUG, output_dir=tmp_path, dsn=None,
    )
    assert out is None


def test_rendered_html_contains_expected_stats(tmp_path):
    """Spot-check the rendered HTML for the canonical numbers + the
    firm-name in the cover."""
    from recupero.reports import law_firm_dashboard as renderer
    portfolio = _make_portfolio_confident()

    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=portfolio,
    ):
        out_path = renderer.render_law_firm_dashboard(
            FIRM_SLUG, output_dir=tmp_path, dsn="postgres://fake",
        )
    html = out_path.read_text(encoding="utf-8")
    # Firm header.
    assert "Demo Firm LLP" in html
    # Caseload stats.
    assert ">12<" in html or "Cases Referred" in html
    assert "$12,500,000.00" in html
    assert "$3,400,000.00" in html
    assert "$1,100,000.00" in html
    # Throughput card unlocked (confident=True).
    assert "Median Intake" in html
    assert "24 h" in html or "23 h" in html  # rounded format
    # Top issuers.
    assert "Tether" in html
    assert "Circle" in html
    # Cooperation rates only on Tether (Circle has None → "—" fallback).
    assert "78%" in html
    assert "61%" in html


def test_rendered_html_handles_empty_portfolio_gracefully(tmp_path):
    """A brand-new firm renders without StrictUndefined errors and
    surfaces the insufficient-data fallback."""
    from recupero.reports import law_firm_dashboard as renderer
    portfolio = _make_portfolio_empty()

    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=portfolio,
    ):
        out_path = renderer.render_law_firm_dashboard(
            FIRM_SLUG, output_dir=tmp_path, dsn="postgres://fake",
        )
    assert out_path is not None
    html = out_path.read_text(encoding="utf-8")
    assert "Brand-New Firm LLP" in html
    # Throughput card NOT unlocked.
    assert "Throughput medians require at least 3" in html
    # Top issuers empty branch.
    assert "No issuer letters" in html


def test_html_escapes_firm_name(tmp_path):
    """A firm name with HTML-special characters must be escaped by
    Jinja's autoescape; raw <script> must not appear in the output."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    from recupero.reports import law_firm_dashboard as renderer
    portfolio = LawFirmPortfolio(
        firm_id=FIRM_ID,
        firm_slug=FIRM_SLUG,
        firm_name="<script>alert(1)</script> & Co.",
        firm_status="active",
    )
    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=portfolio,
    ):
        out_path = renderer.render_law_firm_dashboard(
            FIRM_SLUG, output_dir=tmp_path, dsn="postgres://fake",
        )
    html = out_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # Ampersand also escaped.
    assert "&amp; Co." in html


def test_render_all_returns_empty_list_when_dsn_none(tmp_path):
    from recupero.reports.law_firm_dashboard import (
        render_all_law_firm_dashboards,
    )
    assert render_all_law_firm_dashboards(
        output_dir=tmp_path, dsn=None,
    ) == []
