"""PUNISH-A: punishing tests for v0.26 law-firm portfolio dashboard.

A partner firm reading this dashboard is making business decisions:
"are these cases moving?", "are we getting wins?", "is the
cross-firm cooperation data useful?". The HTML must answer those
questions accurately and prominently, or the partnership erodes.

Each test mirrors a specific thing a partner would notice on
inspection. No softening — every check is unconditional.
"""

from __future__ import annotations

import re
import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

_FIRM_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_FIRM_SLUG = "demo-firm"


def _make_confident_portfolio():
    """A fully-populated partner portfolio that should render every
    stat tile, the throughput card, and a 2-issuer top-issuer table.
    """
    from recupero.monitoring.law_firm_dashboard import (
        FirmIssuerSummary,
        LawFirmPortfolio,
    )
    return LawFirmPortfolio(
        firm_id=_FIRM_ID,
        firm_slug=_FIRM_SLUG,
        firm_name="Morgan Stanley Recovery LLP",
        firm_status="active",
        n_referred_cases=14,
        n_completed_traces=9,
        n_in_queue=5,
        n_with_letters_sent=8,
        total_loss_usd=Decimal("18500000.00"),
        total_frozen_usd=Decimal("4250000.00"),
        total_returned_to_victim_usd=Decimal("1800000.00"),
        median_hours_intake_to_first_letter=27.0,
        median_hours_letter_to_first_freeze=41.5,
        has_confident_throughput=True,
        top_issuers=[
            FirmIssuerSummary(
                issuer="Tether", n_letters_sent=6, n_freezes_observed=5,
                total_frozen_usd=Decimal("3200000.00"),
                cross_firm_response_rate=0.81,
                cross_firm_full_freeze_rate=0.67,
            ),
            FirmIssuerSummary(
                issuer="Circle", n_letters_sent=2, n_freezes_observed=1,
                total_frozen_usd=Decimal("1050000.00"),
                cross_firm_response_rate=None,
                cross_firm_full_freeze_rate=None,
            ),
        ],
        latest_referral_at="2026-04-15T12:00:00Z",
        latest_letter_sent_at="2026-04-18T09:00:00Z",
    )


def _make_empty_portfolio():
    """A brand-new firm — all zeros."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    return LawFirmPortfolio(
        firm_id=_FIRM_ID,
        firm_slug=_FIRM_SLUG,
        firm_name="Brand-New Firm LLP",
        firm_status="active",
    )


def _render(portfolio) -> str:
    """Render the dashboard via the production renderer + return HTML."""
    from recupero.reports import law_firm_dashboard as renderer
    tmp = Path(tempfile.mkdtemp(prefix="dash_test_"))
    with patch(
        "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
        return_value=portfolio,
    ):
        out = renderer.render_law_firm_dashboard(
            portfolio.firm_slug, output_dir=tmp, dsn="postgres://fake",
        )
    assert out is not None, "renderer returned None for a populated portfolio"
    return out.read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Confident-portfolio rendering — every section populated
# ─────────────────────────────────────────────────────────────────────────────


def test_dashboard_starts_with_doctype():
    html = _render(_make_confident_portfolio())
    assert html.lstrip().startswith("<!DOCTYPE"), (
        "dashboard HTML must start with <!DOCTYPE"
    )


def test_dashboard_title_names_the_firm():
    html = _render(_make_confident_portfolio())
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    assert m, "no <title>"
    title = m.group(1).strip()
    assert "Morgan Stanley Recovery LLP" in title, (
        f"<title> {title!r} does not name the firm"
    )


def test_dashboard_h1_names_the_firm():
    """The first heading on the cover must be the firm name."""
    html = _render(_make_confident_portfolio())
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
    assert m, "no <h1> tag"
    h1_text = re.sub(r"<[^>]+>", " ", m.group(1))
    assert "Morgan Stanley Recovery LLP" in h1_text, (
        f"<h1> is {h1_text!r} — should be the firm name"
    )


def test_dashboard_confidential_banner_names_the_firm():
    html = _render(_make_confident_portfolio())
    assert "Confidential · For Morgan Stanley Recovery LLP" in html, (
        "confidential banner does not name the firm"
    )


def test_dashboard_shows_every_volume_stat():
    """Caseload-at-a-Glance: every stat tile must have the right
    number AND the right label."""
    p = _make_confident_portfolio()
    html = _render(p)
    expectations = {
        "Cases Referred": str(p.n_referred_cases),
        "Completed Traces": str(p.n_completed_traces),
        "In Queue": str(p.n_in_queue),
        "With Letters Sent": str(p.n_with_letters_sent),
    }
    for label, value in expectations.items():
        # Each label appears with its value somewhere in the HTML.
        assert label in html, (
            f"stat label {label!r} missing from dashboard"
        )
        assert value in html, (
            f"stat value {value!r} for {label!r} missing"
        )


def test_dashboard_shows_total_loss_with_dollars():
    """The "Total Reported Loss" stat must display the formatted
    figure with $ + thousands separators."""
    html = _render(_make_confident_portfolio())
    assert "Total Reported Loss" in html, "label missing"
    assert "$18,500,000.00" in html, (
        "total_loss_usd not formatted as $18,500,000.00"
    )


def test_dashboard_shows_total_frozen_with_dollars():
    html = _render(_make_confident_portfolio())
    assert "Total Frozen To Date" in html, "label missing"
    assert "$4,250,000.00" in html, (
        "total_frozen_usd not formatted as $4,250,000.00"
    )


def test_dashboard_shows_total_returned_with_dollars():
    html = _render(_make_confident_portfolio())
    assert "Returned To Victims" in html, "label missing"
    assert "$1,800,000.00" in html, (
        "total_returned not formatted as $1,800,000.00"
    )


def test_dashboard_renders_throughput_card_when_confident():
    """has_confident_throughput=True → the throughput card MUST render
    with both median figures."""
    html = _render(_make_confident_portfolio())
    assert "Median Intake → First Letter" in html, (
        "throughput-card label missing for intake→letter"
    )
    assert "Median Letter → First Freeze" in html, (
        "throughput-card label missing for letter→freeze"
    )
    # 27.0 hours rendered as "27 h"
    assert "27 h" in html, "median intake→letter not rendered"
    # 41.5 hours rendered as "42 h" (rounded by %.0f format)
    assert "42 h" in html or "41 h" in html, (
        "median letter→freeze not rendered"
    )


def test_dashboard_top_issuers_table_has_a_row_per_issuer():
    """Each FirmIssuerSummary must appear as a row with issuer name +
    n_letters_sent + n_freezes_observed + $ frozen."""
    html = _render(_make_confident_portfolio())
    # The table header must be present.
    assert "Top Issuers Across Your Portfolio" in html, (
        "top-issuers section missing"
    )
    # Both issuers' rows must be present with their amounts.
    assert "Tether" in html, "Tether missing from top issuers"
    assert "Circle" in html, "Circle missing from top issuers"
    assert "$3,200,000.00" in html, "Tether's $3,200,000 missing"
    assert "$1,050,000.00" in html, "Circle's $1,050,000 missing"
    # The "letters sent" column shows the numbers.
    assert ">6<" in html or " 6 " in html, "Tether n_letters=6 missing"
    assert ">2<" in html or " 2 " in html, "Circle n_letters=2 missing"


def test_dashboard_top_issuers_shows_cross_firm_rate_when_confident():
    """When a FirmIssuerSummary has cross_firm_response_rate set,
    the value must render as a percentage."""
    html = _render(_make_confident_portfolio())
    # Tether: 0.81 → "81%"
    assert "81%" in html, (
        "Tether cross_firm_response_rate=0.81 should render as 81%"
    )
    # Tether: 0.67 → "67%"
    assert "67%" in html, (
        "Tether cross_firm_full_freeze_rate=0.67 should render as 67%"
    )


def test_dashboard_top_issuers_renders_em_dash_when_unknown():
    """Circle has cross_firm_*_rate = None → cells render as —."""
    html = _render(_make_confident_portfolio())
    # The Circle row's cooperation cells must be the placeholder.
    # We just assert SOMETHING with an em-dash appears in the table area.
    assert "—" in html, "em-dash placeholder for missing rates not present"


def test_dashboard_no_unrendered_jinja():
    html = _render(_make_confident_portfolio())
    var_matches = re.findall(r"\{\{[^}]+\}\}", html)
    block_matches = re.findall(r"\{%[^%]+%\}", html)
    assert not var_matches, f"unrendered Jinja vars: {var_matches[:3]!r}"
    assert not block_matches, "unrendered Jinja blocks"


def test_dashboard_no_placeholder_strings():
    html = _render(_make_confident_portfolio())
    forbidden = ["TODO", "FIXME", "XXX", "TBD", "PLACEHOLDER"]
    leaked = [w for w in forbidden if w in html]
    assert not leaked, f"placeholder leak: {leaked}"


def test_dashboard_includes_generated_at_timestamp():
    """Footer must show generation time so the partner knows the
    dashboard's freshness."""
    html = _render(_make_confident_portfolio())
    assert "UTC" in html, "generated_at UTC stamp missing"
    # ISO date prefix at top of cover
    assert re.search(r"20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", html), (
        "no ISO timestamp in HTML"
    )


def test_dashboard_html_escapes_firm_name_with_special_chars():
    """A firm name with HTML-significant chars must be escaped."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    portfolio = LawFirmPortfolio(
        firm_id=_FIRM_ID,
        firm_slug=_FIRM_SLUG,
        firm_name="<script>alert(1)</script> & Co.",
        firm_status="active",
    )
    html = _render(portfolio)
    assert "<script>alert(1)</script>" not in html, "raw <script> tag"
    assert "&lt;script&gt;" in html, "<script> not escaped"
    assert "&amp; Co." in html, "& not escaped"


# ─────────────────────────────────────────────────────────────────────────────
# Empty / new-firm rendering
# ─────────────────────────────────────────────────────────────────────────────


def test_empty_portfolio_shows_throughput_insufficient_data_message():
    """has_confident_throughput=False → throughput card must NOT
    render, and an explicit insufficient-data note must appear."""
    html = _render(_make_empty_portfolio())
    assert "Median Intake" not in html, (
        "throughput card rendered for empty portfolio (should hide)"
    )
    assert "at least 3" in html, (
        "no 'at least 3 cases' insufficient-data note shown"
    )


def test_empty_portfolio_shows_no_top_issuers_message():
    html = _render(_make_empty_portfolio())
    assert "No issuer letters" in html, (
        "empty top-issuers section should have a fallback message"
    )


def test_empty_portfolio_dollar_stats_render_as_zero():
    """Even with no data, the $ stats must render as $0.00 not as
    blank or 'None' — partners need to see the number, just zero."""
    html = _render(_make_empty_portfolio())
    assert "$0.00" in html, "empty portfolio should show $0.00 not blank"


def test_empty_portfolio_h1_still_names_the_firm():
    html = _render(_make_empty_portfolio())
    assert "Brand-New Firm LLP" in html, (
        "empty portfolio's <h1> still must name the firm"
    )


def test_empty_portfolio_has_no_unrendered_jinja():
    """StrictUndefined paranoia: zero-data path must still render
    every variable. A missing field on the empty fixture would
    throw a TemplateError if Jinja's StrictUndefined catches it
    — we test the OUTPUT for unrendered placeholders here."""
    html = _render(_make_empty_portfolio())
    assert "{{ " not in html, "unrendered {{ }} on empty portfolio"
    assert "{% " not in html, "unrendered {% %} on empty portfolio"
