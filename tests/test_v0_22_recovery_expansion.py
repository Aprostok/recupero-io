"""v0.22.0 E2E + unit tests — Recovery Probability expansion.

Covers:
  * Scorer per_issuer field is populated with IssuerRecoveryRow entries
  * to_json_safe() exposes per_issuer in template-ready form
  * LE handoff Section 5.4 "Recovery Forecast" renders per-issuer table
  * LE handoff "Recovery drivers" section renders
  * LE handoff "Net to victim" block renders with ROI fields
  * Recovery Snapshot deliverable renders + writes to disk
  * Snapshot recommendation pill maps the four recommendation values
  * Empty / degraded inputs degrade gracefully (no StrictUndefined)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Scorer per_issuer + IssuerRecoveryRow
# ─────────────────────────────────────────────────────────────────────────────


def test_score_recovery_populates_per_issuer_breakdown():
    """v0.22.0: every freezable entry in the brief produces an
    IssuerRecoveryRow on the returned RecoveryEstimate."""
    from recupero.recovery.scorer import IssuerRecoveryRow, score_recovery

    brief = {
        "TOTAL_LOSS_USD": "$3,000,000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "$1,200,000",
             "freeze_capability": "yes", "evidence_mode": "current_balance_only"},
            {"issuer": "Circle", "total_usd": "$800,000",
             "freeze_capability": "yes", "evidence_mode": "current_balance_only"},
            {"issuer": "Coinbase", "total_usd": "$600,000",
             "freeze_capability": "limited", "evidence_mode": "historical_only"},
        ],
        "VICTIM_JURISDICTION": "United States",
    }
    estimate = score_recovery(brief, auto_load_priors=False)

    assert len(estimate.per_issuer) == 3
    assert all(isinstance(r, IssuerRecoveryRow) for r in estimate.per_issuer)
    # Should be sorted DESC by expected_recovered_usd
    amounts = [r.expected_recovered_usd for r in estimate.per_issuer]
    assert amounts == sorted(amounts, reverse=True)


def test_score_recovery_per_issuer_marks_learned_vs_heuristic():
    """When a learned prior exists for an issuer, the row's
    is_learned_prior flag is True. Otherwise False.

    The flag drives the template's "from N actual outcomes" vs
    "industry heuristic" annotation — material to the defensibility
    of the recovery number.
    """
    from recupero.freeze_learning.recorder import IssuerPrior
    from recupero.recovery.scorer import score_recovery

    learned = {
        "Tether": IssuerPrior(
            issuer="Tether", letter_tier="standard",
            sample_size=50, p_any_freeze=0.85, p_full_freeze=0.6,
            p_returned_to_victim=0.4,
            avg_response_hours=48.0, median_response_hours=24.0,
            is_learned=True,
        ),
    }
    brief = {
        "TOTAL_LOSS_USD": "$2,000,000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
            {"issuer": "Circle", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
    }
    estimate = score_recovery(brief, learned_priors=learned, auto_load_priors=False)

    by_issuer = {r.issuer: r for r in estimate.per_issuer}
    assert by_issuer["Tether"].is_learned_prior is True
    assert by_issuer["Circle"].is_learned_prior is False


def test_score_recovery_to_json_safe_includes_per_issuer():
    """to_json_safe() exposes per_issuer as a list of dicts ready for
    the Jinja templates (string-formatted USD + pct fields)."""
    from recupero.recovery.scorer import score_recovery

    brief = {
        "TOTAL_LOSS_USD": "$1,000,000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "$500,000",
             "freeze_capability": "yes"},
        ],
    }
    json_safe = score_recovery(brief, auto_load_priors=False).to_json_safe()
    assert "per_issuer" in json_safe
    assert len(json_safe["per_issuer"]) == 1
    row = json_safe["per_issuer"][0]
    assert row["issuer"] == "Tether"
    assert "$" in row["requested_usd_human"]
    assert "%" in row["base_prior_pct"]
    assert "%" in row["effective_prior_pct"]
    assert isinstance(row["is_learned_prior"], bool)


# ─────────────────────────────────────────────────────────────────────────────
# LE handoff renders new sections
# ─────────────────────────────────────────────────────────────────────────────


def _v_cfi01_le_render(*, recovery_estimate=None):
    """Render the LE handoff on the V-CFI01 fixture with a given
    recovery_estimate dict."""
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

    with tempfile.TemporaryDirectory(prefix="v22_le_") as tmp:
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=Path(tmp),
            recovery_estimate=recovery_estimate,
        )
        return bundle.le_path.read_text(encoding="utf-8")


def test_le_handoff_renders_per_issuer_recovery_forecast():
    """Section 5.4 Recovery Forecast: per-issuer table with effective
    prior + expected recovery + learned/heuristic source flag."""
    recovery = {
        "expected_recovered_usd": "$1,200,000.00",
        "expected_recovered_low_usd": "$800,000.00",
        "expected_recovered_high_usd": "$1,600,000.00",
        "probability_any_recovery_90d": 0.62,
        "recommendation": "recommend",
        "headline_summary": "V-CFI01 multi-issuer case",
        "per_issuer": [
            {
                "issuer": "Tether",
                "requested_usd_human": "$1,200,000.00",
                "base_prior_pct": "85%",
                "evidence_discount_pct": "100%",
                "evidence_mode": "current_balance_only",
                "effective_prior_pct": "85%",
                "expected_recovered_usd_human": "$1,020,000.00",
                "is_learned_prior": True,
            },
            {
                "issuer": "Circle",
                "requested_usd_human": "$800,000.00",
                "base_prior_pct": "80%",
                "evidence_discount_pct": "100%",
                "evidence_mode": "current_balance_only",
                "effective_prior_pct": "80%",
                "expected_recovered_usd_human": "$640,000.00",
                "is_learned_prior": False,
            },
        ],
        "drivers": [],
    }
    html = _v_cfi01_le_render(recovery_estimate=recovery)
    assert "Recovery Forecast" in html
    assert "Tether" in html
    assert "$1,020,000.00" in html
    assert "$640,000.00" in html
    assert "85%" in html
    # Learned/heuristic source annotation visible
    assert "learned" in html.lower()
    assert "heuristic" in html.lower()


def test_le_handoff_renders_drivers_table_when_provided():
    """Recovery drivers list — colour-coded positive/negative."""
    recovery = {
        "expected_recovered_usd": "$500,000.00",
        "drivers": [
            {"factor": "primary_issuer", "direction": "positive",
             "weight": 0.5, "description": "Tether is highly cooperative."},
            {"factor": "jurisdiction", "direction": "negative",
             "weight": 0.4, "description": "BVI venue adds friction."},
        ],
        "per_issuer": [],
    }
    html = _v_cfi01_le_render(recovery_estimate=recovery)
    assert "Recovery drivers" in html
    assert "primary_issuer" in html
    assert "jurisdiction" in html
    assert "Tether is highly cooperative" in html
    assert "BVI venue adds friction" in html
    # Direction pills present
    assert "supports" in html
    assert "reduces" in html


def test_le_handoff_renders_net_to_victim_roi_block():
    """Net to victim block with CI range + Recupero fees + payback prob."""
    recovery = {
        "expected_recovered_usd": "$1,000,000.00",
        "expected_net_to_victim_usd": "$850,000.00",
        "expected_net_low_usd": "$600,000.00",
        "expected_net_high_usd": "$1,100,000.00",
        "expected_recupero_revenue_usd": "$150,000.00",
        "probability_pays_back_engagement_180d": 0.92,
        "drivers": [],
        "per_issuer": [],
    }
    html = _v_cfi01_le_render(recovery_estimate=recovery)
    assert "Net to victim" in html
    assert "$850,000.00" in html
    assert "$600,000.00" in html
    assert "$1,100,000.00" in html
    assert "92%" in html


def test_le_handoff_hides_recovery_sections_when_estimate_empty():
    """All v0.22 sections must be guarded by `if recovery_estimate ...`
    so the LE template renders cleanly when no estimate is available."""
    html = _v_cfi01_le_render(recovery_estimate=None)
    # All v0.22 sections must be absent
    assert "Recovery Forecast" not in html
    assert "Recovery drivers" not in html
    assert "Net to victim" not in html


# ─────────────────────────────────────────────────────────────────────────────
# Recovery Snapshot standalone deliverable
# ─────────────────────────────────────────────────────────────────────────────


def test_recovery_snapshot_renders_full_document():
    """The standalone recovery snapshot renders to disk under
    briefs/recovery_snapshot_<case>.html and contains the headline +
    per-issuer + drivers blocks."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    recovery = {
        "expected_recovered_usd": "$2,100,000.00",
        "expected_net_to_victim_usd": "$1,785,000.00",
        "expected_net_low_usd": "$1,200,000.00",
        "expected_net_high_usd": "$2,400,000.00",
        "expected_recupero_revenue_usd": "$315,000.00",
        "probability_any_recovery_90d": 0.58,
        "probability_pays_back_engagement_180d": 0.91,
        "recommendation": "recommend",
        "headline_summary": "Multi-issuer recoverable; primary target Tether USDT at 85% prior.",
        "per_issuer": [
            {
                "issuer": "Tether",
                "requested_usd_human": "$1,200,000.00",
                "base_prior_pct": "85%",
                "evidence_discount_pct": "100%",
                "evidence_mode": "current_balance_only",
                "effective_prior_pct": "85%",
                "expected_recovered_usd_human": "$1,020,000.00",
                "is_learned_prior": True,
            },
        ],
        "drivers": [
            {"factor": "primary_issuer", "direction": "positive",
             "weight": 0.5, "description": "Tether cooperation history is strong."},
        ],
    }

    with tempfile.TemporaryDirectory(prefix="snapshot_") as tmp:
        briefs_dir = Path(tmp)
        path = render_recovery_snapshot(
            case_id="RCP-2026-0501",
            recovery_estimate=recovery,
            briefs_dir=briefs_dir,
        )
        assert path is not None
        assert path.exists()
        assert path.name == "recovery_snapshot_RCP-2026-0501.html"
        html = path.read_text(encoding="utf-8")

    # Headline
    assert "Recovery" in html and "Snapshot" in html
    assert "$1,785,000.00" in html
    assert "58%" in html
    # Recommendation pill
    assert "recommend" in html.lower()
    # Per-issuer table
    assert "Tether" in html
    assert "$1,020,000.00" in html
    # Drivers
    assert "primary_issuer" in html
    assert "Tether cooperation history is strong" in html
    # Footer + audience framing present
    assert "Pre-engagement" in html


def test_recovery_snapshot_handles_each_recommendation_value():
    """Each recommendation value maps to a distinct pill style."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    for rec, expected_substring in [
        ("recommend",  "Recommended for engagement"),
        ("caveat",     "Engage with caveat"),
        ("discourage", "Engagement discouraged"),
        ("reject",     "Recovery not advised"),
    ]:
        recovery = {
            "expected_net_to_victim_usd": "$100,000.00",
            "expected_net_low_usd": "$50,000.00",
            "expected_net_high_usd": "$150,000.00",
            "probability_any_recovery_90d": 0.5,
            "recommendation": rec,
            "headline_summary": f"test for {rec}",
            "per_issuer": [],
            "drivers": [],
        }
        with tempfile.TemporaryDirectory(prefix=f"snapshot_{rec}_") as tmp:
            path = render_recovery_snapshot(
                case_id=f"CASE-{rec}",
                recovery_estimate=recovery,
                briefs_dir=Path(tmp),
            )
            html = path.read_text(encoding="utf-8")
        assert expected_substring in html, (
            f"recommendation={rec!r}: expected '{expected_substring}' "
            f"in rendered HTML, missing"
        )


def test_recovery_snapshot_returns_none_when_estimate_empty():
    """No recovery estimate → render_recovery_snapshot returns None
    rather than producing a degraded HTML."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    with tempfile.TemporaryDirectory(prefix="snapshot_empty_") as tmp:
        path = render_recovery_snapshot(
            case_id="EMPTY",
            recovery_estimate={},
            briefs_dir=Path(tmp),
        )
    assert path is None


def test_recovery_snapshot_safe_case_id_in_filename():
    """A case_id with unsafe chars (slashes, spaces) is sanitized in
    the output filename — avoids file-system path traversal."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    recovery = {
        "expected_net_to_victim_usd": "$1,000",
        "expected_net_low_usd": "$500",
        "expected_net_high_usd": "$1,500",
        "probability_any_recovery_90d": 0.5,
        "recommendation": "caveat",
        "headline_summary": "test",
        "per_issuer": [],
        "drivers": [],
    }
    with tempfile.TemporaryDirectory(prefix="snapshot_unsafe_") as tmp:
        path = render_recovery_snapshot(
            case_id="../../etc/passwd",
            recovery_estimate=recovery,
            briefs_dir=Path(tmp),
        )
    # Sanitized — all unsafe chars become underscores
    assert "passwd" in path.name
    assert ".." not in path.name
    assert "/" not in path.name
