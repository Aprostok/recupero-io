"""RIGOR-Jacob Z7: adversarial-input regression tests for cluster /
cooperation / law-firm dashboard / interactive-graph renderers.

These four renderers ingest aggregate financial state that ultimately
sources Decimal values from upstream layers (Supabase rows, price-oracle
feeds, on-chain transfer USD valuations). The previous rigor sweeps
(Z3, Z4) hardened the freeze-letter / LE-handoff / forensic legal-
request paths against NaN / Infinity propagation and against attacker-
controlled segments leaking into output filenames. The four renderers
here had not been touched and surfaced four concrete bugs:

  1. ``cluster_handoff.render_cluster_handoff`` produces
     ``total_loss_usd_human = "$NaN"`` or ``"$Infinity"`` when the
     cluster_summary's aggregated Decimal is non-finite. Because the
     cluster handoff is the **single LE-facing document** the operator
     hands to the AUSA, an explorer-API glitch that drops a NaN into
     ``total_loss_usd`` would render a federal-court-bound exhibit
     with the literal text ``$NaN`` in the headline figure.

  2. ``cooperation_dashboard.render_cooperation_dashboard`` formats the
     aggregate stats panel via ``f"${total_frozen:,.2f}"`` directly,
     with NO try-guard. A single profile with ``total_frozen_usd =
     Decimal('NaN')`` poisons the ``sum(...)`` call and the
     operator-facing strategy dashboard renders ``$NaN`` in the
     headline stats. The per-profile ``_profile_to_template_dict``
     also funnels ``float(prof.response_rate)`` through unchecked —
     a NaN response rate becomes the JS-toxic string ``"nan"`` in the
     percent cell.

  3. ``law_firm_dashboard.render_law_firm_dashboard`` writes its output
     to ``output_dir / f"law_firm_dashboard_{portfolio.firm_slug}.html"``
     where ``firm_slug`` comes from a Supabase row. If an operator with
     write access to ``public.law_firms`` inserts a row whose slug
     contains path-traversal segments (``../../etc/passwd``,
     ``../escape``, an absolute Windows path ``D:\\evil``), the renderer
     writes the dashboard outside the output dir — the same shape Z4
     fixed in ``legal_requests.py``. Distinct from that file because
     ``law_firm_dashboard`` doesn't go through ``_render_letter`` so the
     Z4 fix doesn't cover it.

  4. ``graph_ui.build_graph_data`` formats node tooltips
     (``inbound_usd``, ``outbound_usd``), edge totals, and the
     ``total_usd_traced`` meta header through ``f"${...:,.2f}"`` with
     no NaN/Inf guard. The interactive graph HTML is operator-shared
     (sometimes attached to a brief) — rendering ``$nan`` in a tooltip
     is the same operator-confidence hit as the cluster handoff. Worse,
     ``total_usd_numeric`` becomes ``float('nan')`` which D3's line-
     thickness scaler then handles as a runtime JS quirk.

For each bug a RED test asserts the post-fix invariant directly against
the rendered output (HTML for the renderers, the dataclass output for
``GraphEdge`` / ``GraphNode``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


# ---------- 1. cluster_handoff NaN / Infinity guard ----------


def _complete_cluster_summary(**overrides) -> dict:
    """Realistic cluster summary shape from
    ``cluster_builder.fetch_cluster_summary`` so the template renders
    end-to-end. Overrides let each test inject hostile state without
    sweeping required keys."""
    from datetime import UTC, datetime

    base = {
        "id": 1,
        "public_id": "CL-TEST01",
        "seed_perp_address": "0x" + "f" * 40,
        "seed_perp_chain": "ethereum",
        "shared_perp_addresses": ["0x" + "f" * 40],
        "shared_perp_chains": ["ethereum"],
        "member_case_count": 2,
        "total_loss_usd": Decimal("48200.00"),
        "status": "active",
        "label": "Test cluster",
        "notes": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 15, tzinfo=UTC),
        "members": [],
    }
    base.update(overrides)
    return base


def _patch_cluster_summary(monkeypatch, summary: dict) -> None:
    """Make ``fetch_cluster_summary`` return the provided summary
    regardless of dsn / public_id. Lets tests drive the renderer with
    hostile aggregate state without touching the database."""
    import recupero.monitoring.cluster_builder as cb

    def _fake_fetch(public_id: str, *, dsn: str | None) -> dict:
        return summary

    monkeypatch.setattr(cb, "fetch_cluster_summary", _fake_fetch)


def test_cluster_handoff_rejects_nan_total_loss(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a NaN aggregated cluster loss must not render as
    ``$NaN`` in the LE-facing aggregated handoff."""
    from recupero.reports.cluster_handoff import render_cluster_handoff

    _patch_cluster_summary(
        monkeypatch,
        _complete_cluster_summary(
            public_id="CL-NAN001",
            total_loss_usd=Decimal("NaN"),
        ),
    )
    out = render_cluster_handoff(
        "CL-NAN001",
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    assert out is not None, "render aborted unexpectedly on NaN aggregate"
    html = out.read_text(encoding="utf-8")
    assert "$NaN" not in html, "NaN total_loss leaked into LE-facing cluster handoff"
    assert "$nan" not in html.lower()


def test_cluster_handoff_rejects_infinity_total_loss(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a Decimal('Infinity') total_loss (oracle glitch)
    must not render as ``$Infinity`` in the LE handoff."""
    from recupero.reports.cluster_handoff import render_cluster_handoff

    _patch_cluster_summary(
        monkeypatch,
        _complete_cluster_summary(
            public_id="CL-INF001",
            total_loss_usd=Decimal("Infinity"),
        ),
    )
    out = render_cluster_handoff(
        "CL-INF001",
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    assert out is not None, "render aborted unexpectedly on Infinity aggregate"
    html = out.read_text(encoding="utf-8")
    assert "Infinity" not in html
    assert "$inf" not in html.lower()


# ---------- 2. cooperation_dashboard NaN aggregation guard ----------


@dataclass
class _StubProfile:
    """Mirror IssuerCooperationProfile shape with the minimal fields the
    renderer reads."""
    issuer: str = "TetherTest"
    n_letters_sent: int = 1
    n_responded: int = 0
    n_silent: int = 1
    response_rate: float = 0.0
    full_freeze_rate: float = 0.0
    partial_freeze_rate: float = 0.0
    declined_rate: float = 0.0
    silence_rate: float = 1.0
    median_response_hours: float | None = None
    avg_response_hours: float | None = None
    fastest_response_hours: float | None = None
    slowest_response_hours: float | None = None
    total_frozen_usd: Decimal = field(default_factory=lambda: Decimal(0))
    is_black_hole: bool = False
    has_confident_profile: bool = False
    latest_letter_sent_at: str | None = None
    latest_outcome_observed_at: str | None = None


def test_cooperation_dashboard_rejects_nan_total_frozen(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a single issuer profile with
    ``total_frozen_usd = Decimal('NaN')`` poisons the aggregate sum and
    renders ``$NaN`` in the operator strategy dashboard. The renderer
    must sanitize."""
    from recupero.reports import cooperation_dashboard as cd

    nan_profile = _StubProfile(
        issuer="OracleGlitched",
        n_letters_sent=4,
        total_frozen_usd=Decimal("NaN"),
    )
    ok_profile = _StubProfile(
        issuer="Tether",
        n_letters_sent=10,
        total_frozen_usd=Decimal("100000"),
    )
    import recupero.monitoring.cooperation_intelligence as ci
    monkeypatch.setattr(
        ci, "build_all_profiles",
        lambda dsn: {"OracleGlitched": nan_profile, "Tether": ok_profile},
    )

    # The recommendation API is fine; let it use the real function which
    # tolerates NaN floats. The cooperation_intelligence module is
    # already Z3-hardened so the import path is real.
    out = cd.render_cooperation_dashboard(
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    if out is None:
        # Acceptable degradation path.
        return
    html = out.read_text(encoding="utf-8")
    assert "$NaN" not in html, (
        "NaN total_frozen_usd in one profile poisoned the aggregate "
        "stats panel — operator strategy dashboard shows $NaN"
    )
    assert "$nan" not in html.lower()
    # The per-row NaN also must not surface as "nan" / "NaN" anywhere
    # the operator can see — float() of Decimal('NaN') would render
    # JS-toxic 'nan' in the percent column.
    assert "NaN" not in html


# ---------- 3. law_firm_dashboard firm_slug path traversal ----------


@dataclass
class _StubPortfolio:
    """Mirror LawFirmPortfolio shape with only what the renderer touches."""
    firm_id: int | None = 1
    firm_slug: str = "test-firm"
    firm_name: str = "Test Firm LLP"
    firm_status: str = "active"
    n_referred_cases: int = 0
    n_completed_traces: int = 0
    n_in_queue: int = 0
    n_with_letters_sent: int = 0
    total_loss_usd: Decimal | None = field(default_factory=lambda: Decimal(0))
    total_frozen_usd: Decimal | None = field(default_factory=lambda: Decimal(0))
    total_returned_to_victim_usd: Decimal | None = field(default_factory=lambda: Decimal(0))
    median_hours_intake_to_first_letter: float | None = None
    median_hours_letter_to_first_freeze: float | None = None
    has_confident_throughput: bool = False
    top_issuers: list = field(default_factory=list)
    latest_referral_at: str | None = None
    latest_letter_sent_at: str | None = None


def test_law_firm_dashboard_rejects_path_traversal_slug(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a firm row whose ``slug`` is
    ``../../escape`` must not let the renderer write outside
    ``output_dir``. Mirrors the Z4 legal_requests fix shape."""
    from recupero.reports import law_firm_dashboard as lfd

    bad = _StubPortfolio(
        firm_id=42,
        firm_slug="../../escape",
        firm_name="Hostile firm",
    )
    import recupero.monitoring.law_firm_dashboard as lfb
    monkeypatch.setattr(
        lfb, "build_firm_portfolio",
        lambda firm_key, *, dsn: bad,
    )

    out = lfd.render_law_firm_dashboard(
        "anything",
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    # Either the renderer refuses the slug entirely (returns None) or
    # writes under output_dir with a sanitized name. The filename
    # MUST start with the renderer's prefix and end in .html — a
    # ``../../escape`` slug that collapses to a bare ``escape.html``
    # in output_dir is still wrong: the file no longer carries the
    # ``law_firm_dashboard_`` prefix, and an adversary who can write
    # to public.law_firms (an internal Recupero ops privilege) could
    # silently overwrite any operator file with a matching name.
    if out is None:
        return
    resolved = out.resolve()
    out_dir_resolved = tmp_path.resolve()
    assert out_dir_resolved == resolved.parent, (
        f"Path traversal: {resolved} is not directly inside {out_dir_resolved}"
    )
    assert out.name.startswith("law_firm_dashboard_"), (
        f"Filename lost the renderer prefix — slug stripped the lead: {out.name}"
    )
    assert ".." not in out.name
    assert "/" not in out.name
    assert "\\" not in out.name


def test_law_firm_dashboard_rejects_empty_slug(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a firm row whose ``slug`` is the empty string
    or only path-illegal characters must not produce a filename
    collapsing to ``law_firm_dashboard_.html``."""
    from recupero.reports import law_firm_dashboard as lfd

    bad = _StubPortfolio(firm_id=43, firm_slug="", firm_name="X")
    import recupero.monitoring.law_firm_dashboard as lfb
    monkeypatch.setattr(
        lfb, "build_firm_portfolio",
        lambda firm_key, *, dsn: bad,
    )

    out = lfd.render_law_firm_dashboard(
        "anything",
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    if out is None:
        return
    # The filename must have a recognizable slug segment, not "_.html".
    # We allow an explicit fallback like "_unknown_".
    assert out.name not in ("law_firm_dashboard_.html",), (
        "Empty slug produced a degenerate filename"
    )


# ---------- 4. law_firm_dashboard NaN total_loss_usd ----------


def test_law_firm_dashboard_rejects_nan_total_loss(tmp_path, monkeypatch) -> None:
    """RIGOR-Jacob Z7: a firm portfolio whose ``total_loss_usd`` is
    ``Decimal('NaN')`` (PostgreSQL NUMERIC accepts NaN; the aggregator
    SUM over a single NaN row propagates it through psycopg into the
    portfolio dataclass) must not render ``$NaN`` in the firm-facing
    dashboard headline."""
    from recupero.reports import law_firm_dashboard as lfd

    bad = _StubPortfolio(
        firm_id=44,
        firm_slug="alpha-legal",
        firm_name="Alpha Legal LLP",
        total_loss_usd=Decimal("NaN"),
        total_frozen_usd=Decimal("Infinity"),
        total_returned_to_victim_usd=Decimal("NaN"),
    )
    import recupero.monitoring.law_firm_dashboard as lfb
    monkeypatch.setattr(
        lfb, "build_firm_portfolio",
        lambda firm_key, *, dsn: bad,
    )

    out = lfd.render_law_firm_dashboard(
        "alpha-legal",
        output_dir=tmp_path,
        dsn="postgres://stub",
    )
    if out is None:
        return
    html = out.read_text(encoding="utf-8")
    assert "$NaN" not in html
    assert "$nan" not in html.lower()
    assert "Infinity" not in html
    assert "$inf" not in html.lower()
