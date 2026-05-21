"""v0.26.1 audit-fix regression tests.

Each test pins one v0.26.0 audit finding so the bug cannot quietly
regress in a future refactor.

  * CRIT-1 — cases.status filter used non-existent values; now
    derives completion from investigations.status='complete'
  * CRIT-2 — top-issuers double-counted frozen_usd; now uses the
    strongest-outcome ROW_NUMBER pattern
  * HIGH-1 — returned_to_victim_usd now reads returned_usd column
    (with COALESCE to frozen_usd for legacy rows)
  * HIGH-2 — --all flow no longer double-builds every portfolio
  * MED-3 — paused/closed/archived firms get an empty portfolio
    (the dashboard surfaces nothing fresh-looking)
"""

from __future__ import annotations

import inspect
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID


FIRM_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
FIRM_SLUG = "demo-firm"


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-1 — n_completed_traces uses investigations.status='complete'
# ─────────────────────────────────────────────────────────────────────────────


def test_crit1_volume_sql_joins_investigations_for_completion_signal():
    """The volume query MUST derive completion from
    investigations.status='complete', not from cases.status text
    values (which the codebase never sets to 'completed' or
    'tracing' anywhere)."""
    from recupero.monitoring import law_firm_dashboard as mod
    src = inspect.getsource(mod._populate_volume_and_money)
    # Must mention the canonical worker status value.
    assert "status = 'complete'" in src
    # Must JOIN to public.investigations on case_id.
    assert "public.investigations" in src
    assert "i.case_id = cr.case_id" in src or "case_id = cr.case_id" in src
    # The actual SQL must aggregate via the bool_or trick so a case
    # with ANY complete investigation counts as completed.
    assert "bool_or(i.status = 'complete')" in src
    assert "has_complete_inv" in src


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-2 — top issuers uses ROW_NUMBER strongest-outcome
# ─────────────────────────────────────────────────────────────────────────────


def test_crit2_top_issuers_sql_uses_row_number_strongest_outcome():
    """The top-issuers query MUST pick the strongest outcome per
    letter via ROW_NUMBER PARTITION BY letter_id; the prior code
    SUM'd across all positive outcomes and inflated $ totals 2-3×."""
    from recupero.monitoring import law_firm_dashboard as mod
    src = inspect.getsource(mod._populate_top_issuers)
    # ROW_NUMBER + PARTITION BY letter_id is the contract.
    assert "ROW_NUMBER()" in src
    assert "PARTITION BY" in src
    assert "letter_id" in src
    # Must filter on rn = 1 (only the strongest row counts).
    assert "rn = 1" in src or "rn=1" in src
    # Must use the same outcome-ranking order.
    assert "'returned_to_victim'" in src
    assert "'full_freeze'" in src
    assert "'partial_freeze'" in src


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-1 — returned_to_victim_usd uses returned_usd column
# ─────────────────────────────────────────────────────────────────────────────


def test_high1_returned_to_victim_uses_returned_usd_column():
    """The returned-to-victim aggregate MUST read the dedicated
    returned_usd column (with COALESCE to frozen_usd as a fallback
    for legacy rows where only frozen_usd was recorded)."""
    from recupero.monitoring import law_firm_dashboard as mod
    src = inspect.getsource(mod._populate_volume_and_money)
    # returned_usd column must appear in the SELECT.
    assert "returned_usd" in src
    # The aggregator should COALESCE returned_usd, frozen_usd to
    # cover legacy rows that pre-date the returned_usd convention.
    assert (
        "COALESCE(returned_usd, frozen_usd)" in src
        or "COALESCE(fo.returned_usd, fo.frozen_usd)" in src
    )


# ─────────────────────────────────────────────────────────────────────────────
# HIGH-2 — --all does not double-build portfolios
# ─────────────────────────────────────────────────────────────────────────────


def test_high2_render_all_does_not_double_build():
    """render_all_law_firm_dashboards must call build_firm_portfolio
    EXACTLY once per active firm — not twice. The pre-fix code called
    build_all_firm_portfolios + then build_firm_portfolio per slug,
    doubling every aggregation."""
    from recupero.reports import law_firm_dashboard as renderer

    # Capture every call to build_firm_portfolio.
    build_calls = []

    def _fake_build(firm_key, *, dsn):
        from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
        build_calls.append(firm_key)
        return LawFirmPortfolio(
            firm_id=UUID(int=hash(firm_key) & ((1 << 128) - 1)),
            firm_slug=firm_key, firm_name=firm_key, firm_status="active",
        )

    # Stub the DB connection that the --all flow opens to list slugs.
    cur = MagicMock()
    cur.fetchall.return_value = [
        {"slug": "firm-a"},
        {"slug": "firm-b"},
        {"slug": "firm-c"},
    ]
    cur.execute = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "recupero.monitoring.law_firm_dashboard.build_firm_portfolio",
            side_effect=_fake_build,
        ), patch(
            "recupero._common.db_connect", return_value=conn,
        ):
            renderer.render_all_law_firm_dashboards(
                output_dir=Path(tmp), dsn="postgres://x",
            )

    # Exactly 3 build calls (one per firm) — NOT 6 (the pre-fix bug).
    assert len(build_calls) == 3, (
        f"build_firm_portfolio called {len(build_calls)} times; "
        "expected exactly 3 (one per firm)"
    )
    assert sorted(build_calls) == ["firm-a", "firm-b", "firm-c"]


# ─────────────────────────────────────────────────────────────────────────────
# MED-3 — non-active firm returns empty portfolio (no aggregates)
# ─────────────────────────────────────────────────────────────────────────────


def test_med3_archived_firm_returns_empty_aggregate():
    """A firm with status='archived' must NOT populate aggregates.
    The dashboard for an off-boarded partner should not look fresh
    and authoritative; bail with an empty portfolio."""
    from recupero.monitoring import law_firm_dashboard as mod

    # Resolve returns the firm row with status='archived'. FIRM_SLUG
    # isn't a UUID, so _resolve_firm_row skips the UUID branch and
    # only runs the slug query (one execute + one fetchone).
    cur = MagicMock()
    cur.fetchone.return_value = {
        "id": str(FIRM_ID),
        "slug": FIRM_SLUG,
        "name": "Off-Boarded Firm LLP",
        "status": "archived",
    }
    cur.execute = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ):
        p = mod.build_firm_portfolio(FIRM_SLUG, dsn="postgres://x")

    # Firm metadata IS populated so the caller can see the status.
    assert p.firm_slug == FIRM_SLUG
    assert p.firm_status == "archived"
    # But aggregates are NOT populated — every count is the default 0.
    assert p.n_referred_cases == 0
    assert p.n_completed_traces == 0
    assert p.total_frozen_usd == Decimal(0)
    assert p.top_issuers == []
    # Crucially, no further cursor calls past the resolve query —
    # _populate_volume_and_money / _populate_throughput /
    # _populate_top_issuers all skipped. Slug-branch resolve = exactly
    # one execute.
    assert cur.execute.call_count == 1


def test_med3_paused_firm_also_returns_empty():
    """status='paused' takes the same path."""
    from recupero.monitoring import law_firm_dashboard as mod

    cur = MagicMock()
    cur.fetchone.return_value = {
        "id": str(FIRM_ID), "slug": FIRM_SLUG, "name": "X",
        "status": "paused",
    }
    cur.execute = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ):
        p = mod.build_firm_portfolio(FIRM_SLUG, dsn="postgres://x")

    assert p.firm_status == "paused"
    assert p.n_referred_cases == 0
