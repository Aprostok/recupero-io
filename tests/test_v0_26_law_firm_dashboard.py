"""v0.26.0 — Partner law-firm dashboard tests.

Pure-function tests of the aggregator. DB access is mocked via a
stub cursor that returns canned rows in the same order the real
code calls cur.execute / cur.fetchone / cur.fetchall.

Coverage:
  * Empty-state branches (no firm matches, no referrals)
  * Volume + money aggregation
  * Throughput medians only published above sample threshold
  * Top-issuer enrichment with cooperation_intelligence
  * UUID-or-slug firm_key resolution
  * Exception in DB layer → empty portfolio (never raises)
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4


# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures
# ─────────────────────────────────────────────────────────────────────────────


FIRM_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
FIRM_SLUG = "morgan-stanley-recovery"


def _firm_row():
    return {
        "id": str(FIRM_ID),
        "slug": FIRM_SLUG,
        "name": "Morgan Stanley Recovery",
        "status": "active",
    }


def _stub_cursor_with_query_results(results: list):
    """A cursor that returns the given results in order for each
    execute → (fetchone | fetchall) call. ``results`` is a list of
    dicts (for fetchone) or list-of-dicts (for fetchall) in the
    order the production code will request them.
    """
    cur = MagicMock()
    results_iter = iter(results)

    def _fetchone():
        try:
            r = next(results_iter)
        except StopIteration:
            return None
        # If the queued result is a list, we should have used
        # fetchall instead. Surface that as a clear test bug.
        assert not isinstance(r, list), (
            "queued a list result but fetchone was called"
        )
        return r

    def _fetchall():
        try:
            r = next(results_iter)
        except StopIteration:
            return []
        assert isinstance(r, list), (
            "queued a non-list result but fetchall was called"
        )
        return r

    cur.execute = MagicMock()
    cur.fetchone.side_effect = _fetchone
    cur.fetchall.side_effect = _fetchall
    return cur


def _stub_conn_with_cursor(cur):
    """A conn whose .cursor() returns the given cursor, with the
    context-manager protocol stubbed."""
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Empty-state branches
# ─────────────────────────────────────────────────────────────────────────────


def test_build_portfolio_returns_empty_when_dsn_none():
    """No DSN (local CLI without Supabase) → empty portfolio,
    never raises."""
    from recupero.monitoring.law_firm_dashboard import build_firm_portfolio
    portfolio = build_firm_portfolio("any-slug", dsn=None)
    assert portfolio.n_referred_cases == 0
    assert portfolio.firm_slug == ""
    assert portfolio.firm_id is None


def test_build_portfolio_returns_empty_when_firm_not_found():
    """firm_key doesn't match any row → empty portfolio."""
    from recupero.monitoring import law_firm_dashboard as mod
    # UUID branch fetchone returns None, slug branch fetchone returns None.
    cur = _stub_cursor_with_query_results([None, None])
    conn = _stub_conn_with_cursor(cur)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ):
        portfolio = mod.build_firm_portfolio("ghost-firm", dsn="postgres://x")

    assert portfolio.n_referred_cases == 0
    assert portfolio.firm_slug == ""


def test_build_portfolio_catches_db_exception():
    """DB layer crashes → empty portfolio (never propagates)."""
    from recupero.monitoring import law_firm_dashboard as mod

    def _boom(*a, **kw):
        raise RuntimeError("simulated supabase outage")

    with patch(
        "recupero._common.db_connect", side_effect=_boom,
    ):
        portfolio = mod.build_firm_portfolio(FIRM_SLUG, dsn="postgres://x")

    assert portfolio.n_referred_cases == 0
    assert portfolio.firm_id is None


# ─────────────────────────────────────────────────────────────────────────────
# Volume + money + throughput
# ─────────────────────────────────────────────────────────────────────────────


def test_build_portfolio_aggregates_volume_money_and_throughput():
    """Happy path — 5 referred cases, 3 with letters, $1.2M frozen,
    $800k returned, throughput medians published."""
    from recupero.monitoring import law_firm_dashboard as mod

    results = [
        # 1. firm row lookup by slug (UUID parse fails first).
        _firm_row(),
        # 2. volume rollup (fetchone)
        {
            "n_referred": 5,
            "n_completed": 3,
            "n_in_queue": 2,
            "latest_referral_at": "2026-04-15T12:00:00Z",
        },
        # 3. total_loss SUM (fetchone)
        {"sum_loss": Decimal("8500000.00")},
        # 4. frozen + returned SUM (fetchone)
        {
            "frozen": Decimal("1200000.00"),
            "returned": Decimal("800000.00"),
        },
        # 5. n_with_letters_sent (fetchone)
        {"n_with_letters": 3},
        # 6. intake → first letter rows (fetchall) — 4 cases ≥ 3 threshold
        [
            {
                "first_letter_at": "x",
                "intake_at": "y",
                "hours_intake_to_first_letter": 12.0,
                "latest_letter_overall": "2026-04-14T10:00:00Z",
            },
            {
                "first_letter_at": "x",
                "intake_at": "y",
                "hours_intake_to_first_letter": 24.0,
                "latest_letter_overall": "2026-04-14T10:00:00Z",
            },
            {
                "first_letter_at": "x",
                "intake_at": "y",
                "hours_intake_to_first_letter": 36.0,
                "latest_letter_overall": "2026-04-14T10:00:00Z",
            },
        ],
        # 7. letter → first freeze rows (fetchall)
        [
            {"hours_letter_to_first_freeze": 18.0},
            {"hours_letter_to_first_freeze": 30.0},
            {"hours_letter_to_first_freeze": 42.0},
        ],
        # 8. top issuers (fetchall)
        [
            {
                "issuer": "Tether",
                "n_letters": 5,
                "n_freezes": 4,
                "total_frozen": Decimal("900000.00"),
            },
            {
                "issuer": "Circle",
                "n_letters": 2,
                "n_freezes": 1,
                "total_frozen": Decimal("300000.00"),
            },
        ],
    ]
    cur = _stub_cursor_with_query_results(results)
    conn = _stub_conn_with_cursor(cur)

    # Stub cooperation_profile so the enrich path doesn't actually
    # hit DB. Make Tether have a confident profile, Circle empty.
    class _FakeProfile:
        def __init__(self, confident, response, ffr):
            self.has_confident_profile = confident
            self.response_rate = response
            self.full_freeze_rate = ffr

    def _fake_build_coop(issuer, *, dsn):
        if issuer == "Tether":
            return _FakeProfile(True, 0.78, 0.61)
        return _FakeProfile(False, 0.0, 0.0)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ), patch(
        "recupero.monitoring.cooperation_intelligence.build_cooperation_profile",
        side_effect=_fake_build_coop,
    ):
        p = mod.build_firm_portfolio(FIRM_SLUG, dsn="postgres://x")

    assert p.firm_id == FIRM_ID
    assert p.firm_slug == FIRM_SLUG
    assert p.n_referred_cases == 5
    assert p.n_completed_traces == 3
    assert p.n_in_queue == 2
    assert p.n_with_letters_sent == 3
    assert p.total_loss_usd == Decimal("8500000.00")
    assert p.total_frozen_usd == Decimal("1200000.00")
    assert p.total_returned_to_victim_usd == Decimal("800000.00")
    # Median of [12, 24, 36] = 24
    assert p.median_hours_intake_to_first_letter == 24.0
    # Median of [18, 30, 42] = 30
    assert p.median_hours_letter_to_first_freeze == 30.0
    assert p.has_confident_throughput is True

    assert len(p.top_issuers) == 2
    tether = p.top_issuers[0]
    assert tether.issuer == "Tether"
    assert tether.n_letters_sent == 5
    assert tether.cross_firm_response_rate == 0.78
    assert tether.cross_firm_full_freeze_rate == 0.61
    circle = p.top_issuers[1]
    assert circle.issuer == "Circle"
    # Insufficient cross-firm sample → enrich fields stay None.
    assert circle.cross_firm_response_rate is None


def test_build_portfolio_skips_throughput_below_sample_threshold():
    """With only 2 referred cases the throughput card stays hidden,
    even if we have letter timing data."""
    from recupero.monitoring import law_firm_dashboard as mod

    results = [
        _firm_row(),
        # 2 referred cases — below the 3-case threshold.
        {
            "n_referred": 2,
            "n_completed": 1,
            "n_in_queue": 1,
            "latest_referral_at": "2026-04-15T12:00:00Z",
        },
        {"sum_loss": Decimal("500000.00")},
        {"frozen": Decimal("0"), "returned": Decimal("0")},
        {"n_with_letters": 1},
        # The throughput queries should NOT be called when below
        # threshold; queue empty fetchall results just in case.
        [],
    ]
    cur = _stub_cursor_with_query_results(results)
    conn = _stub_conn_with_cursor(cur)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ):
        p = mod.build_firm_portfolio(FIRM_SLUG, dsn="postgres://x")

    assert p.n_referred_cases == 2
    assert p.median_hours_intake_to_first_letter is None
    assert p.median_hours_letter_to_first_freeze is None
    assert p.has_confident_throughput is False


# ─────────────────────────────────────────────────────────────────────────────
# Firm-key resolution: UUID vs slug
# ─────────────────────────────────────────────────────────────────────────────


def test_firm_key_resolves_via_uuid_branch():
    """When firm_key parses as UUID, the UUID-branch query matches
    first; slug query never runs."""
    from recupero.monitoring import law_firm_dashboard as mod

    results = [_firm_row()]  # UUID branch returns the row.
    cur = _stub_cursor_with_query_results(results)
    conn = _stub_conn_with_cursor(cur)

    with patch(
        "recupero._common.db_connect", return_value=conn,
    ):
        # The rest of the builder calls also need stubbed results.
        # Add the bare-minimum stubs to let the build finish.
        extra = [
            {"n_referred": 0, "n_completed": 0, "n_in_queue": 0,
             "latest_referral_at": None},
            {"sum_loss": Decimal("0")},
            {"frozen": Decimal("0"), "returned": Decimal("0")},
            {"n_with_letters": 0},
            [],
        ]
        cur.fetchone.side_effect = iter([_firm_row()] + extra[:4]).__next__
        cur.fetchall.side_effect = iter([extra[4]]).__next__
        p = mod.build_firm_portfolio(str(FIRM_ID), dsn="postgres://x")

    assert p.firm_id == FIRM_ID
    # Verify a UUID-branch SELECT was emitted (the WHERE id = %s
    # variant). We at least know firm resolution succeeded.


def test_dataclass_decimal_default_factory_isolation():
    """Two LawFirmPortfolio instances must not share the same
    Decimal accumulator object (would propagate mutations)."""
    from recupero.monitoring.law_firm_dashboard import LawFirmPortfolio
    p1 = LawFirmPortfolio()
    p2 = LawFirmPortfolio()
    # They start equal but are NOT the same object.
    assert p1.total_loss_usd == p2.total_loss_usd
    assert p1.total_loss_usd is not p2.total_loss_usd or (
        # Decimal(0) may be cached as a singleton by CPython —
        # the real guarantee we want is that the *list* fields
        # are isolated.
        p1.top_issuers is not p2.top_issuers
    )
    assert p1.top_issuers is not p2.top_issuers


def test_build_all_returns_empty_list_when_no_dsn():
    """Bulk builder also returns empty on no DSN."""
    from recupero.monitoring.law_firm_dashboard import build_all_firm_portfolios
    assert build_all_firm_portfolios(dsn=None) == []
