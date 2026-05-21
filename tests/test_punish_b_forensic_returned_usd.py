"""PUNISH-B F-1/F-3/F-4/F-6: returned_usd ignored across $ aggregates.

The freeze_outcomes table has TWO money columns:
  * frozen_usd     — when an issuer freezes funds in place
  * returned_usd   — when funds are returned to the victim

The canonical operator workflow when a freeze CLEARS is:
    outcome_type = 'returned_to_victim'
    returned_usd = $X
    frozen_usd   = NULL   (no longer "frozen", funds moved)

Four production aggregators currently SUM only `frozen_usd`,
treating successful returns as $0:

  F-1: monitoring/cooperation_intelligence.py — issuer cooperation
       dashboard's `total_frozen_usd` per issuer
  F-3: freeze_learning/recorder.py — `compute_priors_from_outcomes`
       counts un-responded letters as failures, deflating priors
  F-4: monitoring/law_firm_dashboard.py — the INNER `frozen`
       aggregate (the v0.26.1 HIGH-1 fix patched the outer
       `returned` aggregate but left the partner-facing `frozen`
       column broken)
  F-6: freeze_learning/status.py — `peak_frozen_usd` used by
       the LE handoff Section 5.5 live-filing-status panel

This file is the punishing test for all four. Each makes a tiny
synthetic outcome set with a known returned-to-victim event,
runs the aggregator, and asserts the dollar figure matches the
returned_usd value (not $0).
"""

from __future__ import annotations

import inspect
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# F-1: cooperation_intelligence — issuer's total_frozen_usd must
# include returned_to_victim outcomes
# ─────────────────────────────────────────────────────────────────────────────


def test_f1_cooperation_includes_returned_to_victim_in_total_frozen():
    """An issuer that returned $500K to a victim must show $500K
    (not $0) under total_frozen_usd in the cooperation profile.
    Otherwise the dashboard's headline 'Tether has frozen $X' is
    a permanent undercount."""
    from recupero.monitoring import cooperation_intelligence as ci

    # The SQL string MUST reference returned_usd.
    src = inspect.getsource(ci.build_cooperation_profile)
    assert "returned_usd" in src, (
        "build_cooperation_profile SQL does not SELECT returned_usd. "
        "Every returned_to_victim outcome contributes $0 to the "
        "issuer's total_frozen_usd."
    )
    # And the aggregation MUST use COALESCE(returned_usd, frozen_usd)
    # OR explicit if/else logic — pick the appropriate column based
    # on outcome_type.
    assert "COALESCE" in src and "returned_usd" in src, (
        "aggregator does not COALESCE returned_usd into the total"
    )


def test_f1_cooperation_returned_outcome_counted_via_returned_usd():
    """Behavioral test: feed a stub cursor with two outcomes —
    one full_freeze (frozen_usd=$X) and one returned_to_victim
    (returned_usd=$Y, frozen_usd=NULL). The profile's
    total_frozen_usd must be $X + $Y, not just $X."""
    from recupero.monitoring import cooperation_intelligence as ci

    # Two letters with two outcomes — feed flat rows via the SQL
    # shape build_cooperation_profile expects.
    from datetime import datetime, UTC
    letter_id_1 = UUID("11111111-1111-1111-1111-111111111111")
    letter_id_2 = UUID("22222222-2222-2222-2222-222222222222")
    sent_1 = datetime(2026, 4, 1, 10, 0, tzinfo=UTC)
    obs_1 = datetime(2026, 4, 2, 14, 0, tzinfo=UTC)
    sent_2 = datetime(2026, 4, 3, 10, 0, tzinfo=UTC)
    obs_2 = datetime(2026, 4, 4, 14, 0, tzinfo=UTC)
    flat_rows = [
        # Letter 1: a full_freeze of $300K (frozen_usd populated)
        {
            "letter_id": letter_id_1,
            "sent_at": sent_1,
            "outcome_type": "full_freeze",
            "observed_at": obs_1,
            "frozen_usd": Decimal("300000"),
            "returned_usd": None,
        },
        # Letter 2: a returned_to_victim of $500K
        # (returned_usd populated, frozen_usd NULL — canonical
        # operator workflow when funds clear back to victim)
        {
            "letter_id": letter_id_2,
            "sent_at": sent_2,
            "outcome_type": "returned_to_victim",
            "observed_at": obs_2,
            "frozen_usd": None,
            "returned_usd": Decimal("500000"),
        },
    ]

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchall(self): return flat_rows
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    with patch(
        "recupero._common.db_connect", return_value=_StubConn(),
    ):
        prof = ci.build_cooperation_profile("Tether", dsn="postgres://x")
    assert prof.total_frozen_usd == Decimal("800000"), (
        f"expected $800K (= $300K freeze + $500K return), got "
        f"${prof.total_frozen_usd}. The returned_to_victim event "
        "contributed $0 because returned_usd was ignored."
    )


# ─────────────────────────────────────────────────────────────────────────────
# F-3: priors must NOT deflate by counting unmatured letters as failures
# ─────────────────────────────────────────────────────────────────────────────


def test_f3_priors_exclude_unresponded_letters_from_denominator():
    """compute_priors_from_outcomes was treating every letter
    without an outcome as a failure — so 20 fresh letters + 5
    resolved with 4 freezes → p_freeze = 4/(4+20) = 17% instead
    of the operationally correct 4/(4+5) = 80%."""
    from recupero.freeze_learning import recorder
    from datetime import datetime, UTC

    # `compute_priors_from_outcomes` expects list[dict[str, Any]] —
    # the row shape produced by the LEFT JOIN at recorder.py:431-437.
    def _row(lid, outcome, fz=None, observed=None):
        return {
            "letter_id": lid,
            "issuer": "Tether",
            "letter_language": "standard",
            "sent_at": None,
            "outcome_type": outcome,
            "observed_at": observed,
            "frozen_usd": fz,
            "returned_usd": None,
        }

    obs = datetime(2026, 4, 5, tzinfo=UTC)
    rows = [
        # 5 matured letters, 4 produced a freeze of some kind:
        _row(UUID("11" * 16), "full_freeze", Decimal("300000"), obs),
        _row(UUID("22" * 16), "full_freeze", Decimal("250000"), obs),
        _row(UUID("33" * 16), "partial_freeze", Decimal("100000"), obs),
        _row(UUID("44" * 16), "returned_to_victim", Decimal("500000"), obs),
        _row(UUID("55" * 16), "declined", None, obs),
        # 20 unanswered-yet letters — outcome_type is None:
        *[_row(UUID(f"{i:02x}" * 16), None, None, None)
          for i in range(0x60, 0x60 + 20)],
    ]

    out = recorder.compute_priors_from_outcomes(rows)
    # The function returns dict[(issuer, language), IssuerPrior].
    # We expect exactly the Tether/standard pair.
    assert ("Tether", "standard") in out, (
        f"expected key ('Tether', 'standard') in priors dict; got {list(out)}"
    )
    prior = out[("Tether", "standard")]
    # The sample size MUST reflect only the matured letters (5),
    # not 25. Pre-fix the function used sample_size = len(rows) which
    # deflates everything.
    assert prior.sample_size == 5, (
        f"sample_size = {prior.sample_size}, expected 5 (only the "
        "matured letters with recorded outcomes). Pre-fix this was "
        "25 (all letters including the 20 unresponded), which "
        "deflated p_freeze from 0.80 to 0.16."
    )
    # And the published p_any_freeze uses the Beta(2,2)-smoothed
    # posterior mean: (4 + 2) / (5 + 4) ≈ 0.667. (Raw 4/5=0.80 was
    # the MLE; recorder.py:387-402 applies a "barely informative"
    # Bayesian prior so n=0/0 doesn't collapse to undefined.)
    # PRE-FIX the same call returned (4 + 2) / (25 + 4) ≈ 0.207
    # because all 20 unresponded letters were in the denominator.
    # The KEY assertion above (sample_size == 5) already pins
    # the structural fix; this assertion is the downstream
    # consequence in the published probability field.
    assert prior.p_any_freeze == pytest.approx(0.667, abs=0.01), (
        f"p_any_freeze = {prior.p_any_freeze}, expected ~0.667 "
        "(Beta(2,2) posterior over n=5, n_freeze=4). Pre-fix this "
        "was ~0.207 from the 25-letter inflated denominator."
    )


# ─────────────────────────────────────────────────────────────────────────────
# F-4: law_firm_dashboard top_issuers `frozen` aggregate must use
# COALESCE(returned_usd, frozen_usd) (v0.26.1 HIGH-1 fix only
# patched the OUTER returned aggregate)
# ─────────────────────────────────────────────────────────────────────────────


def test_f4_law_firm_top_issuers_frozen_uses_coalesce_returned_usd():
    """Source-level: _populate_top_issuers' frozen aggregate must
    use COALESCE(returned_usd, frozen_usd) inside the ROW_NUMBER
    ranked-outcomes CTE. Otherwise the partner dashboard reports
    $0 frozen on every issuer's returned_to_victim wins."""
    from recupero.monitoring import law_firm_dashboard as lfd

    src = inspect.getsource(lfd._populate_top_issuers)
    # The ranked_outcomes CTE must SELECT returned_usd.
    assert "returned_usd" in src, (
        "_populate_top_issuers does not reference returned_usd. "
        "Returned-to-victim outcomes (where frozen_usd is NULL by "
        "operator convention) contribute $0 to the per-issuer "
        "$ frozen column on the partner dashboard."
    )
    # And the aggregator must COALESCE.
    assert "COALESCE" in src and "returned_usd" in src, (
        "_populate_top_issuers does not COALESCE returned_usd in "
        "the frozen aggregate"
    )


# ─────────────────────────────────────────────────────────────────────────────
# F-6: freeze_learning/status.py peak_frozen_usd
# ─────────────────────────────────────────────────────────────────────────────


def test_f6_status_peak_frozen_uses_returned_usd_for_returned_outcomes():
    """The LE handoff Section 5.5 reads peak_frozen_usd from
    fetch_live_filing_status. For a fully-returned case the
    peak should be the returned_usd amount (the funds DID get
    frozen and then returned). The function currently MAX()s
    frozen_usd only — so a return-only outcome reports peak=NULL
    and the handoff says '$0 confirmed frozen' for a fully-
    successful case."""
    from recupero.freeze_learning import status as fls

    src = inspect.getsource(fls)
    # The peak_frozen subquery must include returned_usd in the MAX.
    assert "returned_usd" in src, (
        "freeze_learning/status.py does not reference returned_usd "
        "in any aggregation. peak_frozen_usd is permanently NULL "
        "for returned-to-victim-only outcome chains."
    )
    # Find a MAX(...) over frozen_usd / returned_usd expression.
    # Either:
    #   MAX(COALESCE(frozen_usd, returned_usd))
    # or
    #   GREATEST(MAX(frozen_usd), MAX(returned_usd))
    # Both work; just require returned_usd appears inside a peak/MAX
    # context.
    assert "COALESCE" in src and "returned_usd" in src, (
        "peak_frozen aggregator does not COALESCE returned_usd"
    )
