"""Tests for v0.14.2 freeze-success learning loop.

DB I/O is skipped; tests focus on the pure aggregation logic
(compute_priors_from_outcomes) which is what actually decides what
the recovery scorer reads. Plus integration test verifying the
scorer prefers learned priors when supplied.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from recupero.freeze_learning.recorder import (
    IssuerPrior,
    compute_priors_from_outcomes,
)
from recupero.recovery.scorer import score_recovery


def _outcome_row(
    *,
    letter_id=None,
    issuer="Tether",
    letter_language="standard",
    sent_at=None,
    outcome_type="full_freeze",
    observed_at=None,
):
    sent_at = sent_at or datetime(2026, 1, 1, tzinfo=timezone.utc)
    observed_at = observed_at or sent_at + timedelta(hours=12)
    return {
        "letter_id": letter_id or uuid4(),
        "issuer": issuer,
        "letter_language": letter_language,
        "sent_at": sent_at,
        "outcome_type": outcome_type,
        "observed_at": observed_at,
        "frozen_usd": None,
        "returned_usd": None,
    }


# ---- compute_priors_from_outcomes ---- #


def test_single_letter_with_full_freeze_outcome() -> None:
    """v0.17.1 (QUANT-1): with the Beta(2, 2) prior, one full_freeze
    observation produces posterior mean (2 + 1) / (2 + 2 + 1) = 0.6,
    NOT the pre-v0.17.1 frequency MLE of 1.0. The Beta posterior
    refuses to overcommit on a single data point — which is exactly
    why we adopted it (MLE collapses to 0.0 / 1.0 on small samples
    and over-promises in legal documents)."""
    rows = [_outcome_row(outcome_type="full_freeze")]
    priors = compute_priors_from_outcomes(rows)
    assert ("Tether", "standard") in priors
    p = priors[("Tether", "standard")]
    assert p.sample_size == 1
    # Beta(2+1, 2+0) posterior mean = 3/5 = 0.6
    assert p.p_any_freeze == pytest.approx(0.6, abs=0.001)
    assert p.p_full_freeze == pytest.approx(0.6, abs=0.001)
    # No win observation → Beta(2+0, 2+1) = 2/5 = 0.4
    assert p.p_returned_to_victim == pytest.approx(0.4, abs=0.001)


def test_declined_outcome_counts_as_no_freeze() -> None:
    """v0.17.1: Beta(2, 2) posterior with 0 wins, 1 loss → 2/5 = 0.4
    (NOT 0.0). The prior 0.0 was overconfident — it implied "this
    issuer will NEVER freeze" from a single data point."""
    rows = [_outcome_row(outcome_type="declined")]
    priors = compute_priors_from_outcomes(rows)
    p = priors[("Tether", "standard")]
    assert p.p_any_freeze == pytest.approx(0.4, abs=0.001)


def test_returned_to_victim_is_win() -> None:
    """v0.17.1: Beta posterior produces 0.6 for both fields with n=1."""
    rows = [_outcome_row(outcome_type="returned_to_victim")]
    priors = compute_priors_from_outcomes(rows)
    p = priors[("Tether", "standard")]
    assert p.p_any_freeze == pytest.approx(0.6, abs=0.001)
    assert p.p_returned_to_victim == pytest.approx(0.6, abs=0.001)


def test_strongest_outcome_per_letter_wins() -> None:
    """A letter that first gets 'acknowledged' then 'full_freeze' →
    counts as full_freeze (the stronger outcome).

    v0.17.1: with Beta(2, 2) prior + 1 win, posterior = 3/5 = 0.6.
    """
    letter_id = uuid4()
    rows = [
        _outcome_row(letter_id=letter_id, outcome_type="acknowledged"),
        _outcome_row(letter_id=letter_id, outcome_type="full_freeze"),
    ]
    priors = compute_priors_from_outcomes(rows)
    p = priors[("Tether", "standard")]
    assert p.sample_size == 1
    assert p.p_any_freeze == pytest.approx(0.6, abs=0.001)
    assert p.p_full_freeze == pytest.approx(0.6, abs=0.001)


def test_multiple_letters_aggregate() -> None:
    """5 letters: 3 frozen, 2 declined.

    v0.17.1: Beta(2 + 3, 2 + 2) posterior = 5/9 ≈ 0.556 (vs MLE 0.6).
    The prior pulls the estimate slightly toward 0.5; data dominates
    at this sample size but the floor/ceiling don't collapse.
    """
    rows = []
    for _ in range(3):
        rows.append(_outcome_row(outcome_type="full_freeze"))
    for _ in range(2):
        rows.append(_outcome_row(outcome_type="declined"))
    priors = compute_priors_from_outcomes(rows)
    p = priors[("Tether", "standard")]
    assert p.sample_size == 5
    # Beta(5, 4) posterior mean = 5/9 ≈ 0.5556
    assert p.p_any_freeze == pytest.approx(5 / 9, abs=0.001)


def test_partial_freeze_counts_as_freeze() -> None:
    """partial_freeze → counts as any_freeze=true.

    v0.17.1: Beta(2+1, 2+0) posterior = 0.6 (NOT 1.0). And since
    it's partial (not full), p_full_freeze gets 0 wins → 0.4.
    """
    rows = [_outcome_row(outcome_type="partial_freeze")]
    p = compute_priors_from_outcomes(rows)[("Tether", "standard")]
    assert p.p_any_freeze == pytest.approx(0.6, abs=0.001)
    assert p.p_full_freeze == pytest.approx(0.4, abs=0.001)  # not full
    assert p.p_returned_to_victim == pytest.approx(0.4, abs=0.001)


def test_per_issuer_buckets_separate() -> None:
    """Tether and Circle are aggregated separately."""
    rows = [
        _outcome_row(issuer="Tether", outcome_type="full_freeze"),
        _outcome_row(issuer="Circle", outcome_type="declined"),
    ]
    priors = compute_priors_from_outcomes(rows)
    # Tether: 1 win, 0 loss → Beta(3, 2) = 0.6
    # Circle: 0 win, 1 loss → Beta(2, 3) = 0.4
    assert priors[("Tether", "standard")].p_any_freeze == pytest.approx(0.6, abs=0.001)
    assert priors[("Circle", "standard")].p_any_freeze == pytest.approx(0.4, abs=0.001)


def test_per_letter_language_buckets_separate() -> None:
    """'standard' and 'le_backed' letters at Tether get separate
    priors — this is how the operator learns 'does FBI backing
    materially help?'.

    v0.17.1: Beta posterior means 0.4 / 0.6 instead of 0.0 / 1.0.
    """
    rows = [
        _outcome_row(
            issuer="Tether", letter_language="standard",
            outcome_type="declined",
        ),
        _outcome_row(
            issuer="Tether", letter_language="le_backed",
            outcome_type="full_freeze",
        ),
    ]
    priors = compute_priors_from_outcomes(rows)
    assert priors[("Tether", "standard")].p_any_freeze == pytest.approx(0.4, abs=0.001)
    assert priors[("Tether", "le_backed")].p_any_freeze == pytest.approx(0.6, abs=0.001)


def test_beta_posterior_mean_helper_known_values() -> None:
    """Sanity-check the Beta-Binomial conjugate math.

    Beta(α+wins, β+losses) posterior mean = (α+wins) / (α+β+n) where
    n = wins + losses. With α=β=2:
      * 0 wins, 0 trials  → prior mean = 2/4 = 0.5
      * 0 wins, 1 trial   → Beta(2, 3), mean = 2/5 = 0.4
      * 1 win, 1 trial    → Beta(3, 2), mean = 3/5 = 0.6
      * 10 wins, 10 trials (ALL wins) → Beta(12, 2), mean = 12/14 ≈ 0.857
        — the prior pulls back from 1.0 toward 0.5 with weight 4, so
        even "perfect track record" yields 86%, not overconfident 100%.
      * 5 wins, 10 trials (BALANCED) → Beta(7, 7), mean = 0.5
      * 19 wins, 20 trials → Beta(21, 3), mean = 21/24 ≈ 0.875
        (NOT MLE 0.95 — the prior still has visible weight at this n).
    """
    from recupero.freeze_learning.recorder import _beta_posterior_mean
    assert _beta_posterior_mean(0, 0) == pytest.approx(0.5, abs=0.001)
    assert _beta_posterior_mean(0, 1) == pytest.approx(0.4, abs=0.001)
    assert _beta_posterior_mean(1, 1) == pytest.approx(0.6, abs=0.001)
    assert _beta_posterior_mean(10, 10) == pytest.approx(12 / 14, abs=0.001)
    assert _beta_posterior_mean(5, 10) == pytest.approx(0.5, abs=0.001)
    assert _beta_posterior_mean(19, 20) == pytest.approx(21 / 24, abs=0.001)
    # Edge case: degenerate input (more wins than trials) falls back
    # to the prior mean instead of exploding.
    assert _beta_posterior_mean(5, 2) == pytest.approx(0.5, abs=0.001)
    assert _beta_posterior_mean(-1, 5) == pytest.approx(0.5, abs=0.001)


def test_beta_credible_interval_bounds_sanity() -> None:
    """Beta credible interval must satisfy low <= mean <= high
    and the bounds must lie in [0, 1]."""
    from recupero.freeze_learning.recorder import (
        _beta_posterior_mean, beta_credible_interval,
    )
    for wins, n in [(0, 1), (1, 1), (5, 10), (50, 100), (95, 100)]:
        low, high = beta_credible_interval(wins, n, level=0.90)
        mean = _beta_posterior_mean(wins, n)
        assert 0.0 <= low <= mean <= high <= 1.0
        # Wider interval for smaller n
        assert (high - low) > 0



def test_response_time_computed_from_timestamps() -> None:
    """avg_response_hours = mean of (observed_at - sent_at) over
    non-silence outcomes."""
    sent = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [
        _outcome_row(
            sent_at=sent,
            observed_at=sent + timedelta(hours=12),
            outcome_type="full_freeze",
        ),
        _outcome_row(
            sent_at=sent,
            observed_at=sent + timedelta(hours=24),
            outcome_type="full_freeze",
        ),
    ]
    p = compute_priors_from_outcomes(rows)[("Tether", "standard")]
    assert p.avg_response_hours == 18.0


def test_silence_outcomes_excluded_from_response_time() -> None:
    """silence_30d / silence_90d outcomes shouldn't pollute the
    avg-response-hours metric."""
    sent = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [
        _outcome_row(
            sent_at=sent,
            observed_at=sent + timedelta(hours=12),
            outcome_type="full_freeze",
        ),
        _outcome_row(
            sent_at=sent,
            observed_at=sent + timedelta(days=30),
            outcome_type="silence_30d",
        ),
    ]
    p = compute_priors_from_outcomes(rows)[("Tether", "standard")]
    # Only the 12h full_freeze counts; the silence is excluded.
    assert p.avg_response_hours == 12.0


def test_below_threshold_is_learned_false() -> None:
    """Below 20 samples → is_learned=False (scorer should fall back
    to heuristics)."""
    rows = [_outcome_row(outcome_type="full_freeze") for _ in range(10)]
    p = compute_priors_from_outcomes(rows)[("Tether", "standard")]
    assert p.is_learned is False


def test_above_threshold_is_learned_true() -> None:
    rows = [_outcome_row(outcome_type="full_freeze") for _ in range(25)]
    p = compute_priors_from_outcomes(rows)[("Tether", "standard")]
    assert p.is_learned is True
    assert p.sample_size == 25


def test_empty_outcomes_returns_empty_dict() -> None:
    assert compute_priors_from_outcomes([]) == {}


def test_outcome_without_letter_id_skipped() -> None:
    """Defensive: outcome row missing letter_id is skipped (likely
    a corrupted join result)."""
    rows = [
        _outcome_row(),
        {"letter_id": None, "outcome_type": "full_freeze",
         "issuer": "Tether", "letter_language": "standard"},
    ]
    priors = compute_priors_from_outcomes(rows)
    # Only the valid row was aggregated.
    assert priors[("Tether", "standard")].sample_size == 1


# ---- Integration: scorer uses learned priors when supplied ---- #


def test_scorer_uses_learned_prior_over_heuristic() -> None:
    """When a learned prior is supplied for an issuer, it overrides
    the hand-coded heuristic.

    Heuristic for Tether is 0.73. We supply a learned prior of 0.20.
    Expected recovery should reflect the lower learned rate."""
    learned = {
        "Tether": IssuerPrior(
            issuer="Tether",
            letter_language="standard",
            sample_size=50,
            p_any_freeze=0.20,
            p_full_freeze=0.15,
            p_returned_to_victim=0.10,
            avg_response_hours=72.0,
            median_response_hours=48.0,
            is_learned=True,
        ),
    }
    brief = {
        "TOTAL_LOSS_USD": "$1,000,000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
        "VICTIM_JURISDICTION": "USA",
    }
    est_with_learned = score_recovery(brief, learned_priors=learned)
    est_with_heuristic = score_recovery(brief)
    # Note: freeze_capability='yes' overrides BOTH priors to >=0.85.
    # So this specific test fixture won't show the learned prior
    # effect because the capability override wins. Use a case
    # without the capability override.
    brief_no_cap = {
        "TOTAL_LOSS_USD": "$1,000,000",
        "FREEZABLE": [
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "limited"},  # cap caps at 0.5
        ],
        "VICTIM_JURISDICTION": "USA",
    }
    est_with_learned = score_recovery(brief_no_cap, learned_priors=learned)
    est_with_heuristic = score_recovery(brief_no_cap)
    # learned=0.20, capability='limited' caps at 0.5 → prior stays 0.20
    # heuristic=0.73, capability='limited' caps at 0.5 → prior becomes 0.5
    # So learned recovery should be LOWER than heuristic.
    assert est_with_learned.expected_recovered_usd < est_with_heuristic.expected_recovered_usd


def test_scorer_falls_back_when_no_learned_prior() -> None:
    """Issuer not in learned_priors dict → fall back to heuristic."""
    learned = {
        "Circle": IssuerPrior(
            issuer="Circle", letter_language="standard", sample_size=50,
            p_any_freeze=0.95, p_full_freeze=0.90,
            p_returned_to_victim=0.85,
            avg_response_hours=8.0, median_response_hours=6.0,
            is_learned=True,
        ),
    }
    brief = {
        "TOTAL_LOSS_USD": "$100,000",
        "FREEZABLE": [
            # Tether NOT in learned_priors → heuristic applies.
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "limited"},
        ],
        "VICTIM_JURISDICTION": "USA",
    }
    # Should not raise; should produce a reasonable estimate.
    est = score_recovery(brief, learned_priors=learned)
    assert est.expected_recovered_usd > Decimal("0")
