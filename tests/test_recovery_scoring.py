"""Tests for v0.14.1 recovery probability scoring + cost model."""

from __future__ import annotations

from decimal import Decimal

from recupero.recovery.scorer import (
    score_recovery,
)


def _brief(
    *,
    total_loss: str = "$100,000",
    freezable: list[dict] | None = None,
    unrecoverable: list[dict] | None = None,
    jurisdiction: str = "USA (California)",
    cross_chain_handoffs: list | None = None,
    dex_swaps: list | None = None,
) -> dict:
    return {
        "TOTAL_LOSS_USD": total_loss,
        "FREEZABLE": freezable or [],
        "UNRECOVERABLE": unrecoverable or [],
        "VICTIM_JURISDICTION": jurisdiction,
        "CROSS_CHAIN_HANDOFFS": cross_chain_handoffs or [],
        "DEX_SWAPS": dex_swaps or [],
    }


# ---- Recommendation thresholds ---- #


def test_no_freezable_recommends_reject() -> None:
    """Case with $0 freezable → reject (we have nothing to recover)."""
    brief = _brief(total_loss="$50,000")
    est = score_recovery(brief)
    assert est.recommendation == "reject"
    assert est.expected_net_to_victim_usd <= Decimal("0")


def test_large_high_confidence_freezable_recommends_engagement() -> None:
    """$3M freezable at Tether (P≈0.73) → expected net well above
    $25K threshold → recommend."""
    brief = _brief(
        total_loss="$3,200,000",
        freezable=[
            {
                "issuer": "Tether",
                "total_usd": "$3,000,000",
                "freeze_capability": "HIGH",
            },
        ],
    )
    est = score_recovery(brief)
    assert est.recommendation == "recommend"
    assert est.expected_recovered_usd > Decimal("1_000_000")


def test_modest_freezable_recommends_caveat() -> None:
    """$50K freezable at Tether → expected ~$36K freezable → net
    after fees in the $5K-$25K range → caveat."""
    brief = _brief(
        total_loss="$60,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$50,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    # Expected: net is positive but below the recommend threshold.
    assert est.recommendation in ("caveat", "recommend")
    assert est.expected_net_to_victim_usd > Decimal("0")


def test_dai_only_recommends_reject() -> None:
    """DAI is freeze_capability='no' → expected freezable = 0 →
    reject."""
    brief = _brief(
        total_loss="$200,000",
        freezable=[
            {"issuer": "Sky Protocol", "total_usd": "$200,000",
             "freeze_capability": "no"},
        ],
    )
    est = score_recovery(brief)
    assert est.recommendation == "reject"


# ---- Issuer-specific priors ---- #


def test_circle_prior_is_higher_than_tether() -> None:
    """Circle's freeze prior (0.91) > Tether's (0.73). A case with
    the same USD at Circle should produce a higher expected
    recovery than at Tether."""
    brief_circle = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Circle", "total_usd": "$100,000",
             "freeze_capability": "yes"},
        ],
    )
    brief_tether = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "yes"},
        ],
    )
    est_circle = score_recovery(brief_circle)
    est_tether = score_recovery(brief_tether)
    assert est_circle.expected_recovered_usd > est_tether.expected_recovered_usd


def test_unknown_issuer_uses_default_prior() -> None:
    """An issuer not in the lookup table gets the conservative
    default (0.30)."""
    brief = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "WeirdNovelIssuer", "total_usd": "$100,000",
             "freeze_capability": "yes"},  # 'yes' upgrades to >=0.85
        ],
    )
    est = score_recovery(brief)
    # 'yes' override gives 0.85 even for unknown issuers.
    assert est.expected_recovered_usd >= Decimal("80_000")


def test_freeze_capability_no_overrides_issuer_prior() -> None:
    """Even Tether (prior 0.73), if capability='no' → recovery=0."""
    brief = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "no"},
        ],
    )
    est = score_recovery(brief)
    assert est.expected_recovered_usd == Decimal("0")


# ---- Jurisdiction ---- #


def test_usa_jurisdiction_baseline_recovery() -> None:
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
        jurisdiction="USA",
    )
    est = score_recovery(brief)
    assert est.expected_recovered_usd > Decimal("700_000")  # 0.85 prior, no friction


def test_russia_jurisdiction_severe_discount() -> None:
    """Russian victims face severe recovery friction
    (jurisdiction mult ~0.15)."""
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
        jurisdiction="Russia",
    )
    est = score_recovery(brief)
    assert est.expected_recovered_usd < Decimal("200_000")
    # Driver records the jurisdiction penalty.
    assert any(d.factor == "jurisdiction" and d.direction == "negative"
               for d in est.drivers)


def test_unknown_jurisdiction_uses_default_discount() -> None:
    brief = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "yes"},
        ],
        jurisdiction="",
    )
    est = score_recovery(brief)
    # Unknown jurisdiction → 0.7 multiplier → discount applied.
    assert est.expected_recovered_usd < Decimal("80_000")


# ---- Trace complexity ---- #


def test_multiple_bridge_hops_add_friction() -> None:
    """3 cross-chain handoffs → ~15% friction multiplier."""
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
        cross_chain_handoffs=[{"id": 1}, {"id": 2}, {"id": 3}],
    )
    est = score_recovery(brief)
    # Expect trace_complexity driver fires.
    assert any(d.factor == "trace_complexity" and d.direction == "negative"
               for d in est.drivers)


def test_concentration_positive_driver() -> None:
    """80%+ of loss at one freeze target → positive concentration
    driver."""
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$900,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    assert any(d.factor == "concentration" and d.direction == "positive"
               for d in est.drivers)


def test_dispersed_funds_negative_driver() -> None:
    """Loss spread across 4+ small targets → negative concentration."""
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$50,000",
             "freeze_capability": "yes"} for _ in range(4)
        ] + [
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "yes"},  # 5th, 10% share
        ],
    )
    est = score_recovery(brief)
    drivers_dispersed = [
        d for d in est.drivers
        if d.factor == "concentration" and d.direction == "negative"
    ]
    assert len(drivers_dispersed) > 0


# ---- Confidence interval ---- #


def test_confidence_interval_brackets_expected() -> None:
    """The 95% CI [low, high] must contain expected_recovered."""
    brief = _brief(
        total_loss="$500,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$500,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    assert est.expected_recovered_low_usd <= est.expected_recovered_usd
    assert est.expected_recovered_usd <= est.expected_recovered_high_usd


def test_zero_recovery_zero_ci() -> None:
    """If expected = 0, the CI band is also [0, 0]."""
    brief = _brief(total_loss="$50,000")
    est = score_recovery(brief)
    assert est.expected_recovered_low_usd == Decimal("0")
    assert est.expected_recovered_high_usd == Decimal("0")


# ---- Net to victim ---- #


def test_net_to_victim_subtracts_fees() -> None:
    """Net = expected_recovered - Recupero revenue. Should be less."""
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$1,000,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    assert est.expected_net_to_victim_usd < est.expected_recovered_usd
    # The gap should be approximately the revenue.
    diff = est.expected_recovered_usd - est.expected_net_to_victim_usd
    assert diff > Decimal("100_000")  # 15% contingency + $10K engagement + $499


# ---- Headline summary ---- #


def test_headline_includes_recommendation_and_top_target() -> None:
    brief = _brief(
        total_loss="$3,000,000",
        freezable=[
            {"issuer": "Maple Finance", "total_usd": "$3,000,000",
             "freeze_capability": "limited"},
        ],
    )
    est = score_recovery(brief)
    assert "Maple Finance" in est.headline_summary
    assert any(
        word in est.headline_summary
        for word in ("RECOMMEND", "CAVEAT", "DISCOURAGE", "REJECT")
    )


# ---- to_json_safe ---- #


def test_to_json_safe_serializes_decimals_as_strings() -> None:
    brief = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$100,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    d = est.to_json_safe()
    # Decimals get formatted as $X.XX strings.
    assert d["expected_recovered_usd"].startswith("$")
    assert d["expected_net_to_victim_usd"].startswith("$")
    # JSON-serializable.
    import json
    json.dumps(d)


# ---- Edge cases ---- #


def test_empty_brief_returns_reject() -> None:
    """Brief with nothing in it → reject (no recoverable target)."""
    est = score_recovery({})
    assert est.recommendation == "reject"
    assert est.expected_recovered_usd == Decimal("0")


def test_malformed_freezable_entry_skipped_not_crash() -> None:
    """A FREEZABLE entry without usd value should be skipped
    silently, not crash."""
    brief = _brief(
        total_loss="$100,000",
        freezable=[
            {"issuer": "Broken"},  # no total_usd
            {"issuer": "Tether", "total_usd": "$50,000",
             "freeze_capability": "yes"},
        ],
    )
    est = score_recovery(brief)
    # The valid Tether entry still contributes.
    assert est.expected_recovered_usd > Decimal("0")


# ---- v0.32.1 financial-audit: table ↔ headline ↔ CI reconciliation ---- #
#
# These lock the CRITICAL + HIGH fixes from the v0.32.1 audit cycle:
#   * friction (bridge/DEX hops) must fold into the SINGLE multiplier
#     applied uniformly to the headline, the per-issuer rows, AND the CI
#     band — pre-fix it hit only the scalar headline, so the LE Section
#     5.4 table over-summed the headline by up to ~43% on any bridged case
#     (re-opening the v0.22.1-C1 "table doesn't sum to headline" defect);
#   * the headline / CI / rows can never promise more than total_loss.
# Tolerance is $0.10 — the rows are cent-rounded (and re-rounded after the
# friction + clamp rescales), so a few cents of drift is expected; a real
# regression is thousands of dollars off, not pennies.

_RECONCILE_TOL = Decimal("0.10")


def _sum_rows(est) -> Decimal:
    return sum((r.expected_recovered_usd for r in est.per_issuer), Decimal("0"))


def test_per_issuer_rows_sum_to_headline_with_friction() -> None:
    """CRITICAL: multi-issuer case WITH bridge + DEX hops — the
    per-issuer table must still reconcile to the friction-discounted
    headline (pre-fix the rows carried jur×sanctions but not friction)."""
    brief = _brief(
        total_loss="$5,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$2,000,000", "freeze_capability": "HIGH"},
            {"issuer": "Circle", "total_usd": "$1,500,000", "freeze_capability": "HIGH"},
            {"issuer": "Binance", "total_usd": "$1,000,000", "freeze_capability": "yes"},
        ],
        cross_chain_handoffs=[{}, {}, {}],  # 3 bridge hops
        dex_swaps=[{}, {}],                  # 2 DEX swaps → friction = 0.25
    )
    est = score_recovery(brief, auto_load_priors=False)
    assert est.per_issuer, "expected per-issuer rows"
    drift = abs(_sum_rows(est) - est.expected_recovered_usd)
    assert drift <= _RECONCILE_TOL, (
        f"per-issuer table (${_sum_rows(est)}) must reconcile to headline "
        f"(${est.expected_recovered_usd}); drift ${drift}"
    )


def test_friction_reduces_expected_recovery() -> None:
    """The friction multiplier must actually bite: an identical case
    WITH six bridge hops (30% friction, the cap) recovers strictly less
    than one WITHOUT, and the rows still reconcile to the headline."""
    base_freezable = [
        {"issuer": "Tether", "total_usd": "$3,000,000", "freeze_capability": "HIGH"},
    ]
    clean = score_recovery(
        _brief(total_loss="$10,000,000", freezable=base_freezable),
        auto_load_priors=False,
    )
    bridged = score_recovery(
        _brief(
            total_loss="$10,000,000",
            freezable=base_freezable,
            cross_chain_handoffs=[{}, {}, {}, {}, {}, {}],  # 6 hops → 30% cap
        ),
        auto_load_priors=False,
    )
    assert bridged.expected_recovered_usd < clean.expected_recovered_usd
    drift = abs(_sum_rows(bridged) - bridged.expected_recovered_usd)
    assert drift <= _RECONCILE_TOL


def test_ci_band_reconciles_with_friction() -> None:
    """CRITICAL: the CI band is computed with the SAME friction-inclusive
    multiplier as the headline (was friction-free → band over-stated on
    bridged cases). Lock: low ≤ headline ≤ high."""
    brief = _brief(
        total_loss="$10,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$3,000,000", "freeze_capability": "HIGH"},
        ],
        cross_chain_handoffs=[{}, {}, {}, {}],  # 4 hops → 20% friction
    )
    est = score_recovery(brief, auto_load_priors=False)
    assert est.expected_recovered_low_usd <= est.expected_recovered_usd
    assert est.expected_recovered_usd <= est.expected_recovered_high_usd


def test_expected_recovery_never_exceeds_total_loss() -> None:
    """HIGH: on a pooled-victim case the summed FREEZABLE can exceed THIS
    victim's loss; the headline, BOTH CI bounds, and the per-issuer rows
    must all be clamped to total_loss — and the rows must still sum to the
    clamped headline."""
    loss = Decimal("1000000")
    brief = _brief(
        total_loss="$1,000,000",
        freezable=[
            {"issuer": "Tether", "total_usd": "$5,000,000", "freeze_capability": "HIGH"},
            {"issuer": "Circle", "total_usd": "$3,000,000", "freeze_capability": "HIGH"},
        ],
    )
    est = score_recovery(brief, auto_load_priors=False)
    assert est.expected_recovered_usd <= loss, (
        f"headline ${est.expected_recovered_usd} must not exceed loss ${loss}"
    )
    assert est.expected_recovered_high_usd <= loss
    assert est.expected_recovered_low_usd <= loss
    drift = abs(_sum_rows(est) - est.expected_recovered_usd)
    assert drift <= _RECONCILE_TOL, (
        f"clamped per-issuer rows (${_sum_rows(est)}) must still sum to the "
        f"clamped headline (${est.expected_recovered_usd}); drift ${drift}"
    )
