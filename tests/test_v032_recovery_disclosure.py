"""v0.32 Tier-0 gap #2 — honest recovery-rate disclosure tests.

Covers:
  * Wilson 95% CI: known values + edge cases (n=0, k=0, k=n, small n)
  * compute_recovery_stats: industry baseline when DSN is None
  * compute_recovery_stats: industry baseline when sample < 30
  * compute_recovery_stats: OUR rate when sample >= 30
  * compute_recovery_stats: DB error degrades to industry baseline
  * Cache TTL behavior
  * /v1/intake GET — disclosure block renders in HTML
  * /v1/intake POST without acknowledged checkbox → 400
  * recovery_disclosures audit-write contract
  * close-case CLI requires --outcome
  * close-case CLI rejects invalid outcome
  * close-case CLI requires --recovered-usd for full_recovery
"""

from __future__ import annotations

import math
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from recupero.monitoring.recovery_rate import (
    INDUSTRY_BASELINE_LABEL,
    INDUSTRY_FULL_RECOVERY_RATE,
    MIN_SAMPLE_FOR_OUR_RATE,
    RecoveryStats,
    _clear_cache,
    _industry_baseline_stats,
    _our_data_stats,
    compute_recovery_stats,
    wilson_score_interval,
)

# ─────────────────────────────────────────────────────────────────────────────
# Wilson score interval
# ─────────────────────────────────────────────────────────────────────────────


def test_wilson_n_zero_returns_widest_interval():
    low, high = wilson_score_interval(0, 0)
    assert low == 0.0
    assert high == 1.0


def test_wilson_k_zero_lower_bound_is_zero():
    """When k=0, the Wilson lower bound is exactly 0; upper bound is
    strictly > 0 (the "rule of three" gives ~3.7/n at 95% for k=0)."""
    low, high = wilson_score_interval(0, 30, level=0.95)
    assert low == 0.0
    assert high > 0.0
    # Upper bound for k=0, n=30 at 95% should be roughly 0.10-0.13.
    assert 0.05 < high < 0.20


def test_wilson_k_equals_n_upper_bound_is_one():
    """When k=n, the Wilson upper bound is exactly 1; lower bound < 1."""
    low, high = wilson_score_interval(30, 30, level=0.95)
    assert high == 1.0
    assert low < 1.0
    assert 0.85 < low < 1.0


def test_wilson_known_value_50_of_100_at_95pct():
    """Wilson 95% CI for k=50, n=100 (p̂=0.5) is approximately
    (0.404, 0.596). Verify against this published value."""
    low, high = wilson_score_interval(50, 100, level=0.95)
    assert abs(low - 0.404) < 0.01
    assert abs(high - 0.596) < 0.01


def test_wilson_known_value_1_of_30_at_95pct():
    """Wilson 95% CI for k=1, n=30 — small sample. p̂ ≈ 0.033;
    Wilson interval roughly (0.006, 0.166)."""
    low, high = wilson_score_interval(1, 30, level=0.95)
    assert 0.0 < low < 0.02
    assert 0.10 < high < 0.20


def test_wilson_bounds_are_clamped_to_unit_interval():
    """Defense in depth: bounds must stay in [0, 1] for every input."""
    for n in (1, 2, 5, 10, 30, 100, 1000):
        for k in (0, n // 2, n):
            low, high = wilson_score_interval(k, n, level=0.95)
            assert 0.0 <= low <= 1.0, f"low out of range for k={k} n={n}: {low}"
            assert 0.0 <= high <= 1.0, f"high out of range for k={k} n={n}: {high}"
            assert low <= high


def test_wilson_rejects_k_greater_than_n():
    with pytest.raises(ValueError):
        wilson_score_interval(11, 10)


def test_wilson_rejects_negative_inputs():
    with pytest.raises(ValueError):
        wilson_score_interval(-1, 10)
    with pytest.raises(ValueError):
        wilson_score_interval(5, -1)


# ─────────────────────────────────────────────────────────────────────────────
# compute_recovery_stats — degraded paths
# ─────────────────────────────────────────────────────────────────────────────


def test_compute_stats_returns_industry_baseline_when_dsn_is_none():
    """None DSN → industry baseline, no DB call attempted."""
    _clear_cache()
    stats = compute_recovery_stats(dsn=None)
    assert isinstance(stats, RecoveryStats)
    assert stats.is_our_data is False
    assert stats.industry_baseline_used == INDUSTRY_BASELINE_LABEL
    assert stats.full_recovery_rate == INDUSTRY_FULL_RECOVERY_RATE
    assert stats.sample_size == 0


def test_compute_stats_returns_industry_baseline_when_dsn_empty():
    """Empty string DSN treated same as None."""
    _clear_cache()
    stats = compute_recovery_stats(dsn="")
    assert stats.is_our_data is False
    assert stats.full_recovery_rate == INDUSTRY_FULL_RECOVERY_RATE


def test_compute_stats_falls_back_on_db_error():
    """DB query raises → industry baseline returned, never raises."""
    _clear_cache()
    with patch(
        "recupero.monitoring.recovery_rate._query_recovery_stats",
        side_effect=RuntimeError("connection refused"),
    ):
        stats = compute_recovery_stats(dsn="postgres://fake/db")
    assert stats.is_our_data is False
    assert stats.full_recovery_rate == INDUSTRY_FULL_RECOVERY_RATE


# ─────────────────────────────────────────────────────────────────────────────
# compute_recovery_stats — our-data branch via the pure helper
# ─────────────────────────────────────────────────────────────────────────────


def test_our_data_stats_below_threshold_returns_industry_baseline():
    """Even when _query_recovery_stats finds real rows, if
    sample_size < MIN_SAMPLE_FOR_OUR_RATE the disclosure shows the
    industry baseline. The closed-case counts are still surfaced."""
    _clear_cache()

    # Mock the query path to return < 30 cases.
    def _fake_query(dsn: str) -> RecoveryStats:
        # Simulate 10 closed cases with 1 full recovery — well below threshold.
        return RecoveryStats(
            sample_size=10,
            n_full_recovery=1,
            n_partial_recovery=2,
            n_zero_recovery=7,
            full_recovery_rate=INDUSTRY_FULL_RECOVERY_RATE,
            full_recovery_rate_ci_low=INDUSTRY_FULL_RECOVERY_RATE,
            full_recovery_rate_ci_high=INDUSTRY_FULL_RECOVERY_RATE,
            is_our_data=False,
            industry_baseline_used=INDUSTRY_BASELINE_LABEL,
            median_recovery_usd=None,
            median_time_to_recovery_days=None,
        )

    with patch(
        "recupero.monitoring.recovery_rate._query_recovery_stats",
        side_effect=_fake_query,
    ):
        stats = compute_recovery_stats(dsn="postgres://fake/db")
    assert stats.sample_size == 10
    assert stats.is_our_data is False
    assert stats.industry_baseline_used == INDUSTRY_BASELINE_LABEL


def test_our_data_stats_above_threshold_uses_real_rate():
    """sample_size >= 30 → is_our_data=True + Wilson CI computed
    from the real numbers. NEVER inflates: if rate is 1%, show 1%."""
    _clear_cache()

    stats = _our_data_stats(
        sample_size=100,
        n_full=1,
        n_partial=5,
        n_zero=94,
        recovery_usd_amounts=[Decimal("50000")],
        time_to_recovery_days=[28],
    )
    assert stats.is_our_data is True
    assert stats.sample_size == 100
    assert stats.n_full_recovery == 1
    assert stats.full_recovery_rate == 0.01  # 1 / 100 — honest, not inflated
    # Wilson CI for k=1, n=100, 95%: roughly (0.002, 0.054).
    assert stats.full_recovery_rate_ci_low > 0
    assert stats.full_recovery_rate_ci_high < 0.10
    assert stats.median_recovery_usd == Decimal("50000")
    assert stats.median_time_to_recovery_days == 28


def test_our_data_stats_zero_recoveries_shows_zero():
    """0 recoveries in 50 closed cases → published rate is 0.0.
    The honesty contract demands we NEVER show better than reality."""
    stats = _our_data_stats(
        sample_size=50,
        n_full=0,
        n_partial=0,
        n_zero=50,
        recovery_usd_amounts=[],
        time_to_recovery_days=[],
    )
    assert stats.is_our_data is True
    assert stats.full_recovery_rate == 0.0
    assert stats.n_full_recovery == 0
    assert stats.full_recovery_rate_ci_low == 0.0
    # Upper bound > 0 (Wilson rule of three).
    assert stats.full_recovery_rate_ci_high > 0
    assert stats.median_recovery_usd is None


def test_our_data_stats_min_threshold_constant_is_30():
    """Lock the threshold value — changing this is a customer-facing
    contract change."""
    assert MIN_SAMPLE_FOR_OUR_RATE == 30


# ─────────────────────────────────────────────────────────────────────────────
# Cache behavior
# ─────────────────────────────────────────────────────────────────────────────


def test_cache_returns_same_object_within_ttl():
    """Two calls within 60s should hit the cache and return identical
    objects (the goal is to bound the per-request DB cost)."""
    _clear_cache()
    call_count = {"n": 0}

    def _fake_query(dsn: str) -> RecoveryStats:
        call_count["n"] += 1
        return _industry_baseline_stats()

    with patch(
        "recupero.monitoring.recovery_rate._query_recovery_stats",
        side_effect=_fake_query,
    ):
        compute_recovery_stats(dsn="postgres://cached")
        compute_recovery_stats(dsn="postgres://cached")
        compute_recovery_stats(dsn="postgres://cached")
    assert call_count["n"] == 1, (
        "expected 1 DB query for 3 calls within TTL"
    )


# ─────────────────────────────────────────────────────────────────────────────
# /v1/intake — GET disclosure renders + POST gate
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def intake_client(monkeypatch):
    """TestClient with Stripe + DSN env configured so the POST
    happy path can build the diagnostic Payment Link."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake")
    monkeypatch.setenv(
        "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
        "https://buy.stripe.com/test_diagnostic_link",
    )
    _clear_cache()
    # Reset the IP rate-limiter bucket so adjacent test files don't
    # blow our budget. The rl state is process-global module state in
    # recupero.api.app._intake_rl_state and persists across tests.
    try:
        from recupero.api import app as _api_app
        if hasattr(_api_app, "_intake_rl_state"):
            _api_app._intake_rl_state.clear()
    except Exception:  # noqa: BLE001
        pass
    # Patch the DB-touching helper so render is fast + deterministic.
    from recupero.monitoring import recovery_rate
    with patch.object(
        recovery_rate,
        "_query_recovery_stats",
        return_value=_industry_baseline_stats(),
    ):
        from recupero.api.app import app
        yield TestClient(app, follow_redirects=False)


def _good_post_form(**overrides) -> dict:
    form = {
        "client_name": "Jane Doe",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-05-01",
        "description": "Phishing site drained my wallet on May 1.",
        "country": "United States",
        "acknowledge_disclosure": "yes",
    }
    form.update(overrides)
    return form


def test_intake_get_renders_disclosure_block(intake_client):
    """GET /v1/intake includes the disclosure block + acknowledgment
    checkbox. The customer must NOT be able to reach checkout without
    seeing this."""
    resp = intake_client.get("/v1/intake")
    assert resp.status_code == 200
    body = resp.text
    # Disclosure block headline present.
    assert "Honest recovery-rate disclosure" in body or "disclosure" in body.lower()
    # The acknowledgment checkbox is present + required + named.
    assert 'name="acknowledge_disclosure"' in body
    assert "required" in body
    # The industry-baseline text shows up (we have no real data yet).
    assert "industry baseline" in body.lower() or "Chainalysis" in body
    assert "does" in body and "guarantee" in body.lower()


def test_intake_post_without_ack_returns_400(intake_client):
    """POST omitting acknowledge_disclosure must be rejected with
    400 and a clear error message — server-side validation is the
    legal hook; HTML5 `required` is only UX."""
    form = _good_post_form()
    form.pop("acknowledge_disclosure", None)
    resp = intake_client.post("/v1/intake", data=form)
    assert resp.status_code == 400
    body = resp.text
    # Error banner rendered.
    assert "error" in body.lower()
    assert "guarantee" in body.lower()


def test_intake_post_with_wrong_ack_value_returns_400(intake_client):
    """Submitting acknowledge_disclosure with any value other than
    'yes' is treated as not-acknowledged."""
    resp = intake_client.post(
        "/v1/intake",
        data=_good_post_form(acknowledge_disclosure="no"),
    )
    assert resp.status_code == 400


def test_intake_post_with_ack_proceeds_to_stripe(intake_client):
    """With the ack box ticked + valid form → 303 redirect to Stripe."""
    fake_id = UUID("44444444-4444-4444-4444-444444444444")
    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=fake_id,
    ):
        resp = intake_client.post("/v1/intake", data=_good_post_form())
    assert resp.status_code == 303
    location = resp.headers.get("location", "")
    assert location.startswith("https://buy.stripe.com/")


def test_intake_post_with_ack_writes_disclosure_row(intake_client):
    """When the customer affirmatively acknowledges, we log the
    audit row to recovery_disclosures. Best-effort — failure does
    NOT block the checkout flow, but a successful write is what we
    will produce in court if asked."""
    fake_id = UUID("55555555-5555-5555-5555-555555555555")
    calls: list = []

    def _capture_log(*, case_id, stats, dsn, acknowledged):
        calls.append({
            "case_id": case_id,
            "acknowledged": acknowledged,
            "rate": stats.full_recovery_rate,
        })
        return True

    with patch(
        "recupero.portal.intake.create_case_from_intake",
        return_value=fake_id,
    ), patch(
        "recupero.monitoring.recovery_rate.log_disclosure",
        side_effect=_capture_log,
    ):
        resp = intake_client.post("/v1/intake", data=_good_post_form())
    assert resp.status_code == 303
    assert len(calls) == 1
    assert calls[0]["case_id"] == str(fake_id)
    assert calls[0]["acknowledged"] is True


# ─────────────────────────────────────────────────────────────────────────────
# close-case CLI — argparse + outcome validation
# ─────────────────────────────────────────────────────────────────────────────


def test_close_case_cli_requires_outcome():
    """`recupero-ops close-case --case <id>` without --outcome fails
    at argparse with non-zero exit."""
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "recupero.ops.cli", "close-case",
         "--case", "00000000-0000-0000-0000-000000000001"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "outcome" in (result.stderr + result.stdout).lower()


def test_close_case_cli_rejects_invalid_outcome():
    """argparse's `choices=` rejects unknown outcomes."""
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "recupero.ops.cli", "close-case",
         "--case", "00000000-0000-0000-0000-000000000001",
         "--outcome", "miracle"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "invalid choice" in (result.stderr + result.stdout).lower() or \
           "miracle" in (result.stderr + result.stdout).lower()


def test_close_case_validation_layer_outcome_set_is_locked():
    """The CLI surface MUST be exactly these four outcomes; changing
    the set is a customer-facing contract change."""
    from recupero.ops.commands.close_case import VALID_CLI_OUTCOMES
    assert frozenset({
        "full_recovery", "partial_recovery", "no_recovery", "dropped",
    }) == VALID_CLI_OUTCOMES


def test_close_case_full_recovery_requires_positive_usd():
    """full_recovery without --recovered-usd > 0 must be rejected
    BEFORE any DB write. Without this gate, the recovery-rate
    aggregator silently skips the win (returned_usd IS NULL filter)."""
    from recupero.ops.commands.close_case import run
    rc = run(
        case_id=UUID("00000000-0000-0000-0000-000000000001"),
        outcome="full_recovery",
        recovered_usd_raw=None,
        note=None,
        dsn="postgres://fake",
    )
    assert rc == 1


def test_close_case_full_recovery_rejects_zero_usd():
    from recupero.ops.commands.close_case import run
    rc = run(
        case_id=UUID("00000000-0000-0000-0000-000000000001"),
        outcome="full_recovery",
        recovered_usd_raw="0",
        note=None,
        dsn="postgres://fake",
    )
    assert rc == 1


def test_close_case_full_recovery_rejects_nan_usd():
    from recupero.ops.commands.close_case import run
    rc = run(
        case_id=UUID("00000000-0000-0000-0000-000000000001"),
        outcome="full_recovery",
        recovered_usd_raw="NaN",
        note=None,
        dsn="postgres://fake",
    )
    assert rc == 1


def test_close_case_rejects_unknown_outcome_at_function_layer():
    """Defense in depth: even if argparse choices=... is bypassed
    (programmatic call to run()), the validator rejects."""
    from recupero.ops.commands.close_case import run
    rc = run(
        case_id=UUID("00000000-0000-0000-0000-000000000001"),
        outcome="full_returned_to_god",
        recovered_usd_raw=None,
        note=None,
        dsn="postgres://fake",
    )
    assert rc == 1


# ─────────────────────────────────────────────────────────────────────────────
# Case-close gate — invariant
# ─────────────────────────────────────────────────────────────────────────────


def test_close_case_cli_outcomes_map_to_valid_freeze_outcomes():
    """Every CLI outcome maps to a freeze_outcomes.outcome_type that
    exists in the table's CHECK constraint."""
    from recupero.freeze_learning.recorder import VALID_OUTCOME_TYPES
    from recupero.ops.commands.close_case import CLI_OUTCOMES
    for cli_outcome, db_outcome in CLI_OUTCOMES.items():
        assert db_outcome in VALID_OUTCOME_TYPES, (
            f"close-case maps {cli_outcome} → {db_outcome} which is "
            f"NOT in freeze_outcomes CHECK constraint"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Migration shape
# ─────────────────────────────────────────────────────────────────────────────


def test_migration_027_exists_and_creates_table():
    """The migration file must exist with the right table definition."""
    from pathlib import Path
    here = Path(__file__).resolve().parents[1]
    migration = here / "migrations" / "027_recovery_disclosures.sql"
    assert migration.exists()
    sql = migration.read_text(encoding="utf-8")
    assert "recovery_disclosures" in sql
    # The legal-audit core columns.
    for col in (
        "case_id", "shown_at_utc", "rate_displayed", "ci_low",
        "ci_high", "sample_size", "is_our_data",
        "customer_acknowledged", "customer_acknowledged_at_utc",
    ):
        assert col in sql, f"migration 027 missing column {col}"


# ─────────────────────────────────────────────────────────────────────────────
# Property: published rate matches honesty contract
# ─────────────────────────────────────────────────────────────────────────────


def test_published_rate_never_inflates_above_observed():
    """If 1 of 100 cases recovered, the rate is 0.01 — not 0.05.
    This is the load-bearing honesty invariant for the disclosure."""
    stats = _our_data_stats(
        sample_size=100,
        n_full=1,
        n_partial=0,
        n_zero=99,
        recovery_usd_amounts=[Decimal("1000")],
        time_to_recovery_days=[10],
    )
    assert stats.full_recovery_rate == 0.01
    # The CI's upper bound IS allowed to be > p̂ (that's what a CI is);
    # but the point estimate matches reality.
    assert math.isclose(
        stats.full_recovery_rate, 1 / 100, rel_tol=1e-9,
    )
