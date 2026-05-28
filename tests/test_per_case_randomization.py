"""Tests for the per-case randomized-threshold module.

Pins the contracts the JACOB_ADVERSARY_AUDIT_v032 M-5 mitigation
requires:

* Determinism: same case + threshold name → same value.
* Jitter bounds: ±jitter_pct of the base, no escape.
* Secret-binding: different secret → different value distribution.
* Adversary unpredictability: across 100 cases, Pearson correlation
  between adjacent threshold values is < 0.1 (effectively random).
* Dev fallback warns exactly once per process.
"""

from __future__ import annotations

import logging
import os
import string
import uuid
from unittest import mock

import pytest

from recupero.security import per_case_randomization as pcr
from recupero.security.per_case_randomization import (
    CaseThresholds,
    case_threshold,
    get_case_thresholds,
)


# ---------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------


def test_threshold_is_deterministic_for_same_case_and_name():
    """Twice with the same inputs → same output."""
    case_id = "case-001"
    name = "dust_min_fanout"
    base = 10
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-A"}):
        v1 = case_threshold(case_id, name, base)
        v2 = case_threshold(case_id, name, base)
    assert v1 == v2


def test_threshold_differs_across_threshold_names_same_case():
    """Same case, different threshold names → different randomizations."""
    case_id = "case-001"
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-A"}):
        a = case_threshold(case_id, "fanout", 100)
        b = case_threshold(case_id, "outflow", 100)
    # Cryptographically random — collision probability negligible at this size.
    assert a != b


def test_get_case_thresholds_returns_named_tuple():
    """The bundle is a NamedTuple with the 7 documented fields."""
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-A"}):
        t = get_case_thresholds("case-001")
    assert isinstance(t, CaseThresholds)
    # Pin field names so a future-rename breaks loudly.
    assert set(t._fields) == {
        "dust_min_fanout",
        "service_wallet_outflow",
        "shared_infra_partner",
        "min_clustering_usd",
        "cex_continuity_window_h",
        "dust_threshold_usd",
        "common_funding_window_h",
    }


# ---------------------------------------------------------------------
# Jitter bounds: 1000 random IDs must all land in [70%, 130%] of base
# ---------------------------------------------------------------------


def test_jitter_bounds_1000_random_cases_within_30_pct():
    """For base=100, every randomized value falls in [70, 130]."""
    base = 100
    name = "fanout"
    lo = int(round(base * 0.70))  # 70
    hi = int(round(base * 1.30))  # 130
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-B"}):
        for _ in range(1000):
            cid = str(uuid.uuid4())
            v = case_threshold(cid, name, base)
            assert lo <= v <= hi, (
                f"case {cid}: threshold={v} outside [{lo}, {hi}]"
            )


def test_floor_clamps_to_one_for_tiny_bases():
    """base=1 with ±30% jitter rounds to 1 either way (never 0)."""
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-B"}):
        for i in range(50):
            cid = f"tiny-case-{i}"
            v = case_threshold(cid, "dust_threshold_usd", 1)
            assert v >= 1


# ---------------------------------------------------------------------
# Secret-binding: same case but different secret → different result
# ---------------------------------------------------------------------


def test_different_secrets_produce_different_distributions():
    """A case_id under two different secrets must rarely coincide.

    We pick 50 case IDs and compare under secret-A vs secret-B; the
    overlap should be tiny (a few collisions by chance are OK in a
    30-value band, but not many).
    """
    name = "fanout"
    base = 100
    cases = [f"case-{i}" for i in range(50)]

    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-A"}):
        values_a = [case_threshold(c, name, base) for c in cases]
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-B"}):
        values_b = [case_threshold(c, name, base) for c in cases]
    # Most cases should disagree under different secrets. We accept
    # some coincidence because the output space is only ~60 distinct
    # values (70..130). The expected # of coincidences when sampling
    # uniformly is ~50/60 ≈ 0.83; allowing 8 is well above that
    # without being a meaningless threshold.
    n_match = sum(1 for a, b in zip(values_a, values_b) if a == b)
    assert n_match < 8, (
        f"Too many collisions under different secrets: {n_match}/50"
    )


# ---------------------------------------------------------------------
# Dev fallback warns exactly once per process
# ---------------------------------------------------------------------


def test_dev_fallback_warns_once(caplog: pytest.LogCaptureFixture):
    """Unset env → WARN logged once, returns same value as a real
    secret would (deterministic on the literal sentinel)."""
    # Reset the module's "have we warned" sentinel so this test is
    # independent of other tests in the file.
    pcr._reset_warn_state()
    # Make sure the env var is genuinely absent.
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("RECUPERO_RANDOMIZATION_SECRET", None)
        with caplog.at_level(logging.WARNING, logger=pcr.__name__):
            _ = case_threshold("case-xyz", "fanout", 10)
            _ = case_threshold("case-xyz", "fanout", 10)
            _ = case_threshold("case-other", "outflow", 100)
        warn_records = [
            r for r in caplog.records
            if r.name == pcr.__name__ and r.levelno >= logging.WARNING
        ]
    # Exactly one WARN regardless of number of calls.
    assert len(warn_records) == 1, (
        f"expected 1 dev-fallback WARN, got {len(warn_records)}: "
        f"{[r.getMessage() for r in warn_records]}"
    )
    assert "DEV_FALLBACK_NOT_FOR_PRODUCTION" in warn_records[0].getMessage()


# ---------------------------------------------------------------------
# Adversary unpredictability: Pearson correlation < 0.1
# ---------------------------------------------------------------------


def _pearson(xs: list[float], ys: list[float]) -> float:
    """Pearson correlation, no numpy dep."""
    n = len(xs)
    assert n == len(ys) and n > 1
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs) ** 0.5
    dy = sum((y - my) ** 2 for y in ys) ** 0.5
    if dx == 0.0 or dy == 0.0:
        return 0.0
    return num / (dx * dy)


def test_adversary_cannot_predict_via_correlation_across_100_cases():
    """Across 100 cases, fanout and outflow thresholds are independent.

    The adversary would love to learn "if I see fanout=X for case 1
    I can predict outflow=Y" — i.e. some structural correlation
    between threshold values driven by the case_id. HMAC-SHA256 is
    a PRF so there should be NO such correlation. We assert
    abs(Pearson r) < 0.1.
    """
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-Z"}):
        fanouts: list[float] = []
        outflows: list[float] = []
        for i in range(100):
            cid = f"case-{i:03d}"
            fanouts.append(case_threshold(cid, "dust_min_fanout", 10))
            outflows.append(case_threshold(cid, "service_wallet_outflow", 200))
    r = _pearson(fanouts, outflows)
    assert abs(r) < 0.1, f"correlation {r} too high — randomness compromised"


# ---------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------


def test_empty_case_id_rejected():
    with pytest.raises(ValueError):
        case_threshold("", "fanout", 10)


def test_empty_threshold_name_rejected():
    with pytest.raises(ValueError):
        case_threshold("case-1", "", 10)


def test_bad_base_value_rejected():
    with pytest.raises(ValueError):
        case_threshold("case-1", "fanout", 0)
    with pytest.raises(ValueError):
        case_threshold("case-1", "fanout", -5)


def test_bad_jitter_rejected():
    with pytest.raises(ValueError):
        case_threshold("case-1", "fanout", 10, jitter_pct=0.0)
    with pytest.raises(ValueError):
        case_threshold("case-1", "fanout", 10, jitter_pct=1.0)
    with pytest.raises(ValueError):
        case_threshold("case-1", "fanout", 10, jitter_pct=-0.1)


def test_threshold_name_only_lowercase_letters_underscore_acceptable():
    """Any non-empty string is accepted as the name; this test just
    verifies a few realistic inputs work without exception."""
    with mock.patch.dict(os.environ, {"RECUPERO_RANDOMIZATION_SECRET": "secret-A"}):
        for name in ["fanout", "min_clustering_usd", "x", string.ascii_letters]:
            assert case_threshold("case-1", name, 10) >= 1
