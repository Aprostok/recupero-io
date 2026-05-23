"""RIGOR-Jacob Z3: monitoring aggregation NaN/Infinity hardening.

Three real bugs surfaced in src/recupero/monitoring/:

Bug 1 (cluster_builder._parse_usd):
    A poisoned brief["TOTAL_LOSS_USD"] of "NaN" or "$NaN" raises
    decimal.InvalidOperation in the ``val > 0`` comparison — which
    sits OUTSIDE the try/except, and OUTSIDE the outer try in
    build_or_update_cluster_for_case. The function documents
    "NEVER raises" but does. A single malformed brief loaf during
    cluster join blows up emit_brief.

Bug 2 (cluster_builder._parse_usd):
    A poisoned "Infinity" string returns Decimal('Infinity'), which
    is silently propagated into case_clusters.total_loss_usd. Any
    downstream comparison or aggregation against this row becomes
    poisoned.

Bug 3 (cooperation_intelligence.build_cooperation_profile):
    A poisoned freeze_outcomes.frozen_usd or .returned_usd of
    Decimal('NaN') propagates into ``total_frozen`` via silent
    Decimal addition (NaN+x is NaN without raising), then escapes
    into ``profile.total_frozen_usd``. Downstream renderers that
    compare ``profile.total_frozen_usd > 0`` (LE template Section
    5.7, cooperation dashboard ranker) crash on InvalidOperation
    when displaying the issuer's history. A single bad row
    poisons every render of that issuer's profile until cleaned.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from recupero.monitoring.cluster_builder import _parse_usd


# ----------------------------------------------------------------------
# Bug 1 — _parse_usd must not raise on "NaN" inputs
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "poison",
    [
        "NaN",
        "$NaN",
        "nan",
        "$nan",
        "+NaN",
        "-NaN",
        "sNaN",  # signaling NaN — Decimal parses this too
    ],
)
def test_cluster_parse_usd_returns_zero_for_nan_strings(poison):
    """_parse_usd must clamp NaN inputs to Decimal(0), never raise.

    The function is called from build_or_update_cluster_for_case BEFORE
    the outer try/except block — raising here breaks emit_brief.
    """
    result = _parse_usd(poison)
    assert isinstance(result, Decimal)
    assert not result.is_nan(), f"NaN escaped: {result!r}"
    assert result == Decimal(0)


# ----------------------------------------------------------------------
# Bug 2 — _parse_usd must not pass Infinity through
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "poison",
    [
        "Infinity",
        "Inf",
        "$Infinity",
        "-Infinity",
        "+Infinity",
    ],
)
def test_cluster_parse_usd_returns_zero_for_infinity_strings(poison):
    """_parse_usd must clamp Infinity to Decimal(0). An infinite
    TOTAL_LOSS_USD silently injected into case_clusters.total_loss_usd
    pollutes every downstream consumer."""
    result = _parse_usd(poison)
    assert isinstance(result, Decimal)
    assert result.is_finite(), f"non-finite escaped: {result!r}"
    assert result == Decimal(0)


def test_cluster_parse_usd_handles_decimal_nan_directly():
    """When the brief already carries Decimal('NaN') (e.g. a prior
    stage returned NaN as a Decimal sentinel), _parse_usd must
    coerce it to Decimal(0) and not raise."""
    result = _parse_usd(Decimal("NaN"))
    assert result == Decimal(0)


def test_cluster_parse_usd_handles_decimal_infinity_directly():
    result = _parse_usd(Decimal("Infinity"))
    assert result == Decimal(0)
    assert result.is_finite()


def test_cluster_parse_usd_handles_float_nan_directly():
    result = _parse_usd(float("nan"))
    assert result == Decimal(0)


def test_cluster_parse_usd_handles_float_inf_directly():
    result = _parse_usd(float("inf"))
    assert result == Decimal(0)


def test_cluster_parse_usd_preserves_valid_amount():
    """Sanity: normal positive amounts pass through unchanged."""
    assert _parse_usd("$3,600,000.00") == Decimal("3600000.00")
    assert _parse_usd("42500") == Decimal("42500")
    assert _parse_usd(Decimal("100.50")) == Decimal("100.50")


# ----------------------------------------------------------------------
# Bug 3 — cooperation profile must not let NaN through total_frozen_usd
# ----------------------------------------------------------------------

def test_cooperation_profile_rejects_nan_frozen_usd(monkeypatch):
    """A poisoned Decimal('NaN') in freeze_outcomes.frozen_usd must
    NOT propagate into IssuerCooperationProfile.total_frozen_usd.

    Pre-fix: Decimal(0) + Decimal('NaN') silently produces NaN, which
    escapes into the published profile and crashes downstream
    comparisons (LE template Section 5.7 ranker).
    """
    from datetime import UTC, datetime, timedelta

    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    observed_at = sent_at + timedelta(hours=24)

    # Fake DB row carrying NaN in frozen_usd — exactly what a
    # mis-encoded numeric column or a poisoned test fixture would
    # produce on read.
    fake_rows = [
        {
            "letter_id": uuid4(),
            "sent_at": sent_at,
            "outcome_type": "full_freeze",
            "observed_at": observed_at,
            "frozen_usd": Decimal("NaN"),
            "returned_usd": None,
        },
    ]

    class _FakeCursor:
        def execute(self, *a, **kw):
            pass

        def fetchall(self):
            return fake_rows

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeConn:
        def cursor(self):
            return _FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_db_connect(*a, **kw):
        return _FakeConn()

    # Monkeypatch import target inside the function — _common.db_connect.
    import recupero._common as _common
    monkeypatch.setattr(_common, "db_connect", _fake_db_connect)

    profile = cooperation_intelligence.build_cooperation_profile(
        "PoisonIssuer", dsn="postgresql://fake/dsn",
    )

    # Either the issuer aggregates to a zero/finite total, or the
    # whole row was dropped — either is acceptable. What is NOT
    # acceptable is NaN escaping into the published profile.
    assert profile.total_frozen_usd.is_finite(), (
        f"NaN escaped into total_frozen_usd: {profile.total_frozen_usd!r}"
    )
    # Comparing NaN against zero raises — assert this works without
    # raising, which is what every downstream consumer expects.
    assert profile.total_frozen_usd >= Decimal(0)


def test_cooperation_profile_rejects_infinity_frozen_usd(monkeypatch):
    """Same shape as the NaN test but for Infinity. An infinity in
    frozen_usd silently propagates through the sum and pollutes the
    issuer's cross-case total."""
    from datetime import UTC, datetime, timedelta

    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    observed_at = sent_at + timedelta(hours=24)

    fake_rows = [
        {
            "letter_id": uuid4(),
            "sent_at": sent_at,
            "outcome_type": "full_freeze",
            "observed_at": observed_at,
            "frozen_usd": Decimal("Infinity"),
            "returned_usd": None,
        },
    ]

    class _FakeCursor:
        def execute(self, *a, **kw):
            pass

        def fetchall(self):
            return fake_rows

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeConn:
        def cursor(self):
            return _FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import recupero._common as _common
    monkeypatch.setattr(_common, "db_connect", lambda *a, **kw: _FakeConn())

    profile = cooperation_intelligence.build_cooperation_profile(
        "PoisonIssuer", dsn="postgresql://fake/dsn",
    )
    assert profile.total_frozen_usd.is_finite(), (
        f"Infinity escaped: {profile.total_frozen_usd!r}"
    )
    assert profile.total_frozen_usd >= Decimal(0)
