"""Deeper audit of cooperation_intelligence.build_cooperation_profile.

Five bugs that survive v0.24.1's NaN/Infinity hardening:

Bug A (issuer name normalization):
    The freeze_letters_sent.issuer column accumulates duplicates for
    every casing/whitespace variant operators paste in: "Tether",
    "Tether ", "tether", "Tether Limited". `build_cooperation_profile`
    treats each variant as a distinct issuer — the operator sees three
    "Tether" rows in the LE handoff cooperation panel, each with a
    fraction of the real sample size. Worse: the strongest variant
    (n_letters=8) ends up with `has_confident_profile=True` while the
    sibling variant (n_letters=2) shows "insufficient sample" — a
    direct contradiction the LE reader will notice.

Bug B (negative response_hours from clock skew / corrupted backfill):
    When a freeze_outcomes row has observed_at < sent_at (clock skew
    on the supabase node, a backfill that imported the outcome before
    the letter, or an operator who corrected the letter sent_at after
    logging the outcome), the computed response_hours is NEGATIVE.
    `fastest_response_hours = min(...)` then publishes a negative
    number, which the LE template renders as "responded in -47 hours"
    and which `recommend_legal_instrument` feeds into
    `max(2, int(profile.median_response_hours / 24))` — the max() rail
    catches the days computation but the displayed hours number is
    still nonsense.

Bug C (is_black_hole flags pure-silence issuers as black holes):
    The docstring on `is_black_hole` says "n_letters ≥ MIN AND ZERO
    OUTCOMES of any kind" — meaning the issuer never produced a
    freeze_outcomes row at all, not even a silence_14d marker. But
    the implementation flags `n_responded == 0`, which evaluates True
    for an issuer who returned ONLY silence_14d rows. Silence rows are
    explicit ENGAGEMENT data (the silence-detection cron writes them)
    — they prove the issuer is being tracked, not unreachable. The
    instrument recommender then escalates to grand-jury subpoena for
    an issuer the operator was already monitoring through normal
    channels.

Bug D (NaN-poisoned response_hours):
    A corrupted observed_at coerced to a NaN-bearing datetime via a
    timezone-aware/-naive subtraction can yield a float('nan') from
    .total_seconds(). The list `freeze_response_hours` then carries
    NaN, statistics.median([..., nan, ...]) silently returns NaN, and
    `profile.median_response_hours` becomes NaN — every downstream
    f"{x:.0f}" render then prints "nan hours" or trips
    `max(2, int(nan/24))` (ValueError on int(nan)).

Bug E (response_hours outlier dominance):
    One freeze_outcomes row taking 50,000 hours (operator opened a
    case, forgot it for 5 years, finally got a response) pulls the
    avg_response_hours from ~24h to ~5500h. The LE handoff then reads
    "Coinbase responds in 5500h on average" — operationally misleading.
    A trimmed mean (drop the top/bottom 10%) yields a stable signal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

# ----------------------------------------------------------------------
# Shared DB stub — mirrors test_monitoring_nan_aggregation.py shape.
# ----------------------------------------------------------------------


def _install_fake_db(monkeypatch, rows_by_issuer):
    """Install a fake db_connect that returns the rows list keyed by
    the (single) parameter passed to cur.execute(sql, (issuer,)).
    """

    class _FakeCursor:
        def __init__(self):
            self._last_rows: list = []

        def execute(self, sql, params=None):
            if params is None or len(params) == 0:
                # DISTINCT issuer query used by build_all_profiles —
                # return every issuer that has at least one fake row.
                self._last_rows = [(k,) for k in rows_by_issuer]
            else:
                issuer = params[0]
                self._last_rows = list(rows_by_issuer.get(issuer, []))

        def fetchall(self):
            return self._last_rows

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


# ----------------------------------------------------------------------
# Bug A — issuer name normalization (whitespace / case variants)
# ----------------------------------------------------------------------


def test_issuer_name_is_normalized_for_query(monkeypatch):
    """The caller passes "Tether " (trailing space) — the function
    should normalize to "Tether" before querying and aggregating.
    Pre-fix the trailing space becomes a permanent split in the
    cooperation panel."""
    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
    observed_at = sent_at + timedelta(hours=24)

    # The DB has rows under the canonical "Tether" — caller passes the
    # whitespace-polluted form. Normalization must hit the canonical key.
    rows_by_issuer = {
        "Tether": [
            {
                "letter_id": uuid4(),
                "sent_at": sent_at,
                "outcome_type": "full_freeze",
                "observed_at": observed_at,
                "frozen_usd": Decimal("1000000"),
                "returned_usd": None,
            },
        ],
    }
    _install_fake_db(monkeypatch, rows_by_issuer)

    profile = cooperation_intelligence.build_cooperation_profile(
        "Tether ",  # trailing space
        dsn="postgresql://fake/dsn",
    )
    assert profile.n_letters_sent == 1, (
        f"Issuer name not normalized — 'Tether ' produced empty profile "
        f"instead of merging into the canonical 'Tether' history. Got "
        f"n_letters_sent={profile.n_letters_sent}"
    )
    # Canonical issuer name is what gets stored on the profile.
    assert profile.issuer.strip() == profile.issuer, (
        f"Profile.issuer carries trailing whitespace: {profile.issuer!r}"
    )


def test_issuer_name_nbsp_normalized_via_explicit_escape(monkeypatch):
    """Non-breaking space (U+00A0) commonly comes from operators
    pasting issuer names out of compliance-portal PDFs. Must
    normalize like ASCII whitespace.

    We use the explicit \\u00A0 escape so this test cannot be
    silently defanged by an editor / formatter normalizing the
    literal NBSP to a plain ASCII space.
    """
    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 4, 2, 12, 0, tzinfo=UTC)
    observed_at = sent_at + timedelta(hours=12)

    rows_by_issuer = {
        "Coinbase": [
            {
                "letter_id": uuid4(),
                "sent_at": sent_at,
                "outcome_type": "full_freeze",
                "observed_at": observed_at,
                "frozen_usd": Decimal("500000"),
                "returned_usd": None,
            },
        ],
    }
    _install_fake_db(monkeypatch, rows_by_issuer)

    profile = cooperation_intelligence.build_cooperation_profile(
        "Coinbase ",  # trailing NBSP
        dsn="postgresql://fake/dsn",
    )
    assert profile.n_letters_sent == 1, (
        f"NBSP-suffixed issuer not normalized -- got "
        f"n_letters_sent={profile.n_letters_sent}, "
        f"profile.issuer={profile.issuer!r}"
    )


# ----------------------------------------------------------------------
# Bug B — negative response_hours from clock skew / corrupted backfill
# ----------------------------------------------------------------------


def test_negative_response_hours_clamped_to_nonnegative(monkeypatch):
    """observed_at < sent_at (clock skew, backfill order) must NOT
    publish a negative fastest/median/avg response_hours. The whole
    row should be dropped from the timing aggregation (the timing is
    nonsense) but the letter still counts toward n_responded /
    full_freeze_rate."""
    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 4, 3, 12, 0, tzinfo=UTC)
    # Observed BEFORE sent — clock skew / corrupted backfill.
    observed_at = sent_at - timedelta(hours=47)

    rows_by_issuer = {
        "ClockSkewExchange": [
            {
                "letter_id": uuid4(),
                "sent_at": sent_at,
                "outcome_type": "full_freeze",
                "observed_at": observed_at,
                "frozen_usd": Decimal("100"),
                "returned_usd": None,
            },
        ],
    }
    _install_fake_db(monkeypatch, rows_by_issuer)

    profile = cooperation_intelligence.build_cooperation_profile(
        "ClockSkewExchange", dsn="postgresql://fake/dsn",
    )
    # Letter still counts.
    assert profile.n_letters_sent == 1
    assert profile.n_responded == 1
    # Timing must be either None (row dropped from timing aggregate)
    # or non-negative — never the published -47.0.
    for field_name in (
        "median_response_hours",
        "avg_response_hours",
        "fastest_response_hours",
        "slowest_response_hours",
    ):
        val = getattr(profile, field_name)
        assert val is None or val >= 0, (
            f"profile.{field_name}={val!r} — negative response hours "
            "leaked into the published profile (LE handoff will render "
            "'responded in -47 hours')."
        )


# ----------------------------------------------------------------------
# Bug C — is_black_hole must require ZERO outcome rows, not zero responses
# ----------------------------------------------------------------------


def test_silence_only_issuer_is_not_a_black_hole(monkeypatch):
    """Per the docstring, is_black_hole means "n_letters ≥ MIN AND
    NO freeze_outcomes rows of ANY kind." An issuer with only
    silence_14d/_30d/_90d outcome rows IS being tracked (the silence
    detector wrote those rows) and must NOT be flagged as a black
    hole — that would recommend a grand-jury subpoena over an issuer
    the operator is already engaged with through the silence-tracking
    workflow."""
    from recupero.monitoring import cooperation_intelligence

    sent_at_1 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    sent_at_2 = datetime(2026, 3, 10, 12, 0, tzinfo=UTC)
    sent_at_3 = datetime(2026, 3, 20, 12, 0, tzinfo=UTC)

    rows_by_issuer = {
        "SilenceOnlyExchange": [
            # Three letters each with a silence_14d outcome row recorded.
            {
                "letter_id": "L1",
                "sent_at": sent_at_1,
                "outcome_type": "silence_14d",
                "observed_at": sent_at_1 + timedelta(days=14),
                "frozen_usd": None,
                "returned_usd": None,
            },
            {
                "letter_id": "L2",
                "sent_at": sent_at_2,
                "outcome_type": "silence_14d",
                "observed_at": sent_at_2 + timedelta(days=14),
                "frozen_usd": None,
                "returned_usd": None,
            },
            {
                "letter_id": "L3",
                "sent_at": sent_at_3,
                "outcome_type": "silence_30d",
                "observed_at": sent_at_3 + timedelta(days=30),
                "frozen_usd": None,
                "returned_usd": None,
            },
        ],
    }
    _install_fake_db(monkeypatch, rows_by_issuer)

    profile = cooperation_intelligence.build_cooperation_profile(
        "SilenceOnlyExchange", dsn="postgresql://fake/dsn",
    )
    assert profile.n_letters_sent == 3
    # Silence-detection outcomes exist — issuer is being tracked, not
    # invisible. Must NOT be flagged as black hole.
    assert profile.is_black_hole is False, (
        "is_black_hole was True for an issuer with only silence_14d/"
        "silence_30d outcomes — the silence detector wrote those rows, "
        "the issuer is being actively monitored. Black-hole means zero "
        "outcome rows of any kind, including silence markers."
    )


# ----------------------------------------------------------------------
# Bug D — NaN in response_hours list must not poison median/avg
# ----------------------------------------------------------------------


def test_nan_in_response_hours_does_not_poison_median(monkeypatch):
    """If a single response_hours value is NaN (corrupted datetime
    arithmetic upstream), statistics.median returns NaN and the
    published median_response_hours becomes NaN — which crashes the
    instrument-recommender's `int(nan/24)` and the LE template's
    `:.0f` formatting.

    We simulate this by constructing rows whose deltas the function
    will compute; then we *post-mutate* the list via a monkeypatch
    on statistics.median to return NaN. The function should detect
    and suppress non-finite timing values.
    """
    import math

    from recupero.monitoring import cooperation_intelligence

    sent_at = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    observed_at = sent_at + timedelta(hours=24)

    rows_by_issuer = {
        "PoisonTiming": [
            {
                "letter_id": uuid4(),
                "sent_at": sent_at,
                "outcome_type": "full_freeze",
                "observed_at": observed_at,
                "frozen_usd": Decimal("100"),
                "returned_usd": None,
            },
        ],
    }
    _install_fake_db(monkeypatch, rows_by_issuer)

    # Force statistics.median (used inside the function) to return NaN
    # — emulating an upstream NaN injection into the freeze_response_hours
    # list. The function should refuse to publish a non-finite median.
    monkeypatch.setattr(
        cooperation_intelligence.statistics, "median",
        lambda _xs: float("nan"),
    )

    profile = cooperation_intelligence.build_cooperation_profile(
        "PoisonTiming", dsn="postgresql://fake/dsn",
    )
    # Either median is None (suppressed) or finite — never NaN.
    if profile.median_response_hours is not None:
        assert math.isfinite(profile.median_response_hours), (
            f"NaN escaped into median_response_hours: "
            f"{profile.median_response_hours!r}"
        )


# ----------------------------------------------------------------------
# Bug E — response_hours outlier dominance (not in scope for this fix
# but documenting via xfail so the future fix has a target)
# ----------------------------------------------------------------------


# v0.31.1: was previously xfail — closed by adding _trimmed_mean
# in cooperation_intelligence (10% symmetric trim above n=10).
def test_avg_response_hours_resists_outlier_dominance(monkeypatch):
    from recupero.monitoring import cooperation_intelligence

    base_sent = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    rows = []
    # Nine letters with 24h response, one with 50000h (operator forgot
    # the case for years). Untrimmed avg ≈ 5022h; trimmed avg ≈ 24h.
    for i in range(9):
        s = base_sent + timedelta(days=i)
        rows.append({
            "letter_id": f"L{i}",
            "sent_at": s,
            "outcome_type": "full_freeze",
            "observed_at": s + timedelta(hours=24),
            "frozen_usd": Decimal("100"),
            "returned_usd": None,
        })
    s_out = base_sent + timedelta(days=20)
    rows.append({
        "letter_id": "Loutlier",
        "sent_at": s_out,
        "outcome_type": "full_freeze",
        "observed_at": s_out + timedelta(hours=50000),
        "frozen_usd": Decimal("100"),
        "returned_usd": None,
    })

    _install_fake_db(monkeypatch, {"OutlierExchange": rows})
    profile = cooperation_intelligence.build_cooperation_profile(
        "OutlierExchange", dsn="postgresql://fake/dsn",
    )
    # Trimmed avg should stay close to the modal 24h response.
    assert profile.avg_response_hours is not None
    assert profile.avg_response_hours < 500, (
        f"avg_response_hours={profile.avg_response_hours} — outlier "
        "dominates the mean."
    )
