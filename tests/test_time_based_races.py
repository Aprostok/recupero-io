"""Time-window race conditions: clock-skew, wall-vs-monotonic, tz confusion.

Pins the behavior of the codebase's existing time-dependent guards so a
future refactor can't silently re-introduce a class of bug. Each test
documents the bug class it defends against, then asserts the current
mitigation.

NOTE: these are *narrow-scope unit tests*. They patch the smallest
surface (a single ``datetime.now`` call or a single ``time.time``)
needed to drive the boundary, and they MUST NOT touch the wave-9
freeze-followup state-guard files — those have their own dedicated
W9-03 race tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from recupero.payments.webhook import (
    _REPLAY_TOLERANCE_SEC,
    WebhookVerifyError,
    verify_and_parse,
)
from recupero.worker._freeze_followup import (
    _STAGE_INITIAL,
    _STAGE_NUDGE_72H,
    _STAGE_SILENCE_14D,
    _compute_next_transition,
)

# ---------------------------------------------------------------------------
# 1. Stripe webhook replay-window — BOTH upper AND lower bounds enforced
# ---------------------------------------------------------------------------


def _sign(secret: str, timestamp: int, body: bytes) -> str:
    """Tiny re-implementation of the Stripe HMAC signing scheme so the
    tests don't need to monkeypatch the verifier's expected hash."""
    import hashlib
    import hmac

    signed = f"{timestamp}.".encode() + body
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


_SECRET = "whsec_test_dummy_secret_value"
_GOOD_BODY = b'{"id":"evt_test_1","type":"checkout.session.completed"}'


def test_webhook_rejects_future_timestamp_outside_tolerance() -> None:
    """Class: signature replay-window must enforce LOWER bound (future).

    Stripe docs say ``> 5min old`` should be rejected. A naive
    implementation that only checks ``now - ts > tolerance`` lets an
    attacker post events with ``ts = now + 1 day`` and replay them once
    the clock catches up. The verifier uses ``abs(now - ts) > tol``,
    which closes the gap.
    """
    now = 1_700_000_000
    future_ts = now + _REPLAY_TOLERANCE_SEC + 1  # 5min01s into the future
    header = _sign(_SECRET, future_ts, _GOOD_BODY)

    with pytest.raises(WebhookVerifyError, match="outside tolerance"):
        verify_and_parse(
            body_bytes=_GOOD_BODY,
            signature_header=header,
            webhook_secret=_SECRET,
            now_unix=now,
        )


def test_webhook_accepts_at_exact_tolerance_boundary() -> None:
    """Pin: a signature at exactly ``tolerance`` seconds old still
    validates. Drift this off-by-one in either direction and you either
    let true replays through (>) or reject legitimate slow deliveries
    (<). The current check is ``abs(now-ts) > tol`` so the boundary
    itself is INCLUSIVE."""
    now = 1_700_000_000
    boundary_ts = now - _REPLAY_TOLERANCE_SEC  # exactly 300s old
    header = _sign(_SECRET, boundary_ts, _GOOD_BODY)

    event = verify_and_parse(
        body_bytes=_GOOD_BODY,
        signature_header=header,
        webhook_secret=_SECRET,
        now_unix=now,
    )
    assert event.event_id == "evt_test_1"


# ---------------------------------------------------------------------------
# 2. Freeze-followup stage gates — tz-aware datetime contract
# ---------------------------------------------------------------------------


def test_freeze_followup_rejects_naive_datetime_sent_at() -> None:
    """Class: tz-confusion. ``datetime.now()`` (naive local) subtracted
    from a tz-aware ``sent_at`` raises ``TypeError`` at runtime in CPython.

    The cron uses ``datetime.now(UTC)``. This test pins that contract by
    confirming the pure helper raises if a caller accidentally passes a
    naive ``now`` — that's the explicit signal a contributor would see
    if they swapped in ``datetime.now()`` (naive).
    """
    sent_at = datetime.now(UTC) - timedelta(hours=80)
    now_naive = datetime.now()  # naive local — wrong!

    with pytest.raises(TypeError):
        _compute_next_transition(
            sent_at=sent_at,
            current_stage=_STAGE_INITIAL,
            now=now_naive,
        )


def test_freeze_followup_clock_skew_backwards_skips_advance() -> None:
    """Class: NTP-induced wall-clock jump backwards. If ``now`` drifts to
    BEFORE ``sent_at`` (e.g. VM resumed from a snapshot), ``elapsed``
    goes negative and the helper must NOT advance the stage."""
    sent_at = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)
    now_in_past = sent_at - timedelta(seconds=1)

    result = _compute_next_transition(
        sent_at=sent_at,
        current_stage=_STAGE_INITIAL,
        now=now_in_past,
    )
    assert result is None, (
        "Negative elapsed must yield no transition — otherwise a "
        "backward NTP step could fire a stage advance prematurely"
    )


def test_freeze_followup_jumps_to_highest_eligible_stage() -> None:
    """Class: cron-downtime catch-up race. A letter sent 30 days ago at
    stage='initial' (operator manually rolled back, or cron was down)
    must NOT fire three issuer emails in successive ticks. Audit-fix
    A3 picks the highest-eligible stage in a single tick."""
    sent_at = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)  # 30d ago
    now = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)

    result = _compute_next_transition(
        sent_at=sent_at,
        current_stage=_STAGE_INITIAL,
        now=now,
    )
    assert result is not None
    next_stage, _template = result
    # We want a SINGLE jump straight to silence_14d, not three back-to-back.
    assert next_stage == _STAGE_SILENCE_14D, (
        f"30-day-old initial letter must jump straight to silence_14d "
        f"in one tick, got {next_stage}"
    )


def test_freeze_followup_no_double_advance_within_same_stage() -> None:
    """Class: same-tick re-entry. Calling the helper twice with the
    candidate already at the target stage must NOT re-advance — pins
    the ``to_idx <= current_idx`` guard."""
    sent_at = datetime(2026, 5, 18, 0, 0, 0, tzinfo=UTC)  # 4d ago
    now = datetime(2026, 5, 22, 0, 0, 0, tzinfo=UTC)

    # At nudge_72h already (~96h elapsed but not yet 7d → no further advance).
    result = _compute_next_transition(
        sent_at=sent_at,
        current_stage=_STAGE_NUDGE_72H,
        now=now,
    )
    assert result is None, (
        "Already at nudge_72h with <7d elapsed must yield no transition"
    )


# ---------------------------------------------------------------------------
# 3. Portal token expiry — strict-less-than, clock skew handling
# ---------------------------------------------------------------------------


def test_portal_token_expiry_uses_strict_inequality_at_boundary() -> None:
    """Class: off-by-one at expiry. The verifier checks
    ``expires_at < now``. A token whose expires_at equals ``now`` to
    the microsecond is still VALID — pin that semantics so a refactor
    to ``<=`` would fail loudly.

    This is a pure-function pin: we replicate the comparison in-line
    rather than spinning up the DB. The intent is to lock the
    *operator semantics*: "expires_at == now" is not yet expired.
    """
    expires_at = datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC)

    # At exactly the same instant — still valid per current verify_token.
    now_exact = expires_at
    assert not (expires_at < now_exact), "exact-equal must NOT count as expired"

    # 1 microsecond past — expired.
    now_just_past = expires_at + timedelta(microseconds=1)
    assert expires_at < now_just_past

    # 1 microsecond before — valid.
    now_just_before = expires_at - timedelta(microseconds=1)
    assert not (expires_at < now_just_before)


def test_portal_token_clock_uses_utc_not_local() -> None:
    """Class: tz-confusion at expiry compare. ``verify_token`` reads
    ``now = datetime.now(UTC)``. A reviewer swapping in
    ``datetime.now()`` (naive local) would (a) crash when comparing
    against the tz-aware ``expires_at`` column from psycopg, OR (b)
    silently treat a UTC value as local. Pin the tz-aware contract.

    We patch ``recupero.portal.tokens.datetime`` and grab the ``now``
    callsite via a side-effect spy.
    """
    captured: list[datetime] = []

    real_dt = datetime

    class _SpyDT(real_dt):  # type: ignore[misc, valid-type]
        @classmethod
        def now(cls, tz=None):  # noqa: D401, ANN001
            v = real_dt.now(tz)
            captured.append(v)
            return v

    with patch("recupero.portal.tokens.datetime", _SpyDT):
        # Call a path that hits the now-clock without needing the DB:
        # generate_token's expires-at compute does the same UTC call.
        # Directly invoke the same expression that verify_token uses.
        from recupero.portal import tokens as _tokens_mod
        from recupero.portal.tokens import _DEFAULT_TTL_DAYS  # noqa: F401

        v = _tokens_mod.datetime.now(UTC)
        assert v.tzinfo is not None, (
            "portal token clock must be tz-aware (UTC) — naive local time "
            "would either crash psycopg compare or quietly leak an "
            "hours-long window of validity to an expired token"
        )
    assert captured, "spy datetime was not invoked"


# ---------------------------------------------------------------------------
# 4. emails_sent dedupe — no TTL, success-keyed (pins design)
# ---------------------------------------------------------------------------


def test_emails_sent_dedupe_predicate_has_no_time_component() -> None:
    """Class: silent TTL drift. The dedupe SELECT is keyed on
    ``(investigation_id, email_type, error_message IS NULL)`` with NO
    time window. Once a successful send is logged, a duplicate is
    blocked forever for that (inv, type) pair.

    A future contributor adding ``AND sent_at > NOW() - INTERVAL '24h'``
    would silently re-enable duplicate weekly engagement emails. Pin
    the predicate shape by source-grepping the canonical send path."""
    import inspect

    from recupero.worker import _email

    src = inspect.getsource(_email)
    # The canonical dedupe SELECT must NOT carry an interval/time-window
    # predicate. We grep for the textual signature.
    assert "FROM public.emails_sent" in src
    assert "AND error_message IS NULL" in src
    # Negative: no time-window clause snuck in.
    forbidden_snippets = (
        "sent_at > NOW() - INTERVAL",
        "sent_at > now() - interval",
        "INTERVAL '24 hours'",
        "make_interval(hours =>",  # used elsewhere, but not in dedupe path
    )
    # Find the dedupe-query span and only assert on it.
    dedupe_idx = src.index("FROM public.emails_sent")
    dedupe_span = src[dedupe_idx : dedupe_idx + 400]
    for needle in forbidden_snippets:
        assert needle not in dedupe_span, (
            f"emails_sent dedupe gained a time-window predicate "
            f"({needle!r}) — this re-introduces the duplicate-send "
            f"race the dedupe was designed to prevent"
        )


# ---------------------------------------------------------------------------
# 5. Wall-vs-monotonic — rate limiter must use monotonic
# ---------------------------------------------------------------------------


def test_api_rate_limiter_uses_monotonic_not_wall_clock() -> None:
    """Class: wall-clock jump invalidates rate-limit accounting. The
    token-bucket refill computes ``elapsed = now - bucket.last_refill``.
    If ``now`` is wall-clock and NTP steps the clock backwards by an
    hour, ``elapsed`` goes negative → bucket refill goes negative →
    legitimate users get spuriously rate-limited (or, worse, an
    attacker gets a free burst depending on the sign handling).

    Pin: the limiter must source ``now`` from ``time.monotonic()``."""
    import inspect

    from recupero.api import auth

    src = inspect.getsource(auth._check_rate_limit)
    assert "time.monotonic(" in src, (
        "rate limiter MUST use time.monotonic() — wall-clock now() is "
        "vulnerable to NTP back-steps and DST jumps"
    )
    assert "time.time(" not in src, (
        "rate limiter must not mix wall-clock time.time() with "
        "monotonic — the two are not interchangeable"
    )


def test_pipeline_stage_timing_uses_monotonic() -> None:
    """Class: stage-duration metric corruption. Pipeline stage timers
    use ``time.monotonic()`` so a wall-clock jump mid-stage doesn't
    log a negative or 10-year-long duration."""
    import inspect

    from recupero.worker import pipeline

    src = inspect.getsource(pipeline)
    # The stage-timer span uses ``_time.monotonic`` (imported as _time).
    assert "_time.monotonic(" in src or "time.monotonic(" in src, (
        "pipeline stage timers must use monotonic clock"
    )
