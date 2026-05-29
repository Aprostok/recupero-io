"""Confidence-decay policy: any label with added_at > 180 days AND no
confidence_refreshed_at within the last 180 days has its EFFECTIVE
confidence downgraded one tier when looked up.

This protects against CEX hot-wallet rotation that the seed file
hasn't caught up to: a Binance hot wallet labeled "high" 11 months
ago is realistically "medium" today.

The seed file is NOT modified. Decay happens at lookup time. Operators
see the original stored confidence AND the effective (decayed) one in
the brief.

Decay table (stored → effective):
  * 'high'   un-refreshed for ``EFFECTIVE_DECAY_DAYS`` (default 180)   → 'medium'
  * 'medium' un-refreshed for ``EFFECTIVE_DECAY_DAYS``                 → 'low'
  * 'low'                                                              → 'low' (floor)

Decay is per-180-day window, capped at one tier per window. A 400-day
old un-refreshed 'high' label decays to 'low' (high → medium → low),
not to "below low" — there is no "very low" tier.

``RECUPERO_LABEL_DECAY_DAYS`` overrides the 180-day default at module
load time; bad values fall back to default with a WARN.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

log = logging.getLogger(__name__)

EFFECTIVE_DECAY_DAYS = 180


def _decay_days_from_env() -> int:
    """Resolve ``RECUPERO_LABEL_DECAY_DAYS`` once per call.

    Read at call-time (not module-load) so tests can monkeypatch the
    env without re-importing. Bad input → default with WARN; we don't
    allow 0 because that would decay every label on the first lookup.
    """
    raw = (os.environ.get("RECUPERO_LABEL_DECAY_DAYS") or "").strip()
    if not raw:
        return EFFECTIVE_DECAY_DAYS
    try:
        val = int(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_LABEL_DECAY_DAYS=%r is not an int — using "
            "default %d", raw, EFFECTIVE_DECAY_DAYS,
        )
        return EFFECTIVE_DECAY_DAYS
    if val <= 0 or val > 3650:
        log.warning(
            "RECUPERO_LABEL_DECAY_DAYS=%d out of range [1, 3650] — "
            "using default %d", val, EFFECTIVE_DECAY_DAYS,
        )
        return EFFECTIVE_DECAY_DAYS
    return val


_TIER_ORDER = ("high", "medium", "low")


def _coerce_aware_utc(dt: datetime | None) -> datetime | None:
    """Promote a naive datetime to UTC-aware. Aware values pass
    through. None stays None.

    Without this a stored ``added_at`` (typically naive in older seed
    files) can't be subtracted from an aware ``now``. We assume UTC
    because the rest of the codebase enforces "datetimes are always
    UTC" via models.py.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def apply_decay(
    stored_confidence: str,
    added_at: datetime | None,
    refreshed_at: datetime | None,
    now: datetime,
) -> str:
    """Return the EFFECTIVE confidence after applying the decay policy.

    Rules:
      * If ``refreshed_at`` is set, the age clock uses ``now -
        refreshed_at`` instead of ``now - added_at`` — a refresh
        resets the decay.
      * One tier drop per ``EFFECTIVE_DECAY_DAYS`` (default 180)
        elapsed since the effective anchor.
      * 'low' is the floor — never decays below 'low'.
      * Unknown stored values pass through unchanged (defensive).
    """
    if stored_confidence not in _TIER_ORDER:
        # Defensive: foreign value. Pass through unchanged so we never
        # crash a brief on a typo'd seed row.
        return stored_confidence

    # Pick the freshest anchor. If both are None we can't decay — the
    # caller's seed file is missing both ``added_at`` AND
    # ``confidence_refreshed_at``, which is a data-quality bug but not
    # this function's problem.
    anchor = refreshed_at if refreshed_at is not None else added_at
    anchor = _coerce_aware_utc(anchor)
    now = _coerce_aware_utc(now)
    if anchor is None or now is None:
        return stored_confidence

    decay_days = _decay_days_from_env()
    try:
        delta = now - anchor
    except TypeError:
        # If a caller passes a hand-crafted datetime that breaks
        # subtraction (mixed timezone weirdness), don't decay.
        return stored_confidence
    if delta < timedelta(0):
        # Anchor is in the future — clock skew or hand-crafted test.
        # Do not decay.
        return stored_confidence

    # Integer number of decay windows elapsed.
    windows_elapsed = delta.days // decay_days
    if windows_elapsed <= 0:
        return stored_confidence

    # Walk the tier table down by `windows_elapsed`, clamped at 'low'.
    idx = _TIER_ORDER.index(stored_confidence)
    new_idx = min(idx + windows_elapsed, len(_TIER_ORDER) - 1)
    return _TIER_ORDER[new_idx]


def apply_decay_to_label(label, now: datetime | None = None):
    """Convenience: take a Label (or any object with .confidence /
    .added_at / .valid_from attrs) and return its EFFECTIVE confidence.

    Does NOT mutate the input. The LabelStore wires this into its
    lookup path so callers see the decayed value without needing to
    know decay exists. The stored value remains intact for the brief's
    "original vs effective" surfacing.
    """
    if label is None:
        return None
    if now is None:
        now = datetime.now(UTC)

    # The Label model doesn't (yet) carry a `confidence_refreshed_at`
    # field — the audit-driven `last_verified_at` plays that role for
    # the v0.29.x label-DB sweep and stays in the seed file as a free-
    # form optional. We accept either attribute name on the input
    # object so callers can hand us a Label or a plain dict-shaped
    # row.
    refreshed = getattr(label, "confidence_refreshed_at", None)
    if refreshed is None:
        refreshed = getattr(label, "last_verified_at", None)

    return apply_decay(
        stored_confidence=getattr(label, "confidence", "medium"),
        added_at=getattr(label, "added_at", None),
        refreshed_at=refreshed,
        now=now,
    )


__all__ = (
    "EFFECTIVE_DECAY_DAYS",
    "apply_decay",
    "apply_decay_to_label",
)
