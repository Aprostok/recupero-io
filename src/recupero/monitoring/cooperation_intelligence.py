"""Exchange / issuer cooperation intelligence (v0.24.0).

The v0.21.0 live-filings work started accumulating per-letter outcome
data in ``freeze_outcomes``. v0.22.0 surfaced per-issuer recovery
priors. v0.23.0 surfaced multi-victim clusters. v0.24.0 is the
strategic layer on top of that data: **cross-case cooperation
intelligence**.

Operators don't just want to know "what happened on this case." They
want to know *how to sequence* their interaction with each issuer
across all cases. Specifically:

  * Tether responds to freeze letters in a median of 31 hours and
    fully freezes 73% of the time → send the letter, expect a quick
    win, allocate operator attention elsewhere meanwhile.
  * Coinbase responds in 72 hours and fully freezes 45% of the time
    → send the letter, prepare a 314(b) escalation in parallel.
  * Binance has never responded in 12 attempts across 8 cases →
    skip the letter, go straight to grand jury subpoena via the
    cooperating AUSA.

Without this layer, every operator re-learns these dynamics on every
case. With it, the Nth case benefits from the lessons of cases
1..N-1.

This module is the compounding-moat capability that distinguishes
Recupero from a single-case forensic tool. The freeze_outcomes
table is the substrate; this module is the strategy surface on top.

Public surface:

  * ``IssuerCooperationProfile`` — dataclass aggregating an issuer's
    full cross-case history into the numbers an operator needs to
    sequence their next move.
  * ``build_cooperation_profile(issuer, dsn)`` — read freeze_outcomes,
    aggregate, return the profile. Pure-function except for the DB read.
  * ``build_all_profiles(dsn)`` — bulk for the dashboard.
  * ``recommend_legal_instrument(profile, jurisdiction)`` — given the
    cooperation profile + the issuer's jurisdiction, return the
    recommended legal instrument (direct_request / fincen_314b /
    mlat / grand_jury_subpoena) with a short reason string.

All DB ops are wrapped — a Supabase outage causes ``build_*`` to
return an empty/default profile so the LE handoff render doesn't
break.
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)


# Outcome categories used by the cooperation aggregator.
_RESPONSE_OUTCOMES = frozenset([
    "acknowledged",
    "request_more_info",
    "declined",
    "partial_freeze",
    "full_freeze",
    "released",
    "returned_to_victim",
])
_POSITIVE_FREEZE_OUTCOMES = frozenset([
    "partial_freeze",
    "full_freeze",
    "returned_to_victim",
])
_FULL_FREEZE_OUTCOMES = frozenset([
    "full_freeze",
    "returned_to_victim",
])
_SILENCE_OUTCOMES = frozenset([
    "silence_14d",
    "silence_30d",
    "silence_90d",
])
_DECLINED_OUTCOMES = frozenset([
    "declined",
])

# Threshold for "is_black_hole" — issuer has received this many or
# more letters AND has never produced a freeze_outcomes row of any
# kind (no response, no decline, nothing). Different from "responded
# but said no" — that's a cooperative no.
_BLACK_HOLE_MIN_LETTERS = 3

# Minimum sample size before we'll express confidence in the
# response_rate / median_response_hours numbers. Below this, the
# profile is "insufficient data" and the LE handoff hides the
# cooperation panel for that issuer.
_MIN_LETTERS_FOR_CONFIDENT_PROFILE = 3


# Recommended legal instrument values — matches the existing
# letter_language CHECK constraint in freeze_letters_sent
# (migration 013) so the recommended instrument can be threaded
# directly into the next letter's letter_language column.
INSTRUMENT_DIRECT_REQUEST = "standard"
INSTRUMENT_LE_BACKED = "le_backed"
INSTRUMENT_AUSA_SIGNED = "ausa_signed"
INSTRUMENT_FINCEN_314B = "314b"
INSTRUMENT_MLAT = "mlat_routed"
INSTRUMENT_GRAND_JURY_SUBPOENA = "subpoena"

VALID_INSTRUMENTS = frozenset([
    INSTRUMENT_DIRECT_REQUEST,
    INSTRUMENT_LE_BACKED,
    INSTRUMENT_AUSA_SIGNED,
    INSTRUMENT_FINCEN_314B,
    INSTRUMENT_MLAT,
    INSTRUMENT_GRAND_JURY_SUBPOENA,
])


@dataclass
class IssuerCooperationProfile:
    """Cross-case cooperation history for one issuer.

    Built by aggregating every ``freeze_letters_sent`` row + its
    associated ``freeze_outcomes`` rows for the issuer. Powers the
    LE handoff Section 5.7 + the standalone cooperation dashboard.
    """
    issuer: str

    # Volume.
    n_letters_sent: int = 0
    n_responded: int = 0       # at least one non-silence outcome
    n_silent: int = 0          # letters with only silence_* outcomes OR no outcome at all yet

    # Outcome rates (0..1). NaN-safe: zero when sample insufficient.
    response_rate: float = 0.0
    full_freeze_rate: float = 0.0
    partial_freeze_rate: float = 0.0
    declined_rate: float = 0.0
    silence_rate: float = 0.0

    # Timing — response hours observed across responded letters.
    median_response_hours: float | None = None
    avg_response_hours: float | None = None
    fastest_response_hours: float | None = None
    slowest_response_hours: float | None = None

    # Frozen $ across the issuer's full history (from outcomes.frozen_usd).
    total_frozen_usd: Decimal = field(default_factory=lambda: Decimal(0))

    # Operational signals.
    is_black_hole: bool = False          # n_letters ≥ MIN AND zero outcomes ever
    has_confident_profile: bool = False  # n_letters ≥ MIN_FOR_CONFIDENT

    # Latest contact timestamps (string ISO) — useful for the dashboard's
    # "most recent activity" column.
    latest_letter_sent_at: str | None = None
    latest_outcome_observed_at: str | None = None


@dataclass(frozen=True)
class InstrumentRecommendation:
    """Output of ``recommend_legal_instrument``."""
    instrument: str          # one of VALID_INSTRUMENTS
    reason: str              # human-readable short reason
    estimated_response_days: int | None  # how long until we expect movement


def build_cooperation_profile(
    issuer: str,
    *,
    dsn: str | None,
) -> IssuerCooperationProfile:
    """Aggregate ``freeze_letters_sent`` + ``freeze_outcomes`` for
    ``issuer`` into a single IssuerCooperationProfile.

    Returns an empty-shape profile (``n_letters_sent=0``, all rates 0)
    when:
      * dsn is None (local CLI emit_brief path) — LE handoff Section 5.7
        renders the "insufficient data" branch
      * DB error during the join — logged at WARN; same empty branch
      * Issuer has never appeared in freeze_letters_sent
    """
    profile = IssuerCooperationProfile(issuer=issuer)
    if not dsn:
        return profile

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return profile

    from recupero._common import db_connect
    from psycopg.rows import dict_row

    sql = """
        SELECT fl.id              AS letter_id,
               fl.sent_at         AS sent_at,
               array_agg(
                   ROW(fo.outcome_type, fo.observed_at, fo.frozen_usd)
                   ORDER BY fo.observed_at ASC
               ) FILTER (WHERE fo.id IS NOT NULL) AS outcomes
          FROM public.freeze_letters_sent fl
          LEFT JOIN public.freeze_outcomes fo ON fo.letter_id = fl.id
         WHERE fl.issuer = %s
         GROUP BY fl.id, fl.sent_at
         ORDER BY fl.sent_at ASC
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, (issuer,))
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "build_cooperation_profile failed for issuer %r: %s",
            issuer, exc,
        )
        return profile

    if not rows:
        return profile

    # Walk each letter, classify by its outcome history.
    response_hours: list[float] = []
    n_full_freeze = 0
    n_partial_freeze = 0
    n_declined = 0
    n_silent_only = 0       # letters where ALL outcomes are silence_* (or none)
    n_responded = 0         # letters with at least one non-silence outcome
    total_frozen = Decimal(0)
    latest_outcome_at: str | None = None
    latest_letter_at: str | None = None

    for row in rows:
        latest_letter_at = (
            row["sent_at"].isoformat() if row.get("sent_at") else latest_letter_at
        )
        outcomes = row.get("outcomes") or []
        if not outcomes:
            n_silent_only += 1
            continue

        # outcomes is a list of tuple-likes (outcome_type, observed_at, frozen_usd)
        # — psycopg renders Postgres ROW types as tuples.
        non_silence = [
            o for o in outcomes
            if o[0] not in _SILENCE_OUTCOMES
        ]
        if not non_silence:
            n_silent_only += 1
            # Even when all outcomes are silence_*, track the most
            # recent so the dashboard can show "last activity".
            for o in outcomes:
                if o[1] and (latest_outcome_at is None or o[1].isoformat() > latest_outcome_at):
                    latest_outcome_at = o[1].isoformat()
            continue

        n_responded += 1
        # First non-silence outcome's time → response time.
        first_resp = non_silence[0]
        if first_resp[1] and row.get("sent_at"):
            delta = first_resp[1] - row["sent_at"]
            response_hours.append(delta.total_seconds() / 3600)

        # Pick the strongest outcome for the categorization.
        outcome_types = {o[0] for o in non_silence}
        if outcome_types & _FULL_FREEZE_OUTCOMES:
            n_full_freeze += 1
        elif "partial_freeze" in outcome_types:
            n_partial_freeze += 1
        elif outcome_types & _DECLINED_OUTCOMES:
            n_declined += 1

        # Track total frozen USD across the issuer's full history.
        for o in outcomes:
            if o[2] is not None and o[0] in _POSITIVE_FREEZE_OUTCOMES:
                try:
                    total_frozen += Decimal(str(o[2]))
                except Exception:  # noqa: BLE001
                    pass
            if o[1] and (latest_outcome_at is None or o[1].isoformat() > latest_outcome_at):
                latest_outcome_at = o[1].isoformat()

    profile.n_letters_sent = len(rows)
    profile.n_responded = n_responded
    profile.n_silent = n_silent_only
    profile.total_frozen_usd = total_frozen
    profile.latest_letter_sent_at = latest_letter_at
    profile.latest_outcome_observed_at = latest_outcome_at

    if profile.n_letters_sent > 0:
        profile.response_rate = n_responded / profile.n_letters_sent
        profile.full_freeze_rate = n_full_freeze / profile.n_letters_sent
        profile.partial_freeze_rate = n_partial_freeze / profile.n_letters_sent
        profile.declined_rate = n_declined / profile.n_letters_sent
        profile.silence_rate = n_silent_only / profile.n_letters_sent

    if response_hours:
        profile.median_response_hours = float(statistics.median(response_hours))
        profile.avg_response_hours = float(statistics.mean(response_hours))
        profile.fastest_response_hours = float(min(response_hours))
        profile.slowest_response_hours = float(max(response_hours))

    profile.has_confident_profile = (
        profile.n_letters_sent >= _MIN_LETTERS_FOR_CONFIDENT_PROFILE
    )
    profile.is_black_hole = (
        profile.n_letters_sent >= _BLACK_HOLE_MIN_LETTERS
        and n_responded == 0
    )
    return profile


def build_all_profiles(dsn: str | None) -> dict[str, IssuerCooperationProfile]:
    """Bulk-build cooperation profiles for every issuer that has at
    least one ``freeze_letters_sent`` row. Used by the cooperation
    dashboard renderer.

    Returns an empty dict when no DSN / no letters / DB error.
    """
    if not dsn:
        return {}
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return {}
    from recupero._common import db_connect

    profiles: dict[str, IssuerCooperationProfile] = {}
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT issuer FROM public.freeze_letters_sent"
            )
            issuers = [r[0] for r in cur.fetchall() if r[0]]
    except Exception as exc:  # noqa: BLE001
        log.warning("build_all_profiles: distinct-issuer query failed: %s", exc)
        return {}

    for issuer in issuers:
        profiles[issuer] = build_cooperation_profile(issuer, dsn=dsn)
    return profiles


def recommend_legal_instrument(
    profile: IssuerCooperationProfile,
    *,
    jurisdiction: str | None = None,
    ofac_exposed: bool = False,
    ic3_case_id: str | None = None,
) -> InstrumentRecommendation:
    """Recommend the right legal instrument given an issuer's
    cooperation history + jurisdiction + sanctions exposure.

    Logic (high to low precedence):

      1. OFAC-exposed counterparties → grand jury subpoena. The
         compliance team's hands are tied for direct freeze; only
         a court order surmounts the sanctions overlay.
      2. Black hole (≥3 letters, zero outcomes) → grand jury
         subpoena. Direct letters demonstrably don't work for this
         issuer.
      3. Non-US jurisdiction + low response_rate → MLAT via DOJ-OIA.
         Direct + 314(b) both require US jurisdiction over the issuer.
      4. US jurisdiction + low response_rate → FinCEN 314(b)
         information-sharing request. Authority comes from the
         Patriot Act; bypasses the issuer's discretion.
      5. Confident profile with response_rate ≥ 0.5 → standard
         direct request, optionally LE-backed if an IC3 number is
         on file (le_backed letters land faster).
      6. No confident profile yet → standard direct request with
         a "first letter to this issuer" caveat.
    """
    # Precedence #1 — OFAC.
    if ofac_exposed:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_GRAND_JURY_SUBPOENA,
            reason=(
                "OFAC-exposed counterparty — compliance teams cannot "
                "act without a court order due to the sanctions "
                "overlay. Grand jury subpoena via the cooperating "
                "AUSA is the only viable path."
            ),
            estimated_response_days=30,
        )

    # Precedence #2 — Black hole.
    if profile.is_black_hole:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_GRAND_JURY_SUBPOENA,
            reason=(
                f"{profile.issuer} has received {profile.n_letters_sent} "
                "informal freeze requests across prior cases with zero "
                "responses of any kind. Direct letters demonstrably do "
                "not produce results for this issuer; recommend skipping "
                "the informal channel entirely and proceeding directly "
                "to a grand jury subpoena."
            ),
            estimated_response_days=45,
        )

    jurisdiction_lc = (jurisdiction or "").lower().strip()
    is_non_us = (
        jurisdiction_lc != ""
        and "us" not in jurisdiction_lc
        and "united states" not in jurisdiction_lc
    )

    low_response = (
        profile.has_confident_profile
        and profile.response_rate < 0.30
    )

    # Precedence #3 — Non-US + low cooperation → MLAT.
    if is_non_us and low_response:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_MLAT,
            reason=(
                f"{profile.issuer} is in {jurisdiction or 'a non-US'} "
                f"jurisdiction with a {profile.response_rate*100:.0f}% "
                f"response rate across {profile.n_letters_sent} prior "
                "informal requests. MLAT routing via DOJ-OIA is the "
                "appropriate channel; direct + 314(b) require US "
                "jurisdiction over the issuer."
            ),
            estimated_response_days=120,
        )

    # Precedence #4 — US + low cooperation → 314(b).
    if low_response and not is_non_us:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_FINCEN_314B,
            reason=(
                f"{profile.issuer} has a {profile.response_rate*100:.0f}% "
                f"response rate across {profile.n_letters_sent} prior "
                "informal requests. A FinCEN 314(b) information-sharing "
                "request bypasses the issuer's discretion — the "
                "authority comes from the Patriot Act, not from the "
                "issuer's compliance team's willingness to engage."
            ),
            estimated_response_days=21,
        )

    # Precedence #5 — Good cooperation, LE-backed.
    if profile.has_confident_profile and profile.response_rate >= 0.50 and ic3_case_id:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_LE_BACKED,
            reason=(
                f"{profile.issuer} responds to direct freeze requests "
                f"{profile.response_rate*100:.0f}% of the time (sample "
                f"size {profile.n_letters_sent}) with a median response "
                f"time of {profile.median_response_hours:.0f} hours when "
                "they do. With the IC3 reference on file, an LE-backed "
                "letter typically lands faster than a standard request."
            ),
            estimated_response_days=max(2, int((profile.median_response_hours or 24) / 24)),
        )

    # Precedence #5 (cont.) — Good cooperation, no IC3.
    if profile.has_confident_profile and profile.response_rate >= 0.50:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_DIRECT_REQUEST,
            reason=(
                f"{profile.issuer} responds to direct freeze requests "
                f"{profile.response_rate*100:.0f}% of the time across "
                f"{profile.n_letters_sent} prior cases. Standard "
                "letter format is appropriate."
            ),
            estimated_response_days=max(2, int((profile.median_response_hours or 72) / 24)),
        )

    # Precedence #6 — No confident profile yet (insufficient sample).
    return InstrumentRecommendation(
        instrument=INSTRUMENT_DIRECT_REQUEST,
        reason=(
            f"{profile.issuer} has {profile.n_letters_sent} prior letter"
            f"{'s' if profile.n_letters_sent != 1 else ''} on file — "
            "insufficient sample to compute a confident cooperation "
            "profile (≥3 required). Standard direct request is the "
            "default starting position; revisit instrument choice "
            "after the next outcome lands."
        ),
        estimated_response_days=None,
    )


__all__ = (
    "IssuerCooperationProfile",
    "InstrumentRecommendation",
    "INSTRUMENT_DIRECT_REQUEST",
    "INSTRUMENT_LE_BACKED",
    "INSTRUMENT_FINCEN_314B",
    "INSTRUMENT_MLAT",
    "INSTRUMENT_GRAND_JURY_SUBPOENA",
    "VALID_INSTRUMENTS",
    "build_cooperation_profile",
    "build_all_profiles",
    "recommend_legal_instrument",
)
