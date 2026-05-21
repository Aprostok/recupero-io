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

    # v0.24.1 (audit-fix CRIT-1): replaced `array_agg(ROW(...))` with
    # a flat LEFT JOIN. Pre-v0.24.1 psycopg's default text-mode
    # RecordLoader returned the anonymous ROW composite as
    # tuple[str, str, str] (every field as a string), so downstream
    # code that did `first_resp[1] - row["sent_at"]` (datetime
    # arithmetic on a string) raised TypeError mid-loop. The entire
    # cooperation feature was dead-on-arrival in production. Tests
    # passed because they fed real datetime/Decimal-typed tuples
    # directly, bypassing the psycopg deserialization layer.
    #
    # Flat scalar columns are returned with proper Python types
    # (datetime, Decimal) — no composite deserialization required.
    sql = """
        -- PUNISH-B F-1: include returned_usd so the aggregator can
        -- COALESCE returned_usd → frozen_usd for returned_to_victim
        -- outcomes. The canonical operator workflow when funds clear
        -- back to the victim is to set returned_usd=$X and leave
        -- frozen_usd NULL — pre-fix the cooperation profile
        -- contributed $0 for every successful return, making the
        -- per-issuer total_frozen a permanent undercount.
        SELECT fl.id                AS letter_id,
               fl.sent_at           AS sent_at,
               fo.outcome_type      AS outcome_type,
               fo.observed_at       AS observed_at,
               fo.frozen_usd        AS frozen_usd,
               fo.returned_usd      AS returned_usd
          FROM public.freeze_letters_sent fl
          LEFT JOIN public.freeze_outcomes fo ON fo.letter_id = fl.id
         WHERE fl.issuer = %s
         ORDER BY fl.id, fo.observed_at ASC
    """

    # v0.24.1 (audit-fix MED-3): wrap the ENTIRE aggregation loop in
    # the try/except. Pre-v0.24.1 only the cursor was wrapped — any
    # data-shape error in the loop propagated to the caller,
    # violating the function's "Supabase outage → empty profile"
    # contract.
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, (issuer,))
            rows = cur.fetchall()

        if not rows:
            return profile

        # Group flat rows by letter_id (CRIT-1 fix companion).
        # PUNISH-B F-1: tuple now carries returned_usd as the 4th
        # element so the strongest-outcome aggregator below can
        # COALESCE returned_usd → frozen_usd for returned_to_victim
        # entries (where frozen_usd is NULL by operator convention).
        from collections import OrderedDict
        letters: OrderedDict = OrderedDict()
        for row in rows:
            lid = row["letter_id"]
            if lid not in letters:
                letters[lid] = {
                    "sent_at": row["sent_at"],
                    # list of (outcome_type, observed_at,
                    #         frozen_usd, returned_usd)
                    "outcomes": [],
                }
            if row.get("outcome_type") is not None:
                letters[lid]["outcomes"].append((
                    row["outcome_type"],
                    row["observed_at"],
                    row["frozen_usd"],
                    row.get("returned_usd"),
                ))

        # Walk each letter, classify by its outcome history.
        # v0.24.1 (audit-fix HIGH-1): track time-to-first-FREEZE
        # separately from time-to-first-engagement. The published
        # `median_response_hours` is the time to first FREEZE-action
        # outcome (partial_freeze / full_freeze / returned_to_victim)
        # — what an AUSA / FBI agent actually wants to know — not
        # the time to acknowledgment.
        freeze_response_hours: list[float] = []
        n_full_freeze = 0
        n_partial_freeze = 0
        n_declined = 0
        n_silent_only = 0
        n_responded = 0
        total_frozen = Decimal(0)
        latest_outcome_at: str | None = None
        latest_letter_at: str | None = None

        for letter in letters.values():
            sent_at = letter["sent_at"]
            if sent_at is not None:
                iso = sent_at.isoformat()
                if latest_letter_at is None or iso > latest_letter_at:
                    latest_letter_at = iso

            outcomes = letter["outcomes"]
            if not outcomes:
                n_silent_only += 1
                continue

            non_silence = [o for o in outcomes if o[0] not in _SILENCE_OUTCOMES]
            if not non_silence:
                n_silent_only += 1
                for o in outcomes:
                    if o[1] is not None:
                        iso = o[1].isoformat()
                        if latest_outcome_at is None or iso > latest_outcome_at:
                            latest_outcome_at = iso
                continue

            n_responded += 1

            # Time to first FREEZE-ACTION outcome (HIGH-1).
            first_freeze = next(
                (o for o in non_silence if o[0] in _POSITIVE_FREEZE_OUTCOMES),
                None,
            )
            if first_freeze and first_freeze[1] is not None and sent_at is not None:
                delta = first_freeze[1] - sent_at
                freeze_response_hours.append(delta.total_seconds() / 3600)

            # Pick the strongest outcome for the categorization (already
            # correct in v0.24.0 — preserved here).
            outcome_types = {o[0] for o in non_silence}
            if outcome_types & _FULL_FREEZE_OUTCOMES:
                n_full_freeze += 1
            elif "partial_freeze" in outcome_types:
                n_partial_freeze += 1
            elif outcome_types & _DECLINED_OUTCOMES:
                n_declined += 1

            # v0.24.1 (audit-fix CRIT-3): pick the STRONGEST positive
            # outcome's frozen_usd as this letter's contribution to the
            # cluster aggregate. Pre-v0.24.1 we summed across ALL
            # positive outcomes per letter — a letter that progressed
            # partial_freeze($500K) → full_freeze($1M) → returned($1M)
            # accumulated $2.5M when the true frozen amount is $1M
            # (the documented happy-path outcome chain per
            # migration 013).
            strongest_frozen: Decimal | None = None
            # Strength order: returned_to_victim > full_freeze > partial_freeze.
            # PUNISH-B F-1: COALESCE(frozen_usd, returned_usd). The
            # returned_to_victim outcome's frozen_usd column is
            # operationally NULL when funds clear (per migration 013
            # convention) — without this fallback the issuer's
            # cooperation profile shows $0 frozen for every successful
            # return chain, permanently undercounting the best wins.
            for strength_label in ("returned_to_victim", "full_freeze", "partial_freeze"):
                for o in non_silence:
                    if o[0] != strength_label:
                        continue
                    # Try frozen_usd first; fall back to returned_usd.
                    candidate = o[2] if o[2] is not None else o[3]
                    if candidate is None:
                        continue
                    try:
                        strongest_frozen = Decimal(str(candidate))
                        break
                    except Exception:  # noqa: BLE001
                        pass
                if strongest_frozen is not None:
                    break
            if strongest_frozen is not None:
                total_frozen += strongest_frozen

            for o in outcomes:
                if o[1] is not None:
                    iso = o[1].isoformat()
                    if latest_outcome_at is None or iso > latest_outcome_at:
                        latest_outcome_at = iso

        profile.n_letters_sent = len(letters)
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

        if freeze_response_hours:
            profile.median_response_hours = float(statistics.median(freeze_response_hours))
            profile.avg_response_hours = float(statistics.mean(freeze_response_hours))
            profile.fastest_response_hours = float(min(freeze_response_hours))
            profile.slowest_response_hours = float(max(freeze_response_hours))

        profile.has_confident_profile = (
            profile.n_letters_sent >= _MIN_LETTERS_FOR_CONFIDENT_PROFILE
        )
        profile.is_black_hole = (
            profile.n_letters_sent >= _BLACK_HOLE_MIN_LETTERS
            and n_responded == 0
        )
        return profile

    except Exception as exc:  # noqa: BLE001
        log.warning(
            "build_cooperation_profile failed for issuer %r (returning "
            "empty profile so caller can render gracefully): %s",
            issuer, exc,
        )
        return IssuerCooperationProfile(issuer=issuer)


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

    # v0.24.1 (audit-fix HIGH-3): wrap each per-issuer build so one
    # poison row can't crash the whole dashboard. build_cooperation_profile
    # already catches its own SQL errors, but defensive in case a future
    # change introduces an unhandled path.
    for issuer in issuers:
        try:
            profiles[issuer] = build_cooperation_profile(issuer, dsn=dsn)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "build_all_profiles: skipping issuer %r due to error: %s",
                issuer, exc,
            )
            profiles[issuer] = IssuerCooperationProfile(issuer=issuer)
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

    # v0.24.1 (audit-fix CRIT-2): the pre-v0.24.1 substring match
    # `"us" not in jurisdiction_lc` matched Russia, Belarus, Cyprus,
    # Mauritius, Australia, Caucasus, Belarus → low-cooperation
    # issuers in those jurisdictions got recommended FinCEN 314(b)
    # (a US Patriot Act instrument with ZERO force outside the US)
    # instead of the correct MLAT route. The LE handoff would read
    # as operationally illiterate to the FBI/AUSA. Fix: explicit
    # US whitelist matched against tokenized words, not substrings.
    jurisdiction_lc = (jurisdiction or "").lower().strip()
    # Strip punctuation that operators commonly use ("U.S.", "(US)", etc.)
    # then tokenize so "United States" matches but "Belarus" doesn't.
    _jur_norm = jurisdiction_lc.replace(".", " ").replace(",", " ")
    _jur_norm = _jur_norm.replace("(", " ").replace(")", " ")
    _jur_tokens = set(_jur_norm.split())
    _US_TOKEN_MATCHES = frozenset({
        "us", "usa", "u s a",
        "america", "united states",
        # Common state-level surface forms operators paste in:
        "delaware", "new york", "california", "nevada", "wyoming",
        "florida", "texas", "massachusetts",
    })
    # An exact-token match against "us"/"usa" OR a substring match
    # against any multi-word phrase ("united states", "u s a", etc).
    is_us = bool(
        _jur_tokens & {"us", "usa", "america"}
    ) or any(phrase in _jur_norm for phrase in (
        "united states", "u s a", "u.s.a",
    ))
    is_non_us = jurisdiction_lc != "" and not is_us

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

    # v0.24.1 (audit-fix MED-1): the f-string `:.0f` format spec
    # raises TypeError when median_response_hours is None. Compute
    # a safe display fragment once and reuse it across branches.
    if profile.median_response_hours is not None:
        _median_display = f"{profile.median_response_hours:.0f} hours"
    else:
        _median_display = "an unknown response time (no priced timing data)"
    # Estimated response days from median; None-safe.
    if profile.median_response_hours is not None:
        _est_resp_days_from_median = max(2, int(profile.median_response_hours / 24))
    else:
        _est_resp_days_from_median = None

    # Precedence #5 — Good cooperation, LE-backed.
    if profile.has_confident_profile and profile.response_rate >= 0.50 and ic3_case_id:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_LE_BACKED,
            reason=(
                f"{profile.issuer} responds to direct freeze requests "
                f"{profile.response_rate*100:.0f}% of the time (sample "
                f"size {profile.n_letters_sent}) with a median response "
                f"time of {_median_display} when they do. With the "
                "IC3 reference on file, an LE-backed letter typically "
                "lands faster than a standard request."
            ),
            estimated_response_days=_est_resp_days_from_median or 7,
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
            estimated_response_days=_est_resp_days_from_median or 14,
        )

    # v0.24.1 (audit-fix HIGH-2): explicit precedence-5c for the
    # confident-but-medium-response gap (0.30 ≤ response_rate < 0.50).
    # Pre-v0.24.1 this case fell through to the precedence-6
    # "insufficient sample" branch — the reason text contradicted
    # itself ("Coinbase has 10 letters on file — insufficient sample"
    # when the sample IS sufficient at ≥3).
    if profile.has_confident_profile and 0.30 <= profile.response_rate < 0.50:
        return InstrumentRecommendation(
            instrument=INSTRUMENT_DIRECT_REQUEST,
            reason=(
                f"{profile.issuer} has a moderate "
                f"{profile.response_rate*100:.0f}% historical response "
                f"rate across {profile.n_letters_sent} prior letters. "
                "A standard direct request is the appropriate starting "
                "position; consider escalating to FinCEN 314(b) (US "
                "jurisdiction) or MLAT (non-US) if no response within "
                "seven days."
            ),
            estimated_response_days=_est_resp_days_from_median or 14,
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
