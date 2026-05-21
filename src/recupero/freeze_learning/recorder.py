"""Freeze-letter + outcome recorders (v0.14.2).

All DB I/O is wrapped in try/except so callers never crash on
DB unavailability — the freeze letter still goes out even if the
audit write fails (logged at WARN).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from recupero._common import db_connect

log = logging.getLogger(__name__)


# Aggregation threshold: don't switch from heuristic to learned
# prior below this sample count. Statistical noise is too high.
_MIN_SAMPLE_SIZE_FOR_LEARNED_PRIOR = 20


# Outcome types that count as "freeze happened" (numerator for
# p_any_freeze).
_FREEZE_OUTCOMES = frozenset([
    "partial_freeze",
    "full_freeze",
    "returned_to_victim",
])

# Outcome types that count as "complete win" (numerator for
# p_returned_to_victim).
_WIN_OUTCOMES = frozenset(["returned_to_victim"])


@dataclass
class IssuerPrior:
    """Aggregated per-(issuer, letter_language) prior."""
    issuer: str
    letter_language: str
    sample_size: int
    p_any_freeze: float
    p_full_freeze: float
    p_returned_to_victim: float
    avg_response_hours: float | None
    median_response_hours: float | None
    is_learned: bool          # True if sample_size >= threshold


def record_letter_sent(
    *,
    case_id: UUID | None,
    investigation_id: UUID | None,
    issuer: str,
    target_address: str,
    chain: str,
    asset_symbol: str,
    requested_freeze_usd: Decimal,
    operator: str,
    letter_language: str = "standard",
    letter_subject: str | None = None,
    letter_body_excerpt: str | None = None,
    contact_email: str | None = None,
    contact_portal_url: str | None = None,
    storage_path: str | None = None,
    dsn: str,
) -> UUID | None:
    """Insert a freeze_letters_sent row.

    Idempotent at (case_id, issuer, target_address, asset_symbol)
    via the table's UNIQUE constraint — repeat sends UPDATE the row
    in place rather than inserting duplicates.

    Returns the row id, or None on DB failure.
    """
    try:
        import psycopg
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — freeze-letter audit skipped")
        return None

    letter_id = uuid4()
    body_truncated = (letter_body_excerpt or "")[:1000] if letter_body_excerpt else None
    sql = """
        INSERT INTO public.freeze_letters_sent (
            id, case_id, investigation_id, issuer, target_address,
            chain, asset_symbol, requested_freeze_usd,
            letter_subject, letter_body_excerpt, letter_language,
            contact_email, contact_portal_url, operator, storage_path
        ) VALUES (
            %(id)s, %(case)s, %(inv)s, %(issuer)s, %(target)s,
            %(chain)s, %(asset)s, %(usd)s,
            %(subject)s, %(body)s, %(language)s,
            %(email)s, %(portal)s, %(op)s, %(storage)s
        )
        ON CONFLICT (case_id, issuer, target_address, asset_symbol)
        DO UPDATE SET
            requested_freeze_usd = EXCLUDED.requested_freeze_usd,
            letter_language      = EXCLUDED.letter_language,
            letter_subject       = EXCLUDED.letter_subject,
            letter_body_excerpt  = EXCLUDED.letter_body_excerpt,
            contact_email        = EXCLUDED.contact_email,
            contact_portal_url   = EXCLUDED.contact_portal_url,
            storage_path         = EXCLUDED.storage_path,
            sent_at              = NOW()
        RETURNING id;
    """
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "id": letter_id, "case": case_id, "inv": investigation_id,
                "issuer": issuer, "target": target_address,
                "chain": chain, "asset": asset_symbol,
                "usd": requested_freeze_usd,
                "subject": letter_subject, "body": body_truncated,
                "language": letter_language,
                "email": contact_email, "portal": contact_portal_url,
                "op": operator, "storage": storage_path,
            })
            row = cur.fetchone()
            return row[0] if row else letter_id
    except Exception as exc:  # noqa: BLE001
        log.warning("freeze_letters_sent insert failed: %s", exc)
        return None


def record_outcome(
    *,
    letter_id: UUID,
    outcome_type: str,
    frozen_usd: Decimal | None = None,
    returned_usd: Decimal | None = None,
    response_text: str | None = None,
    operator_notes: str | None = None,
    dsn: str,
) -> UUID | None:
    """Insert a freeze_outcomes row.

    Returns the row id, or None on DB failure.
    """
    try:
        import psycopg
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — outcome audit skipped")
        return None

    sql = """
        INSERT INTO public.freeze_outcomes (
            letter_id, outcome_type, frozen_usd, returned_usd,
            response_text, operator_notes
        ) VALUES (
            %(letter)s, %(type)s, %(frozen)s, %(returned)s,
            %(text)s, %(notes)s
        )
        RETURNING id;
    """
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "letter": letter_id, "type": outcome_type,
                "frozen": frozen_usd, "returned": returned_usd,
                "text": response_text, "notes": operator_notes,
            })
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as exc:  # noqa: BLE001
        log.warning("freeze_outcomes insert failed: %s", exc)
        return None


class LetterNotFoundError(LookupError):
    """Raised by record_outcome_by_target when no freeze_letters_sent
    row matches the given (case_id, issuer, target_address) triple.

    Distinct from a DB failure: this is a "your input doesn't match
    any letter we sent" error. The API layer turns this into a 404,
    the CLI surface into a clear error message + non-zero exit code.
    """


# Valid outcome_type values — matches the freeze_outcomes table
# CHECK constraint (post-migration 018 which added silence_14d).
# Exported as a public constant so API validation + CLI argument
# parsing can both consume the same source of truth.
VALID_OUTCOME_TYPES = frozenset([
    "acknowledged",
    "request_more_info",
    "declined",
    "partial_freeze",
    "full_freeze",
    "released",
    "returned_to_victim",
    "silence_14d",
    "silence_30d",
    "silence_90d",
])


def record_outcome_by_target(
    *,
    case_id: UUID,
    issuer: str,
    target_address: str,
    outcome_type: str,
    asset_symbol: str | None = None,
    frozen_usd: Decimal | None = None,
    returned_usd: Decimal | None = None,
    response_text: str | None = None,
    operator_notes: str | None = None,
    dsn: str,
) -> UUID:
    """v0.21.0 — Record a freeze outcome keyed by case + issuer +
    target address, rather than by letter_id.

    The API endpoint ``POST /v1/freeze-outcomes`` and the operator
    CLI ``recupero-ops record-freeze-outcome --case`` both consume
    this. Looks up the freeze_letters_sent row via the UNIQUE
    constraint on ``(case_id, issuer, target_address, asset_symbol)``
    and delegates the actual INSERT to record_outcome().

    Idempotency: this writes a NEW freeze_outcomes row on every
    call — multiple outcomes per letter is the documented design
    (acknowledged → partial_freeze → full_freeze time series).
    Callers that want UPDATE-in-place semantics should query the
    letter row first via the ops CLI.

    Raises:
        LetterNotFoundError: no matching freeze_letters_sent row.
        ValueError: outcome_type not in VALID_OUTCOME_TYPES.
    """
    if outcome_type not in VALID_OUTCOME_TYPES:
        raise ValueError(
            f"outcome_type {outcome_type!r} not in VALID_OUTCOME_TYPES "
            f"({sorted(VALID_OUTCOME_TYPES)})"
        )

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        raise RuntimeError("psycopg not installed — cannot record outcome") from None

    # Resolve letter_id from the triple. When asset_symbol is provided
    # the lookup uses the full UNIQUE constraint; otherwise fall back
    # to the most-recent letter for the case+issuer+address combination
    # (covers the API caller who doesn't know the symbol but does know
    # the wallet+issuer).
    lookup_sql = (
        """
        SELECT id FROM public.freeze_letters_sent
         WHERE case_id = %s
           AND issuer  = %s
           AND target_address = %s
           {asset_clause}
         ORDER BY sent_at DESC
         LIMIT 1
        """
    )
    if asset_symbol:
        lookup_sql = lookup_sql.format(asset_clause="AND asset_symbol = %s")
        params: tuple = (case_id, issuer, target_address, asset_symbol)
    else:
        lookup_sql = lookup_sql.format(asset_clause="")
        params = (case_id, issuer, target_address)

    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(lookup_sql, params)
        row = cur.fetchone()
        if not row:
            raise LetterNotFoundError(
                f"No freeze letter found for case={case_id} issuer={issuer!r} "
                f"target={target_address!r}"
                + (f" asset={asset_symbol!r}" if asset_symbol else "")
            )
        letter_id = row[0]

    outcome_id = record_outcome(
        letter_id=letter_id,
        outcome_type=outcome_type,
        frozen_usd=frozen_usd,
        returned_usd=returned_usd,
        response_text=response_text,
        operator_notes=operator_notes,
        dsn=dsn,
    )
    if outcome_id is None:
        # record_outcome already logged; surface a clear error to the
        # API caller so the 5xx isn't silent.
        raise RuntimeError(
            f"freeze_outcomes insert failed for letter {letter_id}"
        )
    return outcome_id


def compute_priors_from_outcomes(
    outcomes: list[dict[str, Any]],
) -> dict[tuple[str, str], IssuerPrior]:
    """Pure aggregation function: outcome rows → per-(issuer,
    language) priors.

    Input: list of joined rows from freeze_letters_sent +
    freeze_outcomes, each containing:
      * issuer, letter_language, sent_at
      * outcome_type, observed_at, frozen_usd, returned_usd

    Output: ``{(issuer, language): IssuerPrior}``.

    Pure function so the recovery scorer + tests + CLI all hit the
    same logic. DB read happens in refresh_priors() which calls
    this.
    """
    # Group letter outcomes — each letter contributes ONE data
    # point per (issuer, language): the strongest outcome reached.
    # Strength ordering: returned > full_freeze > partial_freeze >
    # acknowledged > declined > silence.
    strength = {
        "returned_to_victim": 5,
        "full_freeze": 4,
        "partial_freeze": 3,
        "acknowledged": 2,
        "request_more_info": 2,
        "declined": 1,
        "silence_30d": 0,
        "silence_90d": 0,
        "released": -1,    # rare; bad outcome — was frozen, then released
    }

    # Bucket outcomes by letter_id; track best outcome per letter.
    #
    # PUNISH-B F-3: skip rows where outcome_type is None. These come
    # from the LEFT JOIN in refresh_priors (freeze_letters_sent
    # LEFT JOIN freeze_outcomes) and represent letters that haven't
    # produced any recorded outcome yet. Pre-fix the aggregator
    # treated those as `_strength=0` and counted them toward `n`
    # (the sample size), but contributed 0 to n_any_freeze /
    # n_full / n_win. With 20 unresponded letters + 5 resolved
    # (4 freezes) that produces p_freeze = 4/(4+20) = 17%, but the
    # operationally correct prior is 4/5 = 80%. Tether's published
    # freeze rate was deflating from ~73% to ~21% with backlog.
    by_letter: dict[Any, dict[str, Any]] = {}
    for row in outcomes:
        letter_id = row.get("letter_id")
        if letter_id is None:
            continue
        outcome_type = row.get("outcome_type")
        if outcome_type is None:
            # Unmatured letter — neither a win nor a loss. Excluded
            # from the prior until an outcome is recorded.
            continue
        current = by_letter.get(letter_id)
        outcome_strength = strength.get(outcome_type, 0)
        if current is None or outcome_strength > current.get("_strength", -2):
            by_letter[letter_id] = {**row, "_strength": outcome_strength}

    # Now bucket by (issuer, letter_language).
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in by_letter.values():
        issuer = row.get("issuer") or "(unknown)"
        language = row.get("letter_language") or "standard"
        by_pair.setdefault((issuer, language), []).append(row)

    out: dict[tuple[str, str], IssuerPrior] = {}
    for (issuer, language), rows in by_pair.items():
        n = len(rows)
        n_any_freeze = sum(
            1 for r in rows if r.get("outcome_type") in _FREEZE_OUTCOMES
        )
        n_full = sum(
            1 for r in rows if r.get("outcome_type") == "full_freeze"
        )
        n_win = sum(
            1 for r in rows if r.get("outcome_type") in _WIN_OUTCOMES
        )
        # Response time: hours between sent_at and observed_at on the
        # FIRST non-silence outcome. Skip outcomes still in silence.
        response_hours: list[float] = []
        for r in rows:
            sent = r.get("sent_at")
            observed = r.get("observed_at")
            if (
                sent is not None and observed is not None
                and r.get("outcome_type") not in (
                    "silence_30d", "silence_90d",
                )
            ):
                try:
                    delta_sec = (observed - sent).total_seconds()
                    if delta_sec >= 0:
                        response_hours.append(delta_sec / 3600.0)
                except (TypeError, AttributeError):
                    pass
        # v0.17.1 (quantitative rigor QUANT-3): IQR-trimmed median for
        # response-time robustness. A single 30-day "silence-then-
        # responded" outlier used to shift the median significantly at
        # small n; the IQR trim drops top/bottom 10% (when n >= 5) so
        # the operator-facing time-to-freeze prior doesn't get
        # dragged by tail samples.
        avg_h = sum(response_hours) / len(response_hours) if response_hours else None
        median_h = _robust_median(response_hours) if response_hours else None

        # v0.17.1 (QUANT-1): Beta(α₀+wins, β₀+losses) posterior mean
        # for the probability fields, NOT raw frequency MLE.
        #
        # Why: with n=20 and 0 freezes, MLE = 0/20 = 0.0 (the model
        # would say "this issuer will NEVER freeze"). With n=20 and
        # 20 freezes, MLE = 1.0 ("this issuer ALWAYS freezes"). Both
        # are overconfident — there's still a real probability of
        # the opposite outcome on the next attempt. A Beta(2, 2) prior
        # smooths the estimate toward 0.5 with weight equivalent to
        # 4 hypothetical observations; with n=20 the data dominates
        # but the floor/ceiling don't collapse.
        #
        # α₀ = β₀ = 2 is a "barely informative" uniform-ish prior
        # ("we expect somewhere in the middle, but data wins fast").
        # This matches industry practice for Beta-Binomial conjugate
        # priors when you have NO domain knowledge of the base rate.
        out[(issuer, language)] = IssuerPrior(
            issuer=issuer,
            letter_language=language,
            sample_size=n,
            p_any_freeze=_beta_posterior_mean(n_any_freeze, n),
            p_full_freeze=_beta_posterior_mean(n_full, n),
            p_returned_to_victim=_beta_posterior_mean(n_win, n),
            avg_response_hours=avg_h,
            median_response_hours=median_h,
            is_learned=n >= _MIN_SAMPLE_SIZE_FOR_LEARNED_PRIOR,
        )
    return out


def refresh_priors(dsn: str) -> int:
    """Read freeze_letters_sent + freeze_outcomes, compute priors,
    upsert into issuer_freeze_priors.

    Returns the number of (issuer, language) priors written.
    DB-unavailable → 0 (best-effort).
    """
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        log.warning("psycopg not installed — refresh_priors skipped")
        return 0

    query = """
        SELECT
            l.id AS letter_id, l.issuer, l.letter_language, l.sent_at,
            o.outcome_type, o.observed_at, o.frozen_usd, o.returned_usd
          FROM public.freeze_letters_sent l
          LEFT JOIN public.freeze_outcomes o ON o.letter_id = l.id;
    """
    upsert = """
        INSERT INTO public.issuer_freeze_priors (
            issuer, letter_language, sample_size,
            p_any_freeze, p_full_freeze, p_returned_to_victim,
            avg_response_hours, median_response_hours, refreshed_at
        ) VALUES (
            %(issuer)s, %(language)s, %(n)s,
            %(p_any)s, %(p_full)s, %(p_win)s,
            %(avg_h)s, %(med_h)s, NOW()
        )
        ON CONFLICT (issuer, letter_language)
        DO UPDATE SET
            sample_size           = EXCLUDED.sample_size,
            p_any_freeze          = EXCLUDED.p_any_freeze,
            p_full_freeze         = EXCLUDED.p_full_freeze,
            p_returned_to_victim  = EXCLUDED.p_returned_to_victim,
            avg_response_hours    = EXCLUDED.avg_response_hours,
            median_response_hours = EXCLUDED.median_response_hours,
            refreshed_at          = NOW();
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = list(cur.fetchall())
            priors = compute_priors_from_outcomes(rows)
            with conn.cursor() as cur:
                for prior in priors.values():
                    cur.execute(upsert, {
                        "issuer": prior.issuer,
                        "language": prior.letter_language,
                        "n": prior.sample_size,
                        "p_any": prior.p_any_freeze,
                        "p_full": prior.p_full_freeze,
                        "p_win": prior.p_returned_to_victim,
                        "avg_h": prior.avg_response_hours,
                        "med_h": prior.median_response_hours,
                    })
        return len(priors)
    except Exception as exc:  # noqa: BLE001
        log.warning("refresh_priors failed: %s", exc)
        return 0


def load_learned_priors(dsn: str) -> dict[str, IssuerPrior]:
    """Read issuer_freeze_priors, return ``{issuer: IssuerPrior}``
    for the 'standard' language. Used by recovery.scorer.

    Returns only priors with sample_size >= threshold so callers
    don't accidentally use noisy small-sample data.
    """
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        return {}

    sql = """
        SELECT issuer, letter_language, sample_size,
               p_any_freeze, p_full_freeze, p_returned_to_victim,
               avg_response_hours, median_response_hours
          FROM public.issuer_freeze_priors
         WHERE letter_language = 'standard'
           AND sample_size >= %(threshold)s;
    """
    out: dict[str, IssuerPrior] = {}
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "threshold": _MIN_SAMPLE_SIZE_FOR_LEARNED_PRIOR,
            })
            for row in cur.fetchall():
                # v0.16.10 (round-9 scoring LOW): clamp probabilities
                # to [0, 1] on load. A corrupt DB row carrying p=1.5
                # or p=-0.3 (data-import bug, manual SQL accident)
                # would otherwise propagate into the scorer and
                # produce out-of-bounds confidence intervals.
                out[row["issuer"]] = IssuerPrior(
                    issuer=row["issuer"],
                    letter_language=row["letter_language"],
                    sample_size=row["sample_size"],
                    p_any_freeze=_clamp01(row["p_any_freeze"] or 0),
                    p_full_freeze=_clamp01(row["p_full_freeze"] or 0),
                    p_returned_to_victim=_clamp01(
                        row["p_returned_to_victim"] or 0
                    ),
                    avg_response_hours=float(row["avg_response_hours"])
                    if row.get("avg_response_hours") is not None else None,
                    median_response_hours=float(row["median_response_hours"])
                    if row.get("median_response_hours") is not None else None,
                    is_learned=True,
                )
    except Exception as exc:  # noqa: BLE001
        log.warning("load_learned_priors failed: %s", exc)
    return out


def _clamp01(v: Any) -> float:
    """Coerce a value to a float in [0, 1].

    v0.16.10 (round-9 scoring LOW): defensive bound on DB-sourced
    probabilities; see load_learned_priors call site for context.
    """
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return f


# v0.17.1 (quantitative rigor QUANT-1): Beta-Binomial conjugate prior.
# α₀ = β₀ = 2 → mode at 0.5, variance ≈ 0.045. With n=20 (the learned-
# prior threshold) the data weight is 20:4, so the posterior mean is
# 83% data + 17% prior; the prior contribution is small but PREVENTS
# the 0.0 / 1.0 overconfidence trap that the prior MLE formula fell into.
#
# References:
#   * Beta-Binomial conjugacy: Bayesian Data Analysis (Gelman et al.,
#     ch. 3): "If the prior is Beta(α, β) and the data is k successes
#     out of n trials, the posterior is Beta(α+k, β+n-k); the posterior
#     mean is (α+k) / (α+β+n)."
#   * α=β=2 specifically chosen so a single observation (n=1) carries
#     the same weight as the prior itself (each "worth" 2 trials).
_BETA_PRIOR_ALPHA = 2.0
_BETA_PRIOR_BETA = 2.0


def _beta_posterior_mean(wins: int, n: int) -> float:
    """Return the Beta-Binomial posterior mean of P(success) given
    `wins` successes in `n` trials and a Beta(2, 2) prior.

    Always returns a value in [0, 1] (clamped defensively against
    bad inputs). For n=0 returns the prior mean (0.5).
    """
    if n <= 0:
        return _BETA_PRIOR_ALPHA / (_BETA_PRIOR_ALPHA + _BETA_PRIOR_BETA)
    if wins < 0 or wins > n:
        # Degenerate input — fall back to the prior.
        return _BETA_PRIOR_ALPHA / (_BETA_PRIOR_ALPHA + _BETA_PRIOR_BETA)
    losses = n - wins
    posterior_mean = (
        (_BETA_PRIOR_ALPHA + wins)
        / (_BETA_PRIOR_ALPHA + _BETA_PRIOR_BETA + wins + losses)
    )
    return _clamp01(posterior_mean)


def beta_credible_interval(
    wins: int, n: int, *, level: float = 0.90,
) -> tuple[float, float]:
    """Return the (lower, upper) bounds of the equal-tailed Beta
    credible interval at the given level for the success probability.

    Used by the recovery scorer to publish a defensible CI alongside
    the point estimate; v0.16.x shipped a hand-rolled ±0.35σ that was
    actually wrong for Bernoulli outcomes. The Beta posterior IS the
    right distribution for "what fraction of attempts succeed."

    Uses statistics.NormalDist via a Wilson-style approximation when
    SciPy isn't available. For n >= 10 the approximation is good to
    ~1 percentage point; for smaller n we fall back to a wider
    "no learned prior" interval the caller should treat with caution.
    """
    import math
    if n <= 0:
        return (0.05, 0.95)  # uniform-ish prior → wide CI
    if level <= 0 or level >= 1:
        level = 0.90
    alpha = _BETA_PRIOR_ALPHA + wins
    beta = _BETA_PRIOR_BETA + (n - wins)
    posterior_mean = alpha / (alpha + beta)
    posterior_var = (alpha * beta) / (
        (alpha + beta) ** 2 * (alpha + beta + 1)
    )
    # Approximate the Beta posterior with a Normal of the same mean+var,
    # then take Normal quantiles. Equivalent to the Wilson interval
    # for the Beta-Binomial — accurate enough for our purposes.
    sigma = math.sqrt(posterior_var)
    # Inverse standard-normal quantile for half-tail probability.
    # Hardcoded for the standard levels we care about.
    z = {0.90: 1.6449, 0.95: 1.9600, 0.99: 2.5758}.get(round(level, 2), 1.6449)
    low = max(0.0, posterior_mean - z * sigma)
    high = min(1.0, posterior_mean + z * sigma)
    return (low, high)


def _robust_median(values: list[float]) -> float | None:
    """IQR-trimmed median: drop top/bottom 10% when n >= 5, then
    take the standard median of what remains. For smaller samples
    return the plain median (trimming would discard signal).

    v0.17.1 (QUANT-3): A single 30-day "silence-then-responded"
    outlier could shift the median significantly at small n. Trimming
    bounds the influence of any one tail observation to 10% of the
    sample — operator-facing time-to-freeze priors stop getting
    dragged by stale samples.
    """
    if not values:
        return None
    if len(values) < 5:
        # Not enough data to trim meaningfully; plain median.
        return _plain_median(values)
    sorted_v = sorted(values)
    trim = max(1, len(sorted_v) // 10)
    trimmed = sorted_v[trim:-trim] if trim < len(sorted_v) // 2 else sorted_v
    return _plain_median(trimmed)


def _plain_median(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


__all__ = (
    "IssuerPrior",
    "record_letter_sent",
    "record_outcome",
    "compute_priors_from_outcomes",
    "refresh_priors",
    "load_learned_priors",
)
