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
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
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
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
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
    by_letter: dict[Any, dict[str, Any]] = {}
    for row in outcomes:
        letter_id = row.get("letter_id")
        if letter_id is None:
            continue
        current = by_letter.get(letter_id)
        outcome_strength = strength.get(row.get("outcome_type", ""), 0)
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
        avg_h = sum(response_hours) / len(response_hours) if response_hours else None
        median_h = (
            sorted(response_hours)[len(response_hours) // 2]
            if response_hours else None
        )

        out[(issuer, language)] = IssuerPrior(
            issuer=issuer,
            letter_language=language,
            sample_size=n,
            p_any_freeze=n_any_freeze / n if n > 0 else 0.0,
            p_full_freeze=n_full / n if n > 0 else 0.0,
            p_returned_to_victim=n_win / n if n > 0 else 0.0,
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
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
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
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, {
                    "threshold": _MIN_SAMPLE_SIZE_FOR_LEARNED_PRIOR,
                })
                for row in cur.fetchall():
                    out[row["issuer"]] = IssuerPrior(
                        issuer=row["issuer"],
                        letter_language=row["letter_language"],
                        sample_size=row["sample_size"],
                        p_any_freeze=float(row["p_any_freeze"] or 0),
                        p_full_freeze=float(row["p_full_freeze"] or 0),
                        p_returned_to_victim=float(
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


__all__ = (
    "IssuerPrior",
    "record_letter_sent",
    "record_outcome",
    "compute_priors_from_outcomes",
    "refresh_priors",
    "load_learned_priors",
)
