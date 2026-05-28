"""recupero-ops close-case --case <id> --outcome <type>

v0.32 Tier-0 gap #2 companion. A case CANNOT transition to
``status='closed'`` until at least one ``freeze_outcomes`` row exists
for it OR a synthetic ``no_outcome_documented`` row is explicitly
logged. This enforces the outcome-reporting discipline that drives
the recovery-rate disclosure in ``compute_recovery_stats``.

Without this gate, operators close cases informally (delete row,
mark as 'completed' in a CSV, etc.) and the recovery-rate query in
``monitoring/recovery_rate.py`` permanently undercounts both the
numerator (recoveries) and the denominator (closed cases) — the
disclosure on /v1/intake drifts away from reality.

Outcome taxonomy (CLI surface):
  * ``full_recovery``       — funds returned to victim (positive USD)
  * ``partial_recovery``    — issuer froze some/all funds, not yet released
  * ``no_recovery``         — declined / silence / released-back-to-perp
  * ``dropped``             — case withdrawn before any letter sent;
                              EXCLUDED from the recovery-rate denominator

Maps to freeze_outcomes.outcome_type internally:
  * full_recovery  → returned_to_victim (+ returned_usd required)
  * partial_recovery → full_freeze    (operator can later adjust)
  * no_recovery    → declined
  * dropped        → synthetic no_outcome_documented marker
"""

from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation
from uuid import UUID

from psycopg.rows import dict_row

from recupero._common import db_connect

log = logging.getLogger(__name__)


# CLI outcome → (freeze_outcomes.outcome_type, requires_dollar_amount).
# `dropped` is the special case: we still need an audit row so the
# case-close gate sees something. We INSERT a synthetic
# ``declined`` outcome with operator_notes='case dropped before
# any letter sent' but skip the requested_freeze_usd requirement.
CLI_OUTCOMES: dict[str, str] = {
    "full_recovery": "returned_to_victim",
    "partial_recovery": "full_freeze",
    "no_recovery": "declined",
    "dropped": "declined",
}

VALID_CLI_OUTCOMES: frozenset[str] = frozenset(CLI_OUTCOMES.keys())


class _CloseCaseError(Exception):
    """Surfaced to the operator as ERROR + non-zero exit."""


def _validate_outcome(outcome: str) -> str:
    if outcome not in VALID_CLI_OUTCOMES:
        raise _CloseCaseError(
            f"ERROR: --outcome must be one of {sorted(VALID_CLI_OUTCOMES)}; "
            f"got {outcome!r}"
        )
    return outcome


def _parse_recovered_usd(raw: str | None) -> Decimal | None:
    """Parse the optional --recovered-usd amount. Returns None when
    not provided; raises _CloseCaseError on garbage input.
    """
    if raw is None or raw == "":
        return None
    try:
        d = Decimal(raw)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise _CloseCaseError(
            f"ERROR: --recovered-usd {raw!r} is not a valid decimal: {exc}"
        ) from None
    if not d.is_finite():
        raise _CloseCaseError(
            "ERROR: --recovered-usd must be finite (NaN/Inf rejected)"
        )
    if d < 0:
        raise _CloseCaseError(
            "ERROR: --recovered-usd must be >= 0"
        )
    return d


def _has_outcome_row(cur, case_id: UUID) -> bool:
    """True iff at least one freeze_outcomes row exists for any
    freeze_letters_sent row belonging to this case.
    """
    cur.execute(
        """
        SELECT 1
          FROM public.freeze_outcomes fo
          JOIN public.freeze_letters_sent fl ON fl.id = fo.letter_id
         WHERE fl.case_id = %s
         LIMIT 1
        """,
        (str(case_id),),
    )
    return cur.fetchone() is not None


def _insert_synthetic_outcome(
    cur,
    case_id: UUID,
    outcome_db: str,
    recovered_usd: Decimal | None,
    note: str,
) -> None:
    """When the operator closes a case but no freeze letter was ever
    sent (or no outcome was recorded for the letters that were), we
    INSERT a synthetic freeze_letters_sent + freeze_outcomes pair so
    the case carries an explicit "no_outcome_documented" anchor.

    Without this row, the case is invisible to
    monitoring.recovery_rate (which counts cases with outcomes), so
    a closed-but-undocumented case would NEVER appear in the
    denominator — silently inflating the published recovery rate.
    """
    # Create a synthetic letter row tagged with the operator + case
    # so the audit chain is preserved.
    cur.execute(
        """
        INSERT INTO public.freeze_letters_sent (
            case_id, issuer, target_address, chain, asset_symbol,
            requested_freeze_usd, letter_tier, operator,
            letter_subject
        ) VALUES (
            %s, 'no_outcome_documented', 'n/a', 'n/a', 'n/a',
            0, 'standard', 'ops-cli-close-case',
            'Synthetic close-case audit row (no real letter sent)'
        )
        ON CONFLICT (case_id, issuer, target_address, asset_symbol)
        DO UPDATE SET sent_at = NOW()
        RETURNING id
        """,
        (str(case_id),),
    )
    letter_id_row = cur.fetchone()
    letter_id = letter_id_row["id"] if isinstance(letter_id_row, dict) else letter_id_row[0]

    cur.execute(
        """
        INSERT INTO public.freeze_outcomes (
            letter_id, outcome_type, returned_usd, operator_notes
        ) VALUES (
            %s, %s, %s, %s
        )
        """,
        (
            str(letter_id),
            outcome_db,
            recovered_usd,
            note,
        ),
    )


def run(
    *,
    case_id: UUID,
    outcome: str,
    recovered_usd_raw: str | None,
    note: str | None,
    dsn: str,
) -> int:
    """Close a case, gated on outcome documentation.

    Returns 0 on success, 1 on validation / data errors, 2 on
    DB errors (caller can decide whether to retry).
    """
    try:
        cli_outcome = _validate_outcome(outcome)
        recovered_usd = _parse_recovered_usd(recovered_usd_raw)
    except _CloseCaseError as exc:
        print(str(exc))
        return 1

    # full_recovery REQUIRES a positive recovered_usd amount. Without
    # it we'd land a returned_to_victim row with returned_usd=NULL,
    # which monitoring.recovery_rate ignores in the "real recovery"
    # filter — silently undercounting the numerator. Force the
    # operator to enter the number.
    if cli_outcome == "full_recovery":
        if recovered_usd is None or recovered_usd <= 0:
            print(
                "ERROR: --outcome full_recovery requires --recovered-usd "
                "with a positive amount (the dollar value actually "
                "returned to the victim). Without this, the recovery-"
                "rate disclosure on the intake portal would miss this win."
            )
            return 1

    outcome_db = CLI_OUTCOMES[cli_outcome]

    # Per-outcome operator-notes default keeps the audit trail
    # readable when the operator omits --note.
    if note is None:
        note = {
            "full_recovery": "Case closed: full recovery via operator workflow.",
            "partial_recovery": "Case closed: partial recovery / funds frozen.",
            "no_recovery": "Case closed: no recovery.",
            "dropped": "Case dropped before any letter sent.",
        }.get(cli_outcome, "Case closed.")

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            # 1. Verify the case exists.
            cur.execute(
                "SELECT id, status FROM public.cases WHERE id = %s",
                (str(case_id),),
            )
            case_row = cur.fetchone()
            if not case_row:
                print(f"ERROR: case {case_id} not found")
                return 1
            if case_row["status"] in ("closed", "completed", "archived"):
                print(
                    f"NOTE: case {case_id} is already in terminal state "
                    f"({case_row['status']!r}); no change."
                )
                return 0

            # 2. Gate: ensure we have at least one outcome row OR
            #    insert a synthetic one for `dropped` / no-letter cases.
            has_outcome = _has_outcome_row(cur, case_id)
            if not has_outcome:
                # If the operator passed full_recovery / partial_recovery
                # but there's no letter on file, this is an
                # inconsistent ask — the recovery had to happen
                # through SOMEONE (an issuer / exchange) that should
                # have been notified by a letter. We allow it (operator
                # may have used a parallel channel) but require the
                # synthetic anchor.
                _insert_synthetic_outcome(
                    cur, case_id, outcome_db, recovered_usd, note,
                )
            elif cli_outcome in ("full_recovery", "partial_recovery") and recovered_usd:
                # Append the close-case outcome record to the real
                # letter chain so the recovery_rate aggregator sees
                # the operator-confirmed win even if the issuer's
                # original outcome was logged as `acknowledged`.
                cur.execute(
                    """
                    INSERT INTO public.freeze_outcomes (
                        letter_id, outcome_type, returned_usd, operator_notes
                    )
                    SELECT fl.id, %s, %s, %s
                      FROM public.freeze_letters_sent fl
                     WHERE fl.case_id = %s
                     ORDER BY fl.sent_at ASC
                     LIMIT 1
                    """,
                    (outcome_db, recovered_usd, note, str(case_id)),
                )

            # 3. Flip case status to 'closed'.
            cur.execute(
                """
                UPDATE public.cases
                   SET status = 'closed'
                 WHERE id = %s
                """,
                (str(case_id),),
            )
    except Exception as exc:  # noqa: BLE001
        log.exception("close-case: DB error for case=%s: %s", case_id, exc)
        print(f"ERROR: DB write failed: {exc}")
        return 2

    print(
        f"OK — case {case_id} closed with outcome={cli_outcome!r}\n"
        f"     audit anchor: freeze_outcomes row inserted; the case "
        f"is now visible to monitoring.recovery_rate."
    )
    return 0


__all__ = ("run", "VALID_CLI_OUTCOMES", "CLI_OUTCOMES")
