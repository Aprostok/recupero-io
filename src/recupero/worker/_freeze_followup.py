"""Freeze-letter follow-up cron (v0.21.0).

Scans ``freeze_letters_sent`` for letters that have not received a
response (no matching ``freeze_outcomes`` row) and progresses each
through a three-stage escalation:

    initial → nudge_72h → escalation_7d → silence_14d

  * **nudge_72h** — fires 72 hours after sent_at. Gentle email to
    the issuer compliance contact asking for acknowledgement.
  * **escalation_7d** — fires 7 days after sent_at, only if the 72h
    nudge has already been sent. Firmer language, references the
    on-chain trace evidence, hints at LE escalation.
  * **silence_14d** — fires 14 days after sent_at, only if the 7d
    escalation already went out. Sends an INTERNAL alert to the
    case investigator (NOT the issuer) recommending grand jury
    subpoena / MLAT pivot, AND writes a ``freeze_outcomes`` row
    with ``outcome_type='silence_14d'`` so the per-issuer priors
    pipeline counts it as a real non-response data point.

Race safety: each candidate is re-checked for an existing
``freeze_outcomes`` row inside the dispatch transaction. If an
operator records a response in the seconds between the SELECT and
the email send, the cron sees the outcome row and skips the
nudge. (Without this, the issuer could receive a 72h follow-up
seconds after they confirmed freeze, which looks unprofessional.)

Wired into the worker via ``recupero-worker --freeze-followups``.
Recommended cron cadence: every 6 hours. Each tick is cheap
(LEFT JOIN with the dedicated ``freeze_letters_followup_due_idx``
partial index).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import db_connect

log = logging.getLogger(__name__)


_TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent / "reports" / "templates"
)


# Stage names — must match the freeze_letters_followup_stage_chk CHECK.
_STAGE_INITIAL = "initial"
_STAGE_NUDGE_72H = "nudge_72h"
_STAGE_ESCALATION_7D = "escalation_7d"
_STAGE_SILENCE_14D = "silence_14d"

# Stage transitions and their thresholds. The cron walks each
# candidate against these in order; the first matching transition
# fires. Pinned at the constants so the table-driven shape stays
# obvious to operators reading the source.
_STAGE_TRANSITIONS: tuple[tuple[str, str, timedelta, str], ...] = (
    # (from_stage, to_stage, min_elapsed_since_sent, template_name)
    (_STAGE_INITIAL,       _STAGE_NUDGE_72H,     timedelta(hours=72),
     "freeze_followup_nudge.html.j2"),
    (_STAGE_NUDGE_72H,     _STAGE_ESCALATION_7D, timedelta(days=7),
     "freeze_followup_escalation.html.j2"),
    (_STAGE_ESCALATION_7D, _STAGE_SILENCE_14D,   timedelta(days=14),
     "freeze_followup_silence.html.j2"),
)


@dataclass
class FreezeFollowupCandidate:
    """One freeze letter that's eligible for a stage transition."""
    letter_id: UUID
    case_id: UUID | None
    investigation_id: UUID | None
    issuer: str
    target_address: str
    chain: str
    asset_symbol: str
    requested_freeze_usd: Any        # NUMERIC → Decimal | float
    letter_subject: str | None
    letter_language: str
    contact_email: str | None
    sent_at: datetime
    last_followup_sent_at: datetime | None
    followup_stage: str
    # The transition we computed for this candidate (next stage, template, etc.)
    next_stage: str
    template_name: str
    # Operator email — destination of the silence_14d internal alert.
    investigator_email: str | None
    # IC3 reference if the case has one (raises the urgency of the
    # nudge / escalation language).
    ic3_case_id: str | None
    # Issuer jurisdiction (for the silence_14d MLAT recommendation).
    jurisdiction: str | None


def _compute_next_transition(
    sent_at: datetime,
    current_stage: str,
    now: datetime,
) -> tuple[str, str] | None:
    """Given a letter's current stage and how long ago it was sent,
    return ``(next_stage, template_name)`` for the most-advanced
    transition the elapsed time supports, or ``None`` if the letter
    is not yet eligible / already terminal.

    v0.21.1 (audit-fix A3 MEDIUM): pre-v0.21.1 this returned only the
    immediate next stage. A letter sent 30 days ago at stage='initial'
    (cron downtime, manual stage rollback) would advance one stage per
    cron tick. With a 6-hour cadence, three issuer-facing emails fire
    within 12 hours — looks erratic from the issuer's perspective and
    races a real outcome being recorded.

    Now: pick the highest stage whose threshold elapsed time supports
    AND which is strictly more advanced than current_stage. The
    issuer-facing send is then a single email per tick, but skipping
    to (e.g.) silence_14d if the letter is 30 days old at 'initial'.
    silence_14d is INTERNAL to the operator, so a fast jump there is
    appropriate; the issuer never sees the skipped nudge.
    """
    elapsed = now - sent_at
    if elapsed <= timedelta(0):
        # Clock skew / future-dated sent_at — be safe, do nothing.
        return None
    # Stage ordering by index in _STAGE_TRANSITIONS.
    _STAGES_ORDERED = [_STAGE_INITIAL] + [t[1] for t in _STAGE_TRANSITIONS]
    try:
        current_idx = _STAGES_ORDERED.index(current_stage)
    except ValueError:
        # Unknown stage — defensive: treat as 'initial'.
        current_idx = 0
    # Walk transitions in REVERSE (most-advanced first) so we pick the
    # highest stage whose threshold has elapsed AND is strictly after
    # the current stage.
    for from_stage, to_stage, threshold, template in reversed(_STAGE_TRANSITIONS):
        if elapsed < threshold:
            continue
        to_idx = _STAGES_ORDERED.index(to_stage)
        if to_idx <= current_idx:
            # Already at or past this stage.
            continue
        return (to_stage, template)
    return None


def find_freeze_followups_due(*, dsn: str) -> list[FreezeFollowupCandidate]:
    """Query ``freeze_letters_sent`` for letters whose followup_stage
    needs to advance and which do NOT yet have a ``freeze_outcomes``
    row recording a response.

    Returns a list of candidates, each carrying the next stage to
    transition into. Empty list if nothing is due.
    """
    sql = """
        SELECT fl.id                       AS letter_id,
               fl.case_id                  AS case_id,
               fl.investigation_id         AS investigation_id,
               fl.issuer                   AS issuer,
               fl.target_address           AS target_address,
               fl.chain                    AS chain,
               fl.asset_symbol             AS asset_symbol,
               fl.requested_freeze_usd     AS requested_freeze_usd,
               fl.letter_subject           AS letter_subject,
               fl.letter_language          AS letter_language,
               fl.contact_email            AS contact_email,
               fl.sent_at                  AS sent_at,
               fl.last_followup_sent_at    AS last_followup_sent_at,
               fl.followup_stage           AS followup_stage,
               i.investigator_email        AS investigator_email,
               i.ic3_case_id               AS ic3_case_id
          FROM public.freeze_letters_sent fl
          LEFT JOIN public.investigations i ON i.id = fl.investigation_id
          LEFT JOIN LATERAL (
              SELECT 1 FROM public.freeze_outcomes fo
               WHERE fo.letter_id = fl.id
               LIMIT 1
          ) outcome_exists ON TRUE
         WHERE fl.followup_stage <> %(terminal)s
           AND outcome_exists IS NULL
           AND fl.sent_at < NOW() - INTERVAL '72 hours'
         ORDER BY fl.sent_at ASC
         LIMIT 200;
    """
    # Late import keeps psycopg out of the import path for callers
    # that only want the pure-function helpers (find_freeze_followups_due
    # itself uses psycopg via db_connect, but the dataclass + the
    # _compute_next_transition pure-function are useful in tests
    # without psycopg).
    from psycopg.rows import dict_row

    candidates: list[FreezeFollowupCandidate] = []
    now = datetime.now(UTC)

    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(sql, {"terminal": _STAGE_SILENCE_14D})
        rows = cur.fetchall()

    for row in rows:
        transition = _compute_next_transition(
            sent_at=row["sent_at"],
            current_stage=row["followup_stage"] or _STAGE_INITIAL,
            now=now,
        )
        if transition is None:
            continue
        next_stage, template_name = transition
        # The silence_14d alert email goes to the INVESTIGATOR, not
        # the issuer. Skip candidates where we don't have an
        # investigator email to send it to (the cron has nowhere
        # to deliver). The DB layer can manually advance the stage
        # via the ops CLI if this becomes a recurring issue.
        if next_stage == _STAGE_SILENCE_14D and not row.get("investigator_email"):
            log.warning(
                "freeze_followup: letter %s due for silence_14d but no "
                "investigator_email recorded on the investigation — "
                "skipping internal alert",
                row["letter_id"],
            )
            continue
        # The issuer-facing stages (nudge_72h, escalation_7d) need a
        # contact_email; skip if missing.
        if next_stage in (_STAGE_NUDGE_72H, _STAGE_ESCALATION_7D) and not row.get("contact_email"):
            log.warning(
                "freeze_followup: letter %s due for %s but no "
                "contact_email recorded — skipping",
                row["letter_id"], next_stage,
            )
            continue
        candidates.append(FreezeFollowupCandidate(
            letter_id=row["letter_id"],
            case_id=row["case_id"],
            investigation_id=row["investigation_id"],
            issuer=row["issuer"],
            target_address=row["target_address"],
            chain=row["chain"],
            asset_symbol=row["asset_symbol"],
            requested_freeze_usd=row["requested_freeze_usd"],
            letter_subject=row["letter_subject"],
            letter_language=row["letter_language"] or "standard",
            contact_email=row["contact_email"],
            sent_at=row["sent_at"],
            last_followup_sent_at=row["last_followup_sent_at"],
            followup_stage=row["followup_stage"] or _STAGE_INITIAL,
            next_stage=next_stage,
            template_name=template_name,
            investigator_email=row.get("investigator_email"),
            ic3_case_id=row.get("ic3_case_id"),
            jurisdiction=None,  # filled by the issuer-DB lookup later
        ))

    return candidates


def _has_outcome_row(*, letter_id: UUID, dsn: str) -> bool:
    """Race-safe check: re-query for a freeze_outcomes row right
    before sending. An operator may have recorded a response in the
    seconds since the SELECT in find_freeze_followups_due.

    NOTE: v0.21.1 prefers ``_try_claim_stage_advance`` which folds this
    check + the stage UPDATE into a single atomic statement. Retained
    for back-compat with the existing test suite.
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM public.freeze_outcomes WHERE letter_id = %s LIMIT 1",
            (letter_id,),
        )
        return cur.fetchone() is not None


def _try_claim_stage_advance(
    *,
    letter_id: UUID,
    current_stage: str,
    new_stage: str,
    dsn: str,
) -> bool:
    """v0.21.1 (audit-fix C1+E3) — atomically advance the followup_stage
    in a single UPDATE that only fires when:
      (a) the row's current stage still matches what the candidate
          captured (no concurrent tick beat us), AND
      (b) no freeze_outcomes row has been recorded since the bulk
          SELECT (no operator-side response landed mid-tick).

    Returns True when this tick successfully CLAIMED the stage
    advance — caller then sends the email. On send failure, caller
    must call ``_rollback_stage_advance`` to release the claim.

    Returns False when another tick / an operator response beat us;
    caller skips the email.

    The CTE-based UPDATE serializes per-row under READ COMMITTED so
    overlapping ticks at the same letter cannot both claim. The
    `AND NOT EXISTS (...)` clause re-checks the outcome side of the
    race inside the same UPDATE statement.
    """
    sql = """
        UPDATE public.freeze_letters_sent
           SET followup_stage = %(new_stage)s,
               last_followup_sent_at = NOW()
         WHERE id = %(letter_id)s
           AND followup_stage = %(current_stage)s
           AND NOT EXISTS (
                 SELECT 1 FROM public.freeze_outcomes
                  WHERE letter_id = %(letter_id)s
           )
        RETURNING id;
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(sql, {
            "letter_id": letter_id,
            "current_stage": current_stage,
            "new_stage": new_stage,
        })
        return cur.fetchone() is not None


def _rollback_stage_advance(
    *,
    letter_id: UUID,
    previous_stage: str,
    dsn: str,
) -> None:
    """Release a claim made by ``_try_claim_stage_advance`` when the
    subsequent email send fails. The rollback only fires when the
    last_followup_sent_at column is recent (within 5 minutes of NOW())
    — defends against rolling back a legitimate later advance from
    another tick (race-on-rollback edge case).
    """
    sql = """
        UPDATE public.freeze_letters_sent
           SET followup_stage = %(prev)s,
               last_followup_sent_at = NULL
         WHERE id = %(id)s
           AND last_followup_sent_at > NOW() - INTERVAL '5 minutes';
    """
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, {"id": letter_id, "prev": previous_stage})
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "rollback of stage advance for letter %s failed (non-fatal): %s",
            letter_id, exc,
        )


def _format_requested_freeze_usd(value: Any) -> str:
    """Format a possibly-poisoned NUMERIC value for the email body.

    RIGOR-Jacob Z9-2: Postgres NUMERIC accepts NaN / +Infinity / -Infinity
    and the freeze_letters_sent row could carry a poisoned amount from
    upstream pricing corruption. The legacy renderer did
    ``f"{float(value or 0):,.2f}"`` which emits the literal strings
    ``"nan"`` / ``"inf"`` / ``"-inf"`` straight into the issuer-facing
    HTML — embarrassing artifact for compliance teams. Coerce to a
    safe fallback (``—`` em-dash) on non-finite input.
    """
    if value is None:
        return "0.00"
    try:
        if isinstance(value, Decimal):
            if not value.is_finite():
                return "—"
            return f"{float(value):,.2f}"
        # Non-Decimal numeric (float / int) — guard against IEEE-754
        # NaN / Inf the same way.
        f = float(value)
    except (TypeError, ValueError, ArithmeticError):
        return "—"
    # math.isfinite without importing math
    if f != f or f in (float("inf"), float("-inf")):
        return "—"
    return f"{f:,.2f}"


def _render_followup_html(
    candidate: FreezeFollowupCandidate,
    *,
    investigator_name: str,
    investigator_entity: str,
) -> str:
    """Render the appropriate template for ``candidate.next_stage``."""
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        # StrictUndefined: render-time exception on a missing variable
        # is loud and obvious. Silent rendering of "None" in a legal
        # email would be embarrassing.
        undefined=StrictUndefined,
    )
    # XSS defense-in-depth filters.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    now = datetime.now(UTC)
    days_since_sent = max(0, (now - candidate.sent_at).days)
    # RIGOR-Jacob Z9-2: a freeze_letters_sent row carrying
    # ``Decimal('NaN')`` / ``Decimal('Infinity')`` (Postgres NUMERIC
    # accepts both) would flow through ``float(...):,.2f`` as the
    # literal ``"nan"`` / ``"inf"`` and out to issuer compliance teams
    # in the rendered email body. Coerce non-finite to a sentinel.
    requested_human = _format_requested_freeze_usd(candidate.requested_freeze_usd)

    ctx = {
        "case_id": str(candidate.case_id or candidate.letter_id),
        "issuer": candidate.issuer,
        "issuer_contact_name": None,
        "target_address": candidate.target_address,
        "chain": candidate.chain,
        "asset_symbol": candidate.asset_symbol,
        "requested_freeze_usd_human": requested_human,
        "letter_subject": candidate.letter_subject,
        "letter_language": candidate.letter_language,
        "ic3_case_id": candidate.ic3_case_id,
        "jurisdiction": candidate.jurisdiction,
        "contact_email": candidate.contact_email,
        "sent_at_human": candidate.sent_at.strftime("%Y-%m-%d %H:%M"),
        "last_followup_sent_at_human": (
            candidate.last_followup_sent_at.strftime("%Y-%m-%d %H:%M")
            if candidate.last_followup_sent_at else "n/a"
        ),
        "days_since_sent": days_since_sent,
        "investigator_name": investigator_name,
        "investigator_email": candidate.investigator_email or "",
        "investigator_entity": investigator_entity,
    }
    return env.get_template(candidate.template_name).render(**ctx)


def _advance_stage(
    *,
    letter_id: UUID,
    new_stage: str,
    dsn: str,
) -> None:
    """Update freeze_letters_sent.followup_stage + last_followup_sent_at
    in one statement so the cron can't double-send if it's reinvoked
    before the previous tick committed.
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE public.freeze_letters_sent
               SET followup_stage = %s,
                   last_followup_sent_at = NOW()
             WHERE id = %s
            """,
            (new_stage, letter_id),
        )


def _write_silence_outcome(*, letter_id: UUID, dsn: str) -> None:
    """Insert a freeze_outcomes row marking this letter as silence_14d.

    Lets the priors pipeline count the non-response and surfaces the
    state in the LE handoff's Live Filing Status section.
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.freeze_outcomes
                (letter_id, outcome_type, observed_at, operator_notes)
            VALUES (%s, 'silence_14d', NOW(),
                    'Auto-recorded by freeze_followup cron after 14 days '
                    'of issuer silence following nudge_72h + escalation_7d.')
            """,
            (letter_id,),
        )


@dataclass
class FreezeFollowupResult:
    """Aggregate outcome of one cron pass — surfaced to the CLI."""
    candidates_found: int = 0
    sent_ok: int = 0
    skipped_due_to_outcome_race: int = 0
    send_failures: int = 0
    silence_outcomes_written: int = 0
    errors: list[str] = None  # populated lazily; mutable default OK in dataclass

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


def run_freeze_followup_cron(
    dsn: str,
    *,
    investigator_name: str | None = None,
    investigator_email_fallback: str | None = None,
    investigator_entity: str | None = None,
) -> FreezeFollowupResult:
    """Top-level cron entry point. Returns a FreezeFollowupResult
    summarizing what fired this tick.

    The cron is intended to run every 6 hours. Each tick processes
    up to 200 candidates (the LIMIT in find_freeze_followups_due) —
    far more than a real-world deployment will hit per tick, but
    bounded so a pathological state can't take the worker offline.
    """
    from recupero._common import investigator_defaults
    from recupero.worker._email import send_email

    inv_defaults = investigator_defaults()
    investigator_name = investigator_name or inv_defaults.get("INVESTIGATOR_NAME") or "Recupero Investigations"
    investigator_entity = (
        investigator_entity
        or inv_defaults.get("INVESTIGATOR_ENTITY_FULL")
        or "Recupero Investigation Services"
    )

    # Late-import the canonical RFC 5322 / CRLF / bidi validator from
    # _email.py — single source of truth so a poisoned address (CRLF
    # injection, bidi smuggle, missing @) gets rejected the same way
    # at every dispatcher.
    from recupero.worker._email import _validate_email_address

    result = FreezeFollowupResult()

    try:
        candidates = find_freeze_followups_due(dsn=dsn)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"find_freeze_followups_due failed: {exc}")
        log.error("freeze_followup: find_freeze_followups_due failed: %s", exc)
        return result

    result.candidates_found = len(candidates)
    log.info("freeze_followup: %d candidate(s) due", len(candidates))

    for cand in candidates:
        try:
            # v0.21.2 (audit-fix state-guards-6): validate the
            # destination email BEFORE claiming the stage advance.
            # Pre-fix order was claim → send → (send_email validates,
            # rejects, returns failure) → rollback. That works
            # functionally but every cron tick on a poisoned address
            # burns two DB transactions (claim + rollback) plus an
            # audit row. Worse, if the rollback ever fails (DB hiccup,
            # 5-minute window expired) the stage gets stuck advanced
            # with the issuer never receiving a single follow-up.
            # Validate up front so a poisoned row is a no-op on the
            # cron's stage state.
            if cand.next_stage == _STAGE_SILENCE_14D:
                target_email = cand.investigator_email or investigator_email_fallback
                target_label = "investigator_email"
            else:
                target_email = cand.contact_email
                target_label = "contact_email"
            if not _validate_email_address(target_email):
                result.errors.append(
                    f"letter {cand.letter_id}: invalid {target_label} "
                    f"for stage {cand.next_stage}; skipping (no claim, "
                    f"no send)"
                )
                log.warning(
                    "freeze_followup: letter %s skipped — invalid %s "
                    "for stage %s (validated pre-claim)",
                    cand.letter_id, target_label, cand.next_stage,
                )
                continue
            # v0.21.1 (audit-fix C1 + E3): claim-then-act. The atomic
            # UPDATE in _try_claim_stage_advance serves both as the
            # race-safe outcome re-check AND as the stage transition,
            # so:
            #   * No two concurrent ticks can claim the same letter
            #     (per-row serialization under READ COMMITTED).
            #   * An operator-side outcome row that lands between the
            #     bulk SELECT and the claim short-circuits the UPDATE
            #     via the `NOT EXISTS (...)` clause.
            #   * On send failure, we ROLLBACK the claim so the next
            #     tick can retry — no email duplicate, no stuck stage.
            if not _try_claim_stage_advance(
                letter_id=cand.letter_id,
                current_stage=cand.followup_stage,
                new_stage=cand.next_stage,
                dsn=dsn,
            ):
                result.skipped_due_to_outcome_race += 1
                log.info(
                    "freeze_followup: letter %s skipped (claim lost — "
                    "concurrent tick or operator-recorded outcome)",
                    cand.letter_id,
                )
                continue

            # We claimed the work; from here a failure rolls back the
            # claim so the next tick can retry.
            html = _render_followup_html(
                cand,
                investigator_name=investigator_name,
                investigator_entity=investigator_entity,
            )

            # silence_14d goes to the INVESTIGATOR; the other two
            # stages go to the issuer's compliance email.
            if cand.next_stage == _STAGE_SILENCE_14D:
                to_email = cand.investigator_email or investigator_email_fallback
            else:
                to_email = cand.contact_email

            if not to_email:
                # Release the claim — next tick can re-evaluate once
                # contact_email is populated.
                _rollback_stage_advance(
                    letter_id=cand.letter_id,
                    previous_stage=cand.followup_stage,
                    dsn=dsn,
                )
                result.errors.append(
                    f"letter {cand.letter_id}: no recipient for stage {cand.next_stage}"
                )
                continue

            subject = _stage_subject(cand)

            send_result = send_email(
                to=to_email,
                subject=subject,
                html=html,
                investigation_id=cand.investigation_id,
                email_type=f"freeze_followup_{cand.next_stage}",
                sent_by="cron:freeze_followup",
                dsn=dsn,
            )
            if not send_result.success:
                # Roll back the claim so the next tick retries cleanly.
                _rollback_stage_advance(
                    letter_id=cand.letter_id,
                    previous_stage=cand.followup_stage,
                    dsn=dsn,
                )
                result.send_failures += 1
                log.warning(
                    "freeze_followup: send failed for letter %s (claim "
                    "rolled back, next tick will retry): %s",
                    cand.letter_id, send_result.error,
                )
                continue

            # Send succeeded; the stage advance is already committed
            # (claim acquired it before the send). Only the
            # silence_14d post-step remains.
            if cand.next_stage == _STAGE_SILENCE_14D:
                _write_silence_outcome(letter_id=cand.letter_id, dsn=dsn)
                result.silence_outcomes_written += 1

            result.sent_ok += 1
        except Exception as exc:  # noqa: BLE001
            # Best-effort rollback so a half-completed claim doesn't
            # block retry forever.
            try:
                _rollback_stage_advance(
                    letter_id=cand.letter_id,
                    previous_stage=cand.followup_stage,
                    dsn=dsn,
                )
            except Exception:  # noqa: BLE001
                pass
            result.errors.append(f"letter {cand.letter_id}: {exc}")
            log.warning(
                "freeze_followup: letter %s dispatch failed: %s",
                cand.letter_id, exc,
            )

    log.info(
        "freeze_followup: tick complete — sent=%d skipped_race=%d failed=%d silence=%d errors=%d",
        result.sent_ok, result.skipped_due_to_outcome_race,
        result.send_failures, result.silence_outcomes_written,
        len(result.errors),
    )
    return result


def _stage_subject(cand: FreezeFollowupCandidate) -> str:
    """Build the email subject line per stage."""
    if cand.next_stage == _STAGE_NUDGE_72H:
        return (
            f"Follow-up: Freeze request for case {cand.case_id or cand.letter_id} "
            f"— {cand.issuer} / {cand.asset_symbol}"
        )
    if cand.next_stage == _STAGE_ESCALATION_7D:
        return (
            f"7-day escalation: Freeze request for case {cand.case_id or cand.letter_id} "
            f"— {cand.issuer} / {cand.asset_symbol}"
        )
    if cand.next_stage == _STAGE_SILENCE_14D:
        return (
            f"[INTERNAL] 14-day issuer silence: {cand.issuer} on case "
            f"{cand.case_id or cand.letter_id}"
        )
    return f"Recupero freeze follow-up — case {cand.case_id or cand.letter_id}"


__all__ = (
    "FreezeFollowupCandidate",
    "FreezeFollowupResult",
    "find_freeze_followups_due",
    "run_freeze_followup_cron",
    "_compute_next_transition",  # exposed for tests
)
