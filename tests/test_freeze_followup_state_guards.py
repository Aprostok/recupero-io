"""State-machine + adversarial-input guards for the freeze-followup cron.

Pins down the safety properties the cron MUST maintain. Each test
captures a property whose violation would either (a) double-send the
same stage email, (b) follow up on a case where an outcome was
recorded, (c) advance past a stage gate, (d) emit a malformed legal
email, or (e) regress the Z9 / Z17 input-sanitization fixes.

Properties under test:

  1. ``_try_claim_stage_advance`` SQL must require the previous
     ``followup_stage`` in the WHERE clause (no skipping gates).
  2. ``_try_claim_stage_advance`` SQL must re-check
     ``freeze_outcomes`` inside the same UPDATE (atomic claim,
     no two ticks can both send).
  3. ``find_freeze_followups_due`` SQL must exclude letters with any
     ``freeze_outcomes`` row.
  4. Z9 preserve: ``_format_requested_freeze_usd`` returns a finite,
     non-"nan"/"inf" string for poisoned Decimal('NaN')/Infinity
     inputs.
  5. Z17 preserve: a future-dated ``sent_at`` (NTP skew) renders
     ``days_since_sent`` clamped to 0, never negative.
  6. issuer_email validation: a malformed ``contact_email``
     (CRLF/bidi/missing @) must NOT advance the stage AND MUST NOT
     reach ``send_email``. Validation has to fire BEFORE the claim
     so a poisoned address doesn't burn a stage transition + audit
     row on every cron tick.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID

from recupero.worker._freeze_followup import (
    FreezeFollowupCandidate,
    _format_requested_freeze_usd,
    _render_followup_html,
    _try_claim_stage_advance,
    find_freeze_followups_due,
    run_freeze_followup_cron,
)

LETTER_ID = UUID("11111111-2222-3333-4444-555555555555")
CASE_ID = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
INV_ID = UUID("99999999-8888-7777-6666-555555555555")


def _cand(
    *,
    next_stage: str = "nudge_72h",
    template_name: str = "freeze_followup_nudge.html.j2",
    contact_email: str | None = "compliance@circle.com",
    investigator_email: str | None = "ops@recupero.io",
    sent_at: datetime | None = None,
    followup_stage: str = "initial",
    requested_freeze_usd=Decimal("1000.00"),
) -> FreezeFollowupCandidate:
    if sent_at is None:
        sent_at = datetime.now(UTC) - timedelta(hours=73)
    return FreezeFollowupCandidate(
        letter_id=LETTER_ID,
        case_id=CASE_ID,
        investigation_id=INV_ID,
        issuer="Circle",
        target_address="0x" + "a" * 40,
        chain="ethereum",
        asset_symbol="USDC",
        requested_freeze_usd=requested_freeze_usd,
        letter_subject="Freeze request",
        letter_tier="standard",
        contact_email=contact_email,
        sent_at=sent_at,
        last_followup_sent_at=None,
        followup_stage=followup_stage,
        next_stage=next_stage,
        template_name=template_name,
        investigator_email=investigator_email,
        ic3_case_id=None,
        jurisdiction=None,
    )


# ──────────────────────────────────────────────────────────────────────
# (1) Claim UPDATE must require previous stage in WHERE
# ──────────────────────────────────────────────────────────────────────


def test_claim_update_sql_requires_previous_stage():
    """The atomic claim UPDATE must be gated on the current
    ``followup_stage`` so a concurrent tick that already advanced the
    row (or an operator manual change) causes our claim to MISS — no
    UPDATE rows returned, no email sent.

    Without ``WHERE followup_stage = %(current_stage)s`` the cron
    would happily skip gates (e.g. ``initial`` → ``escalation_7d``
    bypassing the issuer-facing nudge_72h that earned trust with
    compliance teams)."""
    captured_sql: list[str] = []

    fake_conn = MagicMock()
    fake_cur = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.cursor.return_value.__enter__.return_value = fake_cur
    # Simulate "no rows updated" — the concurrent tick beat us.
    fake_cur.fetchone.return_value = None

    def _capture_exec(sql, params=None):
        captured_sql.append(sql)
        return None

    fake_cur.execute.side_effect = _capture_exec

    with patch(
        "recupero.worker._freeze_followup.db_connect",
        return_value=fake_conn,
    ):
        ok = _try_claim_stage_advance(
            letter_id=LETTER_ID,
            current_stage="initial",
            new_stage="nudge_72h",
            dsn="postgres://fake",
        )

    assert ok is False, "Claim must return False when no row matched"
    assert captured_sql, "Claim UPDATE must have been executed"
    sql = captured_sql[0]
    # Must gate on the prev stage and re-check outcomes atomically.
    assert "followup_stage = %(current_stage)s" in sql, (
        "Stage WHERE gate missing — a concurrent tick could skip "
        "stages by racing the UPDATE"
    )


# ──────────────────────────────────────────────────────────────────────
# (2) Claim UPDATE must re-check freeze_outcomes in same statement
# ──────────────────────────────────────────────────────────────────────


def test_claim_update_sql_rechecks_freeze_outcomes_atomically():
    """The same UPDATE statement must include a ``NOT EXISTS (SELECT
    1 FROM freeze_outcomes ...)`` so an operator-recorded response
    that lands BETWEEN the bulk SELECT and our claim short-circuits
    the email send. Two concurrent ticks cannot both observe "no
    outcome" and both fire the nudge.
    """
    captured_sql: list[str] = []

    fake_conn = MagicMock()
    fake_cur = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.cursor.return_value.__enter__.return_value = fake_cur
    fake_cur.fetchone.return_value = (LETTER_ID,)

    def _capture_exec(sql, params=None):
        captured_sql.append(sql)
        return None

    fake_cur.execute.side_effect = _capture_exec

    with patch(
        "recupero.worker._freeze_followup.db_connect",
        return_value=fake_conn,
    ):
        _try_claim_stage_advance(
            letter_id=LETTER_ID,
            current_stage="initial",
            new_stage="nudge_72h",
            dsn="postgres://fake",
        )

    sql = captured_sql[0]
    assert "NOT EXISTS" in sql and "freeze_outcomes" in sql, (
        "Claim UPDATE must atomically re-check freeze_outcomes — "
        "without this, two ticks can both pass the outcome check "
        "and both send the same stage email"
    )


# ──────────────────────────────────────────────────────────────────────
# (3) find_freeze_followups_due SQL must exclude letters with outcome
# ──────────────────────────────────────────────────────────────────────


def test_find_due_sql_excludes_letters_with_outcome_recorded():
    """The bulk SELECT must filter out any letter that already has a
    ``freeze_outcomes`` row. Outcome rows always carry a non-NULL
    ``outcome_type`` (migration 013 enforces NOT NULL), so the
    presence of the row alone means an outcome was recorded."""
    captured_sql: list[str] = []

    fake_conn = MagicMock()
    fake_cur = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.cursor.return_value.__enter__.return_value = fake_cur
    fake_cur.fetchall.return_value = []

    def _capture_exec(sql, params=None):
        captured_sql.append(sql)
        return None

    fake_cur.execute.side_effect = _capture_exec

    with patch(
        "recupero.worker._freeze_followup.db_connect",
        return_value=fake_conn,
    ):
        find_freeze_followups_due(dsn="postgres://fake")

    sql = captured_sql[0]
    assert "freeze_outcomes" in sql, (
        "Candidate SELECT must reference freeze_outcomes to exclude "
        "letters where an operator already recorded a response"
    )
    # Either the LATERAL/LEFT-JOIN-IS-NULL pattern, or NOT EXISTS —
    # both correctly exclude rows. Just confirm one is present.
    assert (
        ("LEFT JOIN" in sql and "IS NULL" in sql)
        or "NOT EXISTS" in sql
    ), (
        "Candidate SELECT must use an anti-join (LEFT JOIN ... IS "
        "NULL) or NOT EXISTS against freeze_outcomes — otherwise "
        "responded-to cases keep receiving follow-ups"
    )


# ──────────────────────────────────────────────────────────────────────
# (4) Z9 preserve: NaN / Infinity formatted as finite sentinel
# ──────────────────────────────────────────────────────────────────────


def test_z9_format_requested_freeze_usd_rejects_non_finite():
    """Regression for Z9-2: Postgres NUMERIC accepts NaN / Infinity.
    A poisoned ``freeze_letters_sent.requested_freeze_usd`` must NOT
    surface as the literal ``"nan"`` / ``"inf"`` in the rendered
    issuer-facing email body. Acceptable replacements: em-dash, ``0.00``,
    or any finite-looking string with neither ``nan`` nor ``inf``."""
    for poisoned in (
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        float("nan"),
        float("inf"),
        float("-inf"),
    ):
        s = _format_requested_freeze_usd(poisoned).lower()
        assert "nan" not in s and "inf" not in s, (
            f"poisoned {poisoned!r} rendered as {s!r} — Z9 fix has "
            "regressed; this string would land in a compliance email"
        )


# ──────────────────────────────────────────────────────────────────────
# (5) Z17 preserve: future-dated sent_at clamps days_since_sent
# ──────────────────────────────────────────────────────────────────────


def test_z17_renderer_clamps_days_since_sent_for_future_sent_at():
    """A future-dated ``sent_at`` (clock skew between worker and DB)
    must NOT render as ``-1 days since`` in the issuer email. Z17
    clamp ``max(0, ...)`` keeps the value non-negative."""
    cand = _cand(
        sent_at=datetime.now(UTC) + timedelta(hours=2),  # future-dated
        # _compute_next_transition would normally skip this case, but
        # we test the renderer guard directly.
    )
    html = _render_followup_html(
        cand,
        investigator_name="Test",
        investigator_entity="Recupero",
    )
    # No "-1" / "-2" rendered as a day count.
    for negative in ("-1 day", "-2 day", "-3 day"):
        assert negative not in html, (
            f"days_since_sent rendered as {negative!r} — Z17 clamp "
            "regressed; future-dated sent_at must produce 0 days, "
            "not a negative number"
        )


# ──────────────────────────────────────────────────────────────────────
# (6) issuer_email validation BEFORE claim
# ──────────────────────────────────────────────────────────────────────


def test_cron_rejects_malformed_contact_email_without_claiming():
    """An issuer-facing stage (nudge_72h / escalation_7d) with a
    malformed ``contact_email`` (e.g. CRLF injection, bidi controls,
    missing ``@``) must:

      * NOT advance the stage (no _try_claim_stage_advance call)
      * NOT reach send_email
      * NOT write an audit row that records a poisoned address as "to"

    Pre-fix, the cron would CLAIM the stage advance, then call
    send_email, which would reject the address internally. Result: the
    stage is now "nudge_72h" without the issuer ever receiving the
    nudge — and on the next tick the cron skips the gate because the
    stage already shows nudge_72h. The issuer never gets a follow-up
    at all on that case."""
    poisoned_emails = [
        "compliance@circle.com\r\nBcc: leak@evil.com",  # CRLF injection
        "compliance‮circle.com",                    # bidi RLO smuggle
        "no-at-sign-here",                               # missing @
        "",                                              # empty
        "spaces in@local.com",                           # whitespace
    ]

    for bad_email in poisoned_emails:
        cand = _cand(contact_email=bad_email, next_stage="nudge_72h")

        claim_calls: list = []

        def _stub_claim(*, letter_id, current_stage, new_stage, dsn):
            claim_calls.append((letter_id, current_stage, new_stage))
            return True

        send_calls: list = []

        def _stub_send(**kwargs):
            send_calls.append(kwargs)
            return type("R", (), {
                "success": True, "message_id": "m1", "error": None,
                "skipped": False,
            })()

        with patch(
            "recupero.worker._freeze_followup.find_freeze_followups_due",
            return_value=[cand],
        ), patch(
            "recupero.worker._freeze_followup._try_claim_stage_advance",
            side_effect=_stub_claim,
        ), patch(
            "recupero.worker._email.send_email",
            side_effect=_stub_send,
        ):
            result = run_freeze_followup_cron(dsn="postgres://fake")

        assert claim_calls == [], (
            f"Malformed contact_email {bad_email!r} caused a stage "
            f"claim to fire — validation must run BEFORE the claim "
            f"so a poisoned address doesn't silently burn the stage"
        )
        assert send_calls == [], (
            f"Malformed contact_email {bad_email!r} reached send_email "
            f"— must be rejected up front"
        )
        assert result.sent_ok == 0
        # Error must be recorded so operators see the bad row.
        assert result.errors, (
            f"Malformed contact_email {bad_email!r} did not produce "
            f"an error entry — operators have no visibility"
        )


def test_cron_rejects_malformed_investigator_email_for_silence_stage():
    """silence_14d sends INTERNAL to the investigator. A malformed
    ``investigator_email`` (e.g. attacker-poisoned investigations row)
    must be rejected up front — must NOT claim, must NOT send, must
    NOT write a silence outcome row.

    Pre-fix the cron would advance to silence_14d, fail the send, then
    rollback. But the silence_14d outcome row write happens only after
    a SUCCESSFUL send so the outcome side is safe today; the regression
    risk is that the CLAIM still happens, burning the retry budget on
    every tick. Catch it before the claim."""
    cand = _cand(
        next_stage="silence_14d",
        template_name="freeze_followup_silence.html.j2",
        sent_at=datetime.now(UTC) - timedelta(days=15),
        # Issuer contact doesn't matter for silence_14d but must be
        # well-formed to ensure the rejection comes from the
        # investigator_email gate specifically.
        contact_email="compliance@circle.com",
        investigator_email="ops\r\nBcc: leak@evil.com",
    )

    claim_calls: list = []
    send_calls: list = []
    silence_writes: list = []

    def _stub_claim(**kw):
        claim_calls.append(kw)
        return True

    def _stub_send(**kw):
        send_calls.append(kw)
        return type("R", (), {
            "success": True, "message_id": "m1", "error": None,
            "skipped": False,
        })()

    def _stub_silence(**kw):
        silence_writes.append(kw)

    with patch(
        "recupero.worker._freeze_followup.find_freeze_followups_due",
        return_value=[cand],
    ), patch(
        "recupero.worker._freeze_followup._try_claim_stage_advance",
        side_effect=_stub_claim,
    ), patch(
        "recupero.worker._email.send_email",
        side_effect=_stub_send,
    ), patch(
        "recupero.worker._freeze_followup._write_silence_outcome",
        side_effect=_stub_silence,
    ):
        result = run_freeze_followup_cron(dsn="postgres://fake")

    assert claim_calls == [], (
        "Malformed investigator_email reached the claim UPDATE — "
        "must validate before claiming so the stage doesn't get burned"
    )
    assert send_calls == []
    assert silence_writes == []
    assert result.sent_ok == 0
    assert result.silence_outcomes_written == 0
    assert result.errors
