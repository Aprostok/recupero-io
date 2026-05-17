"""Tests for the Stripe event → workflow dispatcher.

The dispatcher is the workhorse: it reads metadata from the Stripe
event, decides whether to create an investigation (diagnostic
payment) / activate an engagement (engagement payment) / log to
audit only (anything else), and writes the payments row.

DB calls are mocked. The live happy path is exercised in the
canary verification at release time.

Contracts under test:
  * Idempotency — re-delivery of the same event_id is a no-op.
  * Diagnostic payment with valid case_id + seed_address →
    INSERT investigation.
  * Diagnostic payment WITHOUT seed_address → audit-only (the
    operator must populate before the pipeline can run).
  * Engagement payment with valid investigation_id → UPDATE
    engagement_started_at + fee.
  * Engagement payment WITHOUT investigation_id → audit-only.
  * Refund event → 'refunded' status, audit-only (no workflow
    reversal for now).
  * Malformed UUIDs in metadata → audit-only with a clear note.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

from recupero.payments.dispatcher import dispatch
from recupero.payments.webhook import StripeEvent


def _mk_event(
    *,
    event_id: str = "evt_test_abc",
    event_type: str = "checkout.session.completed",
    payment_status: str = "paid",
    metadata: dict | None = None,
    amount_total: int = 49900,
) -> StripeEvent:
    """Construct a synthetic Stripe event for the dispatcher."""
    return StripeEvent(
        event_id=event_id,
        event_type=event_type,
        payload={
            "id": event_id,
            "type": event_type,
            "data": {
                "object": {
                    "id": "cs_test_abc",
                    "object": "checkout.session",
                    "payment_status": payment_status,
                    "amount_total": amount_total,
                    "currency": "usd",
                    "payment_intent": "pi_test_xyz",
                    "metadata": metadata or {},
                },
            },
        },
    )


def _setup_db_mock(
    *,
    insert_returns_new_row: bool = True,
    case_row: dict | None = None,
    inv_row: dict | None = None,
    prior_payment_row: dict | None = None,
) -> tuple[MagicMock, MagicMock]:
    """Build a psycopg.connect mock with a programmable cursor.

    `insert_returns_new_row=False` simulates the ON CONFLICT DO
    NOTHING path (duplicate event_id). `case_row` and `inv_row`
    let tests inject pre-condition rows for the SELECT queries
    inside _handle_diagnostic / _handle_engagement.
    """
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    fetchone_seq: list[dict | None] = []
    if insert_returns_new_row:
        # INSERT INTO payments ... RETURNING id → new row
        fetchone_seq.append({"id": str(uuid4())})
    else:
        # INSERT returned nothing (ON CONFLICT) → then SELECT prior row
        fetchone_seq.append(None)
        fetchone_seq.append(prior_payment_row or {})
    # _handle_diagnostic does a SELECT FROM cases
    # _handle_engagement does a SELECT FROM investigations
    fetchone_seq.append(case_row)
    fetchone_seq.append(inv_row)
    mock_cursor.fetchone.side_effect = fetchone_seq
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    return mock_conn, mock_cursor


def test_duplicate_event_short_circuits() -> None:
    """Re-delivery of an event we've already processed → no side
    effects, return DispatchResult(duplicate=True)."""
    event = _mk_event()
    prior = {
        "id": str(uuid4()), "case_id": str(uuid4()),
        "investigation_id": None, "amount_type": "diagnostic",
        "notes": "first delivery",
    }
    mock_conn, cur = _setup_db_mock(
        insert_returns_new_row=False, prior_payment_row=prior,
    )
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.duplicate is True
    assert result.action == "duplicate"
    assert result.case_id == prior["case_id"]
    # No INSERT investigations / UPDATE investigations should have run.
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    inserts = [s for s in sql_calls if "INSERT INTO public.investigations" in s]
    updates = [s for s in sql_calls if "UPDATE public.investigations" in s]
    assert inserts == []
    assert updates == []


def test_diagnostic_payment_creates_investigation() -> None:
    """Happy path for the $499 diagnostic: case_id + seed_address
    in metadata → INSERT investigations row."""
    case_uuid = uuid4()
    event = _mk_event(
        amount_total=49900,
        metadata={
            "type": "diagnostic",
            "case_id": str(case_uuid),
            "seed_address": "0xabc123",
            "chain": "ethereum",
        },
    )
    mock_conn, cur = _setup_db_mock(
        case_row={"id": str(case_uuid), "case_number": "V-99999"},
    )
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.duplicate is False
    assert result.action == "investigation_created"
    assert result.investigation_id is not None
    # One INSERT into investigations + one UPDATE on payments to
    # record processed_at + investigation_id + notes.
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    assert any("INSERT INTO public.investigations" in s for s in sql_calls)


def test_diagnostic_payment_without_seed_address_is_audit_only() -> None:
    """Common operator-side mistake: Checkout Session metadata has
    case_id but no seed_address. We can't start a trace without
    the wallet to trace from, so log + flag for operator triage."""
    case_uuid = uuid4()
    event = _mk_event(
        metadata={
            "type": "diagnostic",
            "case_id": str(case_uuid),
            # seed_address deliberately omitted
        },
    )
    mock_conn, cur = _setup_db_mock(
        case_row={"id": str(case_uuid), "case_number": "V-77777"},
    )
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    assert result.notes and "seed_address" in result.notes
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    # Crucially: NO INSERT into investigations.
    assert not any("INSERT INTO public.investigations" in s for s in sql_calls)


def test_diagnostic_payment_with_unknown_case_id_is_audit_only() -> None:
    """metadata.case_id references a case that doesn't exist → log
    + flag. Don't insert a dangling investigation."""
    bogus_case = uuid4()
    event = _mk_event(metadata={
        "type": "diagnostic",
        "case_id": str(bogus_case),
        "seed_address": "0xabc",
    })
    mock_conn, cur = _setup_db_mock(case_row=None)
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    assert result.notes and "unknown case" in result.notes
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    assert not any("INSERT INTO public.investigations" in s for s in sql_calls)


def test_engagement_payment_activates_engagement() -> None:
    """Happy path for the $10,000 engagement fee: UPDATE the
    investigation's engagement_started_at + fee."""
    inv_uuid = uuid4()
    event = _mk_event(
        amount_total=1000000,  # $10,000.00 in cents
        metadata={
            "type": "engagement",
            "investigation_id": str(inv_uuid),
        },
    )
    # Engagement path skips the case lookup; sequence is:
    #   1. INSERT INTO payments → payment row
    #   2. SELECT FROM investigations → inv row
    mock_conn = MagicMock()
    cur = MagicMock()
    cur.fetchone.side_effect = [
        {"id": str(uuid4())},
        {"id": str(inv_uuid)},
    ]
    mock_conn.cursor.return_value.__enter__.return_value = cur
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "engagement_activated"
    assert result.investigation_id == str(inv_uuid)
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    inv_updates = [s for s in sql_calls if "UPDATE public.investigations" in s]
    assert len(inv_updates) == 1
    # The UPDATE uses COALESCE so a portal e-sign that ran first
    # has its timestamp preserved.
    assert "COALESCE(engagement_started_at" in inv_updates[0]


def test_engagement_payment_without_investigation_id_is_audit_only() -> None:
    """Operator-side mistake: Checkout Session for engagement fee
    is missing metadata.investigation_id. Log + flag.
    No investigation lookup at all since inv_uuid is None."""
    event = _mk_event(amount_total=1000000, metadata={"type": "engagement"})
    mock_conn = MagicMock()
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": str(uuid4())}]  # only payments INSERT
    mock_conn.cursor.return_value.__enter__.return_value = cur
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    assert result.notes and "investigation_id" in result.notes


def test_refund_event_is_audit_only() -> None:
    """charge.refunded → record the refund + status='refunded' but
    don't auto-reverse engagement state. Refund handling is
    operator-supervised triage today; the test locks the behavior
    so a future 'auto-reverse on refund' change has to update it."""
    event = _mk_event(
        event_type="charge.refunded",
        payment_status="paid",  # the original payment status; refund is the new state
        metadata={"type": "engagement", "investigation_id": str(uuid4())},
    )
    # Refund / non-paid path → no workflow lookup runs; only the
    # payments INSERT.
    mock_conn = MagicMock()
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": str(uuid4())}]
    mock_conn.cursor.return_value.__enter__.return_value = cur
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    assert result.notes and "non-paid" in result.notes
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    inv_updates = [s for s in sql_calls if "UPDATE public.investigations" in s]
    # No workflow reversal — the engagement stays active.
    assert inv_updates == []


def test_malformed_uuid_in_metadata_is_audit_only() -> None:
    """metadata.case_id = 'not-a-uuid' → dispatcher logs a warning
    and degrades to audit-only. The payments row still inserts
    with case_id=NULL so the operator sees something happened."""
    event = _mk_event(metadata={
        "type": "diagnostic", "case_id": "not-a-uuid",
        "seed_address": "0xabc",
    })
    mock_conn, cur = _setup_db_mock(case_row=None)
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    sql_calls = [c.args[0] for c in cur.execute.call_args_list]
    # First INSERT into payments still ran (audit captured); no
    # INSERT into investigations.
    assert any("INSERT INTO public.payments" in s for s in sql_calls)
    assert not any("INSERT INTO public.investigations" in s for s in sql_calls)


def test_unknown_amount_type_is_audit_only() -> None:
    """metadata.type='gift_card' → audit-only with a note flagging
    the unrecognized type for operator review."""
    event = _mk_event(metadata={"type": "gift_card"})
    # Unknown type → no workflow lookup runs; only the payments INSERT.
    mock_conn = MagicMock()
    cur = MagicMock()
    cur.fetchone.side_effect = [{"id": str(uuid4())}]
    mock_conn.cursor.return_value.__enter__.return_value = cur
    with patch("recupero.payments.dispatcher.psycopg.connect") as connect:
        connect.return_value.__enter__.return_value = mock_conn
        result = dispatch(event=event, dsn="fake")

    assert result.action == "audit_only"
    assert result.notes and "unrecognized amount_type" in result.notes
