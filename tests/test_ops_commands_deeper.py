"""Deeper adversarial coverage for ops/commands/ — focuses on the
modules Z13 didn't reach: send_le_handoff (recipient validation past
the regex), generate_customer_link (ttl_days bounds, label sanity).

Z13 covered mark_engaged / mark_closed / promote_freezable. The
modules below carry equivalent footguns (operator-supplied strings
that flow straight to email headers, DB rows, or `datetime` math)
and need the same friendly-error treatment.

Each test is paired with one bug. Re-running after the fix lands
confirms the friendly-error path; the test stays RED until then.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

# ---- send_le_handoff: regex-bypass adversarial inputs in --to ---- #


def test_send_le_handoff_rejects_null_byte_in_to_email(capsys) -> None:
    """``--to le\\x00@fbi.gov`` should be rejected at the command
    layer. The existing email regex is
    ``^[^@\\s]+@[^@\\s]+\\.[A-Za-z]{2,}$`` — ``\\s`` in Python regex
    is ``[ \\t\\n\\r\\f\\v]`` plus Unicode whitespace, but NUL (``\\x00``)
    is NOT whitespace. A NUL-bearing recipient passes the regex,
    then either crashes psycopg on the audit insert OR (worse) header-
    injects through the SMTP MTA.
    """
    from recupero.ops.commands import send_le_handoff
    result = send_le_handoff.run(
        investigation_id=uuid4(),
        to_email="le\x00@fbi.gov",
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result != 0, (
        "send_le_handoff accepted a NUL byte in --to. The regex at "
        "the top of run() filters @ and \\s but NOT NUL — a malicious "
        "or pasted-from-Excel recipient with embedded NUL flows "
        "straight to send_email() and the audit log. Reject with a "
        "friendly 'control character' message before the SELECT."
    )
    out = capsys.readouterr().out.lower()
    assert "control" in out or "null" in out or "invalid" in out, (
        "Expected a friendly error mentioning 'control'/'null'/"
        "'invalid'; got: " + capsys.readouterr().out
    )


def test_send_le_handoff_rejects_bidi_override_in_to_email(capsys) -> None:
    """A bidi-override (RLO U+202E) inside the local-part of --to
    spoofs the audit-rendered recipient. Reject at command layer."""
    from recupero.ops.commands import send_le_handoff
    result = send_le_handoff.run(
        investigation_id=uuid4(),
        to_email="le‮_evil@fbi.gov",
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result != 0, (
        "send_le_handoff accepted a bidi U+202E override in --to. "
        "The regex doesn't catch bidi controls — reject explicitly."
    )


def test_send_le_handoff_rejects_oversize_to_email(capsys) -> None:
    """RFC 5321 caps the addr-spec at 254 octets. A pasted 5KB blob
    in --to should be rejected with a friendly cap, not blasted into
    send_email + the audit log."""
    from recupero.ops.commands import send_le_handoff
    huge = ("x" * 5000) + "@fbi.gov"
    result = send_le_handoff.run(
        investigation_id=uuid4(),
        to_email=huge,
        dsn="fake-dsn",
        confirm=lambda *_a, **_kw: True,
    )
    assert result != 0, (
        "send_le_handoff accepted a 5KB --to address. Cap recipient "
        "addresses at RFC 5321's 254 octets before any DB work."
    )


# ---- generate_customer_link: ttl_days bounds ---- #


def test_generate_customer_link_rejects_negative_ttl_days(capsys) -> None:
    """``--ttl-days -7`` mints a token that expired a week ago.
    ``timedelta(days=-7)`` is silently accepted by datetime arithmetic
    and the operator only realizes when the customer reports a 401
    on first click. Reject at command layer."""
    from recupero.ops.commands import generate_customer_link
    case_id = uuid4()
    fake_case_row = {"case_number": "V-XXXXXX", "client_name": "Test Client"}
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = fake_case_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    with patch("recupero.ops.commands.generate_customer_link.db_connect") as mock_db:
        mock_db.return_value.__enter__.return_value = mock_conn
        result = generate_customer_link.run(
            case_id=case_id,
            ttl_days=-7,
            label=None,
            dsn="fake-dsn",
        )
    assert result != 0, (
        "generate_customer_link accepted --ttl-days=-7 and would "
        "mint an already-expired token. Validate ttl_days > 0 at "
        "the command layer before calling generate_token()."
    )


def test_generate_customer_link_rejects_excessive_ttl_days(capsys) -> None:
    """``--ttl-days 100000`` mints a 273-year token — almost certainly
    an operator typo. Cap at a sane upper bound (e.g. 730 = 2y)."""
    from recupero.ops.commands import generate_customer_link
    case_id = uuid4()
    fake_case_row = {"case_number": "V-XXXXXX", "client_name": "Test Client"}
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = fake_case_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    with patch("recupero.ops.commands.generate_customer_link.db_connect") as mock_db:
        mock_db.return_value.__enter__.return_value = mock_conn
        result = generate_customer_link.run(
            case_id=case_id,
            ttl_days=100_000,
            label=None,
            dsn="fake-dsn",
        )
    assert result != 0, (
        "generate_customer_link accepted --ttl-days=100000. Cap "
        "ttl_days at a sane upper bound (730 = 2 years) so an operator "
        "typo doesn't mint a near-immortal portal token."
    )


def test_generate_customer_link_rejects_null_byte_in_label(capsys) -> None:
    """``--label 'urgent\\x00'`` lands directly in case_tokens.label
    (psycopg silently strips NULs on TEXT or errors mid-transaction).
    Reject at the command layer."""
    from recupero.ops.commands import generate_customer_link
    case_id = uuid4()
    fake_case_row = {"case_number": "V-XXXXXX", "client_name": "Test Client"}
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = fake_case_row
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    with patch("recupero.ops.commands.generate_customer_link.db_connect") as mock_db:
        mock_db.return_value.__enter__.return_value = mock_conn
        result = generate_customer_link.run(
            case_id=case_id,
            ttl_days=90,
            label="urgent\x00reissue",
            dsn="fake-dsn",
        )
    assert result != 0, (
        "generate_customer_link accepted a NUL byte in --label. "
        "Reject control characters before invoking generate_token()."
    )
