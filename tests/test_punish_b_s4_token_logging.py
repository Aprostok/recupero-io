"""PUNISH-B S-4: portal token logged in plaintext + persisted to
payments.notes.

The portal URL is a bearer credential — possessing the URL is
equivalent to possessing the victim's auth. Currently the URL gets:
  1. Logged at INFO in intake_notifications.send_intake_confirmation
     (twice — happy path + disable-email skip branch)
  2. Persisted into public.payments.notes via dispatcher.py:237-241

Anyone with Railway log access or `payments` SELECT can copy the
URL straight from those sites and impersonate the victim.

Fix: replace `portal_url=%s` in log lines with `token_id=%s` (the
DB UUID, which is NOT replayable to verify_token). Strip the URL
from the notes-append payload.
"""

from __future__ import annotations

import logging
import re
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest


CASE_ID = UUID("11111111-1111-1111-1111-111111111111")
INV_ID = UUID("22222222-2222-2222-2222-222222222222")
TOKEN_ID = UUID("33333333-3333-3333-3333-333333333333")


def _stub_db_with_case_row(row):
    class _C:
        def execute(self, sql, params): pass
        def fetchone(self): return row
        def __enter__(self): return self
        def __exit__(self, *a): pass
    class _Conn:
        def cursor(self): return _C()
        def __enter__(self): return self
        def __exit__(self, *a): pass
    return _Conn()


def _capture_logs(level=logging.INFO):
    """Capture every log record emitted by the recupero package.

    Sets the recupero logger's effective level so the handler
    actually receives records — without this, pytest's default
    logger config swallows INFO-level lines."""
    records: list[logging.LogRecord] = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record)

    h = _H(level=level)
    log = logging.getLogger("recupero")
    prev_level = log.level
    log.setLevel(level)
    log.addHandler(h)

    def cleanup():
        log.removeHandler(h)
        log.setLevel(prev_level)

    return records, cleanup


def _all_log_text(records) -> str:
    return "\n".join(r.getMessage() for r in records)


# ─────────────────────────────────────────────────────────────────────────────
# Happy path — log MUST NOT include the raw portal URL
# ─────────────────────────────────────────────────────────────────────────────


def test_happy_path_log_does_not_leak_portal_url():
    """On a successful send, the log line MUST NOT contain the raw
    portal_url. The token is a bearer credential; logging it gives
    anyone with Railway log access full case-portal auth."""
    from recupero.portal.intake_notifications import send_intake_confirmation

    raw_token = "secret-token-xyz-7c0d4a"
    portal_url = f"https://portal.recupero.io/portal/{raw_token}"
    stub = _stub_db_with_case_row(
        ("victim@example.com", "Jane", "RCP-CASE-1"),
    )
    fake_email = type(
        "FakeResult", (),
        {"success": True, "message_id": "m1", "error": None, "skipped": False},
    )()

    records, cleanup = _capture_logs()
    try:
        with patch(
            "recupero._common.db_connect", return_value=stub,
        ), patch(
            "recupero.portal.tokens.generate_token",
            return_value=(TOKEN_ID, raw_token, None),
        ), patch(
            "recupero.portal.tokens.public_portal_url",
            return_value=portal_url,
        ), patch(
            "recupero.worker._email.send_email",
            return_value=fake_email,
        ):
            send_intake_confirmation(
                case_id=CASE_ID, investigation_id=INV_ID,
                dsn="postgres://fake",
            )
    finally:
        cleanup()

    log_text = _all_log_text(records)
    # The raw token must NEVER appear in any log line.
    assert raw_token not in log_text, (
        f"raw bearer token leaked into log:\n{log_text}"
    )
    # The full portal URL must NEVER appear in any log line.
    assert portal_url not in log_text, (
        f"portal URL leaked into log:\n{log_text}"
    )
    # We DO expect the token_id (DB UUID) to appear — it's a safe
    # identifier that isn't replayable.
    assert str(TOKEN_ID) in log_text, (
        "token_id should still appear so operators can correlate "
        "the send with the case_tokens row"
    )


def test_disabled_email_branch_log_does_not_leak_portal_url():
    """RECUPERO_DISABLE_EMAIL=1 branch (the v0.25.1 HIGH E-1 fix)
    also currently logs portal_url. Must NOT leak."""
    from recupero.portal.intake_notifications import send_intake_confirmation

    raw_token = "another-secret-token-xyz-99"
    portal_url = f"https://portal.recupero.io/portal/{raw_token}"
    stub = _stub_db_with_case_row(
        ("victim@example.com", "Jane", "RCP-CASE-2"),
    )
    skipped_email = type(
        "FakeResult", (),
        {"success": False, "message_id": None,
         "error": "skipped: RECUPERO_DISABLE_EMAIL", "skipped": True},
    )()

    records, cleanup = _capture_logs()
    try:
        with patch(
            "recupero._common.db_connect", return_value=stub,
        ), patch(
            "recupero.portal.tokens.generate_token",
            return_value=(TOKEN_ID, raw_token, None),
        ), patch(
            "recupero.portal.tokens.public_portal_url",
            return_value=portal_url,
        ), patch(
            "recupero.worker._email.send_email",
            return_value=skipped_email,
        ):
            send_intake_confirmation(
                case_id=CASE_ID, investigation_id=INV_ID,
                dsn="postgres://fake",
            )
    finally:
        cleanup()

    log_text = _all_log_text(records)
    assert raw_token not in log_text, (
        f"DISABLE_EMAIL branch leaked raw token to log:\n{log_text}"
    )
    assert portal_url not in log_text, (
        f"DISABLE_EMAIL branch leaked portal URL:\n{log_text}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# dispatcher.py:238 — payments.notes must NOT carry the URL
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatcher_notes_append_does_not_write_portal_url():
    """The dispatcher post-commit hook writes a breadcrumb into
    payments.notes. That column is read by operators and BI tools
    — the URL must not land there. Source-level guard since the
    integration test requires a real DB."""
    import inspect
    from recupero.payments import dispatcher
    src = inspect.getsource(dispatcher.dispatch)
    # Locate the notes-append block (UPDATE public.payments SET notes).
    m = re.search(
        r"UPDATE public\.payments SET notes.*?[)\];]",
        src, flags=re.DOTALL,
    )
    assert m, "could not locate notes-append SQL block"
    # The notes-append block must NOT reference confirm.portal_url
    # anywhere. Look at the wider context — from `if confirm.success`
    # to the next `else:` — and assert portal_url is absent.
    confirm_pos = src.find("if confirm.success")
    assert confirm_pos > 0, "could not find post-commit confirm branch"
    # Slice from `if confirm.success` to the next top-level `else:`.
    after = src[confirm_pos:]
    else_pos = after.find("else:")
    assert else_pos > 0, "could not delimit confirm.success block"
    success_block = after[:else_pos]
    # Strip Python comments before the check — a comment that
    # EXPLAINS why portal_url was removed will (by necessity)
    # mention the word, but it doesn't execute.
    code_only_lines = [
        line for line in success_block.splitlines()
        if not line.lstrip().startswith("#")
    ]
    code_only = "\n".join(code_only_lines)
    assert "portal_url" not in code_only, (
        "dispatcher's confirm.success block still references "
        "portal_url in EXECUTABLE code — this writes the bearer "
        "URL into payments.notes. Code (comments stripped):\n"
        f"{code_only}"
    )
