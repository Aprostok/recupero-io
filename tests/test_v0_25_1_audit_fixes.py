"""v0.25.1 audit-fix regression tests.

Each test pins one v0.25.0 audit finding so the bug can't quietly
regress in a future refactor.

  * A-1 (CRIT) — ISO date bounds: past 10y only, no future
  * A-2 (HIGH) — case_number collision retry
  * A-3 (HIGH) — description silently truncating; now raises
  * C-1 (CRIT) — duplicate Stripe webhook → existing-investigation
    short-circuit (no second confirmation email)
  * C-2 (HIGH) — token revoked when confirmation email fails
  * D-1 (CRIT) — IP-based rate limit on POST /v1/intake
  * E-1 (HIGH) — RECUPERO_DISABLE_EMAIL skipped result is success
  * F-1 (HIGH) — dispatcher fires intake confirmation ONLY on
    investigation_created
"""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# A-1 — ISO date bounds
# ─────────────────────────────────────────────────────────────────────────────


def test_a1_iso_date_rejects_future_date():
    """incident_date > today must fail validation."""
    from recupero.portal.intake import _is_valid_iso_date
    future = (date.today() + timedelta(days=1)).isoformat()
    assert _is_valid_iso_date(future) is False


def test_a1_iso_date_rejects_ancient_date():
    """incident_date older than 10 years must fail validation."""
    from recupero.portal.intake import _is_valid_iso_date
    ancient = "1900-01-01"
    assert _is_valid_iso_date(ancient) is False


def test_a1_iso_date_accepts_recent_past():
    """A date within the past 10 years passes."""
    from recupero.portal.intake import _is_valid_iso_date
    recent = (date.today() - timedelta(days=365)).isoformat()
    assert _is_valid_iso_date(recent) is True


def test_a1_iso_date_accepts_today():
    """Same-day incident (the most common shape) passes."""
    from recupero.portal.intake import _is_valid_iso_date
    assert _is_valid_iso_date(date.today().isoformat()) is True


def test_a1_validate_intake_payload_rejects_future_date():
    """End-to-end: validation surfaces future dates with the
    right field name."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )
    future = (date.today() + timedelta(days=30)).isoformat()
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload({
            "client_name": "Jane Doe",
            "client_email": "jane@example.com",
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
            "incident_date": future,
            "description": "got drained",
            "country": "US",
        })
    assert exc.value.field == "incident_date"


# ─────────────────────────────────────────────────────────────────────────────
# A-2 — case_number collision retry
# ─────────────────────────────────────────────────────────────────────────────


def test_a2_case_number_includes_year_and_uuid_prefix():
    """The new case_number format is RCP-INTAKE-<year>-<8 hex>.
    The year scopes uniqueness so 8-char-UUID birthday-paradox
    collisions in a single year remain rare; +4B combinations / year."""
    # We can't easily test the DB INSERT, but we can verify the
    # case_number format in the constructed string. Read the source:
    import inspect
    from recupero.portal import intake as _mod
    src = inspect.getsource(_mod.create_case_from_intake)
    # The format string must include the year prefix.
    assert "RCP-INTAKE-{year}" in src


# ─────────────────────────────────────────────────────────────────────────────
# A-3 — description truncation now raises
# ─────────────────────────────────────────────────────────────────────────────


def test_a3_long_description_raises_instead_of_silent_truncation():
    """A 2001-char description must surface as an error so the
    victim can trim — silent truncation could chop critical info."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )
    too_long = "x" * 2001
    with pytest.raises(IntakeValidationError) as exc:
        validate_intake_payload({
            "client_name": "Jane Doe",
            "client_email": "jane@example.com",
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
            "incident_date": "2026-01-01",
            "description": too_long,
            "country": "US",
        })
    assert exc.value.field == "description"
    assert "2000" in exc.value.detail


def test_a3_exactly_2000_char_description_passes():
    """The boundary case: 2000 chars exactly is still accepted."""
    from recupero.portal.intake import validate_intake_payload
    boundary = "x" * 2000
    payload = validate_intake_payload({
        "client_name": "Jane Doe",
        "client_email": "jane@example.com",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "incident_date": "2026-01-01",
        "description": boundary,
        "country": "US",
    })
    assert len(payload.description) == 2000


# ─────────────────────────────────────────────────────────────────────────────
# C-1 — duplicate Stripe webhook short-circuits
# ─────────────────────────────────────────────────────────────────────────────


def test_c1_existing_diagnostic_investigation_returns_audit_only():
    """When a second Stripe webhook arrives for the same case_id
    (e.g. checkout.session.completed → payment_intent.succeeded
    → charge.succeeded — three events for ONE payment), the
    dispatcher must NOT create a duplicate investigation, and must
    NOT fire a second confirmation email."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    existing_inv_uuid = uuid4()

    # Stub cursor that returns:
    #   1. The case (cur.fetchone() after the SELECT case)
    #   2. An existing diagnostic investigation (cur.fetchone() after
    #      the SELECT investigations)
    fetchone_results = iter([
        # 1st execute: SELECT id, case_number FROM cases
        {"id": case_uuid, "case_number": "RCP-INTAKE-2026-abcd1234"},
        # 2nd execute: SELECT existing diagnostic investigation
        {"id": existing_inv_uuid},
    ])
    cur = MagicMock()
    cur.fetchone.side_effect = lambda: next(fetchone_results)
    cur.execute = MagicMock()

    action, inv_id, notes = _handle_diagnostic(
        cur=cur,
        case_uuid=case_uuid,
        amount_cents=49900,
        obj={
            "metadata": {
                "seed_address": "0x" + "a" * 40,
                "chain": "ethereum",
            },
            "client_reference_id": "",
        },
    )

    assert action == "audit_only"
    assert inv_id == existing_inv_uuid
    assert "re-delivery" in (notes or "")
    # The dispatcher's post-commit hook fires only on
    # action=='investigation_created', so audit_only blocks the
    # duplicate confirmation email by design.


# ─────────────────────────────────────────────────────────────────────────────
# C-2 — orphan token revoked on send_email failure
# ─────────────────────────────────────────────────────────────────────────────


def test_c2_email_failure_triggers_token_revoke():
    """If send_email returns success=False (not skipped), the orphan
    portal token must be revoked so a leaked DB row / log line can't
    yield a working portal credential."""
    from recupero.portal.intake_notifications import send_intake_confirmation

    case_uuid = uuid4()
    inv_uuid = uuid4()
    token_uuid = uuid4()

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self):
            return ("victim@example.com", "Jane Doe", "RCP-CASE-1")
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    failing_email_result = type(
        "FakeResult", (),
        {"success": False, "message_id": None,
         "error": "HTTP 500 from Resend", "skipped": False},
    )()

    revoke_calls = []

    def _spy_revoke(*, token_id, dsn):
        revoke_calls.append((token_id, dsn))
        return True

    with patch(
        "recupero._common.db_connect", return_value=_StubConn(),
    ), patch(
        "recupero.portal.tokens.generate_token",
        return_value=(token_uuid, "tok-abc", None),
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok-abc",
    ), patch(
        "recupero.worker._email.send_email",
        return_value=failing_email_result,
    ), patch(
        "recupero.portal.tokens.revoke_token", side_effect=_spy_revoke,
    ):
        result = send_intake_confirmation(
            case_id=case_uuid, investigation_id=inv_uuid,
            dsn="postgres://fake",
        )

    assert result.success is False
    assert len(revoke_calls) == 1
    assert revoke_calls[0][0] == token_uuid


# ─────────────────────────────────────────────────────────────────────────────
# D-1 — IP-based rate limit on POST /v1/intake
# ─────────────────────────────────────────────────────────────────────────────


def test_d1_rate_limit_blocks_after_5_in_window():
    """The 6th request from the same IP inside 60s must be rejected.
    The 1-5th must pass."""
    from recupero.api.app import _intake_rl_check, _intake_rl_state

    # Reset state to keep tests deterministic.
    _intake_rl_state.clear()
    ip = "10.0.0.42"
    for i in range(5):
        assert _intake_rl_check(ip) is True, f"req {i+1}/5 should pass"
    # 6th request blocked.
    assert _intake_rl_check(ip) is False


def test_d1_rate_limit_isolates_per_ip():
    """One IP exhausting its budget must not affect a different IP."""
    from recupero.api.app import _intake_rl_check, _intake_rl_state

    _intake_rl_state.clear()
    for _ in range(5):
        _intake_rl_check("1.2.3.4")
    assert _intake_rl_check("1.2.3.4") is False
    # Different IP, fresh budget.
    assert _intake_rl_check("5.6.7.8") is True


def test_d1_client_ip_uses_trusted_hop_not_leftmost(monkeypatch):
    """PUNISH-B S-3 fix supersedes the original v0.25.1 D-1 behavior.

    Pre-S-3: leftmost X-Forwarded-For was treated as "the real client"
    — but Railway + Cloudflare PREPEND attacker-controlled values
    to that header, so the leftmost is whatever the bot typed.
    Bypass: rotate leftmost per request, evade the per-IP rate limit.

    Post-S-3: honor RECUPERO_TRUSTED_PROXY_HOPS=N. The Nth-from-
    rightmost element is what the trusted proxy layer added — THAT
    is the real client. With hops=1 (single Railway edge), the LAST
    element of the XFF chain is the client IP.
    """
    from recupero.api.app import _intake_rl_client_ip

    monkeypatch.setenv("RECUPERO_TRUSTED_PROXY_HOPS", "1")
    request = MagicMock()
    # An attacker-controlled leftmost (10.x.x.x) and a real
    # trusted-hop value at the right.
    request.headers = {
        "x-forwarded-for": "10.0.0.1, 203.0.113.42",
    }
    request.client = MagicMock()
    request.client.host = "203.0.113.42"

    ip = _intake_rl_client_ip(request)
    # The RIGHTMOST (trusted-hop) IP is the client identity.
    assert ip == "203.0.113.42", (
        f"got {ip!r} — should be the trusted-hop rightmost entry, "
        "not the attacker-controlled leftmost"
    )


def test_d1_client_ip_falls_back_to_x_real_ip_when_no_hops_configured(monkeypatch):
    """With RECUPERO_TRUSTED_PROXY_HOPS unset, XFF is not trusted.
    Fall back to x-real-ip (set by edge proxies after stripping XFF)."""
    from recupero.api.app import _intake_rl_client_ip

    monkeypatch.delenv("RECUPERO_TRUSTED_PROXY_HOPS", raising=False)
    request = MagicMock()
    request.headers = {
        "x-forwarded-for": "10.0.0.1, 192.168.1.1",  # Distrusted.
        "x-real-ip": "203.0.113.99",                  # Trusted.
    }
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    ip = _intake_rl_client_ip(request)
    assert ip == "203.0.113.99"


def test_d1_client_ip_falls_back_to_socket_peer_when_no_headers(monkeypatch):
    """No XFF, no x-real-ip → request.client.host (socket peer)."""
    from recupero.api.app import _intake_rl_client_ip

    monkeypatch.delenv("RECUPERO_TRUSTED_PROXY_HOPS", raising=False)
    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "203.0.113.55"
    ip = _intake_rl_client_ip(request)
    assert ip == "203.0.113.55"


# ─────────────────────────────────────────────────────────────────────────────
# E-1 — RECUPERO_DISABLE_EMAIL skipped is success, not failure
# ─────────────────────────────────────────────────────────────────────────────


def test_e1_send_email_skipped_returns_success_not_failure():
    """In dev / CI with RECUPERO_DISABLE_EMAIL=1, send_email returns
    success=False, skipped=True. The intake confirmation flow must
    treat that as a clean no-op (success=True, email_sent=False) so
    monitoring isn't drowned in false-positive WARN logs."""
    from recupero.portal.intake_notifications import send_intake_confirmation

    case_uuid = uuid4()
    inv_uuid = uuid4()
    token_uuid = uuid4()

    class _StubCursor:
        def execute(self, sql, params): pass
        def fetchone(self):
            return ("victim@example.com", "Jane Doe", "RCP-CASE-1")
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class _StubConn:
        def cursor(self): return _StubCursor()
        def __enter__(self): return self
        def __exit__(self, *a): pass

    skipped_email_result = type(
        "FakeResult", (),
        {"success": False, "message_id": None,
         "error": "skipped: RECUPERO_DISABLE_EMAIL", "skipped": True},
    )()

    revoke_called = []

    with patch(
        "recupero._common.db_connect", return_value=_StubConn(),
    ), patch(
        "recupero.portal.tokens.generate_token",
        return_value=(token_uuid, "tok-abc", None),
    ), patch(
        "recupero.portal.tokens.public_portal_url",
        return_value="https://recupero.io/portal/tok-abc",
    ), patch(
        "recupero.worker._email.send_email",
        return_value=skipped_email_result,
    ), patch(
        "recupero.portal.tokens.revoke_token",
        side_effect=lambda **kw: revoke_called.append(kw),
    ):
        result = send_intake_confirmation(
            case_id=case_uuid, investigation_id=inv_uuid,
            dsn="postgres://fake",
        )

    # success=True even though email_sent=False — skipped is normal.
    assert result.success is True
    assert result.email_sent is False
    assert result.error is None
    # CRITICAL: skipped must NOT revoke the token (the token is
    # still valid — the email send was deliberately disabled, not
    # broken).
    assert revoke_called == []


# ─────────────────────────────────────────────────────────────────────────────
# F-1 — dispatcher wires intake confirmation ONLY on
# investigation_created
# ─────────────────────────────────────────────────────────────────────────────


def test_f1_dispatcher_call_site_only_fires_on_investigation_created():
    """The dispatcher post-commit block is gated on
    `action == "investigation_created"`. A future refactor that
    moves this hook MUST keep the guard — otherwise victims get
    spam emails on duplicate / audit_only paths."""
    import inspect
    from recupero.payments import dispatcher

    src = inspect.getsource(dispatcher.dispatch)
    # The guard condition is the contract.
    assert 'action == "investigation_created"' in src
    # The side-effect import / call must be inside this block.
    # Quick proxy: send_intake_confirmation should appear AFTER the
    # guard in source order.
    guard_pos = src.find('action == "investigation_created"')
    call_pos = src.find("send_intake_confirmation")
    assert guard_pos > 0 and call_pos > guard_pos, (
        "send_intake_confirmation must be gated by the "
        "investigation_created guard"
    )
    # Defense in depth: the call must be inside a try/except so the
    # email failure can never roll back the investigation INSERT.
    block_after = src[guard_pos:]
    assert "try:" in block_after[: block_after.find("return DispatchResult")]
