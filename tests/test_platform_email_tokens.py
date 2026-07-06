"""Tests for email verification + password reset (single-use token flows).

Store SQL shape via a recording cursor; router handler logic via monkeypatched
store (Depends bypassed by direct call). No live DB.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import router, store, tenancy

# ---- store DAO SQL shape ---- #

class _Cur:
    def __init__(self, fetchone=None):
        self.executed: list[tuple[str, object]] = []
        self._fetchone = fetchone

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


def test_consume_user_token_is_atomic_and_expiry_checked() -> None:
    cur = _Cur(fetchone=("user-1",))
    uid = store.consume_user_token(_Conn(cur), kind="verify_email", token_hash="h")
    assert uid == "user-1"
    sql = cur.executed[0][0]
    # single UPDATE marks used + checks unused + unexpired + right kind
    assert "SET used_at = now()" in sql
    assert "used_at IS NULL" in sql and "expires_at > now()" in sql
    assert "kind = %s" in sql


def test_consume_user_token_returns_none_when_no_row() -> None:
    assert store.consume_user_token(_Conn(_Cur(fetchone=None)), kind="password_reset",
                                    token_hash="h") is None


def test_create_user_token_hash_only() -> None:
    cur = _Cur()
    store.create_user_token(_Conn(cur), user_id="u1", kind="verify_email",
                            token_hash="deadbeef", expires_at="2026-01-01")
    sql, params = cur.executed[0]
    assert "INSERT INTO public.user_tokens" in sql
    assert params == ("u1", "verify_email", "deadbeef", "2026-01-01")


# ---- router handlers ---- #

def _principal(user_id="u1"):
    return store.OrgContext(org_id="org1", plan="pro", user_id=user_id, role="owner")


def test_verify_request_then_confirm(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_APP_BASE_URL", "https://app.example")
    created = {}
    monkeypatch.setattr(store, "create_user_token", lambda conn, **k: created.update(k))
    out = router.request_email_verification(principal=_principal(), conn=object())
    assert out["verify_url"].startswith("https://app.example/verify?token=")
    # the stored hash matches the returned token
    assert tenancy.hash_invite_token(out["verify_token"]) == created["token_hash"]
    assert created["kind"] == "verify_email"

    # confirm consumes it → marks verified
    verified = {}
    monkeypatch.setattr(store, "consume_user_token", lambda conn, **k: "u1")
    monkeypatch.setattr(store, "set_email_verified", lambda conn, uid: verified.update(uid=uid))
    res = router.confirm_email_verification(router.TokenIn(token=out["verify_token"]), conn=object())
    assert res == {"verified": True}
    assert verified["uid"] == "u1"


def test_verify_confirm_rejects_bad_token(monkeypatch) -> None:
    monkeypatch.setattr(store, "consume_user_token", lambda conn, **k: None)
    with pytest.raises(HTTPException) as ei:
        router.confirm_email_verification(router.TokenIn(token="bad-token"), conn=object())
    assert ei.value.status_code == 400


def test_reset_request_no_enumeration_and_no_token_leak(monkeypatch) -> None:
    # Unknown email → still 202, no token minted, response carries no token.
    monkeypatch.setattr(store, "get_user_by_email", lambda conn, email: None)
    called = {"n": 0}
    monkeypatch.setattr(store, "create_user_token", lambda conn, **k: called.__setitem__("n", called["n"] + 1))
    out = router.request_password_reset(router.ResetRequestIn(email="nobody@example.com"), conn=object())
    assert out == {"status": "sent"}
    assert called["n"] == 0
    assert "token" not in out and "verify_token" not in out

    # Known email → token minted, but STILL not returned in the response.
    monkeypatch.setattr(store, "get_user_by_email", lambda conn, email: {"id": "u9"})
    minted = {}
    monkeypatch.setattr(store, "create_user_token", lambda conn, **k: minted.update(k))
    out2 = router.request_password_reset(router.ResetRequestIn(email="real@example.com"), conn=object())
    assert out2 == {"status": "sent"}
    assert minted["kind"] == "password_reset" and minted["user_id"] == "u9"


def test_reset_confirm_sets_new_password(monkeypatch) -> None:
    monkeypatch.setattr(store, "consume_user_token", lambda conn, **k: "u9")
    updated = {}
    monkeypatch.setattr(store, "update_password_hash",
                        lambda conn, user_id, password_hash: updated.update(uid=user_id, h=password_hash))
    res = router.confirm_password_reset(
        router.ResetConfirmIn(token="reset-token", new_password="brand-new-strong"), conn=object(),
    )
    assert res == {"reset": True}
    assert updated["uid"] == "u9"
    # a real, verifiable hash was stored
    assert tenancy.verify_password("brand-new-strong", updated["h"]) is True


def test_reset_confirm_rejects_bad_token(monkeypatch) -> None:
    monkeypatch.setattr(store, "consume_user_token", lambda conn, **k: None)
    with pytest.raises(HTTPException) as ei:
        router.confirm_password_reset(
            router.ResetConfirmIn(token="bad-token-long-enough", new_password="brand-new-strong"),
            conn=object(),
        )
    assert ei.value.status_code == 400
