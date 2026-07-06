"""Unit tests for org member management + invites.

Three layers, no live DB:
* pure invite-token crypto (tenancy);
* store DAO SQL shape via a recording cursor (idempotent re-invite, owner count);
* router-handler decision logic by monkeypatching the `store` functions the
  handler calls (FastAPI `Depends` is bypassed when a handler is called
  directly), so seat-quota / last-owner / expiry guards are exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException

from recupero.platform import router, store, tenancy

_SECRET = "members-test-secret"


# --------------------------------------------------------------------------- #
# pure invite-token crypto
# --------------------------------------------------------------------------- #

def test_invite_token_hash_matches_generator() -> None:
    token, token_hash = tenancy.generate_invite_token()
    assert token and token_hash
    assert tenancy.hash_invite_token(token) == token_hash
    assert tenancy.hash_invite_token("other") != token_hash


def test_invite_token_hash_is_stable_and_hex() -> None:
    h = tenancy.hash_invite_token("abc")
    assert h == tenancy.hash_invite_token("abc")
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


# --------------------------------------------------------------------------- #
# store DAO — SQL shape via recording cursor
# --------------------------------------------------------------------------- #

class _RecCursor:
    def __init__(self, *, fetchone=None, rowcount=1):
        self.executed: list[tuple[str, object]] = []
        self._fetchone = fetchone
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone


class _RecConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


def test_create_invite_clears_prior_pending_then_inserts() -> None:
    cur = _RecCursor(fetchone=("invite-1",))
    exp = datetime(2026, 8, 1, tzinfo=UTC)
    out = store.create_invite(
        _RecConn(cur), org_id="org1", email="A@Example.com", role="member",
        invited_by="u1", token_hash="h", expires_at=exp,
    )
    assert out == "invite-1"
    # Two statements: DELETE the prior pending, then INSERT the new invite.
    assert len(cur.executed) == 2
    assert "DELETE FROM public.org_invites" in cur.executed[0][0]
    assert "INSERT INTO public.org_invites" in cur.executed[1][0]
    # Email is normalised to lower-case in both statements.
    assert cur.executed[0][1] == ("org1", "a@example.com")
    assert cur.executed[1][1][1] == "a@example.com"


def test_count_owners_filters_role() -> None:
    cur = _RecCursor(fetchone=(2,))
    assert store.count_owners(_RecConn(cur), "org1") == 2
    assert "role = 'owner'" in cur.executed[0][0]


def test_revoke_invite_only_pending() -> None:
    cur = _RecCursor(rowcount=1)
    assert store.revoke_invite(_RecConn(cur), org_id="org1", invite_id="i1") is True
    assert "accepted_at IS NULL" in cur.executed[0][0]


# --------------------------------------------------------------------------- #
# router handlers — decision logic (Depends bypassed via direct call)
# --------------------------------------------------------------------------- #

def _principal(role="owner"):
    return store.OrgContext(org_id="org1", plan="free", user_id="owner-1", role=role)


def _patch_store(monkeypatch, **overrides):
    for name, fn in overrides.items():
        monkeypatch.setattr(store, name, fn)


def test_invite_member_blocked_when_seat_quota_exhausted(monkeypatch) -> None:
    # free plan max_seats = 2; already 2 committed (1 member + 1 pending) → 402.
    _patch_store(
        monkeypatch,
        get_org=lambda conn, org_id: {"plan": "free"},
        count_seats=lambda conn, org_id: 1,
        count_pending_invites=lambda conn, org_id: 1,
        create_invite=lambda *a, **k: pytest.fail("must not create invite over quota"),
    )
    with pytest.raises(HTTPException) as ei:
        router.invite_member(
            router.InviteIn(email="new@example.com", role="member"),
            principal=_principal(), conn=object(),
        )
    assert ei.value.status_code == 402


def test_invite_member_succeeds_under_quota(monkeypatch) -> None:
    created = {}
    _patch_store(
        monkeypatch,
        get_org=lambda conn, org_id: {"plan": "pro"},   # 10 seats
        count_seats=lambda conn, org_id: 1,
        count_pending_invites=lambda conn, org_id: 0,
        create_invite=lambda conn, **k: created.update(k) or "invite-9",
    )
    out = router.invite_member(
        router.InviteIn(email="teammate@example.com", role="admin"),
        principal=_principal(), conn=object(),
    )
    assert out["invite_id"] == "invite-9"
    assert out["email"] == "teammate@example.com" and out["role"] == "admin"
    # token returned once, and its hash is what was persisted
    assert tenancy.hash_invite_token(out["invite_token"]) == created["token_hash"]


def test_accept_invite_not_found(monkeypatch) -> None:
    _patch_store(monkeypatch, get_invite_by_token=lambda conn, h: None)
    with pytest.raises(HTTPException) as ei:
        router.accept_member_invite(router.AcceptInviteIn(token="tok-abcdef"), conn=object())
    assert ei.value.status_code == 404


def test_accept_invite_expired(monkeypatch) -> None:
    past = datetime.now(UTC) - timedelta(days=1)
    _patch_store(
        monkeypatch,
        get_invite_by_token=lambda conn, h: {
            "id": "i1", "org_id": "org1", "email": "x@example.com",
            "role": "member", "expires_at": past, "accepted_at": None,
        },
    )
    with pytest.raises(HTTPException) as ei:
        router.accept_member_invite(router.AcceptInviteIn(token="tok-abcdef"), conn=object())
    assert ei.value.status_code == 410


def test_accept_invite_existing_user_returns_session(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_PLATFORM_JWT_SECRET", _SECRET)
    future = datetime.now(UTC) + timedelta(days=1)
    added = {}
    _patch_store(
        monkeypatch,
        get_invite_by_token=lambda conn, h: {
            "id": "i1", "org_id": "org1", "email": "x@example.com",
            "role": "admin", "expires_at": future, "accepted_at": None,
        },
        get_user_by_email=lambda conn, email: {"id": "u-existing", "email": email,
                                               "password_hash": "scrypt$…", "name": None},
        get_org=lambda conn, org_id: {"plan": "pro"},
        get_membership=lambda conn, org_id, user_id: None,
        count_seats=lambda conn, org_id: 1,
        add_membership=lambda conn, **k: added.update(k),
        mark_invite_accepted=lambda conn, **k: None,
    )
    out = router.accept_member_invite(router.AcceptInviteIn(token="tok-abcdef"), conn=object())
    claims = tenancy.verify_jwt(out.access_token, secret=_SECRET)
    assert out.org_id == "org1"
    assert claims["org"] == "org1" and claims["role"] == "admin"
    assert added == {"org_id": "org1", "user_id": "u-existing", "role": "admin"}


def test_accept_invite_new_user_requires_password(monkeypatch) -> None:
    future = datetime.now(UTC) + timedelta(days=1)
    _patch_store(
        monkeypatch,
        get_invite_by_token=lambda conn, h: {
            "id": "i1", "org_id": "org1", "email": "new@example.com",
            "role": "member", "expires_at": future, "accepted_at": None,
        },
        get_user_by_email=lambda conn, email: None,
    )
    with pytest.raises(HTTPException) as ei:
        router.accept_member_invite(
            router.AcceptInviteIn(token="tok-abcdef"), conn=object(),
        )
    assert ei.value.status_code == 422


def test_set_member_role_cannot_demote_last_owner(monkeypatch) -> None:
    _patch_store(
        monkeypatch,
        get_membership=lambda conn, org_id, user_id: {"role": "owner"},
        count_owners=lambda conn, org_id: 1,
        update_member_role=lambda *a, **k: pytest.fail("must not update"),
    )
    with pytest.raises(HTTPException) as ei:
        router.set_member_role(
            "owner-1", router.RoleIn(role="member"),
            principal=_principal(), conn=object(),
        )
    assert ei.value.status_code == 409


def test_remove_last_owner_blocked(monkeypatch) -> None:
    _patch_store(
        monkeypatch,
        get_membership=lambda conn, org_id, user_id: {"role": "owner"},
        count_owners=lambda conn, org_id: 1,
        remove_member=lambda *a, **k: pytest.fail("must not remove"),
    )
    with pytest.raises(HTTPException) as ei:
        router.remove_org_member("owner-1", principal=_principal(), conn=object())
    assert ei.value.status_code == 409


def test_invite_rejects_owner_role() -> None:
    # 'owner' is not an assignable invite role → pydantic validation error.
    with pytest.raises(ValueError):
        router.InviteIn(email="x@example.com", role="owner")
