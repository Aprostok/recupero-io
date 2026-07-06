"""Unit tests for the per-org audit trail (platform/audit.py) + its wiring.

No live DB: the recorder/reader run against a recording fake cursor, and the
never-raises guarantee is checked with a cursor that throws. One wiring test
confirms a router handler actually records its event.
"""

from __future__ import annotations

from recupero.platform import audit, router, store


class _RecCursor:
    def __init__(self, *, fetchall=None, boom=False):
        self.executed: list[tuple[str, object]] = []
        self._fetchall = fetchall or []
        self._boom = boom

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        if self._boom:
            raise RuntimeError("db down")
        self.executed.append((sql, params))

    def fetchall(self):
        return list(self._fetchall)


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


# ---- record ---- #

def test_record_inserts_org_scoped_row() -> None:
    cur = _RecCursor()
    ok = audit.record(
        _Conn(cur), org_id="org1", actor="u1", action="member.invited",
        target="x@example.com", target_kind="invite", metadata={"role": "member"},
    )
    assert ok is True
    sql, params = cur.executed[0]
    assert "INSERT INTO public.audit_log" in sql
    # org_id first, then actor/action; metadata JSON-encoded.
    assert params[0] == "org1" and params[1] == "u1" and params[2] == "member.invited"
    assert '"role": "member"' in params[7]


def test_record_never_raises_on_db_error() -> None:
    # A failing cursor must NOT propagate — auditing can't break the action.
    assert audit.record(_Conn(_RecCursor(boom=True)), org_id="o", actor="a", action="x") is False


def test_record_caps_oversized_metadata() -> None:
    cur = _RecCursor()
    audit.record(_Conn(cur), org_id="o", actor="a", action="x",
                 metadata={"blob": "y" * 10_000})
    assert cur.executed[0][1][7] == '{"_truncated": true}'


# ---- list ---- #

def test_list_events_maps_rows() -> None:
    rows = [(7, None, "u1", "auth.login", "u1", "user", "success", "{}")]
    out = audit.list_events(_Conn(_RecCursor(fetchall=rows)), org_id="org1")
    assert out == [{
        "id": 7, "occurred_at": None, "actor": "u1", "action": "auth.login",
        "target": "u1", "target_kind": "user", "outcome": "success", "metadata": {},
    }]


def test_list_events_degrades_to_empty_on_error() -> None:
    assert audit.list_events(_Conn(_RecCursor(boom=True)), org_id="o") == []


# ---- wiring: a handler records its event ---- #

def test_role_change_records_audit_event(monkeypatch) -> None:
    events: list[dict] = []
    monkeypatch.setattr(store, "get_membership", lambda conn, org_id, user_id: {"role": "member"})
    monkeypatch.setattr(store, "update_member_role", lambda conn, **k: True)
    monkeypatch.setattr(
        audit, "record",
        lambda conn, **k: events.append(k) or True,
    )
    principal = store.OrgContext(org_id="org1", plan="pro", user_id="admin-1", role="admin")
    router.set_member_role(
        "target-1", router.RoleIn(role="viewer"), principal=principal, conn=object(),
    )
    assert len(events) == 1
    assert events[0]["action"] == "member.role_changed"
    assert events[0]["org_id"] == "org1" and events[0]["target"] == "target-1"
