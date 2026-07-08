"""Unit tests for Wallet Guard (WalletBlock) — no live DB.

Three layers, matching test_platform_members:
* pure ScreeningResult → GuardVerdict mapping (verdict/action/alert threshold);
* store DAO SQL shape via a recording cursor (upsert, unacked filter, ack);
* router-handler decision logic by monkeypatching the `walletguard`/`store`/
  `audit` functions the handler calls (FastAPI Depends is bypassed on a direct
  call), so the alert-on-risky and 422/404 paths are exercised.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import router, store, walletguard


# --------------------------------------------------------------------------- #
# pure verdict mapping
# --------------------------------------------------------------------------- #

class _FakeScreen:
    def __init__(self, verdict, score, note="", address="0xabc", labels=None):
        self.risk_verdict = verdict
        self.risk_score = score
        self.investigator_note = note
        self._address = address
        self._labels = labels or []

    def to_json_safe(self):
        return {"address": self._address, "risk_verdict": self.risk_verdict,
                "risk_score": self.risk_score, "labels": self._labels}


@pytest.mark.parametrize(
    "verdict, expected_action, expected_alert",
    [
        ("sanctioned", "block", True),
        ("high", "block", True),
        ("medium", "warn", False),
        ("low", "allow", False),
        ("clean", "allow", False),
    ],
)
def test_guard_verdict_action_and_alert_threshold(verdict, expected_action, expected_alert):
    gv = walletguard.guard_verdict(_FakeScreen(verdict, 5, note="note"))
    assert gv.action == expected_action
    assert gv.should_alert is expected_alert
    assert gv.verdict == verdict
    # advice is always present and protective (never a safety guarantee)
    assert gv.advice
    assert "guarantee" in gv.advice.lower() or gv.action != "allow"


def test_guard_verdict_headline_falls_back_without_note():
    gv = walletguard.guard_verdict(_FakeScreen("clean", 0, note=""))
    assert "clean" in gv.headline.lower()


def test_check_address_wraps_screener(monkeypatch):
    fake = _FakeScreen("sanctioned", 10, note="OFAC hit", address="0xDEAD")
    monkeypatch.setattr(
        "recupero.screen.screener.screen_address",
        lambda address, **k: fake,
    )
    out = walletguard.check_address("0xDEAD", chain="ethereum")
    assert out["screening"]["address"] == "0xDEAD"
    assert out["guard"]["action"] == "block"
    assert out["guard"]["should_alert"] is True


# --------------------------------------------------------------------------- #
# store DAO — SQL shape via recording cursor
# --------------------------------------------------------------------------- #

class _RecCursor:
    def __init__(self, *, fetchone=None, fetchall=None, rowcount=1):
        self.executed: list[tuple[str, object]] = []
        self._fetchone = fetchone
        self._fetchall = fetchall or []
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone

    def fetchall(self):
        return self._fetchall


class _RecConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


def test_add_watched_address_upserts_and_returns_id():
    cur = _RecCursor(fetchone=("wa-1",))
    out = walletguard.add_watched_address(
        _RecConn(cur), org_id="org1", chain="ethereum", address="0xabc",
        label="Binance hot", created_by="u1", verdict="clean", risk_score=0,
    )
    assert out == "wa-1"
    sql = cur.executed[0][0]
    assert "INSERT INTO public.watched_addresses" in sql
    assert "ON CONFLICT (org_id, chain, address) DO UPDATE" in sql


def test_delete_watched_address_scoped_by_org():
    cur = _RecCursor(rowcount=1)
    assert walletguard.delete_watched_address(
        _RecConn(cur), org_id="org1", watched_id="wa-1",
    ) is True
    assert cur.executed[0][1] == ("wa-1", "org1")


def test_list_alerts_only_unacked_adds_clause():
    cur = _RecCursor(fetchall=[])
    walletguard.list_alerts(_RecConn(cur), org_id="org1", only_unacked=True)
    assert "acknowledged_at IS NULL" in cur.executed[0][0]


def test_list_alerts_all_omits_clause():
    cur = _RecCursor(fetchall=[])
    walletguard.list_alerts(_RecConn(cur), org_id="org1", only_unacked=False)
    assert "acknowledged_at IS NULL" not in cur.executed[0][0]


def test_ack_alert_updates_only_unacked():
    cur = _RecCursor(rowcount=1)
    assert walletguard.ack_alert(
        _RecConn(cur), org_id="org1", alert_id="a1", user_id="u1",
    ) is True
    assert "acknowledged_at IS NULL" in cur.executed[0][0]


# --------------------------------------------------------------------------- #
# router handlers — decision logic (Depends bypassed via direct call)
# --------------------------------------------------------------------------- #

def _principal(role="member"):
    return store.OrgContext(org_id="org1", plan="free", user_id="u1", role=role)


def _result(verdict, should_alert, address="0xabc"):
    return {
        "screening": {"address": address, "labels": []},
        "guard": {"verdict": verdict, "risk_score": 9 if should_alert else 1,
                  "headline": "h", "should_alert": should_alert, "action": "block"},
    }


def test_guard_check_risky_creates_alert(monkeypatch):
    created = {}
    monkeypatch.setattr(walletguard, "check_address",
                        lambda addr, **k: _result("sanctioned", True))
    monkeypatch.setattr(walletguard, "create_alert",
                        lambda conn, **k: created.update(k) or "alert-1")
    monkeypatch.setattr(store, "record_usage", lambda *a, **k: None)
    out = router.guard_check(
        router.GuardCheckIn(address="0xabc", chain="ethereum"),
        principal=_principal(), conn=object(),
    )
    assert out["alert_id"] == "alert-1"
    assert created["verdict"] == "sanctioned"
    assert created["source"] == "guard_check"


def test_guard_check_clean_raises_no_alert(monkeypatch):
    monkeypatch.setattr(walletguard, "check_address",
                        lambda addr, **k: _result("clean", False))
    monkeypatch.setattr(walletguard, "create_alert",
                        lambda *a, **k: pytest.fail("must not alert on clean"))
    monkeypatch.setattr(store, "record_usage", lambda *a, **k: None)
    out = router.guard_check(
        router.GuardCheckIn(address="0xabc"), principal=_principal(), conn=object(),
    )
    assert out["alert_id"] is None


def test_guard_check_invalid_address_422(monkeypatch):
    def _boom(addr, **k):
        raise ValueError("address too long")
    monkeypatch.setattr(walletguard, "check_address", _boom)
    with pytest.raises(HTTPException) as ei:
        router.guard_check(
            router.GuardCheckIn(address="0xabc"), principal=_principal(), conn=object(),
        )
    assert ei.value.status_code == 422


def test_add_guard_address_screens_upserts_and_audits(monkeypatch):
    monkeypatch.setattr(walletguard, "check_address",
                        lambda addr, **k: _result("high", True, address="0xCANON"))
    monkeypatch.setattr(walletguard, "add_watched_address",
                        lambda conn, **k: "wa-9")
    monkeypatch.setattr(walletguard, "create_alert", lambda conn, **k: "alert-2")
    audited = {}
    monkeypatch.setattr("recupero.platform.router.audit.record",
                        lambda conn, **k: audited.update(k))
    out = router.add_guard_address(
        router.WatchIn(address="0xabc", chain="ethereum", label="scammer"),
        principal=_principal(), conn=object(),
    )
    assert out["id"] == "wa-9"
    assert out["address"] == "0xCANON"      # stored in canonical (screened) form
    assert out["alert_id"] == "alert-2"
    assert audited["action"] == "guard.address_added"


def test_delete_guard_address_not_found_404(monkeypatch):
    monkeypatch.setattr(walletguard, "delete_watched_address", lambda conn, **k: False)
    with pytest.raises(HTTPException) as ei:
        router.delete_guard_address("nope", principal=_principal(), conn=object())
    assert ei.value.status_code == 404


def test_ack_guard_alert_not_found_404(monkeypatch):
    monkeypatch.setattr(walletguard, "ack_alert", lambda conn, **k: False)
    with pytest.raises(HTTPException) as ei:
        router.ack_guard_alert("nope", principal=_principal(), conn=object())
    assert ei.value.status_code == 404
