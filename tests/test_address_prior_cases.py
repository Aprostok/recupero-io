"""Address -> prior-case drill-down (v0.42).

Covers ``correlation.find_cases_for_address`` (the concrete case-id resolver the
screener's count-only correlation can't provide) with a faked DB connection,
and the address-profile route attaching ``prior_cases`` so the console can
deep-link into the per-case "Where It's Sitting Now" view.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import recupero.trace.correlation as corr
from recupero.screen.screener import ScreeningCorrelation, ScreeningResult
from recupero.trace.correlation import AddressCaseRef, find_cases_for_address

_ADDR = "0x" + "ab" * 20


# --------------------------------------------------------------------------- #
# Faked DB plumbing (mirrors db_connect's context-manager usage)
# --------------------------------------------------------------------------- #

class _FakeCur:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def __enter__(self) -> "_FakeCur":
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def execute(self, sql: str, params: dict | None = None) -> None:  # noqa: D401
        self.sql, self.params = sql, params

    def fetchall(self) -> list[dict]:
        return self._rows


class _FakeConn:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def __enter__(self) -> "_FakeConn":
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def cursor(self) -> _FakeCur:
        return _FakeCur(self._rows)


def _patch_db(monkeypatch: pytest.MonkeyPatch, rows: list[dict]) -> None:
    monkeypatch.setattr(corr, "db_connect", lambda *a, **k: _FakeConn(rows))


def _row(**kw) -> dict:
    base = {
        "case_id": None, "investigation_id": None, "role": "hop",
        "label_name": None, "risk_verdict": None, "usd_flowed": None,
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    base.update(kw)
    return base


# --------------------------------------------------------------------------- #
# find_cases_for_address
# --------------------------------------------------------------------------- #

def test_find_cases_no_dsn_returns_empty() -> None:
    assert find_cases_for_address(_ADDR, dsn="") == []
    assert find_cases_for_address("", dsn="postgres://x") == []


def test_find_cases_maps_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_db(monkeypatch, [
        _row(case_id="c1", investigation_id="inv1", role="perpetrator_hub",
             risk_verdict="high", usd_flowed=Decimal("5000")),
    ])
    refs = find_cases_for_address(_ADDR, dsn="postgres://x")
    assert len(refs) == 1
    r = refs[0]
    assert isinstance(r, AddressCaseRef)
    assert r.case_id == "c1"
    assert r.investigation_id == "inv1"
    assert r.role == "perpetrator_hub"
    assert r.risk_verdict == "high"
    assert r.usd_flowed == Decimal("5000")
    assert r.observed_at_iso.startswith("2026-01-01")


def test_find_cases_dedupes_by_investigation(monkeypatch: pytest.MonkeyPatch) -> None:
    # Same investigation appears twice (two roles) -> one ref; a second distinct
    # investigation -> a second ref.
    _patch_db(monkeypatch, [
        _row(case_id="c1", investigation_id="inv1", role="victim"),
        _row(case_id="c1", investigation_id="inv1", role="hop"),
        _row(case_id="c2", investigation_id="inv2", role="mixer"),
    ])
    refs = find_cases_for_address(_ADDR, dsn="postgres://x")
    assert [r.investigation_id for r in refs] == ["inv1", "inv2"]


def test_find_cases_respects_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_db(monkeypatch, [
        _row(case_id=f"c{i}", investigation_id=f"inv{i}") for i in range(10)
    ])
    refs = find_cases_for_address(_ADDR, dsn="postgres://x", limit=3)
    assert len(refs) == 3


def test_find_cases_db_error_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(corr, "db_connect", _boom)
    assert find_cases_for_address(_ADDR, dsn="postgres://x") == []


def test_find_cases_falls_back_to_case_id_when_no_investigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_db(monkeypatch, [_row(case_id="only-case", investigation_id=None)])
    refs = find_cases_for_address(_ADDR, dsn="postgres://x")
    assert len(refs) == 1
    assert refs[0].case_id == "only-case"
    assert refs[0].investigation_id is None


# --------------------------------------------------------------------------- #
# Route attaches prior_cases
# --------------------------------------------------------------------------- #

def _client() -> TestClient:
    from recupero.api.address_profile import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _flagged():
    return ScreeningResult(
        address=_ADDR, chain="ethereum", risk_verdict="high", risk_score=8,
        is_ofac_sanctioned=False, is_mixer=False, is_ransomware=False, is_drainer=False,
        correlation=ScreeningCorrelation(prior_case_count=2),
    )


def test_route_attaches_prior_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://x")
    import recupero.screen.screener as screener_mod
    monkeypatch.setattr(screener_mod, "screen_address", lambda *a, **k: _flagged())
    monkeypatch.setattr(
        corr, "find_cases_for_address",
        lambda *a, **k: [AddressCaseRef(
            case_id="c1", investigation_id="inv1", role="perpetrator_hub",
            label_name=None, risk_verdict="high", usd_flowed=None,
            observed_at_iso="2026-01-01T00:00:00Z",
        )],
    )
    r = _client().get(
        "/v1/address/profile", params={"address": _ADDR, "chain": "ethereum"},
        headers={"X-Recupero-Admin-Key": "secret"},
    )
    assert r.status_code == 200
    pc = r.json().get("prior_cases")
    assert pc and pc[0]["link_id"] == "inv1"  # prefers investigation_id
    assert pc[0]["case_id"] == "c1"


def test_route_no_prior_cases_without_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    import recupero.screen.screener as screener_mod
    monkeypatch.setattr(screener_mod, "screen_address", lambda *a, **k: _flagged())
    r = _client().get(
        "/v1/address/profile", params={"address": _ADDR, "chain": "ethereum"},
        headers={"X-Recupero-Admin-Key": "secret"},
    )
    assert r.status_code == 200
    assert "prior_cases" not in r.json()  # additive; absent without the DB
