"""RBAC roles (v0.38, enterprise non-data #2). Additive on the existing
API-key auth: viewer < analyst < admin, default analyst (no access regression),
admins always admin. require_role() gates by minimum role; /v1/whoami reports it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from recupero.api import auth
from recupero.api.auth import require_role, role_for_key


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch) -> None:
    # Deterministic auth env for each test.
    monkeypatch.setenv("RECUPERO_API_KEYS", "viewerk:vsec,analystk:asec,admink:adsec")
    monkeypatch.delenv("RECUPERO_API_KEY_ADMINS", raising=False)
    monkeypatch.delenv("RECUPERO_API_KEY_ROLES", raising=False)
    monkeypatch.delenv("RECUPERO_API_AUTH_OPTIONAL", raising=False)
    auth.reset_buckets_for_tests()


# ---- role resolution ---- #


def test_default_role_is_analyst(monkeypatch) -> None:
    assert role_for_key("analystk") == "analyst"  # unmapped → default


def test_roles_map_assigns_role(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "viewerk:viewer,admink:admin")
    assert role_for_key("viewerk") == "viewer"
    assert role_for_key("admink") == "admin"
    assert role_for_key("analystk") == "analyst"  # still default


def test_admins_env_wins_over_roles_map(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ADMINS", "admink")
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "admink:viewer")  # ignored for admins
    assert role_for_key("admink") == "admin"


def test_unknown_role_token_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "viewerk:superuser")  # invalid
    assert role_for_key("viewerk") == "analyst"


def test_optional_auth_resolves_admin(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_AUTH_OPTIONAL", "1")
    assert role_for_key("anonymous") == "admin"


# ---- require_role gating on a tiny app ---- #


def _app_with_role(min_role: str) -> FastAPI:
    app = FastAPI()

    @app.get("/guarded")
    async def guarded(name: str = Depends(require_role(min_role))) -> dict:
        return {"name": name}

    return app


def _hdr(secret: str) -> dict:
    return {"X-Recupero-API-Key": secret}


def test_require_role_allows_equal_and_higher(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "viewerk:viewer,admink:admin")
    c = TestClient(_app_with_role("analyst"))
    assert c.get("/guarded", headers=_hdr("asec")).status_code == 200   # analyst == min
    assert c.get("/guarded", headers=_hdr("adsec")).status_code == 200  # admin > min


def test_require_role_forbids_lower(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "viewerk:viewer")
    c = TestClient(_app_with_role("analyst"))
    r = c.get("/guarded", headers=_hdr("vsec"))  # viewer < analyst
    assert r.status_code == 403
    assert "insufficient" in r.json()["detail"]


def test_require_role_401_without_key(monkeypatch) -> None:
    c = TestClient(_app_with_role("viewer"))
    assert c.get("/guarded").status_code == 401


# ---- /v1/whoami ---- #


@pytest.fixture
def client() -> Iterator[TestClient]:
    from recupero.api.app import app
    with TestClient(app) as c:
        yield c


def test_whoami_reports_name_and_role(client, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_API_KEY_ROLES", "admink:admin")
    r = client.get("/v1/whoami", headers=_hdr("adsec"))
    assert r.status_code == 200
    body = r.json()
    assert body["api_key_name"] == "admink"
    assert body["role"] == "admin"


def test_whoami_requires_auth(client) -> None:
    assert client.get("/v1/whoami").status_code == 401
