"""Deploy P1 — env-gated prod-hardening middleware on the API.

``_install_optional_middleware`` adds TrustedHost / CORS middleware ONLY when
the corresponding env var is set, so the default (unset) preserves the current
permissive behavior — no behavior change for existing deployments or tests.

Pins:
  * unset env -> neither middleware installed.
  * RECUPERO_API_ALLOWED_HOSTS set -> TrustedHostMiddleware installed (only).
  * RECUPERO_API_CORS_ORIGINS set -> CORSMiddleware installed (only).

Operates on a FRESH FastAPI() so it's independent of import-time env / the
module-level app's middleware stack.
"""

from __future__ import annotations

from fastapi import FastAPI

from recupero.api.app import _install_optional_middleware


def _mw_classes(app: FastAPI) -> set[str]:
    return {m.cls.__name__ for m in app.user_middleware}


def test_no_optional_middleware_by_default(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_API_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("RECUPERO_API_CORS_ORIGINS", raising=False)
    app = FastAPI()
    _install_optional_middleware(app)
    classes = _mw_classes(app)
    assert "TrustedHostMiddleware" not in classes
    assert "CORSMiddleware" not in classes


def test_trustedhost_added_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv(
        "RECUPERO_API_ALLOWED_HOSTS",
        "api.recupero.io, recupero-io-production.up.railway.app",
    )
    monkeypatch.delenv("RECUPERO_API_CORS_ORIGINS", raising=False)
    app = FastAPI()
    _install_optional_middleware(app)
    classes = _mw_classes(app)
    assert "TrustedHostMiddleware" in classes
    assert "CORSMiddleware" not in classes


def test_cors_added_when_env_set(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_API_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("RECUPERO_API_CORS_ORIGINS", "https://app.recupero.io")
    app = FastAPI()
    _install_optional_middleware(app)
    classes = _mw_classes(app)
    assert "CORSMiddleware" in classes
    assert "TrustedHostMiddleware" not in classes


def test_blank_env_installs_nothing(monkeypatch) -> None:
    # Whitespace-only values must be treated as unset (no empty allow-lists).
    monkeypatch.setenv("RECUPERO_API_ALLOWED_HOSTS", "   ")
    monkeypatch.setenv("RECUPERO_API_CORS_ORIGINS", " , ")
    app = FastAPI()
    _install_optional_middleware(app)
    classes = _mw_classes(app)
    assert "TrustedHostMiddleware" not in classes
    assert "CORSMiddleware" not in classes
