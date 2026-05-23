"""Adversarial audit of src/recupero/api/auth.py.

Targets the boundary behaviours of `require_api_key` and friends:
constant-time match, whitespace handling on the provided key, empty/
case sensitivity, multi-header semantics, and the production-env gate
on the dev-mode bypass.

The headline bug exercised here is **whitespace stripping on the
incoming `X-Recupero-API-Key` header**. The pre-fix code did:

    key_secret = request.headers.get("X-Recupero-API-Key", "").strip()

…which silently accepts ``" sk_secret\\t"`` as equivalent to
``"sk_secret"``. That subverts the constant-time match's whole
purpose: a leaked secret can be probed with arbitrary whitespace
decorations (``"\\nsk_secret "``, ``"\\tsk_secret"``, …) all of which
hash to the same configured value, expanding the cache-/log-fingerprint
surface and making naive prefix-matching detectors (WAF, audit log
diff) fail to recognise equivalent keys.

Fix: do **not** strip the incoming header. Validate exactly what the
client sent. (We still strip configured keys at parse time — that's
operator-controlled.)
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from recupero.api.auth import (
    _find_api_key_constant_time,
    _is_optional_auth,
    _is_production_environment,
    require_api_key,
    reset_buckets_for_tests,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _scrub_env() -> Iterator[None]:
    """Save/restore all auth-related env vars so tests don't bleed."""
    keys = (
        "RECUPERO_API_KEYS",
        "RECUPERO_API_AUTH_OPTIONAL",
        "RECUPERO_API_RATE_LIMITS",
        "RAILWAY_ENVIRONMENT",
        "ENVIRONMENT",
        "ENV",
        "NODE_ENV",
        "RECUPERO_ENV",
        "SENTRY_ENVIRONMENT",
    )
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    reset_buckets_for_tests()
    # Invalidate the parsed-keys cache by writing a sentinel then clearing.
    from recupero.api import auth as _auth_mod
    with _auth_mod._keys_cache_lock:
        _auth_mod._keys_cache.clear()
        _auth_mod._keys_cache_fingerprint = None
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    reset_buckets_for_tests()
    with _auth_mod._keys_cache_lock:
        _auth_mod._keys_cache.clear()
        _auth_mod._keys_cache_fingerprint = None


def _make_client() -> TestClient:
    """Tiny FastAPI app with one auth-gated route, for header tests."""
    app = FastAPI()

    @app.get("/probe")
    async def probe(name: str = Depends(require_api_key)) -> dict[str, str]:
        return {"name": name}

    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Constant-time match is in place
# ─────────────────────────────────────────────────────────────────────────────


def test_finder_uses_hmac_compare_digest_not_eq() -> None:
    """Source-level check: the lookup must use hmac.compare_digest."""
    import inspect

    src = inspect.getsource(_find_api_key_constant_time)
    assert "hmac.compare_digest" in src, (
        "_find_api_key_constant_time must use hmac.compare_digest for "
        "constant-time key compare; raw `==` leaks via timing."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Empty header → explicit 401, never silently treated as no-auth
# ─────────────────────────────────────────────────────────────────────────────


def test_empty_header_rejected_with_401() -> None:
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get("/probe", headers={"X-Recupero-API-Key": ""})
    assert r.status_code == 401, (
        "Empty X-Recupero-API-Key must be rejected, not interpreted as "
        f"unauthenticated/bypass; got {r.status_code} {r.text!r}"
    )


def test_whitespace_only_header_rejected_with_401() -> None:
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get("/probe", headers={"X-Recupero-API-Key": "   \t  "})
    assert r.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 3. Whitespace in the provided key is NOT silently accepted (THE BUG)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "decorated",
    [
        " s3cretXXXXXXXXX",     # leading space
        "s3cretXXXXXXXXX ",     # trailing space
        " s3cretXXXXXXXXX ",    # both
        "\ts3cretXXXXXXXXX",    # leading tab
        "s3cretXXXXXXXXX\n",    # trailing newline
    ],
)
def test_whitespace_decorated_key_is_rejected(decorated: str) -> None:
    """An attacker who leaks ``sk_xxx`` should NOT be able to authenticate
    via ``" sk_xxx\\t"`` — pre-fix `.strip()` of the inbound header
    enabled exactly that. The valid key must match byte-for-byte.
    """
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get("/probe", headers={"X-Recupero-API-Key": decorated})
    assert r.status_code == 401, (
        f"Whitespace-decorated key {decorated!r} was accepted "
        f"({r.status_code}); auth must compare exact bytes."
    )


def test_exact_key_still_accepted() -> None:
    """Sanity: the legitimate, untouched key still authenticates."""
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get(
        "/probe", headers={"X-Recupero-API-Key": "s3cretXXXXXXXXX"},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "tester"}


# ─────────────────────────────────────────────────────────────────────────────
# 4. Case sensitivity — mixed-case must be rejected
# ─────────────────────────────────────────────────────────────────────────────


def test_mixed_case_key_rejected() -> None:
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get(
        "/probe", headers={"X-Recupero-API-Key": "S3CRETxxxxxxxxx"},
    )
    assert r.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 5. Optional-auth bypass refuses to engage in production
# ─────────────────────────────────────────────────────────────────────────────


def test_optional_auth_bypass_blocked_in_production() -> None:
    os.environ["RECUPERO_API_AUTH_OPTIONAL"] = "1"
    os.environ["ENVIRONMENT"] = "production"
    assert _is_production_environment() is True
    assert _is_optional_auth() is False, (
        "Optional-auth bypass must NOT engage when a production "
        "marker is present, even if RECUPERO_API_AUTH_OPTIONAL=1."
    )


def test_optional_auth_bypass_works_outside_production() -> None:
    os.environ["RECUPERO_API_AUTH_OPTIONAL"] = "1"
    # No production markers set.
    assert _is_optional_auth() is True


# ─────────────────────────────────────────────────────────────────────────────
# 6. Unknown key returns 401, not 500/200
# ─────────────────────────────────────────────────────────────────────────────


def test_unknown_key_returns_401() -> None:
    os.environ["RECUPERO_API_KEYS"] = "tester:s3cretXXXXXXXXX"
    client = _make_client()
    r = client.get(
        "/probe", headers={"X-Recupero-API-Key": "nope-not-a-real-key"},
    )
    assert r.status_code == 401
