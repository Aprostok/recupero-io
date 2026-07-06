"""Tests for password-hash hardening (argon2id-when-available + rehash-on-login)
and the router-wide request-size guard.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import deps, tenancy

# ---- password format dispatch ---- #

def test_scrypt_roundtrip_default() -> None:
    h = tenancy.hash_password("correct horse battery")
    assert h.startswith("scrypt$")
    assert tenancy.verify_password("correct horse battery", h) is True
    assert tenancy.verify_password("wrong", h) is False


def test_verify_dispatches_on_prefix_and_never_raises() -> None:
    # An argon2-looking hash with the library absent → False, not an exception.
    assert tenancy.verify_password("x", "$argon2id$v=19$m=65536,t=3,p=4$abc$def") in (True, False)
    assert tenancy.verify_password("x", "garbage") is False
    assert tenancy.verify_password("x", "") is False


def test_needs_rehash_false_for_scrypt_when_argon2_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_PASSWORD_ARGON2", raising=False)
    h = tenancy.hash_password("pw-really-strong")
    assert tenancy.needs_rehash(h) is False


def test_argon2_opt_in_inert_without_library(monkeypatch) -> None:
    # Enabling the flag WITHOUT argon2-cffi installed must NOT switch formats
    # (graceful) — hash stays scrypt and needs_rehash stays False.
    monkeypatch.setenv("RECUPERO_PASSWORD_ARGON2", "1")
    tenancy._argon2_hasher.cache_clear()
    if tenancy._argon2_hasher() is None:  # library absent in this env (expected)
        h = tenancy.hash_password("pw-really-strong")
        assert h.startswith("scrypt$")
        assert tenancy.needs_rehash(h) is False
    tenancy._argon2_hasher.cache_clear()


# ---- request-size guard ---- #

def test_max_request_body_allows_small(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_MAX_REQUEST_BYTES", raising=False)
    # under the 256 KiB default → no raise
    assert deps.max_request_body(content_length="1024") is None
    # missing header → allowed (chunked; ASGI server is the backstop)
    assert deps.max_request_body(content_length=None) is None
    # non-numeric → ignored, no raise
    assert deps.max_request_body(content_length="abc") is None


def test_max_request_body_rejects_oversized(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MAX_REQUEST_BYTES", "2048")
    with pytest.raises(HTTPException) as ei:
        deps.max_request_body(content_length="99999")
    assert ei.value.status_code == 413


def test_max_body_bytes_floor(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_MAX_REQUEST_BYTES", "10")  # below floor
    assert deps._max_body_bytes() >= 1024
    monkeypatch.setenv("RECUPERO_MAX_REQUEST_BYTES", "not-an-int")
    assert deps._max_body_bytes() == 262144
