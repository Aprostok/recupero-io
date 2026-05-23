"""RIGOR-Jacob V: SupabaseCaseStore investigation_id UUID validation.

``investigation_id`` is documented as the UUID primary key of
``public.investigations``. ``__init__`` only checks
``if not investigation_id`` — a value like ``"../../bucket/admin"``
slips through and lands in the storage path
``investigations/../../bucket/admin/case.json``. Even if Supabase
Storage normalizes path segments, this is a violation of the
documented contract and surfaces as confusing 4xx errors.

Lock the contract: investigation_id MUST be a parseable UUID at
construction time.
"""

from __future__ import annotations

import pytest


def _build_config():
    from recupero.config import RecuperoConfig
    return RecuperoConfig()


def test_init_rejects_non_uuid_investigation_id() -> None:
    """Non-UUID strings must raise ValueError at __init__."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    for bad in (
        "not-a-uuid",
        "../../bucket/admin",
        "abc/123",
        "fake-id",
        "0000",
    ):
        with pytest.raises(ValueError):
            SupabaseCaseStore(
                _build_config(),
                supabase_url="https://fake.supabase.co",
                service_role_key="sk-fake",
                investigation_id=bad,
            )


def test_init_rejects_traversal_in_investigation_id() -> None:
    """Path-traversal segments must be explicitly rejected."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    for traversal in (
        "../escape",
        "..",
        "abc/../sibling",
        "/abs/path",
    ):
        with pytest.raises(ValueError):
            SupabaseCaseStore(
                _build_config(),
                supabase_url="https://fake.supabase.co",
                service_role_key="sk-fake",
                investigation_id=traversal,
            )


def test_init_accepts_valid_uuid() -> None:
    """Sanity: a real UUID is accepted."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    store = SupabaseCaseStore(
        _build_config(),
        supabase_url="https://fake.supabase.co",
        service_role_key="sk-fake",
        investigation_id="00000000-0000-0000-0000-000000000000",
    )
    assert store.storage_prefix == (
        "investigations/00000000-0000-0000-0000-000000000000/"
    )


def test_init_accepts_uppercase_uuid() -> None:
    """UUIDs are case-insensitive; either form should work."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    upper = "ABCDEF12-3456-4789-ABCD-EF1234567890"
    store = SupabaseCaseStore(
        _build_config(),
        supabase_url="https://fake.supabase.co",
        service_role_key="sk-fake",
        investigation_id=upper,
    )
    # The storage_prefix should keep the supplied form (UUID library
    # canonicalizes to lower in Python but the surface should be
    # consistent — either is fine).
    assert "abcdef" in store.storage_prefix.lower() or upper in store.storage_prefix
