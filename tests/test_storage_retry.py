"""Tests for the retry-on-5xx wrapper around SupabaseCaseStore HTTP calls.

The store wraps _upload / _download / _list with a tenacity retry
decorator that catches httpx.TransportError + an internal
_StorageTransient marker raised for 5xx responses. 4xx
responses bubble up as the original RuntimeError / FileNotFoundError
without retry.

These tests pin the discriminator logic — _is_storage_transient —
and verify the response-handling functions raise the right
exception type for each status class.

We don't exercise the full retry loop here (the tenacity wait
schedule would slow tests to 14s+ per case); the unit-level
contract is "does the right exception get raised so retry kicks
in or not?" and that's testable without the timing harness.
"""

from __future__ import annotations

import httpx

from recupero.storage.supabase_case_store import (
    PayloadTooLargeError,
    _is_storage_transient,
    _StorageTransient,
)

# ---- _is_storage_transient discriminator ---- #


def test_transient_marker_is_retriable() -> None:
    """Our internal 5xx marker exception → retry."""
    assert _is_storage_transient(_StorageTransient("5xx")) is True


def test_httpx_transport_error_is_retriable() -> None:
    """httpx.TransportError covers DNS / connect / read timeout /
    connection reset — exactly the family we want to absorb."""
    # ConnectError is a concrete TransportError subclass we can
    # actually construct without a real request.
    exc = httpx.ConnectError("connection refused")
    assert _is_storage_transient(exc) is True


def test_runtime_error_is_not_retriable() -> None:
    """A generic RuntimeError — used for 4xx — should NOT trigger
    a retry. Caller bugs don't fix themselves with waiting."""
    assert _is_storage_transient(RuntimeError("bad request")) is False


def test_file_not_found_is_not_retriable() -> None:
    """404 surfaces as FileNotFoundError — callers may handle it
    (lookups that legitimately miss). No retry."""
    assert _is_storage_transient(FileNotFoundError("missing")) is False


def test_payload_too_large_is_not_retriable() -> None:
    """413 → PayloadTooLargeError. No amount of waiting fixes an
    oversize body. Caller must reduce the payload."""
    exc = PayloadTooLargeError("path/x.json", 15 * 1024 * 1024, 413)
    assert _is_storage_transient(exc) is False


def test_generic_exception_is_not_retriable() -> None:
    """Anything outside the two retriable families → no retry. We
    don't want a ValueError or KeyError to burn the retry budget."""
    assert _is_storage_transient(ValueError("bad input")) is False
    assert _is_storage_transient(KeyError("missing")) is False
