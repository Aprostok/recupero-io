"""Wave-10 deeper hardening for investigations_api.

These RED tests probe the Supabase Storage adapter for traversal,
token-leak, malformed-response, and prefix-isolation defects beyond
the Wave-9 sign-URL fix. They mock urllib.request.urlopen so they
run with zero network in <50ms.
"""

from __future__ import annotations

import io
import json
from unittest import mock

import pytest

from recupero.worker import investigations_api as mod

# ---- helpers ---- #


class _FakeResp:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


# ---- 1. object_path traversal in sign-URL ---- #


def test_sign_storage_url_rejects_dotdot_traversal() -> None:
    """A caller (or upstream bug) passing ``..`` in object_path must
    NOT round-trip into the signed URL request. urllib.parse.quote
    leaves '..' intact when safe='/', so a defense-in-depth check
    is required."""
    captured: dict[str, object] = {}

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        return _FakeResp({"signedURL": "/object/sign/x/y?token=abc"})

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ValueError, match="(?i)traversal|invalid"):
            mod._sign_storage_url(
                supabase_url="https://x.supabase.co",
                service_role_key="sk_test",
                object_path="investigations/abc/../../etc/passwd",
                ttl_sec=60,
            )


# ---- 2. service-role token redaction on list path ---- #


def test_list_bucket_http_error_redacts_service_role_key() -> None:
    """If Supabase 5xx's with a body that echoes the Authorization
    header (observed in diagnostic-mode responses), the exception
    surfaced upward must NOT contain the raw service-role key.
    Reading the body for diagnostics is fine — leaking it is not."""
    secret = "eyJhbGciOiJIUzI1NiJ9.SUPER_SECRET_TOKEN_XYZ.sig"

    # Simulate a misbehaving Supabase that echoes our auth header.
    def boom(req, timeout=10):
        body = json.dumps({"error": "internal", "echo_auth": f"Bearer {secret}"})
        raise mod.urllib.error.HTTPError(
            req.full_url, 500, "server error", hdrs=None,
            fp=io.BytesIO(body.encode()),
        )

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=boom):
        with pytest.raises(Exception) as exc:
            mod._list_bucket("https://x.supabase.co", secret, "investigations/abc/")
    assert secret not in str(exc.value), \
        f"service-role token leaked into list-path exception: {exc.value!r}"
    assert secret not in repr(exc.value)


# ---- 3. malformed JSON response shape ---- #


def test_list_bucket_rejects_non_list_response() -> None:
    """Supabase's list endpoint must return a JSON array. If a
    proxy/CDN swaps in an error-envelope dict (e.g. ``{"error": ...}``),
    we must raise a typed error rather than silently returning a dict
    whose iteration order yields meaningless keys."""
    def fake_urlopen(req, timeout=10):
        # Error envelope shape: not a list
        return _FakeResp({"error": "not_found", "message": "no such bucket"})

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises((TypeError, ValueError, RuntimeError)):
            mod._list_bucket("https://x.supabase.co", "sk", "investigations/abc/")


# ---- 4. prefix isolation: malicious investigation_id ---- #


def test_build_artifacts_map_rejects_traversal_in_investigation_id() -> None:
    """If a buggy caller passes an investigation_id like
    ``abc/../def``, the constructed prefix would escape the
    investigation's own directory. _build_artifacts_map must
    reject such ids before composing the prefix."""
    def fake_urlopen(req, timeout=10):
        return _FakeResp([])

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
        with pytest.raises(ValueError, match="(?i)invalid|traversal"):
            mod._build_artifacts_map(
                supabase_url="https://x.supabase.co",
                service_role_key="sk",
                investigation_id="abc/../other-investigation",
                ttl_sec=60,
            )


def test_build_artifacts_map_rejects_slash_in_investigation_id() -> None:
    """A leading or embedded slash also breaks prefix isolation
    (e.g. ``/etc`` or ``foo/bar`` would land under a different prefix)."""
    with pytest.raises(ValueError, match="(?i)invalid|traversal"):
        mod._build_artifacts_map(
            supabase_url="https://x.supabase.co",
            service_role_key="sk",
            investigation_id="foo/bar",
            ttl_sec=60,
        )


# ---- 5. token redaction on summary path ---- #


def test_build_summary_rejects_traversal_in_investigation_id() -> None:
    """_build_summary inlines investigation_id into the case.json
    URL. A traversal-unsafe id (``abc/../other``) would let summary
    pull case.json from an unrelated investigation. The function is
    best-effort (catches Exception) but it must NOT issue an HTTP
    request constructed from a poisoned id at all."""
    calls: list[str] = []

    def fake_urlopen(req, timeout=10):
        calls.append(req.full_url)
        return _FakeResp({})

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
        out = mod._build_summary(
            supabase_url="https://x.supabase.co",
            service_role_key="sk",
            investigation_id="abc/../other-investigation",
        )
    # Empty/zero shape on rejected id — and crucially, no HTTP
    # request fired against the traversal-poisoned path.
    assert out["transfers"] == 0
    assert calls == [], f"summary made network call with poisoned id: {calls!r}"


# ---- 6. response shape: list_bucket returns sane shape ---- #


def test_list_bucket_returns_list_for_valid_array() -> None:
    """Sanity check: a valid array response still passes through
    unmodified after the shape-validation fix."""
    sample = [{"name": "case.json", "metadata": {"size": 42, "mimetype": "application/json"}}]

    def fake_urlopen(req, timeout=10):
        return _FakeResp(sample)

    with mock.patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
        out = mod._list_bucket("https://x.supabase.co", "sk", "investigations/abc/")
    assert out == sample
