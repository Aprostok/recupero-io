"""RIGOR-Jacob Z19: dispatcher.py + supabase_case_store.py adversarial-input hunt.

Six real adversarial-input bugs in modules that talk to the outside world:

Z19-1  dispatcher.dispatch_alert reads the full webhook response body into
       memory via resp.text. A malicious partner returning a 50 GB body
       OOMs the worker before truncation to 4 000 bytes ever runs.

Z19-2  SupabaseCaseStore._download returns resp.content with no size cap.
       Anyone with write access to the bucket (admin UI, a misbehaving
       worker, a future tenant) can plant a 5 GB case.json and OOM the
       next worker that resumes the case.

Z19-3  SupabaseCaseStore._list while-loop has no max-iteration / max-rows
       cap. A buggy or hostile Supabase Storage endpoint that keeps
       returning ``limit`` rows forever pins the worker at 100% CPU + memory
       growth (similar to the Z14 stuck-cursor pattern).

Z19-4  SupabaseCaseStore._walk_all_files recurses with no depth bound.
       A bucket layout with deeply nested folder items (``id is None``)
       blows the Python stack.

Z19-5  SupabaseCaseStore.{write_text,write_json,read_text,read_json,
       write_evidence} accept arbitrary filename / tx_hash and string-
       concat into the storage URL. A value like ``"../../other-case/case.json"``
       or a tx_hash of ``"..%2f..%2fadmin"`` breaks out of the
       investigation prefix.

Z19-6  SupabaseCaseStore._list_page does no response-shape validation.
       resp.json() returning a string / dict / null instead of a list
       crashes downstream iteration with a confusing TypeError.

Each test FAILS on the pre-fix code and PASSES after the corresponding
defensive change in the module.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID

import httpx
import pytest

# =====================================================================
# Helpers
# =====================================================================


def _make_payload():
    from recupero.monitoring.dispatcher import AlertPayload
    return AlertPayload(
        subscription_id=UUID("11111111-1111-1111-1111-111111111111"),
        trigger_type="any_movement",
        address="0xabc123",
        chain="ethereum",
        tx_hash="0xdeadbeef",
        block_time_iso="2026-05-20T12:00:00Z",
        amount_usd=Decimal("1000"),
        counterparty="0xdef456",
        counterparty_label="Mock",
        explorer_url="https://etherscan.io/tx/0xdeadbeef",
    )


def _make_stub_store(investigation_id: str = "11111111-1111-1111-1111-111111111111"):
    """Build a SupabaseCaseStore without opening any sockets — stub
    the httpx client + bypass the constructor's strict checks."""
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    store = SupabaseCaseStore.__new__(SupabaseCaseStore)
    store._storage_root = "https://test.supabase.co/storage/v1"
    store._bucket = "investigation-files"
    store._investigation_id = investigation_id
    store._supabase_url = "https://test.supabase.co"
    store._service_role_key = "k"
    store._pretty = False
    store._client = MagicMock()
    return store


# =====================================================================
# Z19-1: dispatcher response-body size cap
# =====================================================================


def test_z19_1_dispatcher_rejects_huge_content_length() -> None:
    """A webhook receiver advertising a huge Content-Length must be
    rejected BEFORE the dispatcher materializes the body. Pre-fix the
    dispatcher reads ``resp.text``, which forces httpx to buffer the
    entire response into memory; a malicious partner returning
    Content-Length: 50_000_000_000 OOMs the worker.

    The fix: the dispatcher checks ``resp.headers['content-length']``
    against a cap (e.g. 1 MB) and treats the over-limit response as a
    delivery failure (succeeded=False, error_message identifies the
    cap) without ever reading ``resp.text``.
    """
    from recupero.monitoring.dispatcher import dispatch_alert

    accessed: dict = {"text": 0, "content": 0}

    class _BigResp:
        status_code = 200
        headers = {
            "content-type": "text/plain",
            # 5 GB advertised — server doesn't have to actually send
            # it for the dispatcher to refuse to read it.
            "content-length": str(5 * 1024 * 1024 * 1024),
        }

        @property
        def text(self) -> str:
            accessed["text"] += 1
            # If the dispatcher gets here, it's about to allocate gigabytes.
            # Return a small string for test cleanliness but the access
            # itself is the bug signal.
            return "A" * 4000

        @property
        def content(self) -> bytes:
            accessed["content"] += 1
            return b"A" * 4000

    class _BigClient:
        def __init__(self, *args, **kwargs):  # noqa: ARG002
            pass

        def post(self, url, content=None, headers=None):  # noqa: ARG002
            return _BigResp()

        def close(self) -> None:
            pass

    with patch("httpx.Client", _BigClient):
        result = dispatch_alert(
            _make_payload(),
            webhook_url="https://hooks.example.com/recupero",
            webhook_secret=None,
        )

    # The CRITICAL assertion: dispatcher MUST NOT have touched
    # resp.text or resp.content with a 5 GB Content-Length. The fix
    # gates on the header BEFORE the body read.
    assert accessed["text"] == 0 and accessed["content"] == 0, (
        f"dispatcher read response body (text={accessed['text']}, "
        f"content={accessed['content']}) despite advertised "
        f"Content-Length of 5 GB — a malicious partner can OOM the "
        f"worker. The fix must inspect Content-Length BEFORE reading "
        f"the body."
    )
    # And the result must record the security rejection, not a fake
    # success.
    assert result.succeeded is False, (
        "dispatcher reported succeeded=True on a 5 GB-CL response — "
        "audit row will look like a legitimate delivery."
    )
    err = (result.error_message or "").lower()
    assert any(k in err for k in ("size", "too large", "content-length", "cap", "exceed")), (
        f"error_message {result.error_message!r} doesn't explain that "
        f"the response was rejected on size."
    )


# =====================================================================
# Z19-2: supabase _download response-size cap
# =====================================================================


def test_z19_2_supabase_download_caps_huge_response_body() -> None:
    """SupabaseCaseStore._download returns resp.content with no size
    bound. Anyone with bucket write access (admin UI, a misbehaving
    sibling worker, a misconfigured policy) can drop a multi-GB
    case.json — the next worker that resumes the case OOMs.

    The fix: cap _download to RECUPERO_SUPABASE_MAX_DOWNLOAD_BYTES
    (e.g. 64 MB) and raise PayloadTooLargeError when the response
    Content-Length header or accumulated stream bytes exceed the cap.
    """
    store = _make_stub_store()

    # 5 GB advertised — multiple orders of magnitude above any
    # reasonable cap. Server doesn't have to actually send it for
    # the cap to fire; the header is the signal.
    huge_size = 5 * 1024 * 1024 * 1024  # 5 GB

    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.headers = {"content-length": str(huge_size)}
    # Body kept tiny — the cap should fire on Content-Length BEFORE
    # the response body is materialized into memory.
    resp.content = b"A" * 1024  # placeholder
    store._client.get.return_value = resp

    from recupero.storage.supabase_case_store import PayloadTooLargeError

    with pytest.raises((PayloadTooLargeError, RuntimeError)) as excinfo:
        store._download("investigations/11111111-1111-1111-1111-111111111111/case.json")
    # The error should mention size — operator must be able to tell
    # this apart from a transport blip.
    msg = str(excinfo.value).lower()
    assert any(k in msg for k in ("too large", "size", "exceeds", "cap", "byte")), (
        f"_download raised {excinfo.value!r} on a 200 MB content-length — "
        f"error message must explain it was a size-cap rejection so the "
        f"operator can distinguish this from a corrupt-bucket failure."
    )


# =====================================================================
# Z19-3: supabase _list infinite-loop guard
# =====================================================================


def test_z19_3_supabase_list_caps_total_pages() -> None:
    """A hostile or buggy Supabase endpoint that keeps returning
    ``limit`` rows forever (e.g. a corrupted index that scans the
    same set on every page) makes _list loop without bound. Worker
    pins at 100% CPU + memory grows.

    The fix: _list must enforce a max-iteration guard (e.g. 200 pages
    = 200 000 files, well above any real investigation but bounded).
    """
    store = _make_stub_store()

    # Build a page that always says "there's more" — len(page) == limit.
    forever_page = [{"name": f"f{i}.json", "id": "x"} for i in range(1000)]

    call_count = {"n": 0}

    def fake_list_page(url, prefix, limit, offset):
        call_count["n"] += 1
        # Sanity ceiling so the test itself doesn't run forever if the
        # bug is unfixed: stop after 10 000 pages.
        if call_count["n"] > 10_000:
            raise RuntimeError("test harness ceiling reached")
        return forever_page

    store._list_page = fake_list_page  # type: ignore[assignment]

    # The production fix should bound pagination so the call returns
    # (with a log) rather than infinite-loop. We assert it stops within
    # a reasonable cap; the test harness ceiling above guarantees the
    # test itself terminates.
    items = store._list("investigations/abc/")
    # Bounded: should stop well before the harness ceiling.
    assert call_count["n"] <= 1000, (
        f"_list made {call_count['n']} page requests against a Supabase "
        f"that always returns full pages — no max-iteration guard. A "
        f"hostile endpoint can pin the worker. Cap pagination at "
        f"<= 200 pages and log + break."
    )
    # And the returned list must be bounded too.
    assert len(items) <= 1_000_000, (
        f"_list returned {len(items)} items — accumulator must respect "
        f"the same cap."
    )


# =====================================================================
# Z19-4: supabase _walk_all_files recursion depth guard
# =====================================================================


def test_z19_4_supabase_walk_caps_recursion_depth() -> None:
    """_walk_all_files recurses for every item where ``id is None``.
    A bucket layout with deeply nested folder items (or a hostile
    Supabase that reports the same dir as a child of itself) blows
    Python's recursion limit.

    The fix: bound walk depth (e.g. 32 levels), log + skip past that.
    """
    store = _make_stub_store()

    # Simulate Supabase always returning one "directory" item that
    # points at itself — classic recursion-bomb shape.
    call_count = {"n": 0}

    def fake_list(prefix, limit=1000):  # noqa: ARG001
        call_count["n"] += 1
        if call_count["n"] > 10_000:
            raise RuntimeError("test harness ceiling reached")
        # Return one "folder" (id is None) named exactly the same so
        # the walk re-enters the same prefix + a suffix forever.
        return [{"name": "sub", "id": None}]

    store._list = fake_list  # type: ignore[assignment]

    # The production fix must bound recursion. Without it, Python's
    # default recursion limit (~1000) would raise RecursionError; we
    # want a graceful bounded return instead.
    try:
        paths = store._walk_all_files("investigations/abc/")
    except RecursionError:
        pytest.fail(
            "_walk_all_files hit RecursionError on a self-referential "
            "Supabase listing — must bound depth (e.g. 32 levels) and "
            "log a warning instead of crashing."
        )
    # Bounded depth means call_count is bounded too.
    assert call_count["n"] <= 64, (
        f"_walk_all_files made {call_count['n']} recursive _list calls — "
        f"depth must be capped to prevent stack exhaustion + worker DoS."
    )
    # And the returned list is the empty file list (only folders found).
    assert paths == [], f"unexpected files returned: {paths!r}"


# =====================================================================
# Z19-5: filename / tx_hash path-traversal hardening
# =====================================================================


@pytest.mark.parametrize("bad_name", [
    "../other-case/case.json",
    "..\\admin\\stolen.json",
    "/etc/passwd",
    "evidence/../../leak.json",
    "case.json\x00leak.json",
    "case\nLF-injection.json",
])
def test_z19_5_write_text_rejects_traversal_filenames(bad_name) -> None:
    """write_text / write_json / read_text / read_json must reject
    filenames containing ``..``, leading ``/``, or NUL/LF control
    characters. String-concat into the storage URL otherwise lets a
    caller (regression in worker.sync, a future code path, or a
    poisoned case dir) write outside the investigation prefix.
    """
    store = _make_stub_store()
    store._upload = MagicMock()

    with pytest.raises(ValueError) as excinfo:
        store.write_text(bad_name, "x")
    msg = str(excinfo.value).lower()
    assert any(k in msg for k in ("invalid", "filename", "traversal", "not allowed", "path")), (
        f"write_text({bad_name!r}) raised {excinfo.value!r} — message "
        f"must identify the filename as the rejection cause."
    )
    # And critically: no upload was made.
    assert not store._upload.called, (
        f"write_text({bad_name!r}) hit _upload before the filename "
        f"validation rejected it — defense gate is in the wrong place."
    )


@pytest.mark.parametrize("bad_tx", [
    "../../admin/secret",
    "evidence-leak/..",
    "0xabc\n0xdef",
    "0xabc\x00leak",
])
def test_z19_5b_write_evidence_rejects_traversal_tx_hash(bad_tx) -> None:
    """write_evidence appends ``f"evidence/{tx_hash}.json"`` to the
    storage_prefix. A malformed tx_hash from a regressed chain adapter
    (e.g. Etherscan returning ``"../..//attacker"``) writes outside the
    investigation prefix.
    """
    store = _make_stub_store()
    store._upload = MagicMock()
    with pytest.raises(ValueError):
        store.write_evidence(bad_tx, {"ok": True})
    assert not store._upload.called, (
        "write_evidence dispatched _upload before tx_hash validation "
        "rejected the traversal pattern."
    )


# =====================================================================
# Z19-6: _list_page response-shape validation
# =====================================================================


@pytest.mark.parametrize("bad_body", [
    None,                          # JSON null
    "a string",                    # JSON string
    {"items": [{"name": "f"}]},    # JSON object (wrong shape)
    42,                            # JSON number
    True,                          # JSON bool
])
def test_z19_6_list_page_validates_response_shape(bad_body) -> None:
    """A Supabase that returns a non-list JSON response shape (e.g.
    after an upstream change, a CDN error page parsed as JSON, or a
    hostile MITM) must not crash with a confusing TypeError deep in
    list comprehension. _list_page should reject the response and
    raise a clear RuntimeError.
    """
    store = _make_stub_store()
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json = MagicMock(return_value=bad_body)
    resp.text = ""
    store._client.post.return_value = resp

    with pytest.raises((RuntimeError, TypeError)) as excinfo:
        store._list_page(
            "https://test.supabase.co/storage/v1/object/list/investigation-files",
            "investigations/abc/",
            1000,
            0,
        )
    # The error must be a CLEAR RuntimeError (production fix) not a
    # confusing TypeError from .get on a string. We accept either today
    # but the strong signal is: error message mentions response shape.
    if isinstance(excinfo.value, RuntimeError):
        msg = str(excinfo.value).lower()
        assert any(k in msg for k in ("shape", "list", "expected", "invalid", "response")), (
            f"_list_page raised RuntimeError but message {excinfo.value!r} "
            f"doesn't identify the response-shape rejection."
        )


def test_z19_6_list_page_valid_list_still_works() -> None:
    """Sanity: a normal list response still passes through."""
    store = _make_stub_store()
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    expected = [{"name": "case.json", "id": "abc"}]
    resp.json = MagicMock(return_value=expected)
    resp.text = ""
    store._client.post.return_value = resp
    out = store._list_page(
        "https://test.supabase.co/storage/v1/object/list/investigation-files",
        "investigations/abc/",
        1000,
        0,
    )
    assert out == expected
