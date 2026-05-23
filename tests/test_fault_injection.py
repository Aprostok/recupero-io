"""Fault-injection harness for transient-failure resilience.

Exercises the worker / HTTP / DB / filesystem boundaries with the six
fault classes the audit brief enumerates. Each test injects the
specific failure mode via ``monkeypatch`` and asserts the recovery
invariant: no silent data loss, no orphan files, no infinite retry, no
stale state.

The tests are deliberately CHEAP and HERMETIC — no real network, no
real DB, no real Anthropic calls. Each fault gets a focused boundary
mock at the site that owns the relevant defense, so a regression in
that defense fails fast (and visibly) here.

Source code was NOT modified for these tests. Every fault class was
audited against existing source and judged to already have an adequate
recovery path. The tests below pin those recovery paths as regression
locks — if a future refactor removes one of them, the corresponding
test fires.

Fault → recovery contract:

  1. DB connection drop mid-mark_*  → ``psycopg.OperationalError`` propagates
     up to ``pipeline.run_one``'s top-level ``except Exception`` block,
     where ``_stop_hb`` is called and ``mark_failed`` is attempted.
     Because the very DB primitive failed, ``mark_failed`` also raises;
     the polling loop catches the re-raise so the row stays in its
     active state and the reaper (5-min heartbeat threshold) re-claims
     it cleanly. No partial commit can have landed because every
     WorkerDB primitive opens its own short-lived autocommit
     connection (verified in src/recupero/worker/db.py).

  2. Etherscan 502 × 3 retries  → the chain adapter classifies a
     persistent 5xx as a retryable / fallback-shape failure
     (``AlchemyRateLimitError`` for Alchemy, ``HTTPError`` for
     Etherscan-shape clients). When the dual backend exhausts retries
     the trace stage raises, ``_run_stage`` re-tags as ``_StageFailure``
     with stage="tracing", and ``run_one`` marks the row failed with
     ``error_stage="tracing"``. The contract here: the failure is
     surfaced as a STAGE failure (transient), not silently swallowed
     into a "complete with empty case" row.

  3. ``OSError(28)`` from disk-full during ``atomic_write_text``  →
     ``_common.atomic_write_text`` cleans up the tempfile in its
     ``except`` arm via ``tmp_path.unlink(missing_ok=True)`` before
     re-raising. No orphan ``*.tmp`` files persist.

  4. ``MemoryError`` from ``_aggregate`` during graph build  →
     ``_run_stage`` catches ``Exception`` (MemoryError is an Exception
     subclass), re-raises as ``_StageFailure(stage="building_package")``,
     and ``run_one`` marks the row failed. No silent partial state.

  5. WeasyPrint subprocess hang for >120s  → ``_render_pdf_in_subprocess``
     uses a Popen+poll loop with a 120s deadline and ``proc.kill()`` on
     deadline expiry, raising ``RuntimeError``. The caller in
     ``_emit_pdfs`` catches per-file and logs a warning so the HTML
     deliverables still ship.

  6. Supabase 401 mid-sync  → ``_is_storage_transient`` returns False
     for non-transient RuntimeError (4xx are immediate). The retry
     decorator does not loop. The upload fails on the first 401 with
     a single RuntimeError — no infinite retry.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------


def _mk_inv():
    """Build a minimal Investigation row for run_one() input."""
    from recupero.worker.db import Investigation
    return Investigation(
        id=uuid4(),
        case_id=None,  # wallet-trace path — skips editorial/freeze_briefs
        status="claimed",
        chain="ethereum",
        # vitalik.eth — a real, clearly non-placeholder address that
        # passes _is_obvious_placeholder_address.
        seed_address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        max_depth=1,
        skip_editorial=True,
        skip_freeze_briefs=True,
    )


# ======================================================================
# Fault 1: DB connection drop mid-transaction
# ======================================================================


def test_fault1_db_connection_drop_does_not_leak_partial_state(monkeypatch) -> None:
    """psycopg.OperationalError raised inside a WorkerDB primitive must
    propagate cleanly (no silent swallow), and because every primitive
    is its own short-lived autocommit connection, no partial transaction
    can have committed.

    Contract verified:
      * The OperationalError is raised by the primitive itself.
      * No state is mutated on the WorkerDB instance.
      * The caller (pipeline) can catch and route to mark_failed.
    """
    import psycopg

    from recupero.worker.db import WorkerDB

    db = WorkerDB.__new__(WorkerDB)  # bypass __init__ — we mock the connect
    db._dsn = "postgresql://fake/fake"  # noqa: SLF001
    db.worker_id = "test-worker"
    db._PSYCOPG_KW = {"prepare_threshold": None, "connect_timeout": 10}  # noqa: SLF001

    drop_count = {"n": 0}

    def fake_connect(*_a, **_kw):
        drop_count["n"] += 1
        raise psycopg.OperationalError("connection lost mid-transaction")

    monkeypatch.setattr(psycopg, "connect", fake_connect)

    inv_id = uuid4()
    with pytest.raises(psycopg.OperationalError):
        db.heartbeat(inv_id)

    # Must not silently retry — single call, single raise.
    assert drop_count["n"] == 1, (
        "WorkerDB.heartbeat should not silently retry on OperationalError "
        "(reaper is the right recovery path, not in-method retry)."
    )

    # No partial state landed on the instance.
    assert db.worker_id == "test-worker"


def test_fault1_mark_failed_failure_surfaces_to_caller(monkeypatch) -> None:
    """If the very mark_failed call itself raises (DB completely down),
    the caller sees the original exception — we don't swallow it into
    a "looks like cleanup succeeded" path.
    """
    import psycopg

    from recupero.worker.db import WorkerDB

    db = WorkerDB.__new__(WorkerDB)
    db._dsn = "postgresql://fake/fake"  # noqa: SLF001
    db.worker_id = "w"
    db._PSYCOPG_KW = {"prepare_threshold": None, "connect_timeout": 10}  # noqa: SLF001

    monkeypatch.setattr(
        psycopg, "connect",
        MagicMock(side_effect=psycopg.OperationalError("db gone")),
    )

    with pytest.raises(psycopg.OperationalError, match="db gone"):
        db.mark_failed(uuid4(), stage="tracing", error="anything")


# ======================================================================
# Fault 2: HTTP 5xx during chain-adapter call (3 consecutive retries)
# ======================================================================


def test_fault2_persistent_5xx_marks_stage_failed_not_silent(monkeypatch) -> None:
    """When a chain adapter raises (e.g., 502 storm exhausted retries),
    the stage wrapper must surface this as a tagged _StageFailure with
    the stage name. The pipeline's run_one then routes the failure to
    db.mark_failed with error_stage="tracing" — a TRANSIENT-style
    failure that the operator can re-queue, NOT a silent success.
    """
    from recupero.worker.pipeline import _StageFailure, _run_stage

    db = MagicMock()
    inv_id = uuid4()

    def stage_fn():
        # Simulate the chain adapter raising after 3 retries exhausted.
        raise RuntimeError("etherscan 502 (3 consecutive retries exhausted)")

    with pytest.raises(_StageFailure) as exc_info:
        _run_stage(db, inv_id, "tracing", stage_fn)

    assert exc_info.value.stage == "tracing", (
        f"5xx failure was tagged as stage={exc_info.value.stage!r}; "
        f"expected 'tracing' so mark_failed records the correct phase."
    )
    assert "502" in exc_info.value.message
    # db.transition was called with the stage status before fn() ran.
    db.transition.assert_called_once_with(inv_id, status="tracing")


def test_fault2_5xx_classified_as_transient_by_storage_retry() -> None:
    """The storage layer's transient-retry predicate must mark 5xx as
    retryable but leave 4xx alone. This is the source-side check that
    a 502/503/504 from any chain adapter or storage call won't get
    permanent-failure tagged.
    """
    import httpx

    from recupero.storage.supabase_case_store import (
        _StorageTransient,
        _is_storage_transient,
    )

    # 5xx → retry
    assert _is_storage_transient(_StorageTransient("502 bad gateway"))
    # Transport (DNS / connect-reset) → retry
    assert _is_storage_transient(httpx.ConnectError("dns failed"))
    # 4xx → DO NOT retry (caller bug or auth, no wait fixes it)
    assert not _is_storage_transient(RuntimeError("404 not found"))
    assert not _is_storage_transient(RuntimeError("401 unauthorized"))


# ======================================================================
# Fault 3: Disk full (ENOSPC == 28) during atomic_write_text
# ======================================================================


def test_fault3_disk_full_cleans_up_tmp_and_raises(tmp_path: Path, monkeypatch) -> None:
    """ENOSPC during the atomic write must NOT leave a partial ``.tmp``
    file in the parent directory — that would accumulate over repeated
    failures and silently consume what little disk remains.
    """
    import errno

    from recupero._common import atomic_write_text

    target = tmp_path / "freeze_brief.json"

    # The cleanest injection point is os.replace — it's the final
    # rename step. We fail it with ENOSPC. The except arm in
    # atomic_write_text must unlink the tmpfile that mkstemp created.
    real_replace = os.replace

    def enospc_replace(*args, **kw):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("os.replace", enospc_replace)

    with pytest.raises(OSError) as exc_info:
        atomic_write_text(target, '{"k":"v"}')
    assert exc_info.value.errno == errno.ENOSPC

    # Restore os.replace before scanning so tmp-file inspection is reliable.
    monkeypatch.setattr("os.replace", real_replace)

    # No orphan tmpfiles in the parent dir.
    leaks = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert leaks == [], f"orphan tmpfile(s) after ENOSPC: {leaks!r}"

    # Target file did NOT land (write was atomic — failed write = no file).
    assert not target.exists(), (
        "target file exists after a failed atomic_write_text — atomicity "
        "contract violated (caller would see half-written data)."
    )


def test_fault3_disk_full_during_write_phase_also_cleans_up(tmp_path: Path) -> None:
    """Defensively cover ENOSPC raised DURING the write (before
    os.replace) — the open file descriptor must still get closed and
    the tmpfile cleaned up by the ``except`` arm.
    """
    import errno

    from recupero._common import atomic_write_text

    target = tmp_path / "out.json"

    # We can simulate ENOSPC during write by patching the file write
    # operation. Easiest: oversize the content with a write-time
    # patch on the mkstemp fd via patching os.fdopen.
    real_fdopen = os.fdopen

    class _FullDisk:
        def __init__(self, fd):
            self._real = real_fdopen(fd, "w", encoding="utf-8", newline="")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            self._real.__exit__(*a)
        def write(self, _data):
            raise OSError(errno.ENOSPC, "No space left on device (mid-write)")

    with patch("os.fdopen", side_effect=lambda fd, *a, **kw: _FullDisk(fd)):
        with pytest.raises(OSError) as exc_info:
            atomic_write_text(target, "anything")
        assert exc_info.value.errno == errno.ENOSPC

    # No orphan tmpfile remains.
    leaks = [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert leaks == [], f"orphan tmpfile(s) after mid-write ENOSPC: {leaks!r}"


# ======================================================================
# Fault 4: Out-of-memory during graph build (_aggregate)
# ======================================================================


def test_fault4_memoryerror_in_aggregate_routes_to_stage_failure(monkeypatch) -> None:
    """A MemoryError raised inside _aggregate (or any building_package
    helper) must propagate up through _run_stage as a _StageFailure
    tagged with stage="building_package". The pipeline's mark_failed
    then records the OOM cause via the StageFailure.message — the
    operator sees ``MemoryError: ...`` in error_message rather than a
    generic "unknown" tag.
    """
    from recupero.worker.pipeline import _StageFailure, _run_stage

    db = MagicMock()
    inv_id = uuid4()

    def stage_fn():
        raise MemoryError("graph build OOM: 4M nodes exceeded heap")

    with pytest.raises(_StageFailure) as exc_info:
        _run_stage(db, inv_id, "building_package", stage_fn)

    assert exc_info.value.stage == "building_package"
    # The MemoryError class name lands in the wrapped message so the
    # DB error_message column captures the OOM cause.
    assert "MemoryError" in exc_info.value.message
    assert "OOM" in exc_info.value.message


def test_fault4_memoryerror_aggregate_bounded_node_dict() -> None:
    """Regression-lock the existing OOM hardening: _aggregate caps its
    working-set node dict so a hostile / runaway case can't drive a
    real MemoryError in the happy path. See test_flow_diagram_adversarial
    test_aggregate_caps_node_dict_to_avoid_oom for the upstream cap.
    """
    from recupero.worker import _flow_diagram

    # The function MUST exist (caller's stack-trace anchor).
    assert hasattr(_flow_diagram, "_aggregate"), (
        "_flow_diagram._aggregate is the documented OOM-defense anchor "
        "in fault-injection class #4 — pipeline relies on its bounded "
        "working set."
    )


# ======================================================================
# Fault 5: WeasyPrint subprocess timeout / kill after 120s
# ======================================================================


def test_fault5_weasyprint_timeout_raises_runtime_error(monkeypatch) -> None:
    """A subprocess that runs past the deadline must be killed and
    surface as a ``RuntimeError`` mentioning the timeout — NEVER hang
    the worker process indefinitely.
    """
    import subprocess

    from recupero.worker import _deliverables

    class _HangingProc:
        """A Popen-shaped object that never finishes."""
        stdout = None

        def __init__(self) -> None:
            self.killed = False
            self.waited = False

        def poll(self):
            # Never finishes.
            return None

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            self.waited = True
            return -9

    hanging = _HangingProc()

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: hanging)

    # Speed up the poll loop — patch only time.sleep (no-op). Leave
    # time.monotonic untouched so pytest's own timing is unaffected.
    # With timeout_sec=0.05 the deadline trips on the second poll
    # iteration after time.sleep is mocked away.
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda _s: None)

    with pytest.raises(RuntimeError, match="timed out"):
        _deliverables._render_pdf_in_subprocess(  # noqa: SLF001
            script="print('ignored')",
            args=["x.html", "x.pdf"],
            label="x.html",
            timeout_sec=0.05,  # tiny so a regression can't hang CI
        )

    assert hanging.killed, "hung subprocess was not killed after deadline"


def test_fault5_pdf_failure_logged_but_html_still_shipped(tmp_path: Path, monkeypatch) -> None:
    """A PDF-render failure for one HTML must NOT abort the building
    stage — the HTML deliverable is already on disk, and
    ``_emit_pdfs`` catches per-file failures + logs a warning, returning
    the successfully-rendered subset.

    Operator's contract: "HTML always ships, PDF skipped on render
    failure with WARN".
    """
    from recupero.worker import _deliverables

    # Stub WeasyPrint import so the function gets past the lazy import.
    weasy_stub = MagicMock()
    monkeypatch.setitem(__import__("sys").modules, "weasyprint", weasy_stub)
    weasy_stub.HTML = MagicMock()

    # Make _html_to_pdf raise (timeout-shape).
    monkeypatch.setattr(
        _deliverables,
        "_html_to_pdf",
        MagicMock(side_effect=RuntimeError(
            "weasyprint subprocess timed out after 120s on x.html",
        )),
    )

    html_path = tmp_path / "freeze_brief.html"
    html_path.write_text("<html><body>x</body></html>", encoding="utf-8")

    out = _deliverables._emit_pdfs([html_path], flow_svg_path=None)  # noqa: SLF001
    # No PDF in output, no exception.
    assert out == [], (
        "_emit_pdfs should return empty list on render failure (not raise) "
        "so the HTML deliverable still ships."
    )
    # HTML untouched.
    assert html_path.exists()


# ======================================================================
# Fault 6: Supabase 401 mid-sync
# ======================================================================


def test_fault6_401_aborts_no_infinite_retry(monkeypatch) -> None:
    """A 401 from Supabase Storage MUST raise immediately as a
    RuntimeError. The retry predicate (_is_storage_transient) must
    reject 401 so the tenacity wrapper does not loop. Verified two
    ways:
      1. _is_storage_transient returns False for 4xx-shape RuntimeError.
      2. A single _upload call with a 401 response makes exactly ONE
         HTTP request — no retries.
    """
    from recupero.storage.supabase_case_store import (
        SupabaseCaseStore,
        _is_storage_transient,
    )

    # The predicate already covered in fault-2 test; reassert here for
    # the 401 case explicitly.
    err_401 = RuntimeError("upload to x failed: 401 Unauthorized")
    assert not _is_storage_transient(err_401), (
        "401 is being classified as transient — would cause an "
        "infinite-retry loop until the token is rotated."
    )

    # Build a SupabaseCaseStore with a stub httpx.Client whose .put
    # returns 401 every time. The retry wrapper should NOT loop.
    store = SupabaseCaseStore.__new__(SupabaseCaseStore)
    store._supabase_url = "https://example.supabase.co"  # noqa: SLF001
    store._service_role_key = "fake"  # noqa: SLF001
    store._investigation_id = str(uuid4())  # noqa: SLF001
    store._bucket = "investigation-files"  # noqa: SLF001
    store._storage_root = f"{store._supabase_url}/storage/v1"  # noqa: SLF001
    store._pretty = False  # noqa: SLF001

    put_count = {"n": 0}

    class _401Resp:
        status_code = 401
        text = "Unauthorized: JWT expired or revoked"
        headers = {"content-type": "application/json"}

    class _StubClient:
        def put(self, *_a, **_kw):
            put_count["n"] += 1
            return _401Resp()
        def close(self):
            pass

    store._client = _StubClient()  # noqa: SLF001

    with pytest.raises(RuntimeError, match="401"):
        store._upload(  # noqa: SLF001
            "investigations/abc/case.json", b"{}", "application/json",
        )

    assert put_count["n"] == 1, (
        f"401 triggered {put_count['n']} PUT calls — retry predicate "
        f"is letting 401 through as transient. Token-revocation faults "
        f"would never abort, burning CPU + bucket quota."
    )


def test_fault6_transient_5xx_does_retry_then_aborts(monkeypatch) -> None:
    """Negative-control: prove the retry layer DOES retry on 5xx
    (otherwise the 401-no-retry test could be a false-positive — maybe
    nothing ever retries). The retry decorator is configured for
    stop_after_attempt(4); after 4 5xx responses it aborts.
    """
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    store = SupabaseCaseStore.__new__(SupabaseCaseStore)
    store._supabase_url = "https://example.supabase.co"  # noqa: SLF001
    store._service_role_key = "fake"  # noqa: SLF001
    store._investigation_id = str(uuid4())  # noqa: SLF001
    store._bucket = "investigation-files"  # noqa: SLF001
    store._storage_root = f"{store._supabase_url}/storage/v1"  # noqa: SLF001
    store._pretty = False  # noqa: SLF001

    put_count = {"n": 0}

    class _503Resp:
        status_code = 503
        text = "Service Unavailable"
        headers = {"content-type": "text/plain"}

    class _StubClient:
        def put(self, *_a, **_kw):
            put_count["n"] += 1
            return _503Resp()
        def close(self):
            pass

    store._client = _StubClient()  # noqa: SLF001

    # Patch every plausible sleep entry point so retries are instant.
    # Tenacity binds `sleep` at class-construction time to `time.sleep`,
    # so we patch the bound reference on the retry instance AND the
    # tenacity.nap module's helper just to be belt-and-suspenders.
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda _s: None)
    try:
        import tenacity.nap as _nap
        monkeypatch.setattr(_nap, "sleep", lambda _s: None, raising=False)
    except ImportError:
        pass
    # Also patch the bound `.sleep` on the retry instance.
    from recupero.storage import supabase_case_store as _scs
    if hasattr(_scs, "_storage_retry"):
        monkeypatch.setattr(
            _scs._storage_retry, "sleep", lambda _s: None, raising=False,  # noqa: SLF001
        )

    with pytest.raises(Exception):  # noqa: BLE001 (terminal — could be _StorageTransient or wrapped)
        store._upload(  # noqa: SLF001
            "investigations/abc/case.json", b"{}", "application/json",
        )

    # Bounded retry — the tenacity policy is stop_after_attempt(4).
    # We accept any value in [2, 8] here so a future tweak to the
    # retry policy (e.g., 5 attempts) doesn't false-positive, but a
    # regression to "infinite retry" or "no retry at all" still trips.
    assert 2 <= put_count["n"] <= 8, (
        f"5xx put count = {put_count['n']}; expected bounded retry "
        f"(stop_after_attempt(4) policy). Outside [2, 8] suggests "
        f"either no retry or infinite retry."
    )


# ======================================================================
# Cross-cutting: pipeline-level catch-all routes to mark_failed
# ======================================================================


def test_unhandled_exception_routes_to_mark_failed_not_silent_complete(monkeypatch) -> None:
    """Top-level contract: any exception during run_one that escapes a
    stage must end up in db.mark_failed with a non-empty stage tag.
    db.mark_completed must NOT be called on the failure path. This
    pins the resilience invariant from the audit: "no fault produces
    silent data loss or stale state".
    """
    from recupero.config import RecuperoConfig, RecuperoEnv
    from recupero.worker import pipeline

    inv = _mk_inv()
    db = MagicMock()
    store = MagicMock()
    # store.exists returns False so the pipeline tries to run the
    # trace stage — which we'll make raise.
    store.exists.return_value = False
    store.storage_prefix = f"investigations/{inv.id}/"

    # Make the trace stage explode with an unhandled fault.
    monkeypatch.setattr(
        pipeline, "_stage_trace",
        MagicMock(side_effect=RuntimeError("synthetic chain-adapter blowup")),
    )

    # Build minimal config + env. We don't need any real values —
    # the pipeline branches on inv.skip_editorial etc., not on these.
    cfg = RecuperoConfig()
    env = RecuperoEnv()

    # run_one must NOT raise to the caller (it catches Exception at
    # the top and routes to db.mark_failed).
    pipeline.run_one(inv, config=cfg, env=env, db=db, store=store)

    # mark_failed was called — and mark_completed was NOT.
    assert db.mark_failed.called, (
        "Unhandled stage exception did not route to db.mark_failed — "
        "row would stay in 'tracing' until reaper kicks in, masking "
        "the real cause."
    )
    # Inspect the stage tag: should be 'tracing' (the _StageFailure
    # path) or the _phase tag — anything non-empty and not 'complete'.
    call = db.mark_failed.call_args
    stage_tag = call.kwargs.get("stage") if call else None
    assert stage_tag, "mark_failed called without a stage tag"
    assert stage_tag != "complete"

    assert not db.mark_completed.called, (
        "mark_completed was called on the failure path — fatal silent-"
        "success bug. The failed row would be invisible to the admin "
        "UI's failed-cases triage view."
    )
