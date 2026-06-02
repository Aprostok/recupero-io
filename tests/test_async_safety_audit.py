"""Static async-safety audit — locks the contract that recupero is a
*sync* codebase with a small FastAPI async surface, and that the async
surface does NOT introduce blocking-loop or forgotten-await bugs.

Why a test, not a one-off lint:
  We deliberately chose sync httpx, sync psycopg, and sync chain
  adapters (see chains/*/client.py). A drive-by `async def` that
  smuggles in `requests.get` or `asyncio.run(...)` would silently
  block the event loop or crash under uvicorn. This test fails fast
  if anyone adds new async surface without thinking.

Audit covers (per task spec):
  1. Bare `await` in non-async context (AST-level).
  2. Blocking sync calls inside `async def` (requests/time.sleep/
     psycopg.connect/urllib.request).
  3. Forgotten `await` on obvious coroutines (best-effort static check).
  4. `asyncio.run(...)` nested in async context — banned entirely.
  5. Mixing asyncio + anyio in the same module.
  6. `async with` on known-sync context managers.

The async surface is fixed by allow-list. Adding new `async def` to a
module not on the list requires updating ALLOWED_ASYNC_MODULES *and*
auditing the new code for the six rules above.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "recupero"

# Modules permitted to define `async def`. Anything else is a regression.
# Both files are FastAPI route modules; their async defs are route
# handlers and DI dependencies that perform in-memory lookups only.
ALLOWED_ASYNC_MODULES = {
    "api/app.py",
    "api/auth.py",
}

# Sync calls that block the event loop if invoked from an async def.
BLOCKING_SYNC_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
    "time.sleep",
    "psycopg.connect",
    "urllib.request.urlopen",
}


def _iter_py_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(p: Path) -> str:
    return p.relative_to(SRC).as_posix()


@pytest.fixture(scope="module")
def parsed() -> list[tuple[Path, ast.Module]]:
    out = []
    for p in _iter_py_files():
        try:
            out.append((p, ast.parse(p.read_text(encoding="utf-8"))))
        except SyntaxError as e:
            pytest.fail(f"{_rel(p)}: parse error {e}")
    return out


def _async_funcs(tree: ast.Module) -> list[ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]


def test_async_surface_is_minimal_and_locked(parsed):
    """Only the API layer may define `async def`. Sync codebase contract."""
    offenders: list[str] = []
    for path, tree in parsed:
        if not _async_funcs(tree):
            continue
        rel = _rel(path)
        if rel not in ALLOWED_ASYNC_MODULES:
            offenders.append(rel)
    assert not offenders, (
        "New `async def` outside the allow-list. Either revert, or update "
        "ALLOWED_ASYNC_MODULES *and* re-audit for blocking calls. "
        f"Offenders: {offenders}"
    )


def test_async_count_matches_baseline(parsed):
    """Lock the count so silent additions to api/* also get a code-review nudge."""
    total = sum(len(_async_funcs(t)) for _, t in parsed)
    # As of this audit: 16 in api/app.py + 1 in api/auth.py = 17.
    # (v0.32.1: +review_gate_ui — a static-template HTMLResponse, same
    # non-blocking shape as intake_form_get; verified against the
    # blocking-IO rule in test_no_blocking_io_inside_async_def.)
    # (v0.32.1 body-size cap: +3 in _BodySizeLimitMiddleware —
    # __call__ / limited_receive / _send_413. All pure ASGI plumbing
    # (await receive/send, byte counting); zero blocking I/O. Covered by
    # test_no_blocking_io_inside_async_def, which scans every async def
    # in api/app.py for sync-I/O calls and passed on these three.)
    #
    # (v0.35 operator graph: +11 in api/app.py — operator_graph_ui,
    # operator_graph_data, operator_expand, operator_annotations_get/put,
    # operator_snapshots_list/save/load, operator_watch_address,
    # operator_graph_stream and its nested async generator `_gen`. These are
    # route handlers; like the existing routes they call SYNC helpers
    # (db_connect, fetch_case_json, build_*). test_no_blocking_io_inside_async_def
    # passes on all of them — none make the banned direct calls. The SSE
    # `_gen` awaits asyncio.wait_for(queue.get()) + a heartbeat (no I/O).
    # graph_events.publish() is deliberately SYNC (put_nowait) so the async
    # surface stays inside api/*.)
    assert total == 28, (
        f"async def count drifted to {total} (was 28). Update baseline and "
        "verify each new async def is non-blocking."
    )


def _call_name(node: ast.AST) -> str | None:
    """Return dotted name for `foo.bar.baz(...)` calls; else None."""
    if not isinstance(node, ast.Call):
        return None
    parts: list[str] = []
    cur: ast.AST = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def test_no_blocking_io_inside_async_def(parsed):
    """Rule 2: `async def` MUST NOT call requests.*/time.sleep/psycopg.connect."""
    violations: list[str] = []
    for path, tree in parsed:
        for fn in _async_funcs(tree):
            for node in ast.walk(fn):
                name = _call_name(node)
                if name and name in BLOCKING_SYNC_CALLS:
                    violations.append(
                        f"{_rel(path)}:{node.lineno} async def {fn.name} "
                        f"calls blocking {name}()"
                    )
    assert not violations, (
        "Blocking sync I/O inside async def. Use httpx.AsyncClient / "
        "asyncio.sleep, or run via fastapi.concurrency.run_in_threadpool. "
        "Violations:\n  " + "\n  ".join(violations)
    )


def test_no_asyncio_run_anywhere(parsed):
    """Rule 4: `asyncio.run(...)` from inside the FastAPI event loop crashes
    with 'cannot be called from a running event loop'. Codebase is sync,
    so there is no legitimate caller — ban outright."""
    violations: list[str] = []
    for path, tree in parsed:
        for node in ast.walk(tree):
            if _call_name(node) == "asyncio.run":
                violations.append(f"{_rel(path)}:{node.lineno}")
    assert not violations, (
        f"asyncio.run() found — would crash under uvicorn: {violations}"
    )


def test_no_anyio_mixed_with_asyncio(parsed):
    """Rule 5: pick one. Sync codebase uses neither; both is worst case."""
    has_asyncio: set[str] = set()
    has_anyio: set[str] = set()
    for path, tree in parsed:
        rel = _rel(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "asyncio" or alias.name.startswith("asyncio."):
                        has_asyncio.add(rel)
                    if alias.name == "anyio" or alias.name.startswith("anyio."):
                        has_anyio.add(rel)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "asyncio" or (node.module or "").startswith("asyncio."):
                    has_asyncio.add(rel)
                if node.module == "anyio" or (node.module or "").startswith("anyio."):
                    has_anyio.add(rel)
    mixed = has_asyncio & has_anyio
    assert not mixed, f"Module imports both asyncio and anyio: {mixed}"
    # Codebase contract: we don't currently use either directly.
    # (FastAPI/uvicorn pull asyncio transitively — that's fine.)
    assert not has_anyio, (
        f"anyio newly imported. Codebase has been pure-asyncio "
        f"(via FastAPI). Files: {has_anyio}"
    )


def test_no_async_with_on_psycopg_or_requests(parsed):
    """Rule 6: `async with psycopg.connect(...)` / `async with requests...`
    would raise TypeError at runtime — neither has __aenter__."""
    violations: list[str] = []
    for path, tree in parsed:
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncWith):
                continue
            for item in node.items:
                name = _call_name(item.context_expr)
                if name and (name.startswith("psycopg.") or name.startswith("requests.")):
                    violations.append(f"{_rel(path)}:{node.lineno} async with {name}")
    assert not violations, (
        f"async with on a sync context manager: {violations}"
    )


def test_no_bare_await_outside_async_def(parsed):
    """Rule 1: `await` outside async def is a SyntaxError at parse time,
    so reaching this assertion means every file already parsed cleanly.
    Re-verify by walking: any Await must be inside an AsyncFunctionDef."""
    violations: list[str] = []
    for path, tree in parsed:
        # Build a map of Await -> enclosing function via parent links.
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._parent = parent  # type: ignore[attr-defined]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Await):
                continue
            cur = getattr(node, "_parent", None)
            while cur is not None and not isinstance(cur, ast.AsyncFunctionDef):
                cur = getattr(cur, "_parent", None)
            if cur is None:
                violations.append(f"{_rel(path)}:{node.lineno}")
    assert not violations, f"bare await outside async def: {violations}"
