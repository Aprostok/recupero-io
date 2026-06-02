"""Module-level mutable state audit — pin allowlist.

Background
----------
A Jacob-style audit pass over ``src/recupero/`` identified every
module-level assignment whose right-hand side is an empty mutable
literal (``{}``, ``[]``, ``set()``) — the canonical shape for a
process-global cache or counter that is later mutated by a function in
the same module. Each finding was classified:

* lock-guarded     → there is a ``threading.Lock`` in the same module
                     wrapping every read-modify-write site.
* single-threaded  → the lifetime / call site documents it is only
                     touched by one thread (e.g. cleared at tick
                     boundary by the same coroutine that wrote it).
* best-effort      → mutation racing is acknowledged in a module
                     docstring; the worst-case outcome is a duplicate
                     log line or an extra rate-limit budget on the
                     first request after a window roll.

This test pins the allowlist. If a future change adds a new
``_cache: dict = {}`` at module level and mutates it, the test fails
with a pointer to this docstring so the author has to either:

  1. Add a ``threading.Lock`` + take it on every mutation, or
  2. Justify single-threaded usage in a module-level comment, or
  3. Add the new symbol to ``ALLOWED`` here with a one-line rationale.

What is checked
---------------
For every ``*.py`` file under ``src/recupero``, the AST is scanned for:

  * ``Name = <Dict|List|Set>()``     (empty mutable literal)
  * ``Name: T = <Dict|List|Set>()``  (annotated empty mutable literal)
  * ``Name = defaultdict(...) | OrderedDict() | dict() | list() | set()``

then for each such name, the AST is walked again to see if any function
body in the SAME file mutates it via:

  * ``Name[key] = value``      (subscript-assign)
  * ``Name.append(...)``       (and any common mutator method)
  * ``del Name[key]``

A ``(module, symbol)`` pair that satisfies both checks ("declared empty
mutable" + "mutated by some function") is what we call a
*module-level mutable hotspot* and must be in ``ALLOWED``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "recupero"


# ──────────────────────────────────────────────────────────────────────────────
# Allowlist: every (module-relative-path, symbol) pair we have audited
# and accepted as safe. Format: relative POSIX path under src/recupero,
# symbol name.
#
# Adding a new entry REQUIRES a one-line rationale in the comment block
# directly above it. Removing an entry is fine (means the hotspot was
# deleted or the empty-mutable was promoted to a non-empty literal).
# ──────────────────────────────────────────────────────────────────────────────
ALLOWED: dict[tuple[str, str], str] = {
    # api/auth.py: per-API-key token-bucket map.
    # Guarded by `_buckets_lock` on every read-modify-write.
    ("api/auth.py", "_buckets"):
        "lock-guarded by _buckets_lock",

    # reports/graph_expand.py: in-process TTL cache of expansion results,
    # keyed by (chain, address, direction, cap, priced). Best-effort — a
    # race causes at most one redundant chain-API fetch; values are
    # immutable once stored, and the dict self-bounds (cleared at >512).
    ("reports/graph_expand.py", "_expansion_cache"):
        "best-effort TTL cache; race at most causes 1 redundant fetch, self-bounded",

    # reports/graph_events.py: investigation_id -> set of SSE subscriber
    # asyncio.Queues. Mutated only from the single FastAPI event-loop
    # thread (subscribe/unsubscribe in the SSE route, publish from async
    # routes on the same loop) — single-threaded by lifetime.
    ("reports/graph_events.py", "_subscribers"):
        "single-threaded by lifetime (FastAPI event loop only)",

    # v0.32 monitoring/recovery_rate.py: 60-second cache of the
    # RecoveryStats computation. Read-modify-write is fine
    # best-effort — a race produces at most one extra DB query
    # per cache window (60s). The cached value is immutable
    # once stored. Never crashes on race.
    ("monitoring/recovery_rate.py", "_CACHE"):
        "best-effort 60s memoization; race at most causes 1 redundant query",

    # api/auth.py: parsed RECUPERO_API_KEYS map.
    # Guarded by `_keys_cache_lock` on every clear/update.
    ("api/auth.py", "_keys_cache"):
        "lock-guarded by _keys_cache_lock",

    # api/app.py: intake-form per-IP rate limiter state.
    # Best-effort: acknowledged in the module comment block
    # (L1078-L1086 as of v0.20.1) that per-replica drift is acceptable
    # — worst case an attacker gets N * 5/min instead of 5/min.
    ("api/app.py", "_intake_rl_state"):
        "best-effort rate limiter, documented at the declaration site",

    # worker/monitor_tick.py: per-tick adapter cache.
    # Single-threaded by lifetime: created + cleared inside a single
    # `run_monitor_tick()` invocation by `_reset_adapter_cache()`. The
    # tick is awaited sequentially by the worker loop.
    ("worker/monitor_tick.py", "_ADAPTER_CACHE"):
        "single-threaded; cleared per tick by _reset_adapter_cache()",

    # v0.32.1 (CRIT-1) chains/bitcoin/inputs_registry.py: tx_hash ->
    # frozenset of input addresses for the Bitcoin co-spending (H1)
    # heuristic. Every read-modify-write (register/lookup/clear/size)
    # takes `_LOCK`; cleared per case by clear_for_case().
    ("chains/bitcoin/inputs_registry.py", "_BTC_INPUTS_BY_TX"):
        "lock-guarded by _LOCK",

    # v0.32.1 chains/bitcoin/adapter.py: registry of synthetic CoinJoin-
    # unwrap (tx_hash, to_address) rows so the brief/LE renderer can
    # badge probabilistic rows. Every mutation (mark_synthetic_coinjoin
    # / clear_synthetic_coinjoin_registry) takes `_SYNTHETIC_LOCK`.
    ("chains/bitcoin/adapter.py", "_SYNTHETIC_COINJOIN_KEYS"):
        "lock-guarded by _SYNTHETIC_LOCK",

    # v0.32.1 chains/bitcoin/adapter.py: confidence/rationale metadata
    # paired with _SYNTHETIC_COINJOIN_KEYS. Same lock discipline.
    ("chains/bitcoin/adapter.py", "_SYNTHETIC_COINJOIN_META"):
        "lock-guarded by _SYNTHETIC_LOCK",

    # v0.34 trace/tracer.py: per-case accumulator of per-address fetch-cap
    # truncations, feeding the coverage-completeness notice. Appended ONLY by
    # _trace_one_hop (a pure list.append, which is GIL-atomic — no read-modify-
    # write, so no lock needed). Cleared by _clear_coverage_truncations() at the
    # START of every run_trace, BEFORE any ThreadPoolExecutor wave thread is
    # submitted, and read exactly once at case assembly AFTER all waves join —
    # so there is never a concurrent read-during-write. Same per-case lifetime
    # contract as the Bitcoin registries above.
    ("trace/tracer.py", "_COVERAGE_TRUNCATIONS"):
        "GIL-atomic appends; cleared pre-wave + read post-join, no read-during-write",

    # v0.34 trace/tracer.py: per-case accumulator of zero-value poison edges
    # dropped pre-pricing. Identical concurrency contract to
    # _COVERAGE_TRUNCATIONS above: appended ONLY by _trace_one_hop (GIL-atomic
    # list.append, no read-modify-write), cleared by _clear_coverage_truncations()
    # before any wave thread is submitted, and read once at case assembly after
    # all waves join — no concurrent read-during-write.
    ("trace/tracer.py", "_POISON_PRUNED"):
        "GIL-atomic appends; cleared pre-wave + read post-join, no read-during-write",
}


# ──────────────────────────────────────────────────────────────────────────────
# AST scan helpers
# ──────────────────────────────────────────────────────────────────────────────

_MUTATOR_METHODS = frozenset({
    "append", "extend", "insert",
    "update", "setdefault",
    "pop", "popitem", "clear",
    "add", "remove", "discard",
    "sort",
    "__setitem__", "__delitem__",
})


def _is_empty_mutable_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        return len(node.keys) == 0
    if isinstance(node, ast.List):
        return len(node.elts) == 0
    if isinstance(node, ast.Set):
        return len(node.elts) == 0
    return False


def _is_mutable_factory_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    name = getattr(f, "id", None) or getattr(f, "attr", None)
    return name in {
        "dict", "list", "set",
        "defaultdict", "OrderedDict",
    }


def _module_empty_mutables(tree: ast.Module) -> dict[str, int]:
    """Return {symbol_name: lineno} for every top-level assignment
    whose RHS is an empty mutable literal or empty-mutable factory call.
    """
    found: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            rhs = node.value
            if _is_empty_mutable_literal(rhs) or _is_mutable_factory_call(rhs):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        found[tgt.id] = node.lineno
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue
            rhs = node.value
            if _is_empty_mutable_literal(rhs) or _is_mutable_factory_call(rhs):
                if isinstance(node.target, ast.Name):
                    found[node.target.id] = node.lineno
    return found


def _names_mutated_in_functions(
    tree: ast.Module, candidates: set[str],
) -> set[str]:
    """Return the subset of ``candidates`` that is mutated by at least
    one function in the module (subscript-assign, mutator-method call,
    or del on subscript)."""
    mutated: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if (
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id in candidates
                    ):
                        mutated.add(tgt.value.id)
            elif isinstance(sub, ast.Call):
                f = sub.func
                if (
                    isinstance(f, ast.Attribute)
                    and isinstance(f.value, ast.Name)
                    and f.value.id in candidates
                    and f.attr in _MUTATOR_METHODS
                ):
                    mutated.add(f.value.id)
            elif isinstance(sub, ast.Delete):
                for tgt in sub.targets:
                    if (
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id in candidates
                    ):
                        mutated.add(tgt.value.id)
    return mutated


def _discover_hotspots() -> dict[tuple[str, str], int]:
    """Walk ``src/recupero`` and return every (rel_path, symbol) pair
    that is a declared empty mutable AND mutated by a function in the
    same module. Value is the declaration lineno (for error messages).
    """
    hotspots: dict[tuple[str, str], int] = {}
    for py_path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in py_path.parts:
            continue
        try:
            src = py_path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            tree = ast.parse(src, filename=str(py_path))
        except SyntaxError:
            continue
        declared = _module_empty_mutables(tree)
        if not declared:
            continue
        mutated = _names_mutated_in_functions(tree, set(declared.keys()))
        if not mutated:
            continue
        rel = py_path.relative_to(SRC_ROOT).as_posix()
        for name in mutated:
            hotspots[(rel, name)] = declared[name]
    return hotspots


# ──────────────────────────────────────────────────────────────────────────────
# RED tests
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def hotspots() -> dict[tuple[str, str], int]:
    return _discover_hotspots()


def test_hotspots_are_a_subset_of_allowlist(hotspots):
    """Every discovered module-level mutable+mutator pair must be in
    ALLOWED. New ones require a justification entry."""
    unexpected = sorted(set(hotspots) - set(ALLOWED))
    assert not unexpected, (
        "New module-level mutable hotspots were introduced. Each must be "
        "either lock-guarded, single-threaded by lifetime, or explicitly "
        "documented as best-effort, then added to ALLOWED in "
        "tests/test_module_mutable_audit.py with a one-line rationale.\n"
        f"Unexpected: {unexpected}"
    )


def test_allowlist_has_no_stale_entries(hotspots):
    """ALLOWED entries must still exist in the source tree — drop any
    that have been deleted/refactored away."""
    stale = sorted(set(ALLOWED) - set(hotspots))
    assert not stale, (
        "ALLOWED contains entries that are no longer present in the "
        "source — drop them from tests/test_module_mutable_audit.py.\n"
        f"Stale: {stale}"
    )


def test_lock_guarded_modules_actually_declare_a_lock():
    """Any allowlist entry whose rationale claims a lock guard must
    have a ``threading.Lock()`` declared at module level in the same
    file."""
    lock_guarded = {
        key: rationale
        for key, rationale in ALLOWED.items()
        if "lock-guarded" in rationale.lower()
    }
    for (rel_path, symbol), rationale in lock_guarded.items():
        text = (SRC_ROOT / rel_path).read_text(encoding="utf-8")
        # Cheap textual check — the rationale also names the lock.
        # Pull the lock identifier out of the rationale.
        assert "by" in rationale, rationale
        lock_name = rationale.split("by", 1)[1].strip().split()[0]
        assert (
            f"{lock_name} = threading.Lock()" in text
            or f"{lock_name}: threading.Lock = threading.Lock()" in text
        ), (
            f"{rel_path}:{symbol} claims lock-guard by {lock_name!r} but "
            f"no `threading.Lock()` declaration of that name was found "
            f"in the module."
        )


def test_no_lru_cache_with_side_effecting_target():
    """Catch a future regression: ``@functools.lru_cache`` (or
    ``@cache``) applied to a function that mutates module-level state.

    A cached function whose body writes into ``_some_dict`` will run
    its side effect only on the first call per argument-tuple, then
    silently skip it forever — a subtle source of order-dependent
    bugs.

    Scope: this audit is intentionally conservative — it walks every
    decorated function in the tree, and only flags those decorated by
    ``lru_cache``, ``cache``, ``functools.lru_cache`` or
    ``functools.cache`` whose body contains a write to a module-level
    Name (subscript-assign on a name declared at module level OR a
    mutator-method call on such a name).
    """
    offenders: list[str] = []
    for py_path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in py_path.parts:
            continue
        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        module_names = {
            tgt.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for tgt in node.targets
            if isinstance(tgt, ast.Name)
        } | {
            node.target.id
            for node in tree.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
        }
        for fn in ast.walk(tree):
            if not isinstance(
                fn, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            decorated_by_cache = False
            for dec in fn.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                name = (
                    getattr(target, "id", None)
                    or getattr(target, "attr", None)
                )
                if name in {"lru_cache", "cache"}:
                    decorated_by_cache = True
                    break
            if not decorated_by_cache:
                continue
            for sub in ast.walk(fn):
                if (
                    isinstance(sub, ast.Assign)
                    and any(
                        isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.value, ast.Name)
                        and tgt.value.id in module_names
                        for tgt in sub.targets
                    )
                ):
                    offenders.append(
                        f"{py_path.relative_to(SRC_ROOT).as_posix()}::{fn.name}",
                    )
                    break
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id in module_names
                    and sub.func.attr in _MUTATOR_METHODS
                ):
                    offenders.append(
                        f"{py_path.relative_to(SRC_ROOT).as_posix()}::{fn.name}",
                    )
                    break
    assert not offenders, (
        "Found @lru_cache / @cache decorated functions that mutate "
        "module-level state. The mutation runs only on cache miss — "
        "this is almost certainly an order-dependent bug. Either drop "
        "the cache decorator or move the side effect to an uncached "
        "wrapper.\n"
        f"Offenders: {offenders}"
    )


def test_no_module_level_list_appended_from_multiple_call_sites():
    """A module-level ``_things: list = []`` that's appended to from
    more than one function is the classic shared-mutable-list bug
    (each call site forgets the previous content was added by someone
    else). Locks rarely help here because the LIST itself is the bug,
    not the race.

    Allowlist exception: nothing for now. If a legitimate case appears
    later, add it to MODULE_LIST_ALLOWED below with a rationale.
    """
    MODULE_LIST_ALLOWED: set[tuple[str, str]] = set()
    offenders: list[str] = []
    for py_path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in py_path.parts:
            continue
        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        # Module-level lists.
        module_lists: dict[str, int] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.List):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            module_lists[tgt.id] = node.lineno
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.value, ast.List) and isinstance(
                    node.target, ast.Name,
                ):
                    module_lists[node.target.id] = node.lineno
        if not module_lists:
            continue
        # Per-name set of mutating function names.
        appenders: dict[str, set[str]] = {n: set() for n in module_lists}
        for fn in ast.walk(tree):
            if not isinstance(
                fn, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            for sub in ast.walk(fn):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id in appenders
                    and sub.func.attr in {"append", "extend", "insert"}
                ):
                    appenders[sub.func.value.id].add(fn.name)
        rel = py_path.relative_to(SRC_ROOT).as_posix()
        for name, fns in appenders.items():
            if len(fns) >= 2 and (rel, name) not in MODULE_LIST_ALLOWED:
                offenders.append(f"{rel}::{name} (appended by {sorted(fns)})")
    assert not offenders, (
        "Found module-level lists appended to from multiple functions "
        "in the same file — this is almost always a shared-mutable bug. "
        "Convert to a return-value-and-collect pattern, or add to "
        "MODULE_LIST_ALLOWED with a rationale.\n"
        f"Offenders: {offenders}"
    )


def test_singleton_flags_have_documented_idempotency():
    """Catch a future regression: module-level ``_FOO_DID_X = False``
    flipped to True inside a function without ``threading.Lock``
    coverage. The current codebase has exactly one such flag
    (``_IP_MISCONFIG_WARNED`` in portal/server.py) and its worst-case
    is a duplicate log line — acceptable.

    This test pins that allowlist so any NEW boolean singleton flag
    requires a justification entry."""
    SINGLETON_FLAG_ALLOWED: set[tuple[str, str]] = {
        # portal/server.py: log-once flag for IP-extraction
        # misconfiguration. Race-worst-case = 2 log lines.
        ("portal/server.py", "_IP_MISCONFIG_WARNED"),
        # v0.31.4 cron_scheduler.py: _SHUTDOWN is set only by
        # _handler (SIGTERM/SIGINT). Signal handlers run in the
        # main thread; the flag is checked by the main loop and
        # the inner-sleep loop in run_scheduler. Race-worst-case
        # = one extra tick before the loop notices. Idempotency:
        # re-setting to True is a no-op. threading.Event would
        # have been cleaner but the signal-handler/main-thread
        # coupling makes the simple boolean flag adequate.
        ("worker/cron_scheduler.py", "_SHUTDOWN"),
    }
    offenders: list[str] = []
    for py_path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in py_path.parts:
            continue
        try:
            tree = ast.parse(py_path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        # Module-level `_NAME = False` or `_NAME = True`.
        bool_flags: dict[str, int] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(
                node.value, ast.Constant,
            ):
                if isinstance(node.value.value, bool):
                    for tgt in node.targets:
                        if (
                            isinstance(tgt, ast.Name)
                            and tgt.id.startswith("_")
                            # Require at least one uppercase char to
                            # avoid pinning every ``_x = True`` local.
                            and any(c.isupper() for c in tgt.id)
                        ):
                            bool_flags[tgt.id] = node.lineno
        if not bool_flags:
            continue
        # Detect any function that reassigns one of these.
        for fn in ast.walk(tree):
            if not isinstance(
                fn, (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            uses_global: set[str] = set()
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Global):
                    uses_global.update(sub.names)
            for name in uses_global & bool_flags.keys():
                rel = py_path.relative_to(SRC_ROOT).as_posix()
                if (rel, name) not in SINGLETON_FLAG_ALLOWED:
                    offenders.append(f"{rel}::{name} (mutated in {fn.name})")
    assert not offenders, (
        "Found new module-level boolean singleton flag(s) reassigned "
        "via `global`. Either lock-guard the flip, document the "
        "idempotency rationale and add to SINGLETON_FLAG_ALLOWED, or "
        "move to threading.Event / contextvars.\n"
        f"Offenders: {sorted(set(offenders))}"
    )
