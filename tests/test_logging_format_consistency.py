"""Logging-format consistency audit.

Pins the invariant: every call to ``log.<level>(...)`` (and the common
aliases ``logger``, ``LOG``, ``LOGGER``, ``_log``, ``_logger``,
``self.log``, ``self.logger``) passes a *static* format string as the
message, NOT an f-string, string-concat, or ``"fmt %s" % var``
expression.

Why this matters
================

``log.info(f"foo {bar}")`` evaluates ``bar`` and builds the
interpolated string BEFORE the logging machinery decides whether the
record will be emitted. For DEBUG/INFO under a WARNING-and-above
configuration that work is pure waste — but more importantly, an
expensive ``__str__`` (e.g. a SQLAlchemy row, a large dict, a remote
fetch) runs unconditionally on every hot-path call.

The deferred-formatting pattern ``log.info("foo %s", bar)`` lets the
logger short-circuit interpolation when the record is filtered out,
and lets structured-log handlers (we ship one — see
``recupero.logging_setup``) see ``bar`` as a separate argument
instead of a pre-rendered blob.

This test scans the entire ``src/recupero`` tree with the ``ast``
module (NOT regex — regex doesn't see multi-line calls correctly) and
fails CI if a regression sneaks in.

Allowlist policy
================

ERROR / EXCEPTION / CRITICAL calls are allowed to use f-strings: by
the time we hit those levels the cost of one extra interpolation is
irrelevant compared to the operator-readability win of inline values.
DEBUG / INFO / WARNING are strict.

Concat (``"foo " + bar``) and ``"foo %s" % bar`` are ALWAYS rejected
at the same levels — neither is more readable than ``log.info("foo %s", bar)``
and both have the same eager-evaluation cost.

If you legitimately need an f-string at INFO/WARNING (e.g. the format
arguments are themselves expensive lazy expressions and you'd rather
pay once than thread the laziness through), add the file:line to
``_ALLOWLIST`` below with a one-line justification.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

# ---------------------------------------------------------------- #
# Configuration
# ---------------------------------------------------------------- #

# Levels where deferred formatting is mandatory. ``warn`` is the
# deprecated alias for ``warning`` — we enforce both.
_STRICT_LEVELS: frozenset[str] = frozenset(
    {"debug", "info", "warning", "warn"}
)

# Levels where any formatting style is acceptable (cost is dominated
# by the error-handling path itself).
_LAX_LEVELS: frozenset[str] = frozenset({"error", "exception", "critical"})

# Identifiers we treat as Logger instances at attribute-access time.
_LOGGER_NAMES: frozenset[str] = frozenset(
    {"log", "logger", "LOG", "LOGGER", "_log", "_logger"}
)

# Attribute names (used after self/cls or arbitrary expression) we
# also treat as a Logger — e.g. ``self.log.info(...)`` or
# ``ctx.logger.warning(...)``.
_LOGGER_ATTR_NAMES: frozenset[str] = frozenset({"log", "logger"})

# Explicit per-file:line allowlist. Format: "<relative-posix-path>:<lineno>".
# Add with a justification comment.
_ALLOWLIST: frozenset[str] = frozenset()


# ---------------------------------------------------------------- #
# AST helpers
# ---------------------------------------------------------------- #


def _is_logger_call(node: ast.Call) -> tuple[bool, str]:
    """Return (is_logger_call, level). Level is "" if not a logger call."""
    func = node.func
    if not isinstance(func, ast.Attribute):
        return (False, "")
    level = func.attr
    if level not in (_STRICT_LEVELS | _LAX_LEVELS):
        return (False, "")
    base = func.value
    if isinstance(base, ast.Name) and base.id in _LOGGER_NAMES:
        return (True, level)
    if isinstance(base, ast.Attribute) and base.attr in _LOGGER_ATTR_NAMES:
        return (True, level)
    return (False, "")


def _message_arg(node: ast.Call, level: str) -> ast.expr | None:
    """Return the AST node that represents the format-string argument.

    ``log.<level>(msg, *args)`` puts msg at position 0, EXCEPT for
    ``log.log(LEVEL, msg, *args)`` where msg is at position 1. We
    don't enforce on ``.log()`` because it's rare and the caller is
    already being explicit; covered by the same allowlist if needed.
    """
    if level == "log":
        return None  # not in our enforced sets anyway
    if not node.args:
        return None
    return node.args[0]


def _classify(msg: ast.expr) -> str | None:
    """Classify the message expression. Returns the issue tag or None
    if the message is acceptable (static string / Name / attribute /
    call returning a translated string)."""
    if isinstance(msg, ast.JoinedStr):
        # f-string. Treat empty f"" (no FormattedValue children) as OK
        # because some linters auto-prefix; without interpolation it's
        # semantically identical to a plain str literal.
        if any(isinstance(v, ast.FormattedValue) for v in msg.values):
            return "fstring"
        return None
    if isinstance(msg, ast.BinOp):
        if isinstance(msg.op, ast.Add):
            return "concat"
        if isinstance(msg.op, ast.Mod):
            # ``"foo %s" % bar`` — only reject when the LEFT side is a
            # string literal. ``some_var % other`` could be integer
            # modulo on a non-message expression upstream; not our job.
            if isinstance(msg.left, ast.Constant) and isinstance(
                msg.left.value, str
            ):
                return "percent"
    return None


# ---------------------------------------------------------------- #
# Scanner
# ---------------------------------------------------------------- #


def _scan_tree(root: pathlib.Path) -> list[tuple[str, int, str, str]]:
    """Walk every .py under ``root`` and collect violations.

    Returns list of (relative-posix-path, lineno, level, kind).
    """
    violations: list[tuple[str, int, str, str]] = []
    for path in sorted(root.rglob("*.py")):
        try:
            src = path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            # A .py we can't parse is a separate problem — out of
            # scope for this audit; let other tests catch it.
            continue
        rel = path.relative_to(root.parent.parent).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_log, level = _is_logger_call(node)
            if not is_log:
                continue
            if level not in _STRICT_LEVELS:
                continue
            msg = _message_arg(node, level)
            if msg is None:
                continue
            kind = _classify(msg)
            if kind is None:
                continue
            key = f"{rel}:{node.lineno}"
            if key in _ALLOWLIST:
                continue
            violations.append((rel, node.lineno, level, kind))
    return violations


# ---------------------------------------------------------------- #
# Tests
# ---------------------------------------------------------------- #


def _repo_src_root() -> pathlib.Path:
    """Locate ``src/recupero`` from this test file."""
    here = pathlib.Path(__file__).resolve()
    # tests/<this>.py → repo / src / recupero
    candidate = here.parent.parent / "src" / "recupero"
    if not candidate.is_dir():
        pytest.skip(
            f"src/recupero not found relative to {here}; cwd={pathlib.Path.cwd()}"
        )
    return candidate


def test_no_fstring_or_eager_format_in_info_or_below() -> None:
    """No DEBUG/INFO/WARNING callsite may use an f-string, ``+``-concat,
    or ``"fmt" % args`` as the message argument.

    If this fails: convert ``log.info(f"foo {bar}")`` →
    ``log.info("foo %s", bar)``. Deferred formatting is mandatory at
    these levels because (a) they are frequently filtered out under
    the production handler config, and (b) the structured-log handler
    needs the args separate to emit them as fields.

    To allowlist a callsite (rare), add ``"<relative-posix-path>:<lineno>"``
    to ``_ALLOWLIST`` in this file with a one-line justification.
    """
    src_root = _repo_src_root()
    violations = _scan_tree(src_root)
    if violations:
        lines = "\n".join(
            f"  {rel}:{ln}  [{level}]  {kind}"
            for rel, ln, level, kind in violations
        )
        pytest.fail(
            "Eager log formatting detected (use 'log.<level>(\"%s\", arg)'):\n"
            + lines
        )


def test_scanner_detects_fstring_synthetic() -> None:
    """Self-check: the scanner must flag a synthetic f-string log
    call. Without this we have no way to know the audit is alive —
    a future ast-API tweak that breaks ``_classify`` would silently
    pass the main test."""
    src = (
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "def f(bar):\n"
        "    log.info(f'value={bar}')\n"
    )
    tree = ast.parse(src)
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_log, level = _is_logger_call(node)
        if not is_log:
            continue
        msg = _message_arg(node, level)
        if msg is None:
            continue
        kind = _classify(msg)
        if kind is not None:
            found.append(kind)
    assert found == ["fstring"], found


def test_scanner_detects_concat_synthetic() -> None:
    """Self-check: ``log.info("foo " + bar)`` must be flagged as concat."""
    src = (
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "def f(bar):\n"
        "    log.warning('prefix-' + bar)\n"
    )
    tree = ast.parse(src)
    kinds: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_log, level = _is_logger_call(node)
        if not is_log:
            continue
        msg = _message_arg(node, level)
        if msg is None:
            continue
        k = _classify(msg)
        if k is not None:
            kinds.append(k)
    assert kinds == ["concat"], kinds


def test_scanner_detects_percent_synthetic() -> None:
    """Self-check: ``log.info("foo %s" % bar)`` must be flagged as percent."""
    src = (
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "def f(bar):\n"
        "    log.debug('val=%s' % bar)\n"
    )
    tree = ast.parse(src)
    kinds: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_log, level = _is_logger_call(node)
        if not is_log:
            continue
        msg = _message_arg(node, level)
        if msg is None:
            continue
        k = _classify(msg)
        if k is not None:
            kinds.append(k)
    assert kinds == ["percent"], kinds


def test_scanner_accepts_deferred_format() -> None:
    """Self-check: the correct pattern must NOT be flagged."""
    src = (
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "def f(bar):\n"
        "    log.info('value=%s', bar)\n"
        "    log.warning('a=%s b=%d', bar, 42)\n"
        "    log.debug('static message')\n"
    )
    tree = ast.parse(src)
    found_any = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_log, level = _is_logger_call(node)
        if not is_log:
            continue
        msg = _message_arg(node, level)
        if msg is None:
            continue
        if _classify(msg) is not None:
            found_any = True
    assert found_any is False


def test_scanner_allows_fstring_at_error_level() -> None:
    """Self-check: ``log.error(f"...")`` is intentionally NOT scanned
    (error/exception/critical are in ``_LAX_LEVELS``)."""
    src = (
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "def f(bar):\n"
        "    log.error(f'fatal: {bar}')\n"
        "    log.exception(f'boom: {bar}')\n"
    )
    tree = ast.parse(src)
    strict_hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_log, level = _is_logger_call(node)
        if not is_log:
            continue
        if level not in _STRICT_LEVELS:
            continue
        msg = _message_arg(node, level)
        if msg is None:
            continue
        if _classify(msg) is not None:
            strict_hits.append(level)
    assert strict_hits == []
