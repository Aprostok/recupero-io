"""Audit that every audit-log table is append-only.

Locks the invariant that historical audit rows cannot be rewritten or
deleted by application code. AST-scans every ``src/recupero/**/*.py``
file for SQL literals passed to ``cursor.execute(...)`` and asserts no
UPDATE / DELETE / TRUNCATE statement targets a strict-append-only
table.

Strictly append-only (zero UPDATE / DELETE / TRUNCATE allowed):

  * ``emails_sent``             -- one INSERT per send attempt; never mutated
  * ``freeze_outcomes``         -- one INSERT per observed outcome event
  * ``monitoring_alerts_sent``  -- one INSERT per alert dispatch

Lifecycle tables (UPDATE allowed but only on a whitelist of mutable
workflow columns; the audit fields stay frozen):

  * ``freeze_letters_sent`` -- the body, recipient, and sent-at columns
    are audit history and never updated; ``followup_stage`` /
    ``last_followup_sent_at`` are workflow state that the followup cron
    legitimately advances.

  * ``payments`` -- the Stripe event row is created at webhook receipt
    and finalized in the dispatcher (``processed_at``,
    ``investigation_id``, ``notes`` append). The amount / customer /
    stripe_event_id audit fields stay frozen.

This test is a regression guard: if a future commit adds e.g.
``UPDATE emails_sent SET body = ...`` or ``DELETE FROM freeze_outcomes
WHERE ...`` the test fails and the reviewer must either revert the
mutation or move the table off the strict-append list (and document
why).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[1]
_SRC_ROOT = _REPO_ROOT / "src" / "recupero"

# Tables that must NEVER see UPDATE / DELETE / TRUNCATE from app code.
_STRICT_APPEND_ONLY = (
    "emails_sent",
    "freeze_outcomes",
    "monitoring_alerts_sent",
)

# Lifecycle tables: UPDATEs allowed only on these columns. Audit
# columns (body, recipient, sent_at, amount, stripe_event_id, ...) stay
# frozen.
_LIFECYCLE_UPDATE_WHITELIST = {
    "freeze_letters_sent": {"followup_stage", "last_followup_sent_at"},
    "payments": {"processed_at", "investigation_id", "notes"},
}


def _iter_sql_literals() -> list[tuple[Path, int, str]]:
    """Walk every .py under src/recupero, AST-parse it, and yield
    (path, lineno, sql_text) for every string literal handed to a
    ``.execute(...)`` call (positional arg 0).

    Catches both ``cur.execute("SQL", params)`` and the f-string-less
    triple-quoted form. Skips f-strings (they cannot be statically
    inspected without false positives).
    """
    results: list[tuple[Path, int, str]] = []
    for path in _SRC_ROOT.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr != "execute":
                continue
            if not node.args:
                continue
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                results.append((path, arg0.lineno, arg0.value))
    return results


_SQL_LITERALS = _iter_sql_literals()


def _normalize(sql: str) -> str:
    """Collapse whitespace + lowercase for prefix matching."""
    return re.sub(r"\s+", " ", sql).strip().lower()


def _statements_targeting(table: str, verb: str) -> list[tuple[Path, int, str]]:
    """Find every SQL literal whose first statement is ``verb table``
    (or ``verb public.table``, with optional whitespace). Matches the
    leading verb only — does not flag JOINs or subqueries against the
    table from inside a SELECT.
    """
    verb_l = verb.lower()
    # `\b` around table prevents `payments_audit` from matching `payments`.
    if verb_l == "delete":
        pattern = rf"^delete\s+from\s+(public\.)?{re.escape(table)}\b"
    elif verb_l == "truncate":
        pattern = rf"^truncate\s+(table\s+)?(public\.)?{re.escape(table)}\b"
    else:  # update
        pattern = rf"^{verb_l}\s+(public\.)?{re.escape(table)}\b"
    rx = re.compile(pattern)
    out: list[tuple[Path, int, str]] = []
    for path, lineno, sql in _SQL_LITERALS:
        if rx.match(_normalize(sql)):
            out.append((path, lineno, sql))
    return out


@pytest.mark.parametrize("table", _STRICT_APPEND_ONLY)
def test_strict_append_only_no_update(table: str) -> None:
    """No application code may issue ``UPDATE <table>``."""
    hits = _statements_targeting(table, "update")
    assert not hits, (
        f"Audit-log table {table!r} is strict-append-only but found "
        f"UPDATE statements at: "
        + ", ".join(f"{p.relative_to(_REPO_ROOT)}:{ln}" for p, ln, _ in hits)
    )


@pytest.mark.parametrize("table", _STRICT_APPEND_ONLY)
def test_strict_append_only_no_delete(table: str) -> None:
    """No application code may issue ``DELETE FROM <table>``."""
    hits = _statements_targeting(table, "delete")
    assert not hits, (
        f"Audit-log table {table!r} is strict-append-only but found "
        f"DELETE statements at: "
        + ", ".join(f"{p.relative_to(_REPO_ROOT)}:{ln}" for p, ln, _ in hits)
    )


@pytest.mark.parametrize("table", _STRICT_APPEND_ONLY)
def test_strict_append_only_no_truncate(table: str) -> None:
    """No application code may issue ``TRUNCATE <table>``."""
    hits = _statements_targeting(table, "truncate")
    assert not hits, (
        f"Audit-log table {table!r} is strict-append-only but found "
        f"TRUNCATE statements at: "
        + ", ".join(f"{p.relative_to(_REPO_ROOT)}:{ln}" for p, ln, _ in hits)
    )


# ---- lifecycle-table guard ----
# freeze_letters_sent and payments allow UPDATEs but ONLY on the
# whitelisted workflow columns. Any UPDATE that touches a column
# outside the whitelist would mutate audit history.

_SET_CLAUSE_RX = re.compile(
    r"\bset\s+(.+?)(?:\s+where\b|\s+returning\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)


def _columns_touched_by_update(sql: str) -> set[str]:
    """Best-effort parse of the column names on the LHS of each
    assignment in a ``SET col = ..., col = ...`` clause. Strips
    optional ``public.``/table qualifiers."""
    m = _SET_CLAUSE_RX.search(sql)
    if not m:
        return set()
    set_body = m.group(1)
    cols: set[str] = set()
    # Split on commas at depth 0 (no parens). Crude but adequate for the
    # short UPDATE statements in this codebase.
    depth = 0
    buf: list[str] = []
    parts: list[str] = []
    for ch in set_body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    for part in parts:
        lhs, _, _ = part.partition("=")
        col = lhs.strip().split(".")[-1].strip('"').strip()
        if col:
            cols.add(col.lower())
    return cols


@pytest.mark.parametrize("table", sorted(_LIFECYCLE_UPDATE_WHITELIST))
def test_lifecycle_update_only_touches_whitelisted_columns(table: str) -> None:
    """UPDATE statements on lifecycle tables may only set columns in
    the workflow-state whitelist. Touching an audit column (body,
    recipient, sent_at, amount, stripe_event_id, etc.) is forbidden.
    """
    whitelist = _LIFECYCLE_UPDATE_WHITELIST[table]
    offenders: list[tuple[Path, int, set[str]]] = []
    for path, lineno, sql in _statements_targeting(table, "update"):
        touched = _columns_touched_by_update(sql)
        if not touched:
            # Could not parse SET clause — be conservative and flag it.
            offenders.append((path, lineno, set()))
            continue
        stray = touched - whitelist
        if stray:
            offenders.append((path, lineno, stray))
    assert not offenders, (
        f"Lifecycle table {table!r} permits UPDATE only on "
        f"{sorted(whitelist)}, but found stray-column UPDATEs at: "
        + ", ".join(
            f"{p.relative_to(_REPO_ROOT)}:{ln} (cols={sorted(c) or 'unparsed'})"
            for p, ln, c in offenders
        )
    )


@pytest.mark.parametrize("table", sorted(_LIFECYCLE_UPDATE_WHITELIST))
def test_lifecycle_no_delete(table: str) -> None:
    """Even lifecycle tables disallow DELETE — once a payment / letter
    row exists, it stays. Cancellation goes through an outcome row, not
    a row deletion."""
    hits = _statements_targeting(table, "delete")
    assert not hits, (
        f"Lifecycle audit table {table!r} must not be DELETE'd, but found: "
        + ", ".join(f"{p.relative_to(_REPO_ROOT)}:{ln}" for p, ln, _ in hits)
    )


@pytest.mark.parametrize("table", sorted(_LIFECYCLE_UPDATE_WHITELIST))
def test_lifecycle_no_truncate(table: str) -> None:
    """No TRUNCATE on lifecycle audit tables."""
    hits = _statements_targeting(table, "truncate")
    assert not hits, (
        f"Lifecycle audit table {table!r} must not be TRUNCATE'd, but found: "
        + ", ".join(f"{p.relative_to(_REPO_ROOT)}:{ln}" for p, ln, _ in hits)
    )


def test_scan_actually_found_sql() -> None:
    """Smoke check: the AST scan must have found a non-trivial number
    of SQL literals. Catches a regression where _iter_sql_literals
    silently returns [] (e.g., because the src tree moved) and every
    other test above passes vacuously."""
    assert len(_SQL_LITERALS) >= 50, (
        f"AST scan found only {len(_SQL_LITERALS)} SQL literals under "
        f"{_SRC_ROOT} — expected dozens. The scan likely broke."
    )
