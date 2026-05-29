"""Static schema drift detector.

Scans every ``migrations/*.sql`` to learn ``table -> {columns}`` from
``CREATE TABLE`` and ``ALTER TABLE ... ADD COLUMN`` statements, then
scans every ``src/recupero/**/*.py`` for SQL string literals that
reference real columns of those tables. Any column referenced by code
that does not exist in any migration is reported as drift.

This is a STATIC check — no DB connection, no fixture, no runtime
plumbing. It catches the common bug class where worker code SELECTs
``foo.bar`` and the column was never migrated in (the v0.19.2
``incident_time_null`` pattern, generalised).

The detector is intentionally tolerant: aggregate functions,
``SELECT * ...``, dynamic column names (Python-interpolated), and
unknown tables (CTEs, ``information_schema``, system tables) are
skipped. False-positive suppression lives in
``_FALSE_POSITIVE_ALLOWLIST``; if a future grammar twist surfaces a
new noise pattern, add it there with a one-line justification.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[1]
_MIGRATIONS_DIR = _REPO_ROOT / "migrations"
_SRC_DIR = _REPO_ROOT / "src" / "recupero"


# ---------------------------------------------------------------------------
# Migration parser: build {table -> {columns}}
# ---------------------------------------------------------------------------

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\((.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_ALTER_ADD_RE = re.compile(
    r"ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+(.+?);",
    re.IGNORECASE | re.DOTALL,
)
_ADD_COLUMN_RE = re.compile(
    r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
    re.IGNORECASE,
)

# Tokens that look like a column name at the start of a CREATE TABLE
# body line but are actually table-level constraint clauses.
_NON_COLUMN_LEADERS = frozenset(
    {
        "constraint",
        "primary",
        "unique",
        "foreign",
        "check",
        "exclude",
        "like",
    }
)


def _strip_paren_balanced(body: str) -> str:
    """Strip nested parens to depth 0 for safe top-level splitting.

    A CREATE TABLE body can contain ``CHECK (status IN ('a','b'))`` or
    ``NUMERIC(20,2)`` — naive comma-splitting would shred those. This
    walks the string and replaces commas inside parens with a sentinel
    so the caller can split on top-level commas only.
    """
    out: list[str] = []
    depth = 0
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth > 0:
            out.append("\x00")
        else:
            out.append(ch)
    return "".join(out)


def _parse_create_table(table: str, body: str) -> set[str]:
    cols: set[str] = set()
    flat = _strip_paren_balanced(body)
    for raw in flat.split(","):
        line = raw.strip().replace("\x00", ",")
        if not line:
            continue
        # Strip leading SQL comment lines.
        if line.startswith("--"):
            continue
        first = line.split(None, 1)[0].lower()
        if first in _NON_COLUMN_LEADERS:
            continue
        # Column name is the first token; lowercase + strip quotes.
        name = line.split(None, 1)[0].strip('"').lower()
        if name.isidentifier():
            cols.add(name)
    return cols


def build_schema(migrations_dir: Path) -> dict[str, set[str]]:
    """Parse all ``*.sql`` under ``migrations_dir`` into ``{table -> {col}}``."""
    schema: dict[str, set[str]] = defaultdict(set)
    for sql_path in sorted(migrations_dir.glob("*.sql")):
        text = sql_path.read_text(encoding="utf-8")
        # Strip ``-- line comments`` and ``/* block comments */`` so the
        # regexes don't trip over commented-out DDL.
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        text = re.sub(r"--[^\n]*", " ", text)
        for m in _CREATE_TABLE_RE.finditer(text):
            tbl, body = m.group(1).lower(), m.group(2)
            schema[tbl] |= _parse_create_table(tbl, body)
        for m in _ALTER_ADD_RE.finditer(text):
            tbl, body = m.group(1).lower(), m.group(2)
            for col_m in _ADD_COLUMN_RE.finditer(body):
                schema[tbl].add(col_m.group(1).lower())
    return dict(schema)


# ---------------------------------------------------------------------------
# Source scanner: find (table, column) references in SQL string literals
# ---------------------------------------------------------------------------

# Match SQL within Python triple/single/double-quoted strings. We look
# for FROM/JOIN/UPDATE/INSERT INTO clauses naming a table, then collect
# every ``table.column`` or alias.column we can see in the same
# logical statement.
_FROM_TABLE_RE = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INSERT\s+INTO)\s+(?:public\.)?(\w+)(?:\s+(?:AS\s+)?(\w+))?",
    re.IGNORECASE,
)

# table.column references — straightforward.
_DOT_COL_RE = re.compile(r"\b(\w+)\.(\w+)\b")

# Match (column, column, column) in an INSERT INTO foo(...) clause.
_INSERT_COLS_RE = re.compile(
    r"INSERT\s+INTO\s+(?:public\.)?(\w+)\s*\(([^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)

# Match ``UPDATE foo SET ...`` clauses. The body runs up to the next
# WHERE / RETURNING / end-of-statement so the SET column extractor can
# scan it.
_UPDATE_SET_RE = re.compile(
    r"UPDATE\s+(?:public\.)?(\w+)(?:\s+\w+)?\s+SET\s+(.+?)"
    r"(?=\s+(?:WHERE|RETURNING|FROM)\b|\s*;|\s*$)",
    re.IGNORECASE | re.DOTALL,
)

# Match the LHS of each ``col = ...`` assignment inside a SET clause.
# Stops at commas / newlines so multi-line SETs don't merge.
_SET_LHS_RE = re.compile(r"(?:^|,)\s*(?:\w+\.)?(\w+)\s*=", re.MULTILINE)

# SQL keywords / functions that look like identifiers but aren't columns.
_SQL_KEYWORDS = frozenset(
    {
        "select", "from", "where", "and", "or", "not", "in", "is",
        "null", "true", "false", "as", "on", "by", "order", "group",
        "limit", "offset", "having", "distinct", "case", "when",
        "then", "else", "end", "cast", "interval", "now", "current_timestamp",
        "current_date", "exists", "between", "like", "ilike", "asc",
        "desc", "with", "returning", "do", "nothing", "set", "values",
        "conflict", "constraint", "default", "using", "union", "all",
        "join", "left", "right", "inner", "outer", "cross", "lateral",
        "count", "sum", "avg", "min", "max", "coalesce", "nullif",
        "extract", "date_trunc", "to_char", "to_timestamp", "array",
        "any", "some", "filter", "over", "partition", "row_number",
        "rank", "dense_rank", "lag", "lead", "first_value", "last_value",
        "for", "update", "share", "skip", "locked", "of", "into",
        "insert", "delete", "truncate", "create", "alter", "drop",
        "table", "index", "view", "if",
    }
)

# Tables whose columns we don't try to validate (CTE aliases,
# information_schema, pg_catalog, etc.) and aliases that appear inline
# in tests/fixtures rather than the real schema.
_SKIP_TABLES = frozenset(
    {
        "information_schema",
        "pg_catalog",
        "pg_class",
        "pg_index",
        "pg_indexes",
        "pg_tables",
        "pg_attribute",
        "pg_constraint",
        "pg_namespace",
    }
)

# Real, intentional false-positive carve-outs. Each entry is
# ``(table, column)`` and includes a justification comment above it.
_FALSE_POSITIVE_ALLOWLIST: set[tuple[str, str]] = {
    # ``EXCLUDED.col`` is the implicit pseudo-table populated inside
    # ON CONFLICT DO UPDATE — never a real schema table.
    ("excluded", "*"),
}


def _is_allowlisted(table: str, column: str) -> bool:
    if table in _SKIP_TABLES:
        return True
    if (table, "*") in _FALSE_POSITIVE_ALLOWLIST:
        return True
    if (table, column) in _FALSE_POSITIVE_ALLOWLIST:
        return True
    return False


def _walk_python(src_dir: Path):
    for py in src_dir.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        yield py


def _extract_sql_blocks(text: str) -> list[tuple[int, str]]:
    """Yield ``(line_no, block)`` for each triple-quoted string literal.

    We restrict to triple-quoted blocks because that's where the
    project actually writes SQL (the codebase convention; verified by
    eyeballing ``worker/dashboard_summary.py``,
    ``payments/dispatcher.py``, ``freeze_learning/recorder.py``).
    Single-line SQL via ``"...";`` exists too but is overwhelmingly
    SELECTs against ``pg_catalog`` / ``information_schema`` and
    trivially-correct one-column statements.
    """
    out: list[tuple[int, str]] = []
    # Walk both ``"""..."""`` and ``'''...'''`` blocks.
    for pat in (r'"""(.*?)"""', r"'''(.*?)'''"):
        for m in re.finditer(pat, text, flags=re.DOTALL):
            block = m.group(1)
            # Cheap filter: only blocks that actually contain SQL DML.
            upper = block.upper()
            if not any(
                kw in upper
                for kw in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM")
            ):
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            out.append((line_no, block))
    return out


def _collect_table_aliases(block: str) -> dict[str, str]:
    """Map ``alias -> real_table`` from FROM / JOIN clauses in ``block``."""
    aliases: dict[str, str] = {}
    for m in _FROM_TABLE_RE.finditer(block):
        tbl, alias = m.group(1).lower(), (m.group(2) or "").lower()
        aliases[tbl] = tbl  # self-alias
        if alias and alias not in _SQL_KEYWORDS:
            aliases[alias] = tbl
    return aliases


def _scan_block_for_refs(
    block: str,
    schema: dict[str, set[str]],
) -> list[tuple[str, str]]:
    """Return drift ``(table, column)`` references found in ``block``."""
    refs: list[tuple[str, str]] = []
    aliases = _collect_table_aliases(block)

    # 1) Qualified ``alias.column`` references.
    for m in _DOT_COL_RE.finditer(block):
        alias, col = m.group(1).lower(), m.group(2).lower()
        # Skip ``schema.table`` patterns where ``col`` is itself a
        # table name — happens with ``public.investigations``.
        if alias == "public":
            continue
        if col in _SQL_KEYWORDS:
            continue
        if alias not in aliases:
            # Unknown alias (probably a python identifier mistakenly
            # caught) — skip.
            continue
        tbl = aliases[alias]
        if tbl not in schema:
            continue  # unknown table (CTE, pg_*, etc.)
        if _is_allowlisted(tbl, col):
            continue
        if col not in schema[tbl]:
            refs.append((tbl, col))

    # 2) ``INSERT INTO foo (a, b, c)`` column lists.
    for m in _INSERT_COLS_RE.finditer(block):
        tbl = m.group(1).lower()
        if tbl not in schema:
            continue
        for raw in m.group(2).split(","):
            col = raw.strip().strip('"').lower()
            # Skip placeholders (``%s``) and parameter style refs.
            if not col or not col.isidentifier():
                continue
            if col in _SQL_KEYWORDS:
                continue
            if _is_allowlisted(tbl, col):
                continue
            if col not in schema[tbl]:
                refs.append((tbl, col))

    # 3) ``UPDATE foo SET col = ..., col2 = ...`` assignment LHSes.
    # Catches bare columns that don't appear as ``alias.col``
    # elsewhere in the block — this is how we'd otherwise miss e.g.
    # ``UPDATE public.investigations SET change_summary = %s`` where
    # ``change_summary`` only shows up in the SET clause.
    for m in _UPDATE_SET_RE.finditer(block):
        tbl = m.group(1).lower()
        if tbl not in schema:
            continue
        set_body = m.group(2)
        for col_m in _SET_LHS_RE.finditer(set_body):
            col = col_m.group(1).lower()
            if col in _SQL_KEYWORDS:
                continue
            if _is_allowlisted(tbl, col):
                continue
            if col not in schema[tbl]:
                refs.append((tbl, col))

    return refs


def _scan_repo(
    src_dir: Path, schema: dict[str, set[str]]
) -> list[tuple[Path, int, str, str]]:
    drift: list[tuple[Path, int, str, str]] = []
    for py in _walk_python(src_dir):
        try:
            text = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, block in _extract_sql_blocks(text):
            for tbl, col in _scan_block_for_refs(block, schema):
                drift.append((py, line_no, tbl, col))
    return drift


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_migrations_define_core_tables():
    """Sanity: the parser actually finds the bootstrap tables.

    If this fails, the regex broke — every downstream drift report
    would be a false positive ("table does not exist") so we'd rather
    fail loud here than silently green.
    """
    schema = build_schema(_MIGRATIONS_DIR)
    assert "cases" in schema, "migration 000 must define public.cases"
    assert "investigations" in schema, (
        "migration 000 must define public.investigations"
    )
    assert "watchlist" in schema, "migration 001 must define public.watchlist"
    assert "freeze_letters_sent" in schema, (
        "migration 013 must define public.freeze_letters_sent"
    )
    # Spot-check that ALTER ADD COLUMN landed:
    assert "engagement_started_at" in schema["investigations"], (
        "migration 006 ADD COLUMN engagement_started_at missing"
    )
    assert "kyc_confirmed_at" in schema["watchlist"], (
        "migration 009 ADD COLUMN kyc_confirmed_at missing"
    )


def test_no_schema_drift_in_source_sql():
    """For every ``table.column`` referenced in ``src/recupero/**/*.py``
    SQL string literals, the column must exist in some migration.

    Drift report on failure: ``file:line  table.column  (suggested fix)``.
    """
    schema = build_schema(_MIGRATIONS_DIR)
    assert schema, "no migrations parsed — refusing to silently green"

    drift = _scan_repo(_SRC_DIR, schema)

    if drift:
        lines = []
        # De-duplicate by (file, line, table, col) so the same line
        # isn't reported once per regex pass.
        seen: set[tuple[str, int, str, str]] = set()
        for py, ln, tbl, col in drift:
            key = (str(py), ln, tbl, col)
            if key in seen:
                continue
            seen.add(key)
            rel = py.relative_to(_REPO_ROOT)
            cols = sorted(schema.get(tbl, set()))
            preview = ", ".join(cols[:8]) + ("..." if len(cols) > 8 else "")
            lines.append(
                f"  {rel}:{ln}  {tbl}.{col}  "
                f"(known {tbl} cols: {preview})"
            )
        msg = (
            "Schema drift: code references columns that no migration "
            "creates.\n"
            "Fix by either (a) adding a migration that creates the "
            "column, or (b) removing the stale reference from code.\n"
            + "\n".join(lines)
        )
        pytest.fail(msg)
