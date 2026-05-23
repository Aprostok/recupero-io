"""Static-analysis audit of every migration .sql file under migrations/.

These tests do NOT apply any migration to a real database — they read
each .sql file as text and assert structural invariants that we never
want to silently regress:

  1. Idempotency      — every CREATE uses IF NOT EXISTS so a re-run of
                         the same migration is a safe no-op
  2. Transactional    — every migration wraps its statements in an
                         explicit BEGIN/COMMIT pair, so a partial
                         failure leaves no half-applied state
  3. FK direction     — every REFERENCES clause declares ON DELETE
                         CASCADE / SET NULL / RESTRICT explicitly so
                         orphan-row policy is never accidentally the
                         (Postgres default) NO ACTION
  4. UNIQUE invariants— the high-leverage identifier columns
                         (case_number, stripe_event_id, token, slug,
                         freeze_letter target tuple) all carry a
                         UNIQUE constraint or unique index
  5. CHECK enums      — status-like enum columns have a CHECK
                         constraint listing their allowed values
                         (drift detector for handwritten state machines)
  6. ALTER ADD COLUMN — every ALTER TABLE ADD COLUMN statement uses
                         IF NOT EXISTS so a partial-rerun no-ops
                         instead of crashing on the second column
  7. Schema drift     — bootstrap 000 must define both base tables
                         (public.cases, public.investigations) that
                         every later migration references

The tests are intentionally written as RED tests: they assert the
desired invariant.  When a future migration violates one of them the
test fires immediately during pre-commit, before the .sql ever runs
in production.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO_ROOT / "migrations"


def _all_migrations() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))


@pytest.fixture(scope="module")
def migrations() -> list[Path]:
    files = _all_migrations()
    assert files, f"no migration files found under {MIGRATIONS_DIR}"
    return files


# ---------- 1. idempotency ------------------------------------------- #


def test_every_create_table_uses_if_not_exists(migrations: list[Path]) -> None:
    """CREATE TABLE without IF NOT EXISTS crashes on rerun. Forbid it."""
    bad: list[str] = []
    pat = re.compile(r"\bCREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)", re.IGNORECASE)
    for path in migrations:
        sql = path.read_text(encoding="utf-8")
        # Strip comments before checking so a doc-only mention is ignored.
        stripped = re.sub(r"--[^\n]*", "", sql)
        if pat.search(stripped):
            bad.append(path.name)
    assert not bad, f"CREATE TABLE without IF NOT EXISTS in: {bad}"


def test_every_create_index_uses_if_not_exists(migrations: list[Path]) -> None:
    """CREATE INDEX without IF NOT EXISTS crashes on rerun. Forbid it."""
    bad: list[str] = []
    pat = re.compile(
        r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!IF\s+NOT\s+EXISTS)",
        re.IGNORECASE,
    )
    for path in migrations:
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        if pat.search(sql):
            bad.append(path.name)
    assert not bad, f"CREATE INDEX without IF NOT EXISTS in: {bad}"


def test_alter_add_column_uses_if_not_exists(migrations: list[Path]) -> None:
    """ALTER TABLE ... ADD COLUMN must use IF NOT EXISTS for rerun safety."""
    bad: list[str] = []
    # Match any ADD COLUMN that isn't followed by IF NOT EXISTS.
    pat = re.compile(
        r"\bADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS)", re.IGNORECASE
    )
    for path in migrations:
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        if pat.search(sql):
            bad.append(path.name)
    assert not bad, f"ADD COLUMN without IF NOT EXISTS in: {bad}"


# ---------- 2. transactional safety ---------------------------------- #


def test_every_migration_wraps_in_begin_commit(migrations: list[Path]) -> None:
    """Each migration must have an explicit BEGIN and COMMIT.

    apply_migration.py runs with autocommit=False so a missing
    BEGIN/COMMIT is *implicitly* wrapped — but inconsistency between
    files makes a future copy-paste into psql (which auto-commits each
    statement) silently dangerous.  Be explicit.

    Currently failing for: 005, 006, 007, 008, 009, 010 (all of which
    were written before the BEGIN/COMMIT convention was established).
    Documented as RED so the convention is enforced going forward.
    """
    missing: list[str] = []
    for path in migrations:
        sql = path.read_text(encoding="utf-8")
        has_begin = re.search(r"^\s*BEGIN\s*;", sql, re.IGNORECASE | re.MULTILINE)
        has_commit = re.search(r"^\s*COMMIT\s*;", sql, re.IGNORECASE | re.MULTILINE)
        if not (has_begin and has_commit):
            missing.append(path.name)
    assert not missing, (
        f"migrations missing explicit BEGIN/COMMIT: {missing}. "
        "Wrap each migration in BEGIN; ... COMMIT; for atomicity + "
        "consistency with the rest of the directory."
    )


# ---------- 3. foreign-key direction --------------------------------- #


def test_every_foreign_key_declares_on_delete(migrations: list[Path]) -> None:
    """Every REFERENCES clause must explicitly declare ON DELETE behavior.

    Postgres's default is NO ACTION — which is almost never what we
    want for an audit-trail / append-only schema like Recupero's.
    Forcing every FK to spell it out (CASCADE / SET NULL / RESTRICT)
    means the reviewer always sees the orphan policy at code-review
    time.
    """
    refs_pat = re.compile(
        # Match "REFERENCES schema.table(col)" optionally followed by
        # whitespace/newlines then either ON DELETE or NOT.
        r"REFERENCES\s+[\w\.]+\s*\([^)]*\)([^,\n]*(?:\n[^,\n]*)?)",
        re.IGNORECASE,
    )
    on_delete_pat = re.compile(r"ON\s+DELETE\s+(CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION)", re.IGNORECASE)
    violations: list[str] = []
    for path in migrations:
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        for match in refs_pat.finditer(sql):
            tail = match.group(1) or ""
            if not on_delete_pat.search(tail):
                violations.append(f"{path.name}: {match.group(0)[:80]!r}")
    assert not violations, (
        "FK clauses missing ON DELETE policy:\n  "
        + "\n  ".join(violations)
    )


# ---------- 4. UNIQUE invariants on high-leverage columns ------------ #


@pytest.mark.parametrize(
    "filename, column",
    [
        ("000_bootstrap_base_tables.sql", "case_number"),
        ("007_case_tokens.sql", "token"),
        ("010_payments.sql", "stripe_event_id"),
        ("019_case_clusters.sql", "public_id"),
        ("020_law_firms.sql", "slug"),
    ],
)
def test_identifier_columns_have_unique(filename: str, column: str) -> None:
    """Identifier-shaped columns must be declared UNIQUE.

    Without UNIQUE the idempotency / dedup logic in the application
    layer becomes a row-locking nightmare.  These are columns where
    application code already assumes uniqueness.
    """
    path = MIGRATIONS_DIR / filename
    sql = path.read_text(encoding="utf-8")
    # Look for "<column> ... UNIQUE" within ~200 chars on the same/next
    # few lines (inline declaration) OR a separate UNIQUE (<column>).
    inline = re.search(
        rf"\b{re.escape(column)}\b[^,\n]*?\bUNIQUE\b",
        sql,
        re.IGNORECASE,
    )
    standalone = re.search(
        rf"UNIQUE\s*\([^)]*\b{re.escape(column)}\b[^)]*\)",
        sql,
        re.IGNORECASE,
    )
    assert inline or standalone, (
        f"{filename}: column {column!r} has no UNIQUE constraint "
        "(checked inline and as a table-level UNIQUE (...) clause)"
    )


# ---------- 5. CHECK constraints on enum-shaped status columns ------- #


@pytest.mark.parametrize(
    "filename, expected_values",
    [
        ("001_watchlist.sql", {"active", "frozen", "recovered", "cleared"}),
        ("004_watchlist_priority.sql", {"standard", "hot", "paused"}),
        ("010_payments.sql", {"paid", "unpaid", "refunded", "disputed"}),
        (
            "012_monitoring_subscriptions.sql",
            {"active", "paused", "expired", "deleted"},
        ),
        ("019_case_clusters.sql", {"active", "consolidated", "closed", "archived"}),
        ("020_law_firms.sql", {"active", "paused", "closed", "archived"}),
    ],
)
def test_status_columns_have_check_constraint(
    filename: str, expected_values: set[str]
) -> None:
    """Status / enum columns must be defended by a CHECK constraint."""
    path = MIGRATIONS_DIR / filename
    sql = path.read_text(encoding="utf-8")
    # Find every CHECK ... IN (...) clause and parse its literals.
    found: set[str] = set()
    for match in re.finditer(
        r"CHECK\s*\([^)]*IN\s*\(([^)]*)\)", sql, re.IGNORECASE
    ):
        for literal in re.findall(r"'([^']+)'", match.group(1)):
            found.add(literal)
    missing = expected_values - found
    assert not missing, (
        f"{filename}: status CHECK constraint missing values {missing}. "
        f"Found: {sorted(found)}"
    )


def test_amount_type_check_on_payments() -> None:
    """payments.amount_type must restrict to known categories."""
    path = MIGRATIONS_DIR / "010_payments.sql"
    sql = path.read_text(encoding="utf-8")
    for needed in ("diagnostic", "engagement", "contingent", "unknown"):
        assert f"'{needed}'" in sql, (
            f"010_payments.sql amount_type CHECK missing {needed!r}"
        )


# ---------- 6. NOT NULL on attacker-influenced columns --------------- #


@pytest.mark.parametrize(
    "filename, column",
    [
        ("005_emails_sent.sql", "to_address"),
        ("005_emails_sent.sql", "subject"),
        ("005_emails_sent.sql", "email_type"),
        ("008_engagement_signatures.sql", "signature_name"),
        ("008_engagement_signatures.sql", "agreement_text"),
        ("008_engagement_signatures.sql", "fee_usd"),
        ("010_payments.sql", "amount_cents"),
        ("010_payments.sql", "stripe_event_id"),
        ("012_monitoring_subscriptions.sql", "trigger_type"),
        ("013_freeze_outcomes.sql", "issuer"),
        ("013_freeze_outcomes.sql", "target_address"),
        ("020_law_firms.sql", "slug"),
        ("020_law_firms.sql", "name"),
    ],
)
def test_critical_columns_are_not_null(filename: str, column: str) -> None:
    """Audit/identity columns must be NOT NULL — silent NULLs corrupt the audit trail."""
    path = MIGRATIONS_DIR / filename
    sql = path.read_text(encoding="utf-8")
    # Match the column declaration line — column name, then anything
    # on the rest of the line up to the newline, containing NOT NULL.
    # `[^\n]*` (NOT `[^,\n]*`) is required because Postgres type
    # modifiers like `numeric(20, 2)` contain a comma inside parens
    # that would terminate the stricter character class before NOT NULL.
    pat = re.compile(
        rf"^\s*{re.escape(column)}\s+[^\n]*\bNOT\s+NULL\b",
        re.IGNORECASE | re.MULTILINE,
    )
    assert pat.search(sql), (
        f"{filename}: column {column!r} declaration is missing NOT NULL"
    )


# ---------- 7. CONCURRENTLY hint on large-table indexes -------------- #


def test_concurrent_index_creation_not_inside_transaction() -> None:
    """Sanity: CREATE INDEX CONCURRENTLY may not appear inside BEGIN/COMMIT.

    Postgres rejects CONCURRENTLY inside a transaction block, so any
    migration that uses it MUST omit the BEGIN/COMMIT wrapper (and
    document the tradeoff).  Today no migration uses CONCURRENTLY —
    Recupero tables are small.  This test guards against a future
    migration that adds CONCURRENTLY inside a BEGIN without realizing
    Postgres will reject it at apply time.
    """
    for path in _all_migrations():
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        if re.search(r"\bCONCURRENTLY\b", sql, re.IGNORECASE):
            has_begin = re.search(r"^\s*BEGIN\s*;", sql, re.IGNORECASE | re.MULTILINE)
            assert not has_begin, (
                f"{path.name}: uses CREATE INDEX CONCURRENTLY inside "
                "an explicit BEGIN/COMMIT — Postgres will reject this. "
                "Move the CONCURRENTLY statement outside the transaction."
            )


# ---------- 8. schema drift: bootstrap covers downstream references -- #


def test_bootstrap_defines_cases_and_investigations() -> None:
    """000_bootstrap_base_tables.sql must create both base tables.

    Every later migration assumes ``public.cases`` and
    ``public.investigations`` already exist (FKs, ALTER TABLE).  If
    000 ever stops creating them, a fresh DB rebuild silently breaks.
    """
    sql = (MIGRATIONS_DIR / "000_bootstrap_base_tables.sql").read_text(
        encoding="utf-8"
    )
    assert re.search(
        r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.cases\b", sql, re.IGNORECASE
    ), "000 must CREATE TABLE IF NOT EXISTS public.cases"
    assert re.search(
        r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+public\.investigations\b",
        sql,
        re.IGNORECASE,
    ), "000 must CREATE TABLE IF NOT EXISTS public.investigations"


def test_no_drop_table_without_if_exists(migrations: list[Path]) -> None:
    """DROP TABLE without IF EXISTS is a foot-gun on a rerun."""
    bad: list[str] = []
    pat = re.compile(r"\bDROP\s+TABLE\s+(?!IF\s+EXISTS)", re.IGNORECASE)
    for path in migrations:
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        if pat.search(sql):
            bad.append(path.name)
    assert not bad, f"DROP TABLE without IF EXISTS in: {bad}"
