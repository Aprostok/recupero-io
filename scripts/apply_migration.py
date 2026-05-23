#!/usr/bin/env python3
"""Apply a SQL migration file to the Supabase database.

Tiny helper so we can move forward on schema without blocking on the
admin-UI repo's migration tooling. Each migration is a hand-written
.sql file in ``migrations/`` with idempotent ``CREATE ... IF NOT EXISTS``
guards, so running the same file twice is safe.

Hardening invariants (see ``tests/test_apply_migration_audit.py``):
  * Refuse any path that does not resolve into the repo's
    ``migrations/`` directory — operators must not be able to apply
    ``/tmp/whatever.sql`` or escape via ``..``.
  * Refuse files larger than ``_MAX_SQL_BYTES`` (paste-accident guard).
  * Refuse migrations containing destructive DDL (``DROP TABLE``,
    ``DROP SCHEMA``, ``TRUNCATE``, ``ALTER USER ... PASSWORD``) unless
    the operator confirms with ``--yes-i-really-mean-it``.
  * Never echo the SQL body (a stray ``ALTER USER ... PASSWORD`` would
    otherwise leak via stdout / trace logs) or the DSN.

Usage:
    python scripts/apply_migration.py migrations/001_watchlist.sql
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MIGRATIONS_DIR = (_REPO_ROOT / "migrations").resolve()
_MAX_SQL_BYTES = 5 * 1024 * 1024  # 5 MiB — generous for hand-written DDL

# Destructive-DDL fingerprints. Word-boundary anchored, case-insensitive.
# These match the *raw* SQL text, which is conservative — a DROP TABLE
# buried in a comment will still trip the guard. That's fine: the
# operator can either remove the comment or pass --yes-i-really-mean-it.
_DESTRUCTIVE_PATTERNS = (
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+SCHEMA\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
    re.compile(r"\bALTER\s+USER\b.*\bPASSWORD\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bALTER\s+ROLE\b.*\bPASSWORD\b", re.IGNORECASE | re.DOTALL),
)


def _is_inside_migrations(path: Path) -> bool:
    """True iff ``path`` resolves to a file under ``migrations/``."""
    try:
        resolved = path.resolve()
    except OSError:
        return False
    try:
        resolved.relative_to(_MIGRATIONS_DIR)
    except ValueError:
        return False
    return True


def _find_destructive(sql: str) -> str | None:
    """Return the matched destructive snippet, or ``None`` if clean."""
    for pat in _DESTRUCTIVE_PATTERNS:
        m = pat.search(sql)
        if m:
            return m.group(0)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Path to .sql migration file")
    parser.add_argument(
        "--yes-i-really-mean-it",
        action="store_true",
        dest="confirm_destructive",
        help="Acknowledge destructive DDL (DROP/TRUNCATE/ALTER USER PASSWORD).",
    )
    args = parser.parse_args()

    if not args.file.exists():
        print(f"ERROR: {args.file} does not exist", file=sys.stderr)
        return 2

    if not _is_inside_migrations(args.file):
        # Do NOT echo the resolved path back — operators sometimes pass
        # secrets-bearing temp paths.
        print(
            "ERROR: migration file must live under the repo's migrations/ "
            "directory (rejecting out-of-tree path).",
            file=sys.stderr,
        )
        return 2

    try:
        size = args.file.stat().st_size
    except OSError as exc:
        print(f"ERROR: cannot stat migration file: {exc}", file=sys.stderr)
        return 2
    if size > _MAX_SQL_BYTES:
        print(
            f"ERROR: migration file size {size} bytes exceeds cap "
            f"{_MAX_SQL_BYTES} bytes; refusing (too large).",
            file=sys.stderr,
        )
        return 2

    load_dotenv()
    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        # Never echo the (missing) DSN value — just the var name.
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2

    sql = args.file.read_text(encoding="utf-8")

    destructive = _find_destructive(sql)
    if destructive and not args.confirm_destructive:
        print(
            f"ERROR: migration contains destructive DDL ({destructive!r}); "
            "re-run with --yes-i-really-mean-it to confirm.",
            file=sys.stderr,
        )
        return 2

    # Deliberately do NOT print ``sql`` — the body may carry secrets
    # (e.g. ALTER USER ... PASSWORD). Only file name + byte count.
    print(f"Applying {args.file.name} ({len(sql)} bytes)…")

    try:
        with psycopg.connect(dsn, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
    except psycopg.Error as exc:
        # ``exc`` from libpq may carry the connection target; scrub
        # anything that resembles the DSN before surfacing it.
        safe = str(exc).replace(dsn, "<dsn-redacted>")
        print(f"ERROR: migration failed: {safe}", file=sys.stderr)
        return 1

    print("OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
