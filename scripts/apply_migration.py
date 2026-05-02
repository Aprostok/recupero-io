#!/usr/bin/env python3
"""Apply a SQL migration file to the Supabase database.

Tiny helper so we can move forward on schema without blocking on the
admin-UI repo's migration tooling. Each migration is a hand-written
.sql file in ``migrations/`` with idempotent ``CREATE ... IF NOT EXISTS``
guards, so running the same file twice is safe.

Usage:
    python scripts/apply_migration.py migrations/001_watchlist.sql
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Path to .sql migration file")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"ERROR: {args.file} does not exist", file=sys.stderr)
        return 2

    load_dotenv()
    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2

    sql = args.file.read_text(encoding="utf-8")
    print(f"Applying {args.file} ({len(sql)} bytes)…")

    try:
        with psycopg.connect(dsn, autocommit=False) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
    except psycopg.Error as exc:
        print(f"ERROR: migration failed: {exc}", file=sys.stderr)
        return 1

    print("OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
