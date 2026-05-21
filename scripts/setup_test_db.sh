#!/usr/bin/env bash
#
# Stand up a fresh `recupero_int_test` Postgres database and apply
# every migration. Idempotent: drops and recreates the database
# from scratch (DESTRUCTIVE — never run against production).
#
# Created during RIGOR-1 (real integration testing). Before this
# script, getting a new operator's environment to the point where
# integration tests could run required:
#   1. Discover that migrations 001-020 reference public.cases /
#      public.investigations as base tables (they do, via FK).
#   2. Discover that those base tables aren't defined in ANY
#      migration — they live only in Jacob's prod Supabase.
#   3. Manually craft the base schema by reading every code site
#      that touches the tables.
# Now: this script (plus the new 000_bootstrap_base_tables.sql
# migration that ships in the repo) takes a fresh Postgres instance
# from zero to "all integration tests pass" in under a minute.
#
# Usage:
#   bash scripts/setup_test_db.sh
#
# Required env:
#   PGPASSWORD             — Postgres superuser password
#   PGHOST  (default 127.0.0.1)
#   PGPORT  (default 5432)
#   PGUSER  (default postgres)
#   PSQL    (default: auto-detect from /c/Program Files/PostgreSQL/*/bin/psql.exe)
#
# Output:
#   * Creates database `recupero_int_test`
#   * Applies migrations/000_*.sql .. migrations/0NN_*.sql in order
#   * Prints final `\dt public.*` listing
#   * Prints the DSN to export for pytest runs

set -euo pipefail

DB_NAME="${RECUPERO_INT_TEST_DB:-recupero_int_test}"
PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"

# Auto-detect psql on Windows when not explicitly set.
if [ -z "${PSQL:-}" ]; then
  for candidate in \
      "/c/Program Files/PostgreSQL/16/bin/psql.exe" \
      "/c/Program Files/PostgreSQL/17/bin/psql.exe" \
      "/c/Program Files/PostgreSQL/15/bin/psql.exe" \
      "/usr/bin/psql" \
      "/usr/local/bin/psql"
  do
    if [ -x "$candidate" ]; then
      PSQL="$candidate"
      break
    fi
  done
fi
if [ -z "${PSQL:-}" ]; then
  echo "ERROR: psql binary not found. Set PSQL env var or install PostgreSQL." >&2
  exit 2
fi
if [ -z "${PGPASSWORD:-}" ]; then
  echo "ERROR: PGPASSWORD env var is required." >&2
  exit 2
fi

echo "=== Postgres setup_test_db.sh ==="
echo "Using psql: $PSQL"
echo "Target:     $PGUSER@$PGHOST:$PGPORT/$DB_NAME"

export PGPASSWORD

echo "=== Dropping + recreating $DB_NAME ==="
"$PSQL" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
  -c "DROP DATABASE IF EXISTS $DB_NAME;" >/dev/null
"$PSQL" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
  -c "CREATE DATABASE $DB_NAME;" >/dev/null

# Apply migrations in order. Sort with `-V` so 002 comes before 010.
echo "=== Applying migrations ==="
ERRORS=0
for f in $(ls migrations/0*.sql | sort -V); do
  RESULT=$("$PSQL" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
              -d "$DB_NAME" -v ON_ERROR_STOP=1 -f "$f" 2>&1)
  if echo "$RESULT" | grep -q ERROR; then
    echo "FAIL $f"
    echo "$RESULT" | tail -5
    ERRORS=$((ERRORS+1))
  else
    echo "OK   $f"
  fi
done
if [ $ERRORS -ne 0 ]; then
  echo "=== $ERRORS migrations failed ==="
  exit 1
fi

echo "=== Tables ==="
"$PSQL" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
  -d "$DB_NAME" -c "\dt public.*" | head -40

echo ""
echo "=== Ready ==="
echo "Export this DSN to run the integration tests:"
echo "  export RECUPERO_RUN_INTEGRATION=1"
echo "  export RECUPERO_INTEGRATION_DSN='postgresql://$PGUSER:\$PGPASSWORD@$PGHOST:$PGPORT/$DB_NAME'"
echo ""
echo "Then:"
echo "  python -m pytest tests/integration/ -v"
echo "  python -m pytest tests/integration/test_real_concurrent_races.py -v"
