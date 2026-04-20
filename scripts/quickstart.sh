#!/usr/bin/env bash
# Quickstart for fresh environments. Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Recupero quickstart"
echo "    Repo: $ROOT"

# 1. Python version check
PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: python3 not found on PATH"
  exit 1
fi
PYVER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
echo "    Python: $PYVER ($($PY -c "import sys; print(sys.executable)"))"
case "$PYVER" in
  3.11|3.12|3.13)
    ;;
  *)
    echo "WARN: Recupero targets Python 3.11+. You have $PYVER. Continuing anyway."
    ;;
esac

# 2. Virtualenv
if [ ! -d ".venv" ]; then
  echo "==> Creating virtualenv at .venv"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# 3. Install
echo "==> Installing recupero (editable + dev extras)"
pip install --upgrade pip >/dev/null
pip install -e ".[dev]"

# 4. .env
if [ ! -f .env ]; then
  echo "==> Creating .env from template"
  cp .env.example .env
  echo "    Edit .env and fill in ETHERSCAN_API_KEY and COINGECKO_API_KEY before running a trace."
fi

# 5. Quick sanity check
echo "==> Running unit tests (no network calls)"
pytest tests/ -q

echo ""
echo "All set. Next:"
echo "    1. Edit .env with your API keys"
echo "    2. python scripts/verify_zigha.py    # runs the Zigha acceptance harness"
echo "    3. recupero --help                   # CLI entry point"
