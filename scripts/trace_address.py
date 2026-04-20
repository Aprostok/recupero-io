#!/usr/bin/env python3
"""Convenience wrapper around `recupero trace`.

Equivalent to:
    recupero trace --chain ethereum --address <addr> --incident-time <ts> --case-id <id>

Useful as a copy/paste starting point — edit the values below and run with
`python scripts/trace_address.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running before `pip install -e .`
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from recupero.cli import app  # noqa: E402

if __name__ == "__main__":
    # Hand off to Typer with the trace subcommand pre-selected
    sys.argv = [
        "trace_address.py",
        "trace",
        "--chain", "ethereum",
        "--address", "0x0cdC902f4448b51289398261DB41E8ADC99bE955",
        "--incident-time", "2025-10-09T00:00:00Z",
        "--case-id", "ZIGHA-MANUAL",
    ]
    app()
