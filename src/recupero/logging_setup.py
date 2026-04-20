"""Logging configuration.

Outputs to stdout (Rich-formatted) and to a per-case log file in
{case_dir}/logs/trace.log. Both at the configured level.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(level: str, case_dir: Path | None = None) -> None:
    # Force UTF-8 on stdout/stderr (Windows defaults to cp1252 which crashes on Unicode)
    import sys
    for stream in (sys.stdout, sys.stderr):
        rec = getattr(stream, "reconfigure", None)
        if rec is not None:
            try: rec(encoding="utf-8", errors="replace")
            except Exception: pass
    root = logging.getLogger()
    # Reset to avoid double-handlers on repeated runs
    for h in list(root.handlers):
        root.removeHandler(h)

    root.setLevel(level.upper())

    # Console
    console = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
    console.setLevel(level.upper())
    root.addHandler(console)

    # File
    if case_dir is not None:
        log_dir = case_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "trace.log", mode="w", encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)-30s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        ))
        fh.setLevel(level.upper())
        root.addHandler(fh)

    # Quiet overly chatty libs at INFO level
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
