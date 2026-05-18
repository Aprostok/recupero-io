"""Logging configuration.

Outputs to stdout (Rich-formatted) and to a per-case log file in
{case_dir}/logs/trace.log. Both at the configured level.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from rich.logging import RichHandler


# v0.16.7 (round-9 security HIGH): redact secrets from every log record
# before it lands in stdout / Railway / the per-case trace.log file.
#
# Two patterns matter in practice:
#
#   1. Postgres DSNs of the form `postgres(ql)?://user:PASSWORD@host:port/db`.
#      psycopg's connection-failure messages routinely include the full DSN
#      with password inline; one DNS hiccup on Supabase would otherwise
#      print our database password to operator logs (Railway retains those
#      indefinitely).
#
#   2. Bearer tokens / API keys following `Authorization: Bearer ...` or
#      common query-param patterns. Less common in our log lines, but cheap
#      defense-in-depth.
_DSN_PASSWORD_PATTERN = re.compile(
    r"(postgres(?:ql)?://[^:/@\s]+:)([^@\s]+)(@)",
    flags=re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(
    r"(?i)(Bearer\s+)([A-Za-z0-9._\-]{8,})",
)
_API_KEY_PATTERN = re.compile(
    r"(?i)([?&](?:api[_-]?key|admin[_-]?key|token)=)([^&\s]+)",
)


def _redact(text: str) -> str:
    if not text:
        return text
    text = _DSN_PASSWORD_PATTERN.sub(r"\1***\3", text)
    text = _BEARER_PATTERN.sub(r"\1***", text)
    text = _API_KEY_PATTERN.sub(r"\1***", text)
    return text


class _SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts DSN passwords + bearer tokens before
    a record is emitted to any handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Build the formatted message ONCE here so we can redact a
            # consistent string, then stash it as record.msg with no
            # args. This avoids double-formatting downstream.
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True  # never block a log record on filter failure
        redacted = _redact(msg)
        if redacted != msg:
            record.msg = redacted
            record.args = None
        # Also redact any exc_info text that's already been rendered.
        if record.exc_text:
            record.exc_text = _redact(record.exc_text)
        return True


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

    # Redact DSN passwords + bearer tokens from EVERY log record before
    # it reaches any handler. Attached at the root-logger level so child
    # loggers automatically inherit it.
    secret_filter = _SecretRedactingFilter()

    # Console
    console = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
    console.setLevel(level.upper())
    console.addFilter(secret_filter)
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
        fh.addFilter(secret_filter)
        root.addHandler(fh)

    # Quiet overly chatty libs at INFO level
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
