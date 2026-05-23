"""Logging configuration.

Outputs to stdout (Rich-formatted by default, JSON via env var) and
to a per-case log file in {case_dir}/logs/trace.log. Both at the
configured level.

v0.17.0 (observability):
  * `RECUPERO_LOG_FORMAT=json` switches stdout to JSON-per-line so
    Railway's log filter UI can pivot on structured fields directly.
  * `RECUPERO_LOG_FORMAT=rich` (default) keeps the existing
    human-readable RichHandler output for local dev.
  * Per-request context (investigation_id, case_id, stage, request_id)
    propagates via a contextvars.ContextVar, populated by the
    `RunContext` helper. Every log record emitted INSIDE a `with
    run_context(...)` block carries the same correlation fields
    automatically — no per-call `extra={...}` boilerplate.
"""

from __future__ import annotations

import contextlib
import contextvars
import json as _json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from rich.logging import RichHandler

# v0.17.0: per-request context. Stores a dict of correlation fields
# (investigation_id, case_id, stage, request_id) that the JSON
# formatter merges into every log record emitted inside the context.
# Async-safe via contextvars: each asyncio task / thread sees its own
# binding once `.set()` has been called inside that task.
#
# IMPORTANT: default is `None`, not `{}`. A mutable `{}` default is
# SHARED across all contexts that never call `.set()` — anyone who
# mutates the value (e.g., `ctx["foo"] = "bar"` instead of `dict(ctx)
# | {"foo": "bar"}`) would leak the mutation everywhere. Using None
# forces every caller through `current_log_context()`, which copies
# defensively. Ruff B039 ("mutable contextvar default") catches this.
_LOG_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "_LOG_CONTEXT", default=None,
)


def _current_raw_context() -> dict[str, Any]:
    """Internal: read the contextvar, treating an unset/None binding
    as an empty dict. Callers MUST NOT mutate the returned dict
    in-place — use `dict(_current_raw_context())` if you need to
    derive a new one."""
    ctx = _LOG_CONTEXT.get()
    return ctx if ctx is not None else {}


@contextlib.contextmanager
def run_context(**fields: Any):
    """Push correlation fields onto the per-task log context.

    Usage:

        with run_context(investigation_id=str(inv.id), stage="trace"):
            log.info("starting trace")  # auto-tagged

    Nested calls merge with parent context; the outer fields win on
    collision (the inner block can't override the run's
    investigation_id, but it CAN add a more-specific stage tag).

    A fresh `request_id` UUID is auto-generated when not provided.
    """
    parent = _current_raw_context()
    merged = dict(parent)
    if "request_id" not in fields and "request_id" not in merged:
        merged["request_id"] = uuid4().hex[:12]
    # Caller fields don't override parent fields (outer scope wins).
    for k, v in fields.items():
        merged.setdefault(k, v)
    token = _LOG_CONTEXT.set(merged)
    try:
        yield merged
    finally:
        _LOG_CONTEXT.reset(token)


def current_log_context() -> dict[str, Any]:
    """Return a snapshot of the current log context. Used by Sentry
    integration to tag events without reaching into the contextvar
    directly."""
    return dict(_current_raw_context())


class _ContextInjectingFilter(logging.Filter):
    """Merge the active run_context fields into every log record's
    __dict__ so formatters + downstream handlers can read them
    uniformly. Records that already carry an `extra={...}` field of
    the same name win (explicit > contextual).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = _current_raw_context()
        for k, v in ctx.items():
            if not hasattr(record, k):
                setattr(record, k, v)
        return True


class _JsonFormatter(logging.Formatter):
    """One-line JSON per record. Includes correlation fields from the
    run_context contextvar plus any `extra={...}` kwargs passed at
    the log call site.

    Output shape:
      {"ts": "2026-05-18T04:22:17.123Z", "level": "INFO",
       "logger": "recupero.worker.pipeline", "msg": "...",
       "investigation_id": "...", "stage": "trace", "request_id": "...",
       "duration_sec": 12.3, "outcome": "ok"}

    Reserved keys are populated unconditionally. Anything else on the
    LogRecord's __dict__ (set by the context filter or `extra=`) is
    emitted as-is unless it's a stdlib logging internal (filtered).
    """

    _STDLIB_RECORD_KEYS = {
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process", "message",
    }

    def format(self, record: logging.LogRecord) -> str:
        # ISO8601 with Z suffix + millisecond resolution.
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
        ts = f"{ts}.{int(record.msecs):03d}Z"
        try:
            message = record.getMessage()
        except Exception as exc:  # noqa: BLE001
            message = f"<getMessage failed: {exc}>"
        payload: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "msg": message,
        }
        # Merge any custom attributes (set by the context filter or by
        # the call site's extra={...}). Stdlib-internal keys excluded.
        for k, v in record.__dict__.items():
            if k in self._STDLIB_RECORD_KEYS or k.startswith("_"):
                continue
            try:
                _json.dumps(v)  # cheap serializability check
                payload[k] = v
            except (TypeError, ValueError):
                payload[k] = repr(v)
        # Exception info if present (already rendered by the
        # _SecretRedactingFilter into record.exc_text).
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            payload["exception"] = record.exc_text
        return _json.dumps(payload, separators=(",", ":"))


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
# v0.17.10 (round-10 security MED): Recupero-specific header redaction.
# When an httpx response is logged with response.headers / .request.headers
# the sensitive auth-key headers come through verbatim. These patterns
# match the literal `Header-Name: VALUE` / `'Header-Name': 'VALUE'` shapes
# httpx + Python's stdlib logging produce.
_AUTH_HEADER_PATTERN = re.compile(
    r"(?i)(['\"]?(?:x-recupero-api-key|tron-pro-api-key|x-cg-pro-api-key|"
    r"x-cg-demo-api-key|x-api-key|helius-api-key|authorization)['\"]?\s*[:=]\s*['\"]?)"
    r"([A-Za-z0-9._\-]{8,})",
)
# Anthropic API keys (ant-...) and OpenAI keys (sk-..., sk-proj-...).
_LITERAL_KEY_PATTERN = re.compile(
    r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,})",
)
# Wave 5+ extension: vendor key prefixes with underscore-style tokens.
# Stripe live/test/restricted secret keys + webhook signing secret.
# Resend live/test API keys (re_...). The shared pattern accepts any
# `(prefix_)(token)` shape — we anchor on the prefix to avoid false
# positives on arbitrary `xx_yy` identifiers.
_STRIPE_KEY_PATTERN = re.compile(
    r"\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,})",
)
_STRIPE_WEBHOOK_PATTERN = re.compile(
    r"\b(whsec_[A-Za-z0-9]{16,})",
)
_RESEND_KEY_PATTERN = re.compile(
    r"\b(re_[A-Za-z0-9]{16,})",
)
# GitHub Personal Access Tokens — classic + fine-grained.
# Prefix list per GitHub docs: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server),
# ghs_ (server-to-server), ghr_ (refresh).
_GITHUB_TOKEN_PATTERN = re.compile(
    r"\b(gh[pousr]_[A-Za-z0-9]{20,})",
)
# AWS access key ID — exactly 16 uppercase alphanumerics after AKIA / ASIA
# (temporary STS). Anchor on word boundary so we don't gobble a longer hex.
_AWS_ACCESS_KEY_PATTERN = re.compile(
    r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
)
# JWT-shaped tokens: three base64url segments separated by dots, with the
# header beginning `eyJ` (the literal base64 of `{"`). Catches Supabase
# service-role JWTs, Anthropic OAuth, generic auth0 / cognito tokens.
_JWT_PATTERN = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
)
# New-style Supabase keys. The JWT-shape legacy service-role token is
# being phased out for prefixed opaque keys:
#   sb_secret_<base62>       — server-only service role
#   sb_publishable_<base62>  — client anon key (less sensitive, but
#                              still an identifier we don't want in
#                              shared log archives)
#   sbp_<base62>             — short prefix variant seen in CLI tooling
# Adversarial sync audit: SupabaseCaseStore echoes the upstream error
# body in RuntimeError("upload ... failed: <status> <text[:200]>"), so
# any 4xx that reflects the inbound header would leak the bearer key.
_SUPABASE_NEWKEY_PATTERN = re.compile(
    r"\b((?:sb_secret|sb_publishable|sbp)_[A-Za-z0-9]{16,})",
)
# Recupero portal tokens — secrets.token_urlsafe(32) produces ~43 chars of
# URL-safe base64 (A-Z, a-z, 0-9, -, _). Catch when one is accidentally
# logged as a free-form literal. Require the explicit context label so we
# don't redact unrelated 43-char IDs (txids, etc.).
_PORTAL_TOKEN_PATTERN = re.compile(
    r"(?i)((?:portal[_-]?token|access[_-]?token|share[_-]?token)['\"]?\s*[:=]\s*['\"]?)"
    r"([A-Za-z0-9_\-]{32,})",
)


def _redact(text: str) -> str:
    if not text:
        return text
    text = _DSN_PASSWORD_PATTERN.sub(r"\1***\3", text)
    text = _BEARER_PATTERN.sub(r"\1***", text)
    text = _API_KEY_PATTERN.sub(r"\1***", text)
    text = _AUTH_HEADER_PATTERN.sub(r"\1***", text)
    text = _PORTAL_TOKEN_PATTERN.sub(r"\1***", text)
    # Stripe / Resend / GitHub / AWS / JWT redaction runs BEFORE the
    # generic sk-/ant- pattern so the more-specific shapes win cleanly.
    text = _STRIPE_KEY_PATTERN.sub("***", text)
    text = _STRIPE_WEBHOOK_PATTERN.sub("***", text)
    text = _RESEND_KEY_PATTERN.sub("***", text)
    text = _GITHUB_TOKEN_PATTERN.sub("***", text)
    text = _AWS_ACCESS_KEY_PATTERN.sub("***", text)
    text = _JWT_PATTERN.sub("***", text)
    text = _SUPABASE_NEWKEY_PATTERN.sub("***", text)
    text = _LITERAL_KEY_PATTERN.sub("***", text)
    return text


# Adversarial-input wave (v0.20.2): log-injection defense. An attacker
# who controls a logged argument (a case_id carrying "\r\nFATAL: faked
# log line") can forge an entire log line in plain-text handlers
# (RichHandler / file handler). The JSON formatter escapes CR/LF for
# us as a side effect of json.dumps, but it's the plain-text path
# that's the operator's primary monitor. Strip CR/LF/NUL + other
# ASCII control chars from every message before emission.
#
# CRLF is replaced with " | " so a multi-line traceback summary still
# reads sensibly when an exception's message accidentally contained
# embedded newlines; control chars are dropped entirely.
def _strip_log_injection(text: str) -> str:
    if not text:
        return text
    # Replace CR/LF with a marker so multi-line strings collapse to one
    # log line. Drop NUL + remaining ASCII control chars (incl. tab is
    # KEPT because operator-friendly traces use it).
    text = text.replace("\r\n", " | ").replace("\n", " | ").replace("\r", " | ")
    cleaned = []
    for c in text:
        cp = ord(c)
        if cp == 0:
            continue
        # Keep tab (0x09) for legibility; drop other C0 controls (excluding
        # what we already handled).
        if cp < 0x20 and cp != 0x09:
            continue
        if cp == 0x7F:
            continue
        # Strip bidi / direction-override controls — these have been used
        # to disguise the actual content of log lines (e.g., "Trojan Source"
        # style attacks).
        if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            continue
        cleaned.append(c)
    return "".join(cleaned)


class _SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts DSN passwords + bearer tokens AND
    strips log-injection control characters before a record is
    emitted to any handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Build the formatted message ONCE here so we can redact a
            # consistent string, then stash it as record.msg with no
            # args. This avoids double-formatting downstream.
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True  # never block a log record on filter failure
        # Order matters: redact secrets FIRST, then strip control
        # chars. A password might contain `\n` characters; stripping
        # before redaction could mangle the DSN match.
        redacted = _redact(msg)
        sanitized = _strip_log_injection(redacted)
        if sanitized != msg:
            record.msg = sanitized
            record.args = None
        # Also redact + sanitize any exc_info text that's already been
        # rendered. Multi-line tracebacks are intentional — only
        # control chars NOT part of the LF separator get stripped.
        if record.exc_text:
            record.exc_text = _redact(record.exc_text)
        return True


def setup_logging(level: str, case_dir: Path | None = None) -> None:
    """Configure root logger handlers.

    Format selection via `RECUPERO_LOG_FORMAT`:
      * "json"  → JSON-per-line on stdout (Railway-friendly, machine-
                  parseable; includes run_context correlation fields).
      * "rich"  → human-readable Rich tracebacks (default; local dev).
      * unset / other → defaults to "rich".

    File handler (case_dir-rooted trace.log) always uses the
    plain-text format — it's a per-case forensic artifact, not a
    log-aggregation feed.
    """
    # Force UTF-8 on stdout/stderr (Windows defaults to cp1252 which crashes on Unicode)
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
    # v0.17.0: merge run_context correlation fields into every record
    # so the JSON formatter can emit them and the plain-text formatter
    # can ignore them gracefully.
    context_filter = _ContextInjectingFilter()

    log_format = (os.environ.get("RECUPERO_LOG_FORMAT") or "").strip().lower()

    # Console
    if log_format == "json":
        console: logging.Handler = logging.StreamHandler(sys.stdout)
        console.setFormatter(_JsonFormatter())
    else:
        console = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
    console.setLevel(level.upper())
    console.addFilter(context_filter)  # context BEFORE redaction
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
        fh.addFilter(context_filter)
        fh.addFilter(secret_filter)
        root.addHandler(fh)

    # Quiet overly chatty libs at INFO level
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


__all__ = (
    "setup_logging",
    "run_context",
    "current_log_context",
)
