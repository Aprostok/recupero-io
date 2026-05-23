"""Sentry integration — opt-in via the SENTRY_DSN env var.

The integration is intentionally light:

  * `init_sentry()` configures the Sentry SDK if `sentry-sdk` is
    installed AND SENTRY_DSN is set. Returns True when enabled.
  * A `before_send` hook merges the current run_context (investigation_id,
    case_id, stage, request_id) into every event as tags + context,
    so the Sentry UI can filter by case.
  * Secret-redaction runs on event payloads via the same patterns as
    logging_setup._SecretRedactingFilter — a DSN password in a
    breadcrumb message gets ***'d before it leaves the worker.

If sentry-sdk isn't installed, init_sentry() returns False silently;
the worker keeps running without Sentry capture. This keeps the
default `pip install -e .` lean for development environments that
don't need Sentry.
"""

from __future__ import annotations

import logging
import math
import os
from typing import Any

log = logging.getLogger(__name__)


_sentry_enabled = False


# Adversarial-input wave (v0.20.2): per-Sentry-tag length cap. Sentry
# accepts up to 200 chars per tag value; anything past that is
# silently truncated, but worse — values containing CR/LF/NUL can
# break the on-wire JSON payload or appear as "injected" log entries
# on the Sentry side. We sanitize before Sentry sees them.
_MAX_TAG_VALUE_LEN = 200


def _sanitize_tag_value(v: Any) -> str:
    """Coerce a Sentry tag value to a safe, bounded string.

    Strips control characters (CR/LF/NUL/bidi) and truncates to
    Sentry's documented tag-value limit. Defends against an attacker
    who controls a correlation field (case_id, address, error string)
    smuggling control characters or oversized payloads into the
    Sentry UI."""
    s = str(v) if v is not None else ""
    out = []
    for c in s:
        cp = ord(c)
        if cp < 0x20 or cp == 0x7F:
            continue
        if 0x200B <= cp <= 0x200F or 0x202A <= cp <= 0x202E:
            continue
        if 0x2066 <= cp <= 0x2069 or cp == 0xFEFF:
            continue
        out.append(c)
    cleaned = "".join(out)
    if len(cleaned) > _MAX_TAG_VALUE_LEN:
        cleaned = cleaned[: _MAX_TAG_VALUE_LEN] + "...(truncated)"
    return cleaned


def sentry_enabled() -> bool:
    """True when init_sentry() succeeded earlier in this process."""
    return _sentry_enabled


def init_sentry() -> bool:
    """Initialize Sentry if configured. Returns True when enabled.

    Reads:
      * SENTRY_DSN              — required to enable (when empty,
                                  this function is a no-op).
      * RECUPERO_ENV            — "production" | "staging" | "dev"
                                  → maps to Sentry's environment tag.
      * RECUPERO_RELEASE        — usually `recupero@<version>`; falls
                                  back to the installed package version.
      * SENTRY_TRACES_SAMPLE_RATE — float 0..1; default 0.0 (no
                                  performance traces, errors only).
    """
    global _sentry_enabled
    dsn = (os.environ.get("SENTRY_DSN") or "").strip()
    if not dsn:
        log.debug("Sentry disabled: SENTRY_DSN unset")
        return False

    try:
        import sentry_sdk  # type: ignore[import-not-found]
        from sentry_sdk.integrations.logging import (
            LoggingIntegration,  # type: ignore[import-not-found]
        )
    except ImportError:
        log.warning(
            "SENTRY_DSN set but sentry-sdk not installed; "
            "Sentry capture disabled. Add `sentry-sdk` to requirements."
        )
        return False

    env_name = (os.environ.get("RECUPERO_ENV") or "dev").strip() or "dev"
    release = (os.environ.get("RECUPERO_RELEASE") or "").strip() or None
    if release is None:
        try:
            from recupero import __version__
            release = f"recupero@{__version__}"
        except Exception:  # noqa: BLE001
            release = None

    try:
        traces_rate = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0") or 0.0)
    except (ValueError, TypeError):
        traces_rate = 0.0
    # Clamp to [0, 1]; reject NaN. Sentry's SDK will silently disable
    # tracing on bad values, but that hides the misconfiguration —
    # better to log + use a deterministic fallback.
    if not math.isfinite(traces_rate) or traces_rate < 0.0:
        log.warning(
            "SENTRY_TRACES_SAMPLE_RATE=%r is invalid; falling back to 0",
            os.environ.get("SENTRY_TRACES_SAMPLE_RATE"),
        )
        traces_rate = 0.0
    elif traces_rate > 1.0:
        log.warning(
            "SENTRY_TRACES_SAMPLE_RATE=%r > 1.0; clamping to 1.0",
            os.environ.get("SENTRY_TRACES_SAMPLE_RATE"),
        )
        traces_rate = 1.0

    sentry_sdk.init(
        dsn=dsn,
        environment=env_name,
        release=release,
        # Capture INFO+ as breadcrumbs (context only), send WARNING+
        # as events. Tunes the signal/noise to "alert on warnings,
        # explain with breadcrumbs."
        integrations=[
            LoggingIntegration(level=logging.INFO, event_level=logging.WARNING),
        ],
        before_send=_before_send,
        before_breadcrumb=_before_breadcrumb,
        traces_sample_rate=traces_rate,
        # Don't ship the worker's local file paths to Sentry — they
        # change per deploy and add noise.
        send_default_pii=False,
    )
    _sentry_enabled = True
    log.info(
        "Sentry initialized: environment=%s release=%s traces_sample_rate=%s",
        env_name, release, traces_rate,
    )
    return True


def _merge_run_context(event: dict[str, Any]) -> None:
    """Lift run_context fields into Sentry tags + context."""
    try:
        from recupero.logging_setup import current_log_context
    except ImportError:
        return
    ctx = current_log_context()
    if not ctx:
        return
    # Each correlation field becomes a Sentry tag (filterable in the
    # UI) AND lives inside the 'contexts.run' block (richer view).
    tags = event.setdefault("tags", {})
    for k in ("investigation_id", "case_id", "stage", "request_id", "worker_id"):
        v = ctx.get(k)
        if v is None:
            continue
        # Adversarial-input hardening: sanitize CR/LF/NUL/bidi controls
        # and cap length. Without this an attacker-controlled case_id
        # carrying "\n" appears in the Sentry UI as a fake newline,
        # disguising the real source of a captured event.
        tags[k] = _sanitize_tag_value(v)
    contexts = event.setdefault("contexts", {})
    contexts["run"] = dict(ctx)


# Secret redaction — applied to event payload BEFORE Sentry uploads.
# Mirrors the logging filter so DSN passwords / bearer tokens can't
# reach Sentry even if they slipped into a breadcrumb.
def _redact_in_place(obj: Any) -> Any:
    from recupero.logging_setup import _redact  # noqa: PLC0415
    if isinstance(obj, str):
        return _redact(obj)
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            obj[k] = _redact_in_place(v)
        return obj
    if isinstance(obj, list):
        return [_redact_in_place(v) for v in obj]
    return obj


def _before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any] | None:
    """Sentry `before_send` hook: merge context + redact secrets."""
    try:
        _merge_run_context(event)
    except Exception:  # noqa: BLE001
        pass
    try:
        _redact_in_place(event)
    except Exception:  # noqa: BLE001
        pass
    return event


def _before_breadcrumb(
    crumb: dict[str, Any], hint: dict[str, Any],
) -> dict[str, Any] | None:
    """Sentry `before_breadcrumb` hook: redact secrets in breadcrumb msg."""
    try:
        _redact_in_place(crumb)
    except Exception:  # noqa: BLE001
        pass
    return crumb


__all__ = ("init_sentry", "sentry_enabled")
