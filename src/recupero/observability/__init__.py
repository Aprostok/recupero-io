"""Observability surface: Sentry integration + Prometheus metrics.

Both subsystems are OPT-IN — Recupero runs cleanly without either,
falling back to the JSON-formatted log stream (logging_setup.py)
for everything operators need. The wiring here just gives ops teams
who want Sentry + Prometheus the standard hooks they expect.

Enable via:
  * SENTRY_DSN              — turn on Sentry event capture
  * RECUPERO_METRICS_PORT   — turn on /metrics HTTP listener
"""

from __future__ import annotations

from recupero.observability.metrics import (
    METRICS,
    metrics_endpoint_text,
    record_claim,
    record_stage_duration,
    start_metrics_server,
)
from recupero.observability.sentry import init_sentry, sentry_enabled

__all__ = (
    "init_sentry",
    "sentry_enabled",
    "METRICS",
    "metrics_endpoint_text",
    "record_claim",
    "record_stage_duration",
    "start_metrics_server",
)
