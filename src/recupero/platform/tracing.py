"""OpenTelemetry tracing for the API — opt-in and dependency-optional.

Enabled only when ``RECUPERO_OTEL_ENABLED`` is truthy AND the OpenTelemetry
packages are installed (``pip install .[otel]``). Otherwise ``init_tracing`` is a
no-op that returns False and NEVER raises — so the base install carries no
opentelemetry dependency and an unconfigured deploy is unaffected.

When enabled it instruments the FastAPI app (auto spans per request, with the
`/v2` route templates) and exports OTLP/HTTP to the collector at
``OTEL_EXPORTER_OTLP_ENDPOINT`` (the standard OTel env var). Service name comes
from ``RECUPERO_OTEL_SERVICE_NAME`` (default ``recupero-api``).
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)


def _enabled() -> bool:
    return (os.environ.get("RECUPERO_OTEL_ENABLED") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def init_tracing(app: Any) -> bool:
    """Instrument ``app`` with OpenTelemetry if enabled + installed. Returns True
    when instrumentation was applied, False otherwise. Never raises."""
    if not _enabled():
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # noqa: BLE001 — optional dependency absent
        log.warning("otel: RECUPERO_OTEL_ENABLED set but packages missing (%s); "
                    "tracing disabled. Install with `pip install .[otel]`.", exc)
        return False
    try:
        service = os.environ.get("RECUPERO_OTEL_SERVICE_NAME", "recupero-api")
        provider = TracerProvider(resource=Resource.create({"service.name": service}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        log.info("otel: tracing enabled (service=%s)", service)
        return True
    except Exception as exc:  # noqa: BLE001 — never let telemetry break boot
        log.warning("otel: instrumentation failed (%s); tracing disabled", exc)
        return False


__all__ = ("init_tracing",)
