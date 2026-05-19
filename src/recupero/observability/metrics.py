"""Prometheus metrics — minimal in-process registry.

Why not just `prometheus_client`? Two reasons:

  1. Recupero's worker runs in a single Python process; we don't need
     cross-process aggregation, so a thin in-memory registry with a
     text-format renderer is enough.
  2. Keeping the runtime dependency-free (no `prometheus_client` install)
     means `pip install -e .` stays lean.

The metrics this module exposes match what an SRE actually wants to
see for a forensic-trace pipeline:

  Counters:
    * recupero_claims_total{outcome="ok"|"fail"|"empty"}
    * recupero_stage_runs_total{stage, outcome}
    * recupero_freeze_letters_sent_total{issuer}
    * recupero_alerts_fired_total{trigger_type}

  Histograms:
    * recupero_stage_duration_seconds{stage}
    * recupero_trace_transfers_count
    * recupero_brief_render_seconds

Render at `/metrics` via the worker's existing health server when
`RECUPERO_METRICS_PORT` is set (or, more commonly, the health server
serves /metrics on its own port when configured to do so).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

log = logging.getLogger(__name__)


# Histogram bucket bounds (seconds). Chosen for a forensic-trace workload:
# typical stages run 1-30s; outliers run 60-300s; nothing should exceed
# the 9-min trace timeout enforced in v0.16.11.
_DEFAULT_BUCKETS_SEC = (
    0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
)


class _Counter:
    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help_text = help_text
        self._lock = threading.Lock()
        # labels_tuple → count
        self._values: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            self._values[key] += amount

    def snapshot(self) -> dict[tuple[tuple[str, str], ...], float]:
        with self._lock:
            return dict(self._values)


class _Histogram:
    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = _DEFAULT_BUCKETS_SEC,
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.buckets = buckets
        self._lock = threading.Lock()
        # labels → (bucket_counts, sum, count)
        self._data: dict[
            tuple[tuple[str, str], ...],
            tuple[list[int], float, int],
        ] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            if key not in self._data:
                self._data[key] = ([0] * len(self.buckets), 0.0, 0)
            counts, total, count = self._data[key]
            for i, b in enumerate(self.buckets):
                if value <= b:
                    counts[i] += 1
            self._data[key] = (counts, total + value, count + 1)

    def snapshot(
        self,
    ) -> dict[tuple[tuple[str, str], ...], tuple[list[int], float, int]]:
        with self._lock:
            # Deep-copy the counts list so callers can iterate safely.
            return {k: (list(c), s, n) for k, (c, s, n) in self._data.items()}


# --- Singleton registry ---

class _MetricsRegistry:
    """All metric handles live here. Singleton because we render the
    full registry at /metrics on any operator request."""

    def __init__(self) -> None:
        self.claims_total = _Counter(
            "recupero_claims_total",
            "Number of investigation claim attempts by outcome.",
        )
        self.stage_runs_total = _Counter(
            "recupero_stage_runs_total",
            "Number of stage executions by stage name and outcome.",
        )
        self.freeze_letters_total = _Counter(
            "recupero_freeze_letters_sent_total",
            "Number of freeze letters dispatched, by issuer.",
        )
        self.alerts_fired_total = _Counter(
            "recupero_alerts_fired_total",
            "Number of monitoring alerts fired, by trigger type.",
        )
        self.stage_duration = _Histogram(
            "recupero_stage_duration_seconds",
            "Time spent in each pipeline stage.",
        )
        self.trace_transfers = _Histogram(
            "recupero_trace_transfers_count",
            "Number of transfers in each completed trace.",
            buckets=(10, 50, 200, 1000, 5000, 20_000, 50_000),
        )
        self.brief_render = _Histogram(
            "recupero_brief_render_seconds",
            "Time spent generating brief HTML + manifest.",
        )


METRICS = _MetricsRegistry()


# --- Convenience helpers used by callers ---


def record_claim(outcome: str) -> None:
    """`outcome` ∈ {ok, fail, empty}."""
    METRICS.claims_total.inc(outcome=outcome)


def record_stage_duration(stage: str, seconds: float, outcome: str = "ok") -> None:
    METRICS.stage_runs_total.inc(stage=stage, outcome=outcome)
    METRICS.stage_duration.observe(seconds, stage=stage)


# --- Text-format renderer ---

def metrics_endpoint_text() -> str:
    """Render the current registry as Prometheus exposition format.

    Format reference:
    https://prometheus.io/docs/instrumenting/exposition_formats/

    Output is plain-text; the HTTP handler should set
    Content-Type: text/plain; version=0.0.4
    """
    lines: list[str] = []

    def _fmt_labels(labels: tuple[tuple[str, str], ...]) -> str:
        if not labels:
            return ""
        inner = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
        return "{" + inner + "}"

    def _escape(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    # Counters
    for counter in (
        METRICS.claims_total, METRICS.stage_runs_total,
        METRICS.freeze_letters_total, METRICS.alerts_fired_total,
    ):
        snap = counter.snapshot()
        if not snap:
            continue
        lines.append(f"# HELP {counter.name} {counter.help_text}")
        lines.append(f"# TYPE {counter.name} counter")
        for labels, value in sorted(snap.items()):
            lines.append(f"{counter.name}{_fmt_labels(labels)} {value}")

    # Histograms
    for hist in (
        METRICS.stage_duration, METRICS.trace_transfers, METRICS.brief_render,
    ):
        snap = hist.snapshot()
        if not snap:
            continue
        lines.append(f"# HELP {hist.name} {hist.help_text}")
        lines.append(f"# TYPE {hist.name} histogram")
        for labels, (counts, total, count) in sorted(snap.items()):
            for i, b in enumerate(hist.buckets):
                # Bucket labels carry the histogram's labels PLUS le=<bound>.
                bucket_labels = labels + (("le", str(b)),)
                lines.append(
                    f"{hist.name}_bucket{_fmt_labels(bucket_labels)} {counts[i]}"
                )
            inf_labels = labels + (("le", "+Inf"),)
            lines.append(f"{hist.name}_bucket{_fmt_labels(inf_labels)} {count}")
            lines.append(f"{hist.name}_sum{_fmt_labels(labels)} {total}")
            lines.append(f"{hist.name}_count{_fmt_labels(labels)} {count}")

    if not lines:
        lines.append("# No metrics recorded yet")
    return "\n".join(lines) + "\n"


def start_metrics_server(port: int) -> None:
    """Spin up a tiny stdlib HTTP server serving /metrics on ``port``.

    Background-threaded; never blocks the caller. Re-exports the
    current METRICS registry on every request via the
    metrics_endpoint_text renderer.

    Optional — most deployments will piggyback on the worker's
    existing health-port handler (see worker/_health_server.py) by
    adding a /metrics route. This standalone server exists for
    operators who want metrics on a separate port for
    network-isolation reasons.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = metrics_endpoint_text().encode("utf-8")
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any, **kwargs: Any) -> None:
            # Suppress the default BaseHTTPRequestHandler stderr noise;
            # we have our own logger.
            pass

    server = HTTPServer(("0.0.0.0", port), _Handler)  # noqa: S104
    log.info("metrics server listening on :%d/metrics", port)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True,
        name=f"metrics-:{port}",
    )
    thread.start()


__all__ = (
    "METRICS",
    "record_claim",
    "record_stage_duration",
    "metrics_endpoint_text",
    "start_metrics_server",
)


# Suppress "unused import" warning — `time` is needed for callers that
# import it via `from observability.metrics import time` (none today).
_ = time
