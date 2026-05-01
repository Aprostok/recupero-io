"""Tiny HTTP healthcheck server, run alongside the worker's polling loop.

Railway's health monitoring is HTTP-based: configure ``healthcheckPath`` in
railway.json and Railway will poll that path; 2xx = healthy, anything else
= unhealthy. For a queue-only worker with no public HTTP traffic, this is
purely for ops visibility — the dashboard shows "Healthy" / "Unhealthy"
based on whether the worker can reach Supabase.

Two endpoints:

  GET /healthz    Liveness — 200 as long as the worker process is up.
                  Cheap, no I/O. Use for "is it running?" checks.

  GET /health     Readiness — runs the same DB + bucket reachability
                  checks as ``recupero-worker --health-check``.
                  Returns 503 if any check fails. ~100–300ms per request.

The server runs in a daemon thread (so it dies with the parent process)
on the port given by ``$PORT`` (Railway sets this) or 8080 by default.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

log = logging.getLogger(__name__)


def start_health_server(check_fn: Callable[[], tuple[bool, dict]]) -> ThreadingHTTPServer:
    """Spawn the health server in a daemon thread. Returns the server
    instance so callers can shut it down on graceful exit (the daemon
    flag handles non-graceful exits).

    ``check_fn`` is expected to be a parameterless callable that runs
    the readiness checks and returns ``(ok: bool, details: dict)``.
    """
    port = int(os.environ.get("PORT", "8080"))

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            if self.path == "/healthz":
                self._respond(200, {"alive": True})
            elif self.path in ("/health", "/"):
                try:
                    ok, details = check_fn()
                except Exception as e:  # noqa: BLE001
                    self._respond(503, {"ok": False, "error": str(e)})
                    return
                self._respond(200 if ok else 503, {"ok": ok, "checks": details})
            else:
                self._respond(404, {"error": "not found"})

        def _respond(self, code: int, body: dict) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        # Silence the default per-request stderr line so Railway logs
        # aren't dominated by healthcheck traffic.
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="health-server",
        daemon=True,
    )
    thread.start()
    log.info("health server listening on :%d (/health, /healthz)", port)
    return server
