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
            self._serve(write_body=True)

        def do_HEAD(self) -> None:  # noqa: N802
            # External monitors (UptimeRobot's free tier, Cloudflare
            # health checks, etc.) often use HEAD by default. Without
            # this, BaseHTTPRequestHandler returns 501 Not Implemented
            # and the monitor sees the worker as down even though it's
            # healthy. Same status code logic as GET, no response body.
            self._serve(write_body=False)

        def _serve(self, *, write_body: bool) -> None:
            if self.path == "/healthz":
                self._respond(200, {"alive": True}, write_body=write_body)
            elif self.path in ("/health", "/"):
                try:
                    ok, details = check_fn()
                except Exception as e:  # noqa: BLE001
                    self._respond(503, {"ok": False, "error": str(e)}, write_body=write_body)
                    return
                self._respond(
                    200 if ok else 503,
                    {"ok": ok, "checks": details},
                    write_body=write_body,
                )
            elif self.path == "/dashboard.json":
                # Aggregated counters for the admin-UI homepage.
                # Cached on demand — no in-process cache layer
                # because the queries are cheap (<200ms typically)
                # and the UI polls at 60s+, so cache hit rate is
                # marginal. Add a TTL cache here if traffic warrants.
                try:
                    from recupero.worker.dashboard_summary import (
                        build_dashboard_summary,
                    )
                    import os as _os
                    dsn = _os.environ.get("SUPABASE_DB_URL", "")
                    payload = build_dashboard_summary(dsn=dsn)
                    self._respond(200, payload, write_body=write_body)
                except Exception as e:  # noqa: BLE001
                    self._respond(
                        500, {"error": str(e)}, write_body=write_body,
                    )
            elif self.path.startswith("/investigations"):
                # Investigation list + detail endpoints backing the
                # admin UI's wallet-trace and case-driven views.
                # Routes:
                #   GET /investigations?status=...&chain=...&type=wallet_trace
                #                       &label_prefix=...&limit=N&offset=N
                #   GET /investigations/<uuid>
                self._handle_investigations(write_body=write_body)
            else:
                self._respond(404, {"error": "not found"}, write_body=write_body)

        def _handle_investigations(self, *, write_body: bool) -> None:
            import os as _os
            from urllib.parse import urlsplit, parse_qs
            from uuid import UUID

            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/")
            qs = parse_qs(parsed.query)
            dsn = _os.environ.get("SUPABASE_DB_URL", "")
            sb_url = _os.environ.get("SUPABASE_URL", "").rstrip("/")
            sb_key = _os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
            try:
                from recupero.worker.investigations_api import (
                    list_investigations, get_investigation_detail,
                )
            except Exception as e:  # noqa: BLE001
                self._respond(500, {"error": f"import failed: {e}"},
                              write_body=write_body)
                return

            # /investigations (list) — path is exactly "/investigations".
            if path == "/investigations":
                try:
                    payload = list_investigations(
                        dsn=dsn,
                        status=(qs.get("status") or [None])[0],
                        chain=(qs.get("chain") or [None])[0],
                        investigation_type=(qs.get("type") or [None])[0],
                        label_prefix=(qs.get("label_prefix") or [None])[0],
                        limit=int((qs.get("limit") or ["25"])[0]),
                        offset=int((qs.get("offset") or ["0"])[0]),
                    )
                    self._respond(200, payload, write_body=write_body)
                except ValueError as e:
                    self._respond(400, {"error": f"bad query: {e}"},
                                  write_body=write_body)
                except Exception as e:  # noqa: BLE001
                    self._respond(500, {"error": str(e)},
                                  write_body=write_body)
                return

            # /investigations/<uuid> (detail). Anything else under the
            # /investigations/ prefix is a 404.
            rest = path[len("/investigations/"):] if path.startswith("/investigations/") else ""
            if not rest or "/" in rest:
                self._respond(404, {"error": "not found"},
                              write_body=write_body)
                return
            try:
                inv_id = UUID(rest)
            except ValueError:
                self._respond(400, {"error": "id must be a UUID"},
                              write_body=write_body)
                return
            try:
                payload = get_investigation_detail(
                    dsn=dsn, supabase_url=sb_url, service_role_key=sb_key,
                    investigation_id=inv_id,
                )
                if payload is None:
                    self._respond(404, {"error": "investigation not found"},
                                  write_body=write_body)
                    return
                self._respond(200, payload, write_body=write_body)
            except Exception as e:  # noqa: BLE001
                self._respond(500, {"error": str(e)},
                              write_body=write_body)

        def _respond(self, code: int, body: dict, *, write_body: bool = True) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if write_body:
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
