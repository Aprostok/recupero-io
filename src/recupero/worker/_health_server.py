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
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

        def do_POST(self) -> None:  # noqa: N802
            # Two POST routes today: portal sign + Stripe webhook.
            # Everything else stays GET-only.
            if self.path.startswith("/portal"):
                self._handle_portal(method="POST")
            elif self.path == "/webhooks/stripe":
                self._handle_stripe_webhook()
            else:
                self._respond(405, {"error": "method not allowed"})

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
                    import os as _os

                    from recupero.worker.dashboard_summary import (
                        build_dashboard_summary,
                    )
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
            elif self.path.startswith("/portal"):
                # Token-gated customer portal — token in URL grants
                # read access to case state + artifact downloads and
                # write access to the engagement-signature form.
                # Delegates to recupero.portal.server.handle_portal,
                # which returns the full (code, body, headers) tuple.
                self._handle_portal(method="GET", write_body=write_body)
            else:
                self._respond(404, {"error": "not found"}, write_body=write_body)

        def _handle_investigations(self, *, write_body: bool) -> None:
            import os as _os
            from urllib.parse import parse_qs, urlsplit
            from uuid import UUID

            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/")
            qs = parse_qs(parsed.query)
            dsn = _os.environ.get("SUPABASE_DB_URL", "")
            sb_url = _os.environ.get("SUPABASE_URL", "").rstrip("/")
            sb_key = _os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
            try:
                from recupero.worker.investigations_api import (
                    get_investigation_detail,
                    list_investigations,
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
            # latest_only defaults to True (single brief per issuer).
            # Pass latest_only=false in the query string to get the
            # full historical listing (audit-trail use case).
            latest_only_raw = (qs.get("latest_only") or ["true"])[0].lower()
            latest_only = latest_only_raw not in ("false", "0", "no")
            try:
                payload = get_investigation_detail(
                    dsn=dsn, supabase_url=sb_url, service_role_key=sb_key,
                    investigation_id=inv_id,
                    latest_only=latest_only,
                )
                if payload is None:
                    self._respond(404, {"error": "investigation not found"},
                                  write_body=write_body)
                    return
                self._respond(200, payload, write_body=write_body)
            except Exception as e:  # noqa: BLE001
                self._respond(500, {"error": str(e)},
                              write_body=write_body)

        def _handle_portal(self, *, method: str, write_body: bool = True) -> None:
            """Delegate ``/portal/...`` requests to recupero.portal.server.

            For GETs the dispatcher returns ``(code, body, headers)`` and
            we mirror them onto the response. For POSTs we read the
            request body up to a small cap (the form payload is tiny —
            just a name + checkbox).
            """
            try:
                from recupero.portal.server import handle_portal
            except Exception as e:  # noqa: BLE001
                self._respond(500, {"error": f"portal import failed: {e}"},
                              write_body=write_body)
                return

            body_bytes = b""
            if method == "POST":
                # Cap the body at 64KB — the signature form is < 1KB.
                # Anything bigger is an abuse attempt; reject loudly.
                try:
                    content_length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    content_length = 0
                if content_length > 65536:
                    self._respond(413, {"error": "request too large"},
                                  write_body=write_body)
                    return
                if content_length > 0:
                    body_bytes = self.rfile.read(content_length)

            # Lowercase header keys for the portal handler — it uses
            # ``headers.get("x-forwarded-for", ...)`` etc.
            hdrs = {k.lower(): v for k, v in self.headers.items()}

            try:
                code, resp_body, extra = handle_portal(
                    method=method,
                    path=self.path,
                    body_bytes=body_bytes,
                    headers=hdrs,
                )
            except Exception as e:  # noqa: BLE001
                # Last-resort guard so a portal bug can't take the
                # whole health server down with an uncaught.
                log.exception("portal handler crashed: %s", e)
                self._respond(500, {"error": "portal error"},
                              write_body=write_body)
                return

            # Stream back the response. The portal returns text/html
            # most of the time; for redirects (artifact downloads) we
            # set Location and send a zero-length body.
            self.send_response(code)
            ctype = extra.pop("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(resp_body)))
            for hk, hv in extra.items():
                self.send_header(hk, hv)
            self.end_headers()
            if write_body and resp_body:
                self.wfile.write(resp_body)

        def _handle_stripe_webhook(self) -> None:
            """POST /webhooks/stripe — Stripe payment events.

            Flow:
              1. Read the raw body (capped at 256KB; real events
                 are ~5-15KB).
              2. Verify HMAC signature against STRIPE_WEBHOOK_SECRET.
                 Bad signature → 400 (Stripe will NOT retry these).
              3. Hand the parsed event to the dispatcher, which
                 inserts into public.payments + applies workflow
                 side effects.
              4. Return 200 with a JSON body describing what
                 happened (operator visibility from the Stripe
                 dashboard's webhook log).

            Errors:
              * 400 — signature failure (don't retry; caller fixes)
              * 500 — dispatcher exception (DO retry; transient)
              * 503 — STRIPE_WEBHOOK_SECRET unset (config error)
            """
            try:
                from recupero.payments.dispatcher import dispatch
                from recupero.payments.webhook import (
                    WebhookVerifyError,
                    get_webhook_secret,
                    verify_and_parse,
                )
            except Exception as e:  # noqa: BLE001
                self._respond(500, {"error": f"payments import failed: {e}"})
                return

            secret = get_webhook_secret()
            if not secret:
                log.warning("/webhooks/stripe hit but STRIPE_WEBHOOK_SECRET unset")
                self._respond(503, {"error": "webhook secret not configured"})
                return

            # Body cap. Stripe events are tiny; anything larger is
            # an abuse attempt + bypasses signature verification.
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0
            if content_length > 262144:  # 256KB
                self._respond(413, {"error": "request too large"})
                return
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b""

            sig_header = self.headers.get("Stripe-Signature")
            try:
                event = verify_and_parse(
                    body_bytes=body_bytes,
                    signature_header=sig_header,
                    webhook_secret=secret,
                )
            except WebhookVerifyError as exc:
                log.warning("stripe webhook verify failed: %s", exc)
                self._respond(400, {"error": f"verify failed: {exc}"})
                return

            import os as _os
            dsn = _os.environ.get("SUPABASE_DB_URL", "").strip()
            if not dsn:
                self._respond(503, {"error": "DB not configured"})
                return

            try:
                result = dispatch(event=event, dsn=dsn)
            except Exception as exc:  # noqa: BLE001
                # Return 500 so Stripe retries — this is almost
                # certainly a transient DB blip given the dispatcher
                # is pure SQL.
                log.exception("stripe webhook dispatch failed: %s", exc)
                self._respond(500, {"error": f"dispatch failed: {exc}"})
                return

            self._respond(200, {
                "duplicate": result.duplicate,
                "action": result.action,
                "payment_id": result.payment_id,
                "case_id": result.case_id,
                "investigation_id": result.investigation_id,
                "notes": result.notes,
            })

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
