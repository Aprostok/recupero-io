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


_DEFAULT_HEALTH_PORT = 8080

# Connection-level read timeout (seconds). BaseHTTPRequestHandler exposes
# this as a class attribute; without it slow/partial clients hold the
# worker thread indefinitely (slowloris). 10s is well above any honest
# probe RTT (Railway's healthcheck completes in <500ms) but short enough
# that a stalled socket gets reaped quickly.
_REQUEST_TIMEOUT_SECONDS = 10


def _resolve_health_bind_host() -> str:
    """Wave-9 audit (bind-address): default to loopback so the admin-key
    -gated endpoints (/investigations, /dashboard.json) and the public
    /metrics endpoint aren't exposed on every interface by default.

    Resolution order:
      1. HEALTH_BIND_HOST env (explicit operator override)
      2. ``0.0.0.0`` if PORT is set (Railway/Fly/Heroku style PaaS that
         needs to reach the worker from the platform's edge proxy)
      3. ``127.0.0.1`` otherwise (local dev, tests, on-prem)
    """
    raw = (os.environ.get("HEALTH_BIND_HOST", "") or "").strip()
    if raw:
        return raw
    if (os.environ.get("PORT", "") or "").strip():
        return "0.0.0.0"
    return "127.0.0.1"


def _resolve_health_port() -> int:
    """Wave-9 audit (type-coercion): an operator-supplied ``PORT="foo"``
    used to propagate ``ValueError`` out of ``int()`` and crash worker
    startup before any health checks could run. Treat any non-integer,
    out-of-range, or empty value as the default 8080 so the worker can
    still bind a port (Railway will mark it healthy/unhealthy normally).
    """
    raw = (os.environ.get("PORT", "") or "").strip()
    if not raw:
        return _DEFAULT_HEALTH_PORT
    try:
        n = int(raw)
    except (TypeError, ValueError):
        log.warning(
            "PORT env var is not an integer (%r) — falling back to %d",
            raw, _DEFAULT_HEALTH_PORT,
        )
        return _DEFAULT_HEALTH_PORT
    if n < 1 or n > 65535:
        log.warning(
            "PORT env var %d is outside valid TCP range — "
            "falling back to %d",
            n, _DEFAULT_HEALTH_PORT,
        )
        return _DEFAULT_HEALTH_PORT
    return n


def start_health_server(check_fn: Callable[[], tuple[bool, dict]]) -> ThreadingHTTPServer:
    """Spawn the health server in a daemon thread. Returns the server
    instance so callers can shut it down on graceful exit (the daemon
    flag handles non-graceful exits).

    ``check_fn`` is expected to be a parameterless callable that runs
    the readiness checks and returns ``(ok: bool, details: dict)``.
    """
    port = _resolve_health_port()
    bind_host = _resolve_health_bind_host()

    class _Handler(BaseHTTPRequestHandler):
        # Wave-9 audit: slowloris hardening + info-disclosure scrub.
        # ``timeout`` is honored by BaseHTTPRequestHandler's underlying
        # socket; partial requests are dropped after this many seconds.
        timeout = _REQUEST_TIMEOUT_SECONDS

        def version_string(self) -> str:
            # Suppress the default ``BaseHTTP/x.x Python/x.x.x`` Server
            # header. Knowing the exact Python minor version makes CVE
            # matching trivial; the empty string here yields no Server
            # header at all (BaseHTTPRequestHandler omits it when
            # version_string() returns falsy).
            return ""

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
            elif self.path == "/cron/healthz":
                # v0.32 cron HA (Tier-1 gap #3): per-job health summary
                # for external uptime monitors (Better Uptime, Pingdom).
                # No auth — the payload carries job names + success
                # timestamps but no PII. Status-code conventions:
                #   200  payload.status == "ok"
                #   200  payload.status == "degraded"  (job stale but others ok)
                #   503  payload.status == "down"      (any job >168h, or never succeeded)
                # Monitors typically alarm on non-2xx; "degraded" stays
                # 200 so the alarm only fires on a real outage. Operators
                # who want to alarm on degraded too can hit the payload
                # JSON and parse status.
                try:
                    from recupero.worker.cron_scheduler import (
                        build_cron_healthz_payload,
                    )
                    payload = build_cron_healthz_payload()
                except Exception as e:  # noqa: BLE001
                    self._respond(
                        503,
                        {"status": "down", "error": f"healthz failed: {e}"},
                        write_body=write_body,
                    )
                    return
                code = 503 if payload.get("status") == "down" else 200
                self._respond(code, payload, write_body=write_body)
            elif self.path == "/metrics":
                # v0.17.0 (observability OBS-4): Prometheus text-format
                # metrics. Public — operators expect /metrics to be
                # scrapable without auth (it's the Prometheus convention
                # and the payload carries no PII, just operational
                # counters). Lock down at the network layer if needed
                # (Railway internal-only routing).
                self._serve_metrics(write_body=write_body)
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
                # Aggregated counters for the admin-UI homepage. Same
                # admin-key gate as /investigations* (v0.16.6 audit r8a
                # CRITICAL): the payload exposes case counts, totals,
                # and recent-error labels — operator-internal, not for
                # public eyes.
                import hmac
                import os as _os
                expected = _os.environ.get(
                    "RECUPERO_ADMIN_KEY", "",
                ).strip()
                if not expected:
                    self._respond(
                        503,
                        {"error": "admin endpoint disabled "
                                  "(set RECUPERO_ADMIN_KEY to enable)"},
                        write_body=write_body,
                    )
                    return
                supplied = self.headers.get(
                    "X-Recupero-Admin-Key", "",
                ).strip()
                if not supplied or not hmac.compare_digest(
                    supplied, expected,
                ):
                    self._respond(
                        401,
                        {"error": "missing or invalid X-Recupero-Admin-Key"},
                        write_body=write_body,
                    )
                    return
                try:
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
            import hmac
            import os as _os
            from urllib.parse import parse_qs, urlsplit
            from uuid import UUID

            # v0.16.6 (audit r8a CRITICAL): require an admin shared
            # secret on /investigations* and /dashboard.json. Pre-fix
            # these endpoints exposed full case PII (victim wallet,
            # email, signed-URL artifact links) to anyone who could
            # reach the worker port. The admin UI now sends
            # `X-Recupero-Admin-Key` on every request; the secret is
            # also accepted as a `?admin_key=` query param for local
            # curl-based debugging. If RECUPERO_ADMIN_KEY is unset,
            # the endpoint denies everything (fail-closed) so a
            # mis-configured deploy can't accidentally leak PII.
            expected_admin_key = _os.environ.get(
                "RECUPERO_ADMIN_KEY", ""
            ).strip()
            if not expected_admin_key:
                self._respond(
                    503,
                    {"error": "admin endpoint disabled "
                              "(set RECUPERO_ADMIN_KEY env var to enable)"},
                    write_body=write_body,
                )
                return
            # v0.16.7 (round-9 worker-resilience CRIT): admin key is HEADER ONLY.
            # Pre-v0.16.7 accepted `?admin_key=...` as a fallback "for curl
            # convenience" — but query strings are routinely logged by Railway's
            # edge, intermediate proxies, and downstream services, and they
            # leak via browser Referer headers. A single Railway log dump
            # exposed for support would expose the long-lived admin secret.
            # Header-only forces operators to use proper request tooling and
            # keeps the secret out of every URL-aware log line.
            header_key = self.headers.get(
                "X-Recupero-Admin-Key", ""
            ).strip()
            parsed = urlsplit(self.path)
            qs_pre = parse_qs(parsed.query)
            if not header_key or not hmac.compare_digest(
                header_key, expected_admin_key,
            ):
                self._respond(
                    401,
                    {"error": (
                        "missing or invalid X-Recupero-Admin-Key header "
                        "(query-param auth removed in v0.16.7)"
                    )},
                    write_body=write_body,
                )
                return

            path = parsed.path.rstrip("/")
            qs = qs_pre
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
            except Exception:  # noqa: BLE001
                # Return 500 so Stripe retries — this is almost
                # certainly a transient DB blip given the dispatcher
                # is pure SQL.
                #
                # v0.19.1 (round-12 sec-HIGH-2): generic detail on the
                # wire. Pre-v0.19.1 we echoed `f"dispatch failed: {exc}"`
                # to Stripe's webhook response body, and psycopg's
                # OperationalError messages routinely embed the full
                # DSN with password ("FATAL: password authentication
                # failed for user 'postgres' at host 'aws-1-us-east-1
                # .pooler.supabase.com:6543'"). Any operator with view
                # access to the Stripe Dashboard webhook log saw the
                # DB creds verbatim. This mirrors the v0.18.2 fix to
                # the API's /v1/correlations endpoint.
                log.exception("stripe webhook dispatch failed")
                self._respond(500, {"error": "dispatch failed"})
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
            payload = json.dumps(body, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if write_body:
                self.wfile.write(payload)

        def _serve_metrics(self, *, write_body: bool) -> None:
            """Prometheus text-format render. Always returns 200, even
            with an empty registry (Prometheus accepts that and just
            logs no samples)."""
            try:
                from recupero.observability.metrics import metrics_endpoint_text
                body = metrics_endpoint_text().encode("utf-8")
            except Exception as e:  # noqa: BLE001
                body = f"# metrics renderer failed: {e}\n".encode()
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "text/plain; version=0.0.4; charset=utf-8",
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if write_body:
                self.wfile.write(body)

        # Silence the default per-request stderr line so Railway logs
        # aren't dominated by healthcheck traffic.
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer((bind_host, port), _Handler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="health-server",
        daemon=True,
    )
    thread.start()
    log.info(
        "health server listening on %s:%d (/health, /healthz)",
        bind_host, port,
    )
    return server
