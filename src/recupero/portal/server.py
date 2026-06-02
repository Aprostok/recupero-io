"""HTTP handler for the token-gated customer portal.

Mounted at ``/portal`` by the worker's _health_server.py. Routes:

    GET  /portal/<token>
        Status landing page. Shows case info, engagement state,
        and a list of downloadable artifacts.

    GET  /portal/<token>/artifact/<artifact_key>
        Issues a short-lived signed URL for one specific artifact
        and 302-redirects there. The signed URL is single-use-ish
        (TTL 5 minutes) so the portal token itself doesn't leak
        long-lived storage access.

    GET  /portal/<token>/sign
        Engagement-letter signing form. Pre-rendered with the
        current quoted fee and case info.

    POST /portal/<token>/sign
        Process the signature submission. On success:
          * INSERT into engagement_signatures
          * UPDATE investigations.engagement_started_at = NOW()
            and engagement_fee_paid_usd
          * Render the "you're engaged" confirmation page.

The handler doesn't do its own HTTP plumbing — it's called by
_health_server.py's request loop, which passes in the path,
method, body, and headers and gets back ``(status_code, body,
extra_headers)``.

Why this shape (not Flask/Starlette)?
The worker already has a stdlib BaseHTTPRequestHandler running on
the Railway PORT for healthchecks + dashboard.json. Adding Flask
would mean bundling a second runtime + WSGI adapter for a handful
of routes. The stdlib handler is fine for the portal's traffic
profile (one victim per case, occasional access). If we ever
front this with a load balancer + need real concurrency, we'll
swap in Starlette/uvicorn as part of a separate-deploy refactor.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import secrets
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from recupero.portal.tokens import VerifiedToken, verify_token

log = logging.getLogger(__name__)

# v0.18.2 (round-11 api-CRIT-003): once-per-process warning flag so
# the prod-misconfig ERROR fires once rather than on every request.
_IP_MISCONFIG_WARNED = False


def _set_ip_misconfig_warned() -> None:
    global _IP_MISCONFIG_WARNED
    _IP_MISCONFIG_WARNED = True


def _extract_client_ip(headers: dict[str, str]) -> str:
    """Return the client IP we'll persist alongside an engagement signature.

    X-Forwarded-For is client-controlled: any visitor can put whatever
    they want in the header, so trusting it unconditionally produces a
    forensics-grade record of attacker-supplied lies. The prior code
    read XFF first, no questions asked, meaning the IP column in
    engagement_signatures was effectively user input.

    Mitigation:

    * If ``RECUPERO_TRUSTED_PROXY_HOPS`` is set (an integer N), trust
      only the right-most N hops of XFF — those are the addresses
      inserted by our own proxy layer (Railway / Fly load balancer /
      Cloudflare in front of the worker). Walk leftward from the end
      and return the last entry the trusted layer added.

    * If the env var is unset (default), DO NOT trust XFF at all.
      Fall back to ``x-real-ip`` (which Railway and Fly set themselves
      after stripping XFF) and finally to the empty string. This is
      the safe default for first-deploy / unknown infrastructure.

    The change is intentionally minimal: callers still get a string,
    and storage still happens. We've just stopped trusting whatever
    the client typed.
    """
    raw_xff = headers.get("x-forwarded-for", "") or ""
    xff_chain = [p.strip() for p in raw_xff.split(",") if p.strip()]
    try:
        trusted_hops = int(os.environ.get("RECUPERO_TRUSTED_PROXY_HOPS", "0"))
    except (TypeError, ValueError):
        trusted_hops = 0

    # v0.18.2 (round-11 api-CRIT-003): in production, RECUPERO_TRUSTED_PROXY_HOPS
    # MUST be set. Railway/Fly always sit behind a proxy; if the
    # operator forgot to set the env var, this function silently
    # returned "" for EVERY engagement signature — the legal-defensibility
    # claim on /sign ("Your IP address will be recorded for audit
    # purposes") became a misrepresentation. We now log a one-time
    # ERROR per process when trusted_hops=0 in a detected production
    # environment so the misconfig surfaces.
    if trusted_hops <= 0:
        try:
            from recupero.api.auth import _is_production_environment
            if _is_production_environment() and not _IP_MISCONFIG_WARNED:
                log.error(
                    "portal: RECUPERO_TRUSTED_PROXY_HOPS is unset in a "
                    "PRODUCTION environment — engagement signatures will "
                    "land with ip_address=NULL, breaking the legal-"
                    "defensibility audit trail claimed on /sign. Set "
                    "the env var to the number of proxy hops between "
                    "the client and the worker (Railway = 1; Cloudflare "
                    "+ Railway = 2)."
                )
                _set_ip_misconfig_warned()
        except Exception:  # noqa: BLE001
            pass  # detection failure shouldn't break the signature flow

    candidate: str | None = None
    if trusted_hops > 0 and xff_chain:
        # The right-most entry was added by the load balancer closest
        # to us; walk N hops back from the tail. If the chain is shorter
        # than N hops, the deployment is mis-configured — take the
        # left-most entry (still inside the trusted segment) rather
        # than fabricate trust.
        idx = max(0, len(xff_chain) - trusted_hops)
        candidate = xff_chain[idx]
    if candidate is None:
        # x-real-ip is set by Railway/Fly's edge AFTER stripping the
        # client-supplied XFF, so it's somewhat more trustworthy — but
        # it's still a raw HTTP header value. v0.16.7 (round-9 security
        # audit HIGH): validate as a real IP address before storing.
        # Pre-v0.16.7 we accepted arbitrary strings, enabling
        # log-injection (`X-Real-IP: 127.0.0.1\r\nfake-line`) into the
        # engagement_signatures table.
        real_ip = (headers.get("x-real-ip", "") or "").strip()
        if real_ip:
            candidate = real_ip
    if candidate is None:
        return ""
    # Validate. ipaddress.ip_address accepts v4 and v6 and rejects
    # garbage; trim to 45 chars (max length of an IPv6 string with
    # zone-id). Anything that doesn't parse → store empty rather than
    # let a forged value into the audit log.
    try:
        return str(ipaddress.ip_address(candidate))[:45]
    except (ValueError, TypeError):
        log.warning("portal: rejecting non-IP client-address header value")
        return ""


# Headers that protect against UA-string log injection and clickjacking.
# Returned on every portal response (HTML + redirects + errors). v0.16.7
# (round-9 security audit MEDIUM/HIGH).
_PORTAL_SECURITY_HEADERS: dict[str, str] = {
    # The bearer token is in the URL path → without no-referrer, every
    # outbound click leaks the token via Referer. This is the single
    # most impactful header for the portal.
    "Referrer-Policy": "no-referrer",
    # Clickjacking defense — the /sign form must not be iframed.
    "X-Frame-Options": "DENY",
    # MIME sniffing defense.
    "X-Content-Type-Options": "nosniff",
    # Defense-in-depth CSP. Portal pages use only inline CSS and no
    # external resources; the strict policy here blocks any future
    # accidental introduction of third-party JS.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "script-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    # HSTS — assume HTTPS in front of the worker (Railway always is).
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Permissions-Policy — disable powerful browser APIs that the portal
    # never legitimately uses. Defense-in-depth against a future XSS
    # bypass: even if attacker JS lands on the page, it cannot prompt
    # for camera/mic/geolocation, trigger Payment Request, or read
    # USB/serial. Portal pages are pure HTML+inline CSS today; none
    # of these features are needed.
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), "
        "usb=(), serial=(), bluetooth=(), accelerometer=(), "
        "gyroscope=(), magnetometer=(), interest-cohort=()"
    ),
    # RIGOR-Jacob Z16-1: no-store on every portal HTML/redirect/error
    # response. The bearer token is in the URL path → without
    # Cache-Control: no-store, any shared HTTP cache (CDN, corporate
    # proxy, ISP web cache) sitting in front of the worker can pin
    # the rendered PII page (case_number, client_name, client_email,
    # estimated_value_usd, signature_name on the post-sign page)
    # under the token-bearing URL. The artifact 302 already sets
    # this (v0.17.6 round-10 fix); the HTML response paths were
    # missed in that pass. Browser bfcache can also retain the
    # signed.html.j2 PII after token rotation; no-store inhibits
    # bfcache as well.
    "Cache-Control": "private, no-store, max-age=0",
    # Route-authz audit: Vary defense-in-depth for the few intermediate
    # caches (Cloudflare 'Cache Everything' rule, some ISP-grade
    # transparent proxies) that disregard Cache-Control: private/no-store
    # but still honor Vary when building cache keys. Cookie covers
    # any future session/CSRF cookie the portal might add; Authorization
    # covers a future Bearer-header migration. Without Vary, the cache
    # key is URL-only — two distinct browsers visiting the same token
    # URL collide on one cache entry, so one victim's rendered PII can
    # be served to a different visitor whose request was misrouted
    # through the same edge cache.
    "Vary": "Cookie, Authorization",
}


def _strip_control_chars(s: str, *, max_len: int) -> str:
    """Strip CR/LF/control chars and truncate. Used for user-agent
    storage before it lands in engagement_signatures.

    Pre-v0.16.7 the raw UA was stored after a length truncation only —
    a User-Agent like `chrome\\r\\nFAKE-AUDIT-LINE: case approved`
    would survive into operator views and forge a legitimate-looking
    audit entry. Round-9 security audit HIGH.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", s or "")
    return cleaned[:max_len]


# RIGOR-Jacob Z2-1: bidi-override / zero-width / BOM code points that
# spoof how a signature_name renders in operator views. Mirrors
# portal/intake._FORBIDDEN_CHARS. The /sign POST path was missed in
# the v0.25.0 intake-hardening pass.
_SIGNATURE_TROJAN_CHARS = frozenset({
    "‪",  # LEFT-TO-RIGHT EMBEDDING
    "‫",  # RIGHT-TO-LEFT EMBEDDING
    "‬",  # POP DIRECTIONAL FORMATTING
    "‭",  # LEFT-TO-RIGHT OVERRIDE
    "‮",  # RIGHT-TO-LEFT OVERRIDE
    "⁦",  # LEFT-TO-RIGHT ISOLATE
    "⁧",  # RIGHT-TO-LEFT ISOLATE
    "⁨",  # FIRST-STRONG ISOLATE
    "⁩",  # POP DIRECTIONAL ISOLATE
    "​",  # ZERO-WIDTH SPACE
    "‌",  # ZERO-WIDTH NON-JOINER
    "‍",  # ZERO-WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "﻿",  # BOM / ZERO-WIDTH NO-BREAK SPACE
})


def _signature_name_has_trojan(name: str) -> bool:
    """True iff ``name`` contains a bidi-override / zero-width / BOM."""
    return any(ch in _SIGNATURE_TROJAN_CHARS for ch in name)


def _origin_matches_self(headers: dict[str, str]) -> bool:
    """Return True if the request's Origin (or Referer) is our own host.

    Standard CSRF defense for state-changing POSTs in cookieless apps:
    a cross-origin attacker page can submit a form to our URL, but the
    browser will tag it with an Origin header pointing at the attacker.
    We accept the request only when Origin (or Referer if Origin is
    absent) matches the portal's own scheme://host.

    Trust hierarchy (v0.17.6 round-10 security CRIT tightened):
      1. ``RECUPERO_PORTAL_PUBLIC_ORIGIN`` env (operator-pinned
         canonical origin, e.g. ``https://app.recupero.io``). This is
         the ONLY value trusted in production.
      2. Fallback to the inbound ``Host`` header ONLY when the host
         is a localhost shape (``localhost``, ``127.0.0.1``, ``[::1]``,
         optionally with :port). Pre-v0.17.6 we trusted ``Host`` for
         every host — an attacker who could land arbitrary Host
         headers (some misconfigured reverse proxies pass them
         through unmodified) could spoof an Origin match by serving
         a malicious page on a domain that produces a matching
         Host header echo. The localhost-only relaxation closes
         the prod exposure without breaking local-dev `127.0.0.1:8000`
         workflows.
    """
    configured = os.environ.get("RECUPERO_PORTAL_PUBLIC_ORIGIN", "").strip().rstrip("/")
    expected_origins: list[str] = []
    if configured:
        expected_origins.append(configured)

    # v0.17.6: only relax to Host fallback when the host looks like
    # a local-dev address. Production MUST configure the env var.
    host = (headers.get("host", "") or "").strip().lower()
    if host and _is_localhost_host(host):
        expected_origins.extend([f"https://{host}", f"http://{host}"])

    if not expected_origins:
        # No way to know what to compare against. Fail open here would
        # be terrible; fail closed.
        return False

    origin_header = (headers.get("origin", "") or "").strip()
    if origin_header:
        return any(origin_header.rstrip("/") == e for e in expected_origins)

    # Fall back to Referer (some clients omit Origin on same-origin POSTs).
    referer = (headers.get("referer", "") or "").strip()
    if referer:
        try:
            parsed = urlparse(referer)
            base = f"{parsed.scheme}://{parsed.netloc}"
            return any(base == e for e in expected_origins)
        except Exception:  # noqa: BLE001
            return False

    # Neither header present → reject (same as a cross-origin POST in
    # a browser, which is browser-stripped to "null").
    return False


def _is_localhost_host(host: str) -> bool:
    """True iff `host` (lowercased, may include :port) is local-dev.

    Recognized shapes:
      * localhost (any port)
      * 127.0.0.1 / 127.0.0.x for any 0-255 last octet (any port)
      * ::1 / [::1] (any port)
    """
    # Strip optional :port.
    hostname = host.split(":")[0] if not host.startswith("[") else (
        host[1:].split("]")[0]
    )
    if hostname in ("localhost", "::1"):
        return True
    if hostname.startswith("127."):
        parts = hostname.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
    return False


# Jinja env is lazy-built on first request — avoids the import cost
# for healthcheck-only deployments that never hit /portal.
_jinja_env = None


def _get_jinja_env():
    """Lazy-build a Jinja Environment pointing at the templates/
    sibling folder. Autoescape ON (we render user-typed strings)."""
    global _jinja_env
    if _jinja_env is not None:
        return _jinja_env
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    templates_dir = Path(__file__).parent / "templates"
    _jinja_env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "html.j2"]),
        # Keep whitespace tidy on Phase-5 emails-quality bar — the
        # rendered HTML goes to a customer's browser and should look
        # clean if they view-source.
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # XSS defense-in-depth filters — safe_url neuters javascript:
    # URLs that could slip through into href attributes; safe_text
    # strips bidi-override that could spoof identifier display order.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(_jinja_env)
    return _jinja_env


# ----- Route dispatch ----- #


def handle_portal(
    *,
    method: str,
    path: str,
    body_bytes: bytes,
    headers: dict[str, str],
) -> tuple[int, bytes, dict[str, str]]:
    """Top-level entrypoint called by _health_server.

    Parameters
    ----------
    method : ``"GET"`` or ``"POST"``.
    path   : The full request path (e.g., ``/portal/<token>/sign``).
    body_bytes : Request body for POSTs (form-encoded).
    headers : Lowercased-key request headers (the caller does the
              normalization). Used for IP / user-agent capture.

    Returns
    -------
    ``(status_code, body_bytes, extra_headers)`` — extra_headers is
    a flat dict the HTTP server merges onto the response.
    """
    parsed = urllib.parse.urlsplit(path)
    clean_path = parsed.path.rstrip("/")
    # Strip the /portal prefix so we work with the in-portal route.
    if clean_path == "/portal" or clean_path == "":
        return _render_error(404, "missing token in URL")
    if not clean_path.startswith("/portal/"):
        return _render_error(404, "not found")

    rest = clean_path[len("/portal/"):]
    # First segment is always the token.
    segments = rest.split("/")
    token = segments[0]
    sub_path = "/".join(segments[1:]) if len(segments) > 1 else ""

    dsn = _get_dsn()
    if not dsn:
        return _render_error(503, "portal misconfigured (no DSN)")

    verified = verify_token(token=token, dsn=dsn)
    if verified is None:
        return _render_error(404, "link unavailable")

    # Route table — keep it short, each branch handles its own
    # response building so the dispatcher stays a pure router.
    if sub_path == "" and method == "GET":
        return _route_status(token=token, verified=verified, dsn=dsn)
    if sub_path == "graph" and method == "GET":
        return _route_journey(token=token, verified=verified, dsn=dsn)
    if sub_path == "sign" and method == "GET":
        return _route_sign_form(token=token, verified=verified)
    if sub_path == "sign" and method == "POST":
        return _route_sign_submit(
            token=token, verified=verified, body_bytes=body_bytes,
            headers=headers, dsn=dsn,
        )
    if sub_path.startswith("artifact/") and method == "GET":
        # v0.16.8 (round-9 security HIGH): enforce a strict whitelist on
        # the URL-decoded artifact_key BEFORE we hand it to lookup. The
        # dispatcher already checks the key against `_PORTAL_ARTIFACTS`,
        # so an unknown key is harmless — but we also reject control
        # chars / path separators / overlong values up front so any
        # mis-routing further down the chain inherits a clean string.
        artifact_key = sub_path[len("artifact/"):]
        if not artifact_key or "/" in artifact_key or "\\" in artifact_key \
                or ".." in artifact_key or len(artifact_key) > 64:
            return _render_error(404, "not found")
        return _route_artifact(verified=verified, artifact_key=artifact_key)

    return _render_error(404, "not found")


# ----- Routes ----- #


def _route_status(
    *, token: str, verified: VerifiedToken, dsn: str
) -> tuple[int, bytes, dict[str, str]]:
    artifacts = _portal_artifact_list(verified=verified)
    eng_summary = _engagement_dict(verified)
    html = _get_jinja_env().get_template("status.html.j2").render(
        token=token,
        case=_case_dict(verified),
        engagement=eng_summary,
        artifacts=artifacts,
        expires_at=_fmt_dt(verified.expires_at) if verified.expires_at else None,
    )
    return _ok_html(html)


def _route_journey(
    *, token: str, verified: VerifiedToken, dsn: str
) -> tuple[int, bytes, dict[str, str]]:
    """Embedded, client-safe interactive fund-flow map.

    Unlike the operator graph (``reports.graph_ui``), this builds a
    *sanitized* journey projection server-side and hands only that to
    the browser — raw ``case.json`` never leaves the portal process.

    The page runs inline JavaScript (a self-contained vanilla force
    graph — no third-party JS, no CDN). The portal's global CSP is
    ``script-src 'none'``, so this route returns a per-response,
    nonce-scoped CSP that permits ONLY this page's own inline script.
    """
    journey = _load_journey(verified)
    activity = _fetch_run_activity(case_id=verified.case_id, dsn=dsn)
    nonce = _csp_nonce()
    journey_json = _safe_journey_json(journey) if journey is not None else "null"

    html = _get_jinja_env().get_template("journey.html.j2").render(
        token=token,
        case=_case_dict(verified),
        journey=journey,
        journey_json=journey_json,
        activity=activity,
        nonce=nonce,
        expires_at=_fmt_dt(verified.expires_at) if verified.expires_at else None,
    )
    # Per-response CSP: relax script-src to this page's nonce only (the
    # global policy is script-src 'none'). Everything else stays as
    # locked as the global policy — connect-src 'none' guarantees the
    # inline graph cannot exfiltrate, even if it were somehow subverted.
    csp = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        f"script-src 'nonce-{nonce}'; "
        "connect-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return 200, html.encode("utf-8"), _with_security_headers({
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": csp,
    })


def _csp_nonce() -> str:
    """A fresh base64url CSP nonce per response (no padding, browser-safe)."""
    return secrets.token_urlsafe(16)


def _load_journey(verified: VerifiedToken) -> dict[str, Any] | None:
    """Fetch case.json from storage and build the sanitized journey.

    Returns ``None`` (rendered as a friendly empty state) when there's
    no investigation yet, storage isn't configured, the case isn't in
    the bucket, or anything in the build trips — the map is a nicety,
    never a hard dependency of the portal.
    """
    if not verified.investigation_id:
        return None
    sb_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not sb_url or not sb_key:
        return None
    try:
        from recupero.worker.investigations_api import fetch_case_json
        raw = fetch_case_json(
            supabase_url=sb_url, service_role_key=sb_key,
            investigation_id=str(verified.investigation_id),
        )
        if not raw:
            return None
        from recupero.models import Case
        from recupero.reports.client_journey import build_journey_data
        case = Case.model_validate(raw)
        journey = build_journey_data(case)
        # An empty graph (no nodes) is the same as "no map yet" for the UI.
        if not journey.get("nodes"):
            return None
        return journey
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "portal: journey build failed for inv=%s: %s",
            verified.investigation_id, exc,
        )
        return None


def _safe_journey_json(journey: dict[str, Any]) -> str:
    """Serialize the journey for safe embedding in a
    ``<script type="application/json">`` block.

    Mirrors ``reports.graph_ui`` hardening: ``allow_nan=False`` (reject
    NaN/Inf rather than emit JS literals JSON.parse rejects) plus
    escaping of ``</``, ``<!--`` and ``-->`` so no node label can break
    out of the script-data context even under a lenient HTML parser.
    """
    try:
        blob = json.dumps(journey, separators=(",", ":"), allow_nan=False)
    except ValueError:
        # Defense-in-depth: scrub any non-finite float a future caller
        # might thread in, then re-serialize.
        def _walk(o: Any) -> Any:
            if isinstance(o, float) and not math.isfinite(o):
                return 0
            if isinstance(o, dict):
                return {k: _walk(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [_walk(v) for v in o]
            return o
        blob = json.dumps(_walk(journey), separators=(",", ":"), allow_nan=False)
    return (
        blob.replace("</", "<\\/")
        .replace("<!--", "\\u003c!--")
        .replace("-->", "--\\u003e")
    )


def _fetch_run_activity(
    *, case_id: UUID | None, dsn: str
) -> list[dict[str, str]]:
    """Build a client-friendly timeline of investigation runs for the
    case (most recent first). Best-effort: returns ``[]`` on any error
    or when no DSN is configured.

    No schema change — reads the existing ``investigations`` lifecycle
    timestamps (triggered_at / started_at / completed_at).
    """
    if not case_id or not dsn:
        return []
    rows: list[dict[str, Any]] = []
    try:
        with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=10) as conn, \
                conn.cursor() as cur:
            cur.execute(
                """
                SELECT triggered_at, started_at, completed_at
                  FROM public.investigations
                 WHERE case_id = %s
                 ORDER BY triggered_at DESC NULLS LAST
                 LIMIT 6
                """,
                (str(case_id),),
            )
            rows = cur.fetchall() or []
    except Exception as exc:  # noqa: BLE001
        log.debug("portal: run-activity query failed for case=%s: %s", case_id, exc)
        return []

    out: list[dict[str, str]] = []
    for i, r in enumerate(rows):
        completed = _coerce_utc(r.get("completed_at"))
        triggered = _coerce_utc(r.get("triggered_at"))
        if completed is not None:
            label = "Latest analysis completed" if i == 0 else "Analysis completed"
            out.append({"when": _fmt_dt(completed), "label": label})
        elif triggered is not None:
            label = "Analysis in progress" if i == 0 else "Analysis run"
            out.append({"when": _fmt_dt(triggered), "label": label})
    return out


def _route_sign_form(
    *, token: str, verified: VerifiedToken, error: str | None = None
) -> tuple[int, bytes, dict[str, str]]:
    # If already engaged, route the victim straight to the status page
    # — re-signing is not the typical flow and silently double-charging
    # would be a surprise.
    if (
        verified.engagement_started_at is not None
        and verified.engagement_closed_at is None
    ):
        return _redirect(f"/portal/{token}")
    # RIGOR-Jacob Z16-2: ALSO redirect closed engagements to the
    # status page. The POST handler rejects closed engagements with
    # a 403 (v0.16.7 round-9 HIGH); rendering the sign form here
    # creates two problems:
    #   1. UX-trap — the victim types their full legal name, ticks
    #      the agreement box, hits Submit, gets a 403.
    #   2. Defense-in-depth — if the POST closed-engagement guard
    #      ever regressed, the only thing stopping a silent re-
    #      engagement on a closed case would be a single check.
    # Mirror the active-engagement short-circuit: send the victim
    # to the status page where the closed-engagement messaging +
    # support-contact link live.
    if verified.engagement_closed_at is not None:
        return _redirect(f"/portal/{token}")
    html = _get_jinja_env().get_template("sign.html.j2").render(
        token=token, case=_case_dict(verified), error=error,
    )
    return _ok_html(html)


def _route_sign_submit(
    *,
    token: str,
    verified: VerifiedToken,
    body_bytes: bytes,
    headers: dict[str, str],
    dsn: str,
) -> tuple[int, bytes, dict[str, str]]:
    # CSRF / cross-origin guard. State-changing POST without cookies →
    # the standard defense is verifying Origin/Referer. Pre-v0.16.7 this
    # check did not exist, so any third-party page that learned a portal
    # URL (shoulder-surf, Discord paste, browser history on a shared
    # device, operator email forwarded) could auto-POST a $10K
    # engagement on the victim's behalf. Round-9 security audit CRIT.
    if not _origin_matches_self(headers):
        log.warning(
            "portal: rejecting POST /sign with bad/missing Origin "
            "(token=%s..., origin=%r, referer=%r)",
            token[:8], headers.get("origin"), headers.get("referer"),
        )
        return _render_error(
            status=403,
            message=(
                "This form must be submitted from the Recupero portal. "
                "Please open the engagement link directly and try again."
            ),
        )

    # Already-engaged short-circuit. Same reasoning as the GET handler.
    if (
        verified.engagement_started_at is not None
        and verified.engagement_closed_at is None
    ):
        return _redirect(f"/portal/{token}")

    # v0.16.7 (round-9 security HIGH): block re-engagement on a CLOSED
    # case. Pre-v0.16.7 a portal token whose engagement had been
    # closed by an operator could be re-used to silently re-open the
    # case (no payment, no operator confirmation, just a fresh 30-day
    # service window). Operators rotating tokens at close time is the
    # complete fix; this guard stops the same-token replay attack
    # while that rotation is being adopted.
    if verified.engagement_closed_at is not None:
        log.info(
            "portal: rejecting POST /sign on CLOSED engagement (token=%s...)",
            token[:8],
        )
        return _render_error(
            status=403,
            message=(
                "This engagement was closed. If you believe it should "
                "remain active, please email support@recupero.io for a "
                "fresh engagement link."
            ),
        )

    fields = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="replace"))
    name = (fields.get("signature_name") or [""])[0].strip()
    agreed = (fields.get("agree") or [""])[0] == "on"

    # Cap signature_name length defensively. Pre-v0.16.7 we accepted
    # arbitrary-length names; a 1MB POST burned DB row space and was
    # a cheap DoS vector. Real legal names exceed 200 chars only in
    # ceremonial / multi-generational contexts; we accept up to 200.
    if len(name) > 200:
        return _route_sign_form(
            token=token, verified=verified,
            error="Please enter a legal name under 200 characters.",
        )
    if len(name) < 3 or not agreed:
        return _route_sign_form(
            token=token, verified=verified,
            error="Please enter your full legal name and check the agreement box.",
        )

    # RIGOR-Jacob Z2-1: reject bidi-override / zero-width / BOM in
    # signature_name BEFORE _persist_signature touches the DB. The
    # engagement_signatures column is the legal-defensibility audit
    # trail; a name like ``Smith‮nimdA`` renders as ``SmithAdmin`` in
    # any operator view, undermining the audit claim made on /sign.
    if _signature_name_has_trojan(name):
        log.warning(
            "portal: rejecting /sign POST with bidi/zero-width/BOM in "
            "signature_name (token=%s...)", token[:8],
        )
        return _route_sign_form(
            token=token, verified=verified,
            error=(
                "Your name contains a hidden character "
                "(bidi-override, zero-width, or BOM). Please retype "
                "it directly without copy-pasting from a rich-text "
                "source — your signature is part of the legal audit "
                "record."
            ),
        )

    # RIGOR-Jacob Z2-2: strip CR / LF / NUL / control chars from the
    # signature_name BEFORE the INSERT. Pre-fix, ``Alex\r\nFAKE`` would
    # store a multi-line string that surfaces in admin views as a
    # forged second audit line; a NUL byte crashes psycopg with
    # "A string literal cannot contain NUL (0x00) characters" and
    # surfaces a 500 to the victim. Both shapes neutralized by
    # _strip_control_chars (same helper used for user-agent storage).
    name = _strip_control_chars(name, max_len=200)
    if len(name) < 3:
        return _route_sign_form(
            token=token, verified=verified,
            error="Please enter your full legal name and check the agreement box.",
        )

    try:
        fee = Decimal(str(verified.quoted_fee_usd))
    except (InvalidOperation, TypeError):
        from recupero._pricing import ENGAGEMENT_FEE_USD
        fee = ENGAGEMENT_FEE_USD

    ip = _extract_client_ip(headers)
    # Strip CR/LF/control chars before storage to block UA log-injection.
    # See _strip_control_chars docstring for the attack scenario.
    user_agent = _strip_control_chars(headers.get("user-agent", ""), max_len=500)

    # The agreement text the victim agreed to — keep this verbatim
    # so future template edits don't retroactively change history.
    agreement_text = (
        "By typing my full legal name and submitting this form, I "
        "agree to engage Recupero on the terms shown on the "
        f"engagement page (engagement fee ${fee:,.0f}, 15% "
        "contingent recovery fee, 30-day status reporting). I "
        "understand that recovery is not guaranteed."
    )

    try:
        signed_at = _persist_signature(
            dsn=dsn,
            case_id=verified.case_id,
            investigation_id=verified.investigation_id,
            token_id=verified.token_id,
            signature_name=name,
            agreement_text=agreement_text,
            fee_usd=fee,
            ip_address=ip,
            user_agent=user_agent,
        )
    except _DoubleSubmitError as exc:
        # v0.16.12: a concurrent POST won the FOR UPDATE race. The
        # engagement IS real — the first POST committed — we just
        # don't duplicate the signature row. Redirect to the status
        # page so the user sees the success state.
        log.info(
            "portal: double-submit detected for token=%s..., redirecting: %s",
            token[:8], exc,
        )
        return _redirect(f"/portal/{token}")
    except Exception as exc:  # noqa: BLE001
        log.exception("portal: signature persist failed: %s", exc)
        return _route_sign_form(
            token=token, verified=verified,
            error="We hit a server error recording your signature. "
                  "Please try again, or email support@recupero.io.",
        )

    log.info(
        "portal: signature captured case=%s investigation=%s name=%r fee=%s",
        verified.case_id, verified.investigation_id, name, fee,
    )

    # v0.18.2 (round-11 sec-HIGH-003): rotate the bearer token after
    # successful engagement signing. Pre-v0.18.2 the same token
    # remained valid for its full TTL (90 days default). Anyone who
    # later obtained the URL via:
    #   * email-forward of the original diagnostic email
    #   * browser-history scrape on a shared/kiosk device
    #   * screen-share recording / shoulder surf at signing
    # could re-open /portal/<token>, see PII (case_number, client_email,
    # estimated_value_usd), and download artifacts for ~89 days.
    # New: revoke the just-used token; the signed.html.j2 page is
    # rendered with the SAME token URL (one final render is fine);
    # subsequent /portal/<token> requests fail with "link unavailable".
    # Customers who need ongoing access get a fresh token via the
    # admin UI's generate-customer-link path.
    try:
        from recupero.portal.tokens import revoke_token
        revoke_token(token_id=verified.token_id, dsn=dsn)
        log.info(
            "portal: rotated token after signing token_id=%s case=%s",
            verified.token_id, verified.case_id,
        )
    except Exception as rotate_exc:  # noqa: BLE001
        # Best-effort. If revocation fails, the engagement is still
        # captured; ops can revoke manually. Logged loudly so monitoring
        # picks it up.
        log.exception(
            "portal: post-sign token rotation failed token_id=%s: %s",
            verified.token_id, rotate_exc,
        )

    html = _get_jinja_env().get_template("signed.html.j2").render(
        token=token,
        case=_case_dict(verified),
        signature={
            "signature_name": name,
            "signed_at": _fmt_dt(signed_at),
            "fee_usd": fee,
        },
    )
    return _ok_html(html)


def _route_artifact(
    *, verified: VerifiedToken, artifact_key: str
) -> tuple[int, bytes, dict[str, str]]:
    """Resolve `artifact_key` to a storage path, sign a short-lived
    URL, and 302-redirect there. We do not proxy the file content
    through the portal — that would burn Railway egress for every
    download. Signed URLs are 5-minute TTL so a copy-pasted URL
    doesn't leak access beyond the immediate session.
    """
    if not verified.investigation_id:
        return _render_error(404, "no artifacts available for this case yet")

    # Whitelist check FIRST — before any env-var look-up. Two reasons:
    #   1. Security: don't reveal whether a path would be valid (with
    #      proper env config) to an attacker probing the URL space.
    #   2. Tests / dev envs without SUPABASE_* set should still get
    #      404 on unknown keys, not a misleading 503.
    spec = _PORTAL_ARTIFACTS.get(artifact_key)
    if spec is None:
        return _render_error(404, "unknown artifact")

    sb_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not sb_url or not sb_key:
        return _render_error(503, "artifact downloads not configured")

    # Resolve the actual filename by prefix-match. The worker writes
    # files with per-case hash suffixes (victim_summary_recoverable_
    # a1b2c3d4.pdf, flow_a1b2c3d4.pdf), so we list the briefs/ folder
    # and find the first one matching a whitelisted prefix.
    object_path = _resolve_portal_artifact(
        investigation_id=str(verified.investigation_id),
        prefixes=spec["prefixes"],
        sb_url=sb_url, sb_key=sb_key,
    )
    if object_path is None:
        return _render_error(
            404, "this artifact hasn't been generated for your case yet",
        )

    try:
        from recupero.worker.investigations_api import _sign_storage_url
        signed = _sign_storage_url(
            supabase_url=sb_url, service_role_key=sb_key,
            object_path=object_path, ttl_sec=300,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("portal artifact sign failed: %s", exc)
        return _render_error(503, "could not sign artifact URL — try again")

    # v0.17.6 (round-10 security HIGH): the artifact 302 used to skip
    # _with_security_headers, so the Location-only response was missing
    # Referrer-Policy: no-referrer. Browsers following the redirect
    # would attach the portal URL (which contains the bearer token)
    # in the Referer header to Supabase Storage — leaking it into any
    # downstream CDN access log Supabase serves through. Wrap properly.
    # Also Cache-Control: private, no-store so intermediate caches
    # don't retain the signed URL once it 302's into a different origin.
    return 302, b"", _with_security_headers({
        "Location": signed,
        "Cache-Control": "private, no-store, max-age=0",
    })


def _resolve_portal_artifact(
    *,
    investigation_id: str,
    prefixes: tuple[str, ...],
    sb_url: str,
    sb_key: str,
) -> str | None:
    """List the investigation's briefs/ folder and return the first
    object path whose filename starts with any of `prefixes` and
    ends with `.pdf`. Returns None if no match (artifact hasn't
    been generated yet for this case).

    Re-uses the worker's _list_bucket helper so we don't duplicate
    the Supabase Storage HTTP plumbing here. ``.pdf``-only on
    purpose — the portal only ships PDF deliverables; HTML versions
    are operator-internal.
    """
    try:
        from recupero.worker.investigations_api import _list_bucket
    except Exception as exc:  # noqa: BLE001
        log.warning("portal artifact resolve: import failed: %s", exc)
        return None
    prefix_path = f"investigations/{investigation_id}/briefs/"
    try:
        files = _list_bucket(sb_url, sb_key, prefix_path)
    except Exception as exc:  # noqa: BLE001
        log.warning("portal artifact resolve: list failed: %s", exc)
        return None
    # v0.16.8 (round-9 security HIGH): whitelist the filename shape
    # BEFORE concatenating into a bucket path. Pre-fix the code did
    # `prefix_path + name` with `name` straight off the vendor list
    # response — so a malicious object name like `../other-case/secret.pdf`
    # would land in the signed-URL call and leak across cases. The
    # blast radius today is small (only the worker writes to the bucket)
    # but we are NOT going to depend on that staying true; defense-in-
    # depth costs nothing.
    for f in files:
        name = f.get("name") or ""
        if not _safe_bucket_filename(name):
            log.warning(
                "portal artifact resolve: skipping unsafe filename %r",
                name,
            )
            continue
        if not name.endswith(".pdf"):
            continue
        for p in prefixes:
            if name.startswith(p):
                return prefix_path + name
    return None


# Whitelist for bucket-object filenames. Letters/digits/underscore/
# dot/hyphen, 1-200 chars. Notable rejections:
#   * `..` (path traversal)
#   * `/` and `\` (any path-segment break)
#   * spaces, quotes, control chars
#   * empty / overlong names
_SAFE_BUCKET_FILENAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.\-]{0,199}$")


def _safe_bucket_filename(name: str) -> bool:
    """True if `name` is a plain filename safe to concatenate into a
    bucket prefix-path. See _SAFE_BUCKET_FILENAME for the allowed shape.

    Explicitly rejects `..` substrings as belt-and-suspenders against
    the regex; the dot-prefix exclusion in the first-char class makes
    leading `..` impossible, but a mid-string `..` (e.g.
    `victim_summary_recoverable_..pdf`) is still worth blocking.
    """
    if not name or len(name) > 200:
        return False
    if ".." in name:
        return False
    return bool(_SAFE_BUCKET_FILENAME.match(name))


# ----- Helpers ----- #


# Whitelisted artifact keys → bucket-prefix patterns. Keys appear in
# URLs so they're stable + short; the worker writes files with
# per-case hash suffixes (e.g., victim_summary_recoverable_a1b2c3d4.pdf),
# so we resolve the actual filename by prefix-match at request time.
#
# We deliberately omit:
#   * trace_report — internal-facing technical detail, not customer-
#     friendly. The customer gets the summary-form victim_summary.
#   * freeze_request / le_handoff — those go directly to issuers /
#     law enforcement, not the victim.
#   * Raw bucket files (case.json, freeze_asks.json, etc.) — too
#     technical, and exposing them would risk leaking internal
#     fields not meant for the customer.
#
# Prefixes are tried in order; the first matching file under the
# investigation's briefs/ folder wins. ``.pdf`` is required (no HTML
# — keeps the surface to one renderable format).
_PORTAL_ARTIFACTS: dict[str, dict[str, Any]] = {
    "victim_summary": {
        "label": "Diagnostic summary",
        "kind": "PDF",
        # Either recoverable_ or unrecoverable_ variant, depending on
        # what the editorial stage produced for this case.
        "prefixes": ("victim_summary_recoverable_",
                     "victim_summary_unrecoverable_"),
    },
    "fund_flow": {
        "label": "Fund-flow diagram",
        "kind": "PDF",
        "prefixes": ("flow_",),
    },
}


def _portal_artifact_list(*, verified: VerifiedToken) -> list[dict[str, Any]]:
    """Build the artifacts list shown on the status page.

    We list the whitelist directly — we don't probe the bucket per
    key — because portal latency matters more than perfect
    accuracy. A missing artifact yields a 404 on click (rare; the
    diagnostic pipeline writes all three before sending the
    intake-confirmation email).
    """
    out: list[dict[str, Any]] = []
    if not verified.investigation_id:
        return out
    for key, spec in _PORTAL_ARTIFACTS.items():
        out.append({
            "key": key,
            "label": spec["label"],
            "kind": spec["kind"],
            "size": None,
        })
    return out


def _case_dict(v: VerifiedToken) -> dict[str, Any]:
    return {
        "case_number": v.case_number,
        "client_name": v.client_name,
        "client_email": v.client_email,
        "case_status": v.case_status,
        "case_state": v.case_state,
        "estimated_value_usd": v.estimated_value_usd,
        "quoted_fee_usd": v.quoted_fee_usd or _engagement_fee_default(),
    }


def _engagement_dict(v: VerifiedToken) -> dict[str, Any]:
    """Mirror of worker.investigations_api._build_engagement_summary
    for the portal's case. Inlined to avoid a coupling that would
    make portal startup pull in the full investigations_api module.
    """
    now = datetime.now(UTC)
    started = _coerce_utc(v.engagement_started_at)
    closed = _coerce_utc(v.engagement_closed_at)
    if started is None:
        status = "not_engaged"
        days_remaining = None
        days_since = None
    elif closed is not None:
        status = "closed"
        days_remaining = None
        days_since = (now - started).days
    else:
        days_since = (now - started).days
        if days_since >= 30:
            status = "expired"
            days_remaining = 0
        else:
            status = "active"
            days_remaining = 30 - days_since
    return {
        "status": status,
        "fee_paid_usd": v.engagement_fee_paid_usd,
        "started_at": _fmt_dt(started) if started else None,
        "closed_at": _fmt_dt(closed) if closed else None,
        "days_since_start": days_since,
        "days_remaining": days_remaining,
    }


def _engagement_fee_default() -> Decimal:
    """Default engagement fee for portal-page rendering when the
    case row doesn't carry an explicit quoted_fee_usd. Centralized
    in recupero._pricing so a price change updates without manual
    sync across every fallback point."""
    from recupero._pricing import ENGAGEMENT_FEE_USD
    return ENGAGEMENT_FEE_USD


def _coerce_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _fmt_dt(dt: datetime | None) -> str:
    """Render datetimes for the portal in a customer-friendly form."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.strftime("%B %d, %Y")


class _DoubleSubmitError(Exception):
    """Raised when the engagement-signature row already exists for the
    given investigation (concurrent POST detected). The portal handler
    converts this to a redirect to the status page — the engagement is
    already real, we just don't insert a duplicate."""


def _persist_signature(
    *,
    dsn: str,
    case_id: UUID,
    investigation_id: UUID | None,
    token_id: UUID,
    signature_name: str,
    agreement_text: str,
    fee_usd: Decimal,
    ip_address: str,
    user_agent: str,
) -> datetime:
    """Write the signature row + activate the engagement in one
    transaction. Returns the signed_at timestamp the DB recorded.

    v0.16.12 (round-9 security CRIT): double-submit guard. Two
    simultaneous POSTs (back-button reload, hostile family member,
    browser auto-retry) used to both pass the "already engaged"
    short-circuit at the request entry and both INSERT signature rows
    for the same investigation. Now:

      1. SELECT ... FOR UPDATE on the investigations row serializes
         concurrent transactions trying to engage the same
         investigation.
      2. Re-check engagement_started_at INSIDE the locked transaction.
         If it's already set, raise _DoubleSubmitError — the handler
         redirects to the status page rather than inserting a second
         signature row.
      3. Partial unique index on engagement_signatures
         (investigation_id WHERE NOT NULL) — migration 015 — is
         defense-in-depth: if the lock fails (timeout, retry storm)
         the constraint still rejects the duplicate INSERT.

    Why not just rely on the unique index? The lock-then-check
    pattern lets us redirect on the second POST instead of
    surfacing an IntegrityError to the user — better UX, same
    forensic outcome.

    If the signature row writes but the engagement update fails (or
    vice versa) the operator ends up with a half-engaged case, so
    we wrap both in an explicit BEGIN/COMMIT.
    """
    with psycopg.connect(dsn, autocommit=False, row_factory=dict_row,
                         connect_timeout=10, prepare_threshold=None) as conn:
        with conn.cursor() as cur:
            # v0.16.12: row-lock the investigation FIRST. SKIP LOCKED
            # would silently drop one of the two concurrent POSTs;
            # we want the second one to WAIT and then see the
            # already-engaged state. Plain FOR UPDATE blocks the
            # second POST until the first commits.
            if investigation_id is not None:
                cur.execute(
                    """
                    SELECT engagement_started_at, engagement_closed_at
                      FROM public.investigations
                     WHERE id = %s
                     FOR UPDATE
                    """,
                    (str(investigation_id),),
                )
                lock_row = cur.fetchone()
                if (
                    lock_row is not None
                    and lock_row["engagement_started_at"] is not None
                    and lock_row["engagement_closed_at"] is None
                ):
                    # The first POST won. Don't insert a duplicate;
                    # let the handler redirect to the status page.
                    raise _DoubleSubmitError(
                        f"investigation {investigation_id} already engaged"
                    )

            try:
                cur.execute(
                    """
                    INSERT INTO public.engagement_signatures
                        (case_id, investigation_id, case_token_id,
                         signature_name, agreement_text, fee_usd,
                         ip_address, user_agent)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING signed_at
                    """,
                    (str(case_id),
                     str(investigation_id) if investigation_id else None,
                     str(token_id),
                     signature_name, agreement_text, fee_usd,
                     ip_address or None, user_agent or None),
                )
            except psycopg.errors.UniqueViolation as exc:
                # The partial unique index (migration 015) caught a
                # duplicate that slipped past the row-lock — unlikely
                # but possible on connection-pool retries. Treat the
                # same as the lock-detected case: redirect, not error.
                raise _DoubleSubmitError(
                    f"unique constraint blocked duplicate signature: {exc}"
                ) from exc
            signed_at = cur.fetchone()["signed_at"]

            # Activate the engagement. Idempotency: only set
            # engagement_started_at if it's not already set — that
            # way an accidental double-submit (back-button reload)
            # doesn't extend the 30-day window.
            if investigation_id is not None:
                cur.execute(
                    """
                    UPDATE public.investigations
                       SET engagement_started_at = COALESCE(engagement_started_at, NOW()),
                           engagement_closed_at = NULL,
                           engagement_fee_paid_usd = COALESCE(
                               engagement_fee_paid_usd, %s
                           )
                     WHERE id = %s
                    """,
                    (fee_usd, str(investigation_id)),
                )
        conn.commit()
    return signed_at


# ----- Response helpers ----- #


def _with_security_headers(extra: dict[str, str]) -> dict[str, str]:
    """Merge response headers with the portal's standard security headers.

    Token-in-URL bearer auth means `Referrer-Policy: no-referrer` is
    SAFETY-CRITICAL: every outbound click without it leaks the token.
    Plus CSP / X-Frame-Options / X-Content-Type-Options for defense-
    in-depth. v0.16.7 (round-9 security audit HIGH).
    """
    merged = dict(_PORTAL_SECURITY_HEADERS)
    merged.update(extra)
    return merged


def _ok_html(html: str) -> tuple[int, bytes, dict[str, str]]:
    body = html.encode("utf-8")
    return 200, body, _with_security_headers({"Content-Type": "text/html; charset=utf-8"})


def _redirect(location: str, code: int = 303) -> tuple[int, bytes, dict[str, str]]:
    # 303 forces a GET on the redirect target — matches the
    # POST-redirect-GET pattern used by the sign form.
    return code, b"", _with_security_headers({"Location": location})


def _render_error(code: int = 500, message: str = "", *, status: int | None = None) -> tuple[int, bytes, dict[str, str]]:
    """Render the portal error page.

    Accepts either positional `code` (legacy) or keyword `status=` so
    new call sites can be more readable. Both forms supported during
    the transition.
    """
    if status is not None:
        code = status
    try:
        html = _get_jinja_env().get_template("error.html.j2").render(message=message)
    except Exception:  # noqa: BLE001
        # Last-resort fallback if the template itself failed to render.
        # HTML-escape `message` even though it's internally-sourced — keeps
        # the fallback safe if a future caller passes user input.
        import html as _html_lib
        safe = _html_lib.escape(message or "")
        html = f"<h1>Error</h1><p>{safe}</p>"
    return code, html.encode("utf-8"), _with_security_headers({"Content-Type": "text/html; charset=utf-8"})


def _get_dsn() -> str:
    return os.environ.get("SUPABASE_DB_URL", "").strip()


# ----- Cookie hardening guard rail ----- #
#
# The portal is intentionally cookieless: authentication uses a bearer
# token embedded in the URL path, and state-changing POSTs are defended
# by Origin/Referer matching (_origin_matches_self) rather than a CSRF
# cookie. No code path below today calls _validate_cookie_directive.
#
# We export it anyway as a forcing function: if a future change adds
# any session / preferences / "remember-me" cookie, it must construct
# the Set-Cookie value through this helper first. The helper raises
# ValueError on every weak attribute combination so a regression
# surfaces at unit-test time, not in production.
#
# tests/test_portal_cookies_session.py pins both layers: the actual
# routes today must emit ZERO Set-Cookie headers, AND if Set-Cookie
# is ever emitted it must satisfy every check in the helper.
def _validate_cookie_directive(
    directive: str, *, value_entropy_bits: int = 128
) -> None:
    """Raise ValueError unless ``directive`` is a safe Set-Cookie value.

    Enforces every attribute the portal cookie hardening policy
    requires:

      * ``Secure``                  — never in cleartext.
      * ``HttpOnly``                — JS cannot read the value.
      * ``SameSite=Strict|Lax``     — never ``None`` (never ``None``
                                      even with ``Secure``, because
                                      the portal has no documented
                                      cross-site flow that needs it).
      * ``Path=/portal``            — scoped to the portal mount, not
                                      bare ``/``.
      * No ``Domain=`` attribute    — defaults to host-only; explicit
                                      ``Domain=`` widens to subdomains.
      * ``Max-Age=`` or ``Expires=``— bounded session, not permanent.
      * Opaque cookie name          — must not contain ``case`` /
                                      ``token`` / a UUID-shaped hex
                                      blob (operators see Set-Cookie
                                      in access logs).
      * Cookie value entropy        — Shannon-entropy estimate over
                                      the value must meet
                                      ``value_entropy_bits``. A
                                      deterministic case-id hash
                                      has near-zero secrecy.
    """
    if not directive or "=" not in directive:
        raise ValueError("Set-Cookie directive missing name=value pair")

    # Split into name=value + attributes (semicolon-separated).
    parts = [p.strip() for p in directive.split(";")]
    name_value = parts[0]
    attrs = parts[1:]
    name, _, value = name_value.partition("=")
    name = name.strip()
    value = value.strip()

    # --- name opacity ---
    name_lower = name.lower()
    forbidden_in_name = ("case", "token", "investigation", "client", "victim")
    for needle in forbidden_in_name:
        if needle in name_lower:
            raise ValueError(
                f"cookie name {name!r} is not opaque (contains {needle!r}); "
                f"operator access-log scrapes would deanonymize visitors"
            )
    # 32-char hex blob in the name → likely a UUID-shaped identifier.
    if re.search(r"[0-9a-f]{16,}", name_lower):
        raise ValueError(
            f"cookie name {name!r} embeds a hex blob — names must be opaque"
        )

    # --- attribute parsing (case-insensitive keys) ---
    has_secure = False
    has_httponly = False
    samesite: str | None = None
    path: str | None = None
    has_domain = False
    has_bound = False
    for a in attrs:
        if not a:
            continue
        key, _eq, val = a.partition("=")
        k = key.strip().lower()
        v = val.strip()
        if k == "secure":
            has_secure = True
        elif k == "httponly":
            has_httponly = True
        elif k == "samesite":
            samesite = v.lower()
        elif k == "path":
            path = v
        elif k == "domain":
            has_domain = True
        elif k in ("max-age", "expires"):
            has_bound = True

    # Check SameSite-specific failures BEFORE the missing-Secure
    # check, so a `SameSite=None; (no Secure)` cookie surfaces the
    # more informative "SameSite=None requires Secure" diagnostic
    # instead of the generic "missing Secure" message. The spec
    # (RFC 6265bis) treats SameSite=None+missing-Secure as a
    # SameSite violation, not just a Secure violation.
    if samesite is None:
        raise ValueError("cookie missing SameSite attribute")
    if samesite == "none":
        raise ValueError(
            "cookie SameSite=None disallowed (even with Secure); "
            "use Strict or Lax"
        )
    if samesite not in ("strict", "lax"):
        raise ValueError(
            f"cookie SameSite={samesite!r} disallowed; use Strict or Lax"
        )
    if not has_secure:
        raise ValueError("cookie missing Secure attribute")
    if not has_httponly:
        raise ValueError("cookie missing HttpOnly attribute")
    if path is None or not path.startswith("/portal"):
        raise ValueError(
            f"cookie Path={path!r} must be scoped to /portal, not bare /"
        )
    if has_domain:
        raise ValueError(
            "cookie must NOT set Domain= attribute (host-only is safer)"
        )
    if not has_bound:
        raise ValueError("cookie missing Max-Age / Expires (unbounded)")

    # --- value entropy ---
    if not value:
        raise ValueError("cookie value empty (no entropy)")
    # Shannon entropy estimate: H(X) * len(X). This is an over-estimate
    # for short strings (treats observed symbol frequencies as the true
    # distribution) but small enough that low-entropy junk like a hex
    # hash of the case_id will still fall well below 128 bits.
    from collections import Counter
    counts = Counter(value)
    total = len(value)
    h_per_symbol = -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c > 0
    )
    estimated_bits = h_per_symbol * total
    if estimated_bits < value_entropy_bits:
        raise ValueError(
            f"cookie value entropy {estimated_bits:.1f} bits below "
            f"required {value_entropy_bits} bits — a deterministic "
            f"case_id hash is NOT an acceptable session token"
        )


__all__ = ("handle_portal", "_validate_cookie_directive")
