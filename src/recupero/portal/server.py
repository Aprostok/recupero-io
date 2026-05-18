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
import logging
import os
import re
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


def _origin_matches_self(headers: dict[str, str]) -> bool:
    """Return True if the request's Origin (or Referer) is our own host.

    Standard CSRF defense for state-changing POSTs in cookieless apps:
    a cross-origin attacker page can submit a form to our URL, but the
    browser will tag it with an Origin header pointing at the attacker.
    We accept the request only when Origin (or Referer if Origin is
    absent) matches the portal's own scheme://host.

    The expected origin is `RECUPERO_PORTAL_PUBLIC_ORIGIN` (e.g.
    `https://app.recupero.io`). When unset, we fall back to accepting
    only same-host requests inferred from the inbound `Host` header —
    less strict but better than nothing for local-dev.
    """
    configured = os.environ.get("RECUPERO_PORTAL_PUBLIC_ORIGIN", "").strip().rstrip("/")
    expected_origins: list[str] = []
    if configured:
        expected_origins.append(configured)
    host = (headers.get("host", "") or "").strip()
    if host:
        # Accept either scheme for the same host so local-dev works.
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

    return 302, b"", {"Location": signed}


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

    If the signature row writes but the engagement update fails (or
    vice versa) the operator ends up with a half-engaged case, so
    we wrap both in an explicit BEGIN/COMMIT.
    """
    with psycopg.connect(dsn, autocommit=False, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
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


__all__ = ("handle_portal",)
