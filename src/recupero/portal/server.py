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

import logging
import os
import urllib.parse
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from recupero.portal.tokens import VerifiedToken, verify_token

log = logging.getLogger(__name__)

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
        artifact_key = sub_path[len("artifact/"):]
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
    # Already-engaged short-circuit. Same reasoning as the GET handler.
    if (
        verified.engagement_started_at is not None
        and verified.engagement_closed_at is None
    ):
        return _redirect(f"/portal/{token}")

    fields = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="replace"))
    name = (fields.get("signature_name") or [""])[0].strip()
    agreed = (fields.get("agree") or [""])[0] == "on"

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

    ip = (headers.get("x-forwarded-for", "") or "").split(",")[0].strip()
    if not ip:
        ip = headers.get("x-real-ip", "")
    user_agent = headers.get("user-agent", "")[:500]

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
    for f in files:
        name = f.get("name") or ""
        if not name.endswith(".pdf"):
            continue
        for p in prefixes:
            if name.startswith(p):
                return prefix_path + name
    return None


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


def _ok_html(html: str) -> tuple[int, bytes, dict[str, str]]:
    body = html.encode("utf-8")
    return 200, body, {"Content-Type": "text/html; charset=utf-8"}


def _redirect(location: str, code: int = 303) -> tuple[int, bytes, dict[str, str]]:
    # 303 forces a GET on the redirect target — matches the
    # POST-redirect-GET pattern used by the sign form.
    return code, b"", {"Location": location}


def _render_error(code: int, message: str) -> tuple[int, bytes, dict[str, str]]:
    try:
        html = _get_jinja_env().get_template("error.html.j2").render(message=message)
    except Exception:  # noqa: BLE001
        # Last-resort fallback if the template itself failed to render.
        html = f"<h1>Error</h1><p>{message}</p>"
    return code, html.encode("utf-8"), {"Content-Type": "text/html; charset=utf-8"}


def _get_dsn() -> str:
    return os.environ.get("SUPABASE_DB_URL", "").strip()


__all__ = ("handle_portal",)
