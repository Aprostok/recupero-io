"""Unified operator console hub (v0.35.19 — UI initiative).

The phases the team built (brief review, watchlist, address screening, label
review, monitoring, …) each have backend logic + (some) admin-gated JSON, but
there was no single place to SEE them. This is the hub: an operator home page
that links every console + shows live quick-stats, so the product is one
coherent surface that fills in as each phase view is added.

Same security model as the other consoles (the established secure-shell
pattern): the hub HTML at ``/v1/console`` is unauthenticated and carries NO data;
the nav list (``/v1/console/nav``) is public link metadata (no secret — the
linked consoles each gate themselves); the quick-stats (``/v1/console/stats``)
is admin-gated and best-effort (every stat degrades to null rather than failing
the page when its data source is unavailable).

The nav registry ``_NAV`` is a static list maintained HERE. New phase consoles
append one entry during the single sequential integration step — deliberately
not a parallel-written shared registry, to avoid the lost-write failure mode.
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Response, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/console", tags=["operator-console"])

_HUB_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "operator_dashboard.html"
)
_STORY_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "origin_story.html"
)

# Operator console navigation registry. Each entry = one linkable view.
# `live` marks views that exist now; phase agents append their entry here during
# the sequential integration step (never concurrently). Grouped for the grid.
_NAV: list[dict[str, Any]] = [
    {"group": "Casework", "label": "Review Gate", "icon": "gate",
     "path": "/review-gate", "live": True,
     "desc": "Approve / reject AI-drafted briefs before release."},
    {"group": "Monitoring", "label": "Watchlist", "icon": "eye",
     "path": "/v1/watchlist/console", "live": True,
     "desc": "Live view of watched addresses + movement since last check."},
    {"group": "Screening", "label": "Address Profile", "icon": "search",
     "path": "/v1/address/console", "live": True,
     "desc": "Screen any address: risk verdict, labels, sighting history."},
    # v0.35.20 UI batch-1 phase consoles.
    {"group": "Labels", "label": "Label Review", "icon": "tag",
     "path": "/v1/label-review/console", "live": True,
     "desc": "Review auto-ingested label candidates (promote/reject via API)."},
    {"group": "Ops", "label": "Cron Health", "icon": "gear",
     "path": "/v1/ops/cron-console", "live": True,
     "desc": "Scheduled-job health + last-error for each background job."},
    {"group": "Data health", "label": "Label Freshness", "icon": "clock",
     "path": "/v1/freshness/console", "live": True,
     "desc": "Per-source label freshness vs SLA; OFAC feed-age alarm."},
    # v0.35.21 UI batch-2 phase consoles.
    {"group": "Casework", "label": "Graph Analysis", "icon": "share",
     "path": "/v1/graph-analysis/console", "live": True,
     "desc": "Consolidation hubs (where split funds re-merge) + value cycles "
             "for a case."},
    {"group": "Casework", "label": "Case Index", "icon": "folder",
     "path": "/v1/cases/console", "live": True,
     "desc": "All traced cases + which deliverables each has."},
    # v0.35.22 UI batch-3 phase consoles.
    {"group": "Casework", "label": "Exhibit Pack", "icon": "files",
     "path": "/v1/exhibit-pack/console", "live": True,
     "desc": "Court-admissible exhibit index — every case artifact as Exhibit "
             "A, B, C… with SHA-256 hash and byte size."},
    {"group": "Filings", "label": "SAR / STR Filing", "icon": "bank",
     "path": "/v1/sar-filing/console", "live": True,
     "desc": "FinCEN SAR / NCA SAR / AMLD STR filing DRAFT from a case's freeze "
             "brief — Recupero is not the filer."},
    {"group": "Screening", "label": "Bulk Screening", "icon": "list-check",
     "path": "/v1/screening/console", "live": True,
     "desc": "Paste many addresses; bulk sanctions/mixer/drainer risk screen "
             "via the high-throughput offline cache."},
    # v0.35.23 UI batch-4 phase consoles.
    {"group": "Casework", "label": "AI Triage", "icon": "sparkle",
     "path": "/v1/ai-triage/console", "live": True,
     "desc": "Plain-English AI triage (summary, next steps, completeness gaps) "
             "— read-only view of the stored ai_triage.json; never calls the "
             "model."},
    {"group": "Intelligence", "label": "Cooperation", "icon": "link",
     "path": "/v1/cooperation/console", "live": True,
     "desc": "Per-issuer cooperation profiles: freeze-letter response/freeze "
             "rates, response times, recommended legal instrument, black-hole "
             "flags."},
    # v0.35.24 UI batch-5 phase consoles.
    {"group": "Intelligence", "label": "Law Firm Dashboard", "icon": "scale",
     "path": "/v1/law-firm/console", "live": True,
     "desc": "Per-law-firm portfolio rollups: cases referred/completed/in-queue, "
             "money frozen & returned, throughput medians, top issuers."},
    {"group": "Casework", "label": "Recovery Snapshot", "icon": "coins",
     "path": "/v1/recovery-snapshot/console", "live": True,
     "desc": "Pre-engagement recovery estimate for a case — expected "
             "net-to-victim, per-issuer breakdown, drivers/ROI (read-only)."},
    # v0.35.26 UI batch-7: per-case launcher.
    {"group": "Casework", "label": "Case Overview", "icon": "clipboard",
     "path": "/v1/case-overview/console", "live": True,
     "desc": "Per-case launcher — which deliverables a case has produced, with "
             "a deep link into each console."},
    # v0.35.27 UI batch-8: surface main's just-merged operator-graph feature
    # (client-journey-graph) into the hub. Distinct from "Graph Analysis"
    # (computed consolidation hubs + cycles) — this is the INTERACTIVE explorer.
    {"group": "Investigation", "label": "Operator Graph", "icon": "globe",
     "path": "/operator-graph", "live": True,
     "desc": "Interactive TRM/Chainalysis-style fund-flow graph for an "
             "investigation — expand/filter, live updates (SSE), per-node risk, "
             "annotations, saved views, and watch-address."},
    # v0.35.29 UI batch-10: trace-accuracy benchmark.
    {"group": "Casework", "label": "Trace Benchmark", "icon": "target",
     "path": "/v1/benchmark/console", "live": True,
     "desc": "Score a case's trace against an independently-verified "
             "ground-truth endpoint list — recall / precision / F1, plus missed "
             "and spurious endpoints."},
    # v0.35.30: D6 proactive recovery alerts (persisted freeze-NOW queue).
    {"group": "Monitoring", "label": "Recovery Alerts", "icon": "bell",
     "path": "/v1/recovery-alerts/console", "live": True,
     "desc": "Live act-now / freeze-NOW queue — prioritized D6 recovery alerts "
             "(critical/high) persisted from each watch tick, newest first."},
    # v0.35.32: D4 incident-response plans.
    {"group": "Monitoring", "label": "Incident Plans", "icon": "route",
     "path": "/v1/incident-plans/console", "live": True,
     "desc": "Ordered D4 response playbooks from each recovery alert — re-trace, "
             "venue-conditional freeze/subpoena, notify, follow-up."},
    # Origin story — why Recupero exists (narrative page, public, no data).
    {"group": "About", "label": "Our Story", "icon": "heart",
     "path": "/v1/console/story", "live": True,
     "desc": "How Recupero began — the hack, the recovery with U.S. authorities, "
             "and the mission to help others find their way back."},
]

# ── Monochrome line-icon set (stroke=currentColor). Static + trusted (NOT user
# data), so the hub template injects these as raw SVG. Keys map from _NAV.icon.
def _svg(paths: str) -> str:
    return (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" '
        'aria-hidden="true">' + paths + "</svg>"
    )


_ICONS: dict[str, str] = {
    "gate": _svg('<rect x="6" y="3" width="12" height="18" rx="1"/>'
                 '<path d="M6 21h12"/><path d="M14.5 12h.01"/>'),
    "eye": _svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/>'
                '<circle cx="12" cy="12" r="3"/>'),
    "search": _svg('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>'),
    "tag": _svg('<path d="M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0l-6.2-6.2A2 2 0 0 1 '
                '4 13V5a1 1 0 0 1 1-1h8a2 2 0 0 1 1.4.6l6.2 6.2a2 2 0 0 1 0 '
                '2.6z"/><path d="M8.5 8.5h.01"/>'),
    "gear": _svg('<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3'
                 'M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 '
                 '2.1"/>'),
    "clock": _svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    "share": _svg('<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/>'
                  '<circle cx="18" cy="18" r="2.5"/><path d="M8.2 10.8l7.6-3.6'
                  'M8.2 13.2l7.6 3.6"/>'),
    "folder": _svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1'
                   '-2 2H5a2 2 0 0 1-2-2z"/>'),
    "files": _svg('<rect x="8" y="3" width="12" height="15" rx="2"/>'
                  '<path d="M16 21H6a2 2 0 0 1-2-2V7"/>'),
    "bank": _svg('<path d="M3 10l9-6 9 6"/><path d="M4 10v8M9 10v8M15 10v8M20 '
                 '10v8"/><path d="M3 21h18"/>'),
    "list-check": _svg('<path d="M9 6h12M9 12h12M9 18h12"/><path d="M3 6l1.2 1.2'
                       'L6 5M3 12l1.2 1.2L6 11M3 18l1.2 1.2L6 17"/>'),
    "sparkle": _svg('<path d="M12 3l1.6 4.8L18.4 9.4 13.6 11 12 15.8 10.4 11 5.6 '
                    '9.4 10.4 7.8z"/><path d="M18.5 15l.7 2 2 .7-2 .7-.7 2-.7-2-2'
                    '-.7 2-.7z"/>'),
    "link": _svg('<path d="M9 15l6-6"/><path d="M10.5 6.5l1.8-1.8a4 4 0 0 1 5.7 '
                 '5.7L16.2 12.2"/><path d="M13.5 17.5l-1.8 1.8a4 4 0 0 1-5.7-5.7'
                 'L7.8 11.8"/>'),
    "scale": _svg('<path d="M12 3v18"/><path d="M7 21h10"/><path d="M5 7h14"/>'
                  '<path d="M5 7l-2.3 4.6a2.6 2.6 0 0 0 4.6 0z"/>'
                  '<path d="M19 7l-2.3 4.6a2.6 2.6 0 0 0 4.6 0z"/>'),
    "coins": _svg('<circle cx="8.5" cy="8.5" r="5"/>'
                  '<path d="M13.5 6.6A5 5 0 1 1 16 16.4"/>'),
    "clipboard": _svg('<rect x="5" y="4" width="14" height="17" rx="2"/>'
                      '<path d="M9 4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2H9z"/>'
                      '<path d="M9 12h6M9 16h6"/>'),
    "globe": _svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
                  '<path d="M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>'),
    "target": _svg('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/>'
                   '<path d="M12 12h.01"/>'),
    "bell": _svg('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>'
                 '<path d="M10.5 21a2 2 0 0 0 3 0"/>'),
    "route": _svg('<circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/>'
                  '<path d="M8 19h7a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h7"/>'),
    "heart": _svg('<path d="M12 20s-7-4.4-9.2-8.6A4.6 4.6 0 0 1 12 6.5 4.6 4.6 0 0 '
                  '1 21.2 11.4C19 15.6 12 20 12 20z"/>'),
}
_DEFAULT_ICON = _svg('<circle cx="12" cy="12" r="8"/>')


def _nav_with_icons() -> list[dict[str, Any]]:
    """_NAV with each entry's icon-key resolved to its SVG markup."""
    out: list[dict[str, Any]] = []
    for e in _NAV:
        entry = dict(e)
        entry["icon"] = _ICONS.get(str(e.get("icon", "")), _DEFAULT_ICON)
        out.append(entry)
    return out


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY unset (deny-by-default); 401 otherwise.
    Duplicated from the other admin modules to stay standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="operator console disabled — set RECUPERO_ADMIN_KEY to enable",
        )
    if not provided or not provided.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing X-Recupero-Admin-Key",
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid X-Recupero-Admin-Key",
        )


@router.get(
    "",
    response_class=HTMLResponse,
    summary="Operator console hub (HTML shell). Unauthenticated by design — "
            "no data; the key is entered client-side and used for the stats "
            "fetch + the linked consoles.",
)
def operator_hub() -> HTMLResponse:
    try:
        html = _HUB_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("operator_hub: template read failed: %s", exc)
        return HTMLResponse(
            content="<h1>Operator console unavailable</h1>"
                    "<p>Template could not be read.</p>",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


@router.get(
    "/story",
    response_class=HTMLResponse,
    summary="Recupero origin story (HTML narrative). Unauthenticated by design — "
            "public, data-free page linked from the hub's About group.",
)
def operator_story() -> HTMLResponse:
    try:
        html = _STORY_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("operator_story: template read failed: %s", exc)
        return HTMLResponse(
            content="<h1>Our story is momentarily unavailable</h1>",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


@router.get(
    "/app.css",
    summary="Shared console design-system stylesheet (Apple-grade). Public — "
            "styling only, no secret. Linked by every console template.",
    include_in_schema=False,
)
def operator_css() -> Response:
    from recupero.web.theme import CONSOLE_CSS
    return Response(
        content=CONSOLE_CSS, media_type="text/css",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get(
    "/app.js",
    summary="Shared console micro-interaction script (animated counters, row stagger). "
            "Public — behaviour only, no secret. Linked by every console template.",
    include_in_schema=False,
)
def operator_js() -> Response:
    from recupero.web.theme import CONSOLE_JS
    return Response(
        content=CONSOLE_JS, media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get(
    "/nav",
    summary="Public nav metadata for the hub grid (paths + labels; no secret). "
            "The linked consoles each enforce their own admin auth.",
)
def operator_nav() -> dict[str, Any]:
    return {"consoles": _nav_with_icons(), "count": len(_NAV)}


def _collect_stats() -> dict[str, Any]:
    """Best-effort quick-stats. EVERY stat is independently guarded — a missing
    DB / unavailable source yields null for that card, never a failed page."""
    stats: dict[str, Any] = {
        "pending_reviews": None,
        "watchlist_items": None,
        "watchlist_moved": None,
        "label_candidates_pending": None,
        # Filesystem case rollup — populated below; works WITHOUT a DB.
        "cases_total": None,
        "cases_with_brief": None,
        "cases_triaged": None,
        "cases_with_exhibit": None,
    }

    # Filesystem case rollup (no DB required): a bounded scan of the cases root,
    # matching case_index_api's deliverable-flag conventions (case.json /
    # freeze_brief.json / ai_triage.json / exhibit_pack). Fully guarded — a
    # missing config or cases dir yields nulls, never a failed page. Does NOT
    # parse case.json (robust against a single corrupted case).
    try:
        from recupero.config import load_config
        from recupero.storage.case_store import CaseStore
        cfg, _ = load_config()
        root = CaseStore(cfg).cases_root
        if root.exists():
            n_total = n_brief = n_triage = n_exhibit = 0
            for child in sorted(root.iterdir())[:500]:
                if not child.is_dir() or not (child / "case.json").is_file():
                    continue
                n_total += 1
                if (child / "freeze_brief.json").exists():
                    n_brief += 1
                if (child / "ai_triage.json").exists():
                    n_triage += 1
                if (child / "exhibit_pack").exists():
                    n_exhibit += 1
            stats["cases_total"] = n_total
            stats["cases_with_brief"] = n_brief
            stats["cases_triaged"] = n_triage
            stats["cases_with_exhibit"] = n_exhibit
    except Exception as exc:  # noqa: BLE001 — best-effort
        log.debug("operator stats: case scan unavailable: %s", exc)

    dsn = (os.environ.get("SUPABASE_DB_URL", "") or "").strip()
    if not dsn:
        return stats

    try:
        from recupero.monitoring.watchlist_dashboard import build_watchlist_overview
        ov = build_watchlist_overview(dsn=dsn, investigation_id=None)
        stats["watchlist_items"] = getattr(ov, "n_items", None)
        stats["watchlist_moved"] = getattr(ov, "n_moved", None)
    except Exception as exc:  # noqa: BLE001 — best-effort
        log.debug("operator stats: watchlist unavailable: %s", exc)

    try:
        from recupero.labels.auto_ingest import list_candidates
        stats["label_candidates_pending"] = len(
            list_candidates(status="pending_review", limit=500, dsn=dsn)
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("operator stats: label candidates unavailable: %s", exc)

    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM public.review_queue "
                "WHERE status = 'pending_review'"
            )
            row = cur.fetchone()
            stats["pending_reviews"] = int(row[0]) if row else 0
    except Exception as exc:  # noqa: BLE001
        log.debug("operator stats: review queue unavailable: %s", exc)

    return stats


@router.get(
    "/stats",
    summary="Live quick-stats for the hub cards (admin-gated, best-effort).",
)
def operator_stats(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    return _collect_stats()


__all__ = ("router",)
