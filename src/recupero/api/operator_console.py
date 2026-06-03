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

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/console", tags=["operator-console"])

_HUB_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "operator_dashboard.html"
)

# Operator console navigation registry. Each entry = one linkable view.
# `live` marks views that exist now; phase agents append their entry here during
# the sequential integration step (never concurrently). Grouped for the grid.
_NAV: list[dict[str, Any]] = [
    {"group": "Casework", "label": "Review Gate", "emoji": "🚪",
     "path": "/review-gate", "live": True,
     "desc": "Approve / reject AI-drafted briefs before release."},
    {"group": "Monitoring", "label": "Watchlist", "emoji": "🛰️",
     "path": "/v1/watchlist/console", "live": True,
     "desc": "Live view of watched addresses + movement since last check."},
    {"group": "Screening", "label": "Address Profile", "emoji": "🔎",
     "path": "/v1/address/console", "live": True,
     "desc": "Screen any address: risk verdict, labels, sighting history."},
    # v0.35.20 UI batch-1 phase consoles.
    {"group": "Labels", "label": "Label Review", "emoji": "🏷️",
     "path": "/v1/label-review/console", "live": True,
     "desc": "Review auto-ingested label candidates (promote/reject via API)."},
    {"group": "Ops", "label": "Cron Health", "emoji": "⚙️",
     "path": "/v1/ops/cron-console", "live": True,
     "desc": "Scheduled-job health + last-error for each background job."},
    {"group": "Data health", "label": "Label Freshness", "emoji": "🕒",
     "path": "/v1/freshness/console", "live": True,
     "desc": "Per-source label freshness vs SLA; OFAC feed-age alarm."},
    # v0.35.21 UI batch-2 phase consoles.
    {"group": "Casework", "label": "Graph Analysis", "emoji": "🕸️",
     "path": "/v1/graph-analysis/console", "live": True,
     "desc": "Consolidation hubs (where split funds re-merge) + value cycles "
             "for a case."},
    {"group": "Casework", "label": "Case Index", "emoji": "📁",
     "path": "/v1/cases/console", "live": True,
     "desc": "All traced cases + which deliverables each has."},
    # v0.35.22 UI batch-3 phase consoles.
    {"group": "Casework", "label": "Exhibit Pack", "emoji": "📑",
     "path": "/v1/exhibit-pack/console", "live": True,
     "desc": "Court-admissible exhibit index — every case artifact as Exhibit "
             "A, B, C… with SHA-256 hash and byte size."},
    {"group": "Filings", "label": "SAR / STR Filing", "emoji": "🏛️",
     "path": "/v1/sar-filing/console", "live": True,
     "desc": "FinCEN SAR / NCA SAR / AMLD STR filing DRAFT from a case's freeze "
             "brief — Recupero is not the filer."},
    {"group": "Screening", "label": "Bulk Screening", "emoji": "📊",
     "path": "/v1/screening/console", "live": True,
     "desc": "Paste many addresses; bulk sanctions/mixer/drainer risk screen "
             "via the high-throughput offline cache."},
    # v0.35.23 UI batch-4 phase consoles.
    {"group": "Casework", "label": "AI Triage", "emoji": "🧠",
     "path": "/v1/ai-triage/console", "live": True,
     "desc": "Plain-English AI triage (summary, next steps, completeness gaps) "
             "— read-only view of the stored ai_triage.json; never calls the "
             "model."},
    {"group": "Intelligence", "label": "Cooperation", "emoji": "🤝",
     "path": "/v1/cooperation/console", "live": True,
     "desc": "Per-issuer cooperation profiles: freeze-letter response/freeze "
             "rates, response times, recommended legal instrument, black-hole "
             "flags."},
    # v0.35.24 UI batch-5 phase consoles.
    {"group": "Intelligence", "label": "Law Firm Dashboard", "emoji": "⚖️",
     "path": "/v1/law-firm/console", "live": True,
     "desc": "Per-law-firm portfolio rollups: cases referred/completed/in-queue, "
             "money frozen & returned, throughput medians, top issuers."},
    {"group": "Casework", "label": "Recovery Snapshot", "emoji": "💰",
     "path": "/v1/recovery-snapshot/console", "live": True,
     "desc": "Pre-engagement recovery estimate for a case — expected "
             "net-to-victim, per-issuer breakdown, drivers/ROI (read-only)."},
]


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
    "/nav",
    summary="Public nav metadata for the hub grid (paths + labels; no secret). "
            "The linked consoles each enforce their own admin auth.",
)
def operator_nav() -> dict[str, Any]:
    return {"consoles": _NAV, "count": len(_NAV)}


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
