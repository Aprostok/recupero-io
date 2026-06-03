"""Case-Index operator console + admin JSON endpoint (v0.35.16).

The casework home: a live, authenticated listing of every locally-traced case
plus which deliverables each one has on disk (freeze brief, AI triage, exhibit
pack, interactive graph). It is a fast directory scan — it deliberately does NOT
parse ``case.json`` — so it stays robust against a single corrupted case and
loads instantly even with hundreds of cases. From here the operator copies a
``case_id`` into the per-case views (e.g. the Graph Analysis console).

Security model (mirrors ``/v1/freshness`` / ``/v1/graph-analysis``): the CONSOLE
shell at ``/v1/cases/console`` is served unauthenticated and contains NO data —
every dynamic value is fetched client-side from the admin-gated JSON endpoint
with the operator's ``X-Recupero-Admin-Key``. A browser navigation cannot send a
custom auth header, so server-gating the HTML itself would force the key into the
URL (leaks into logs/history); the shell+client-fetch pattern keeps the key in a
header and leaks nothing to an unauthenticated visitor.

  * ``GET  /v1/cases``           — admin-gated JSON (cases + deliverable flags)
  * ``GET  /v1/cases/console``   — unauthenticated shell (HTML+JS); no data
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/cases", tags=["cases"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "case_index_console.html"
)

# Cap the directory scan so a runaway cases_root (thousands of dirs) can't turn
# the index into a slow, memory-heavy response. 500 is a generous ceiling for a
# single operator's local case load.
_MAX_CASES = 500


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Same shape as cron_admin_api / review_api — duplicated to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case-index API disabled — set RECUPERO_ADMIN_KEY to enable",
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
    summary=(
        "Case index JSON — every locally-traced case plus which deliverables "
        "(freeze brief, AI triage, exhibit pack, graph) each has on disk. Fast "
        "directory scan; does NOT parse case.json. Admin-gated."
    ),
)
def get_cases(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    from recupero.config import load_config
    from recupero.storage.case_store import CaseStore, _validate_case_id

    try:
        cfg, _ = load_config()
        store = CaseStore(cfg)
        root = store.cases_root
        if not root.exists():
            return {"cases": [], "count": 0}

        cases: list[dict[str, Any]] = []
        for child in sorted(root.iterdir()):
            if len(cases) >= _MAX_CASES:
                break
            if not child.is_dir():
                continue
            # Defense-in-depth: skip any subdirectory name that wouldn't pass
            # case_id validation (control chars, traversal patterns, reserved
            # device names) — we never want to surface such an entry as a
            # clickable/copyable case_id.
            try:
                _validate_case_id(child.name)
            except ValueError:
                continue
            if not (child / "case.json").is_file():
                continue
            cases.append(
                {
                    "case_id": child.name,
                    "has_brief": (child / "freeze_brief.json").exists(),
                    "has_ai_triage": (child / "ai_triage.json").exists(),
                    "has_exhibit_pack": (child / "exhibit_pack").exists(),
                    "has_graph": (child / "graph_ui.html").exists(),
                }
            )
        return {"cases": cases, "count": len(cases)}
    except Exception as exc:  # noqa: BLE001 — never 500 the operator console
        log.warning("get_cases: scan failed: %s", exc)
        return {"cases": [], "count": 0, "error": str(exc)}


# ----- Per-case artifact browser (v0.35: "click a case → view its files") ----- #

_MAX_ARTIFACT_BYTES = 25 * 1024 * 1024  # 25 MiB inline/serve cap
_MAX_ARTIFACT_ENTRIES = 2000

# Display order for the per-case file browser. Each file is bucketed by its
# subdir / filename prefix so the operator sees deliverables grouped, not a
# flat dump.
_CATEGORY_ORDER = (
    "Law Enforcement",
    "Freeze",
    "Regulatory",
    "Victim / Engagement",
    "Forensics",
    "Exhibit & Custody",
    "Manifests",
    "Other",
)

_VIEW_BY_EXT = {
    ".html": "html", ".svg": "html",
    ".json": "text", ".jsonl": "text", ".csv": "text", ".txt": "text", ".md": "text",
}

_MEDIA_BY_EXT = {
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".jsonl": "application/json",
    ".csv": "text/csv; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".pdf": "application/pdf",
}


def _classify_artifact(rel_posix: str) -> str:
    """Bucket a case-relative artifact path into a display category."""
    low = rel_posix.lower()
    name = low.rsplit("/", 1)[-1]
    if low.startswith("legal_requests/") or name.startswith(
        ("le_handoff", "subpoena", "mlat", "fincen_314")
    ):
        return "Law Enforcement"
    if name.startswith(("freeze_request", "exchange_freeze", "issuer_freeze")):
        return "Freeze"
    if low.startswith("regulatory_filing/") or "_sar" in name or name.startswith("sar"):
        return "Regulatory"
    if name.startswith(("victim_summary", "recovery_snapshot", "engagement_letter")):
        return "Victim / Engagement"
    if low.startswith(("exhibit_pack/", "custody/")):
        return "Exhibit & Custody"
    if name.startswith(("trace_report", "flow_", "investigator_findings")) or name in {
        "transfers.csv", "freeze_brief.json", "ai_triage.json", "graph_ui.html",
    }:
        return "Forensics"
    if name.startswith("manifest") or name == "case.json":
        return "Manifests"
    return "Other"


def _resolve_case_dir(case_id: str) -> Path:
    """Validate ``case_id`` and return its on-disk dir (no mkdir). 400 on a bad
    id, 404 when the case dir doesn't exist."""
    from recupero.config import load_config
    from recupero.storage.case_store import CaseStore, _validate_case_id

    try:
        _validate_case_id(case_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid case_id: {exc}",
        ) from exc
    cfg, _ = load_config()
    # NOTE: cases_root / case_id directly — NEVER store.case_dir() (it mkdirs).
    case_dir = CaseStore(cfg).cases_root / case_id
    if not case_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="case not found"
        )
    return case_dir


@router.get(
    "/{case_id}/artifacts",
    summary=(
        "Admin-gated: every deliverable file for one case, grouped by category "
        "(LE handoff, freeze, regulatory, forensics, exhibit/custody, …)."
    ),
)
def list_case_artifacts(
    case_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    case_dir = _resolve_case_dir(case_id)
    root = case_dir.resolve()
    items: list[dict[str, Any]] = []
    for p in sorted(case_dir.rglob("*")):
        if len(items) >= _MAX_ARTIFACT_ENTRIES:
            break
        try:
            if p.is_symlink() or not p.is_file():
                continue
            # Defense-in-depth: a resolved path must stay inside the case dir
            # (catches symlinked files pointing elsewhere).
            rel = p.resolve().relative_to(root)
            size = p.stat().st_size
        except (OSError, ValueError):
            continue
        rel_posix = rel.as_posix()
        ext = p.suffix.lower()
        items.append({
            "name": p.name,
            "path": rel_posix,
            "category": _classify_artifact(rel_posix),
            "ext": ext,
            "size_bytes": size,
            "view": _VIEW_BY_EXT.get(ext, "download"),
        })
    order = {c: i for i, c in enumerate(_CATEGORY_ORDER)}
    items.sort(key=lambda d: (order.get(d["category"], 99), d["path"]))
    return {"case_id": case_id, "artifacts": items, "count": len(items)}


@router.get(
    "/{case_id}/artifact",
    summary=(
        "Admin-gated: serve ONE case artifact's content for inline viewing / "
        "download. Path-traversal-guarded + size-capped."
    ),
)
def get_case_artifact(
    case_id: str,
    path: str = Query(..., max_length=400, description="case-relative file path"),
    x_recupero_admin_key: str | None = Header(default=None),
) -> Response:
    _require_admin_auth(x_recupero_admin_key)
    case_dir = _resolve_case_dir(case_id)
    root = case_dir.resolve()
    # Reject absolute paths + any traversal segment before touching the FS.
    norm = path.replace("\\", "/")
    if not path or norm.startswith("/") or ".." in norm.split("/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid artifact path"
        )
    target = (case_dir / norm).resolve()
    if not target.is_relative_to(root):  # symlink/.. escape → blocked
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="artifact path escapes the case directory",
        )
    if not target.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found"
        )
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="artifact not found"
        ) from exc
    if size > _MAX_ARTIFACT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"artifact too large to serve ({size} bytes)",
        )
    ext = target.suffix.lower()
    media = _MEDIA_BY_EXT.get(ext, "application/octet-stream")
    headers = {"X-Content-Type-Options": "nosniff"}
    if media == "application/octet-stream":
        headers["Content-Disposition"] = f'attachment; filename="{target.name}"'
    return Response(content=target.read_bytes(), media_type=media, headers=headers)


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Operator console (HTML shell). Unauthenticated by design — contains "
        "NO data; fetches /v1/cases client-side with the admin key."
    ),
)
def case_index_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("case_index_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Case Index console unavailable</h1>"
                "<p>Template could not be read; inspect the cases directory "
                "directly under <code>data/cases/</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
