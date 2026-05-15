"""Per-investigation API surface for Jacob's admin UI.

This is the worker-side machinery that backs the admin UI's
investigation list + detail views. Two functions cover the
wallet-trace and case-driven flows uniformly:

  * ``list_investigations(...)`` — paginated list with filters
    (status, chain, type=wallet_trace|case_driven, label_prefix).
    Backs the admin UI's investigation index page.

  * ``get_investigation_detail(...)`` — one row + bucket artifact
    metadata + short-lived signed URLs. Backs the per-investigation
    detail page (the one that renders trace_report.html in an
    iframe and surfaces flow-diagram + raw-case downloads).

Both are pure-read, both pool through Supabase's connection pooler,
both return plain JSON-serializable dicts so the HTTP wrapper in
``_health_server.py`` can hand them to ``json.dumps()`` directly.

Signed URLs are 60-minute TTL — long enough that the admin UI
doesn't have to re-fetch between page loads, short enough that a
copy-pasted URL doesn't leak access indefinitely. The admin UI is
expected to re-call ``get_investigation_detail`` if its cached URLs
get close to expiry.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


# Default signed-URL lifetime. 60 minutes balances UI caching against
# the risk of a copy-pasted URL leaking access. Override per-call via
# the ``signed_url_ttl_sec`` kwarg.
_DEFAULT_SIGNED_URL_TTL_SEC = 3600

# Default page size for the list endpoint. Picked to fit comfortably
# in one screen of the admin UI's investigation index without forcing
# a scroll, and small enough that the JSON payload stays under ~30KB
# even for chains with rich artifact metadata.
_DEFAULT_LIST_LIMIT = 25
_MAX_LIST_LIMIT = 100


# Storage bucket the worker writes to. Must match
# ``SupabaseCaseStore``'s ``bucket`` default — keep them in sync.
_BUCKET = "investigation-files"


# Column projection for the list endpoint. Keep this tight — the
# index page only renders a few columns, and shipping the full row
# (with error_message which can be 4KB) for 25 items wastes bandwidth.
_LIST_COLUMNS = (
    "id, case_id, status, chain, seed_address, label, "
    "triggered_by, triggered_at, completed_at, failed_at, "
    "skip_editorial, skip_freeze_briefs, max_depth, "
    "total_loss_usd, max_recoverable_usd, freezable_issuers"
)


# ----- Public API ----- #


def list_investigations(
    *,
    dsn: str,
    status: str | None = None,
    chain: str | None = None,
    investigation_type: str | None = None,
    label_prefix: str | None = None,
    limit: int = _DEFAULT_LIST_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Paginated list of investigations matching the given filters.

    Filters:

      * ``status``: one of pending/claimed/tracing/.../complete/failed.
        Matches the raw DB column. Pass None for "any status".
      * ``chain``: one of ethereum/arbitrum/polygon/base/bsc/solana/hyperliquid.
      * ``investigation_type``: ``"wallet_trace"`` (case_id IS NULL)
        or ``"case_driven"`` (case_id IS NOT NULL). None for both.
      * ``label_prefix``: case-insensitive prefix match on the label
        column. Useful for finding canaries, batch tags, etc.

    Pagination via ``limit`` (1–100, default 25) + ``offset``.

    Returns a dict shape:

      {
        "items":  [ { ...flat row + is_wallet_trace + duration_seconds }, ... ],
        "total":  int (matching filters, BEFORE limit/offset),
        "limit":  int,
        "offset": int,
      }
    """
    limit = max(1, min(_MAX_LIST_LIMIT, int(limit)))
    offset = max(0, int(offset))

    where_clauses: list[str] = []
    params: dict[str, Any] = {}
    if status:
        where_clauses.append("status = %(status)s")
        params["status"] = status
    if chain:
        where_clauses.append("chain = %(chain)s")
        params["chain"] = chain
    if investigation_type == "wallet_trace":
        where_clauses.append("case_id IS NULL")
    elif investigation_type == "case_driven":
        where_clauses.append("case_id IS NOT NULL")
    if label_prefix:
        where_clauses.append("LOWER(COALESCE(label, '')) LIKE %(label_pfx)s")
        params["label_pfx"] = label_prefix.lower() + "%"
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    list_sql = f"""
        SELECT {_LIST_COLUMNS}
          FROM public.investigations
          {where_sql}
         ORDER BY COALESCE(triggered_at, completed_at, failed_at, NOW()) DESC NULLS LAST
         LIMIT %(limit)s OFFSET %(offset)s
    """
    count_sql = f"SELECT COUNT(*) AS n FROM public.investigations {where_sql}"

    params_list = dict(params, limit=limit, offset=offset)
    pooled = _pooled_dsn(dsn)

    items: list[dict[str, Any]] = []
    total = 0
    with psycopg.connect(pooled, autocommit=True, row_factory=dict_row,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(count_sql, params)
            row = cur.fetchone()
            total = int(row["n"]) if row else 0

            cur.execute(list_sql, params_list)
            for r in cur.fetchall():
                items.append(_render_list_row(r))

    return {"items": items, "total": total, "limit": limit, "offset": offset}


def get_investigation_detail(
    *,
    dsn: str,
    supabase_url: str,
    service_role_key: str,
    investigation_id: UUID | str,
    signed_url_ttl_sec: int = _DEFAULT_SIGNED_URL_TTL_SEC,
) -> dict[str, Any] | None:
    """One investigation row + artifact metadata + signed URLs.

    Returns None if the investigation doesn't exist. Otherwise returns
    the full investigation row (with computed fields like ``is_wallet_trace``
    and ``duration_seconds``), an ``artifacts`` dict mapping each
    bucket file to {name, size, signed_url}, and a ``summary`` dict
    pulled from case.json if present.

    Errors fetching the bucket listing or building signed URLs are
    NOT fatal — they log a warning and the response carries empty
    ``artifacts`` (so the UI can still render the row metadata).
    This matches the dashboard_summary's defensive pattern.
    """
    inv_id_str = str(investigation_id)

    pooled = _pooled_dsn(dsn)
    with psycopg.connect(pooled, autocommit=True, row_factory=dict_row,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM public.investigations WHERE id = %s",
                        (inv_id_str,))
            row = cur.fetchone()
    if row is None:
        return None

    detail = _render_detail_row(row)

    try:
        artifacts = _build_artifacts_map(
            supabase_url=supabase_url,
            service_role_key=service_role_key,
            investigation_id=inv_id_str,
            ttl_sec=signed_url_ttl_sec,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("artifact listing failed for inv=%s: %s", inv_id_str, exc)
        artifacts = _empty_artifacts()

    detail["artifacts"] = artifacts
    detail["summary"] = _build_summary(
        supabase_url=supabase_url,
        service_role_key=service_role_key,
        investigation_id=inv_id_str,
    )
    return detail


# ----- Internals ----- #


def _render_list_row(row: dict[str, Any]) -> dict[str, Any]:
    """Render one DB row into the list-item shape. Adds computed
    fields and stringifies non-JSON-native types."""
    out = {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]) if row["case_id"] else None,
        "status": row["status"],
        "chain": row["chain"],
        "seed_address": row["seed_address"],
        "label": row.get("label"),
        "triggered_by": row.get("triggered_by"),
        "triggered_at": _iso(row.get("triggered_at")),
        "completed_at": _iso(row.get("completed_at")),
        "failed_at": _iso(row.get("failed_at")),
        "max_depth": row.get("max_depth"),
        "skip_editorial": bool(row.get("skip_editorial")),
        "skip_freeze_briefs": bool(row.get("skip_freeze_briefs")),
        "total_loss_usd": _decimal_str(row.get("total_loss_usd")),
        "max_recoverable_usd": _decimal_str(row.get("max_recoverable_usd")),
        "freezable_issuers": row.get("freezable_issuers"),
        # Computed convenience for the UI — saves a per-row case_id null check.
        "is_wallet_trace": row["case_id"] is None,
    }
    return out


def _render_detail_row(row: dict[str, Any]) -> dict[str, Any]:
    """Full DB row for the detail view, with computed fields.

    Adds ``duration_seconds`` (claimed_at → completed_at/failed_at)
    and ``is_wallet_trace`` so the UI doesn't have to compute them
    from raw columns.
    """
    out = {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]) if row["case_id"] else None,
        "status": row["status"],
        "chain": row["chain"],
        "seed_address": row["seed_address"],
        "label": row.get("label"),
        "max_depth": row.get("max_depth"),
        "dust_threshold_usd": _decimal_str(row.get("dust_threshold_usd")),
        "incident_time": _iso(row.get("incident_time")),
        "skip_editorial": bool(row.get("skip_editorial")),
        "skip_freeze_briefs": bool(row.get("skip_freeze_briefs")),

        "triggered_by": row.get("triggered_by"),
        "triggered_at": _iso(row.get("triggered_at")),
        "worker_id": row.get("worker_id"),
        "claimed_at": _iso(row.get("claimed_at")),
        "last_heartbeat_at": _iso(row.get("last_heartbeat_at")),
        "started_at": _iso(row.get("started_at")),
        "completed_at": _iso(row.get("completed_at")),
        "failed_at": _iso(row.get("failed_at")),
        "error_stage": row.get("error_stage"),
        "error_message": row.get("error_message"),
        "review_required_at": _iso(row.get("review_required_at")),
        "reviewed_at": _iso(row.get("reviewed_at")),
        "reviewed_by": row.get("reviewed_by"),
        "review_notes": row.get("review_notes"),

        "total_loss_usd": _decimal_str(row.get("total_loss_usd")),
        "max_recoverable_usd": _decimal_str(row.get("max_recoverable_usd")),
        "api_costs_usd": _decimal_str(row.get("api_costs_usd")),
        "freezable_issuers": row.get("freezable_issuers"),
        "supabase_storage_path": row.get("supabase_storage_path"),

        "is_followup_run": bool(row.get("is_followup_run")),
        "prior_investigation_id": (
            str(row["prior_investigation_id"])
            if row.get("prior_investigation_id") else None
        ),
        "material_change_detected": bool(row.get("material_change_detected")),
        "change_summary": row.get("change_summary"),

        "is_wallet_trace": row["case_id"] is None,
        "duration_seconds": _compute_duration_secs(row),
    }
    return out


def _compute_duration_secs(row: dict[str, Any]) -> float | None:
    """Wall-clock seconds from claim to terminal state. Returns None
    if the row hasn't terminated yet or never claimed."""
    claimed = row.get("claimed_at")
    end = row.get("completed_at") or row.get("failed_at")
    if not claimed or not end:
        return None
    delta = (end - claimed).total_seconds()
    return round(delta, 2)


def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    return dt.isoformat()


def _decimal_str(d: Decimal | None) -> str | None:
    if d is None:
        return None
    return str(d)


# ----- Artifacts ----- #


def _empty_artifacts() -> dict[str, Any]:
    return {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [],
    }


def _build_artifacts_map(
    *,
    supabase_url: str,
    service_role_key: str,
    investigation_id: str,
    ttl_sec: int,
) -> dict[str, Any]:
    """List the bucket under ``investigations/<id>/`` and
    ``investigations/<id>/briefs/``, then bucket each file into a
    structured category for the UI.

    Categories (matches the worker's deliverable taxonomy):

      * trace_report  — internal-facing wallet-trace summary (HTML + PDF)
      * flow_diagram  — fund-flow visualization (SVG + PDF)
      * raw           — case.json, manifest.json, transfers.csv, etc.
      * freeze_letters — per-issuer freeze requests + LE handoffs
                        (case-driven runs only — wallet traces emit []).
    """
    prefix_root = f"investigations/{investigation_id}/"
    prefix_briefs = f"investigations/{investigation_id}/briefs/"

    root_files = _list_bucket(supabase_url, service_role_key, prefix_root)
    briefs_files = _list_bucket(supabase_url, service_role_key, prefix_briefs)

    out = _empty_artifacts()

    # Root-level files are the "raw" category. Skip folder entries
    # (Supabase returns them with metadata=None).
    for f in root_files:
        name = f.get("name") or ""
        if not name or _is_folder_entry(f):
            continue
        key = _raw_key_for(name)
        if key is None:
            continue
        out["raw"][key] = _artifact_entry(
            name=name,
            metadata=f.get("metadata") or {},
            path=prefix_root + name,
            supabase_url=supabase_url,
            service_role_key=service_role_key,
            ttl_sec=ttl_sec,
        )

    # Group briefs/ files by hash prefix so HTML + PDF pairs round-trip
    # into the same dict entry.
    freeze_groups: dict[str, dict[str, Any]] = {}
    for f in briefs_files:
        name = f.get("name") or ""
        if not name or _is_folder_entry(f):
            continue
        entry = _artifact_entry(
            name=name,
            metadata=f.get("metadata") or {},
            path=prefix_briefs + name,
            supabase_url=supabase_url,
            service_role_key=service_role_key,
            ttl_sec=ttl_sec,
        )

        if name.startswith("trace_report_") and name.endswith(".html"):
            out["trace_report"]["html"] = entry
        elif name.startswith("trace_report_") and name.endswith(".pdf"):
            out["trace_report"]["pdf"] = entry
        elif name.startswith("flow_") and name.endswith(".svg"):
            out["flow_diagram"]["svg"] = entry
        elif name.startswith("flow_") and name.endswith(".pdf"):
            out["flow_diagram"]["pdf"] = entry
        elif name.startswith("freeze_request_") or name.startswith("le_handoff_"):
            # group on the trailing hash so {issuer}_<hash>.html and
            # {issuer}_<hash>.pdf land together.
            slug, ext = _parse_freeze_filename(name)
            grp = freeze_groups.setdefault(
                slug,
                {"issuer_slug": _issuer_from_slug(slug), "html": None,
                 "pdf": None, "le_handoff_html": None, "le_handoff_pdf": None},
            )
            if name.startswith("freeze_request_") and ext == ".html":
                grp["html"] = entry
            elif name.startswith("freeze_request_") and ext == ".pdf":
                grp["pdf"] = entry
            elif name.startswith("le_handoff_") and ext == ".html":
                grp["le_handoff_html"] = entry
            elif name.startswith("le_handoff_") and ext == ".pdf":
                grp["le_handoff_pdf"] = entry

    out["freeze_letters"] = list(freeze_groups.values())
    return out


def _raw_key_for(name: str) -> str | None:
    """Canonical key in artifacts.raw for a known root-level file.
    Returns None for unknown files so we don't surface random bucket
    detritus to the UI (operators sometimes drop test files in)."""
    mapping = {
        "case.json": "case_json",
        "manifest.json": "manifest_json",
        "freeze_asks.json": "freeze_asks",
        "freeze_brief.json": "freeze_brief",
        "transfers.csv": "transfers_csv",
        "victim.json": "victim_json",
        "brief_editorial.json": "editorial_json",
    }
    return mapping.get(name)


def _is_folder_entry(f: dict[str, Any]) -> bool:
    """Supabase returns subdirectories as entries with metadata=None.
    Filter them out so they don't show up as broken artifacts."""
    return f.get("metadata") is None


def _parse_freeze_filename(name: str) -> tuple[str, str]:
    """Split ``freeze_request_circle_a1b2c3d4.html`` into
    ('circle_a1b2c3d4', '.html'). The slug includes both the issuer
    and the file's per-brief hash so HTML + PDF pair correctly."""
    # Match either freeze_request_ or le_handoff_ prefix.
    for prefix in ("freeze_request_", "le_handoff_"):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            # split off the extension
            dot = rest.rfind(".")
            if dot < 0:
                return rest, ""
            return rest[:dot], rest[dot:]
    return name, ""


def _issuer_from_slug(slug: str) -> str:
    """Extract a human-readable issuer name from
    ``circle_a1b2c3d4`` → "Circle". Falls back to the slug if there's
    no obvious issuer prefix."""
    # The slug is ``<issuer>_<hash8>``. Strip trailing _<hex>.
    m = re.match(r"^([a-z][a-z0-9_-]*?)_[a-f0-9]{6,16}$", slug)
    issuer = m.group(1) if m else slug
    # Title-case for display: "circle" → "Circle", "tether" → "Tether".
    return issuer.replace("_", " ").title()


def _artifact_entry(
    *,
    name: str,
    metadata: dict[str, Any],
    path: str,
    supabase_url: str,
    service_role_key: str,
    ttl_sec: int,
) -> dict[str, Any]:
    """One artifact entry: filename, size, mime, signed URL.

    Signed-URL build failures don't fail the row — log a warning
    and emit signed_url=None so the UI can still surface the
    filename and let the operator know what's there.
    """
    size = metadata.get("size")
    mime = metadata.get("mimetype")
    try:
        signed_url = _sign_storage_url(
            supabase_url=supabase_url,
            service_role_key=service_role_key,
            object_path=path,
            ttl_sec=ttl_sec,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("signed URL failed for %s: %s", path, exc)
        signed_url = None
    return {
        "name": name,
        "size_bytes": int(size) if size is not None else None,
        "mimetype": mime,
        "signed_url": signed_url,
    }


def _list_bucket(supabase_url: str, service_role_key: str, prefix: str) -> list[dict[str, Any]]:
    """POST /storage/v1/object/list/<bucket> with a prefix filter."""
    url = f"{supabase_url.rstrip('/')}/storage/v1/object/list/{_BUCKET}"
    body = json.dumps({"prefix": prefix, "limit": 200, "offset": 0}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {service_role_key}",
            "apikey": service_role_key,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _sign_storage_url(
    *,
    supabase_url: str,
    service_role_key: str,
    object_path: str,
    ttl_sec: int,
) -> str:
    """Generate a short-lived signed URL for one bucket object.

    POST /storage/v1/object/sign/<bucket>/<path> returns
    ``{"signedURL": "/object/sign/bucket/path?token=..."}``; the
    fully-qualified URL is ``{supabase_url}{signedURL}``.
    """
    path_encoded = urllib.parse.quote(object_path, safe="/")
    url = (
        f"{supabase_url.rstrip('/')}/storage/v1/object/sign/"
        f"{_BUCKET}/{path_encoded}"
    )
    body = json.dumps({"expiresIn": int(ttl_sec)}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {service_role_key}",
            "apikey": service_role_key,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    signed_path = payload.get("signedURL") or payload.get("signedUrl")
    if not signed_path:
        raise RuntimeError(f"sign API returned no URL: {payload!r}")
    return f"{supabase_url.rstrip('/')}/storage/v1{signed_path}"


# ----- Summary ----- #


def _build_summary(
    *,
    supabase_url: str,
    service_role_key: str,
    investigation_id: str,
) -> dict[str, Any]:
    """Pull a few headline numbers from case.json so the UI doesn't
    have to fetch + parse the full case to render the detail page's
    summary card. Best-effort — missing case.json yields zeros."""
    out = {
        "transfers": 0,
        "addresses_traced": 0,
        "total_usd_out": None,
        "exchange_endpoints": 0,
        "unlabeled_counterparties": 0,
    }
    try:
        url = (
            f"{supabase_url.rstrip('/')}/storage/v1/object/{_BUCKET}/"
            f"investigations/{investigation_id}/case.json"
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {service_role_key}",
                "apikey": service_role_key,
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            case = json.loads(resp.read().decode("utf-8"))
        transfers = case.get("transfers") or []
        out["transfers"] = len(transfers)
        addresses = {t.get("from_address") for t in transfers} | {t.get("to_address") for t in transfers}
        addresses.discard(None)
        out["addresses_traced"] = len(addresses) or 1  # at least seed
        out["total_usd_out"] = case.get("total_usd_out")
        out["exchange_endpoints"] = len(case.get("exchange_endpoints") or [])
        out["unlabeled_counterparties"] = len(case.get("unlabeled_counterparties") or [])
    except Exception as exc:  # noqa: BLE001
        log.debug("summary build for inv=%s skipped: %s", investigation_id, exc)
    return out


# ----- DSN pooler (mirrors dashboard_summary._pooled_dsn) ----- #


def _pooled_dsn(dsn: str) -> str:
    if "db." in dsn and ".supabase.co" in dsn:
        m = re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co",
            dsn,
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            return (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    return dsn


__all__ = ("list_investigations", "get_investigation_detail")
