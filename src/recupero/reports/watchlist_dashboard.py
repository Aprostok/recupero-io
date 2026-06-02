"""Watchlist / Watcher dashboard renderer (v0.35.0).

Renders a single self-contained HTML page listing EVERYTHING under monitoring —
where each watched address sits, how much it holds, and whether it has MOVED
since the last re-check — for the operator's daily/monthly watch run. Mirrors
the law_firm_dashboard renderer (builder → flatten → Jinja → atomic_write_text).

The page is a snapshot, overwritten each render. Pair it with
``recupero-ops watchlist-run`` (which triggers ``worker.watch_tick`` to refresh
the on-chain snapshots) so the "moved / still-present" verdicts are current.
"""

from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import atomic_write_text, resolve_render_time
from recupero.monitoring.watchlist_dashboard import (
    _STATUS_PILL,
    WatchlistOverview,
    build_watchlist_overview,
)

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _fmt_usd(d: Decimal | None) -> str:
    if d is None:
        return "$0.00"
    try:
        dd = d if isinstance(d, Decimal) else Decimal(str(d))
    except Exception:  # noqa: BLE001
        return "$0.00"
    if not dd.is_finite():
        return "$0.00"
    return f"${dd:,.2f}"


def _fmt_ts(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:  # noqa: BLE001
        return "—"


def _fmt_age(hours: float | None) -> str:
    if hours is None:
        return "never checked"
    if hours < 1:
        return "<1h ago"
    if hours < 48:
        return f"{int(hours)}h ago"
    return f"{int(hours / 24)}d ago"


_MOVE_BADGE = {
    "moved": ("⚠ MOVED", "moved"),
    "still_present": ("✓ still present", "ok"),
    "never_checked": ("• never checked", "new"),
}


def _overview_to_template_dict(ov: WatchlistOverview) -> dict[str, Any]:
    items = []
    for it in ov.items:
        pill_emoji, pill_label = _STATUS_PILL.get(it.status, ("⬜", it.status))
        badge_text, badge_cls = _MOVE_BADGE.get(it.movement, ("?", "new"))
        items.append({
            "address": it.address,
            "chain": it.chain or "—",
            "status": it.status,
            "status_emoji": pill_emoji,
            "status_label": pill_label,
            "role": it.role or "—",
            "priority": it.priority,
            "issuer": it.issuer or "—",
            "asset_symbol": it.asset_symbol or "—",
            "label_name": it.label_name or "—",
            "balance_usd_human": _fmt_usd(it.balance_usd),
            "movement": it.movement,
            "movement_badge": badge_text,
            "movement_class": badge_cls,
            "last_delta_usd_human": (
                _fmt_usd(it.last_delta_usd) if it.last_delta_usd is not None else "—"
            ),
            "last_checked_human": _fmt_ts(it.last_checked_at),
            "age_human": _fmt_age(it.hours_since_check),
            "days_watched": it.days_watched if it.days_watched is not None else "—",
            "stale": it.stale,
            "explorer_url": it.explorer_url,
            "investigation_id": it.investigation_id or "—",
        })
    by_chain = [
        {"chain": ch or "unknown", "n": v["n"], "usd_human": _fmt_usd(v["usd"])}
        for ch, v in sorted(
            ov.by_chain.items(), key=lambda kv: -float(kv[1]["usd"]),
        )
    ]
    by_status = [
        {"status": s, "n": n,
         "emoji": _STATUS_PILL.get(s, ("⬜", s))[0]}
        for s, n in sorted(ov.by_status.items(), key=lambda kv: -kv[1])
    ]
    return {
        "n_items": ov.n_items,
        "total_watched_usd_human": _fmt_usd(ov.total_watched_usd),
        "total_still_present_usd_human": _fmt_usd(ov.total_still_present_usd),
        "total_moved_usd_human": _fmt_usd(ov.total_moved_usd),
        "n_moved": ov.n_moved,
        "n_still_present": ov.n_still_present,
        "n_never_checked": ov.n_never_checked,
        "n_stale": ov.n_stale,
        "stale_after_hours": ov.stale_after_hours,
        "by_chain": by_chain,
        "by_status": by_status,
        # NB: keyed "rows" not "items" — Jinja ``ov.items`` would resolve to the
        # dict's .items() method, not this list.
        "rows": items,
    }


def overview_to_dict(overview: WatchlistOverview) -> dict[str, Any]:
    """Public JSON-serializable view of an overview — same shape the template
    consumes (cards, by-status, by-chain, rows). Used by the live
    ``GET /v1/watchlist`` API so the in-browser console renders identically to
    the rendered-HTML dashboard."""
    return _overview_to_template_dict(overview)


def render_watchlist_dashboard(
    *,
    output_dir: Path,
    dsn: str | None,
    investigation_id: UUID | str | None = None,
    stale_after_hours: int = 24,
    overview: WatchlistOverview | None = None,
) -> Path | None:
    """Render the watchlist dashboard HTML. Returns the path, or None on no DSN.

    ``overview`` may be injected (tests / pre-built); otherwise it is built from
    the DB. Filename: ``watchlist_dashboard.html`` (global) or
    ``watchlist_dashboard_<investigation>.html`` when scoped.
    """
    if overview is None:
        if not dsn:
            log.warning("render_watchlist_dashboard: no DSN configured")
            return None
        overview = build_watchlist_overview(
            dsn=dsn, investigation_id=investigation_id,
            stale_after_hours=stale_after_hours,
        )

    ctx = _overview_to_template_dict(overview)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.35.x"

    generated_at = resolve_render_time().strftime("%Y-%m-%dT%H:%M:%S")

    try:
        html = env.get_template("watchlist_dashboard.html.j2").render(
            ov=ctx,
            generated_at=generated_at,
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("render_watchlist_dashboard: render failed: %s", exc)
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = ""
    if investigation_id is not None:
        safe = "".join(
            c for c in str(investigation_id) if c.isalnum() or c in "-_"
        )[:64]
        if safe:
            suffix = f"_{safe}"
    out_path = output_dir / f"watchlist_dashboard{suffix}.html"
    atomic_write_text(out_path, html)
    return out_path


__all__ = ("render_watchlist_dashboard", "overview_to_dict")
