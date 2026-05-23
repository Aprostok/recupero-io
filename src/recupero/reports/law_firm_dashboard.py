"""Law-firm portfolio dashboard renderer (v0.26.0).

Renders one HTML file per partner firm, summarizing their referred
caseload aggregate. The firm reads this monthly (or on-demand via
``recupero-ops law-firm-dashboard --firm <slug>``) to see their
portfolio's current state.

The shape mirrors cooperation_dashboard.py — one Jinja template, a
flat dict per template row, ``atomic_write_text`` to disk. The file
is overwritten on each run (the firm's dashboard is a snapshot, not
an archive).

Audience contract: the firm reads this. The dashboard MUST NOT leak:
  * Other firms' data
  * Recupero's internal SQL/case-IDs
  * Per-victim PII (only aggregate counts)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import atomic_write_text

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _safe_slug_segment(slug: str | None, *, fallback: str = "unknown") -> str:
    """Sanitize a firm slug into a path-safe filename segment.

    Z7 hardening: ``portfolio.firm_slug`` sources from ``public.law_firms``
    which is operator-writable (internal Recupero ops can insert rows).
    An adversary with write access could insert a slug like
    ``../../etc/passwd`` and have the renderer write outside the
    operator's chosen output_dir; or insert an empty slug that produces
    the degenerate filename ``law_firm_dashboard_.html``.
    """
    if not isinstance(slug, str):
        slug = str(slug) if slug is not None else ""
    cleaned = slug.replace("\\", "_").replace("/", "_")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", "")
    out_chars: list[str] = []
    for ch in cleaned:
        cp = ord(ch)
        if cp == 0:
            continue
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            continue
        if cp in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
                  0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            continue
        if ch.isalnum() or ch in "-_":
            out_chars.append(ch)
        elif ch == " ":
            out_chars.append("_")
    safe = "".join(out_chars).strip("._-")[:64]
    if not safe:
        return fallback
    return safe


def _fmt_usd(d: Decimal | None) -> str:
    """Z7: NaN / Infinity → $0.00 (no literal text leak into the firm-
    facing dashboard headline)."""
    if d is None:
        return "$0.00"
    try:
        if isinstance(d, Decimal):
            dd = d
        else:
            dd = Decimal(str(d))
    except Exception:  # noqa: BLE001
        return "$0.00"
    if not dd.is_finite():
        return "$0.00"
    return f"${dd:,.2f}"


def _fmt_pct(v: float | None) -> str | None:
    if v is None:
        return None
    return f"{v * 100:.0f}%"


def _portfolio_to_template_dict(portfolio: Any) -> dict[str, Any]:
    """Flatten a LawFirmPortfolio for the Jinja template."""
    top_issuers = []
    for s in portfolio.top_issuers:
        top_issuers.append({
            "issuer": s.issuer,
            "n_letters_sent": s.n_letters_sent,
            "n_freezes_observed": s.n_freezes_observed,
            "total_frozen_usd_human": _fmt_usd(s.total_frozen_usd),
            "cross_firm_response_rate_pct":
                _fmt_pct(s.cross_firm_response_rate),
            "cross_firm_full_freeze_rate_pct":
                _fmt_pct(s.cross_firm_full_freeze_rate),
        })
    return {
        "firm_slug": portfolio.firm_slug,
        "firm_name": portfolio.firm_name,
        "firm_status": portfolio.firm_status,
        "n_referred_cases": portfolio.n_referred_cases,
        "n_completed_traces": portfolio.n_completed_traces,
        "n_in_queue": portfolio.n_in_queue,
        "n_with_letters_sent": portfolio.n_with_letters_sent,
        "total_loss_usd_human": _fmt_usd(portfolio.total_loss_usd),
        "total_frozen_usd_human": _fmt_usd(portfolio.total_frozen_usd),
        "total_returned_to_victim_usd_human":
            _fmt_usd(portfolio.total_returned_to_victim_usd),
        "median_hours_intake_to_first_letter":
            portfolio.median_hours_intake_to_first_letter,
        "median_hours_letter_to_first_freeze":
            portfolio.median_hours_letter_to_first_freeze,
        "has_confident_throughput": portfolio.has_confident_throughput,
        "top_issuers": top_issuers,
        "latest_referral_at": portfolio.latest_referral_at,
        "latest_letter_sent_at": portfolio.latest_letter_sent_at,
    }


def render_law_firm_dashboard(
    firm_key: str,
    *,
    output_dir: Path,
    dsn: str | None,
) -> Path | None:
    """Render ONE firm's dashboard HTML.

    Returns the written path or ``None`` on any failure:
      * dsn unset
      * firm not found
      * render error

    Filename: ``law_firm_dashboard_<slug>.html``. The slug is sourced
    from the resolved firm row, so a UUID-keyed call still produces a
    human-readable filename.
    """
    if not dsn:
        log.warning("render_law_firm_dashboard: no DSN configured")
        return None

    from recupero.monitoring.law_firm_dashboard import build_firm_portfolio
    try:
        portfolio = build_firm_portfolio(firm_key, dsn=dsn)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_law_firm_dashboard: build_firm_portfolio failed "
            "for %r: %s", firm_key, exc,
        )
        return None

    if portfolio.firm_id is None:
        log.info(
            "render_law_firm_dashboard: no firm matches %r — nothing "
            "to render", firm_key,
        )
        return None

    ctx = _portfolio_to_template_dict(portfolio)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    # XSS defense-in-depth filters (safe_url / safe_text).
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.26.x"

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    try:
        html = env.get_template("law_firm_dashboard.html.j2").render(
            portfolio=ctx,
            generated_at=generated_at,
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_law_firm_dashboard: render failed for %r: %s",
            firm_key, exc,
        )
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    # Z7: sanitize firm_slug — path traversal + empty slug must not
    # escape output_dir / produce a degenerate filename.
    safe_slug = _safe_slug_segment(portfolio.firm_slug)
    out_path = output_dir / f"law_firm_dashboard_{safe_slug}.html"
    atomic_write_text(out_path, html)
    return out_path


def render_all_law_firm_dashboards(
    *,
    output_dir: Path,
    dsn: str | None,
) -> list[Path]:
    """Render dashboards for every active firm. Returns the list of
    paths actually written.

    v0.26.1 (HIGH-2): the previous implementation called
    ``build_all_firm_portfolios`` and then for each result called
    ``render_law_firm_dashboard`` — which itself calls
    ``build_firm_portfolio`` again, fully re-running every SQL query
    and every cooperation-enrich connection. With N firms × 5 top
    issuers, that's 1500+ redundant DB ops per --all invocation.
    The corrected flow enumerates active firm slugs once via a single
    SQL query and lets ``render_law_firm_dashboard`` do the only
    build per firm.
    """
    if not dsn:
        return []
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return []

    from psycopg.rows import dict_row

    from recupero._common import db_connect

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT slug
                  FROM public.law_firms
                 WHERE status = 'active'
                 ORDER BY slug ASC
                """
            )
            active_slugs = [r["slug"] for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_all_law_firm_dashboards: list active firms "
            "failed: %s", exc,
        )
        return []

    written: list[Path] = []
    for slug in active_slugs:
        path = render_law_firm_dashboard(
            slug, output_dir=output_dir, dsn=dsn,
        )
        if path is not None:
            written.append(path)
    return written


__all__ = (
    "render_law_firm_dashboard",
    "render_all_law_firm_dashboards",
)
