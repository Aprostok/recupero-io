"""Daily watchlist digest deliverable — the "mini freeze" output.

Takes a :class:`recupero.worker.watch_tick.WatchTickReport` and emits
a short HTML letter (+ matching PDF) listing the wallets that crossed
materiality thresholds in the past tick. Designed as a 2–4 page
digest, in contrast to the full per-issuer freeze package which is
typically 8–12 pages and tailored to a single freeze target.

Distribution model: the worker uploads the digest to the
``watchlist-digest/<YYYY-MM-DD>/`` prefix in the Supabase bucket
(NOT under any investigation's prefix — the digest spans many
cases). The admin UI surfaces this prefix as a dated list operators
can subscribe to.

On a no-material-change tick the digest is still produced but is a
single "all clear" page — gives the operator confidence the
monitoring job actually ran and isn't silently failing. The
``all_clear`` Jinja branch keeps it short.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero import __version__
from recupero.worker.watch_tick import MaterialChange, WatchTickReport

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent / "reports" / "templates"


# Chain → address-page explorer URL prefix. Mirrors the table in
# reports/brief.py — kept inline so the watchlist digest doesn't
# need to import from there (separation of concerns: brief.py is
# per-investigation, this module is global watchlist).
_ADDRESS_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
}


@dataclass
class DigestBundle:
    """What a digest render produced."""
    digest_id: str
    html_path: Path
    pdf_path: Path | None  # None when WeasyPrint isn't importable
    bucket_prefix: str     # e.g. "watchlist-digest/2026-05-14/"


def generate_daily_digest(
    report: WatchTickReport,
    *,
    output_dir: Path,
    total_watched: int,
) -> DigestBundle:
    """Render the digest HTML + PDF for one watch-tick pass.

    ``total_watched`` is the count of active watchlist rows at tick
    time (passed in because the report only carries candidates that
    were eligible for snapshotting — rows in their cooldown window
    were skipped and don't appear in ``report.candidates``).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    tick_date = report.started_at.strftime("%Y-%m-%d")
    digest_id = f"DIGEST-{report.started_at.strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"

    ctx = _build_context(
        report=report, total_watched=total_watched,
        digest_id=digest_id, now=now, tick_date=tick_date,
    )

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    html = env.get_template("mini_freeze_digest.html.j2").render(**ctx)

    html_path = output_dir / f"{digest_id}.html"
    html_path.write_text(html, encoding="utf-8")
    log.info("digest HTML rendered: %s (%d bytes)", html_path.name, html_path.stat().st_size)

    pdf_path: Path | None = None
    try:
        from weasyprint import HTML as WeasyHTML
        pdf_path = html_path.with_suffix(".pdf")
        WeasyHTML(filename=str(html_path)).write_pdf(str(pdf_path))
        log.info("digest PDF rendered: %s (%d bytes)", pdf_path.name, pdf_path.stat().st_size)
    except Exception as exc:  # noqa: BLE001
        log.warning("digest PDF render skipped: %s", exc)
        pdf_path = None

    return DigestBundle(
        digest_id=digest_id,
        html_path=html_path,
        pdf_path=pdf_path,
        bucket_prefix=f"watchlist-digest/{tick_date}/",
    )


def _build_context(
    *,
    report: WatchTickReport,
    total_watched: int,
    digest_id: str,
    now: datetime,
    tick_date: str,
) -> dict[str, Any]:
    """Flatten the report into the Jinja-friendly context shape."""
    changes_ctx: list[dict[str, Any]] = []
    freezeable_count = 0
    total_outflow = Decimal(0)
    for mc in report.material_changes:
        if mc.is_freezeable:
            freezeable_count += 1
        if mc.delta_usd is not None and mc.delta_usd < 0:
            total_outflow += -mc.delta_usd  # accumulate as positive USD outflow
        changes_ctx.append(_change_to_ctx(mc))

    duration = (report.finished_at - report.started_at).total_seconds()

    return {
        "digest_id": digest_id,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "tick_date": tick_date,
        "tick_window": (
            f"{report.started_at.strftime('%Y-%m-%d %H:%M:%S')} → "
            f"{report.finished_at.strftime('%H:%M:%S')}"
        ),
        "tick_duration": f"{duration:.1f}s",
        "tick_started_human": report.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "tick_finished_human": report.finished_at.strftime("%Y-%m-%d %H:%M:%S"),
        "snapshotted": report.snapshotted,
        "total_watched": total_watched,
        "material_count": len(report.material_changes),
        "freezeable_count": freezeable_count,
        "total_outflow_usd": _fmt_usd(total_outflow),
        "error_count": len(report.errors),
        "changes": changes_ctx,
        "software_version": __version__,
    }


def _change_to_ctx(mc: MaterialChange) -> dict[str, Any]:
    explorer = _ADDRESS_EXPLORER_BY_CHAIN.get(
        mc.chain, "https://etherscan.io/address/"
    )
    explorer_url = f"{explorer}{mc.address}"
    row_class = "perp-row" if mc.role in {"perpetrator", "current_holder"} else ""

    return {
        "address": mc.address,
        "address_short": _short_addr(mc.address),
        "chain": mc.chain,
        "role": mc.role,
        "label_name": mc.label_name,
        "is_freezeable": mc.is_freezeable,
        "issuer": mc.issuer,
        "asset_symbol": mc.asset_symbol,
        "explorer_url": explorer_url,
        "row_class": row_class,
        "reason": mc.reason,
        "prior_taken_at_human": (
            mc.prior_taken_at.strftime("%Y-%m-%d %H:%M") if mc.prior_taken_at else "—"
        ),
        "new_taken_at_human": mc.new_taken_at.strftime("%Y-%m-%d %H:%M"),
        "prior_usd_human": _fmt_usd(mc.prior_usd),
        "new_usd_human": _fmt_usd(mc.new_usd),
        "prior_tx_count_human": str(mc.prior_tx_count) if mc.prior_tx_count is not None else "—",
        "new_tx_count_human": str(mc.new_tx_count) if mc.new_tx_count is not None else "—",
        "delta_usd_human": _fmt_signed_usd(mc.delta_usd),
        "tx_count_delta_human": _fmt_signed_count(mc.tx_count_delta),
    }


def _short_addr(addr: str) -> str:
    if not addr or len(addr) < 12:
        return addr or ""
    return f"{addr[:6]}…{addr[-4:]}"


def _fmt_usd(usd: Decimal | None) -> str:
    if usd is None:
        return "—"
    try:
        return f"{usd:,.2f}"
    except (ValueError, TypeError):
        return "—"


def _fmt_signed_usd(usd: Decimal | None) -> str:
    if usd is None:
        return "—"
    sign = "+" if usd >= 0 else "-"
    try:
        return f"{sign}${abs(usd):,.2f}"
    except (ValueError, TypeError):
        return "—"


def _fmt_signed_count(n: int | None) -> str:
    if n is None or n == 0:
        return "—"
    return f"+{n}" if n > 0 else str(n)


__all__ = ("DigestBundle", "generate_daily_digest")
