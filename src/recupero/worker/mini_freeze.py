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

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero import __version__
from recupero.worker.watch_tick import MaterialChange, WatchTickReport

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent / "reports" / "templates"


# Chain → address-page explorer URL prefix — centralized in _common.
# Pre-flatten this was an inline duplicate missing bitcoin + tron;
# watchlist digests for those chains silently dropped explorer links.
from recupero._common import (
    ADDRESS_EXPLORER_BY_CHAIN as _ADDRESS_EXPLORER_BY_CHAIN,
)


@dataclass
class DigestBundle:
    """What a digest render produced."""
    digest_id: str
    html_path: Path
    pdf_path: Path | None        # None when WeasyPrint isn't importable
    summary_path: Path | None    # JSON summary for admin UI list views
    bucket_prefix: str           # e.g. "watchlist-digest/2026-05-14/"
    summary: dict[str, Any] = field(default_factory=dict)


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
    now = datetime.now(UTC)
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

    # PDF render in subprocess so a WeasyPrint OOM doesn't take down
    # the cron — same isolation strategy worker/_deliverables uses
    # for the freeze-letter PDFs. The cron container is the same
    # ~512MB image; the digest PDF is much smaller than a full
    # freeze letter so OOM is unlikely, but the subprocess guard
    # costs nothing and matches the production pattern.
    pdf_path: Path | None = None
    try:
        import subprocess
        import sys
        candidate = html_path.with_suffix(".pdf")
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import sys; from weasyprint import HTML; "
                "HTML(filename=sys.argv[1]).write_pdf(sys.argv[2])",
                str(html_path), str(candidate),
            ],
            capture_output=True, timeout=90.0,
        )
        if result.returncode == 0:
            pdf_path = candidate
            log.info(
                "digest PDF rendered: %s (%d bytes)",
                pdf_path.name, pdf_path.stat().st_size,
            )
        else:
            tail = (result.stderr or b"").decode("utf-8", errors="replace")[-300:]
            log.warning(
                "digest PDF render skipped (subprocess exit=%d): ...%s",
                result.returncode, tail,
            )
    except subprocess.TimeoutExpired:
        log.warning("digest PDF render skipped (subprocess timed out)")
    except Exception as exc:  # noqa: BLE001
        log.warning("digest PDF render skipped: %s", exc)

    # JSON summary for the admin UI's "Digest Archive" view. Listed
    # alongside the HTML/PDF in the bucket so the UI can do a single
    # `list watchlist-digest/<date>/*.summary.json` to populate the
    # archive table without parsing 30KB of HTML per row.
    summary = _build_summary_payload(
        report=report, total_watched=total_watched,
        digest_id=digest_id, now=now,
        html_filename=html_path.name,
        pdf_filename=pdf_path.name if pdf_path else None,
    )
    summary_path = output_dir / f"{digest_id}.summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=_json_default),
        encoding="utf-8",
    )
    log.info(
        "digest summary written: %s (%d bytes)",
        summary_path.name, summary_path.stat().st_size,
    )

    return DigestBundle(
        digest_id=digest_id,
        html_path=html_path,
        pdf_path=pdf_path,
        summary_path=summary_path,
        bucket_prefix=f"watchlist-digest/{tick_date}/",
        summary=summary,
    )


def _build_summary_payload(
    *,
    report: WatchTickReport,
    total_watched: int,
    digest_id: str,
    now: datetime,
    html_filename: str,
    pdf_filename: str | None,
) -> dict[str, Any]:
    """Compact JSON payload the admin UI's archive listing can consume
    without parsing the full HTML.

    Stable schema fields (don't rename without a UI coordination):

      digest_id, generated_at, tick_started_at, tick_finished_at,
      total_watched, snapshotted, material_count, freezeable_count,
      error_count, total_outflow_usd, html_filename, pdf_filename,
      material_changes[*] = {address, chain, role, label_name,
                              is_freezeable, issuer, asset_symbol,
                              delta_usd, tx_count_delta, reason}
    """
    freezeable_count = 0
    total_outflow = Decimal(0)
    changes_payload: list[dict[str, Any]] = []
    for mc in report.material_changes:
        if mc.is_freezeable:
            freezeable_count += 1
        if mc.delta_usd is not None and mc.delta_usd < 0:
            total_outflow += -mc.delta_usd
        changes_payload.append({
            "address": mc.address,
            "chain": mc.chain,
            "role": mc.role,
            "label_name": mc.label_name,
            "is_freezeable": mc.is_freezeable,
            "issuer": mc.issuer,
            "asset_symbol": mc.asset_symbol,
            "delta_usd": str(mc.delta_usd) if mc.delta_usd is not None else None,
            "tx_count_delta": mc.tx_count_delta,
            "reason": mc.reason,
        })

    return {
        "digest_id": digest_id,
        "generated_at": now.isoformat(),
        "tick_started_at": report.started_at.isoformat(),
        "tick_finished_at": report.finished_at.isoformat(),
        "tick_duration_seconds": (
            report.finished_at - report.started_at
        ).total_seconds(),
        "total_watched": total_watched,
        "snapshotted": report.snapshotted,
        "skipped_cooldown": report.skipped_cooldown,
        "skipped_unsupported_chain": report.skipped_unsupported_chain,
        "material_count": len(report.material_changes),
        "freezeable_count": freezeable_count,
        "error_count": len(report.errors),
        "total_outflow_usd": str(total_outflow),
        "html_filename": html_filename,
        "pdf_filename": pdf_filename,
        "material_changes": changes_payload,
    }


def _json_default(value: Any) -> Any:
    """JSON fallback encoder — Decimal / datetime / UUID."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    # Let json raise its TypeError for anything else.
    return str(value)


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
