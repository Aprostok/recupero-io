"""Cooperation dashboard renderer (v0.24.0).

One-page operator-facing HTML summarizing every issuer's cross-case
cooperation history. Generated on demand via
``recupero-ops cooperation-dashboard``.

This is the strategy-reference document the operator pins in their
browser tabs. Each row says "next time you have a case naming this
issuer, here's what to expect and which legal instrument to default
to." The data refreshes whenever the operator re-runs the command —
typically after a batch of new freeze outcomes lands.

Distinct from the per-case Section 5.7 view: the per-case section
filters to issuers named in THAT case's freeze ask list; the
dashboard surfaces every issuer with letter history.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import atomic_write_text

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _profile_to_template_dict(
    prof, instrument: str, instrument_reason: str,
) -> dict:
    """Flatten an IssuerCooperationProfile for the Jinja template,
    formatting decimals and computing display fields."""
    total_frozen = prof.total_frozen_usd or Decimal(0)
    try:
        frozen_human = f"${total_frozen:,.2f}"
    except Exception:  # noqa: BLE001
        frozen_human = "$0"
    return {
        "issuer": prof.issuer,
        "n_letters_sent": prof.n_letters_sent,
        "n_responded": prof.n_responded,
        "n_silent": prof.n_silent,
        "response_rate": float(prof.response_rate),
        "full_freeze_rate": float(prof.full_freeze_rate),
        "partial_freeze_rate": float(prof.partial_freeze_rate),
        "declined_rate": float(prof.declined_rate),
        "silence_rate": float(prof.silence_rate),
        "median_response_hours": prof.median_response_hours,
        "avg_response_hours": prof.avg_response_hours,
        "fastest_response_hours": prof.fastest_response_hours,
        "slowest_response_hours": prof.slowest_response_hours,
        "total_frozen_usd_human": frozen_human,
        "is_black_hole": prof.is_black_hole,
        "has_confident_profile": prof.has_confident_profile,
        "latest_letter_sent_at": prof.latest_letter_sent_at,
        "latest_outcome_observed_at": prof.latest_outcome_observed_at,
        "recommended_instrument": instrument,
        "recommended_instrument_reason": instrument_reason,
    }


def render_cooperation_dashboard(
    *,
    output_dir: Path,
    dsn: str | None,
) -> Path | None:
    """Render the cooperation dashboard HTML into ``output_dir``.

    Returns the written path on success, or ``None`` when:
      * dsn is unset
      * no issuers have any freeze letters on file yet
      * the render fails

    Filename: ``cooperation_dashboard.html`` — single per-deployment
    document, overwritten on each run (this is the operator's
    strategy reference; it doesn't need versioned filenames).
    """
    if not dsn:
        log.warning("render_cooperation_dashboard: no DSN configured")
        return None

    from recupero.monitoring.cooperation_intelligence import (
        build_all_profiles,
        recommend_legal_instrument,
    )

    # v0.24.1 (audit-fix HIGH-3): wrap the bulk-profile build so an
    # unhandled exception in the SQL layer doesn't crash the CLI
    # with a stack trace. build_all_profiles already catches the
    # distinct-issuer query error and (after v0.24.1) per-issuer
    # errors; this outer wrap is defense-in-depth.
    try:
        profiles_by_issuer = build_all_profiles(dsn)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_cooperation_dashboard: build_all_profiles failed: %s",
            exc,
        )
        return None

    if not profiles_by_issuer:
        log.info(
            "render_cooperation_dashboard: no issuers with letter "
            "history on file — nothing to render."
        )
        return None

    # Sort by letter volume DESC; the issuers with the most history
    # are the most actionable for the operator.
    profiles_sorted = sorted(
        profiles_by_issuer.values(),
        key=lambda p: (p.n_letters_sent, p.issuer),
        reverse=True,
    )

    # Build the template rows. The dashboard doesn't know the next
    # case's jurisdiction or OFAC posture, so the recommendation is
    # computed with neutral inputs — the per-case LE Section 5.7
    # layer applies case-specific signals on top.
    rows = []
    for prof in profiles_sorted:
        rec = recommend_legal_instrument(
            prof, jurisdiction=None, ofac_exposed=False, ic3_case_id=None,
        )
        rows.append(_profile_to_template_dict(prof, rec.instrument, rec.reason))

    # Aggregate stats panel.
    total_letters = sum(p.n_letters_sent for p in profiles_sorted)
    total_frozen = sum(
        (p.total_frozen_usd for p in profiles_sorted),
        start=Decimal(0),
    )
    n_black_holes = sum(1 for p in profiles_sorted if p.is_black_hole)
    stats = {
        "n_issuers": len(profiles_sorted),
        "n_letters_total": total_letters,
        "total_frozen_usd_human": f"${total_frozen:,.2f}",
        "n_black_holes": n_black_holes,
    }

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.24.x"

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    try:
        html = env.get_template("cooperation_dashboard.html.j2").render(
            profiles=rows,
            stats=stats,
            generated_at=generated_at,
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("render_cooperation_dashboard: render failed: %s", exc)
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "cooperation_dashboard.html"
    atomic_write_text(out_path, html)
    return out_path


__all__ = ("render_cooperation_dashboard",)
