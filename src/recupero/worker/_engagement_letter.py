"""Render the Tier-2 engagement letter (active-recovery contract).

This is the legal document the victim signs when they choose to
engage Recupero for active recovery (Option A in the victim
summary letter). It's pre-generated for every recoverable case
and shipped alongside the other artifacts so the operator can
attach + send it the moment a customer says "yes, engage you" —
no manual case-specific edits needed.

Generation policy
-----------------

Only generated for cases that meet the engagement-economically-
sensible threshold:

  * case_id is set (case-driven investigation, not wallet-trace)
  * skip_freeze_briefs is False (we have freeze letters)
  * Confirmed FREEZABLE total >= the floor (default $500 USD)

For wallet traces or empty-FREEZABLE cases, the engagement letter
is skipped — there's nothing to engage on.

Document structure
------------------

The template renders a professional engagement letter with these
sections:

  1. Background (case reference, what diagnostic found)
  2. Scope of services (what we'll do, 5BD timeline + 30-day
     reporting cadence)
  3. What this engagement does NOT include (no guarantees,
     not legal advice, partial-recovery typical)
  4. Fees (engagement fee with $499 credit, contingency at 15%,
     when invoiced, when due)
  5. Termination (75% refund pre-letter-send, 0% after)
  6. Authority & consent (what we're authorized to do on victim's
     behalf)
  7. Confidentiality
  8. Governing law & dispute resolution (JAMS arbitration)
  9. Signature blocks

Legal disclaimer note
---------------------

This template is professionally drafted but is NOT a replacement for
legal review of your specific business setup. Before scaling beyond
the first few clients, get an attorney in your operating state to
review the contract language, especially the dispute-resolution
clause, the governing-law selection, and the contingency-fee
mechanics under your state's professional-services regulations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero.models import Case
from recupero.reports.brief import InvestigatorInfo
from recupero.reports.victim import VictimInfo

log = logging.getLogger(__name__)

_TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent / "reports" / "templates"
)


def render_engagement_letter(
    *,
    case: Case,
    victim: VictimInfo,
    investigator: InvestigatorInfo,
    freeze_brief: dict[str, Any],
    briefs_dir: Path,
    total_freezable_usd: Decimal,
    total_suspected_usd: Decimal,
    initial_fee_usd: Decimal = Decimal("499"),
    total_engagement_fee_usd: Decimal = Decimal("2000"),
    contingency_pct: int = 15,
    investigator_jurisdiction: str | None = None,
) -> Path | None:
    """Render the Tier-2 engagement letter to ``briefs_dir`` and
    return its path. Returns None if rendering fails (logged as
    warning).

    Caller is expected to check whether this case is engagement-
    eligible (recoverable funds above floor) before invoking. The
    renderer doesn't gate on that — it assumes the decision is
    made upstream so the same template can be reused for any
    case that wants an engagement letter (e.g., manual case-by-
    case overrides from the operator).

    ``total_engagement_fee_usd`` defaults to $2,000 (which covers
    the $499 already paid + $1,500 incremental for the active
    recovery work). Override per-case if the case complexity
    justifies a different fee (see the tier table in
    docs/pricing or the operator runbook).
    """
    try:
        ctx = _build_context(
            case=case,
            victim=victim,
            investigator=investigator,
            freeze_brief=freeze_brief,
            total_freezable_usd=total_freezable_usd,
            total_suspected_usd=total_suspected_usd,
            initial_fee_usd=initial_fee_usd,
            total_engagement_fee_usd=total_engagement_fee_usd,
            contingency_pct=contingency_pct,
            investigator_jurisdiction=investigator_jurisdiction,
        )

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        html = env.get_template("engagement_letter.html.j2").render(**ctx)

        briefs_dir.mkdir(parents=True, exist_ok=True)
        letter_id = uuid4().hex[:8]
        out_path = briefs_dir / f"engagement_letter_{letter_id}.html"
        out_path.write_text(html, encoding="utf-8")
        return out_path
    except Exception as exc:  # noqa: BLE001
        log.warning("engagement letter render failed: %s", exc)
        return None


def _build_context(
    *,
    case: Case,
    victim: VictimInfo,
    investigator: InvestigatorInfo,
    freeze_brief: dict[str, Any],
    total_freezable_usd: Decimal,
    total_suspected_usd: Decimal,
    initial_fee_usd: Decimal,
    total_engagement_fee_usd: Decimal,
    contingency_pct: int,
    investigator_jurisdiction: str | None,
) -> dict[str, Any]:
    """Build the Jinja context for the engagement letter."""
    from recupero import __version__ as software_version

    now = datetime.now(timezone.utc)

    freezable_entries = freeze_brief.get("FREEZABLE") or []
    freezable_issuer_count = len(freezable_entries)

    incremental_fee = total_engagement_fee_usd - initial_fee_usd
    if incremental_fee < 0:
        # Defensive: if total_engagement < initial_fee (someone passed
        # a smaller total by accident), don't render a negative
        # incremental fee. Treat the engagement as covered by the
        # initial fee alone.
        incremental_fee = Decimal(0)

    return {
        "case_id": case.case_id,
        "case": case,
        "victim": victim.model_dump(),
        "investigator": investigator.__dict__,
        "investigator_jurisdiction": investigator_jurisdiction,
        "chain_display": case.chain.value.capitalize(),
        "freezable_issuer_count": freezable_issuer_count,
        "total_freezable_usd": _fmt_usd(total_freezable_usd),
        "total_under_investigation_usd": _fmt_usd(
            total_suspected_usd - total_freezable_usd
        ),
        # Fee text rendered to dollar form for the template
        "initial_fee_text": _fmt_usd(initial_fee_usd),
        "total_engagement_fee_text": _fmt_usd(total_engagement_fee_usd),
        "incremental_engagement_fee_text": _fmt_usd(incremental_fee),
        "contingency_pct": contingency_pct,
        # Timestamps
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "diagnostic_completed_at": (
            case.trace_completed_at.strftime("%Y-%m-%d")
            if case.trace_completed_at else now.strftime("%Y-%m-%d")
        ),
        "software_version": software_version or "0.3.x",
    }


def _fmt_usd(d: Decimal) -> str:
    """Format Decimal as ``$X,XXX.YY`` (e.g., '$2,000.00')."""
    return f"${d:,.2f}"


__all__ = ("render_engagement_letter",)
