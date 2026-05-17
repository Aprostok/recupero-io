"""Render the victim-facing case-summary letter.

This is the artifact the customer (the victim) actually receives in
their inbox after their $499 diagnostic completes. Two variants:

  * ``victim_summary_recoverable.html.j2`` — sent when the diagnostic
    found freezable funds. Pitches Tier 2 engagement as Option A
    and "use the artifacts yourself" as Option B, with realistic
    timeline expectations and important caveats.

  * ``victim_summary_unrecoverable.html.j2`` — sent when the
    diagnostic determined that the funds can't be recovered through
    our standard issuer-freeze process (mixer, cashed-out CEX,
    self-custody, or sub-economic amount). Acknowledges the $99
    refund per the service agreement and gives specific
    actionable next steps (IC3, FBI field office, state AG,
    tax-loss deduction, attorney consultation thresholds).

Determining which variant to render
-----------------------------------

The decision rule lives in ``_classify_recovery_prospects`` and is
based on the case's freeze_brief.json:

  * If at least one issuer has confirmed FREEZABLE holdings totaling
    >= $500 USD: render the **recoverable** variant.
  * Otherwise: render the **unrecoverable** variant.

The $500 floor is conservative — below that, the engagement fee
exceeds the expected recovery, so honestly recommending engagement
would be predatory. The floor is parameterized so an operator can
tighten or loosen it per case.

Why this lives in worker/ not reports/
--------------------------------------

The other letter templates (issuer_freeze_request, le, trace_report)
live under reports/ because they're produced from inside the trace
pipeline. The victim summary is produced AFTER all the other
artifacts are written, because it summarizes them and needs to know
whether the recoverable path was found. It's a deliverable-builder
concern, not a per-case reports concern.
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

# Templates live alongside the other letter templates in reports/.
_TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent / "reports" / "templates"
)

# Recoverable-floor: if confirmed FREEZABLE total is below this, we
# default to the unrecoverable variant. At a $10,000 engagement fee
# (v0.7.0), recommending Tier 2 on cases where the recoverable
# amount is comparable or smaller would be predatory — the trace
# report alone is more useful to the victim for an LE filing in
# that range. Floor is centralized in recupero._pricing and
# defaults to 4× the engagement fee.
from recupero._pricing import RECOVERABLE_FLOOR_USD as _RECOVERABLE_FLOOR_USD


def classify_recovery_prospects(
    freeze_brief: dict[str, Any],
    *,
    floor_usd: Decimal = _RECOVERABLE_FLOOR_USD,
) -> tuple[bool, Decimal, Decimal]:
    """Decide whether the case is recoverable + return the headline
    USD numbers for the template.

    Returns ``(is_recoverable, total_freezable_usd, total_suspected_usd)``.

      * ``is_recoverable``: True if any FREEZABLE entry's confirmed
        total_usd (parsed from "$X,XXX.YY" format) is >= floor_usd.
      * ``total_freezable_usd``: sum of total_usd across all issuers.
      * ``total_suspected_usd``: sum of total_suspected_usd across
        all issuers (includes FREEZABLE + INVESTIGATE).

    Conservatively False when freeze_brief is empty / malformed —
    better to render the unrecoverable variant (which still gives
    the victim a useful filing package) than to over-promise.
    """
    freezable = freeze_brief.get("FREEZABLE") if freeze_brief else None
    if not freezable:
        return False, Decimal(0), Decimal(0)

    total_freezable = Decimal(0)
    total_suspected = Decimal(0)
    for entry in freezable:
        total_freezable += _parse_usd_string(entry.get("total_usd"))
        total_suspected += _parse_usd_string(entry.get("total_suspected_usd"))

    return (total_freezable >= floor_usd, total_freezable, total_suspected)


def render_victim_summary(
    *,
    case: Case,
    victim: VictimInfo,
    investigator: InvestigatorInfo,
    freeze_brief: dict[str, Any],
    briefs_dir: Path,
    flow_filename: str | None = None,
    engagement_fee_text: str | None = None,
    contingency_pct: int | None = None,
    refund_amount_text: str = "$99",
    unrecoverable_reason_short: str | None = None,
    unrecoverable_explanation: str | None = None,
) -> Path | None:
    """Render the appropriate victim-facing summary letter.

    Picks the recoverable vs unrecoverable variant via
    ``classify_recovery_prospects``. Returns the path to the
    written HTML on success, None on render failure (logged as a
    warning — never fail the overall build_all_deliverables).

    ``unrecoverable_reason_short`` and ``unrecoverable_explanation``
    let the operator inject case-specific prose for why the funds
    can't be recovered (mixer / cashed out / self-custody / etc.).
    When None, the template falls back to generic copy.

    ``engagement_fee_text`` and ``contingency_pct`` default to the
    published values in recupero._pricing. v0.7.0 decoupled the
    diagnostic from the engagement (no credit applied) — the
    engagement_fee_text is now a clean dollar amount rather than
    the "incremental over $499" phrasing.
    """
    from recupero._pricing import (
        CONTINGENCY_PCT, ENGAGEMENT_FEE_USD, fmt_usd_short,
    )
    if engagement_fee_text is None:
        engagement_fee_text = fmt_usd_short(ENGAGEMENT_FEE_USD)
    if contingency_pct is None:
        contingency_pct = CONTINGENCY_PCT
    try:
        is_recoverable, total_freezable_usd, total_suspected_usd = (
            classify_recovery_prospects(freeze_brief)
        )

        template_name = (
            "victim_summary_recoverable.html.j2"
            if is_recoverable
            else "victim_summary_unrecoverable.html.j2"
        )

        ctx = _build_context(
            case=case,
            victim=victim,
            investigator=investigator,
            freeze_brief=freeze_brief,
            flow_filename=flow_filename,
            total_freezable_usd=total_freezable_usd,
            total_suspected_usd=total_suspected_usd,
            engagement_fee_text=engagement_fee_text,
            contingency_pct=contingency_pct,
            refund_amount_text=refund_amount_text,
            unrecoverable_reason_short=unrecoverable_reason_short,
            unrecoverable_explanation=unrecoverable_explanation,
        )

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        html = env.get_template(template_name).render(**ctx)

        briefs_dir.mkdir(parents=True, exist_ok=True)
        summary_id = uuid4().hex[:8]
        variant = "recoverable" if is_recoverable else "unrecoverable"
        out_path = briefs_dir / f"victim_summary_{variant}_{summary_id}.html"
        out_path.write_text(html, encoding="utf-8")
        return out_path
    except Exception as exc:  # noqa: BLE001
        log.warning("victim summary render failed: %s", exc)
        return None


# ----- internals ----- #


def _build_context(
    *,
    case: Case,
    victim: VictimInfo,
    investigator: InvestigatorInfo,
    freeze_brief: dict[str, Any],
    flow_filename: str | None,
    total_freezable_usd: Decimal,
    total_suspected_usd: Decimal,
    engagement_fee_text: str,
    contingency_pct: int,
    refund_amount_text: str,
    unrecoverable_reason_short: str | None,
    unrecoverable_explanation: str | None,
) -> dict[str, Any]:
    """Build the Jinja context for both variants. Shared fields are
    common; recoverable-only fields are computed but harmless if
    rendered in the unrecoverable variant (the template ignores
    them)."""
    from recupero import __version__ as software_version

    now = datetime.now(timezone.utc)

    # Per-issuer summary table data
    freezable_entries = freeze_brief.get("FREEZABLE") or []
    freezable_summary: list[dict[str, Any]] = []
    for entry in freezable_entries:
        freezable_usd = _parse_usd_string(entry.get("total_usd"))
        suspected_usd = _parse_usd_string(entry.get("total_suspected_usd"))
        suspected_only = suspected_usd - freezable_usd
        freezable_summary.append({
            "issuer": entry.get("issuer", "?"),
            "token": entry.get("token", "?"),
            "total_usd_freezable": entry.get("total_usd") or "$0",
            "total_usd_suspected_only": _fmt_usd(suspected_only) if suspected_only > 0 else "—",
            "freeze_capability": entry.get("freeze_capability") or "UNKNOWN",
        })

    return {
        "case_id": case.case_id,
        "case": case,
        "victim": victim.model_dump(),
        "investigator": investigator.__dict__,
        "chain_display": case.chain.value.capitalize(),
        "max_depth": case.config_used.get("trace", {}).get("max_depth", 1) if case.config_used else 1,
        "summary": {
            "transfers": len(case.transfers),
            "addresses_traced": _count_unique_addresses(case),
        },
        "freezable_summary": freezable_summary,
        "freezable_issuer_count": len(freezable_summary),
        "total_recoverable_freezable_usd": _fmt_usd(total_freezable_usd),
        "total_under_investigation_usd": _fmt_usd(total_suspected_usd - total_freezable_usd),
        "flow_filename": flow_filename,
        "engagement_fee_text": engagement_fee_text,
        "contingency_pct": contingency_pct,
        "refund_amount_text": refund_amount_text,
        "unrecoverable_reason_short": unrecoverable_reason_short,
        "unrecoverable_explanation": unrecoverable_explanation,
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "verified_at": now.strftime("%Y-%m-%d"),
        "software_version": software_version or "0.2.x",
    }


def _count_unique_addresses(case: Case) -> int:
    """Count unique addresses across all transfers (incl. seed)."""
    addrs: set[str] = {case.seed_address}
    for t in case.transfers:
        if t.from_address:
            addrs.add(t.from_address)
        if t.to_address:
            addrs.add(t.to_address)
    return len(addrs)


def _parse_usd_string(s: str | None) -> Decimal:
    """Parse a freeze_brief-format USD string (``"$1,234.56"``) into Decimal.
    Returns 0 on empty / malformed input."""
    if not s:
        return Decimal(0)
    try:
        cleaned = str(s).replace("$", "").replace(",", "").strip()
        return Decimal(cleaned) if cleaned else Decimal(0)
    except Exception:  # noqa: BLE001
        return Decimal(0)


def _fmt_usd(d: Decimal) -> str:
    """Format Decimal as ``$X,XXX.YY``."""
    return f"${d:,.2f}"


__all__ = ("render_victim_summary", "classify_recovery_prospects")
