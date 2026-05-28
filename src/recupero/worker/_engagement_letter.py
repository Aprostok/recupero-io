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
import os
from datetime import UTC, datetime
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
    initial_fee_usd: Decimal | None = None,
    engagement_fee_usd: Decimal | None = None,
    contingency_pct: int | None = None,
    investigator_jurisdiction: str | None = None,
    # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-EL-1): the recovery-rate
    # disclosure that the customer ack'd at intake must appear on the
    # legal contract they sign. Compute lazily from the env-var Supabase
    # DSN if not passed in. Optional override for tests + custom flows.
    # Type loosened to `Any` to avoid an import-time dependency on
    # monitoring.recovery_rate (which pulls psycopg).
    recovery_stats: Any = None,
    recovery_stats_dsn: str | None = None,
) -> Path | None:
    """Render the Tier-2 engagement letter to ``briefs_dir`` and
    return its path. Returns None if rendering fails (logged as
    warning).

    Caller is expected to check whether this case is engagement-
    eligible (recoverable funds above floor) before invoking. The
    renderer doesn't gate on that — it assumes the decision is
    made upstream so the same template can be reused for any
    case that wants an engagement letter.

    ``initial_fee_usd``, ``engagement_fee_usd``, and
    ``contingency_pct`` default to the published values in
    recupero._pricing — the diagnostic and engagement are
    decoupled (no credit applied), so the engagement fee in the
    letter equals the amount the customer pays through the
    Stripe engagement Payment Link. Overrides exist for unit
    tests + the rare per-case adjustment.
    """
    from recupero._pricing import (
        CONTINGENCY_PCT,
        DIAGNOSTIC_FEE_USD,
        ENGAGEMENT_FEE_USD,
    )
    if initial_fee_usd is None:
        initial_fee_usd = DIAGNOSTIC_FEE_USD
    if engagement_fee_usd is None:
        engagement_fee_usd = ENGAGEMENT_FEE_USD
    if contingency_pct is None:
        contingency_pct = CONTINGENCY_PCT

    # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-EL-1): resolve recovery
    # stats once here so the customer signs a contract that names the
    # same Wilson-CI / industry-baseline number they ticked at intake.
    # Lazy import — this module is loaded long before
    # recovery_rate (which pulls psycopg) on cold-start paths, and
    # the test harness should not require psycopg installed to render
    # an engagement letter.
    if recovery_stats is None:
        try:
            from recupero.monitoring.recovery_rate import compute_recovery_stats
            dsn = (
                recovery_stats_dsn
                if recovery_stats_dsn is not None
                else os.environ.get("SUPABASE_DB_URL", "")
            )
            recovery_stats = compute_recovery_stats(dsn=dsn or None)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "engagement_letter: compute_recovery_stats failed (%s); "
                "rendering without inline recovery-rate stats — the "
                "footer will still carry the disclosure boilerplate "
                "but not the case-of-record numbers.", exc,
            )
            recovery_stats = None

    try:
        ctx = _build_context(
            case=case,
            victim=victim,
            investigator=investigator,
            freeze_brief=freeze_brief,
            total_freezable_usd=total_freezable_usd,
            total_suspected_usd=total_suspected_usd,
            initial_fee_usd=initial_fee_usd,
            engagement_fee_usd=engagement_fee_usd,
            contingency_pct=contingency_pct,
            investigator_jurisdiction=investigator_jurisdiction,
            recovery_stats=recovery_stats,
        )

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # XSS defense-in-depth filters.
        from recupero.reports._jinja_filters import register_safe_filters
        register_safe_filters(env)
        html = env.get_template("engagement_letter.html.j2").render(**ctx)

        briefs_dir.mkdir(parents=True, exist_ok=True)
        # RIGOR-3 (determinism): content-based hash so same case produces
        # same engagement_letter filename across runs. Pre-RIGOR-3 used
        # uuid4().hex[:8] — random per run.
        import hashlib
        case_id_for_hash = (
            getattr(case, "case_id", None)
            or getattr(case, "case_number", None)
            or "no-case"
        )
        seed = (
            f"engagement_letter|{case_id_for_hash}|"
            f"{victim.name or ''}|{victim.wallet_address or ''}"
        )
        letter_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
        out_path = briefs_dir / f"engagement_letter_{letter_id}.html"
        from recupero._common import atomic_write_text
        atomic_write_text(out_path, html)
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
    engagement_fee_usd: Decimal,
    contingency_pct: int,
    investigator_jurisdiction: str | None,
    recovery_stats: Any = None,  # RecoveryStats | None
) -> dict[str, Any]:
    """Build the Jinja context for the engagement letter."""
    from recupero import __version__ as software_version

    # SOURCE_DATE_EPOCH-honoring; falls back to wall-clock when unset.
    # RIGOR-7: byte-identical output across re-runs of the same case.
    from recupero.reports.brief import _resolve_render_time
    now = _resolve_render_time()

    from recupero._common import aggregate_evidence_mode_from_entries
    freezable_entries = freeze_brief.get("FREEZABLE") or []
    freezable_issuer_count = len(freezable_entries)

    # Aggregate evidence_mode for the engagement letter's Background
    # paragraph: branches on "received at" (historical_only) vs
    # "currently held" (current_balance_only) vs mixed language.
    aggregate_evidence_mode = aggregate_evidence_mode_from_entries(
        freezable_entries,
    )

    # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-EL-1): render the
    # recovery-rate disclosure that the customer ticked at intake INTO
    # the legal contract they sign. Mirror the
    # intake.html.j2 disclosure so a lawyer reading the engagement
    # letter sees the same number as the customer saw at checkout.
    # Industry-baseline path (sample < 30) → quote Chainalysis as the
    # honest floor. Our-data path → quote our Wilson-95% CI.
    recovery_disclosure: dict[str, Any] = {
        "available": False,
        "summary_html": "",
    }
    if recovery_stats is not None:
        try:
            is_our_data = bool(getattr(recovery_stats, "is_our_data", False))
            if is_our_data:
                pct = float(recovery_stats.full_recovery_rate) * 100.0
                low = float(recovery_stats.full_recovery_rate_ci_low) * 100.0
                high = float(recovery_stats.full_recovery_rate_ci_high) * 100.0
                n_total = int(recovery_stats.sample_size)
                n_full = int(recovery_stats.n_full_recovery)
                recovery_disclosure = {
                    "available": True,
                    "is_our_data": True,
                    "sample_size": n_total,
                    "n_full_recovery": n_full,
                    "rate_pct_text": f"{pct:.1f}%",
                    "ci_low_pct_text": f"{low:.1f}%",
                    "ci_high_pct_text": f"{high:.1f}%",
                    "summary_html": (
                        f"Recupero has closed <strong>{n_total}</strong> "
                        f"cases. Of those, "
                        f"<strong>{n_full}</strong> resulted in full "
                        f"recovery (funds returned to the victim) — a "
                        f"<strong>{pct:.1f}%</strong> full-recovery rate, "
                        f"with a 95% Wilson confidence interval of "
                        f"[<strong>{low:.1f}%</strong>, "
                        f"<strong>{high:.1f}%</strong>]."
                    ),
                }
            else:
                recovery_disclosure = {
                    "available": True,
                    "is_our_data": False,
                    "industry_label": (
                        getattr(recovery_stats, "industry_baseline_used", "")
                        or "Chainalysis 2024 industry baseline"
                    ),
                    "industry_rate_pct_text": "~3% full-recovery, ~7% partial-recovery",
                    "summary_html": (
                        "Recupero has fewer than 30 closed cases. In lieu "
                        "of our own statistically meaningful rate, this "
                        "engagement letter discloses the published "
                        "industry baseline: "
                        "<strong>~3% full-recovery</strong> and "
                        "<strong>~7% partial-recovery</strong> for crypto "
                        "theft cases involving centralized exchanges "
                        "(source: Chainalysis 2024 Crypto Crime Report). "
                        "Recupero will publish its own rate once sample "
                        "size reaches 30 closed cases."
                    ),
                }
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "engagement_letter: recovery_stats render failed (%s); "
                "the contract will not name the rate but will still "
                "carry the disclosure boilerplate", exc,
            )
            recovery_disclosure = {"available": False, "summary_html": ""}

    return {
        "case_id": case.case_id,
        "case": case,
        "victim": victim.model_dump(),
        "investigator": investigator.__dict__,
        "investigator_jurisdiction": investigator_jurisdiction,
        # v0.32.1 (CRIT-EL-1): wired into Section 3 of the template.
        "recovery_disclosure": recovery_disclosure,
        # v0.19.1 (round-12 PDF-CRIT-5): use canonical chain display
        # name so engagement letter, customer email, and LE handoff
        # all render "BNB Chain" / "Hyperliquid" instead of "Bsc".
        "chain_display": _resolve_chain_display(case.chain.value),
        "freezable_issuer_count": freezable_issuer_count,
        "total_freezable_usd": _fmt_usd(total_freezable_usd),
        # v0.16.7 fix: `total_suspected_usd` is INVESTIGATE-only (see
        # classify_recovery_prospects + emit_brief.py:502). Pre-v0.16.7
        # we subtracted total_freezable_usd, which yielded $0/negative
        # on every engagement letter. Round-9 output-artifacts audit.
        "total_under_investigation_usd": _fmt_usd(total_suspected_usd),
        "aggregate_evidence_mode": aggregate_evidence_mode,
        # Fee text rendered to dollar form for the template.
        # Decoupled model (v0.7.0): diagnostic + engagement are
        # separate prices, NOT credited against each other.
        "initial_fee_text": _fmt_usd(initial_fee_usd),
        "engagement_fee_text": _fmt_usd(engagement_fee_usd),
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
    """Format Decimal as ``$X,XXX.YY`` (e.g., '$2,000.00').

    v0.20.0 (round-13 arch follow-up): delegate to canonical helper.
    The engagement letter never renders an "(unknown)" amount in its
    fee fields (all are non-Optional callers), so the fallback is
    decorative; "$0" is the safe choice for any defensive path.

    RIGOR-Jacob Z15-3: a Decimal("NaN") / Decimal("Infinity") that
    propagated up from an upstream aggregation MUST NOT render as
    the literal '$NaN' / '$Infinity' inline in the legal engagement
    contract the victim is asked to sign. Fall back to '$—' (em dash)
    — strictly better than letting "$NaN" reach the customer.
    """
    if d is not None:
        try:
            from decimal import Decimal as _Dec
            d_dec = d if isinstance(d, _Dec) else _Dec(str(d))
            if not d_dec.is_finite():
                return "$—"
        except Exception:  # noqa: BLE001
            return "$—"
    from recupero._pricing import fmt_usd_or
    return fmt_usd_or(d, fallback="$0")


def _resolve_chain_display(chain: str | None) -> str:
    """Delegate to victim_summary's canonical map so the engagement
    letter, customer email, and LE handoff all render the same name
    for every chain. v0.19.1 (round-12 PDF-CRIT-5)."""
    from recupero.worker._victim_summary import _resolve_chain_display as _rcd
    return _rcd(chain)


__all__ = ("render_engagement_letter",)
