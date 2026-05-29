"""Recovery probability scoring + expected-value computation (v0.14.1).

Pure function `score_recovery(brief)` returns a structured
RecoveryEstimate that the brief surfaces and the operator's
decision-making is anchored on.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import asdict, dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

log = logging.getLogger(__name__)


# Pricing constants — imported (not duplicated) from recupero._pricing.
# v0.16.7 (round-9 audit): the prior code redeclared these as local
# literals "to match", which silently diverged from the canonical
# engagement-letter math whenever someone updated _pricing.py without
# also editing this file. Importing keeps the legal documents and the
# scoring math in lockstep.
from recupero._pricing import (  # noqa: E402  (logical placement, after stdlib imports)
    CONTINGENCY_PCT as _CONTINGENCY_PCT_INT,
)
from recupero._pricing import (
    DIAGNOSTIC_FEE_USD as _DIAGNOSTIC_FEE_USD,
)
from recupero._pricing import (
    ENGAGEMENT_FEE_USD as _ENGAGEMENT_FEE_USD,
)

_CONTINGENCY_PCT = Decimal(_CONTINGENCY_PCT_INT)


# Recommendation thresholds (USD).
_REJECT_NET_BELOW = Decimal("0")
_DISCOURAGE_NET_BELOW = Decimal("5000")
_RECOMMEND_NET_ABOVE = Decimal("25000")


# Issuer base freeze probabilities — heuristic priors. Refined by
# the freeze_outcomes table once it accumulates (v0.14.2).
_ISSUER_FREEZE_PRIOR: dict[str, float] = {
    "Tether": 0.73,
    "Circle": 0.91,
    "Paxos": 0.85,
    "TrueUSD": 0.40,
    "Maple Finance": 0.45,
    "MakerDAO": 0.0,
    "Sky Protocol": 0.0,
    "Lido": 0.0,
}

# Default for unknown issuers — conservative.
_UNKNOWN_ISSUER_PRIOR = 0.30


def _lookup_issuer_prior(raw_issuer: str) -> float:
    """Map an issuer string to a base freeze prior, tolerating real-world
    issuer-name variants.

    Pre-v0.16.7 this was a plain `_ISSUER_FREEZE_PRIOR.get(issuer, default)`
    exact-match lookup. Real issuer strings carry parenthetical
    annotations (e.g. ``"Paxos (BUSD discontinued by NYDFS Feb 2023)"``)
    or vendor-name suffixes (``"Tether Limited"``), and the exact-match
    dropped EVERY BUSD/PYUSD/USDP case onto the 0.30 unknown-issuer
    floor — silently understating expected recovery on Paxos-issued
    stablecoins by 55 percentage points. Round-9 scoring audit HIGH.

    Strategy: try the exact key, then a normalized prefix-match, then
    fall back to the unknown floor.
    """
    if not raw_issuer:
        return _UNKNOWN_ISSUER_PRIOR
    if raw_issuer in _ISSUER_FREEZE_PRIOR:
        return _ISSUER_FREEZE_PRIOR[raw_issuer]
    # Normalized prefix match: strip trailing annotations like
    # " (foo)", " - foo", " Limited", " Inc.", "(formerly Maker)" so the
    # canonical issuer-name key wins.
    base = re.split(r"\s*[\(\-,]", raw_issuer, maxsplit=1)[0].strip()
    if base in _ISSUER_FREEZE_PRIOR:
        return _ISSUER_FREEZE_PRIOR[base]
    # Try first-word match (Tether/Circle/Paxos/etc are single-word issuers)
    first_word = base.split(" ", 1)[0]
    if first_word in _ISSUER_FREEZE_PRIOR:
        return _ISSUER_FREEZE_PRIOR[first_word]
    return _UNKNOWN_ISSUER_PRIOR


# Per-jurisdiction multipliers. USA/EU/UK = baseline 1.0;
# non-cooperative jurisdictions reduce expected recovery.
#
# v0.16.8 (round-9 scoring HIGH): ORDER MATTERS — longer/more-specific
# entries first so they match before shorter aliases. The lookup uses
# word-boundary regex so "UK" doesn't match "Ukraine", "EU" doesn't
# match "European", etc. Round-9 also added: ISO-format variants
# ("Russian Federation", "Korea, Republic of"), formal alternative
# names ("People's Republic of China", "Democratic People's Republic
# of Korea"), and historically-misnamed entries.
_JURISDICTION_MULT: dict[str, float] = {
    # Longest/most-specific entries first.
    "Democratic People's Republic of Korea": 0.05,
    "Russian Federation": 0.15,
    "United Arab Emirates": 0.70,
    "Korea, Republic of": 0.85,
    "Republic of Korea": 0.85,
    "People's Republic of China": 0.50,
    "United Kingdom": 1.0,
    "United States": 1.0,
    "Great Britain": 1.0,
    "Hong Kong SAR": 0.65,
    "North Korea": 0.05,
    "South Korea": 0.85,
    "USA": 1.0,
    "UK": 1.0,
    "EU": 0.95,
    "Canada": 0.95,
    "Switzerland": 0.90,
    "Japan": 0.90,
    "Australia": 0.90,
    "Singapore": 0.85,
    "Hong Kong": 0.65,
    "UAE": 0.70,
    "Brazil": 0.65,
    "Mexico": 0.60,
    "India": 0.65,
    "Ukraine": 0.40,   # cooperative but war-impacted; partial-recovery prior
    "Russia": 0.15,
    "Iran": 0.10,
    "Belarus": 0.10,
}

# Default for unknown jurisdictions — slight discount for uncertainty.
_UNKNOWN_JURISDICTION_MULT = 0.7


@dataclass
class RecoveryDriver:
    """One factor explaining the recovery estimate."""
    factor: str          # e.g. 'freezable_concentration', 'jurisdiction'
    direction: str       # 'positive' | 'negative'
    weight: float        # contribution to the score
    description: str


@dataclass
class IssuerRecoveryRow:
    """Per-issuer recovery row exposed to the LE handoff + victim
    summary templates (v0.22.0).

    Pre-v0.22.0 the scorer computed an internal `issuer_breakdown`
    tuple list but discarded it after picking the top issuer. Now we
    expose every row so downstream consumers can render a full table:
    each issuer's expected_recovered_usd with the base prior, the
    historical-receipt evidence discount, and a flag for whether the
    prior was learned from real outcomes or fell back to heuristic.

    v0.22.1 (audit-fix H4): ``base_prior_before_override`` captures
    the heuristic/learned prior BEFORE the freeze_capability override
    forces it to 0 (for capability='no') or caps it at 0.5
    (capability='limited'). The template displays this so an LE
    reader doesn't see "Tether base prior 0%" on a capability=no
    holding and conclude Tether's track record is zero — the
    capability override is a property of the specific holding, not
    of the issuer's history.
    """
    issuer: str
    requested_usd: Decimal           # what we're asking the issuer to freeze
    base_prior: float                # P(any freeze | the request) — post-override
    base_prior_before_override: float  # heuristic/learned prior; pre-override
    capability_override_applied: bool  # True iff override changed the prior
    evidence_discount: float         # 1.0 = current balance, 0.5 = historical-only
    evidence_mode: str               # 'current_balance_only' / 'historical_only' / 'mixed'
    effective_prior: float           # base_prior * evidence_discount
    expected_recovered_usd: Decimal  # requested_usd * effective_prior * jur * sanctions
    is_learned_prior: bool           # True if from learned_priors DB; else heuristic


@dataclass
class RecoveryEstimate:
    """Top-level scoring output."""
    expected_recovered_usd: Decimal
    expected_recovered_low_usd: Decimal       # 95% CI lower bound
    expected_recovered_high_usd: Decimal      # 95% CI upper bound

    probability_any_recovery_90d: float        # P(recovered > 0 within 90d)
    probability_pays_back_engagement_180d: float  # P(recovered > engagement_fee)

    expected_recupero_revenue_usd: Decimal     # diagnostic + engagement + contingency
    expected_net_to_victim_usd: Decimal        # E[recovered] - our fees
    expected_net_low_usd: Decimal
    expected_net_high_usd: Decimal

    recommendation: str        # 'recommend' | 'caveat' | 'discourage' | 'reject'
    headline_summary: str       # 1-line summary for the brief

    drivers: list[RecoveryDriver] = field(default_factory=list)
    # v0.22.0: per-issuer breakdown for the LE handoff + victim summary
    # "Recovery Forecast" tables. Sorted by expected_recovered_usd DESC
    # so the most-actionable issuer appears first.
    per_issuer: list[IssuerRecoveryRow] = field(default_factory=list)

    def to_json_safe(self) -> dict[str, Any]:
        d = asdict(self)
        for k in (
            "expected_recovered_usd",
            "expected_recovered_low_usd",
            "expected_recovered_high_usd",
            "expected_recupero_revenue_usd",
            "expected_net_to_victim_usd",
            "expected_net_low_usd",
            "expected_net_high_usd",
        ):
            d[k] = f"${self.__dict__[k]:,.2f}"
        # Format per-issuer rows for template consumption.
        d["per_issuer"] = [
            {
                "issuer": r.issuer,
                "requested_usd_human": f"${r.requested_usd:,.2f}",
                # v0.22.1 (audit-fix H4): expose BOTH the heuristic/learned
                # prior (issuer's actual track record) AND the post-override
                # prior used in the recovery math. Templates render the
                # pre-override value as "Base prior" and surface a note
                # when the capability override changed it.
                "base_prior_pct": f"{r.base_prior_before_override * 100:.0f}%",
                "base_prior_post_override_pct": f"{r.base_prior * 100:.0f}%",
                "capability_override_applied": r.capability_override_applied,
                "evidence_discount_pct": f"{r.evidence_discount * 100:.0f}%",
                "evidence_mode": r.evidence_mode,
                "effective_prior_pct": f"{r.effective_prior * 100:.0f}%",
                "expected_recovered_usd_human": f"${r.expected_recovered_usd:,.2f}",
                "is_learned_prior": r.is_learned_prior,
            }
            for r in self.per_issuer
        ]
        return d


def score_recovery(
    brief: dict[str, Any],
    *,
    learned_priors: dict[str, Any] | None = None,
    auto_load_priors: bool = True,
) -> RecoveryEstimate:
    """Score a freeze_brief.json structure into a RecoveryEstimate.

    Inputs (read from the brief):
      * TOTAL_LOSS_USD — the case's loss figure
      * FREEZABLE — list of per-issuer freeze targets with
        total_usd and freeze_capability
      * UNRECOVERABLE — list of non-freezable items
      * VICTIM_JURISDICTION — for jurisdiction multiplier
      * INCIDENT_CLASSIFICATION — drainer attribution (if any)
      * RISK_ASSESSMENT — OFAC exposure flag
      * DEX_SWAPS — count of swap continuations
      * CROSS_CHAIN_HANDOFFS — count of bridge hops (each adds
        recovery friction)

    v0.14.5: When ``learned_priors`` is None and ``auto_load_priors``
    is True, attempt to load per-issuer priors from the
    issuer_freeze_priors table (v0.14.2). If the DB is unavailable
    or no priors exist yet, falls back to heuristic priors.

    Adversarial-input wave (v0.20.2): a non-dict ``brief`` (e.g., the
    caller accidentally passed a string or None) used to crash with
    AttributeError on the first `brief.get(...)`. Now: coerce to an
    empty dict so the scorer returns a zero-recovery estimate
    deterministically.
    """
    if not isinstance(brief, dict):
        log.warning("score_recovery: non-dict brief (%r); using empty",
                    type(brief).__name__)
        brief = {}
    drivers: list[RecoveryDriver] = []

    # Auto-load learned priors from the DB if not explicitly supplied.
    # This makes the scorer self-tuning over time without callers
    # needing to know about the freeze_learning module.
    if learned_priors is None and auto_load_priors:
        try:
            import os as _os
            dsn = _os.environ.get("SUPABASE_DB_URL", "").strip()
            if dsn:
                from recupero.freeze_learning.recorder import load_learned_priors
                learned_priors = load_learned_priors(dsn)
        except Exception:  # noqa: BLE001 — non-fatal, fall back to heuristic
            learned_priors = None

    # --- Pull inputs ---
    try:
        total_loss = _parse_usd(brief.get("TOTAL_LOSS_USD") or "$0")
    except Exception:  # noqa: BLE001
        total_loss = Decimal("0")

    freezable_entries = brief.get("FREEZABLE") or []

    # --- Per-issuer expected recovery ---
    # Breakdown tuple: (issuer_name, usd, base_prior,
    #                   evidence_discount, evidence_mode)
    # v0.22.0: ALSO accumulate IssuerRecoveryRow per entry for the
    # public per_issuer field on the returned RecoveryEstimate.
    expected_freezable = Decimal("0")
    issuer_breakdown: list[tuple[str, Decimal, float, float, str]] = []
    per_issuer_rows: list[IssuerRecoveryRow] = []
    for entry in freezable_entries:
        if not isinstance(entry, dict):
            continue
        issuer = entry.get("issuer") or "(unknown)"
        try:
            issuer_usd = _parse_usd(
                entry.get("total_usd")
                or entry.get("usd_value")
                or "$0"
            )
        except Exception:  # noqa: BLE001
            continue
        if issuer_usd <= 0:
            continue
        # v0.14.2: Use learned prior from freeze_outcomes if available
        # for this issuer; else fall back to heuristic prior.
        # v0.22.0: track which side won so the template can show
        # "based on N actual outcomes" vs. "heuristic prior" — material
        # difference in defensibility of the recovery estimate.
        prior = None
        is_learned = False
        if learned_priors and issuer in learned_priors:
            lp = learned_priors[issuer]
            try:
                _lp_val = float(getattr(lp, "p_any_freeze", lp))
                # Reject NaN/Inf/out-of-range learned priors — they
                # would corrupt every downstream multiplication. Fall
                # back to the heuristic if the learned-prior table
                # contains garbage.
                if math.isfinite(_lp_val) and 0.0 <= _lp_val <= 1.0:
                    prior = _lp_val
                    is_learned = True
            except (TypeError, ValueError):
                pass
        if prior is None:
            prior = _lookup_issuer_prior(issuer)
            is_learned = False
        # v0.22.1 (audit-fix H4): snapshot the pre-override prior so the
        # template can show "Tether base prior 73% — overridden to 0%
        # because freeze_capability=no" instead of misleadingly showing
        # "Tether base prior 0%".
        base_prior_before_override = float(prior)
        # Freeze capability override. The brief produces both forms
        # depending on which layer: emit_brief maps yes/limited/no →
        # HIGH/MEDIUM/LOW for display, but the raw freeze_asks.json
        # carries the lowercase form. Accept both.
        capability = (entry.get("freeze_capability") or "").lower()
        if capability in ("no", "low"):
            prior = 0.0
        elif capability in ("limited", "medium"):
            prior = min(prior, 0.50)
        elif capability in ("yes", "high"):
            prior = max(prior, 0.85)
        # Discount historical-inflow asks vs. confirmed current balances.
        # Issuer compliance can still investigate/recover when balances
        # remain, but the prior on "balance remains 7 months later" is
        # well below the prior on "freeze a confirmed current balance".
        #   historical_only      → 0.50x
        #   mixed                → 0.75x
        #   current_balance_only → 1.00x (unchanged)
        #
        # v0.16.7 (round-9 scoring HIGH): accept BOTH `evidence_mode` (the
        # per-issuer aggregate emitted by emit_brief) AND `evidence_type`
        # (the per-ask field emitted by freeze.asks). Pre-v0.16.7 the
        # scorer ONLY read `evidence_mode`; when fed a raw freeze-asks
        # entry it defaulted to "current_balance_only" → discount 1.00,
        # so the historical-inflow discount silently never fired,
        # overstating expected recovery on stale cases by 2x.
        raw_mode = (entry.get("evidence_mode")
                    or entry.get("evidence_type")
                    or "current_balance_only")
        ev_mode = raw_mode.lower()
        # Translate per-ask names → per-issuer-aggregate names so the
        # downstream comparisons are uniform.
        if ev_mode == "historical_inflow":
            ev_mode = "historical_only"
        elif ev_mode == "current_balance":
            ev_mode = "current_balance_only"
        if ev_mode == "historical_only":
            evidence_discount = Decimal("0.50")
        elif ev_mode == "mixed":
            evidence_discount = Decimal("0.75")
        else:
            evidence_discount = Decimal("1.00")
        # `Decimal(str(prior))` — going through `str()` avoids binary-float
        # noise that `Decimal(prior_float)` injects (e.g., 0.73 → Decimal(
        # '0.7300000000000000266...')). Threshold comparisons downstream
        # are otherwise vulnerable to flipping on sub-cent margins.
        contribution = issuer_usd * Decimal(str(prior)) * evidence_discount
        expected_freezable += contribution
        # Track base_prior + evidence_discount separately so the driver
        # narrative + headline summary can decompose them for the
        # operator (vs. collapsing to a single misleading "P(freeze)").
        issuer_breakdown.append(
            (issuer, issuer_usd, prior, float(evidence_discount), ev_mode)
        )
        # v0.22.0: structured per-issuer row exposed on RecoveryEstimate
        # for the LE handoff + victim summary "Recovery Forecast" tables.
        # v0.22.1 (audit-fixes H4 + M1): preserve base prior pre-override
        # AND use Decimal math for effective_prior to avoid the binary-
        # float noise the contribution computation already guards against.
        _effective_prior_dec = Decimal(str(prior)) * evidence_discount
        per_issuer_rows.append(IssuerRecoveryRow(
            issuer=issuer,
            requested_usd=issuer_usd,
            base_prior=float(prior),
            base_prior_before_override=base_prior_before_override,
            capability_override_applied=(
                base_prior_before_override != float(prior)
            ),
            evidence_discount=float(evidence_discount),
            evidence_mode=ev_mode,
            effective_prior=float(_effective_prior_dec),
            expected_recovered_usd=_round_money(contribution),
            is_learned_prior=is_learned,
        ))

    if issuer_breakdown:
        top_issuer, top_usd, top_prior, top_discount, top_mode = max(
            issuer_breakdown,
            key=lambda x: x[1] * Decimal(x[2]) * Decimal(str(x[3])),
        )
        effective_prior = top_prior * top_discount
        # Honest narrative — decompose for the operator.
        if top_discount < 1.0:
            description = (
                f"Primary freeze target: ${top_usd:,.2f} at {top_issuer} "
                f"(issuer prior ≈ {top_prior:.0%}; evidence_mode={top_mode}, "
                f"discounted by {(1.0 - top_discount):.0%} for historical "
                f"receipt vs. confirmed current balance; effective "
                f"P(freeze) ≈ {effective_prior:.0%})"
            )
        else:
            description = (
                f"Primary freeze target: ${top_usd:,.2f} at {top_issuer} "
                f"(P(freeze) ≈ {effective_prior:.0%})"
            )
        drivers.append(RecoveryDriver(
            factor="primary_issuer",
            direction="positive",
            weight=float(top_usd * Decimal(str(effective_prior)) / max(total_loss, Decimal("1"))),
            description=description,
        ))

    # --- Jurisdiction adjustment ---
    #
    # v0.16.8 (round-9 scoring HIGH): multi-jurisdiction resolver +
    # sanctions overlay.
    #
    # Pre-v0.16.8 we only read VICTIM_JURISDICTION. That ignored:
    #   * Issuer jurisdiction (Tether BVI vs. Circle US — issuer location
    #     drives compliance team responsiveness independent of victim).
    #   * Perpetrator jurisdiction (if perp is in Russia, recovery is
    #     effectively unenforceable post-freeze even when issuer + victim
    #     are both cooperative).
    # The combined multiplier is the MIN across all three (worst-case
    # friction wins) — matches the practical workflow: recovery requires
    # cooperation from every party in the chain.
    #
    # Sanctions overlay: when the case touched an OFAC-sanctioned entity
    # (Tornado Cash, Garantex, Bitzlato, etc.), apply a 0.30× multiplier
    # on top of the jurisdiction floor. Recovery is technically possible
    # but requires OFAC-license-bearing counsel, which slows everything.
    jurisdiction_raw = (brief.get("VICTIM_JURISDICTION") or "").strip()
    issuer_jur = (brief.get("ISSUER_JURISDICTION") or "").strip()
    perp_jur = (brief.get("PERPETRATOR_JURISDICTION") or "").strip()
    victim_mult = _resolve_jurisdiction_multiplier(jurisdiction_raw)
    multipliers: list[tuple[str, str, float]] = [
        ("victim", jurisdiction_raw, victim_mult),
    ]
    if issuer_jur:
        multipliers.append(("issuer", issuer_jur,
                            _resolve_jurisdiction_multiplier(issuer_jur)))
    if perp_jur:
        multipliers.append(("perpetrator", perp_jur,
                            _resolve_jurisdiction_multiplier(perp_jur)))
    # Combined = MIN of contributors. Worst-case venue wins.
    role, who, jur_mult = min(multipliers, key=lambda t: t[2])

    # Sanctions overlay. The brief is expected to surface this via
    # `RISK_ASSESSMENT.ofac_exposure` (bool/str truthy). Conservative
    # default: no overlay when the field is absent.
    risk = brief.get("RISK_ASSESSMENT") or {}
    ofac_exposed = bool(
        risk.get("ofac_exposure")
        or risk.get("sanctions_exposure")
        or risk.get("touched_sanctioned_entity")
    )
    sanctions_mult = 0.30 if ofac_exposed else 1.00
    combined_mult = jur_mult * sanctions_mult

    # --- Bridge / DEX friction (computed UP-FRONT) ---
    #
    # v0.32.1 (financial-audit CRITICAL): friction must fold into the
    # SINGLE reconciling multiplier applied uniformly to the headline,
    # the per-issuer rows, AND the CI bounds. Pre-fix, friction was
    # applied ONLY to the scalar headline while the per-issuer rows + CI
    # carried combined_mult alone — so on ANY case with a bridge/DEX hop
    # the per-issuer table over-summed the headline by up to
    # 1/(1-0.30) ≈ 43%, re-opening the v0.22.1-C1 "table doesn't sum to
    # headline" defect. (5% per hop, capped at 30%; no threshold gate —
    # any complexity reduces expected recovery proportionally. The
    # explanatory driver is appended further below.)
    cross_chain_count = len(brief.get("CROSS_CHAIN_HANDOFFS") or [])
    dex_count = len(brief.get("DEX_SWAPS") or [])
    total_hops = cross_chain_count + dex_count
    friction = min(0.30, 0.05 * total_hops) if total_hops > 0 else 0.0

    # The ONE multiplier: jurisdiction × sanctions × (1 - trace friction).
    final_mult = Decimal(str(combined_mult)) * Decimal(str(1.0 - friction))

    expected_recovered = expected_freezable * final_mult

    # v0.22.1 (audit-fix C1) + v0.32.1: rescale each per-issuer row's
    # `expected_recovered_usd` by the SAME final multiplier so the
    # per-issuer LE Section 5.4 table sums to the headline. Pre-v0.22.1
    # the rows carried the pre-multiplier contribution (table showed
    # "Tether $850K" while headline read "$38K"); pre-v0.32.1 they
    # carried combined_mult but not friction (table over-summed the
    # friction-discounted headline).
    if per_issuer_rows:
        for _row in per_issuer_rows:
            _row.expected_recovered_usd = _round_money(
                _row.expected_recovered_usd * final_mult
            )

    if jur_mult < 0.9:
        drivers.append(RecoveryDriver(
            factor="jurisdiction",
            direction="negative",
            weight=1.0 - jur_mult,
            description=(
                f"{role.capitalize()} jurisdiction {who or '(unknown)'!r} "
                f"reduces expected recovery by {(1.0-jur_mult)*100:.0f}% "
                "(cross-border / non-cooperative venue friction)."
            ),
        ))
    elif jur_mult >= 1.0:
        drivers.append(RecoveryDriver(
            factor="jurisdiction",
            direction="positive",
            weight=jur_mult - 0.9,
            description=(
                f"Jurisdiction {jurisdiction_raw or '(unknown)'!r} is favorable "
                "(cooperative MLAT venue)."
            ),
        ))
    if ofac_exposed:
        drivers.append(RecoveryDriver(
            factor="ofac_sanctions",
            direction="negative",
            weight=0.70,
            description=(
                "Case funds touched an OFAC-sanctioned entity "
                "(e.g., Tornado Cash, Garantex). Recovery requires "
                "specialized counsel licensed to interact with sanctioned "
                "infrastructure — adds 6-12mo delay and ~70% reduction in "
                "expected recoverable amount."
            ),
        ))

    # --- Concentration adjustment ---
    # More concentrated = easier to recover. If 80%+ of expected is
    # at a single issuer, that's a positive signal.
    if total_loss > 0 and issuer_breakdown:
        top_share = float(
            max(issuer_breakdown, key=lambda x: x[1])[1] / total_loss
        )
        if top_share >= 0.7:
            drivers.append(RecoveryDriver(
                factor="concentration",
                direction="positive",
                weight=top_share,
                description=(
                    f"{top_share*100:.0f}% of loss concentrated at one freeze "
                    "target — straightforward to action."
                ),
            ))
        elif top_share <= 0.2 and len(issuer_breakdown) >= 4:
            drivers.append(RecoveryDriver(
                factor="concentration",
                direction="negative",
                weight=0.3,
                description=(
                    "Funds dispersed across many destinations; recovery "
                    "requires coordinated multi-issuer action."
                ),
            ))

    # --- Bridge / DEX friction driver ---
    #
    # The friction multiplier itself was computed up-front and folded
    # into `final_mult` (applied uniformly to headline + per-issuer rows
    # + CI). Here we only surface the explanatory driver when friction is
    # meaningful (~10%+); below that it's signal noise on the brief.
    # (v0.16.10: smooth per-hop linear contribution, no threshold gate.)
    if friction >= 0.10:
        drivers.append(RecoveryDriver(
            factor="trace_complexity",
            direction="negative",
            weight=friction,
            description=(
                f"{cross_chain_count} bridge hop(s) + {dex_count} DEX swap(s) "
                f"add trace complexity (~{friction*100:.0f}% recovery friction)."
            ),
        ))

    # --- Confidence interval ---
    #
    # v0.17.1 (QUANT-2): the CI is now anchored to the Beta credible
    # interval of the freeze-probability distribution, NOT a hand-
    # rolled ±0.35σ Gaussian. The prior CI was statistically
    # indefensible for two reasons:
    #
    #   1. Recovery outcomes are bimodal (likely $0 or likely the
    #      full freezable amount) — a Gaussian centered on the mean
    #      under-reports tail risk on small cases and over-reports
    #      on large concentrated ones.
    #
    #   2. The 0.35σ multiplier had no derivation — it was a magic
    #      number. The Beta posterior IS the right distribution for
    #      "what fraction of attempts at this issuer succeed."
    #
    # Strategy: for each issuer in the breakdown, use the Beta(α₀+
    # learned_successes, β₀+learned_failures) posterior to bracket
    # the realized USD. The top-level CI is the sum of per-issuer
    # bracketed amounts (independence assumption — documented as
    # such on the brief). When learned priors aren't available
    # (small samples), fall back to a wider 90% band derived from
    # the configured prior alone.
    if expected_recovered > 0:
        low, high = _compute_recovery_ci(
            issuer_breakdown=issuer_breakdown,
            # v0.32.1 (financial-audit CRITICAL): pass the SAME
            # friction-inclusive multiplier used for the headline + rows
            # so the CI band reconciles too (was jur_mult*sanctions_mult,
            # i.e. friction-free → band over-stated on bridged cases).
            jur_mult=combined_mult * (1.0 - friction),
            learned_priors=learned_priors,
        )
    else:
        low = high = Decimal("0")

    # v0.32.1 (financial-audit HIGH): a victim can never be promised more
    # than they lost. `expected_freezable` sums per-issuer REQUESTED USD,
    # which on pooled-victim cases legitimately exceeds THIS victim's loss
    # (the brief documents MAX_RECOVERABLE_USD = min(freezable, loss) and
    # clamps there). The scorer must apply the same cap so the headline,
    # the CI band, and the per-issuer rows never exceed total_loss — and
    # so the net/recommendation below can't flip "recommend" on an
    # inflated expected recovery. Rows are rescaled by the same factor to
    # preserve the table↔headline reconciliation.
    if total_loss > 0 and expected_recovered > total_loss:
        _clamp = total_loss / expected_recovered
        expected_recovered = total_loss
        for _row in per_issuer_rows:
            _row.expected_recovered_usd = _round_money(
                _row.expected_recovered_usd * _clamp
            )
    if total_loss > 0:
        high = min(high, total_loss)
        low = min(low, total_loss)

    # --- Probabilities ---
    #
    # v0.17.1 (QUANT-4): `p_any` is loaded from a calibration record
    # (env var RECUPERO_P_ANY_CALIBRATION_JSON) when available; falls
    # back to documented heuristic constants when not. The heuristic
    # floor/slope/cap come from the V-CFI01 pilot baseline (round-7
    # audit notes, ~12 historical cases at the time of calibration):
    #
    #   floor 0.40  ≈ base recovery rate observed even when the
    #                  freezable concentration is low (compliance
    #                  teams investigate when *anything* is named)
    #   slope 0.50  ≈ per-unit ratio of freezable/loss to incremental
    #                  P(any recovery); fit by least-squares against
    #                  the observed outcomes
    #   cap  0.95   ≈ the empirical ceiling — no published recovery
    #                  case reaches 100% certainty.
    #
    # The calibration record can override these as more freeze_outcomes
    # data accumulates. Format: {"floor": 0.4, "slope": 0.5, "cap": 0.95,
    # "min_freezable_usd": 1000}. Missing keys fall back to defaults.
    p_any_cal = _load_p_any_calibration()
    if expected_freezable >= Decimal(str(p_any_cal["min_freezable_usd"])):
        ratio = float(expected_freezable / max(total_loss, Decimal("1")))
        p_any = min(
            p_any_cal["cap"],
            p_any_cal["floor"] + ratio * p_any_cal["slope"],
        )
    else:
        p_any = 0.10
    # v0.32.1 (financial-audit MED): the breakeven recovery for "pays back
    # the engagement" must derive from the pricing constants, not a magic
    # number. A victim only nets >= 0 once recovery R clears ALL
    # out-of-pocket cost — the fixed fees PLUS the contingency skimmed off
    # the recovery itself: R - fixed_fees - contingency*R >= 0  →
    # R >= fixed_fees / (1 - contingency). Pre-fix this used a hardcoded
    # $12,000 (≈ the right value for the legacy $10,499 fees + 15%
    # contingency) that silently drifted out of lockstep whenever pricing
    # changed. Computed here (and reused below) so scoring + legal docs
    # stay locked to recupero._pricing.
    contingency_factor = _CONTINGENCY_PCT / Decimal("100")
    fixed_fees = _DIAGNOSTIC_FEE_USD + _ENGAGEMENT_FEE_USD
    _payback_breakeven = fixed_fees / (Decimal("1") - contingency_factor)
    p_payback = min(0.95, p_any * float(
        min(Decimal("1"), expected_recovered / _payback_breakeven)
    ))

    # --- Our revenue + victim net ---
    #
    # v0.16.7 (round-9 audit CRIT): engagement fee is charged
    # UNCONDITIONALLY at signing per the engagement letter — it is NOT
    # conditional on recovery outcome. The prior formula weighted
    # _ENGAGEMENT_FEE_USD by `p_payback`, which understated total revenue
    # by $10K * (1 - p_payback) and overstated victim-net by the same
    # amount. For a marginal case with p_payback=0.3, this overstated
    # net by $7,000 — flipping `caveat` cases into `recommend` and
    # systematically biasing engagement decisions toward engaging
    # cases that shouldn't be engaged.
    #
    # Also: contingency scales with actual recovered amount, so it must
    # be recomputed PER CI BAND POINT. Holding `expected_revenue`
    # constant across the band overstated `expected_net_high_usd` by
    # 15% * (high - expected_recovered) — wrong number in legal docs.
    # (`contingency_factor` + `fixed_fees` are defined above, at the
    # p_payback breakeven, so the two stay in lockstep.)
    expected_revenue = fixed_fees + expected_recovered * contingency_factor
    expected_net = expected_recovered - expected_revenue
    # Recompute contingency for the CI bounds so the band reflects the
    # actual fee schedule at each tail outcome.
    revenue_at_low = fixed_fees + low * contingency_factor
    revenue_at_high = fixed_fees + high * contingency_factor
    net_low = low - revenue_at_low
    net_high = high - revenue_at_high

    # --- Recommendation ---
    rec = _recommendation_from_net(expected_net)

    # --- Headline summary ---
    summary = _build_headline_summary(
        rec=rec,
        expected_recovered=expected_recovered,
        expected_net=expected_net,
        total_loss=total_loss,
        top_issuer_breakdown=issuer_breakdown,
        p_any=p_any,
    )

    # v0.22.0: sort per-issuer breakdown DESC by expected recovery so
    # the templates lead with the most-actionable issuer.
    per_issuer_sorted = sorted(
        per_issuer_rows,
        key=lambda r: r.expected_recovered_usd,
        reverse=True,
    )

    return RecoveryEstimate(
        expected_recovered_usd=_round_money(expected_recovered),
        expected_recovered_low_usd=_round_money(low),
        expected_recovered_high_usd=_round_money(high),
        probability_any_recovery_90d=round(p_any, 3),
        probability_pays_back_engagement_180d=round(p_payback, 3),
        expected_recupero_revenue_usd=_round_money(expected_revenue),
        expected_net_to_victim_usd=_round_money(expected_net),
        expected_net_low_usd=_round_money(net_low),
        expected_net_high_usd=_round_money(net_high),
        recommendation=rec,
        headline_summary=summary,
        drivers=drivers,
        per_issuer=per_issuer_sorted,
    )


# ---- helpers ---- #


def _parse_usd(s: Any) -> Decimal:
    """Parse a USD-shaped input into a finite, non-negative Decimal.

    Adversarial-input wave (v0.20.2): pre-fix this accepted "NaN",
    "Infinity", "-Infinity" via ``Decimal()`` — those values then
    propagated through the recovery math, producing nonsensical
    NaN-quantized outputs in the legal letter. Now: reject every
    non-finite Decimal and substitute zero (the conservative
    fallback the rest of the scorer is built around).
    """
    if isinstance(s, Decimal):
        d = s
    elif isinstance(s, (int, float)):
        if isinstance(s, float) and not math.isfinite(s):
            return Decimal("0")
        d = Decimal(str(s))
    else:
        s = str(s).replace("$", "").replace(",", "").strip()
        if not s:
            return Decimal("0")
        # Decimal("NaN") / Decimal("Infinity") parse without raising;
        # use is_finite() to filter both forms.
        try:
            d = Decimal(s)
        except (ArithmeticError, ValueError):
            return Decimal("0")
    if not d.is_finite():
        return Decimal("0")
    if d < 0:
        return Decimal("0")
    return d


# v0.17.1 (QUANT-4): default p_any calibration. These constants come
# from the V-CFI01 pilot baseline; future refresh-calibrations can
# override them via the RECUPERO_P_ANY_CALIBRATION_JSON env var (no
# code change needed). The brief footer surfaces the loaded values
# so operators can see which calibration is active.
_P_ANY_DEFAULT_CALIBRATION: dict[str, float] = {
    "floor": 0.40,            # base recovery rate even with low concentration
    "slope": 0.50,            # P(any) increase per unit freezable/loss ratio
    "cap": 0.95,              # empirical ceiling
    "min_freezable_usd": 1000.0,  # below this, no learned signal
}


def _load_p_any_calibration() -> dict[str, float]:
    """Load p_any calibration from env (RECUPERO_P_ANY_CALIBRATION_JSON)
    or return the documented defaults. Returns a complete dict — missing
    keys are filled from defaults.
    """
    import os
    raw = (os.environ.get("RECUPERO_P_ANY_CALIBRATION_JSON") or "").strip()
    if not raw:
        return dict(_P_ANY_DEFAULT_CALIBRATION)
    try:
        import json as _json
        parsed = _json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("expected JSON object")
        merged = dict(_P_ANY_DEFAULT_CALIBRATION)
        for k in merged:
            if k in parsed:
                try:
                    val = float(parsed[k])
                except (TypeError, ValueError):
                    continue
                # Reject NaN/Inf: max(0.0, NaN) returns NaN on CPython,
                # which would poison the recovery math downstream. Fall
                # back to the documented default for that key.
                if not math.isfinite(val):
                    continue
                merged[k] = val
        # Sanity-clamp so a typo can't ship insane values.
        merged["floor"] = max(0.0, min(0.99, merged["floor"]))
        merged["cap"] = max(merged["floor"], min(0.99, merged["cap"]))
        merged["slope"] = max(0.0, merged["slope"])
        merged["min_freezable_usd"] = max(0.0, merged["min_freezable_usd"])
        log.info(
            "p_any calibration loaded: floor=%.3f slope=%.3f cap=%.3f min_usd=%.0f",
            merged["floor"], merged["slope"], merged["cap"],
            merged["min_freezable_usd"],
        )
        return merged
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "RECUPERO_P_ANY_CALIBRATION_JSON parse failed (%s); "
            "using defaults", exc,
        )
        return dict(_P_ANY_DEFAULT_CALIBRATION)


def _compute_recovery_ci(
    *,
    issuer_breakdown: list[tuple[str, Decimal, float, float, str]],
    jur_mult: float,
    learned_priors: Any = None,
) -> tuple[Decimal, Decimal]:
    """Compute the (low, high) 90% credible interval for expected
    recovery, summed across issuers using the Beta posterior CI per
    issuer.

    Each tuple in ``issuer_breakdown`` is
    ``(issuer, issuer_usd, base_prior, evidence_discount, evidence_mode)``.
    We bracket each issuer's contribution at the issuer's 90% Beta
    credible interval bounds for P(freeze), multiplied by the issuer's
    USD × evidence_discount × jurisdiction_multiplier. The total CI
    is the sum (independence assumption — documented in the brief).

    Falls back to a ±35% band when learned priors are unavailable
    (small samples) — this is the v0.16.x heuristic preserved as a
    safety net when we don't have enough data for a real Beta CI.
    """
    if not issuer_breakdown:
        return (Decimal("0"), Decimal("0"))
    # Try to import Beta CI helper; if freeze_learning isn't reachable
    # for some reason, fall back to the heuristic.
    try:
        from recupero.freeze_learning.recorder import beta_credible_interval
    except ImportError:
        beta_credible_interval = None  # type: ignore[assignment]

    total_low = Decimal("0")
    total_high = Decimal("0")
    jur = Decimal(str(jur_mult))
    for (issuer, issuer_usd, base_prior, ev_discount, _ev_mode) in issuer_breakdown:
        learned = (
            learned_priors.get(issuer) if learned_priors else None
        )
        # RIGOR-Wave5 hardening: even if a learned-prior row sneaks
        # past the lookup-time validity gate (race with refresh, or
        # an in-memory mutation), reject NaN/Inf/out-of-range
        # p_any_freeze and non-positive sample_size HERE before
        # feeding them to int(round(...)) — that conversion raises
        # ValueError on NaN and the downstream beta CI math raises
        # on negative posterior variance.
        use_learned = (
            learned is not None
            and beta_credible_interval is not None
        )
        if use_learned:
            try:
                _lp_v = float(learned.p_any_freeze)
                _lp_n = int(learned.sample_size)
            except (TypeError, ValueError):
                use_learned = False
            else:
                if (not math.isfinite(_lp_v)
                        or _lp_v < 0.0 or _lp_v > 1.0
                        or _lp_n <= 0):
                    use_learned = False
        if use_learned:
            wins = int(round(_lp_v * _lp_n))
            lo, hi = beta_credible_interval(wins, _lp_n, level=0.90)
        else:
            # Heuristic fallback (the old ±35% band, preserved for
            # cases with no learned prior). Width matches the
            # pre-v0.17.1 hand-rolled CI so brief diffs stay
            # interpretable until learned data accumulates.
            lo = max(0.0, base_prior - 0.35)
            hi = min(1.0, base_prior + 0.35)
        ev = Decimal(str(ev_discount))
        # Each issuer's USD contribution at the CI bounds.
        total_low += issuer_usd * Decimal(str(lo)) * ev * jur
        total_high += issuer_usd * Decimal(str(hi)) * ev * jur
    return (total_low, total_high)


def _round_money(d: Decimal) -> Decimal:
    # Explicit ROUND_HALF_EVEN (banker's rounding) so the rounding mode
    # doesn't depend on global decimal-context state. Python's default
    # IS HALF_EVEN, but if anything upstream sets
    # `decimal.getcontext().rounding = ROUND_HALF_UP` (which some
    # financial libraries do), our 2dp money output would silently
    # change behavior. Pinning it here removes that variable.
    return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)


def _resolve_jurisdiction_multiplier(jur: str) -> float:
    if not jur:
        return _UNKNOWN_JURISDICTION_MULT
    j_lower = jur.lower()
    # Word-boundary match — `\bUK\b` does NOT match "Ukraine". The
    # earlier substring loop hit "UK" first for any string containing
    # "uk" and returned 1.0 (fully cooperative) for sanctioned/war-risk
    # jurisdictions whose names happened to contain that bigram.
    for key, mult in _JURISDICTION_MULT.items():
        if re.search(rf"\b{re.escape(key.lower())}\b", j_lower):
            return mult
    return _UNKNOWN_JURISDICTION_MULT


def _recommendation_from_net(expected_net: Decimal) -> str:
    if expected_net <= _REJECT_NET_BELOW:
        return "reject"
    if expected_net < _DISCOURAGE_NET_BELOW:
        return "discourage"
    if expected_net >= _RECOMMEND_NET_ABOVE:
        return "recommend"
    return "caveat"


def _build_headline_summary(
    *,
    rec: str,
    expected_recovered: Decimal,
    expected_net: Decimal,
    total_loss: Decimal,
    top_issuer_breakdown: list[tuple[str, Decimal, float, float, str]],
    p_any: float,
) -> str:
    """Build the human-readable summary line that's shipped in the
    brief's RECOVERY_ESTIMATE.

    The breakdown tuple shape is `(issuer, issuer_usd, base_prior,
    evidence_discount, evidence_mode)`. The headline reports the
    EFFECTIVE prior (base × discount) so it matches the driver
    narrative emitted by `score_recovery` — without this, the headline
    used to report base_prior while the driver reported effective,
    producing two contradictory numbers in the same object.
    """
    rec_phrase = {
        "recommend": "RECOMMEND ENGAGEMENT",
        "caveat": "CAVEAT ENGAGEMENT (small expected net)",
        "discourage": "DISCOURAGE ENGAGEMENT (low expected return)",
        "reject": "REJECT (no recoverable target identified)",
    }[rec]
    # v0.16.8 (round-9 scoring HIGH): when expected_net is negative
    # (recovery < our fees), don't render the nonsensical
    # "expected net recovery $-3,200.00" — switch to a "net cost"
    # framing that the customer-facing letter can read sensibly.
    if expected_net < 0:
        net_phrase = (
            f"expected net COST to victim ${abs(expected_net):,.2f} "
            f"(estimated recovery is less than engagement + diagnostic "
            "fees combined)"
        )
    else:
        net_phrase = f"expected net recovery ${expected_net:,.2f}"
    base = (
        f"{rec_phrase}: {net_phrase} "
        f"from ${total_loss:,.2f} loss; "
        f"P(any recovery)≈{p_any:.0%}."
    )
    if top_issuer_breakdown:
        # Rank by EFFECTIVE expected dollars (USD × base × discount)
        # so the "primary target" is the actually-most-recoverable
        # issuer, not the one with the highest gross balance.
        top = max(
            top_issuer_breakdown,
            key=lambda x: x[1] * Decimal(str(x[2])) * Decimal(str(x[3])),
        )
        top_issuer = top[0]
        top_usd = top[1]
        top_effective = top[2] * top[3]
        base += (
            f" Primary target: ${top_usd:,.2f} at {top_issuer} "
            f"(P(freeze)≈{top_effective:.0%})."
        )
    return base


__all__ = (
    "RecoveryDriver",
    "RecoveryEstimate",
    "score_recovery",
)
