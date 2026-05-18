"""Recovery probability scoring + expected-value computation (v0.14.1).

Pure function `score_recovery(brief)` returns a structured
RecoveryEstimate that the brief surfaces and the operator's
decision-making is anchored on.
"""

from __future__ import annotations

import logging
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
    DIAGNOSTIC_FEE_USD as _DIAGNOSTIC_FEE_USD,
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
    """
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
    expected_freezable = Decimal("0")
    issuer_breakdown: list[tuple[str, Decimal, float, float, str]] = []
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
        prior = None
        if learned_priors and issuer in learned_priors:
            lp = learned_priors[issuer]
            prior = float(getattr(lp, "p_any_freeze", lp))
        if prior is None:
            prior = _lookup_issuer_prior(issuer)
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
        expected_freezable += issuer_usd * Decimal(str(prior)) * evidence_discount
        # Track base_prior + evidence_discount separately so the driver
        # narrative + headline summary can decompose them for the
        # operator (vs. collapsing to a single misleading "P(freeze)").
        issuer_breakdown.append(
            (issuer, issuer_usd, prior, float(evidence_discount), ev_mode)
        )

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

    expected_recovered = expected_freezable * Decimal(str(combined_mult))

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

    # --- Bridge / DEX friction ---
    cross_chain_count = len(brief.get("CROSS_CHAIN_HANDOFFS") or [])
    dex_count = len(brief.get("DEX_SWAPS") or [])
    if cross_chain_count >= 2 or dex_count >= 3:
        friction = min(0.3, 0.05 * (cross_chain_count + dex_count))
        expected_recovered *= Decimal(str(1.0 - friction))
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
    # Heuristic: spread is wider when expected is small (more
    # binary outcome) and tightens for large concentrated cases.
    if expected_recovered > 0:
        sigma = float(expected_recovered) * 0.35
        low = max(Decimal("0"), expected_recovered - Decimal(str(sigma * 1.96)))
        high = expected_recovered + Decimal(str(sigma * 1.96))
    else:
        low = high = Decimal("0")

    # --- Probabilities ---
    if expected_freezable >= Decimal("1000"):
        p_any = min(0.95, 0.4 + float(expected_freezable / max(total_loss, Decimal("1"))) * 0.5)
    else:
        p_any = 0.10
    p_payback = min(0.95, p_any * float(
        min(Decimal("1"), expected_recovered / Decimal("12000"))
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
    contingency_factor = _CONTINGENCY_PCT / Decimal("100")
    fixed_fees = _DIAGNOSTIC_FEE_USD + _ENGAGEMENT_FEE_USD
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
    )


# ---- helpers ---- #


def _parse_usd(s: Any) -> Decimal:
    if isinstance(s, (int, float, Decimal)):
        return Decimal(str(s))
    s = str(s).replace("$", "").replace(",", "").strip()
    if not s:
        return Decimal("0")
    return Decimal(s)


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
