"""Recovery probability scoring + expected-value computation (v0.14.1).

Pure function `score_recovery(brief)` returns a structured
RecoveryEstimate that the brief surfaces and the operator's
decision-making is anchored on.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any

log = logging.getLogger(__name__)


# Pricing constants — match recupero._pricing.
_DIAGNOSTIC_FEE_USD = Decimal("499")
_ENGAGEMENT_FEE_USD = Decimal("10000")
_CONTINGENCY_PCT = Decimal("15")  # of recovered amount


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


# Per-jurisdiction multipliers. USA/EU/UK = baseline 1.0;
# non-cooperative jurisdictions reduce expected recovery.
_JURISDICTION_MULT: dict[str, float] = {
    "USA": 1.0,
    "United States": 1.0,
    "United Kingdom": 1.0,
    "UK": 1.0,
    "EU": 0.95,
    "Canada": 0.95,
    "Singapore": 0.85,
    "UAE": 0.7,
    "Russia": 0.15,
    "Belarus": 0.10,
    "North Korea": 0.05,
    "Iran": 0.10,
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
    """
    drivers: list[RecoveryDriver] = []

    # --- Pull inputs ---
    try:
        total_loss = _parse_usd(brief.get("TOTAL_LOSS_USD") or "$0")
    except Exception:  # noqa: BLE001
        total_loss = Decimal("0")

    freezable_entries = brief.get("FREEZABLE") or []
    unrecoverable_entries = brief.get("UNRECOVERABLE") or []

    # --- Per-issuer expected recovery ---
    expected_freezable = Decimal("0")
    issuer_breakdown: list[tuple[str, Decimal, float]] = []
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
            prior = _ISSUER_FREEZE_PRIOR.get(issuer, _UNKNOWN_ISSUER_PRIOR)
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
        expected_freezable += issuer_usd * Decimal(prior)
        issuer_breakdown.append((issuer, issuer_usd, prior))

    if issuer_breakdown:
        top_issuer, top_usd, top_prior = max(
            issuer_breakdown, key=lambda x: x[1] * Decimal(x[2]),
        )
        drivers.append(RecoveryDriver(
            factor="primary_issuer",
            direction="positive",
            weight=float(top_usd * Decimal(top_prior) / max(total_loss, Decimal("1"))),
            description=(
                f"Primary freeze target: ${top_usd:,.2f} at {top_issuer} "
                f"(P(freeze)≈{top_prior:.0%})"
            ),
        ))

    # --- Jurisdiction adjustment ---
    jurisdiction_raw = (brief.get("VICTIM_JURISDICTION") or "").strip()
    jur_mult = _resolve_jurisdiction_multiplier(jurisdiction_raw)
    expected_recovered = expected_freezable * Decimal(jur_mult)
    if jur_mult < 0.9:
        drivers.append(RecoveryDriver(
            factor="jurisdiction",
            direction="negative",
            weight=1.0 - jur_mult,
            description=(
                f"Jurisdiction {jurisdiction_raw or '(unknown)'!r} reduces "
                f"expected recovery by {(1.0-jur_mult)*100:.0f}% "
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
        expected_recovered *= Decimal(1.0 - friction)
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
    contingency_factor = _CONTINGENCY_PCT / Decimal("100")
    expected_revenue = (
        _DIAGNOSTIC_FEE_USD
        + _ENGAGEMENT_FEE_USD * Decimal(p_payback)
        + expected_recovered * contingency_factor
    )
    expected_net = expected_recovered - expected_revenue
    net_low = low - expected_revenue
    net_high = high - expected_revenue

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
    return d.quantize(Decimal("0.01"))


def _resolve_jurisdiction_multiplier(jur: str) -> float:
    if not jur:
        return _UNKNOWN_JURISDICTION_MULT
    j_lower = jur.lower()
    for key, mult in _JURISDICTION_MULT.items():
        if key.lower() in j_lower:
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
    top_issuer_breakdown: list[tuple[str, Decimal, float]],
    p_any: float,
) -> str:
    rec_phrase = {
        "recommend": "RECOMMEND ENGAGEMENT",
        "caveat": "CAVEAT ENGAGEMENT (small expected net)",
        "discourage": "DISCOURAGE ENGAGEMENT (low expected return)",
        "reject": "REJECT (no recoverable target identified)",
    }[rec]
    base = (
        f"{rec_phrase}: expected net recovery "
        f"${expected_net:,.2f} from ${total_loss:,.2f} loss; "
        f"P(any recovery)≈{p_any:.0%}."
    )
    if top_issuer_breakdown:
        top = max(top_issuer_breakdown, key=lambda x: x[1] * Decimal(x[2]))
        base += (
            f" Primary target: ${top[1]:,.2f} at {top[0]} "
            f"(P(freeze)≈{top[2]:.0%})."
        )
    return base


__all__ = (
    "RecoveryDriver",
    "RecoveryEstimate",
    "score_recovery",
)
