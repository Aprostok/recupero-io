"""v0.38.0 — fund-flow EXPOSURE summary (TRM/Chainalysis-style headline).

The single most "TRM/Chainalysis" output: a per-case number that says *what
fraction of the traced value reached each illicit category* — e.g. "12.3% of
traced value ($1.2M) reached OFAC-sanctioned entities; 4.1% reached high-risk
mixers." TRM's KYT headline is exactly this exposure-by-category breakdown.

The pieces already existed (`risk_scoring.load_high_risk_db`,
`indirect_exposure.compute_indirect_exposure`) but were never rolled up into a
first-class exposure % with a denominator. This module does that rollup:

  * DIRECT exposure — value of traced transfers landing AT a high-risk address,
    bucketed by that address's category. Each high-risk address contributes its
    summed traced inflow once. This is the defensible headline number ("funds
    reached a sanctioned/mixer address").
  * INDIRECT exposure — the multi-hop, hop-decayed, amount-share-weighted
    exposure from `compute_indirect_exposure`, folded in as a SEPARATE figure so
    the headline % stays the direct, easy-to-defend number (a court-facing
    deliverable should not lead with a decayed inference).

Confidence posture (consistent with the rest of the engine): direct exposure is
a structural fact (a transfer landed at a labeled address); indirect exposure is
inference and is labeled as such. Returns ``None`` when there is no high-risk
exposure at all, so the brief stays clean on a benign case.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from typing import Any

from recupero._common import canonical_address_key as _ck
from recupero.models import Case

# Human-readable category names for the headline + per-category rows. Keys are
# the risk_category values produced by risk_scoring.load_high_risk_db.
_CATEGORY_HUMAN: dict[str, str] = {
    "ofac_sanctioned": "OFAC-sanctioned entities",
    "intl_sanctioned": "internationally-sanctioned entities",
    "mixer_sanctioned": "OFAC-sanctioned mixers",
    "mixer_high_risk": "high-risk mixers",
    "ransomware": "ransomware operators",
    "scam_drainer": "scam / drainer infrastructure",
    "darknet_market": "darknet markets",
    # internal_blacklist: produced by risk_scoring.load_high_risk_db (severity-3
    # "high"). Without it the rollup fell back to a generic label + rank 0
    # (sorted last), inconsistent with graph_ui's "high" band for the same
    # category.
    "internal_blacklist": "internal known-bad attribution",
}

# Severity ranking for choosing the headline category when several are present
# (a sanctioned exposure outranks a mixer exposure even if smaller by $).
_CATEGORY_RANK: dict[str, int] = {
    "ofac_sanctioned": 100,
    "mixer_sanctioned": 95,
    "intl_sanctioned": 90,
    "ransomware": 80,
    "darknet_market": 70,
    "scam_drainer": 60,
    "internal_blacklist": 55,  # "high" band, below the named-service categories
    "mixer_high_risk": 50,
}


def _human(cat: str) -> str:
    return _CATEGORY_HUMAN.get(cat, cat.replace("_", " "))


def _pct(num: Decimal, denom: Decimal) -> float:
    if denom <= 0:
        return 0.0
    return float(min(Decimal("100"), (num / denom) * 100).quantize(Decimal("0.01")))


def _usd(amount: Decimal) -> str:
    # Never render "$NaN"/"$Infinity" in an exposure rollup that feeds legal
    # artifacts — a poisoned/aggregated non-finite value falls back to "$0.00".
    if not amount.is_finite():
        return "$0.00"
    return f"${amount:,.2f}"


def compute_exposure_summary(
    case: Case,
    high_risk_db: dict[str, Any],
    *,
    total_traced_usd: Decimal | None = None,
    indirect: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Roll up the case's high-risk exposure into a category breakdown + %.

    Args:
      case: the traced case.
      high_risk_db: ``{canonical_addr: HighRiskEntry}`` from
        ``risk_scoring.load_high_risk_db`` (categories: ofac_sanctioned,
        mixer_sanctioned, mixer_high_risk, intl_sanctioned, ransomware,
        scam_drainer, darknet_market).
      total_traced_usd: denominator for the % (the caller's authoritative
        traced/drained total). Falls back to the sum of the seed's outbound
        value when not supplied.
      indirect: optional ``compute_indirect_exposure`` result
        ``{addr: IndirectExposureResult}`` — folded in as the multi-hop figure.

    Returns ``None`` when no high-risk exposure exists (keeps the brief clean).
    """
    if not case.transfers or not high_risk_db:
        return None

    seed = _ck(case.seed_address)

    # Denominator: caller-supplied traced total, else the seed's outbound value.
    denom = total_traced_usd
    if denom is None or denom <= 0:
        denom = Decimal("0")
        for t in case.transfers:
            if (
                t.usd_value_at_tx
                and t.usd_value_at_tx > 0
                and _ck(t.from_address) == seed
            ):
                denom += t.usd_value_at_tx

    # DIRECT exposure: traced value landing AT a high-risk address, by category.
    direct_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    direct_addrs: dict[str, set[str]] = defaultdict(set)
    for t in case.transfers:
        if not t.usd_value_at_tx or t.usd_value_at_tx <= 0:
            continue
        dst = _ck(t.to_address)
        entry = high_risk_db.get(dst)
        if entry is None:
            continue
        cat = (getattr(entry, "risk_category", "") or "").lower()
        if not cat:
            continue
        direct_usd[cat] += t.usd_value_at_tx
        direct_addrs[cat].add(dst)

    if not direct_usd and not indirect:
        return None

    # INDIRECT exposure (multi-hop) by category, from the verified scorer.
    indirect_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    indirect_addrs: dict[str, set[str]] = defaultdict(set)
    if indirect:
        for addr, res in indirect.items():
            for p in getattr(res, "paths", []) or []:
                if getattr(p, "hop_count", 1) <= 1:
                    continue  # 1-hop is the direct number above
                cat = (getattr(p, "risk_category", "") or "").lower()
                amt = getattr(p, "weighted_amount_usd", None)
                # is_finite BEFORE the compare: weighted_amount_usd is a computed
                # aggregate, and `Decimal("NaN") <= 0` RAISES InvalidOperation
                # (crashing the rollup) rather than returning False.
                if not cat or amt is None or not amt.is_finite() or amt <= 0:
                    continue
                indirect_usd[cat] += amt
                indirect_addrs[cat].add(_ck(addr))

    by_category: list[dict[str, Any]] = []
    all_cats = set(direct_usd) | set(indirect_usd)
    for cat in sorted(all_cats, key=lambda c: -_CATEGORY_RANK.get(c, 0)):
        d = direct_usd.get(cat, Decimal("0"))
        i = indirect_usd.get(cat, Decimal("0"))
        by_category.append({
            "category": cat,
            "label": _human(cat),
            "direct_usd": _usd(d),
            "direct_pct": _pct(d, denom),
            "direct_address_count": len(direct_addrs.get(cat, set())),
            "indirect_usd": _usd(i),
            "indirect_address_count": len(indirect_addrs.get(cat, set())),
        })

    # Headline = the highest-ranked category with direct exposure (falls back to
    # the highest-ranked indirect-only category).
    headline_cat = None
    for row in by_category:
        if row["direct_pct"] > 0:
            headline_cat = row
            break
    if headline_cat is None and by_category:
        headline_cat = by_category[0]

    total_direct = sum(direct_usd.values(), start=Decimal("0"))
    headline = None
    if headline_cat is not None:
        amt = headline_cat["direct_usd"] if headline_cat["direct_pct"] > 0 else headline_cat["indirect_usd"]
        pct = headline_cat["direct_pct"] if headline_cat["direct_pct"] > 0 else None
        if pct is not None:
            headline = (
                f"{pct:.1f}% of traced value ({amt}) reached "
                f"{headline_cat['label']}"
            )
        else:
            headline = (
                f"Indirect exposure to {headline_cat['label']} "
                f"({amt}, multi-hop) detected"
            )

    return {
        "total_traced_usd": _usd(denom),
        "total_direct_exposure_usd": _usd(total_direct),
        "total_direct_exposure_pct": _pct(total_direct, denom),
        "headline": headline,
        "by_category": by_category,
        "note": (
            "Direct exposure is a structural fact (traced value landed at a "
            "labeled high-risk address). Indirect exposure is hop-decayed "
            "inference (funds traceably passed through intermediaries to/from a "
            "high-risk address) and is reported separately."
        ),
    }
