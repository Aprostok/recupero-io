"""v0.38 (#1) — attribution-coverage report + prioritized labeling targets.

The single biggest gap vs Chainalysis is ATTRIBUTION DATA SCALE: a trace lands
at ``0x71c7…`` and we say "unlabeled wallet" where Chainalysis says "Binance
hot wallet 7". The label *pipeline* already exists (harvest → review → promote);
the moat is the size of the labeled universe, which grows from operator work.

This module makes that growth SYSTEMATIC instead of ad-hoc. For a traced case it
computes:

  * COVERAGE — what fraction of the traced value (and of the distinct
    counterparties) lands at an address we can attribute (a LabelStore hit or a
    high-risk-DB hit) vs an unlabeled one. The honest "how blind are we on this
    case" number.
  * TARGETS — the highest-VALUE unlabeled addresses, ranked by traced USD
    landing on them. These are exactly the addresses worth an operator's
    research time: label the top few and you attribute the largest share of the
    flow. Each becomes a candidate for the existing review→promote pipeline.

No fabrication: an address is "labeled" only on a real LabelStore / high-risk-DB
hit; targets are reported verbatim (address + observed inbound), never guessed.
Returns ``None`` on an empty / valueless case.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from typing import Any

from recupero._common import canonical_address_key as _ck
from recupero.models import Case


def _usd(amount: Decimal) -> str:
    return f"${amount:,.2f}"


def _pct(num: Decimal, denom: Decimal) -> float:
    if denom <= 0:
        return 0.0
    return float(min(Decimal("100"), (num / denom) * 100).quantize(Decimal("0.01")))


def compute_attribution_coverage(
    case: Case,
    label_store: Any,
    *,
    high_risk_db: dict[str, Any] | None = None,
    top_n: int = 10,
) -> dict[str, Any] | None:
    """Quantify attribution coverage of the traced value + rank the highest-
    value unlabeled counterparties as labeling targets.

    Args:
      case: the traced case.
      label_store: a ``LabelStore`` (``.lookup(addr, chain, point_in_time=...)``)
        or None. None → every address counts as unlabeled (pure coverage gap).
      high_risk_db: optional ``{canonical_addr: HighRiskEntry}`` — a high-risk
        hit counts as attributed (it IS an identification).
      top_n: number of unlabeled targets to surface.

    Returns a dict (coverage %, totals, by-category counts, ranked targets) or
    ``None`` when the case has no valued transfers.
    """
    if not case.transfers:
        return None
    high_risk_db = high_risk_db or {}
    seed = _ck(case.seed_address)

    # Inbound traced USD + a representative chain per counterparty (the value
    # LANDING at an address is what makes attributing it worthwhile).
    inbound_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    inbound_count: dict[str, int] = defaultdict(int)
    chain_of: dict[str, Any] = {}
    for t in case.transfers:
        dst = _ck(t.to_address)
        if not dst or dst == seed:
            continue  # the victim/seed is known; not an attribution target
        if t.usd_value_at_tx and t.usd_value_at_tx > 0:
            inbound_usd[dst] += t.usd_value_at_tx
        inbound_count[dst] += 1
        chain_of.setdefault(dst, t.chain)

    if not inbound_count:
        return None

    def _labeled(addr: str) -> tuple[bool, str | None, str | None]:
        """(is_attributed, source, name). LabelStore hit OR high-risk hit."""
        entry = high_risk_db.get(addr)
        if entry is not None:
            return True, "high_risk", getattr(entry, "name", None)
        if label_store is not None:
            try:
                lbl = label_store.lookup(
                    addr, chain=chain_of.get(addr),
                    point_in_time=case.incident_time,
                )
            except Exception:  # noqa: BLE001
                lbl = None
            if lbl is not None:
                cat = getattr(lbl.category, "value", None) or str(lbl.category)
                return True, cat, getattr(lbl, "name", None)
        return False, None, None

    total_value = sum(inbound_usd.values(), start=Decimal("0"))
    labeled_value = Decimal("0")
    labeled_addrs = 0
    by_source: dict[str, int] = defaultdict(int)
    unlabeled: list[tuple[str, Decimal, int]] = []
    for addr, n in inbound_count.items():
        is_lab, source, _name = _labeled(addr)
        if is_lab:
            labeled_addrs += 1
            labeled_value += inbound_usd.get(addr, Decimal("0"))
            by_source[source or "labeled"] += 1
        else:
            unlabeled.append((addr, inbound_usd.get(addr, Decimal("0")), n))

    total_addrs = len(inbound_count)
    # Highest-value unlabeled counterparties = the prioritized labeling targets.
    unlabeled.sort(key=lambda x: (-x[1], -x[2]))
    targets = [
        {
            "address": addr,
            "chain": getattr(chain_of.get(addr), "value", None) or str(chain_of.get(addr)),
            "inbound_usd": _usd(val),
            "inbound_usd_numeric": float(val),
            "transfer_count": cnt,
        }
        for addr, val, cnt in unlabeled[:max(0, top_n)]
    ]

    headline = (
        f"{_pct(labeled_value, total_value):.1f}% of traced value "
        f"({_usd(labeled_value)} of {_usd(total_value)}) lands at attributed "
        f"addresses; {len(unlabeled)} unlabeled counterpart(ies) remain"
    )

    return {
        "coverage_pct_by_value": _pct(labeled_value, total_value),
        "coverage_pct_by_count": _pct(Decimal(labeled_addrs), Decimal(total_addrs)),
        "attributed_value": _usd(labeled_value),
        "total_counterparty_value": _usd(total_value),
        "attributed_count": labeled_addrs,
        "total_counterparty_count": total_addrs,
        "attributed_by_source": dict(by_source),
        "headline": headline,
        "labeling_targets": targets,
        "note": (
            "An address is 'attributed' only on a real label-store or high-risk-"
            "DB hit. The labeling_targets are the highest-VALUE unlabeled "
            "counterparties — researching + labeling them (via the candidate "
            "review→promote pipeline) attributes the largest share of the flow. "
            "This is the systematic loop for closing the attribution-data gap."
        ),
    }
