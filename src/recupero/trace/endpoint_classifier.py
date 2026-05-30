"""Behavioral classification of UNLABELED trace endpoints (trace-depth #2).

The sweep heuristic in ``cex_attribution`` can only attribute a deposit
address when the hot wallet it sweeps to is already in the label DB. When
funds reach an exchange whose hot wallet ISN'T labeled (a new / obscure
venue), the endpoint is never recognized as a subpoena target. This module
recognizes such unlabeled exchange / service infrastructure from BEHAVIOR.

WHY NOT JUST FAN-IN: within a single theft trace, "many addresses → one
collector" is AMBIGUOUS — it is equally the signature of (a) a CEX deposit
aggregator and (b) the PERPETRATOR's own consolidation hub (the thief
sweeping split funds into one wallet they control). In-case fan-in CANNOT
tell them apart, because every in-case sender is on the theft trail either
way. Misclassifying the perp's hub as a CEX would point a subpoena at the
wrong party and mis-route recovery. So this classifier uses the one signal
that DOES discriminate: COUNTERPARTY DIVERSITY across the address's BROADER
activity. A real exchange hot wallet transacts with hundreds–thousands of
DISTINCT counterparties on both sides; a personal consolidation hub has a
handful. That diversity is measured by a bounded broader-activity probe
(``probe_endpoint_diversity``), not the in-case slice.

FORENSIC INVARIANT: this is a behavioral INFERENCE, never proof. The result
is "low"/"medium" confidence, NEVER "high" (only a label-DB hit is high).
A low-diversity address is reported as ``inconclusive`` — we make NO claim
that it is a CEX, precisely so the perp's hub is never mislabeled.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal

from recupero._common import canonical_address_key as _ck

__all__ = [
    "EndpointDiversity",
    "EndpointClassification",
    "classify_by_counterparty_diversity",
    "probe_endpoint_diversity",
    "infer_infrastructure_endpoints",
]

# Distinct-counterparty thresholds. Tuned conservatively: a perpetrator
# consolidation hub in a theft case rarely touches more than a few dozen
# distinct addresses, while an exchange hot wallet / deposit aggregator
# touches far more. Requiring HIGH diversity on BOTH sides (deposits in
# from many, withdrawals out to many) is the infrastructure signature and
# avoids flagging a one-directional collector (which a perp hub can mimic).
_HIGH_DIVERSITY = 40        # min distinct counterparties (each side) → infra candidate
_STRONG_DIVERSITY = 150     # distinct counterparties (either side) → bump low→medium


@dataclass(frozen=True)
class EndpointDiversity:
    """Distinct-counterparty counts from a broader-activity probe."""

    address: str
    distinct_inbound: int
    distinct_outbound: int
    total_inbound_txs: int
    total_outbound_txs: int
    probe_truncated: bool   # True if a fetch hit its max_results cap


@dataclass(frozen=True)
class EndpointClassification:
    """Behavioral classification of an unlabeled endpoint."""

    address: str
    classification: Literal[
        "likely_exchange_infrastructure", "inconclusive"
    ]
    confidence: Literal["medium", "low"]   # NEVER "high"
    distinct_inbound: int
    distinct_outbound: int
    reason: str


def classify_by_counterparty_diversity(
    *,
    address: str,
    distinct_inbound: int,
    distinct_outbound: int,
    high_diversity: int = _HIGH_DIVERSITY,
    strong_diversity: int = _STRONG_DIVERSITY,
) -> EndpointClassification:
    """Classify an endpoint from its distinct-counterparty diversity.

    ``likely_exchange_infrastructure`` only when diversity is HIGH on BOTH
    sides (many distinct funders AND many distinct recipients) — the
    deposit-in / withdraw-out signature of a hot wallet / aggregator that a
    perpetrator's consolidation hub does not exhibit. Confidence is "medium"
    only when one side is STRONGLY diverse, else "low"; NEVER "high".

    Anything below the bar is ``inconclusive`` — NO claim is made (so the
    perp's own hub is never mislabeled as an exchange).
    """
    if distinct_inbound >= high_diversity and distinct_outbound >= high_diversity:
        strong = (
            distinct_inbound >= strong_diversity
            or distinct_outbound >= strong_diversity
        )
        return EndpointClassification(
            address=address,
            classification="likely_exchange_infrastructure",
            confidence="medium" if strong else "low",
            distinct_inbound=distinct_inbound,
            distinct_outbound=distinct_outbound,
            reason=(
                f"high counterparty diversity ({distinct_inbound} distinct "
                f"senders, {distinct_outbound} distinct recipients) — the "
                "deposit-in/withdraw-out signature of exchange / service "
                "infrastructure, not a personal consolidation hub. "
                "Behavioral inference (correlation, not proof); confirm "
                "against the venue before relying on it."
            ),
        )
    return EndpointClassification(
        address=address,
        classification="inconclusive",
        confidence="low",
        distinct_inbound=distinct_inbound,
        distinct_outbound=distinct_outbound,
        reason=(
            f"counterparty diversity too low ({distinct_inbound} in / "
            f"{distinct_outbound} out) to distinguish exchange "
            "infrastructure from a perpetrator-controlled consolidation "
            "hub — NO exchange claim made."
        ),
    )


def probe_endpoint_diversity(
    address: str,
    *,
    adapter: Any,
    start_block: int,
    max_results: int = 2000,
) -> EndpointDiversity:
    """Measure an address's distinct-counterparty diversity by fetching its
    broader inbound + outbound activity via ``adapter``.

    Bounded by ``max_results`` per leg. Pure given the injected adapter
    (the only I/O is the adapter's fetch methods) → unit-testable with a
    fake adapter. Returns zero-diversity on an adapter with no inbound
    support (the base default), so non-EVM endpoints simply don't classify.
    """
    inbound: list[dict[str, Any]] = []
    outbound: list[dict[str, Any]] = []
    fetches = (
        (adapter.fetch_native_inflows, inbound),
        (adapter.fetch_erc20_inflows, inbound),
        (adapter.fetch_native_outflows, outbound),
        (adapter.fetch_erc20_outflows, outbound),
    )
    truncated = False
    for fetch, sink in fetches:
        try:
            rows = fetch(address, start_block, max_results=max_results)
        except TypeError:
            # Outflow methods may not accept max_results in some adapters.
            rows = fetch(address, start_block)
        except Exception:  # noqa: BLE001 — a probe leg failing must not abort
            rows = []
        if len(rows) >= max_results:
            truncated = True
        sink.extend(rows)

    distinct_in = {
        _ck(r.get("from", "")) for r in inbound if r.get("from")
    }
    distinct_out = {
        _ck(r.get("to", "")) for r in outbound if r.get("to")
    }
    distinct_in.discard("")
    distinct_out.discard("")
    return EndpointDiversity(
        address=address,
        distinct_inbound=len(distinct_in),
        distinct_outbound=len(distinct_out),
        total_inbound_txs=len(inbound),
        total_outbound_txs=len(outbound),
        probe_truncated=truncated,
    )


def infer_infrastructure_endpoints(
    case: Any,
    *,
    adapter: Any,
    start_block: int,
    max_probe: int = 10,
    min_inflow_usd: Decimal = Decimal("1000"),
) -> list[dict[str, Any]]:
    """Probe the top unlabeled terminal endpoints in ``case`` and return the
    ones that classify as likely exchange / service infrastructure.

    Candidates are the case's UNLABELED counterparties that sit on the
    ``adapter``'s chain, ranked by trace-visible USD inflow and capped to
    ``max_probe`` (bounded I/O — this is the opt-in deep tier). Each is
    diversity-probed and classified; only ``likely_exchange_infrastructure``
    hits are returned, as plain dicts ready for the brief's subpoena-targets
    section. Confidence stays "low"/"medium" — a behavioral inference.

    Pure given the injected ``adapter`` (the only I/O is its fetches), so it
    is unit-testable with a fake adapter + a duck-typed case.
    """
    transfers = getattr(case, "transfers", None) or []
    if not transfers:
        return []
    adapter_chain = getattr(getattr(adapter, "chain", None), "value", None) or str(
        getattr(adapter, "chain", "")
    )

    # Per-address trace-visible inflow + the chain it was seen on. Only
    # consider addresses that appear as a RECIPIENT (a terminal/holding
    # endpoint) and are unlabeled.
    unlabeled = {
        _ck(a) for a in (getattr(case, "unlabeled_counterparties", None) or []) if a
    }
    unlabeled.discard("")
    inflow: dict[str, Decimal] = {}
    raw_by_key: dict[str, str] = {}
    chain_by_key: dict[str, str] = {}
    for t in transfers:
        dst_raw = getattr(t, "to_address", None)
        key = _ck(dst_raw or "")
        if not key or key not in unlabeled:
            continue
        usd = getattr(t, "usd_value_at_tx", None)
        with contextlib.suppress(TypeError, ValueError, ArithmeticError):
            inflow[key] = inflow.get(key, Decimal("0")) + (
                Decimal(usd) if usd is not None else Decimal("0")
            )
        raw_by_key.setdefault(key, dst_raw or key)
        tchain = getattr(getattr(t, "chain", None), "value", None) or str(
            getattr(t, "chain", "")
        )
        chain_by_key.setdefault(key, tchain)

    # Rank by inflow, keep those above the floor + on the adapter's chain.
    ranked = sorted(
        (k for k in inflow if inflow[k] >= min_inflow_usd
         and chain_by_key.get(k) == adapter_chain),
        key=lambda k: inflow[k],
        reverse=True,
    )[:max_probe]

    out: list[dict[str, Any]] = []
    for key in ranked:
        raw = raw_by_key.get(key, key)
        try:
            div = probe_endpoint_diversity(raw, adapter=adapter, start_block=start_block)
        except Exception:  # noqa: BLE001 — a probe failure must not abort the trace
            continue
        result = classify_by_counterparty_diversity(
            address=raw,
            distinct_inbound=div.distinct_inbound,
            distinct_outbound=div.distinct_outbound,
        )
        if result.classification != "likely_exchange_infrastructure":
            continue
        out.append({
            "address": raw,
            "chain": chain_by_key.get(key, adapter_chain),
            "heuristic": "counterparty_diversity",
            "classification": result.classification,
            "attribution_confidence": result.confidence,
            "distinct_inbound": result.distinct_inbound,
            "distinct_outbound": result.distinct_outbound,
            "inflow_usd": str(inflow.get(key, Decimal("0"))),
            "note": result.reason,
        })
    return out
