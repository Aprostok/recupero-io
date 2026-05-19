"""Indirect exposure scoring (v0.10.0).

The risk-scoring in v0.9.1 is direct-counterparty only: address
X gets flagged for SANCTIONED exposure if it had a transaction
DIRECTLY with a Lazarus / Tornado Cash / etc. address.

v0.10.0 extends to **N-hop indirect exposure**: if X received
funds from Y, and Y received funds from a sanctioned source S,
then X has *indirect exposure* to S — weighted by:

  * Number of hops (each hop multiplies by a decay factor; 2 hops
    typically counts at 50%, 3 hops at 25%, ...)
  * Amount-share at each hop (if Y received $1M and only $1K of
    it came from S, X's $500 inflow from Y carries only the
    $0.50 attributable share, not the full $500)
  * Severity of the original source

This is what Chainalysis Reactor + TRM call "indirect exposure
attribution" — the dollar-weighted, hop-decayed share of an
address's history that traces back to a sanctioned origin.

Why this matters for the government workflow
---------------------------------------------

OFAC's enforcement model (and Treasury's 50% Rule view) covers
both direct AND indirect exposure. A compliance team at an
exchange that processed funds 3 hops removed from a Lazarus
address may still have SAR / freeze obligations depending on
the size of the indirect exposure.

For our investigator brief: surfacing indirect exposure
upgrades cases that look "clean" on direct-only scoring but
have meaningful upstream sanctions footprint — exactly the
sub-$500K Zigha-shape cases that today look like an FBI-
field-office story but are actually a Treasury / OFAC
enforcement story.

Algorithm
---------

For each high-risk address H in the case (loaded via
load_high_risk_db), compute the **dollar-weighted flow** from H
to every other address in the case, up to max_hops (default 3).
Flow propagation:

  * H has gross outflow of $V_H to the case-graph addresses.
  * For each direct receiver R₁, exposure[R₁] += V(H→R₁) * w(1)
    where w(n) = decay_factor ** n.
  * For each R₁'s direct receivers R₂ within the trace,
    exposure[R₂] += V(H→R₁) * (V(R₁→R₂) / V_R1_total) * w(2)
  * Same recursion to max_hops.

The "amount-share" factor (V(R₁→R₂) / V_R1_total) is the
mixing penalty: if R₁ pools funds from many sources, the
share of S's funds in any single R₁→R₂ outflow is small.

Decay default: 0.5 per hop. So 1-hop is full weight, 2-hop is
50%, 3-hop is 25%. Tunable via env var
``RECUPERO_INDIRECT_DECAY``.

Output (per address in the case)
--------------------------------

  IndirectExposureResult:
    address: str
    total_indirect_usd: Decimal
    paths: list[IndirectPath]      # ranked by exposure amount

Where IndirectPath represents one upstream sanctioned source:
    source_address
    source_name (Lazarus / Tornado Cash / etc.)
    risk_category
    severity
    weighted_amount_usd
    hop_count                       # 1=direct, 2+=indirect
    path_addresses                  # intermediate addresses

The brief's RISK_ASSESSMENT section now surfaces both:
  * direct_score (v0.9.1)
  * indirect_score (v0.10.0)
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from recupero.models import Case
    from recupero.trace.risk_scoring import HighRiskEntry

log = logging.getLogger(__name__)


# Default decay per hop. Indirect exposure at hop N is multiplied
# by decay_factor**N. Setting too high (0.8+) inflates exposure;
# setting too low (0.2-) makes anything past 1 hop irrelevant.
# 0.5 matches Chainalysis's documented public guidance for
# "moderate-decay" exposure attribution.
_DEFAULT_DECAY_FACTOR = 0.5

#: Default max hops. 3 covers most operationally-relevant cases
#: (perpetrator → laundering wallet → off-ramp → final). Going
#: deeper explodes graph compute time + introduces noise.
_DEFAULT_MAX_HOPS = 3

#: Minimum USD floor for a weighted exposure to count. Anything
#: below $1 weighted is noise and gets dropped to keep the brief
#: focused. Independent of trace dust_threshold_usd.
_MIN_EXPOSURE_USD = Decimal("1.00")


@dataclass(frozen=True)
class IndirectPath:
    """One source-to-target indirect exposure path."""
    source_address: str
    source_name: str
    risk_category: str
    severity: int
    weighted_amount_usd: Decimal
    hop_count: int
    path_addresses: tuple[str, ...]   # source → ... → target (intermediates only)


@dataclass
class IndirectExposureResult:
    """Aggregate indirect exposure for one address in the case."""
    address: str
    total_indirect_usd: Decimal = Decimal("0")
    paths: list[IndirectPath] = field(default_factory=list)


def compute_indirect_exposure(
    case: Case,
    high_risk_db: dict[str, HighRiskEntry],
    *,
    max_hops: int | None = None,
    decay_factor: float | None = None,
) -> dict[str, IndirectExposureResult]:
    """Compute N-hop indirect exposure for every case address.

    Returns ``{address: IndirectExposureResult}`` for addresses
    with non-zero indirect exposure. Direct exposures (1-hop) are
    INCLUDED in this output — the result is the complete
    exposure picture, with hop_count distinguishing direct vs
    indirect for downstream consumers.

    Defensive: returns ``{}`` on empty inputs / errors.
    """
    if not case.transfers or not high_risk_db:
        return {}

    decay = decay_factor if decay_factor is not None else _resolve_decay()
    max_h = max_hops if max_hops is not None else _resolve_max_hops()

    # Build the directed flow graph.
    # forward_flows[from][to] = total USD that flowed from→to (sum
    # across all transfers in the case).
    forward_flows: dict[str, dict[str, Decimal]] = defaultdict(
        lambda: defaultdict(Decimal),
    )
    # outflow_totals[from] = total USD leaving from across the trace.
    # Used for amount-share normalization (mixing penalty).
    outflow_totals: dict[str, Decimal] = defaultdict(Decimal)

    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # base58 chains (Solana / Tron / Bitcoin) match the high_risk_db's
    # case-preserved entries. Pre-v0.17.9 the .lower() here defeated
    # the v0.17.5 risk-DB fix — a sanctioned Solana wallet stored
    # case-preserved in high_risk_db couldn't find ITS OWN transfers
    # in the case graph because we keyed them lowercased.
    from recupero._common import canonical_address_key as _ck
    for t in case.transfers:
        if t.usd_value_at_tx is None or t.usd_value_at_tx <= 0:
            continue
        src = _ck(t.from_address)
        dst = _ck(t.to_address)
        if src == dst:
            continue
        forward_flows[src][dst] += t.usd_value_at_tx
        outflow_totals[src] += t.usd_value_at_tx

    # BFS from each high-risk address that's IN the case graph,
    # propagating exposure with hop decay + amount-share scaling.
    results: dict[str, IndirectExposureResult] = {}

    case_addresses = set(forward_flows.keys()) | {
        a for receivers in forward_flows.values() for a in receivers.keys()
    }
    sources_in_case = case_addresses & set(high_risk_db.keys())

    for source in sources_in_case:
        source_entry = high_risk_db[source]
        # Propagate from this source.
        # frontier[addr] = (weighted_amount, hop_count, path_tuple)
        # We accumulate the BEST (highest-weighted) path to each
        # destination — alternative is to track all paths, but
        # that explodes combinatorially.
        best_paths: dict[str, tuple[Decimal, int, tuple[str, ...]]] = {}

        # Initialize with the source's direct outflows (hop 1).
        for dst, amount in forward_flows.get(source, {}).items():
            weighted = amount * Decimal(str(decay ** 1))
            if weighted < _MIN_EXPOSURE_USD:
                continue
            existing = best_paths.get(dst)
            if existing is None or weighted > existing[0]:
                best_paths[dst] = (weighted, 1, ())

        # Hop 2..max_h: for each address we've reached, propagate
        # to its outflow destinations using the amount-share
        # factor.
        for hop in range(2, max_h + 1):
            additions: list[tuple[str, Decimal, int, tuple[str, ...]]] = []
            for addr, (weighted_in, h, path) in list(best_paths.items()):
                if h + 1 > hop:
                    continue
                total_out = outflow_totals.get(addr, Decimal("0"))
                if total_out <= 0:
                    continue
                for next_dst, next_amount in forward_flows.get(addr, {}).items():
                    if next_dst == source:
                        continue  # cycle back to source
                    if next_dst in path:
                        continue  # cycle through path
                    # Amount-share: the fraction of addr's outflow
                    # going to next_dst.
                    share = next_amount / total_out
                    # Weighted contribution: this hop's incoming
                    # exposure × amount share × decay.
                    next_weighted = (
                        weighted_in * share
                        * Decimal(str(decay))
                    )
                    if next_weighted < _MIN_EXPOSURE_USD:
                        continue
                    next_path = path + (addr,)
                    additions.append((next_dst, next_weighted, hop, next_path))

            # Merge additions, keeping highest weight per dst.
            for dst, w, h, p in additions:
                existing = best_paths.get(dst)
                if existing is None or w > existing[0]:
                    best_paths[dst] = (w, h, p)

        # Record paths into IndirectExposureResult per destination.
        for dst, (weighted, h, path) in best_paths.items():
            if dst == source:
                continue
            result = results.setdefault(dst, IndirectExposureResult(address=dst))
            result.total_indirect_usd += weighted
            result.paths.append(IndirectPath(
                source_address=source,
                source_name=source_entry.name,
                risk_category=source_entry.risk_category,
                severity=source_entry.severity,
                weighted_amount_usd=weighted,
                hop_count=h,
                path_addresses=path,
            ))

    # Sort each address's paths by weighted_amount desc.
    for result in results.values():
        result.paths.sort(
            key=lambda p: p.weighted_amount_usd, reverse=True,
        )

    return results


def indirect_exposure_to_brief_section(
    results: dict[str, IndirectExposureResult],
) -> dict[str, any]:
    """Serialize to the brief JSON shape.

    Returns a dict with per-address indirect_exposures + a
    summary block. The brief's RISK_ASSESSMENT section embeds
    this alongside the v0.9.1 direct exposures.
    """
    addresses_payload: dict[str, dict] = {}
    total_addresses_with_indirect = 0
    indirect_ofac_count = 0
    highest_indirect = Decimal("0")
    highest_indirect_address: str | None = None

    for addr, result in results.items():
        if result.total_indirect_usd < _MIN_EXPOSURE_USD:
            continue
        total_addresses_with_indirect += 1
        cats = {p.risk_category for p in result.paths}
        if any(c.startswith("ofac") for c in cats):
            indirect_ofac_count += 1
        if result.total_indirect_usd > highest_indirect:
            highest_indirect = result.total_indirect_usd
            highest_indirect_address = addr
        addresses_payload[addr] = {
            "total_indirect_usd": f"${result.total_indirect_usd:,.2f}",
            "paths": [
                {
                    "source_address": p.source_address,
                    "source_name": p.source_name,
                    "risk_category": p.risk_category,
                    "severity": p.severity,
                    "weighted_amount_usd": f"${p.weighted_amount_usd:,.2f}",
                    "hop_count": p.hop_count,
                    "path_addresses": list(p.path_addresses),
                }
                for p in result.paths[:10]  # top 10 paths per address
            ],
        }

    return {
        "addresses": addresses_payload,
        "summary": {
            "addresses_with_indirect_exposure": total_addresses_with_indirect,
            "indirect_ofac_exposed_count": indirect_ofac_count,
            "highest_indirect_usd": (
                f"${highest_indirect:,.2f}" if highest_indirect > 0 else "$0.00"
            ),
            "highest_indirect_address": highest_indirect_address,
        },
    }


# ----- helpers ----- #


def _resolve_decay() -> float:
    try:
        return float(os.environ.get(
            "RECUPERO_INDIRECT_DECAY", str(_DEFAULT_DECAY_FACTOR),
        ))
    except ValueError:
        return _DEFAULT_DECAY_FACTOR


def _resolve_max_hops() -> int:
    try:
        return int(os.environ.get(
            "RECUPERO_INDIRECT_MAX_HOPS", str(_DEFAULT_MAX_HOPS),
        ))
    except ValueError:
        return _DEFAULT_MAX_HOPS


__all__ = (
    "IndirectExposureResult",
    "IndirectPath",
    "compute_indirect_exposure",
    "indirect_exposure_to_brief_section",
)
