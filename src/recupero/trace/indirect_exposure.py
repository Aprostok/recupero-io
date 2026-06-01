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
        a for receivers in forward_flows.values() for a in receivers
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
        # to its outflow destinations using the amount-share factor.
        #
        # v0.18.3 (round-11 forensic-CRIT-001/002 + trace-CRIT-002):
        # pre-v0.18.3 the gate `if h + 1 > hop: continue` allowed ANY
        # address at h < hop to re-extend, recording the new entry
        # with the OUTER loop's `hop` value rather than `h + 1`. At
        # outer-iter hop=3, an h=1 entry extending one step had its
        # destination stamped hop=3 — but it's truly only 2 hops from
        # source. Combined with single-decay-only weighting, this
        # inflated OFAC indirect-exposure numbers by ~1/decay (2× at
        # default 0.5) and double-counted across sources. The
        # `combined_indirect_usd` headline on the brief was off by
        # 2-4× whenever max_h >= 3.
        #
        # New: strict level-by-level BFS — only extend from entries
        # exactly one hop shallower than the current outer hop.
        for hop in range(2, max_h + 1):
            additions: list[tuple[str, Decimal, int, tuple[str, ...]]] = []
            for addr, (weighted_in, h, path) in list(best_paths.items()):
                if h + 1 != hop:
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


# ============================================================ #
# v0.31.0 MVP indirect-exposure scorer                          #
# ============================================================ #
#
# The v0.10.0 algorithm above is the rich, dollar-weighted, multi-
# source attribution engine. It's accurate but heavyweight: every
# scored address carries a list of `IndirectPath` records with
# severity / source / path-addresses metadata.
#
# v0.31.0 adds a complementary FLAT scorer that returns
# ``{address: float_score}`` keyed by per-address exposure on the
# 0..1 scale and weighted by the fraction-of-total-drained that
# flowed through each hop. Closes gap #3 from the trace-completeness
# assessment (TRM / Chainalysis 4-hop weight-decayed exposure
# scoring) at MVP fidelity:
#
#   hop 1 (direct counterparty of a victim/perp wallet)  → 1.000
#   hop 2 (one degree removed)                           → 0.500
#   hop 3                                                → 0.250
#   hop 4                                                → 0.125
#   each weighted by usd_value_at_tx / total_drained.
#
# High-risk categories that contribute: 'mixer', 'sanctioned' (OFAC),
# 'ransomware', 'darknet_market', 'scam'. Anything below the floor
# 0.01 is dropped.
#
# Designed to be plugged into the editorial JSON's new
# "INDIRECT_EXPOSURE_V031" section. The v0.10.0 INDIRECT_EXPOSURE
# section above stays intact — both surface complementary views.
#
# TODO (post-v0.31 hardening): cycle detection across very long
# chains, multi-source attribution (currently aggregates all paths
# to one score), per-category severity multipliers (mixer vs scam),
# inflow- vs outflow-aware traversal (today we BFS along outflows
# only, which matches the TRM "downstream exposure" framing but
# misses upstream-sanctioned-funder cases). For the operational
# brief the MVP is sufficient to surface the previously-invisible
# 2-hop-removed mixer / OFAC address.

#: Per-hop weight schedule (index 0 unused; index i = weight at hop i).
_V031_HOP_WEIGHTS: tuple[float, ...] = (0.0, 1.0, 0.5, 0.25, 0.125)

#: High-risk category set for MVP exposure attribution. Matched against
#: both LabelStore .category (raw enum value) and HighRiskEntry-style
#: risk_category strings emitted by load_high_risk_db (e.g.
#: 'ofac_sanctioned', 'mixer_sanctioned', 'mixer_high_risk',
#: 'scam_drainer', 'darknet_market', 'ransomware'). A label hits the
#: high-risk set if its category contains any of the substrings below.
_V031_HIGH_RISK_SUBSTRINGS: tuple[str, ...] = (
    "mixer",
    "sanction",   # matches 'sanctioned', 'ofac_sanctioned', 'mixer_sanctioned'
    "ransomware",
    "darknet",    # matches 'darknet_market'
    "scam",       # matches 'scam_drainer'
    "ofac",       # belt-and-braces for OFAC-prefixed categories
)

#: Drop scores below this floor. The task spec sets 0.01 explicitly.
_V031_SCORE_FLOOR: float = 0.01

#: Default decay factor (per-hop). Decay × hop-weight composes for
#: the v0.31 weight schedule (1.0, 0.5, 0.25, 0.125 = 1 × 0.5**0,
#: 1 × 0.5**1, 1 × 0.5**2, 1 × 0.5**3). Decay=0.5 reproduces the
#: spec exactly; callers can supply a different decay to soften /
#: harshen the falloff.
_V031_DEFAULT_DECAY: float = 0.5


def _v031_category_for(label_store: object, address: str) -> str | None:
    """Resolve an address to its label category, defensively.

    Accepts any of:
      * an object with ``.lookup(address) -> Label-like-or-None`` where
        the returned object has either ``.category`` or
        ``.risk_category`` (str / enum)
      * a plain ``dict[str, str]`` mapping address → category-string
      * a plain ``dict[str, object]`` where the value has the above
        attrs

    Returns the category as a string, or ``None`` if no label is
    resolvable. Never raises on a bad / partial label_store.
    """
    if label_store is None or not address:
        return None

    raw: object | None = None
    try:
        if hasattr(label_store, "lookup"):
            # LabelStore-style; the canonical signature is .lookup(addr,
            # chain) but we don't have chain context per-hop, so call
            # the single-arg form and fall back to the two-arg form
            # only on TypeError.
            try:
                raw = label_store.lookup(address)
            except TypeError:
                try:
                    from recupero.models import Chain
                    raw = label_store.lookup(address, Chain.ethereum)
                except Exception:  # noqa: BLE001 — defensive
                    raw = None
        elif isinstance(label_store, dict):
            raw = label_store.get(address)
            if raw is None:
                # Try canonical key
                try:
                    from recupero._common import canonical_address_key
                    raw = label_store.get(canonical_address_key(address))
                except Exception:  # noqa: BLE001
                    raw = None
    except Exception as exc:  # noqa: BLE001 — defensive
        log.debug("v031 label lookup failed for %s: %s", address, exc)
        return None

    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    # Pull a category attribute. Prefer risk_category (HighRiskEntry)
    # then category (Label).
    for attr in ("risk_category", "category"):
        val = getattr(raw, attr, None)
        if val is None:
            continue
        # str(LabelCategory.mixer) == 'LabelCategory.mixer'; we want the
        # value 'mixer'. Enum instances carry .value.
        value = getattr(val, "value", val)
        if isinstance(value, str) and value:
            return value
    return None


def _v031_is_high_risk(category: str | None) -> bool:
    """True iff the category falls in the v0.31 high-risk set."""
    if not category:
        return False
    cat_lower = category.lower()
    return any(needle in cat_lower for needle in _V031_HIGH_RISK_SUBSTRINGS)


def _v031_finite_usd(value: object) -> Decimal | None:
    """Return ``value`` as a finite positive Decimal, or None.

    Mirrors the V030_2_CORRECTNESS_AUDIT T1-B pattern: NaN / Inf
    transfers must never poison scoring. Negative / zero / None →
    treated as missing.
    """
    if value is None:
        return None
    try:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
    except (ValueError, ArithmeticError, TypeError):
        return None
    if not d.is_finite():
        return None
    if d <= 0:
        return None
    return d


def compute_label_exposure_scores(
    case: Case,
    *,
    label_store: object,
    max_hops: int = 4,
    decay: float = _V031_DEFAULT_DECAY,
) -> dict[str, float]:
    """v0.31.0 MVP: flat per-address indirect-exposure scoring.

    Walks ``case.transfers`` outward from victim + perpetrator wallets,
    accumulating per-address exposure each time a hop lands on (or
    passes through) an address whose label_store category is in the
    high-risk set. Score is weighted by USD flow / total drained and
    decayed per hop.

    Args:
      case: the trace case. Only ``case.transfers`` + ``case.seed_address``
        are read.
      label_store: any object with ``.lookup(address)`` returning a
        Label-like object with ``.category`` or ``.risk_category``,
        OR a plain ``dict[address, category_str_or_label]``.
      max_hops: maximum BFS depth. Default 4 per spec; clamped to the
        length of the hop-weight table (4) to avoid index-out-of-range.
      decay: per-hop decay factor. Default 0.5 reproduces the spec's
        (1.0, 0.5, 0.25, 0.125) schedule when ``max_hops=4``.

    Returns:
      ``{address: exposure_score}`` for every address whose computed
      score is >= the floor 0.01. Scores are unitless on the 0..1
      conceptual scale (a direct 100%-of-flow counterparty of a
      mixer scores 1.0); aggregated scores may exceed 1.0 when
      multiple high-risk paths converge.

    Pure function. No DB / network access. Defensive: empty case,
    missing labels, NaN-poisoned USD values, and unsupported
    label_store shapes all return ``{}`` or skip the offending row
    without crashing.
    """
    if case is None or not getattr(case, "transfers", None):
        return {}

    # Clamp max_hops to the supported table. The spec calls for 4 hops;
    # if a caller asks for more we silently truncate (with a debug
    # log) rather than blow up.
    effective_max = min(int(max_hops or 0), len(_V031_HOP_WEIGHTS) - 1)
    if effective_max < 1:
        return {}

    from recupero._common import canonical_address_key as _ck

    # --- Build the per-address outflow graph + total drained ---
    # outflows[src] = list of (dst, usd_decimal) for each finite-USD transfer.
    outflows: dict[str, list[tuple[str, Decimal]]] = defaultdict(list)
    total_drained = Decimal("0")
    seed = _ck(case.seed_address) if getattr(case, "seed_address", None) else None

    for t in case.transfers:
        usd = _v031_finite_usd(getattr(t, "usd_value_at_tx", None))
        if usd is None:
            continue
        src = _ck(getattr(t, "from_address", "") or "")
        dst = _ck(getattr(t, "to_address", "") or "")
        if not src or not dst or src == dst:
            continue
        outflows[src].append((dst, usd))
        # Total drained = sum of USD leaving the seed wallet (matches
        # _compute_total_drained in emit_brief.py, but recomputed here
        # so we stay a pure function with no cross-module dependency).
        if seed and src == seed:
            total_drained += usd

    if total_drained <= 0:
        # Fall back to total finite USD flow if the seed didn't have
        # any direct outflows captured in the trace (defensive: keeps
        # the scorer useful for cases where the seed is the perpetrator
        # hub rather than the victim).
        for transfers in outflows.values():
            for _, usd in transfers:
                total_drained += usd
    if total_drained <= 0:
        return {}

    # --- BFS roots: victim + any explicitly-perpetrator-labeled wallet ---
    # We BFS from the seed (the canonical victim/perp wallet) by default.
    # If the label_store can identify perpetrator wallets we use those
    # too, but for the MVP the seed alone is sufficient.
    roots: set[str] = set()
    if seed:
        roots.add(seed)

    # --- BFS with per-hop USD weighting ---
    # scores[address] = accumulated exposure_score.
    scores: dict[str, float] = defaultdict(float)
    # visited holds (address, hop) so we don't re-visit at a SHALLOWER
    # hop. Each address may legitimately appear via multiple paths;
    # we accumulate scores.
    # Frontier entries: (address, hop_depth, usd_fraction_through_path)
    # where usd_fraction_through_path is the fraction of total_drained
    # that has flowed through THIS path so far.
    visited: set[tuple[str, int]] = set()
    # Seed the frontier with each root at hop 0 (no exposure attributed
    # at the root itself; the first counterparty is hop 1).
    frontier: list[tuple[str, int, float]] = [
        (root, 0, 1.0) for root in roots if root
    ]

    while frontier:
        next_frontier: list[tuple[str, int, float]] = []
        for addr, hop, _frac_in in frontier:
            if hop >= effective_max:
                continue
            next_hop = hop + 1
            weight = _V031_HOP_WEIGHTS[next_hop]
            # Apply caller's decay override on top of the table when
            # decay != _V031_DEFAULT_DECAY. We do this by recomputing:
            # weight_for_hop = decay ** (next_hop - 1). At default
            # decay=0.5 this exactly reproduces the table.
            if decay != _V031_DEFAULT_DECAY:
                try:
                    weight = float(decay) ** (next_hop - 1)
                except (ValueError, ArithmeticError, OverflowError):
                    weight = _V031_HOP_WEIGHTS[next_hop]

            out_list = outflows.get(addr, [])
            # Compute per-edge USD fractions of total_drained.
            for dst, usd in out_list:
                try:
                    edge_frac = float(usd) / float(total_drained)
                except (ValueError, ArithmeticError, ZeroDivisionError):
                    continue
                if not (edge_frac > 0 and edge_frac < float("inf")):
                    continue
                # The "fraction of total_drained flowing through this
                # path" is the MIN of (path-so-far, this-edge). MVP:
                # use this edge's fraction since the spec phrases
                # weighting as "USD flow / total" per hop.
                path_frac = edge_frac

                # Score the dst if its category is high-risk.
                category = _v031_category_for(label_store, dst)
                if _v031_is_high_risk(category):
                    scores[dst] += weight * path_frac

                # Continue BFS if we have hops left.
                key = (dst, next_hop)
                if key not in visited:
                    visited.add(key)
                    next_frontier.append((dst, next_hop, path_frac))
        frontier = next_frontier

    # Apply the score floor.
    return {a: s for a, s in scores.items() if s >= _V031_SCORE_FLOOR}


# Alias matching the task-spec signature. Kept as a parallel name so
# the existing v0.10.0 `compute_indirect_exposure(case, high_risk_db)`
# callers (emit_brief.py, the v0.10.0 test suite) continue to work
# unchanged. Task spec wires consumers against this MVP function.
def compute_indirect_exposure_mvp(
    case: Case,
    *,
    label_store: object,
    max_hops: int = 4,
    decay: float = _V031_DEFAULT_DECAY,
) -> dict[str, float]:
    """v0.31.0 MVP indirect-exposure scorer (task-spec name).

    Thin alias for :func:`compute_label_exposure_scores`. See that
    function's docstring for full behavior.
    """
    return compute_label_exposure_scores(
        case, label_store=label_store, max_hops=max_hops, decay=decay,
    )


def label_exposure_scores_to_brief_section(
    case: Case,
    scores: dict[str, float],
    *,
    label_store: object,
    top_n: int = 10,
    surface_threshold: float = 0.1,
) -> dict[str, object] | None:
    """v0.31.0: serialize scores into the editorial JSON section.

    Returns ``None`` if no scored address has exposure >= surface_threshold
    (the brief should omit the section entirely in that case rather than
    publish an empty block). Returns a dict with a ranked top-N list
    otherwise.

    Each entry carries: address, primary label category, hops from
    victim (best-effort: 1 if a direct counterparty of the seed,
    otherwise the shallowest BFS hop at which it was reached), exposure
    score, total USD flow (sum of finite usd_value_at_tx into the address).
    """
    if not scores:
        return None

    # Are any scores >= the surface threshold? If not, drop the section.
    if not any(s >= surface_threshold for s in scores.values()):
        return None

    from recupero._common import canonical_address_key as _ck

    # Pre-compute (a) hops-from-victim by BFS over outflows, (b) total
    # USD flow received by each address. Both are pure post-process
    # passes over case.transfers — no chain refetch.
    seed = _ck(case.seed_address) if getattr(case, "seed_address", None) else None
    outflows_for_hops: dict[str, set[str]] = defaultdict(set)
    inflow_usd: dict[str, Decimal] = defaultdict(Decimal)
    for t in case.transfers:
        usd = _v031_finite_usd(getattr(t, "usd_value_at_tx", None))
        src = _ck(getattr(t, "from_address", "") or "")
        dst = _ck(getattr(t, "to_address", "") or "")
        if src and dst and src != dst:
            outflows_for_hops[src].add(dst)
            if usd is not None:
                inflow_usd[dst] += usd

    hops_from_victim: dict[str, int] = {}
    if seed:
        queue: list[tuple[str, int]] = [(seed, 0)]
        seen: set[str] = {seed}
        while queue:
            addr, depth = queue.pop(0)
            if depth > 0:
                hops_from_victim.setdefault(addr, depth)
            if depth >= 8:  # safety cap; way past max_hops=4
                continue
            for nxt in outflows_for_hops.get(addr, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                queue.append((nxt, depth + 1))

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    entries: list[dict[str, object]] = []
    for addr, score in ranked[:top_n]:
        category = _v031_category_for(label_store, addr) or "unknown"
        usd_flow = inflow_usd.get(addr, Decimal("0"))
        usd_flow_str = (
            f"${usd_flow:,.2f}"
            if usd_flow.is_finite()
            else "$0.00"
        )
        entries.append({
            "address": addr,
            "primary_label_category": category,
            "hops_from_victim": hops_from_victim.get(addr),
            "exposure_score": round(float(score), 4),
            "total_usd_flow": usd_flow_str,
        })

    return {
        "top_addresses": entries,
        "summary": {
            "scored_addresses": len(scores),
            "addresses_above_surface_threshold": sum(
                1 for s in scores.values() if s >= surface_threshold
            ),
            "surface_threshold": surface_threshold,
            "max_hops": 4,  # MVP fixed schedule
        },
    }


__all__ = (
    "IndirectExposureResult",
    "IndirectPath",
    "compute_indirect_exposure",
    "compute_indirect_exposure_mvp",
    "compute_label_exposure_scores",
    "indirect_exposure_to_brief_section",
    "label_exposure_scores_to_brief_section",
)
