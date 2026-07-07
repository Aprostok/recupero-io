"""Entity clustering (v0.9.0).

Groups addresses that appear to belong to the same actor based
on on-chain behavioral signals. This is what TRM / Chainalysis
charge tens of thousands of dollars per year for, scoped down
to MVP heuristics suitable for a $499 diagnostic.

Why entity clustering matters for crypto recovery
--------------------------------------------------

A perpetrator typically uses MANY addresses — a primary
consolidation hub, multiple smaller staging wallets, redistribution
endpoints. Treating each as an independent counterparty
understates the perpetrator's operational footprint. Government
analysts subpoenaing exchange records ("did this user deposit
from any of these addresses?") need the full set, not just the
one address the victim's funds happened to touch.

What's an "entity" in this MVP?
-------------------------------

A cluster of addresses connected by at least one of the
following heuristics. Each heuristic adds an edge in an
undirected graph; the resulting connected components are the
clusters.

  H1 — Common funding source
      Two addresses that BOTH received their first material
      inflow from the same source EOA within a 24-hour window.
      Strong signal: the source EOA is funding multiple
      operational wallets simultaneously.

  H2 — Common withdrawal target
      Two addresses that BOTH sent material outflows to the
      same destination within a 24-hour window. Common in
      consolidation patterns where the perpetrator drains
      multiple staging wallets into one hub.

  H3 — Direct transfer (self-funding)
      Address A sent funds directly to address B with a
      pattern suggesting same-owner movement (round-number
      amounts, gas-priced from the sender's own balance, no
      intermediary contract). Less reliable than H1/H2;
      flagged as "weak" confidence.

What's out of scope for v0.9.0
-------------------------------

  * ML-based behavioral fingerprinting (gas price patterns,
    timing distributions). Requires training data + a model;
    real work. Deferred to a later release.
  * Cross-chain clustering. Pass-2 perpetrator traces already
    surface cross-chain destinations; full cluster-across-
    chains analysis is a v0.10+ scope.
  * UTXO-style common-input-ownership heuristic. Only applies
    to Bitcoin/Litecoin/etc; our v0.9.0 chains are all account-
    model (Ethereum + L2s + Solana).

Output shape (consumed by emit_brief + AI editorial)
----------------------------------------------------

  {
    "clusters": [
      {
        "cluster_id": "C-1",
        "addresses": ["0xabc...", "0xdef..."],
        "size": 2,
        "total_balance_usd": "$1,234,567.89",
        "evidence": [
          {"heuristic": "common_funding",
           "details": "Both addresses funded by 0x123... within 4h",
           "confidence": "high"},
          {"heuristic": "common_withdrawal",
           "details": "Both sent to 0x789... within 1h",
           "confidence": "high"}
        ]
      }
    ],
    "unclustered_addresses": ["0x111...", ...]
  }
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from recupero.models import Case, Chain, LabelCategory

if TYPE_CHECKING:
    from recupero.labels.store import LabelStore
from recupero.labels.store import lookup_pit_safe  # v0.31.4

log = logging.getLogger(__name__)


# Heuristic tuning. Tightened a bit from naive defaults — clustering
# too aggressively produces false-positive merges (two unrelated
# addresses that happen to share a popular funding source like a
# CEX hot wallet). Operators can override per-investigation via env vars.

#: Time window for "two addresses funded by same source" to count
#: as a clustering signal. 24h matches the operational pattern of
#: a perpetrator funding their wallets in a single session.
_COMMON_FUNDING_WINDOW = timedelta(hours=24)

#: Time window for "two addresses sent to same destination" to
#: count as a clustering signal. Tighter than funding because
#: drain-to-hub patterns happen in minutes-to-hours, not days.
_COMMON_WITHDRAWAL_WINDOW = timedelta(hours=12)

#: Minimum USD value for a transfer to contribute to clustering.
#: Tighter than the trace's dust threshold ($10) because clustering
#: needs higher signal — a $1 transfer from CEX_HOT_WALLET to
#: 100 random users is not a clustering signal.
_MIN_CLUSTERING_USD = Decimal("100")

#: Addresses that are known to be SHARED INFRASTRUCTURE — CEX hot
#: wallets, popular mixers, big DEX routers — should NEVER be
#: used as a clustering signal. Funding 1000 addresses from
#: Binance hot wallet doesn't make them all the same entity.
#: We skip any heuristic involving an address that has > N
#: distinct interaction-partners in the trace; that's a strong
#: signal of shared infrastructure.
_SHARED_INFRA_PARTNER_THRESHOLD = 5


@dataclass(frozen=True)
class ClusterEvidence:
    """One piece of evidence supporting a cluster membership.

    The brief surfaces this as the "why are these addresses
    clustered?" explanation, which is critical for an investigator
    deciding whether to trust the clustering. Without evidence,
    clustering is a black box; with it, the analyst can verify
    the heuristic fired correctly.
    """
    heuristic: str         # "common_funding" | "common_withdrawal" | "direct_transfer"
    details: str           # human-readable explanation
    confidence: str        # "high" | "medium" | "low"
    related_address: str | None = None  # the shared funding source or withdrawal target


@dataclass
class Cluster:
    """One group of addresses inferred to belong to the same entity."""
    cluster_id: str
    addresses: set[str] = field(default_factory=set)
    evidence: list[ClusterEvidence] = field(default_factory=list)
    total_balance_usd: Decimal = Decimal("0")


def cluster_addresses(
    case: Case,
    address_balances: dict[str, Decimal] | None = None,
) -> tuple[list[Cluster], list[str]]:
    """Compute entity clusters from a completed case.

    Parameters
    ----------
    case
        The pass-1 (or merged pass-1+pass-2) case from the trace.
    address_balances
        Optional mapping of lowercased address → current USD
        balance. Used to compute each cluster's
        ``total_balance_usd``. When None, clusters report
        ``Decimal("0")`` for total balance; the cluster
        membership itself is still computed.

    Returns
    -------
    (clusters, unclustered_addresses)
        clusters: list of Cluster objects sorted by total
                  balance desc.
        unclustered: list of addresses that appeared in the
                  case but didn't get grouped with anyone
                  else (singletons).

    Best-effort: failures during heuristic evaluation log a
    warning + degrade gracefully (cluster less, or report no
    clusters).
    """
    if not case.transfers:
        return [], []

    # v0.32.1 W1 (round-2 adversary M-5 wire-up): per-case randomized
    # thresholds for the two clustering knobs an adversary reads from
    # source and games (``_SHARED_INFRA_PARTNER_THRESHOLD`` = 5 and
    # ``_MIN_CLUSTERING_USD`` = $100). Both fall back to the module
    # defaults if randomization fails (missing secret, etc.) — never
    # break clustering over a security wire-up.
    shared_infra_threshold: int = _SHARED_INFRA_PARTNER_THRESHOLD
    min_clustering_usd: Decimal = _MIN_CLUSTERING_USD
    if getattr(case, "case_id", None):
        try:
            from recupero.security.per_case_randomization import case_threshold
            shared_infra_threshold = case_threshold(
                case.case_id, "shared_infra_partner",
                base_value=_SHARED_INFRA_PARTNER_THRESHOLD,
            )
            min_clustering_usd = Decimal(str(case_threshold(
                case.case_id, "min_clustering_usd",
                base_value=int(_MIN_CLUSTERING_USD),
            )))
        except Exception as exc:  # noqa: BLE001 — never break clustering
            log.debug(
                "clustering per-case threshold randomization failed "
                "(case=%r): %s; falling back to fixed defaults",
                getattr(case, "case_id", None), exc,
            )

    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # base58 chains (Solana/Tron/Bitcoin) cluster against case-preserved
    # forms. Pre-v0.17.9 the seed_lower / src.lower() / dst.lower()
    # mangled base58 addresses and split them into two pseudo-addresses
    # (the lowercased form and the canonical-cased form when matched
    # elsewhere), producing false "co-spending pattern" clusters
    # between an address and its own lowercase.
    from recupero._common import canonical_address_key as _ck
    seed_lower = _ck(case.seed_address)
    excluded_addrs = {seed_lower}

    # Build address → first interaction timestamp lookups for
    # the windowing checks.
    first_inflow_at: dict[str, Any] = {}   # addr → (source_addr, datetime)
    first_outflow_at: dict[str, Any] = {}  # addr → (dest_addr, datetime)
    # Track which addresses each address sent to / received from
    # so we can identify shared-infrastructure addresses to skip.
    inflow_sources: dict[str, set[str]] = defaultdict(set)
    outflow_destinations: dict[str, set[str]] = defaultdict(set)
    all_addresses: set[str] = set()

    for t in case.transfers:
        if t.usd_value_at_tx is None or t.usd_value_at_tx < min_clustering_usd:
            continue
        src = _ck(t.from_address)
        dst = _ck(t.to_address)
        ts = t.block_time
        all_addresses.add(src)
        all_addresses.add(dst)

        # Track first material inflow per address.
        if dst not in first_inflow_at and dst not in excluded_addrs:
            first_inflow_at[dst] = (src, ts)
        # Track first material outflow per address.
        if src not in first_outflow_at and src not in excluded_addrs:
            first_outflow_at[src] = (dst, ts)
        inflow_sources[dst].add(src)
        outflow_destinations[src].add(dst)

    # Identify shared-infrastructure addresses (CEX, big DEX
    # routers): too many distinct partners → not a clustering
    # signal. We treat the address as "shared infrastructure"
    # and skip heuristics that involve it.
    shared_infra: set[str] = set()
    for addr in all_addresses:
        partners = inflow_sources[addr] | outflow_destinations[addr]
        if len(partners) >= shared_infra_threshold:
            shared_infra.add(addr)
    log.debug("clustering: %d shared-infrastructure addresses identified",
              len(shared_infra))

    # Build clustering edges via Union-Find.
    uf = _UnionFind()
    evidence_log: dict[tuple[str, str], list[ClusterEvidence]] = defaultdict(list)

    # H1 — Common funding source
    # Group addresses by funding source; within each group, addresses
    # funded within _COMMON_FUNDING_WINDOW are clustered together.
    funding_groups: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for addr, (source, ts) in first_inflow_at.items():
        if source in shared_infra or source in excluded_addrs:
            continue
        if addr in shared_infra or addr in excluded_addrs:
            continue
        funding_groups[source].append((addr, ts))

    for source, group in funding_groups.items():
        if len(group) < 2:
            continue
        # Compare each pair; cluster if within window.
        for i, (addr_a, ts_a) in enumerate(group):
            for addr_b, ts_b in group[i + 1:]:
                if abs((ts_a - ts_b).total_seconds()) > _COMMON_FUNDING_WINDOW.total_seconds():
                    continue
                uf.union(addr_a, addr_b)
                evidence_log[_edge_key(addr_a, addr_b)].append(ClusterEvidence(
                    heuristic="common_funding",
                    details=(
                        f"Both addresses received first material funding from "
                        f"{source} within {abs((ts_a - ts_b).total_seconds()) / 3600:.1f}h"
                    ),
                    # v0.39 forensic-posture fix (audit finding): common funding
                    # source is a behavioral CO-SPEND correlation, NOT proof of
                    # same ownership — the shared funder is frequently a CEX
                    # withdrawal hot wallet, a disperse.app / airdrop contract, an
                    # OTC desk, or a payment processor (the shared_infra filter is
                    # best-effort). "high" is reserved for cryptographic identity
                    # (e.g. same EVM address across chains in address_clustering).
                    confidence="medium",
                    related_address=source,
                ))

    # H2 — Common withdrawal target
    withdrawal_groups: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for addr, (dest, ts) in first_outflow_at.items():
        if dest in shared_infra or dest in excluded_addrs:
            continue
        if addr in shared_infra or addr in excluded_addrs:
            continue
        withdrawal_groups[dest].append((addr, ts))

    for dest, group in withdrawal_groups.items():
        if len(group) < 2:
            continue
        for i, (addr_a, ts_a) in enumerate(group):
            for addr_b, ts_b in group[i + 1:]:
                if abs((ts_a - ts_b).total_seconds()) > _COMMON_WITHDRAWAL_WINDOW.total_seconds():
                    continue
                uf.union(addr_a, addr_b)
                evidence_log[_edge_key(addr_a, addr_b)].append(ClusterEvidence(
                    heuristic="common_withdrawal",
                    details=(
                        f"Both addresses sent first material outflow to "
                        f"{dest} within {abs((ts_a - ts_b).total_seconds()) / 3600:.1f}h"
                    ),
                    # v0.39 forensic-posture fix (audit finding): common
                    # withdrawal target is a co-spend correlation, not ownership
                    # proof (the shared target is often a CEX deposit address or
                    # a common service). Demoted high → medium; see common_funding.
                    confidence="medium",
                    related_address=dest,
                ))

    # H3 — Direct transfer (weak signal). Address A → Address B
    # is treated as a clustering signal only when both addresses
    # appear elsewhere in the case AND the amounts are
    # "self-fund" looking (round numbers).
    for t in case.transfers:
        if t.usd_value_at_tx is None or t.usd_value_at_tx < min_clustering_usd:
            continue
        src = _ck(t.from_address)
        dst = _ck(t.to_address)
        if src in shared_infra or src in excluded_addrs:
            continue
        if dst in shared_infra or dst in excluded_addrs:
            continue
        # Only count if both endpoints have other activity in
        # the case (otherwise it's just a one-off transfer, not
        # a clustering signal).
        src_active = len(outflow_destinations[src]) > 0
        dst_active = len(outflow_destinations[dst]) > 0
        if not (src_active and dst_active):
            continue
        # Round-number heuristic: amount is a "self-fund" if
        # the amount looks like a deliberate human-chosen number.
        amount = t.amount_decimal
        if not _looks_round(amount):
            continue
        uf.union(src, dst)
        evidence_log[_edge_key(src, dst)].append(ClusterEvidence(
            heuristic="direct_transfer",
            details=(
                f"Round-number transfer of {amount} {t.token.symbol} "
                f"directly from one to the other"
            ),
            confidence="low",  # weak signal
            related_address=None,
        ))

    # Materialize clusters from the union-find structure.
    cluster_members: dict[str, set[str]] = defaultdict(set)
    for addr in all_addresses - excluded_addrs - shared_infra:
        root = uf.find(addr)
        cluster_members[root].add(addr)

    clusters: list[Cluster] = []
    unclustered: list[str] = []
    cluster_idx = 1
    for root, members in cluster_members.items():
        if len(members) < 2:
            unclustered.extend(members)
            continue
        # Gather evidence for all edges within this cluster.
        cluster_evidence: list[ClusterEvidence] = []
        seen_evidence_keys: set[tuple[str, str, str]] = set()
        for a in members:
            for b in members:
                if a >= b:
                    continue
                for ev in evidence_log.get(_edge_key(a, b), []):
                    key = (ev.heuristic, ev.related_address or "", ev.details)
                    if key in seen_evidence_keys:
                        continue
                    seen_evidence_keys.add(key)
                    cluster_evidence.append(ev)
        # Z6-2: address_balances can carry Decimal('NaN') / Decimal(
        # 'Infinity') after an upstream price-oracle glitch. ``sum(NaN)``
        # produces NaN which then crashes ``clusters.sort(...)`` mid-sort
        # with ``decimal.InvalidOperation``. Filter to finite, non-negative
        # values via is_finite() so the entire ENTITY_CLUSTERS section
        # doesn't silently disappear from the brief.
        _bals = address_balances or {}
        balance = Decimal("0")
        for a in members:
            v = _bals.get(a, Decimal("0"))
            if isinstance(v, Decimal):
                if v.is_finite():
                    balance += v
            else:
                try:
                    vd = Decimal(str(v))
                    if vd.is_finite():
                        balance += vd
                except Exception:  # noqa: BLE001
                    pass
        clusters.append(Cluster(
            cluster_id=f"C-{cluster_idx}",
            addresses=set(members),
            evidence=cluster_evidence,
            total_balance_usd=balance,
        ))
        cluster_idx += 1

    clusters.sort(key=lambda c: c.total_balance_usd, reverse=True)
    return clusters, sorted(unclustered)


def clusters_to_brief_section(
    clusters: list[Cluster],
    unclustered: list[str],
) -> dict[str, Any]:
    """Serialize the clustering output to the JSON shape the
    brief consumes."""
    return {
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "addresses": sorted(c.addresses),
                "size": len(c.addresses),
                "total_balance_usd": (
                    f"${c.total_balance_usd:,.2f}"
                    if c.total_balance_usd > 0 else None
                ),
                "evidence": [
                    {
                        "heuristic": e.heuristic,
                        "details": e.details,
                        "confidence": e.confidence,
                        "related_address": e.related_address,
                    }
                    for e in c.evidence
                ],
            }
            for c in clusters
        ],
        "unclustered_addresses": unclustered,
    }


# ----- helpers ----- #


class _UnionFind:
    """Standard union-find for cluster building."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            return x
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self._parent[rx] = ry


def _edge_key(a: str, b: str) -> tuple[str, str]:
    """Canonical (lexically ordered) edge key for evidence_log."""
    return (a, b) if a < b else (b, a)


def _looks_round(amount: Decimal) -> bool:
    """Heuristic: is this amount a 'self-fund' looking round
    number? Strict — only treats whole-token transfers of
    1, 5, 10, 25, 50, 100, 250, 500, 1000, etc. as round.
    Excludes the typical token-amount artifacts from contract
    interactions (e.g., 0.05 ETH for gas, $42.13 from a swap).
    """
    # First: is it an integer? Token transfers can be many
    # decimals but human-chosen amounts are usually whole units.
    if amount != amount.to_integral_value():
        return False
    int_amount = int(amount)
    # Common round numbers operators / scammers use.
    round_set = {1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500,
                 5000, 10_000, 25_000, 50_000, 100_000, 250_000,
                 500_000, 1_000_000}
    return int_amount in round_set


# ---------------------------------------------------------------- #
# v0.31.0 — minimum-viable wallet clustering (Gap #4 trace-completeness)
# ---------------------------------------------------------------- #
#
# `compute_address_clusters` is the MVP entry point described in
# docs/V031_CLUSTERING_DESIGN.md. Heuristics, in order of strength:
#
#   H1 — Co-spending (Bitcoin only): two addresses that appeared
#        together as inputs to the same Bitcoin tx. The textbook
#        common-input-ownership heuristic. confidence=high.
#
#   H2 — Common CEX withdrawal: two EVM addresses that both
#        withdrew from the same labeled exchange-deposit address
#        within `_CEX_WITHDRAWAL_WINDOW` (≤ 1h). Same beneficiary
#        likely owns both. confidence=high.
#
#   H3 — Common funding source: two addresses that both received
#        their first material inflow from the same source within
#        `_FUNDING_WINDOW` (≤ 1h). Possible same operator.
#        confidence=medium.
#
#   H4 — Bridge round-trip: source-chain address A bridges to
#        chain X, and another address C on the source chain
#        receives a corresponding bridge return within
#        `_BRIDGE_ROUNDTRIP_WINDOW`. Likely same operator.
#        confidence=medium.
#
# Cluster IDs are stable across runs: cluster_<sha256(sorted_addrs)[:8]>.
#
# Pairs where EITHER address has an explicit label of category
# exchange_deposit / exchange_hot_wallet / bridge / mixer /
# defi_protocol / staking are NEVER clustered — they're shared
# infrastructure, not operator wallets.

#: Tighter than the v0.9 `_COMMON_WITHDRAWAL_WINDOW` (12h). The spec
#: scenario is "same person withdraws from Binance to two of his
#: wallets back-to-back" — minutes, not hours.
_CEX_WITHDRAWAL_WINDOW = timedelta(hours=1)

#: Funding within 1h: addresses initialized for gas from the same
#: source in a single session. Wider than this and the signal degrades
#: into "two unrelated users got funded by the same hot wallet today".
_FUNDING_WINDOW = timedelta(hours=1)

#: Bridge round-trip window. The full hop chain is unknown to us
#: (we don't follow funds across chains in this MVP), so we use a
#: generous window — bridges + chain finality can take tens of
#: minutes plus the operator's own delay.
_BRIDGE_ROUNDTRIP_WINDOW = timedelta(hours=6)

#: Label categories that disqualify an address from being clustered
#: with anything else. These are shared-infrastructure roles where
#: clustering would conflate unrelated users.
_NEVER_CLUSTER_CATEGORIES = frozenset({
    LabelCategory.exchange_deposit,
    LabelCategory.exchange_hot_wallet,
    LabelCategory.bridge,
    LabelCategory.mixer,
    LabelCategory.defi_protocol,
    LabelCategory.staking,
})

#: HIGH-2 fix (v0.48 audit): hard ceiling on distinct input addresses
#: for the common-input-ownership (H1 co-spending) heuristic. A single
#: tx with more than this many distinct inputs is almost always a
#: CoinJoin or a shared-infrastructure consolidation, NOT one owner —
#: pairing them would falsely merge unrelated participants. Standard
#: wallet self-consolidations are well under 8 inputs.
_MAX_CIO_INPUT_ADDRS = 8


def _looks_like_coinjoin(output_values_sats: list[int]) -> bool:
    """True iff the observed output values contain an equal-value cluster
    of 3+ — the canonical CoinJoin / equal-output mixing shape.

    Conservative: any value appearing 3+ times among the observed
    outputs flags the tx as CoinJoin-shaped, so common-input-ownership
    is suppressed. Mirrors the BitcoinAdapter's >=4-in / 3-equal-out
    gate (the input-count check is applied by the caller).
    """
    if len(output_values_sats) < 3:
        return False
    counts: dict[int, int] = defaultdict(int)
    for v in output_values_sats:
        counts[v] += 1
        if counts[v] >= 3:
            return True
    return False


def _stable_cluster_id(addresses: set[str]) -> str:
    """Stable cluster id from the sorted address set.

    Two runs over the same case must produce the same cluster IDs
    so downstream consumers (PDF brief, AI editorial, investigation
    notes) can refer to "cluster_a1b2c3d4" persistently. SHA-256
    over the joined-sorted addresses guarantees that property
    regardless of dict-iteration order or how the union-find tree
    rooted itself.
    """
    if not addresses:
        return "cluster_empty"
    joined = "\n".join(sorted(addresses))
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return f"cluster_{digest[:8]}"


def _is_skip_labeled(
    addr: str,
    label_store: LabelStore | None,
    chain: Chain,
    *,
    point_in_time: datetime | None = None,
) -> bool:
    """True if the address has an explicit label that excludes it
    from clustering (exchange / bridge / mixer / DeFi / staking).

    Returns False when label_store is None or the address has no
    label — those addresses remain eligible for clustering.

    v0.31.4 (Gap 1a): ``point_in_time`` threads through to the
    LabelStore lookup so the exclusion check uses historical state.
    """
    if label_store is None or not addr:
        return False
    try:
        lbl = lookup_pit_safe(label_store, addr, chain=chain, point_in_time=point_in_time,)
    except Exception:  # noqa: BLE001 — never fail clustering on lookup error
        return False
    if lbl is None:
        return False
    try:
        return lbl.category in _NEVER_CLUSTER_CATEGORIES
    except Exception:  # noqa: BLE001
        return False


@dataclass(frozen=True)
class _PairSignal:
    """One heuristic firing for a pair of addresses."""
    heuristic: str         # 'co_spending' | 'cex_withdrawal' | 'common_funding' | 'bridge_round_trip'
    confidence: str        # 'high' | 'medium'
    details: str


def compute_address_clusters(
    case: Case,
    *,
    label_store: LabelStore | None = None,
) -> dict[str, str]:
    """Return ``{address: cluster_id}`` for the MVP clustering pass.

    Pure function: no DB, no network, no filesystem. Single argument
    is the in-memory ``Case``; ``label_store`` is keyword-only so the
    caller has to opt in to the explicit-label suppression behaviour.

    Only addresses that end up in a multi-member cluster appear in
    the returned dict — singletons are omitted. An empty case (no
    transfers) returns ``{}``.

    The returned dict is stable across runs: the cluster ID is a
    sha256 of the sorted address set, so two pipeline runs over the
    same case yield identical IDs.

    Side data (per-cluster heuristic / confidence / member list) is
    available via :func:`compute_clusters_with_metadata` for callers
    (e.g. emit_brief) that need richer output.
    """
    clusters_meta = compute_clusters_with_metadata(
        case, label_store=label_store,
    )
    out: dict[str, str] = {}
    for entry in clusters_meta:
        cid = entry["cluster_id"]
        for addr in entry["addresses"]:
            out[addr] = cid
    return out


def compute_clusters_with_metadata(
    case: Case,
    *,
    label_store: LabelStore | None = None,
) -> list[dict[str, Any]]:
    """MVP clustering with full metadata (heuristic + confidence + members).

    Returns a list of dicts:
        {
          "cluster_id": "cluster_a1b2c3d4",
          "addresses": ["0x...", "0x..."],
          "size": 2,
          "confidence": "high" | "medium",
          "heuristics": ["co_spending", "cex_withdrawal", ...],
          "evidence": [{"heuristic": "...", "details": "...",
                        "confidence": "..."}, ...]
        }

    Sorted by size desc, then cluster_id for determinism.
    """
    if not case.transfers:
        return []

    from recupero._common import canonical_address_key as _ck

    # All edges collected here, then unioned. Each entry is one
    # pair-of-addresses + one heuristic firing. Multiple firings on
    # the same pair are kept so the brief can show ALL the evidence.
    edges: list[tuple[str, str, _PairSignal]] = []

    # -- H1: Co-spending on Bitcoin ---------------------------- #
    # Group Bitcoin transfers by tx_hash; multiple distinct
    # from_address values on the same tx implies common input
    # ownership.
    #
    # v0.32.1 (CRIT-1 + HIGH-11 fix): the heuristic now reads from
    # the bitcoin.inputs_registry, which the BitcoinAdapter populates
    # with the FULL input-address set for every tx it normalizes.
    # Pre-v0.32.1 this loop only saw transfers whose from_address
    # matched a queried-seed address (the adapter dropped the other
    # N-1 inputs to ``first_input_addr`` only) — so the canonical
    # co-spending edge almost never fired. With the registry, a
    # 5-input tx where the trace visited any of the 5 input addresses
    # yields edges across all C(5, 2) = 10 pairs.
    from recupero.chains.bitcoin.inputs_registry import (
        lookup as _btc_lookup_inputs,
    )
    btc_tx_hashes: set[str] = set()
    for t in case.transfers:
        if t.chain != Chain.bitcoin:
            continue
        if t.tx_hash:
            btc_tx_hashes.add(t.tx_hash)

    btc_inputs_by_tx: dict[str, set[str]] = defaultdict(set)
    for tx_hash in btc_tx_hashes:
        # Prefer the registry (full input set captured at adapter
        # boundary). Fall back to whatever the case's transfers
        # surface — for tests / cases where the adapter wasn't run
        # and the registry is empty.
        registry_inputs = _btc_lookup_inputs(tx_hash)
        if registry_inputs:
            for raw_addr in registry_inputs:
                canonical = _ck(raw_addr)
                if canonical:
                    btc_inputs_by_tx[tx_hash].add(canonical)
    # Belt-and-suspender: also add any from_addresses seen via the
    # case's transfers themselves (covers legacy cases where the
    # registry wasn't populated, e.g. cases loaded from disk).
    for t in case.transfers:
        if t.chain != Chain.bitcoin:
            continue
        src = _ck(t.from_address)
        if src and t.tx_hash:
            btc_inputs_by_tx[t.tx_hash].add(src)

    # HIGH-2 fix (v0.48 audit): the common-input-ownership (CIO)
    # heuristic is INVALID for CoinJoin txs — the inputs belong to many
    # unrelated participants, not one owner. Before pairing we exclude:
    #   (a) txs detected as CoinJoin (>=4 inputs + 3+ equal-value
    #       outputs), via the adapter's same gate; and
    #   (b) txs with more than _MAX_CIO_INPUT_ADDRS distinct input
    #       addresses (belt-and-braces: a 100-input Wasabi tx would
    #       otherwise emit C(100,2)=4950 edges merging strangers).
    btc_outputs_by_tx: dict[str, list[int]] = defaultdict(list)
    for t in case.transfers:
        if t.chain != Chain.bitcoin or not t.tx_hash:
            continue
        # amount_raw is in sats for BTC; only outputs (to this case's
        # observed recipients) are visible, but the equal-value-cluster
        # test below is conservative — a real CoinJoin's equal outputs
        # show up here as soon as 3+ are observed.
        raw = getattr(t, "amount_raw", None)
        if isinstance(raw, int) and raw > 0:
            btc_outputs_by_tx[t.tx_hash].append(raw)

    for tx_hash, inputs in btc_inputs_by_tx.items():
        if len(inputs) < 2:
            continue
        # (b) input-count ceiling — skip pathological many-input txs.
        if len(inputs) > _MAX_CIO_INPUT_ADDRS:
            log.debug(
                "clustering H1: skipping co-spending for tx %s — %d "
                "distinct input addresses exceeds CIO ceiling %d "
                "(likely CoinJoin / shared infra, not common ownership)",
                tx_hash, len(inputs), _MAX_CIO_INPUT_ADDRS,
            )
            continue
        # (a) CoinJoin gate — >=4 inputs with a 3+ equal-output cluster
        # is the canonical mixing shape; CIO does not hold there.
        if len(inputs) >= 4 and _looks_like_coinjoin(
            btc_outputs_by_tx.get(tx_hash, [])
        ):
            log.debug(
                "clustering H1: skipping co-spending for tx %s — CoinJoin "
                "shape detected (>=4 inputs + equal-output cluster)",
                tx_hash,
            )
            continue
        inputs_list = sorted(inputs)
        for i, a in enumerate(inputs_list):
            for b in inputs_list[i + 1:]:
                if _is_skip_labeled(a, label_store, Chain.bitcoin, point_in_time=case.incident_time):
                    continue
                if _is_skip_labeled(b, label_store, Chain.bitcoin, point_in_time=case.incident_time):
                    continue
                edges.append((a, b, _PairSignal(
                    heuristic="co_spending",
                    confidence="high",
                    details=(
                        f"Both addresses appeared as inputs to Bitcoin "
                        f"tx {tx_hash[:16]}…"
                    ),
                )))

    # -- H2: Common CEX-deposit withdrawal (EVM, ≤1h) ---------- #
    # Group EVM transfers by from_address (the CEX deposit / hot
    # wallet) where that source is explicitly labeled as an
    # exchange. For each labeled source, find pairs of recipients
    # that received within the 1-hour window.
    cex_outflows: dict[str, list[tuple[str, Any, Chain]]] = defaultdict(list)
    # v0.34 (#225): remember whether each source is a per-user deposit address
    # or a shared hot wallet — it sets the pairing confidence below.
    cex_src_category: dict[str, LabelCategory] = {}
    if label_store is not None:
        for t in case.transfers:
            if t.chain == Chain.bitcoin:
                continue  # H2 is EVM-focused
            src = _ck(t.from_address)
            dst = _ck(t.to_address)
            if not src or not dst:
                continue
            try:
                # v0.31.4 (Gap 1a) point-in-time
                lbl = lookup_pit_safe(label_store, t.from_address, chain=t.chain,
                    point_in_time=case.incident_time,)
            except Exception:  # noqa: BLE001
                lbl = None
            if lbl is None:
                continue
            if lbl.category not in (
                LabelCategory.exchange_deposit,
                LabelCategory.exchange_hot_wallet,
            ):
                continue
            # The receiving address is what we want to cluster; the
            # source is shared infrastructure (CEX). Skip if the
            # recipient itself is exchange / bridge / etc.
            if _is_skip_labeled(dst, label_store, t.chain, point_in_time=case.incident_time):
                continue
            cex_outflows[src].append((dst, t.block_time, t.chain))
            cex_src_category[src] = lbl.category

    for src, recipients in cex_outflows.items():
        if len(recipients) < 2:
            continue
        # Pairwise: cluster within window. Suppress noise if the
        # exchange is dripping to dozens of users (shared infra).
        if len(recipients) > 20:
            log.debug(
                "clustering H2: skipping CEX %s with %d recipients "
                "(treated as shared infra)", src, len(recipients),
            )
            continue
        for i, (a, ts_a, chain_a) in enumerate(recipients):
            for b, ts_b, chain_b in recipients[i + 1:]:
                if a == b:
                    continue
                # v0.32.1 (forensic-audit HIGH): the same-named CEX deposit
                # address can be deployed on multiple chains. Two withdrawals
                # of similar timing on DIFFERENT chains are not evidence of a
                # single controlling entity — only same-chain pairs may
                # cluster (mirrors the H4 chain guard).
                if chain_a != chain_b:
                    continue
                delta = abs((ts_a - ts_b).total_seconds())
                if delta > _CEX_WITHDRAWAL_WINDOW.total_seconds():
                    continue
                # v0.34 (#225): confidence depends on the SOURCE type. A
                # per-user exchange DEPOSIT address paying two recipients within
                # an hour is a strong same-beneficiary signal (high). A shared
                # exchange HOT WALLET serves thousands of unrelated users, so
                # co-timed withdrawals are only weak circumstantial evidence
                # (medium) — clustering two unrelated users at high confidence
                # would be a forensic overclaim in an LE deliverable.
                is_deposit = (
                    cex_src_category.get(src) == LabelCategory.exchange_deposit
                )
                src_kind = "deposit" if is_deposit else "hot-wallet"
                edges.append((a, b, _PairSignal(
                    heuristic="cex_withdrawal",
                    confidence="high" if is_deposit else "medium",
                    details=(
                        f"Both withdrew from exchange {src_kind} address "
                        f"{src[:10]}… within {delta / 60:.1f}min"
                    ),
                )))

    # -- H3: Common funding source (≤1h) ----------------------- #
    # First material inflow per address; pairs sharing a source
    # within the 1h window cluster (medium confidence).
    _MIN_FUNDING_USD = Decimal("100")
    first_inflow: dict[str, tuple[str, Any, Chain]] = {}
    inflow_partners: dict[str, set[str]] = defaultdict(set)
    for t in case.transfers:
        if t.usd_value_at_tx is None or t.usd_value_at_tx < _MIN_FUNDING_USD:
            continue
        src = _ck(t.from_address)
        dst = _ck(t.to_address)
        if not src or not dst:
            continue
        if dst not in first_inflow:
            first_inflow[dst] = (src, t.block_time, t.chain)
        inflow_partners[src].add(dst)

    funding_groups: dict[str, list[tuple[str, Any, Chain]]] = defaultdict(list)
    for addr, (src, ts, chain) in first_inflow.items():
        # Suppress sources that look like shared infrastructure
        # (many distinct recipients) OR carry explicit shared-infra
        # labels. Threshold of 5 matches the legacy clustering pass.
        if len(inflow_partners[src]) >= 5:
            continue
        if _is_skip_labeled(src, label_store, chain, point_in_time=case.incident_time):
            continue
        if _is_skip_labeled(addr, label_store, chain, point_in_time=case.incident_time):
            continue
        funding_groups[src].append((addr, ts, chain))

    for src, members in funding_groups.items():
        if len(members) < 2:
            continue
        for i, (a, ts_a, chain_a) in enumerate(members):
            for b, ts_b, chain_b in members[i + 1:]:
                if a == b:
                    continue
                # v0.32.1 (forensic-audit HIGH, H3 sibling of the H2 fix):
                # the same funding-source address string can exist on
                # multiple chains. Two addresses "funded by src" on
                # DIFFERENT chains are not evidence of one controlling
                # entity — only same-chain pairs may cluster (mirrors the
                # H2/H4 chain guards).
                if chain_a != chain_b:
                    continue
                delta = abs((ts_a - ts_b).total_seconds())
                if delta > _FUNDING_WINDOW.total_seconds():
                    continue
                edges.append((a, b, _PairSignal(
                    heuristic="common_funding",
                    confidence="medium",
                    details=(
                        f"Both initially funded by {src[:10]}… within "
                        f"{delta / 60:.1f}min"
                    ),
                )))

    # -- H4: Bridge round-trip --------------------------------- #
    # An address A sends to a bridge contract on source chain S;
    # another address C receives from a bridge contract on source
    # chain S within the round-trip window. The shape suggests
    # the operator moved funds out and back. We can't follow the
    # money cross-chain in this MVP, so this is a structural
    # heuristic — medium confidence.
    bridge_outs: list[tuple[str, Any, Chain]] = []   # (sender, ts, chain)
    bridge_ins: list[tuple[str, Any, Chain]] = []    # (recipient, ts, chain)
    if label_store is not None:
        for t in case.transfers:
            src = _ck(t.from_address)
            dst = _ck(t.to_address)
            if not src or not dst:
                continue
            # Bridge out: t.to_address is a bridge
            # v0.31.4 (Gap 1a) point-in-time
            try:
                to_lbl = lookup_pit_safe(label_store, t.to_address, chain=t.chain,
                    point_in_time=case.incident_time,)
            except Exception:  # noqa: BLE001
                to_lbl = None
            try:
                from_lbl = lookup_pit_safe(label_store, t.from_address, chain=t.chain,
                    point_in_time=case.incident_time,)
            except Exception:  # noqa: BLE001
                from_lbl = None
            if to_lbl is not None and to_lbl.category == LabelCategory.bridge:
                if not _is_skip_labeled(src, label_store, t.chain, point_in_time=case.incident_time):
                    bridge_outs.append((src, t.block_time, t.chain))
            if from_lbl is not None and from_lbl.category == LabelCategory.bridge:
                if not _is_skip_labeled(dst, label_store, t.chain, point_in_time=case.incident_time):
                    bridge_ins.append((dst, t.block_time, t.chain))

    for sender, ts_out, chain_out in bridge_outs:
        for recipient, ts_in, chain_in in bridge_ins:
            if sender == recipient:
                continue  # same address, not a clustering signal
            if chain_out != chain_in:
                # We only match round-trips that return on the same
                # source chain (the spec scenario). Cross-chain
                # follow is out of scope for MVP.
                continue
            # Bridge return must come AFTER the out (operator
            # bridges, waits, bridges back).
            if ts_in <= ts_out:
                continue
            delta = (ts_in - ts_out).total_seconds()
            if delta > _BRIDGE_ROUNDTRIP_WINDOW.total_seconds():
                continue
            edges.append((sender, recipient, _PairSignal(
                heuristic="bridge_round_trip",
                confidence="medium",
                details=(
                    f"A bridged out on {chain_out.value}; another address "
                    f"received from a bridge on {chain_in.value} "
                    f"{delta / 3600:.1f}h later"
                ),
            )))

    # -- Union-find merge --------------------------------------- #
    if not edges:
        return []

    uf = _UnionFind()
    pair_evidence: dict[tuple[str, str], list[_PairSignal]] = defaultdict(list)
    # MEDIUM-14 fix (v0.48 audit): a separate union-find over ONLY the
    # high-confidence edges. A cluster is "high" iff its high-edge
    # subgraph spans all members — i.e. every member is connected to the
    # rest by a chain of high-confidence edges. Pre-fix a member attached
    # only by a weak bridge_round_trip edge inherited the cluster-level
    # "high" from an unrelated strong edge elsewhere in the component.
    uf_high = _UnionFind()
    for a, b, sig in edges:
        uf.union(a, b)
        pair_evidence[_edge_key(a, b)].append(sig)
        if sig.confidence == "high":
            uf_high.union(a, b)

    # Materialize clusters
    members_by_root: dict[str, set[str]] = defaultdict(set)
    for a, b, _ in edges:
        members_by_root[uf.find(a)].add(a)
        members_by_root[uf.find(a)].add(b)

    out: list[dict[str, Any]] = []
    for _root, members in members_by_root.items():
        if len(members) < 2:
            continue
        cid = _stable_cluster_id(members)
        # Collect deduped evidence from every internal edge.
        evidence: list[dict[str, Any]] = []
        seen_ev: set[tuple[str, str, str]] = set()
        heuristics_set: set[str] = set()
        confidences: set[str] = set()
        sorted_members = sorted(members)
        for i, x in enumerate(sorted_members):
            for y in sorted_members[i + 1:]:
                for sig in pair_evidence.get(_edge_key(x, y), []):
                    key = (sig.heuristic, sig.confidence, sig.details)
                    if key in seen_ev:
                        continue
                    seen_ev.add(key)
                    evidence.append({
                        "heuristic": sig.heuristic,
                        "confidence": sig.confidence,
                        "details": sig.details,
                    })
                    heuristics_set.add(sig.heuristic)
                    confidences.add(sig.confidence)
        # MEDIUM-14 fix (v0.48 audit): cluster-level "high" is granted
        # ONLY when EVERY member is connected to the rest of the cluster
        # by high-confidence edges — i.e. all members share a single
        # high-edge component. A cluster where some member is attached
        # only by a weak (medium/low) edge is at most "medium", since the
        # weakest connecting link governs attachment confidence (the
        # cluster is only as trustworthy as its weakest bridge).
        high_roots = {uf_high.find(m) for m in sorted_members}
        all_members_high_connected = (
            "high" in confidences and len(high_roots) == 1
        )
        overall_conf = "high" if all_members_high_connected else "medium"
        # Per-member attachment confidence: a member in the spanning
        # high-edge component attaches at "high"; otherwise "medium".
        if all_members_high_connected:
            member_confidence = {m: "high" for m in sorted_members}
        else:
            high_root_counts: dict[str, int] = defaultdict(int)
            for m in sorted_members:
                high_root_counts[uf_high.find(m)] += 1
            member_confidence = {
                m: ("high" if high_root_counts[uf_high.find(m)] >= 2 else "medium")
                for m in sorted_members
            }
        out.append({
            "cluster_id": cid,
            "addresses": sorted_members,
            "size": len(sorted_members),
            "confidence": overall_conf,
            "member_confidence": member_confidence,
            "heuristics": sorted(heuristics_set),
            "evidence": evidence,
        })

    out.sort(key=lambda c: (-c["size"], c["cluster_id"]))
    if label_store is not None:
        _name_clusters_by_counterparty(out, case, label_store)
    return out


def _name_clusters_by_counterparty(
    clusters: list[dict[str, Any]],
    case: Case,
    label_store: LabelStore,
) -> None:
    """v0.38.0 (#2, TRM/Chainalysis-style NAMED entities): attach an
    ``entity_hint`` to each cluster derived from the dominant LABELED
    counterparty its members share.

    Cluster members are perpetrator-controlled wallets (labeled service
    addresses like exchange deposits are EXCLUDED from membership), but those
    members transact WITH labeled services — e.g. all funded from / withdrawing
    to the same exchange. The dominant such counterparty names the cluster
    ("associated with Binance"). This is an ASSOCIATION, never an identity
    claim: confidence is calibrated medium (a shared exchange counterparty) /
    low (anything else), never high — consistent with the engine's
    no-fabrication posture. Mutates each cluster dict in place; sets
    ``entity_hint`` to ``None`` when no labeled counterparty is shared.
    """
    from recupero._common import canonical_address_key as _ck

    _CAT_RANK = {
        "exchange_deposit": 3,
        "exchange_hot_wallet": 3,
        "bridge": 1,
        "defi_protocol": 1,
    }
    for cluster in clusters:
        members = {_ck(a) for a in cluster.get("addresses", []) if a}
        # (name, category) -> count of member↔labeled-counterparty transfers.
        counts: dict[tuple[str, str], int] = defaultdict(int)
        for t in case.transfers:
            f = _ck(t.from_address)
            to = _ck(t.to_address)
            f_in, to_in = f in members, to in members
            # We want the counterparty that is NOT a cluster member.
            if f_in and not to_in:
                cp_addr, cp_chain = t.to_address, t.chain
            elif to_in and not f_in:
                cp_addr, cp_chain = t.from_address, t.chain
            else:
                continue
            try:
                lbl = label_store.lookup(cp_addr, chain=cp_chain)
            except Exception:  # noqa: BLE001
                lbl = None
            if lbl is None or not getattr(lbl, "name", None):
                continue
            cat = getattr(lbl.category, "value", None) or str(lbl.category)
            counts[(lbl.name, cat)] += 1
        if not counts:
            cluster["entity_hint"] = None
            continue
        (best_name, best_cat), best_n = max(
            counts.items(),
            key=lambda kv: (_CAT_RANK.get(kv[0][1], 0), kv[1]),
        )
        conf = "medium" if best_cat in (
            "exchange_deposit", "exchange_hot_wallet",
        ) else "low"
        cluster["entity_hint"] = {
            "name": best_name,
            "category": best_cat,
            "relationship": "shared_counterparty",
            "shared_counterparty_transfers": best_n,
            "confidence": conf,
            "note": (
                f"Cluster ASSOCIATED with {best_name} via {best_n} shared-"
                "counterparty transfer(s) (funding/withdrawal). An association, "
                "not an identity claim."
            ),
        }


__all__ = (
    "Cluster",
    "ClusterEvidence",
    "cluster_addresses",
    "clusters_to_brief_section",
    "compute_address_clusters",
    "compute_clusters_with_metadata",
)
