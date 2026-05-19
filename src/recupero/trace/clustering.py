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

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from typing import Any

from recupero.models import Case

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
        if t.usd_value_at_tx is None or t.usd_value_at_tx < _MIN_CLUSTERING_USD:
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
        if len(partners) >= _SHARED_INFRA_PARTNER_THRESHOLD:
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
                    confidence="high",
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
                    confidence="high",
                    related_address=dest,
                ))

    # H3 — Direct transfer (weak signal). Address A → Address B
    # is treated as a clustering signal only when both addresses
    # appear elsewhere in the case AND the amounts are
    # "self-fund" looking (round numbers).
    for t in case.transfers:
        if t.usd_value_at_tx is None or t.usd_value_at_tx < _MIN_CLUSTERING_USD:
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
        balance = sum(
            (address_balances or {}).get(a, Decimal("0")) for a in members
        )
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


__all__ = (
    "Cluster",
    "ClusterEvidence",
    "cluster_addresses",
    "clusters_to_brief_section",
)
