"""Fund-flow graph analysis (v0.35.16 — roadmap C6).

Structural graph algorithms over a traced case — the layer TRM / Chainalysis
surface as "this is a consolidation point", "funds cycle here". Two findings
that directly point at the actor's infrastructure:

  * **Consolidation hubs** — nodes where many DISTINCT upstream paths re-merge.
    After a launderer splits funds (peel/split chains, which we already detect),
    they re-merge them at a consolidation wallet before the next move. A
    high-distinct-in-degree node IS that wallet. Complements peel-chain (split)
    detection with the merge side.
  * **Value cycles** — strongly-connected components (Tarjan) of size > 1 (plus
    self-loops): funds looping back through a set of addresses, a wash / layering
    obfuscation signal.

Plus basic metrics (node/edge counts, max reachable depth from the seed).

PURE + deterministic: operates on the case's transfers (canonical-keyed,
value-weighted), accepts a Case OR a list of transfer objects/dicts (duck-typed).
A structural finding is a fact about the graph, not an attribution — it says
"these addresses re-merge / cycle", never who controls them or fabricates an
edge.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

# Default: a node fed by this many DISTINCT direct sources is a consolidation
# hub candidate. 3 keeps it to genuine re-merge points (a normal hop has 1-2).
_DEFAULT_MIN_DISTINCT_SOURCES = 3


@dataclass(frozen=True)
class ConsolidationHub:
    """A node where many distinct upstream paths re-merge."""
    address: str
    distinct_sources: int
    inbound_usd: str
    source_sample: tuple[str, ...]   # up to a few of the feeding addresses

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "distinct_sources": self.distinct_sources,
            "inbound_usd": self.inbound_usd,
            "source_sample": list(self.source_sample),
            "heuristic": "consolidation_hub",
        }


@dataclass(frozen=True)
class ValueCycle:
    """A strongly-connected set of addresses (funds loop back through them)."""
    members: tuple[str, ...]
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {"members": list(self.members), "size": self.size,
                "heuristic": "value_cycle"}


@dataclass
class GraphAnalysis:
    """Structural analysis of a case's fund-flow graph."""
    node_count: int = 0
    edge_count: int = 0
    max_depth_from_seed: int | None = None
    consolidation_hubs: list[ConsolidationHub] = field(default_factory=list)
    value_cycles: list[ValueCycle] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "max_depth_from_seed": self.max_depth_from_seed,
            "consolidation_hubs": [h.to_dict() for h in self.consolidation_hubs],
            "value_cycles": [c.to_dict() for c in self.value_cycles],
            "summary": {
                "n_consolidation_hubs": len(self.consolidation_hubs),
                "n_value_cycles": len(self.value_cycles),
            },
        }


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _finite_usd(value: Any) -> Decimal:
    if value is None:
        return Decimal(0)
    try:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
    except (ValueError, ArithmeticError, TypeError):
        return Decimal(0)
    if not d.is_finite() or d < 0:
        return Decimal(0)
    return d


def _strongly_connected_components(
    adj: dict[str, set[str]],
) -> list[list[str]]:
    """Tarjan's SCC — iterative (no recursion-depth blowup on long chains).

    Returns components in deterministic order (sorted members, then by first
    member) so the output is stable across runs.
    """
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0

    nodes = sorted(adj.keys())
    for root in nodes:
        if root in index_of:
            continue
        # Iterative DFS: work stack of (node, neighbor-iterator-position).
        work: list[tuple[str, int]] = [(root, 0)]
        succ: dict[str, list[str]] = {}
        while work:
            node, pi = work[-1]
            if node not in index_of:
                index_of[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
                succ[node] = sorted(adj.get(node, ()))
            neighbors = succ[node]
            if pi < len(neighbors):
                work[-1] = (node, pi + 1)
                nb = neighbors[pi]
                if nb not in index_of:
                    work.append((nb, 0))
                elif nb in on_stack:
                    low[node] = min(low[node], index_of[nb])
            else:
                if low[node] == index_of[node]:
                    comp: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == node:
                            break
                    result.append(sorted(comp))
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
    result.sort(key=lambda c: (-len(c), c[0] if c else ""))
    return result


def analyze_transfers(
    transfers: Any,
    *,
    seed: str | None = None,
    min_distinct_sources: int = _DEFAULT_MIN_DISTINCT_SOURCES,
) -> GraphAnalysis:
    """PURE: build the directed fund-flow graph from transfers and analyze it.

    ``transfers`` is any iterable of transfer objects or dicts exposing
    ``from_address`` / ``to_address`` / ``usd_value_at_tx``. Canonical-keyed.
    """
    from recupero._common import canonical_address_key as _ck

    adj: dict[str, set[str]] = defaultdict(set)
    sources_of: dict[str, set[str]] = defaultdict(set)
    inbound_usd: dict[str, Decimal] = defaultdict(Decimal)
    nodes: set[str] = set()
    edge_pairs: set[tuple[str, str]] = set()

    for t in transfers or []:
        src = _ck(str(_field(t, "from_address") or ""))
        dst = _ck(str(_field(t, "to_address") or ""))
        if not src or not dst or src == dst:
            continue
        nodes.add(src)
        nodes.add(dst)
        adj[src].add(dst)
        sources_of[dst].add(src)
        inbound_usd[dst] += _finite_usd(_field(t, "usd_value_at_tx"))
        edge_pairs.add((src, dst))

    # Consolidation hubs: distinct-in-degree >= threshold.
    hubs: list[ConsolidationHub] = []
    for node, srcs in sources_of.items():
        if len(srcs) >= min_distinct_sources:
            hubs.append(ConsolidationHub(
                address=node,
                distinct_sources=len(srcs),
                inbound_usd=f"${inbound_usd.get(node, Decimal(0)):,.2f}",
                source_sample=tuple(sorted(srcs)[:5]),
            ))
    hubs.sort(key=lambda h: (h.distinct_sources,
                             _finite_usd(h.inbound_usd.replace("$", "").replace(",", ""))),
              reverse=True)

    # Value cycles: SCCs of size > 1 (Tarjan) + explicit self-loops.
    sccs = _strongly_connected_components(adj)
    cycles = [ValueCycle(members=tuple(c), size=len(c)) for c in sccs if len(c) > 1]

    # Max depth from seed (longest BFS layer reached).
    max_depth: int | None = None
    if seed:
        seed_k = _ck(seed)
        if seed_k in nodes:
            seen = {seed_k}
            frontier = [seed_k]
            depth = 0
            while frontier:
                nxt: list[str] = []
                for n in frontier:
                    for m in adj.get(n, ()):
                        if m not in seen:
                            seen.add(m)
                            nxt.append(m)
                if nxt:
                    depth += 1
                frontier = nxt
                if depth > 10_000:   # pathological-graph guard
                    break
            max_depth = depth

    return GraphAnalysis(
        node_count=len(nodes),
        edge_count=len(edge_pairs),
        max_depth_from_seed=max_depth,
        consolidation_hubs=hubs,
        value_cycles=cycles,
    )


def analyze_case_graph(case: Any, *, min_distinct_sources: int = _DEFAULT_MIN_DISTINCT_SOURCES) -> GraphAnalysis:
    """Convenience: analyze a Case (or case.json dict) using its seed_address."""
    transfers = _field(case, "transfers") or []
    seed = _field(case, "seed_address")
    return analyze_transfers(
        transfers, seed=seed, min_distinct_sources=min_distinct_sources,
    )


__all__ = (
    "ConsolidationHub",
    "ValueCycle",
    "GraphAnalysis",
    "analyze_transfers",
    "analyze_case_graph",
)
