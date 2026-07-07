"""v0.35.16 (C6) — fund-flow graph analysis.

Pins: consolidation-hub detection (distinct-in-degree >= threshold), value-cycle
(Tarjan SCC) detection incl. the iterative no-recursion-blowup path, self-loop +
NaN-USD guards, canonical-key node merging, depth-from-seed, and the dict shape.
A finding is a structural fact about the graph, not an attribution.
"""

from __future__ import annotations

from decimal import Decimal

from recupero.trace.graph_analysis import analyze_case_graph, analyze_transfers

A = "0x" + "a" * 40
B = "0x" + "b" * 40
C = "0x" + "c" * 40
D = "0x" + "d" * 40
HUB = "0x" + "ee" * 20


def _t(src, dst, usd=100):
    return {"from_address": src, "to_address": dst, "usd_value_at_tx": usd}


def test_consolidation_hub_detected_at_threshold():
    # 3 distinct sources re-merge into HUB → hub (default min=3).
    ts = [_t(A, HUB), _t(B, HUB), _t(C, HUB, 50)]
    g = analyze_transfers(ts)
    assert len(g.consolidation_hubs) == 1
    h = g.consolidation_hubs[0]
    assert h.address == HUB
    assert h.distinct_sources == 3
    assert h.inbound_usd == "$250.00"


def test_two_sources_below_threshold_no_hub():
    g = analyze_transfers([_t(A, HUB), _t(B, HUB)])
    assert g.consolidation_hubs == []


def test_value_cycle_detected():
    # A→B→A is a 2-cycle; C→D is not.
    g = analyze_transfers([_t(A, B), _t(B, A), _t(C, D)])
    assert len(g.value_cycles) == 1
    assert set(g.value_cycles[0].members) == {A, B}
    assert g.value_cycles[0].size == 2


def test_longer_cycle_via_iterative_tarjan():
    # A→B→C→A (3-cycle) — exercises the iterative SCC path.
    g = analyze_transfers([_t(A, B), _t(B, C), _t(C, A)])
    assert len(g.value_cycles) == 1
    assert set(g.value_cycles[0].members) == {A, B, C}


def test_linear_chain_has_no_cycle():
    g = analyze_transfers([_t(A, B), _t(B, C), _t(C, D)], seed=A)
    assert g.value_cycles == []
    assert g.max_depth_from_seed == 3   # A→B→C→D


def test_self_loop_and_nan_skipped():
    ts = [
        _t(A, A),                                  # self-loop → skipped
        {"from_address": B, "to_address": C, "usd_value_at_tx": Decimal("NaN")},
    ]
    g = analyze_transfers(ts)
    # Self-loop contributes no edge; B→C is a valid edge with $0 (NaN→0).
    assert g.node_count == 2
    assert g.edge_count == 1
    assert g.value_cycles == []


def test_canonical_key_merges_mixed_case():
    mixed = "0x" + "Ab" * 20
    lower = mixed.lower()
    # Three distinct sources into the same hub written in different cases.
    ts = [_t(A, mixed), _t(B, lower), _t(C, mixed)]
    g = analyze_transfers(ts)
    assert len(g.consolidation_hubs) == 1
    assert g.consolidation_hubs[0].distinct_sources == 3


def test_empty_graph():
    g = analyze_transfers([])
    assert g.node_count == 0 and g.edge_count == 0
    assert g.consolidation_hubs == [] and g.value_cycles == []


def test_to_dict_and_case_wrapper():
    case = {
        "seed_address": A,
        "transfers": [_t(A, HUB), _t(B, HUB), _t(C, HUB), _t(HUB, D)],
    }
    d = analyze_case_graph(case).to_dict()
    assert d["summary"]["n_consolidation_hubs"] == 1
    assert d["consolidation_hubs"][0]["heuristic"] == "consolidation_hub"
    assert d["node_count"] == 5
    assert d["max_depth_from_seed"] == 2   # A→HUB→D


# ---- no silent caps: BFS depth-guard observability ---- #


def test_bfs_depth_guard_warns_and_floors(monkeypatch, caplog):
    """When the seed-reachability BFS hits the pathological-depth guard, the
    reported max_depth is a FLOOR and must be WARNED (no silent cap) so the
    brief's depth figure can't read as a complete exploration."""
    import logging

    import recupero.trace.graph_analysis as ga

    monkeypatch.setattr(ga, "_MAX_BFS_DEPTH", 2)
    chain = [f"0x{i:040x}" for i in range(1, 8)]  # 7 nodes, 6 edges deep
    ts = [_t(chain[i], chain[i + 1]) for i in range(len(chain) - 1)]
    with caplog.at_level(logging.WARNING):
        g = analyze_transfers(ts, seed=chain[0])
    assert "guard" in caplog.text
    # Broke at depth 3 (first depth strictly greater than the cap of 2),
    # a floor well short of the true 6-hop chain.
    assert g.max_depth_from_seed == 3


def test_bfs_depth_no_warn_under_guard(caplog):
    import logging

    chain = [f"0x{i:040x}" for i in range(1, 5)]  # depth 3, well under 10_000
    ts = [_t(chain[i], chain[i + 1]) for i in range(len(chain) - 1)]
    with caplog.at_level(logging.WARNING):
        g = analyze_transfers(ts, seed=chain[0])
    assert "guard" not in caplog.text
    assert g.max_depth_from_seed == 3
