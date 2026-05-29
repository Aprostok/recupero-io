"""RIGOR-Jacob Z11: adversarial NaN/Infinity hunt across the MAIN
brief generators (brief.py, emit_brief.py, graph_ui.py,
recovery_snapshot.py).

Z7 patched the cluster / cooperation / law_firm dashboards. Z11
covers the unfixed main paths:

  * ``graph_ui.build_graph_data`` propagates ``Decimal('NaN')`` /
    ``Decimal('Infinity')`` through node ``inbound_usd``, edge
    ``total_usd``, and the ``meta.total_usd_traced`` aggregate.
    Three concrete failure modes:
      - Operator-shared HTML renders the literal text ``$NaN`` /
        ``$Infinity`` in tooltips and the page header.
      - ``json.dumps(float('nan'))`` writes the literal ``NaN`` into
        the embedded JSON blob; ``JSON.parse`` in the operator's
        browser throws ``SyntaxError`` so the interactive graph never
        loads — a silent operator-tool outage.

  * ``emit_brief.usd`` and the inline ``f"${...:,.2f}"`` at
    ``emit_brief.py:1812`` for ``CLUSTER_MEMBERSHIP.total_loss_usd_human``
    have no NaN/Inf guard. A NaN cluster aggregate (one member case
    with a poisoned price) ends up as the literal ``"$NaN"`` in
    ``freeze_brief.json``, which then propagates to every downstream
    renderer that reads that field.

  * ``brief._ensure_usd_prefix`` happily accepts the strings ``"NaN"``
    / ``"Infinity"`` (``Decimal('NaN')`` and ``Decimal('Infinity')``
    parse successfully) and emits ``"$NaN"`` / ``"$Infinity"`` —
    poisoning the LE handoff cover the issuer freeze letter total.

  * ``brief.generate_briefs`` aggregates ``theft_events`` USD via
    ``sum(...)`` for both the asset headline AND for ``le_routing``
    threshold evaluation. A single NaN ``usd_value_at_tx`` (e.g., from
    an out-of-band ingestion glitch) propagates into the sum and
    later raises ``decimal.InvalidOperation`` when
    ``recommend_le_routes`` does ``total_loss_usd >= threshold``,
    crashing the entire brief render.

  * ``recovery_snapshot.render_recovery_snapshot`` has a filename
    sanitizer (line 91) that produces ``recovery_snapshot_.html`` for
    an empty case_id — degenerate filename mirroring the Z7
    law_firm_dashboard bug. Same shape as Z7 finding 3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

import pytest

# ---------- 1. graph_ui NaN propagation ----------


@dataclass
class _StubNode:
    """Mirror of ``_flow_diagram._NodeAttrs`` shape with the minimum
    set of fields ``graph_ui.build_graph_data`` reads."""
    address: str
    chain: str = "ethereum"
    category: str = "wallet"
    identity: str | None = None
    inbound_usd: Decimal = Decimal(0)
    outbound_usd: Decimal = Decimal(0)
    issuer: str | None = None


@dataclass
class _StubEdge:
    """Mirror of ``_flow_diagram._EdgeAttrs`` shape with the minimum
    set of fields ``graph_ui.build_graph_data`` reads."""
    src: str
    dst: str
    total_usd: Decimal = Decimal(0)
    transfer_count: int = 1
    dominant_symbol: str | None = None
    first_time: datetime | None = None
    last_time: datetime | None = None
    src_chain: str = "ethereum"
    dst_chain: str = "ethereum"


@dataclass
class _StubCase:
    """Bare-shape Case stand-in so ``build_graph_data`` can read
    ``case_id``, ``seed_address``, ``chain``. Avoid pulling in the
    full pydantic Transfer machinery; ``_aggregate`` is monkey-patched
    in the tests below."""
    case_id: str = "TEST-GRAPH"
    seed_address: str = "0x" + "1" * 40
    chain: Any = None

    def __post_init__(self):
        from recupero.models import Chain
        if self.chain is None:
            self.chain = Chain.ethereum


def test_graph_ui_node_nan_inbound_usd_does_not_render_dollar_nan(monkeypatch):
    """RIGOR-Jacob Z11: a node with ``Decimal('NaN')`` inbound (one
    poisoned transfer in the case) must NOT serialize to
    ``"$NaN"`` in the node tooltip data."""
    from recupero.reports import graph_ui

    seed = "0x" + "1" * 40
    other = "0x" + "2" * 40
    nodes = {
        seed.lower(): _StubNode(address=seed, category="victim", identity="Victim"),
        other.lower(): _StubNode(
            address=other, inbound_usd=Decimal("NaN"),
            outbound_usd=Decimal("Infinity"),
        ),
    }
    edges: list[_StubEdge] = []
    monkeypatch.setattr(
        "recupero.worker._flow_diagram._aggregate",
        lambda case: (nodes, edges),
    )
    data = graph_ui.build_graph_data(_StubCase())
    for node in data["nodes"]:
        assert node["inboundUsd"] != "$NaN", (
            f"NaN propagated to node tooltip: {node}"
        )
        assert "NaN" not in node["inboundUsd"]
        assert "Infinity" not in node["outboundUsd"]
        assert "$inf" not in node["outboundUsd"].lower()


def test_graph_ui_edge_nan_total_usd_does_not_render_dollar_nan(monkeypatch):
    """RIGOR-Jacob Z11: an edge with NaN total_usd (price-oracle
    glitch) must NOT render ``$NaN`` in the edge tooltip and must
    NOT poison ``totalUsdNumeric`` with float('nan') — which then
    serializes to invalid JSON ``NaN`` and breaks ``JSON.parse``
    on the operator's browser."""
    from recupero.reports import graph_ui

    seed = "0x" + "1" * 40
    other = "0x" + "2" * 40
    nodes = {
        seed.lower(): _StubNode(address=seed, category="victim"),
        other.lower(): _StubNode(address=other),
    }
    edges = [
        _StubEdge(src=seed, dst=other, total_usd=Decimal("NaN")),
        _StubEdge(src=other, dst=seed, total_usd=Decimal("Infinity")),
    ]
    monkeypatch.setattr(
        "recupero.worker._flow_diagram._aggregate",
        lambda case: (nodes, edges),
    )
    data = graph_ui.build_graph_data(_StubCase())
    for edge in data["edges"]:
        assert "NaN" not in edge["totalUsd"], edge
        assert "Infinity" not in edge["totalUsd"], edge
        # totalUsdNumeric must be JSON-safe (no NaN / Infinity) or
        # the browser's JSON.parse blows up loading the graph.
        n = edge["totalUsdNumeric"]
        assert isinstance(n, (int, float))
        assert n == n, f"totalUsdNumeric is NaN ({n!r}) — breaks JSON.parse"
        assert n not in (float("inf"), float("-inf")), edge


def test_graph_ui_meta_total_usd_traced_does_not_render_nan(monkeypatch):
    """RIGOR-Jacob Z11: the header ``Traced: $NaN`` in the operator-
    shared graph HTML is a confidence-undermining bug.

    Trigger: any single edge with NaN total_usd poisons the running
    Decimal sum at graph_ui.py:213 (``total_usd += e.total_usd or
    Decimal(0)`` — NaN is truthy so it's added in)."""
    from recupero.reports import graph_ui

    seed = "0x" + "1" * 40
    other = "0x" + "2" * 40
    nodes = {
        seed.lower(): _StubNode(address=seed, category="victim"),
        other.lower(): _StubNode(address=other),
    }
    edges = [
        _StubEdge(src=seed, dst=other, total_usd=Decimal("1000")),
        _StubEdge(src=other, dst=seed, total_usd=Decimal("NaN")),
    ]
    monkeypatch.setattr(
        "recupero.worker._flow_diagram._aggregate",
        lambda case: (nodes, edges),
    )
    data = graph_ui.build_graph_data(_StubCase())
    total = data["meta"]["total_usd_traced"]
    assert "NaN" not in total, f"meta.total_usd_traced poisoned: {total!r}"
    assert "Infinity" not in total


def test_graph_ui_render_writes_valid_json_with_nan_inputs(tmp_path, monkeypatch):
    """RIGOR-Jacob Z11: the rendered HTML's embedded JSON blob must
    be valid JSON even when the case has NaN / Infinity USD totals.

    Pre-fix the blob contains the JS-literal ``NaN`` / ``Infinity``
    that ``JSON.parse(document.getElementById('graph-data').textContent)``
    rejects with SyntaxError; the interactive graph never loads."""
    from recupero.reports import graph_ui

    seed = "0x" + "1" * 40
    other = "0x" + "2" * 40
    nodes = {
        seed.lower(): _StubNode(address=seed, category="victim"),
        other.lower(): _StubNode(
            address=other, inbound_usd=Decimal("NaN"),
        ),
    }
    edges = [
        _StubEdge(src=seed, dst=other, total_usd=Decimal("Infinity")),
    ]
    monkeypatch.setattr(
        "recupero.worker._flow_diagram._aggregate",
        lambda case: (nodes, edges),
    )
    data = graph_ui.build_graph_data(_StubCase())
    out_path = tmp_path / "graph_ui.html"
    graph_ui.render_graph_html(data, out_path)
    html = out_path.read_text(encoding="utf-8")

    # Extract the embedded JSON blob (the one the JS does JSON.parse
    # on). It lives inside `<script id="graph-data" ...>...</script>`.
    import re
    m = re.search(
        r'<script id="graph-data"[^>]*>(.*?)</script>',
        html, re.DOTALL,
    )
    assert m, "graph-data <script> block missing from rendered HTML"
    blob = m.group(1)
    # Must be parseable as strict JSON. If NaN / Infinity / -Infinity
    # appear unquoted, json.loads raises ValueError.
    try:
        json.loads(blob)
    except ValueError as e:
        pytest.fail(
            f"Rendered graph_ui.html contains invalid JSON — "
            f"JSON.parse will reject this in the browser: {e}\n"
            f"blob[:300]={blob[:300]!r}"
        )


# ---------- 2. emit_brief.usd() + CLUSTER_MEMBERSHIP NaN poison ----------


def test_emit_brief_usd_rejects_nan():
    """RIGOR-Jacob Z11: ``emit_brief.usd(Decimal('NaN'))`` must NOT
    return ``"$NaN"``. This function is called pervasively from
    emit_brief — a poisoned ``total_usd`` in any code path leaks
    a literal ``$NaN`` into freeze_brief.json."""
    from recupero.reports.emit_brief import usd

    out = usd(Decimal("NaN"))
    assert out != "$NaN", f"usd() rendered NaN literally: {out!r}"
    assert "NaN" not in out
    assert "nan" not in out.lower()


def test_emit_brief_usd_rejects_infinity():
    """RIGOR-Jacob Z11: same hardening for Decimal('Infinity')."""
    from recupero.reports.emit_brief import usd

    out = usd(Decimal("Infinity"))
    assert "Infinity" not in out
    assert "$inf" not in out.lower()


def test_emit_brief_cluster_total_loss_usd_human_rejects_nan(tmp_path, monkeypatch):
    """RIGOR-Jacob Z11: ``emit_brief.py:1812``
    ``f"${membership.total_loss_usd:,.2f}"`` is an unguarded direct
    format. If the cluster builder returns
    ``total_loss_usd=Decimal('NaN')`` (one poisoned member case),
    the freeze_brief.json gets ``CLUSTER_MEMBERSHIP.total_loss_usd_human
    = "$NaN"`` — which then renders ``$NaN`` in the LE handoff
    Multi-Victim Cluster section.

    Verify via a direct callable contract: any call site formatting
    a Decimal total must not emit ``$NaN``. We assert against the
    canonical `usd()` helper since the post-fix should route through it.
    """
    from recupero.reports.emit_brief import usd

    # The canonical wire: every USD aggregate in emit_brief must go
    # through the usd() guard. Verify both NaN AND Infinity routes
    # produce a safe sentinel — not the literal NaN/Infinity word.
    nan_out = usd(Decimal("NaN"))
    inf_out = usd(Decimal("Infinity"))
    for out in (nan_out, inf_out):
        assert out != "$NaN"
        assert out != "$Infinity"
        # The safe fallback is "$0" (matches the None-path).
        assert "NaN" not in out
        assert "Infinity" not in out


# ---------- 3. brief._ensure_usd_prefix NaN string ----------


def test_brief_ensure_usd_prefix_rejects_nan_string():
    """RIGOR-Jacob Z11: ``_ensure_usd_prefix`` accepts a bare numeric
    string and prefixes it with ``$``. ``Decimal('NaN')`` and
    ``Decimal('Infinity')`` both parse successfully so the function
    currently returns ``"$NaN"`` and ``"$Infinity"``.

    A freeze_brief.json hand-edit (or an upstream aggregator that
    serialized a NaN Decimal as the string ``"NaN"``) feeds this
    helper a poisoned string; the LE handoff then prints ``$NaN``
    in the cover banner."""
    from recupero.reports.brief import _ensure_usd_prefix

    for bad in ("NaN", "nan", "Infinity", "-Infinity", "inf"):
        out = _ensure_usd_prefix(bad)
        assert "NaN" not in out, f"_ensure_usd_prefix({bad!r}) = {out!r}"
        assert "Infinity" not in out, f"_ensure_usd_prefix({bad!r}) = {out!r}"


# ---------- 4. brief._fmt_usd NaN/Inf hardening ----------


def test_brief_fmt_usd_rejects_nan():
    """RIGOR-Jacob Z11: ``brief._fmt_usd`` delegates to
    ``_fmt_usd_bare_or`` (in ``_pricing.py``). The bare formatter
    does ``Decimal(str(amount))`` which accepts NaN/Inf strings
    and renders them via ``f"{d:,.2f}"`` as the literal text
    ``"NaN"``/``"Infinity"``. Pre-fix the LE handoff cover's
    ``USD {{ asset.usd_value_at_theft }}`` line prints ``USD NaN``
    on a poisoned aggregate (the asset block sums theft_events
    USD into a fresh Decimal value that is NOT bounded by the
    Transfer model's finite_number constraint — sum could become
    NaN via in-process Decimal arithmetic, e.g. division by zero
    in a future refactor).
    """
    from recupero.reports.brief import _fmt_usd

    out_nan = _fmt_usd(Decimal("NaN"))
    out_inf = _fmt_usd(Decimal("Infinity"))
    assert "NaN" not in out_nan, f"_fmt_usd(NaN) = {out_nan!r}"
    assert "Infinity" not in out_inf, f"_fmt_usd(Inf) = {out_inf!r}"


# ---------- 5. recovery_snapshot empty/path-traversal case_id ----------


def test_recovery_snapshot_rejects_empty_case_id(tmp_path):
    """RIGOR-Jacob Z11: an empty case_id collapses to filename
    ``recovery_snapshot_.html`` — degenerate (same shape as Z7
    law_firm_dashboard fix). The renderer should either refuse
    or substitute a recognizable fallback segment."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    out = render_recovery_snapshot(
        case_id="",
        recovery_estimate={"recommendation": "recommend"},
        briefs_dir=tmp_path,
    )
    if out is None:
        return  # Refusal is acceptable degradation.
    assert out.name != "recovery_snapshot_.html", (
        f"Empty case_id produced degenerate filename: {out.name}"
    )


def test_recovery_snapshot_rejects_path_traversal_case_id(tmp_path):
    """RIGOR-Jacob Z11: a case_id like ``../../escape`` must not
    let the renderer write outside ``briefs_dir``. Pre-fix the
    sanitizer converts each non-alphanumeric char to ``_``, but a
    test verifies the post-fix invariant directly."""
    from recupero.reports.recovery_snapshot import render_recovery_snapshot

    briefs_dir = tmp_path / "briefs"
    out = render_recovery_snapshot(
        case_id="../../escape",
        recovery_estimate={"recommendation": "recommend"},
        briefs_dir=briefs_dir,
    )
    if out is None:
        return
    out_resolved = out.resolve()
    assert out_resolved.parent == briefs_dir.resolve(), (
        f"Output {out_resolved} escaped briefs_dir {briefs_dir.resolve()}"
    )
    assert ".." not in out.name
    assert "/" not in out.name
    assert "\\" not in out.name
