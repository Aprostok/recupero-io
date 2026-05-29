"""Adversarial-input audit for worker/_flow_diagram._aggregate.

The flow-diagram graph builder feeds two downstream renderers:

  * Graphviz / inline-SVG (the static Triage Report diagram).
  * `graph_ui.build_graph_data` → `interactive_graph.html.j2` (the
    D3 interactive operator UI).

Both consume `_aggregate(case) -> (nodes_dict, edges_list)`. Anything
that survives `_aggregate` ends up either in the SVG `<text>` element
or in the embedded JSON blob that the D3 frontend `JSON.parse`s.

This file hunts seven adversarial-input classes that the existing
`canonical_address_key` hardening did NOT cover:

  1. NaN / Infinity in `usd_value_at_tx` propagating into edge
     totals (downstream graph_ui has a guard; `_aggregate` itself
     does not, so any consumer that bypasses graph_ui — e.g., the
     Graphviz `_edge_label` formatter `_fmt_usd_compact` — still
     prints `$NaN`).
  2. Self-loop transfers (from == to). D3 force-layout treats a
     self-loop as a zero-length link and a sustained tick loop
     burns CPU; Graphviz handles them but the visual is noise.
  3. Unbounded node count — a malicious 100k-address case fills
     the in-memory `nodes` dict BEFORE the `_MAX_NODES` cap in
     `_select_for_render` runs. We pay 100k _NodeAttrs in RAM
     for a render that ultimately shows 36 nodes. The cap belongs
     at aggregation time, not pruning time.
  4. Bidi-override / NUL characters in counterparty labels —
     `_NodeAttrs.identity` is read verbatim from the on-chain label
     (Counterparty.label.name) and flows into the SVG `<text>`
     element. A RTL-override (U+202E) flips visual address order.
  5. `<script>` / `</script>` substrings in the address/identity
     string. The graph_ui.py template wraps the blob in
     `<script type="application/json">`, but a literal `</script>`
     inside an entity identity terminates the script context
     prematurely.
  6. Missing `block_time` on a transfer (None). The aggregator's
     `t.block_time < edge.first_time` comparison raises TypeError
     when block_time is None — crash before render.
  7. Duplicate edges that share `(from, to)` but differ in `chain`
     (e.g., two bridge legs: ETH→addr on ethereum + ETH→same addr
     on arbitrum). Current key is (from_key, to_key) — the second
     transfer's chain CLOBBERS the first. Cross-chain detection
     downstream silently breaks.

Tests use lightweight stubs to bypass the pydantic Transfer model
(which would itself catch some of these — but the production code
path can receive synthetic Transfer-like objects from upstream
normalizers, e.g., the bridge-calldata virtual-transfer builder).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

# Module under test.
from recupero.worker import _flow_diagram as fd

# ---------- Stub Transfer / Case shapes ---------- #


@dataclass
class _StubChain:
    """Match `Chain` enum's `.value` attribute access."""
    value: str = "ethereum"


@dataclass
class _StubToken:
    symbol: str = "USDC"


@dataclass
class _StubLabel:
    name: str = "Counterparty"
    category: Any = None  # LabelCategory-shaped (has .value)
    exchange: str | None = None


@dataclass
class _StubCounterparty:
    label: _StubLabel | None = None


@dataclass
class _StubTransfer:
    """Minimum shape `_aggregate` reads — bypasses pydantic so we
    can probe NaN / None / oversized inputs the real model would
    reject at parse time but in-process synthetic builders won't."""
    from_address: str = "0x" + "1" * 40
    to_address: str = "0x" + "2" * 40
    chain: _StubChain = field(default_factory=_StubChain)
    token: _StubToken = field(default_factory=_StubToken)
    counterparty: _StubCounterparty = field(default_factory=_StubCounterparty)
    usd_value_at_tx: Decimal | None = Decimal("100")
    block_time: datetime | None = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )


@dataclass
class _StubCase:
    case_id: str = "TEST"
    seed_address: str = "0x" + "1" * 40
    chain: _StubChain = field(default_factory=_StubChain)
    transfers: list[Any] = field(default_factory=list)


# ---------- 1. NaN / Infinity in edge totals ---------- #


def test_aggregate_drops_nan_usd_from_edge_total() -> None:
    """A poisoned Decimal('NaN') in `usd_value_at_tx` (price-oracle
    glitch upstream) MUST NOT poison the aggregated edge.total_usd.

    Pre-fix: `edge.total_usd += Decimal('NaN')` → edge.total_usd is
    NaN forever, and every downstream formatter that bypasses
    graph_ui's guard (the Graphviz `_edge_label` formatter chain
    `_fmt_usd_compact(NaN)` returns the literal '$nan') prints
    nonsense in the static SVG."""
    other = "0x" + "2" * 40
    transfers = [
        _StubTransfer(usd_value_at_tx=Decimal("100")),
        _StubTransfer(usd_value_at_tx=Decimal("NaN")),
        _StubTransfer(usd_value_at_tx=Decimal("50")),
    ]
    case = _StubCase(transfers=transfers)

    nodes, edges = fd._aggregate(case)
    assert len(edges) == 1
    e = edges[0]
    assert e.total_usd.is_finite(), (
        f"edge.total_usd is non-finite ({e.total_usd}) — NaN propagated"
    )
    assert e.total_usd == Decimal("150"), (
        f"expected NaN to be dropped (100 + 50 = 150), got {e.total_usd}"
    )
    # Node-level inbound/outbound aggregates must also be clean.
    to_node = next(n for n in nodes.values() if n.address == other)
    assert to_node.inbound_usd.is_finite(), to_node.inbound_usd


def test_aggregate_drops_infinity_usd_from_edge_total() -> None:
    """Decimal('Infinity') must be filtered the same way — otherwise
    `_edge_penwidth(Inf)` returns inf, breaking Graphviz penwidth
    parsing AND `totalUsdNumeric=Infinity` crashes JSON.parse."""
    transfers = [
        _StubTransfer(usd_value_at_tx=Decimal("Infinity")),
        _StubTransfer(usd_value_at_tx=Decimal("200")),
    ]
    case = _StubCase(transfers=transfers)
    nodes, edges = fd._aggregate(case)
    assert edges[0].total_usd.is_finite()
    assert edges[0].total_usd == Decimal("200")


# ---------- 2. Self-loop transfers ---------- #


def test_aggregate_rejects_self_loop_edge() -> None:
    """A transfer from X to X is either a contract self-call (no
    real flow) or a malicious crafted input. D3 force-layout
    treats it as a zero-length link and the simulation never
    settles — sustained CPU burn in the operator's browser tab.

    `_aggregate` should drop self-loops at the source so neither
    renderer ever sees one."""
    same = "0x" + "a" * 40
    other = "0x" + "b" * 40
    transfers = [
        _StubTransfer(from_address=same, to_address=same),
        _StubTransfer(from_address=same, to_address=other),
    ]
    case = _StubCase(seed_address=same, transfers=transfers)
    _nodes, edges = fd._aggregate(case)
    # The self-loop edge must NOT appear.
    for e in edges:
        src_key = e.src.lower()
        dst_key = e.dst.lower()
        assert src_key != dst_key, (
            f"self-loop edge survived aggregation: {e.src} → {e.dst}"
        )


# ---------- 3. Unbounded node count ---------- #


def test_aggregate_caps_node_dict_to_avoid_oom() -> None:
    """A malicious / runaway case with 100k unique counterparties
    fills the in-memory `nodes` dict BEFORE the `_MAX_NODES=36` cap
    in `_select_for_render` ever runs. Memory cost: ~100k
    _NodeAttrs × ~7 fields = many MB for a render that ultimately
    shows 36 nodes.

    `_aggregate` should bound its working set — a hard ceiling
    around an order of magnitude above the render cap is plenty
    of headroom (we still need the BFS context to pick TOP-N
    edges) but rules out 100k blowup. We assert the dict size
    is bounded; the exact ceiling is policy."""
    n_addresses = 5000  # synthetic stress; <<100k for fast CI but >>_MAX_NODES
    transfers = []
    seed = "0x" + "1" * 40
    for i in range(n_addresses):
        addr = "0x" + f"{i:040x}"
        transfers.append(_StubTransfer(from_address=seed, to_address=addr))
    case = _StubCase(seed_address=seed, transfers=transfers)
    nodes, _edges = fd._aggregate(case)
    # Hard ceiling: ~10x the render-cap is reasonable; pre-fix this
    # was len(transfers) + 1.
    HARD_CAP = 2000
    assert len(nodes) <= HARD_CAP, (
        f"_aggregate dict grew to {len(nodes)} nodes — pre-fix was "
        f"{n_addresses+1}, post-fix should be ≤{HARD_CAP}. "
        f"Unbounded growth is an OOM vector for malicious cases."
    )


# ---------- 4. Bidi-override / NUL characters in labels ---------- #


def test_aggregate_strips_bidi_override_from_identity() -> None:
    """A counterparty label containing U+202E (RTL override) flips
    visual character order in the SVG <text> render — a malicious
    label "Exchange\\u202EelbarefiderC" appears as
    "ExchangeCireFireble" in the rendered diagram, spoofing the
    entity name.

    `_aggregate` populates `_NodeAttrs.identity` directly from
    Counterparty.label.name; that field must be sanitized to
    strip bidi-overrides + NUL + other control characters that
    flow into SVG text and (via graph_ui) into the embedded JSON
    blob the frontend renders."""
    from recupero.models import LabelCategory
    poisoned = "Binance‮elbanib"          # RTL override
    poisoned_nul = "Coinbase\x00\x00malicious"  # NUL
    label_a = _StubLabel(name=poisoned, category=LabelCategory.exchange_hot_wallet)
    label_b = _StubLabel(name=poisoned_nul, category=LabelCategory.exchange_hot_wallet)
    t1 = _StubTransfer(
        to_address="0x" + "a" * 40,
        counterparty=_StubCounterparty(label=label_a),
    )
    t2 = _StubTransfer(
        to_address="0x" + "b" * 40,
        counterparty=_StubCounterparty(label=label_b),
    )
    case = _StubCase(transfers=[t1, t2])
    nodes, _ = fd._aggregate(case)
    for n in nodes.values():
        if n.identity is None:
            continue
        assert "‮" not in n.identity, (
            f"bidi-override survived in node identity: {n.identity!r}"
        )
        assert "‭" not in n.identity
        assert "\x00" not in n.identity, (
            f"NUL survived in node identity: {n.identity!r}"
        )


# ---------- 5. `<script>` / `</script>` injection in identity ---------- #


def test_aggregate_strips_script_tags_from_identity() -> None:
    """The graph_ui template embeds the graph blob inside
    `<script type="application/json">...</script>`. A literal
    `</script>` inside an identity string terminates the script
    context — the browser then parses the trailing JSON as HTML.

    `_aggregate` is the upstream choke point. Identity strings
    must not contain HTML/script-context sequences when they
    flow into the JSON blob.

    The downstream graph_ui escapes `</` → `<\\/` but defense-
    in-depth at the data layer means even a non-strict parser
    can't be tricked."""
    from recupero.models import LabelCategory
    poisoned = '</script><script>alert("xss")</script>'
    label = _StubLabel(name=poisoned, category=LabelCategory.exchange_hot_wallet)
    t = _StubTransfer(counterparty=_StubCounterparty(label=label))
    case = _StubCase(transfers=[t])
    nodes, _ = fd._aggregate(case)
    for n in nodes.values():
        if not n.identity:
            continue
        low = n.identity.lower()
        assert "</script>" not in low, (
            f"unescaped </script> in node identity: {n.identity!r}"
        )
        assert "<script" not in low, (
            f"unescaped <script in node identity: {n.identity!r}"
        )


# ---------- 6. Missing block_time on a transfer ---------- #


def test_aggregate_handles_missing_block_time_without_crash() -> None:
    """An upstream synthetic-transfer builder (bridge calldata
    decoder, virtual-transfer normalizer) might emit a Transfer
    with `block_time=None` when the source data is incomplete.

    Pre-fix: `edge.first_time = t.block_time` then on the NEXT
    transfer `t.block_time < edge.first_time` raises TypeError
    (datetime vs None comparison). The whole render aborts —
    silent loss of the SVG from the artifact bundle.

    Post-fix: the aggregator skips the None timestamp gracefully.
    """
    t_with_time = _StubTransfer(
        usd_value_at_tx=Decimal("50"),
        block_time=datetime(2026, 1, 1, tzinfo=UTC),
    )
    t_no_time = _StubTransfer(
        usd_value_at_tx=Decimal("30"),
        block_time=None,
    )
    case = _StubCase(transfers=[t_with_time, t_no_time])
    # Must not raise.
    nodes, edges = fd._aggregate(case)
    assert len(edges) == 1
    assert edges[0].total_usd == Decimal("80")


# ---------- 7. Duplicate edges with different chains ---------- #


def test_aggregate_distinguishes_same_pair_on_different_chains() -> None:
    """A bridge-leg case has the same (from, to) pair on TWO
    chains (e.g., a sentinel bridge address receives USDC on
    Ethereum and then sends USDC.e on Arbitrum to the same
    downstream wallet).

    Pre-fix: edge key is `(from_key, to_key)` only — both legs
    collapse into ONE _EdgeAttrs whose `src_chain` / `dst_chain`
    is overwritten by whichever transfer came last. Downstream
    detection of `is_cross_chain = (src_chain != dst_chain)` is
    blind to the actual cross-chain hop.

    Post-fix: edges differentiate by chain too, OR the merged
    edge surfaces multi-chain context (e.g., a chains-set the
    renderer can read). We assert the WEAKER post-fix invariant:
    the edge model must distinguish the two chain legs in SOME
    way that downstream consumers can read (either two edges, or
    one edge that exposes both chains).
    """
    from_addr = "0x" + "a" * 40
    to_addr = "0x" + "b" * 40
    t_eth = _StubTransfer(
        from_address=from_addr,
        to_address=to_addr,
        chain=_StubChain(value="ethereum"),
        usd_value_at_tx=Decimal("1000"),
    )
    t_arb = _StubTransfer(
        from_address=from_addr,
        to_address=to_addr,
        chain=_StubChain(value="arbitrum"),
        usd_value_at_tx=Decimal("2000"),
    )
    case = _StubCase(seed_address=from_addr, transfers=[t_eth, t_arb])
    _nodes, edges = fd._aggregate(case)

    # Either: two distinct edges (one per chain),
    # OR: one edge that exposes both chains so downstream can render.
    chains_observed: set[str] = set()
    for e in edges:
        if e.src_chain == e.dst_chain:
            chains_observed.add(e.src_chain)
        else:
            chains_observed.update({e.src_chain, e.dst_chain})
    assert {"ethereum", "arbitrum"}.issubset(chains_observed), (
        f"chain info lost during aggregation: edges={edges}"
    )
