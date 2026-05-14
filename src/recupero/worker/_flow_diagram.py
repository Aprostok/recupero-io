"""TRM-style compact fund-flow SVG diagram for freeze briefs / LE handoffs.

Aim is to look closer to TRM Forensics / Chainalysis Reactor than to a
default Graphviz diagram. We use Graphviz's ``dot`` engine for layout —
it's well-developed and battle-tested — then override its defaults with
HTML node labels, modern fonts, hex-shaped entity badges, and a clean
palette so the output reads as a premium product asset, not an
engineering tool dump.

Output is inline-SVG so it embeds in HTML deliverables (and survives
PDF rendering downstream).

------------------------------------------------------------------------
Why this exists in its current shape (lessons from earlier iteration)
------------------------------------------------------------------------

The previous version rendered every single trace transfer as its own
edge, which on a real case produced a 984pt × 20,261pt SVG (~21:1
aspect ratio). Embedded in a letter-width HTML column, edge labels
shrank to a few pixels tall and the diagram was unreadable; printed to
PDF, it cropped or stretched horribly. Jacob (admin UI) flagged this
and we shifted to an attachment-pointer pattern.

This rewrite gets the diagram readable enough to live INSIDE the
letter (as Appendix A) by doing three things differently:

  1. **Aggregate parallel edges.** A trace often has 5–20 transfers
     between the same pair of wallets (USDC top-ups, gas refunds,
     dust). We collapse these into a single edge whose label shows the
     summed USD and the date range. This alone shrinks edge count by
     5–10x on real cases.

  2. **Cap to top-N edges by USD.** Most of the dollar value lives in
     a handful of edges; the long tail is noise that bloats the
     diagram without informing the reader. We render the top 30 edges
     and hide the rest behind a "+ N smaller transfers omitted" footer
     line. Operators who need the long tail open ``case.json`` or the
     standalone SVG.

  3. **Force landscape page-fit via size + ratio.** ``size="12,7.5!"``
     with ``ratio=compress`` tells dot to lay things out into a
     letter-landscape aspect (with some bleed). The exclamation forces
     the constraint even if dot would prefer a different shape.

Visual design (TRM-aligned):

  * Hexagonal nodes for *labeled entities* (exchanges, bridges, mixers,
    issuers, the victim). These read at a glance — the eye locks onto
    them as "the players" and the wallets recede.
  * Rounded-rectangle nodes for *unlabeled intermediate wallets*. They
    appear smaller and in a neutral grey so they don't compete with
    entities.
  * **Chain-coded border colors** on every node — ethereum=blue,
    polygon=purple, base=light blue, arbitrum=darker blue, bsc=gold,
    solana=violet. Cross-chain hops are visually obvious from the
    border color change alone.
  * **Bridge crossings** use dashed outgoing edges so the trace reader
    can see at a glance "funds left this chain here."
  * **Edge thickness** scales log10(USD) so a $1M edge is visibly
    thicker than a $1k edge.
  * Inter font (DejaVu Sans fallback in Docker) for clean typography;
    Graphviz default fonts are bitmap-y and look cheap.

If ``dot`` isn't on the PATH (dev box without the binary), the render
falls back to a placeholder SVG so the rest of the deliverable pipeline
still completes — the operator just sees a "flow diagram unavailable"
notice instead of a hard failure.
"""

from __future__ import annotations

import logging
import math
import shutil
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from recupero.models import Case, LabelCategory, Transfer

log = logging.getLogger(__name__)


# ----- Visual design system ----- #

# Font stack: single-word names only because multi-word names like
# "DejaVu Sans" can't be inside Graphviz HTML labels without breaking
# the XML parser. Browsers/PDF renderers pick whichever is available.
_FONT_FACE = "Inter,Helvetica,Arial,sans-serif"
_MONO_FACE = "Menlo,Consolas,monospace"

# Brand palette (matches _styles.html.j2)
_BRAND_NAVY = "#0B2545"
_BRAND_GOLD = "#B8924A"
_BG_COLOR = "#FFFFFF"
_TITLE_COLOR = _BRAND_NAVY
_SUBTITLE_COLOR = "#64748B"
_EDGE_COLOR = "#94A3B8"
_EDGE_LABEL_COLOR = "#334155"

# Per-category fill / border-stroke / label-text colors. The border color
# is overridden later by the chain coloring; this is the *category* tint
# applied as a subtle fill behind the label.
_NODE_PALETTE: dict[str, tuple[str, str, str]] = {
    "victim":               ("#DBEAFE", "#3B82F6", "#1E3A8A"),  # soft blue
    "exchange_deposit":     ("#DCFCE7", "#16A34A", "#14532D"),  # green
    "exchange_hot_wallet":  ("#DCFCE7", "#16A34A", "#14532D"),
    "mixer":                ("#FEE2E2", "#DC2626", "#7F1D1D"),  # red
    "bridge":               ("#FFEDD5", "#EA580C", "#7C2D12"),  # orange
    "defi_protocol":        ("#EDE9FE", "#7C3AED", "#4C1D95"),  # purple
    "perpetrator":          ("#FECDD3", "#BE123C", "#881337"),  # dark red
    "staking":              ("#E0F2FE", "#0284C7", "#0C4A6E"),  # cyan
    # Fallback (unknown / unlabeled wallet)
    "wallet":               ("#F8FAFC", "#94A3B8", "#475569"),
}

# Chain-coded border color. TRM uses distinct chain colors on every node
# so cross-chain hops jump out. The hue here roughly matches each
# chain's own branding so a familiar reader doesn't need a legend.
_CHAIN_STROKE: dict[str, str] = {
    "ethereum":    "#627EEA",
    "arbitrum":    "#28A0F0",
    "base":        "#0052FF",
    "polygon":     "#8247E5",
    "bsc":         "#F0B90B",
    "solana":      "#9945FF",
    "hyperliquid": "#0F0F0F",
    "bitcoin":     "#F7931A",
}

# Letter-mark logos for top-tier entities. When the trace lands on a
# labeled entity we recognize, the node gets a small colored badge
# next to the name — closer in feel to TRM/Chainalysis where
# Binance/Coinbase/etc. appear with branded marks.
# (letter, fill, text_color)
_ENTITY_BADGES: dict[str, tuple[str, str, str]] = {
    "binance":   ("B", "#F0B90B", "#1A1A1A"),
    "coinbase":  ("C", "#0052FF", "#FFFFFF"),
    "kraken":    ("K", "#5741D9", "#FFFFFF"),
    "okx":       ("O", "#000000", "#FFFFFF"),
    "bybit":     ("B", "#F7A600", "#1A1A1A"),
    "tether":    ("T", "#26A17B", "#FFFFFF"),
    "circle":    ("C", "#1A85FF", "#FFFFFF"),
    "paxos":     ("P", "#FFB800", "#1A1A1A"),
    "midas":     ("M", "#1A1A1A", "#FFFFFF"),
    "tornado":   ("T", "#000000", "#FFFFFF"),     # mixer: monochrome
    "stargate":  ("S", "#1F1F1F", "#FFFFFF"),     # bridge
    "wormhole":  ("W", "#3B0975", "#FFFFFF"),
    "across":    ("A", "#6CF9D8", "#1A1A1A"),
    "lido":      ("L", "#00A3FF", "#FFFFFF"),
    "uniswap":   ("U", "#FF007A", "#FFFFFF"),
    "1inch":     ("1", "#1F2937", "#FFFFFF"),
    "sky":       ("S", "#1AAB9B", "#FFFFFF"),
    "maker":     ("M", "#1AAB9B", "#FFFFFF"),
}


# Render budget. Real cases sometimes produce 200+ transfers — we cap
# to keep the diagram readable on a letter-landscape page.
_MAX_EDGES = 30
_MAX_NODES = 36


def _entity_badge(identity: str | None) -> tuple[str, str, str] | None:
    """Lookup the letter-mark badge for an identity. Matches against the
    entity name case-insensitively — e.g., "Binance Hot Wallet" matches
    the "binance" key. Returns None when nothing matches."""
    if not identity:
        return None
    low = identity.lower()
    for key, badge in _ENTITY_BADGES.items():
        if key in low:
            return badge
    return None


# Chain → explorer URL prefix. When a node renders, we append the address
# so each hex in the diagram links to its own Etherscan/Solscan/etc. page.
# Operators reading the brief can click any node to drill into chain data.
_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    # Hyperliquid has no per-address public explorer comparable to Etherscan.
    # We point at the official UI's address-search view as the closest
    # equivalent so the link still goes somewhere meaningful.
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
}


def _explorer_url(chain: str, address: str) -> str | None:
    prefix = _EXPLORER_BY_CHAIN.get(chain)
    if not prefix or not address:
        return None
    return f"{prefix}{address}"


# ----- Aggregation primitives ----- #


@dataclass
class _NodeAttrs:
    """Per-address attributes after merging the case's transfers.

    A node may appear as both a from- and to-side counterparty across
    multiple transfers, so we accumulate evidence (identity, category,
    chain) instead of taking the first observed values."""
    address: str
    category: str = "wallet"
    identity: str | None = None
    chain: str = "ethereum"
    inbound_usd: Decimal = Decimal(0)
    outbound_usd: Decimal = Decimal(0)


@dataclass
class _EdgeAttrs:
    """Aggregated edge between a unique (from, to) pair."""
    src: str
    dst: str
    total_usd: Decimal = Decimal(0)
    transfer_count: int = 0
    first_time: datetime | None = None
    last_time: datetime | None = None
    dominant_symbol: str | None = None
    dominant_usd: Decimal = Decimal(0)
    src_chain: str = "ethereum"
    dst_chain: str = "ethereum"


def _aggregate(case: Case) -> tuple[dict[str, _NodeAttrs], list[_EdgeAttrs]]:
    """Walk all transfers, collapse parallel edges, and compute per-node
    attributes.

    Returns:
      * A dict of address → _NodeAttrs covering every address the trace
        touched, with the strongest category we observed for that address.
      * A list of _EdgeAttrs, one per unique (src, dst) pair, with USD
        totals and date ranges aggregated across all parallel transfers.
    """
    nodes: dict[str, _NodeAttrs] = {}
    edges: dict[tuple[str, str], _EdgeAttrs] = {}

    # Seed the victim node so it appears even if the case has no
    # transfers originating from it directly (rare but possible during
    # partial trace runs).
    seed = case.seed_address
    seed_chain = case.chain.value
    nodes[seed] = _NodeAttrs(
        address=seed,
        category="victim",
        identity="Victim wallet",
        chain=seed_chain,
    )

    for t in case.transfers:
        # Per-side node bookkeeping. The from-side defaults to an
        # unlabeled wallet (unless we've already seen it as the victim or
        # promoted it via a previous to-side transfer that classified it).
        from_node = nodes.setdefault(
            t.from_address,
            _NodeAttrs(address=t.from_address, chain=t.chain.value),
        )
        # Promote chain in case we hit a multi-chain trace — we record
        # the most recent chain seen on this address; on a single-chain
        # case this is a no-op.
        from_node.chain = t.chain.value

        # The to-side may carry a counterparty label that classifies the
        # address (exchange, mixer, bridge, etc.). Prefer label evidence
        # over the default "wallet" classification — but only upgrade
        # never downgrade (e.g. a single dust-transfer with no label
        # shouldn't wipe an entity classification we got from an earlier
        # transfer).
        to_node = nodes.setdefault(
            t.to_address,
            _NodeAttrs(address=t.to_address, chain=t.chain.value),
        )
        to_node.chain = t.chain.value
        cat_name, identity = _classify_counterparty(t)
        if cat_name != "wallet" and to_node.category == "wallet":
            to_node.category = cat_name
            to_node.identity = identity

        usd = t.usd_value_at_tx or Decimal(0)
        from_node.outbound_usd += usd
        to_node.inbound_usd += usd

        # Aggregate the edge.
        key = (t.from_address, t.to_address)
        edge = edges.setdefault(
            key,
            _EdgeAttrs(
                src=t.from_address,
                dst=t.to_address,
                src_chain=from_node.chain,
                dst_chain=to_node.chain,
            ),
        )
        edge.total_usd += usd
        edge.transfer_count += 1
        edge.src_chain = from_node.chain
        edge.dst_chain = to_node.chain
        if edge.first_time is None or t.block_time < edge.first_time:
            edge.first_time = t.block_time
        if edge.last_time is None or t.block_time > edge.last_time:
            edge.last_time = t.block_time
        # Track the largest single-transfer token symbol — that's the
        # most informative one to show on the aggregated edge label.
        if usd > edge.dominant_usd:
            edge.dominant_usd = usd
            edge.dominant_symbol = t.token.symbol

    return nodes, list(edges.values())


def _select_for_render(
    nodes: dict[str, _NodeAttrs],
    edges: list[_EdgeAttrs],
    case: Case,
) -> tuple[dict[str, _NodeAttrs], list[_EdgeAttrs], int]:
    """Cap the render to a manageable number of edges + nodes.

    Strategy: sort edges by total USD desc, take the top _MAX_EDGES, then
    keep only the nodes that are endpoints of those edges (plus the
    victim, always). Returns the pruned node dict, pruned edge list, and
    the count of edges that were omitted (for the "+ N omitted" footer).

    We force-keep the victim node so the seed of the trace is always
    visible — even on an extreme trace where the top 30 edges by USD all
    happen further downstream.
    """
    edges_sorted = sorted(
        edges,
        key=lambda e: (e.total_usd, e.transfer_count),
        reverse=True,
    )
    kept_edges = edges_sorted[:_MAX_EDGES]
    omitted = max(0, len(edges_sorted) - len(kept_edges))

    keep_addrs: set[str] = {case.seed_address}
    for e in kept_edges:
        keep_addrs.add(e.src)
        keep_addrs.add(e.dst)

    # Secondary cap: if the kept-edges' endpoints still exceed _MAX_NODES
    # (which can happen on a wide fan-out graph), keep the highest-USD
    # nodes by combined inbound+outbound flow.
    if len(keep_addrs) > _MAX_NODES:
        scored = sorted(
            ((a, nodes[a].inbound_usd + nodes[a].outbound_usd) for a in keep_addrs),
            key=lambda kv: kv[1],
            reverse=True,
        )
        keep_addrs = {a for a, _ in scored[:_MAX_NODES]} | {case.seed_address}
        # Drop edges whose endpoints fell out of the node cap.
        kept_edges = [e for e in kept_edges if e.src in keep_addrs and e.dst in keep_addrs]

    pruned_nodes = {a: nodes[a] for a in keep_addrs if a in nodes}
    return pruned_nodes, kept_edges, omitted


def render_flow_diagram(
    case: Case,
    output_svg: Path,
    *,
    title: str | None = None,
) -> Path | None:
    """Render the case as an inline-SVG fund-flow diagram. Returns the
    output path on success, ``None`` on render failure (e.g. dot binary
    unavailable). Caller should use the placeholder helper for HTML
    embedding when this returns None.

    Output is a compact landscape SVG sized to fit a letter-landscape
    page with margins. Real-case traces frequently produce hundreds of
    parallel transfers; the function aggregates these and caps the
    visible edges to keep the page readable. The standalone case.json
    remains the source of truth for the full transfer set.
    """
    if not _dot_available():
        log.warning("graphviz `dot` binary not on PATH — skipping flow diagram")
        _write_placeholder_svg(output_svg, "Flow diagram unavailable (dot binary missing)")
        return None

    # Lazy import — avoids hard dependency on graphviz at module load
    # for environments that don't run the worker (e.g. CLI-only usage).
    try:
        from graphviz import Digraph
    except ImportError as e:
        log.warning("graphviz Python package not installed: %s", e)
        _write_placeholder_svg(output_svg, "Flow diagram unavailable")
        return None

    nodes_all, edges_all = _aggregate(case)
    nodes, edges, omitted = _select_for_render(nodes_all, edges_all, case)

    g = Digraph("flow", format="svg", strict=True)

    # Global graph attributes — compact landscape, premium styling.
    #
    # size="12,7.5!" forces the layout into a 12in × 7.5in box (the
    # exclamation makes it a hard constraint, not a hint). That's
    # letter-landscape with comfortable margins. ratio=compress lets dot
    # squeeze the layout into that box rather than scaling labels down.
    #
    # nodesep / ranksep are dialed back from the previous version so
    # nodes pack tighter — the old 0.85 ranksep was sized for a layout
    # we expected to be wider than tall.
    g.attr(
        rankdir="LR",
        bgcolor=_BG_COLOR,
        labelloc="t",
        labeljust="l",
        label=_html_title_label(case, title, omitted=omitted),
        fontname=_FONT_FACE,
        fontsize="14",
        nodesep="0.35",
        ranksep="0.55",
        pad="0.4",
        margin="0.2",
        splines="spline",
        concentrate="true",
        size="12,7.5!",
        ratio="compress",
    )
    g.attr(
        "node",
        shape="box",
        style="rounded,filled",
        fontname=_FONT_FACE,
        fontsize="10",
        margin="0.18,0.10",
        penwidth="1.8",
    )
    g.attr(
        "edge",
        fontname=_FONT_FACE,
        fontsize="8",
        color=_EDGE_COLOR,
        fontcolor=_EDGE_LABEL_COLOR,
        arrowsize="0.65",
        arrowhead="vee",
        penwidth="1.1",
    )

    # Render nodes.
    for addr, n in nodes.items():
        g.node(_node_id(addr), **_node_style(n))

    # Render edges.
    for e in edges:
        attrs = _edge_style(e)
        g.edge(_node_id(e.src), _node_id(e.dst), **attrs)

    output_svg.parent.mkdir(parents=True, exist_ok=True)
    # graphviz writes <stem>.svg — pass the stem (no extension) so it
    # doesn't double up to flow_id.svg.svg.
    stem = output_svg.with_suffix("")
    try:
        g.render(filename=str(stem), cleanup=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("flow diagram render failed: %s", exc)
        _write_placeholder_svg(output_svg, "Flow diagram render failed")
        return None

    log.info(
        "rendered flow diagram → %s (nodes=%d edges=%d omitted=%d)",
        output_svg, len(nodes), len(edges), omitted,
    )
    return output_svg


# ----- internals ----- #


def _dot_available() -> bool:
    return shutil.which("dot") is not None


def _node_id(address: str) -> str:
    """Stable Graphviz-safe identifier from a hex address."""
    return "n_" + address.lower().replace("0x", "")[:16]


def _short_addr(addr: str) -> str:
    if not addr or len(addr) < 12:
        return addr or ""
    return f"{addr[:6]}…{addr[-4:]}"


def _classify_counterparty(t: Transfer) -> tuple[str, str | None]:
    """Returns (palette_key, identity_string).

    Falls back to plain 'wallet' (neutral) for unlabeled counterparties.
    """
    label = t.counterparty.label
    if label is None:
        return "wallet", None
    cat: LabelCategory = label.category
    name = label.name or (label.exchange if label.exchange else None)
    return cat.value, name


# Node shape selection by category.
#
# Hex (regular polygon with sides=6, orientation tweaked so a flat side
# faces top/bottom) is reserved for *labeled entities*: exchanges,
# mixers, bridges, the victim, perpetrators, DeFi protocols. These are
# "the players" in the case — they should jump out of the diagram.
#
# Rounded rectangles are used for unlabeled wallet hops — they sit
# quietly in the middle and let the entities lead the read.
#
# Note: graphviz's HTML-table labels render inside ``shape=plaintext``
# only. Hex-shaped nodes therefore use a plain (non-HTML) label string
# with newline separators; we lose the colored letter-mark badge for
# hex nodes but gain the silhouette. The wordmark / identity stays
# legible because the label is just identity + short address.
_HEX_CATEGORIES = {
    "victim",
    "exchange_deposit",
    "exchange_hot_wallet",
    "mixer",
    "bridge",
    "defi_protocol",
    "perpetrator",
    "staking",
}


def _node_style(n: _NodeAttrs) -> dict[str, str]:
    """Build Graphviz node attrs for the given aggregated node.

    Labeled entities get a hex shape with chain-coded stroke; intermediate
    wallets get a small rounded rect. Every node has a click-through URL
    pointing at the appropriate chain explorer so operators can drill into
    on-chain history straight from the rendered diagram.
    """
    fill, _border, text_color = _NODE_PALETTE.get(n.category, _NODE_PALETTE["wallet"])
    stroke = _CHAIN_STROKE.get(n.chain, _NODE_PALETTE["wallet"][1])
    short = _short_addr(n.address)
    url = _explorer_url(n.chain, n.address)

    is_entity = n.category in _HEX_CATEGORIES

    if is_entity:
        # Hex-silhouette node, plain-text label (HTML labels aren't
        # supported on polygon shapes in graphviz).
        identity = n.identity or n.category.replace("_", " ").title()
        # Two-line label: bold-ish identity on top, short address below.
        # Graphviz doesn't honor <b> inside non-HTML labels — we lean on
        # font size + the hex silhouette to give the entity emphasis.
        label = f"{identity}\n{short}"
        return {
            "label": label,
            "shape": "hexagon",
            "style": "filled",
            "orientation": "0",  # flat sides top/bottom — TRM-style
            "fillcolor": fill,
            "color": stroke,
            "fontcolor": text_color,
            "fontsize": "10",
            "penwidth": "2.0",
            "width": "1.5",
            "height": "0.85",
            "margin": "0.18,0.10",
            **_url_attrs(url, identity, short),
        }

    # Unlabeled wallet — small rounded rectangle, mono short address only.
    label = (
        f'<<font face="{_MONO_FACE}" point-size="9" color="{text_color}">'
        f'{_escape(short)}</font>>'
    )
    return {
        "label": label,
        "shape": "box",
        "style": "rounded,filled",
        "fillcolor": fill,
        "color": stroke,
        "fontcolor": text_color,
        "penwidth": "1.4",
        "margin": "0.14,0.06",
        **_url_attrs(url, None, short),
    }


def _url_attrs(url: str | None, identity: str | None, short: str) -> dict[str, str]:
    if not url:
        return {}
    return {
        "URL": url,
        "target": "_blank",
        "tooltip": f"{identity or short} — open on chain explorer",
    }


def _edge_style(e: _EdgeAttrs) -> dict[str, str]:
    """Build Graphviz edge attrs for an aggregated edge.

    Edge thickness scales log10(USD). Cross-chain hops (src_chain !=
    dst_chain) render as dashed lines — visually obvious that funds
    left a chain. Edge labels show summed USD plus a compact date hint
    when the aggregated date range spans multiple days.
    """
    pen = _edge_penwidth(e.total_usd)
    attrs: dict[str, str] = {
        "label": _edge_label(e),
        "penwidth": f"{pen:.2f}",
    }
    if e.src_chain != e.dst_chain:
        attrs["style"] = "dashed"
        attrs["color"] = "#EA580C"  # match the bridge category color
        attrs["fontcolor"] = "#7C2D12"
    return attrs


def _edge_label(e: _EdgeAttrs) -> str:
    """Compact aggregated edge label.

    Examples:
      * Single transfer:      "$12,300 USDC · Apr 14"
      * Aggregated, same day: "$45,000 USDC ×3 · Apr 14"
      * Aggregated, range:    "$1.2M USDC ×17 · Apr 12–14"
      * No USD pricing:       "USDC ×3 · Apr 12–14"
    """
    parts: list[str] = []
    if e.total_usd > 0:
        parts.append(_fmt_usd_compact(e.total_usd))
    if e.dominant_symbol:
        parts.append(e.dominant_symbol)
    if e.transfer_count > 1:
        parts[-1] = parts[-1] + f" ×{e.transfer_count}"
    head = " ".join(parts) if parts else "(transfer)"

    if e.first_time and e.last_time:
        if e.first_time.date() == e.last_time.date():
            tail = e.first_time.strftime("%b %-d") if _has_dash_d_fmt() else e.first_time.strftime("%b %d").lstrip("0")
        else:
            tail = (
                f"{e.first_time.strftime('%b %d').lstrip('0')}–"
                f"{e.last_time.strftime('%b %d').lstrip('0')}"
            )
        return f"{head} · {tail}"
    return head


def _has_dash_d_fmt() -> bool:
    # ``%-d`` is glibc-only — falls back to ``%d``+lstrip on Windows.
    try:
        datetime(2020, 1, 1).strftime("%-d")
        return True
    except (ValueError, TypeError):
        return False


def _fmt_usd_compact(usd: Decimal) -> str:
    """``$12,300`` for small amounts, ``$1.2M`` for big ones — TRM-style."""
    u = float(usd)
    if u >= 1_000_000:
        return f"${u/1_000_000:.1f}M".replace(".0M", "M")
    if u >= 10_000:
        return f"${u/1_000:.0f}K"
    if u >= 1_000:
        return f"${u/1_000:.1f}K".replace(".0K", "K")
    if u >= 1:
        return f"${u:,.0f}"
    return f"${u:.2f}"


def _edge_penwidth(usd: Decimal | None) -> float:
    """Scale edge thickness by log10(USD). $0–$100 = 0.8pt, $1k = 1.6pt,
    $10k = 2.4pt, $100k = 3.2pt, $1M+ = 4.0pt."""
    if usd is None or usd <= 0:
        return 0.8
    return max(0.8, 0.8 + 0.8 * math.log10(float(usd) + 1))


def _html_title_label(case: Case, title: str | None, *, omitted: int) -> str:
    """The graph-level title block. HTML-style label (allowed when the
    label value is wrapped in ``<...>``).

    Layout matches the document letterhead aesthetic: serif "Recupero"
    wordmark on the left, the diagram subject on the right. When edges
    were omitted by the render budget, the omission count appears in
    the right cell so the reader knows the diagram is a top-N view.
    """
    primary = title or "Fund Flow Analysis"
    sub_pieces = [
        f"Case {_escape(case.case_id)}",
        f"{len(case.transfers)} transfer(s)",
        case.chain.value,
    ]
    if omitted:
        sub_pieces.append(f"top {_MAX_EDGES} flows · {omitted} smaller omitted")
    sub = " · ".join(sub_pieces)
    return (
        f'<<table border="0" cellspacing="0" cellpadding="0" width="100%">'
        f'<tr>'
        # Left cell: brand wordmark, no logo box
        f'<td align="left" cellpadding="6">'
        f'<font face="Georgia,serif" point-size="13" color="{_BRAND_NAVY}">'
        f'R&#8201;E&#8201;C&#8201;U&#8201;P&#8201;E&#8201;R&#8201;O</font><br/>'
        f'<font face="{_FONT_FACE}" point-size="7" color="{_SUBTITLE_COLOR}">'
        f'I N V E S T I G A T I O N &#160; S E R V I C E S</font>'
        f'</td>'
        # Right cell: subject of this diagram
        f'<td align="right" cellpadding="6">'
        f'<font face="Georgia,serif" point-size="14" color="{_TITLE_COLOR}">'
        f'{_escape(primary)}</font><br/>'
        f'<font face="{_FONT_FACE}" point-size="8" color="{_SUBTITLE_COLOR}">'
        f'{_escape(sub)}</font>'
        f'</td>'
        f'</tr></table>>'
    )


def _escape(s: str | None) -> str:
    """Minimal HTML escape for Graphviz HTML labels."""
    if s is None:
        return ""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _write_placeholder_svg(path: Path, message: str) -> None:
    """Tiny inline SVG used when the dot binary isn't available."""
    path.parent.mkdir(parents=True, exist_ok=True)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="600" height="80" viewBox="0 0 600 80">
  <rect width="600" height="80" fill="#FEF3C7" stroke="#D97706" rx="6"/>
  <text x="300" y="48" font-family="{_FONT_FACE}" font-size="14"
        fill="#78350F" text-anchor="middle">{_escape(message)}</text>
</svg>
"""
    path.write_text(svg, encoding="utf-8")


# ----- Inline-SVG helper used by the deliverables stage ----- #


def read_inline_svg(path: Path) -> str | None:
    """Read a rendered flow SVG from disk and return it as an inline-able
    fragment suitable for embedding inside an HTML template.

    Graphviz emits a standalone document beginning with ``<?xml ...?>``
    and a DOCTYPE block. We strip those so the SVG can drop directly
    into the body of a Jinja2 template and inherit the page's font
    rendering. Width/height attributes are also dropped so the
    enclosing block's CSS controls scaling — otherwise the SVG forces
    its rendered pixel size and overflows on letter-portrait PDFs.
    """
    if not path or not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        log.warning("flow SVG inline read failed for %s: %s", path, exc)
        return None
    # Trim everything before the first <svg ...>
    idx = raw.find("<svg")
    if idx == -1:
        log.warning("flow SVG inline: no <svg> root in %s", path)
        return None
    body = raw[idx:]
    # Strip explicit width="..." and height="..." attributes on the
    # root <svg> so CSS controls layout. We keep the viewBox so the
    # browser/PDF renderer can compute aspect ratio.
    body = _strip_root_svg_size(body)
    return body


def _strip_root_svg_size(svg: str) -> str:
    """Remove width=".." height=".." attributes from the root <svg> tag.

    Naive but safe enough — we only operate on the first ``<svg``
    occurrence in the document (the root). Done with string-level
    regex rather than an XML parser because we want zero deps on
    lxml and the SVG body itself stays untouched."""
    import re
    pattern = re.compile(r"(<svg\b[^>]*?)\s+(width|height)=\"[^\"]*\"", re.IGNORECASE)
    prev = None
    out = svg
    # Loop because there may be both width AND height to strip.
    while prev != out:
        prev = out
        out = pattern.sub(r"\1", out)
    return out


__all__ = (
    "render_flow_diagram",
    "read_inline_svg",
)
