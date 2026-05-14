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
import os
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
# Pure white canvas — TRM Forensics uses crisp white so entity
# borders and letter-mark badges pop maximally. The earlier
# #FAFAF7 off-white was warmer but muted the contrast.
_BG_COLOR = "#FFFFFF"
_TITLE_COLOR = _BRAND_NAVY
_SUBTITLE_COLOR = "#475569"
# Edge color stack — slate-blue for the line so direction reads at
# a glance; deep slate for the label so dollar values dominate.
_EDGE_COLOR = "#94A3B8"
_EDGE_LABEL_COLOR = "#0F172A"
_EDGE_LABEL_BG = "#FFFFFF"  # matches page bg so the "pill" reads as cut-out

# Per-category fill / border-stroke / label-text colors. The border color
# is overridden later by the chain coloring; this is the *category* tint
# applied as a subtle fill behind the label.
#
# Palette principles (TRM-aligned):
#   * Fills are mid-tone — not pastels — so the entity reads as a
#     "solid badge" against the white page, the way TRM's circle
#     nodes do. Pastels look like a wireframe; saturated mid-tones
#     read as product.
#   * Text colors are deep, near-black variants of the fill's hue
#     family so the label has serious contrast (4.5:1+).
#   * Victim is intentionally a different blue from chain-ethereum
#     so the seed node never gets confused with a generic ETH wallet.
#
# Palette upgrade (vibrant + clean, TRM-aligned):
#
#   * Fills are now bright, saturated — closer to brand-asset peak
#     than mid-tone. On a pure-white canvas with thick chain-coded
#     borders, the brighter fill reads as "premium product asset",
#     the way TRM Forensics' entity nodes do. The earlier mid-tones
#     were safe but muted.
#   * Border colors are punchier — bumped saturation a step.
#   * Text colors are deep near-black variants of each fill's hue
#     family so the label still has 7:1+ contrast.
#
_NODE_PALETTE: dict[str, tuple[str, str, str]] = {
    "victim":               ("#93C5FD", "#1D4ED8", "#0C2A6E"),  # vibrant blue
    "exchange_deposit":     ("#86EFAC", "#15803D", "#0F3D1F"),  # vibrant green
    "exchange_hot_wallet":  ("#86EFAC", "#15803D", "#0F3D1F"),
    "mixer":                ("#FCA5A5", "#B91C1C", "#5B1414"),  # vibrant red
    "bridge":               ("#FDBA74", "#C2410C", "#5C1F09"),  # vibrant orange
    "defi_protocol":        ("#C4B5FD", "#6D28D9", "#3C1380"),  # vibrant purple
    "perpetrator":          ("#FDA4AF", "#9F1239", "#5B0B1F"),  # vibrant crimson
    "staking":              ("#7DD3FC", "#0369A1", "#0B3A57"),  # vibrant sky
    # Freezable holdings (Circle / Tether / Sky / Paxos USDC/USDT
    # /DAI/USDP). Punchier gold so the "freeze the funds here"
    # callout reads loudest of all categories — these are the
    # actionable nodes.
    "freezable_holding":    ("#FDE68A", "#B45309", "#5C2D0F"),  # vibrant gold
    # Fallback (unknown / unlabeled wallet) — stays quiet neutral so
    # entity badges win visual hierarchy.
    "wallet":               ("#F1F5F9", "#94A3B8", "#334155"),
}

# Chain-coded border color. TRM uses distinct chain colors on every node
# so cross-chain hops jump out. The hue here roughly matches each
# chain's own branding so a familiar reader doesn't need a legend.
# Saturation bumped a step over each chain's flat brand color to
# print legibly at 1pt+ stroke widths.
_CHAIN_STROKE: dict[str, str] = {
    "ethereum":    "#4F6FF3",
    "arbitrum":    "#1392E5",
    "base":        "#0046E5",
    "polygon":     "#7B3FE4",
    "bsc":         "#E6A800",
    "solana":      "#8B2EFF",
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


def _promote_freezable_holdings(
    nodes: dict[str, _NodeAttrs],
    freeze_brief: dict[str, Any],
) -> None:
    """Mutate ``nodes`` in-place: for every (issuer, address) pair in
    ``freeze_brief['FREEZABLE']``, promote the matching node to a
    ``freezable_holding`` entity with identity ``"<issuer> holding"``.

    Why this exists: the trace BFS records counterparty *labels* at
    transfer time (Etherscan calls the address a "Binance hot wallet",
    etc.). But freezable holdings are detected *after* the trace, by
    walking final dormant balances and matching against issuer-token
    pairs. Those wallets typically don't carry an exchange/mixer/
    bridge label on the transfer itself — so without this promotion
    they'd render as plain rounded-rectangle wallets, and the diagram
    wouldn't visually surface the very wallets the letter is asking
    to freeze.

    Resolution rule: only promote nodes still classified as the
    default ``wallet`` (don't downgrade a real exchange label). A
    wallet that genuinely received USDC at a Binance hot-wallet
    address stays labeled as Binance — that's more useful for the
    reader than "Circle holding".

    Address comparison is case-insensitive (EVM addresses get
    checksummed inconsistently across sources; lower-case is the
    safe normalization).
    """
    holdings = freeze_brief.get("FREEZABLE") or []
    promoted = 0
    addr_lower_to_node: dict[str, _NodeAttrs] = {
        a.lower(): n for a, n in nodes.items()
    }
    for entry in holdings:
        issuer = entry.get("issuer") or "Issuer"
        token = entry.get("token") or ""
        identity = f"{issuer}\nholding ({token})" if token else f"{issuer} holding"
        for h in entry.get("holdings") or []:
            addr = h.get("address")
            if not addr:
                continue
            node = addr_lower_to_node.get(addr.lower())
            if node is None:
                # Wallet didn't appear in any transfer in the trace —
                # the freezable holding is dormant. We don't add a
                # synthetic node for it because there would be no
                # edges to draw; the letter's body table already
                # surfaces these addresses in the freeze ask.
                continue
            if node.category != "wallet":
                # Real exchange/mixer/bridge label takes precedence —
                # don't overwrite Binance with Circle just because
                # Binance's hot wallet happens to hold USDC.
                continue
            node.category = "freezable_holding"
            node.identity = identity
            promoted += 1
    if promoted:
        log.info(
            "flow diagram: promoted %d node(s) to freezable_holding "
            "from freeze_brief cross-ref", promoted,
        )


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
    freeze_brief: dict[str, Any] | None = None,
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

    ``freeze_brief`` (optional, the same JSON shape emit_brief.py
    writes to ``freeze_brief.json``) lets the renderer promote
    wallets that appear in the FREEZABLE list to labeled circle
    entities even when the trace itself didn't classify them. This
    fixes the common pattern where a wallet receives USDC but the
    counterparty label was missed at trace time, so the wallet would
    otherwise render as a generic rounded-rectangle. With the
    cross-ref, that same wallet shows as "Circle holding (USDC)" in
    the diagram — matching what the letter's body asks the issuer to
    freeze.
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
    if (freeze_brief is not None
            and os.environ.get(
                "RECUPERO_DISABLE_FREEZABLE_PROMOTION", ""
            ).strip() != "1"):
        _promote_freezable_holdings(nodes_all, freeze_brief)
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
        # Bigger ranksep + nodesep = more whitespace between nodes,
        # which is the single most reliable visual cue for "this
        # looks like a clean professional asset, not a tool dump".
        # TRM Forensics graphs breathe — we copy that.
        nodesep="0.55",
        ranksep="0.85",
        pad="0.5",
        margin="0.25",
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
        fontsize="9",
        color=_EDGE_COLOR,
        fontcolor=_EDGE_LABEL_COLOR,
        # Tighter, sharper arrowhead. Graphviz's "normal" triangle
        # was already cleaner than "vee"; "open" is even more
        # restrained — it draws as a hollow arrowhead which reads
        # as "flow direction" without dominating the edge.
        arrowsize="0.6",
        arrowhead="open",
        penwidth="1.2",
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

    # Post-process the Graphviz SVG to add elevation + refined edge
    # labels — things Graphviz can't do natively. Best-effort: a
    # post-process failure shouldn't kill the diagram (the raw
    # Graphviz output is still valid SVG).
    #
    # Kill-switch: RECUPERO_DISABLE_FLOW_POLISH=1 skips the polish
    # step entirely. The SVG filters (drop shadow, edge label pills)
    # measurably increase WeasyPrint's PDF render time + memory cost
    # — on a memory-constrained container with 8 PDFs to render per
    # case, that has been observed to OOM the worker. Disabling the
    # polish ships a flatter but still TRM-styled diagram (circles,
    # chain-coded borders, double-ring victim) within the same memory
    # budget as the pre-polish renderer.
    if os.environ.get("RECUPERO_DISABLE_FLOW_POLISH", "").strip() != "1":
        try:
            _polish_svg(output_svg)
        except Exception as exc:  # noqa: BLE001
            log.warning("flow SVG polish failed for %s (continuing with raw): %s",
                        output_svg.name, exc)
    else:
        log.info("flow SVG polish skipped — RECUPERO_DISABLE_FLOW_POLISH=1")

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


def _soft_wrap(text: str, *, width: int) -> str:
    """Word-wrap a label string at roughly ``width`` characters per line.

    Used for entity identity labels inside fixed-size circle nodes —
    long names like "Sky Protocol (formerly MakerDAO)" would overflow
    the silhouette without breaks. We split on word boundaries only
    (never mid-word) and cap at 3 lines to avoid towering labels.
    """
    if not text or len(text) <= width:
        return text or ""
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
            continue
        if len(cur) + 1 + len(w) <= width:
            cur = f"{cur} {w}"
        else:
            lines.append(cur)
            cur = w
            if len(lines) == 2:
                # Cap at 3 lines — last bucket gets remaining words joined.
                cur = " ".join([cur] + words[words.index(w) + 1:])
                break
    if cur:
        lines.append(cur)
    return "\n".join(lines[:3])


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
# Circles are reserved for *labeled entities*: exchanges, mixers,
# bridges, the victim, perpetrators, DeFi protocols. Each one reads as
# a solid badge — the same visual language as TRM Forensics' entity
# graph (where labeled entities are circles with logos inside and
# unlabeled wallets are small rectangles).
#
# Rounded rectangles are used for unlabeled wallet hops — they sit
# quietly in the middle and let the entity circles lead the read.
#
# Note: graphviz's HTML-table labels render inside ``shape=plaintext``
# only. Circle-shaped nodes therefore use a plain (non-HTML) label
# string with newline separators; we lose the colored letter-mark
# badge for circle nodes but gain the silhouette. The wordmark /
# identity stays legible because the label is just identity + short
# address inside the circle.
_ENTITY_CATEGORIES = {
    "victim",
    "exchange_deposit",
    "exchange_hot_wallet",
    "mixer",
    "bridge",
    "defi_protocol",
    "perpetrator",
    "staking",
    "freezable_holding",
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

    is_entity = n.category in _ENTITY_CATEGORIES

    if is_entity:
        # Circle-silhouette node, plain-text label (HTML labels aren't
        # supported on circle shapes in graphviz).
        identity = n.identity or n.category.replace("_", " ").title()
        # Long identities ("Sky Protocol (formerly MakerDAO)") would
        # overflow a fixed-size circle. Wrap softly on word boundaries
        # at ~16 chars so the label sits centered without breaking the
        # silhouette.
        wrapped = _soft_wrap(identity, width=16)
        label = f"{wrapped}\n{short}"
        attrs = {
            "label": label,
            "shape": "circle",
            "style": "filled",
            "fixedsize": "true",
            "width": "1.65",         # bigger entity circles — more legible
            "height": "1.65",
            "fillcolor": fill,
            "color": stroke,
            "fontcolor": text_color,
            "fontsize": "10",        # bumped from 9 — easier read at print res
            "penwidth": "3.0",       # thicker chain-coded border (was 2.4)
            "margin": "0.10,0.10",
            **_url_attrs(url, identity, short),
        }
        # Victim node gets a double-ring (peripheries=2) as the visual
        # anchor — the eye returns to it as the origin of the entire
        # trace. TRM Forensics uses the same convention for the seed.
        if n.category == "victim":
            attrs["peripheries"] = "2"
        return attrs

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


# ----- SVG polish (post-processing Graphviz output) ----- #


_FILTER_DEFS = """  <defs>
    <!-- Soft drop shadow for elevation on entity circles. Subtle —
         we're going for "premium product asset", not "Web 2.0 button". -->
    <filter id="elev" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur in="SourceAlpha" stdDeviation="2.4"/>
      <feOffset dx="0" dy="1.5" result="offsetblur"/>
      <feComponentTransfer>
        <feFuncA type="linear" slope="0.28"/>
      </feComponentTransfer>
      <feMerge>
        <feMergeNode/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
"""


def _polish_svg(path: Path) -> None:
    """Hand-tune the Graphviz SVG output for an elite finish.

    Three injections, all best-effort and idempotent:

      1. ``<defs>`` block with a soft drop-shadow filter ("elev") that
         renders entity circles as raised badges. WeasyPrint honors
         SVG filters on PDF render, so the elevation survives print.

      2. ``filter="url(#elev)"`` applied to every ``<ellipse>`` (these
         are the entity circles — Graphviz emits ``<ellipse>`` for
         shape=circle).

      3. White rounded-rect "pills" added behind every edge text
         label so dollar values read cleanly when they cross another
         edge in the layout. We can't paint these in Graphviz because
         it doesn't support per-label backgrounds — we wrap each
         ``<text>`` element under a ``<g class="edge">`` with a
         pill-shaped rect sized to the text bbox.

    Reads the SVG as text and rewrites in place. Operations are
    regex-based rather than XML-DOM-parsed — keeps zero dependencies
    on lxml, and Graphviz's SVG output is well-structured enough that
    string-level matching is reliable.
    """
    import re

    raw = path.read_text(encoding="utf-8", errors="replace")

    # 1. Inject the <defs> filter right after the <svg ...> open tag,
    #    but only if we haven't already injected it (idempotent).
    if 'id="elev"' not in raw:
        m = re.search(r"(<svg\b[^>]*?>)", raw)
        if m:
            raw = raw[:m.end()] + "\n" + _FILTER_DEFS + raw[m.end():]

    # 2. Apply filter="url(#elev)" to every <ellipse> — those are the
    #    entity circles (shape=circle in Graphviz → <ellipse> in SVG).
    #    We add the attribute only if not already present, so a
    #    re-polish on the same SVG doesn't double-decorate.
    def _add_filter(match: "re.Match[str]") -> str:
        tag = match.group(0)
        if "filter=" in tag:
            return tag
        # Insert before the closing > (preserves self-closing or not).
        if tag.endswith("/>"):
            return tag[:-2] + ' filter="url(#elev)"/>'
        return tag[:-1] + ' filter="url(#elev)">'
    raw = re.sub(r"<ellipse\b[^>]*/?>", _add_filter, raw)

    # 3. Edge-label pills. Find every <text> inside a <g class="edge">
    #    and prepend a matching <rect>. Bbox isn't available without
    #    rendering, so we approximate from text length × font size at
    #    a known average glyph width. This is good enough for pill
    #    sizing — text stays inside the pill on every label we've
    #    seen across smoke tests.
    raw = _wrap_edge_labels_in_pills(raw)

    # 4. Letter-mark badges. For every entity circle whose
    #    xlink:title matches a known entity (Binance/Coinbase/
    #    Tether/Circle/etc.), inject a small colored circle in the
    #    upper-right of the entity badge with the entity's letter
    #    mark in white/black depending on luminance. Mirrors TRM
    #    Forensics's logo treatment.
    raw = _inject_letter_mark_badges(raw)

    path.write_text(raw, encoding="utf-8")


def _inject_letter_mark_badges(svg: str) -> str:
    """Inject a small letter-mark circle in the upper-right of every
    entity circle whose identity matches a known entry in
    ``_ENTITY_BADGES`` (Binance, Coinbase, Tether, Circle, Tornado,
    Stargate, etc.).

    The badge looks like:

        ┌─────────────┐
        │     ◯ B     │  ← small circle with letter, top-right
        │   Binance   │
        │   0x1a..b2  │
        └─────────────┘

    Each entity ``<a><ellipse>...</a>`` group in the Graphviz SVG
    carries an ``xlink:title`` like
    ``"Binance Hot Wallet — open on chain explorer"``. We match the
    title against ``_ENTITY_BADGES`` keys (case-insensitive
    substring) and, on a hit, emit a small badge group right after
    the ``<ellipse>`` so it renders on top.

    Position math:

      * Badge radius = 10pt (fixed).
      * Center placed at (ellipse.cx + ellipse.rx * 0.55,
                          ellipse.cy - ellipse.ry * 0.55).
        That puts the badge in the entity circle's upper-right
        quadrant, overlapping the entity circle's outline so it
        reads as "attached to" rather than "floating beside".

    No-op when no match. Best-effort: parsing failures on a single
    entity leave that entity un-badged but don't break the rest of
    the diagram.
    """
    import re

    # Match each <a ...><ellipse ...>/></a> group inside a node g.
    #
    # The Graphviz SVG layout for an entity node is:
    #   <g id="node_N" class="node">
    #     <title>...</title>
    #     <g id="a_node_N"><a xlink:href="..." xlink:title="EntityName — ...">
    #       <ellipse fill=".." stroke=".." cx=".." cy=".." rx=".." ry=".." ... />
    #       <text ...>EntityName</text>
    #       <text ...>0x1a..b2</text>
    #     </a></g>
    #   </g>
    #
    # We pluck the title and ellipse coords from each anchor block
    # and emit the badge SVG between the ellipse and its accompanying
    # text labels.
    anchor_pattern = re.compile(
        r'(<a\s+xlink:href="[^"]*"\s+xlink:title="([^"]+)"\s+target="_blank">)'
        r'(\s*<ellipse\b[^/]*?\bcx="([\-\d.]+)"[^/]*?\bcy="([\-\d.]+)"'
        r'[^/]*?\brx="([\-\d.]+)"[^/]*?\bry="([\-\d.]+)"[^/]*/>)',
        re.DOTALL,
    )

    def _maybe_inject(match: "re.Match[str]") -> str:
        anchor_open = match.group(1)
        title = match.group(2)
        ellipse_tag = match.group(3)
        cx = float(match.group(4))
        cy = float(match.group(5))
        rx = float(match.group(6))
        ry = float(match.group(7))

        # Skip non-entity nodes — wallets, intermediate hops. These
        # don't carry a known entity name in their title so the
        # badge lookup will miss anyway, but short-circuiting avoids
        # the regex work.
        # Title format: "<identity> — open on chain explorer". We
        # strip the suffix and run the existing _entity_badge match.
        identity = title.split("—")[0].strip()
        badge = _entity_badge(identity)
        if not badge:
            # Also try the case where the entity name has the
            # category in it (e.g. "Tornado Cash" → catches "tornado").
            badge = _entity_badge(title)
        if not badge:
            return anchor_open + ellipse_tag

        letter, fill, text_color = badge
        badge_r = 10.0
        badge_cx = cx + rx * 0.55
        badge_cy = cy - ry * 0.55
        # Drop a subtle white halo behind the badge so it reads
        # cleanly on top of any chain-stroke border color.
        halo_r = badge_r + 1.5
        badge_svg = (
            f'<circle cx="{badge_cx:.1f}" cy="{badge_cy:.1f}" r="{halo_r:.1f}" '
            f'fill="#FAFAF7" stroke="none"/>'
            f'<circle cx="{badge_cx:.1f}" cy="{badge_cy:.1f}" r="{badge_r:.1f}" '
            f'fill="{fill}" stroke="#FFFFFF" stroke-width="1.2"/>'
            f'<text x="{badge_cx:.1f}" y="{badge_cy + 3.4:.1f}" '
            f'text-anchor="middle" font-family="{_FONT_FACE}" font-size="11" '
            f'font-weight="700" fill="{text_color}">{_escape(letter)}</text>'
        )
        return anchor_open + ellipse_tag + badge_svg

    return anchor_pattern.sub(_maybe_inject, svg)


def _wrap_edge_labels_in_pills(svg: str) -> str:
    """Insert a rounded-rect background behind every edge-text label.

    Graphviz emits each edge as a ``<g class="edge">`` wrapper
    containing path(s) + a ``<text>`` for the label. We find each
    ``<text>`` inside an edge group and prepend a ``<rect>`` whose
    bounds approximate the text bounding box.

    Approximation: width = chars * fontsize * 0.55, height = fontsize
    * 1.5. Errs slightly wide so labels never clip the pill on the
    right edge. Pill background is the page color (_EDGE_LABEL_BG)
    so it reads as the edge being interrupted, not as a chip.
    """
    import re

    out: list[str] = []
    pos = 0
    edge_pattern = re.compile(
        r'<g\s+id="[^"]*"\s+class="edge">.*?</g>', re.DOTALL
    )
    # Graphviz writes <text xml:space="preserve" text-anchor="..." x=".." y=".."
    # font-family=".." font-size=".." fill="..">...</text>. Match liberally
    # on attribute order — only x/y/font-size are required for the pill.
    text_pattern = re.compile(
        r'<text\b[^>]*?\bx="([\-\d.]+)"[^>]*?\by="([\-\d.]+)"'
        r'[^>]*?\bfont-size="([\d.]+)"[^>]*>'
        r'([^<]+)</text>',
        re.DOTALL,
    )
    for em in edge_pattern.finditer(svg):
        out.append(svg[pos:em.start()])
        block = em.group(0)
        # For each <text> inside this edge block, prepend a pill.
        def _pill(match: "re.Match[str]") -> str:
            x = float(match.group(1))
            y = float(match.group(2))
            fs = float(match.group(3))
            content = match.group(4)
            # Approximate text bbox.
            glyph_w = fs * 0.55
            w = max(len(content) * glyph_w, fs * 2.0) + 6.0
            h = fs * 1.45
            rx = x - w / 2.0
            ry = y - h * 0.78  # text baseline → rect top
            rect = (
                f'<rect x="{rx:.1f}" y="{ry:.1f}" '
                f'width="{w:.1f}" height="{h:.1f}" rx="2.5" ry="2.5" '
                f'fill="{_EDGE_LABEL_BG}" stroke="none" opacity="0.92"/>'
            )
            return rect + match.group(0)
        new_block = text_pattern.sub(_pill, block)
        out.append(new_block)
        pos = em.end()
    out.append(svg[pos:])
    return "".join(out)


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
        # ``errors="replace"`` so a rogue byte from a locale-misconfigured
        # Graphviz binary (or a label string we didn't expect) becomes
        # U+FFFD instead of failing the whole deliverables stage. Worst
        # case the diagram has one mangled glyph; the letter still ships.
        raw = path.read_text(encoding="utf-8", errors="replace")
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
