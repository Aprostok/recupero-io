"""Interactive fund-flow graph UI (v0.13.6).

Renders the existing flow-graph node/edge data (produced by
worker/_flow_diagram._aggregate) as a single self-contained HTML
file with embedded D3.js, providing pan/zoom/click-to-explore on the
graph. No frontend toolchain — just a static HTML file the operator
opens in any browser.

What this gives Recupero
------------------------

TRM Labs' Reactor and Chainalysis Investigator both have
heavy interactive graph UIs as their flagship customer-facing
asset. The Triage Report's static SVG is fine for at-a-glance
reading, but an investigator who wants to click on a node, see its
balance + label, then click an outgoing edge to see the tx-hash
list, needs interactivity.

This v0.13.6 output ships that capability as a single HTML file —
not a full SPA, not a server, not a frontend build. Just a static
file the operator can email, attach to a brief, or load locally.
The D3.js library is pulled from a CDN (jsDelivr) so the file itself
is ~50KB; standalone-offline mode is possible by inlining D3 as a
follow-on if needed.

Architecture
------------

  1. ``build_graph_data(case)`` — pure function. Walks the case via
     the same ``_aggregate`` pass the Graphviz renderer uses, then
     emits a JSON-serializable dict: ``{nodes: [...], edges: [...]}``
     with everything the frontend needs (addresses, labels, USD
     totals, chain, transfer counts, explorer URLs).

  2. ``render_graph_html(graph_data, output_path, title)`` —
     packages the graph data into a Jinja2-rendered HTML template
     containing the D3 visualization code. Force-directed layout
     with collision detection, draggable nodes, click-to-highlight
     incident paths, search-by-address box.

  3. ``recupero graph-ui CASE_ID`` — CLI command that reads
     case.json and writes graph_ui.html to the case dir.

The HTML is intentionally minimal — no analytics, no telemetry,
nothing that calls out to the network besides the D3 CDN. Operators
can audit the file before sharing it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

if TYPE_CHECKING:  # pragma: no cover
    from recupero.models import Case

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


# Chain → display color (matches the Graphviz palette so the two
# renderings are visually consistent).
_CHAIN_COLOR: dict[str, str] = {
    "ethereum": "#5B6CFF",
    "arbitrum": "#1B4F8C",
    "base": "#0052FF",
    "bsc": "#F0B90B",
    "polygon": "#8247E5",
    "solana": "#9945FF",
    "tron": "#FF060A",
    "bitcoin": "#F7931A",
}


@dataclass
class GraphNode:
    """One node in the interactive graph. JSON-serializable."""
    id: str                # address (used as D3 node id)
    label: str             # display label
    short: str             # short-form address for hover tooltip
    chain: str
    chain_color: str
    category: str          # 'wallet' / 'exchange' / 'mixer' / 'bridge' / 'victim'
    identity: str | None   # human-readable label name if available
    inbound_usd: str       # pre-formatted "$..." for tooltip
    outbound_usd: str
    is_victim: bool
    issuer: str | None
    explorer_url: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "short": self.short,
            "chain": self.chain,
            "chainColor": self.chain_color,
            "category": self.category,
            "identity": self.identity,
            "inboundUsd": self.inbound_usd,
            "outboundUsd": self.outbound_usd,
            "isVictim": self.is_victim,
            "issuer": self.issuer,
            "explorerUrl": self.explorer_url,
        }


@dataclass
class GraphEdge:
    """One aggregated edge. JSON-serializable."""
    source: str           # source address
    target: str           # target address
    total_usd: str        # formatted USD
    total_usd_numeric: float  # for D3 line-thickness scaling
    transfer_count: int
    dominant_symbol: str | None
    first_time: str | None
    last_time: str | None
    is_cross_chain: bool  # True if source/target are on different chains

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "totalUsd": self.total_usd,
            "totalUsdNumeric": self.total_usd_numeric,
            "transferCount": self.transfer_count,
            "dominantSymbol": self.dominant_symbol,
            "firstTime": self.first_time,
            "lastTime": self.last_time,
            "isCrossChain": self.is_cross_chain,
        }


def _short_addr(addr: str) -> str:
    if not addr:
        return ""
    if len(addr) <= 12:
        return addr
    return f"{addr[:6]}…{addr[-4:]}"


def _explorer_url(chain: str, address: str) -> str:
    """Best-effort chain → explorer URL mapping."""
    if not address:
        return ""
    chain_lower = (chain or "").lower()
    if chain_lower == "ethereum":
        return f"https://etherscan.io/address/{address}"
    if chain_lower == "arbitrum":
        return f"https://arbiscan.io/address/{address}"
    if chain_lower == "base":
        return f"https://basescan.org/address/{address}"
    if chain_lower == "bsc":
        return f"https://bscscan.com/address/{address}"
    if chain_lower == "polygon":
        return f"https://polygonscan.com/address/{address}"
    if chain_lower == "solana":
        return f"https://solscan.io/account/{address}"
    if chain_lower == "tron":
        return f"https://tronscan.org/#/address/{address}"
    if chain_lower == "bitcoin":
        return f"https://mempool.space/address/{address}"
    return ""


def build_graph_data(case: Case) -> dict[str, Any]:
    """Walk the case via the same aggregation pass the Graphviz
    renderer uses, then return a JSON-serializable graph dict.

    Returns:
      {
        "nodes": [GraphNode.to_dict(), ...],
        "edges": [GraphEdge.to_dict(), ...],
        "meta": {
          "case_id": str,
          "seed_address": str,
          "node_count": int,
          "edge_count": int,
          "total_usd_traced": str,
        }
      }
    """
    # Reuse the existing aggregation logic — the Graphviz renderer
    # and the interactive UI share the same node/edge model so the
    # two stay visually + semantically consistent.
    from recupero.worker._flow_diagram import _aggregate
    nodes_map, edges_list = _aggregate(case)

    seed_lower = (case.seed_address or "").lower()
    json_nodes: list[dict[str, Any]] = []
    for addr, attrs in nodes_map.items():
        chain = attrs.chain or "ethereum"
        is_victim = addr.lower() == seed_lower
        identity = attrs.identity
        category = attrs.category or "wallet"
        if is_victim:
            category = "victim"
            identity = "Victim wallet" if not identity else identity
        label = (
            identity if identity and identity not in ("(unlabeled)", "unknown")
            else _short_addr(addr)
        )
        node = GraphNode(
            id=addr,
            label=label,
            short=_short_addr(addr),
            chain=chain,
            chain_color=_CHAIN_COLOR.get(chain.lower(), "#9E9E9E"),
            category=category,
            identity=identity,
            inbound_usd=f"${attrs.inbound_usd:,.2f}",
            outbound_usd=f"${attrs.outbound_usd:,.2f}",
            is_victim=is_victim,
            issuer=attrs.issuer,
            explorer_url=_explorer_url(chain, addr),
        )
        json_nodes.append(node.to_dict())

    json_edges: list[dict[str, Any]] = []
    total_usd = Decimal(0)
    for e in edges_list:
        usd_num = float(e.total_usd or 0)
        total_usd += e.total_usd or Decimal(0)
        edge = GraphEdge(
            source=e.src,
            target=e.dst,
            total_usd=f"${e.total_usd:,.2f}",
            total_usd_numeric=usd_num,
            transfer_count=e.transfer_count,
            dominant_symbol=e.dominant_symbol,
            first_time=(
                e.first_time.isoformat().replace("+00:00", "Z")
                if e.first_time else None
            ),
            last_time=(
                e.last_time.isoformat().replace("+00:00", "Z")
                if e.last_time else None
            ),
            is_cross_chain=(e.src_chain != e.dst_chain),
        )
        json_edges.append(edge.to_dict())

    return {
        "nodes": json_nodes,
        "edges": json_edges,
        "meta": {
            "case_id": case.case_id,
            "seed_address": case.seed_address,
            "node_count": len(json_nodes),
            "edge_count": len(json_edges),
            "total_usd_traced": f"${total_usd:,.2f}",
            "chain": case.chain.value,
        },
    }


def render_graph_html(
    graph_data: dict[str, Any],
    output_path: Path,
    *,
    title: str | None = None,
) -> Path:
    """Render the interactive graph as a single self-contained HTML file.

    The HTML pulls D3.js from jsDelivr CDN. The graph data is embedded
    inline in the file as a JSON blob — no external API calls, no
    network requests beyond the D3 library load.

    Returns the path written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("interactive_graph.html.j2")
    html = template.render(
        title=title or f"Fund-flow graph — {graph_data['meta']['case_id']}",
        graph_data_json=json.dumps(graph_data, separators=(",", ":")),
        meta=graph_data["meta"],
    )
    output_path.write_text(html, encoding="utf-8")
    log.info(
        "rendered interactive graph: %s (%d nodes, %d edges, %d bytes)",
        output_path,
        graph_data["meta"]["node_count"],
        graph_data["meta"]["edge_count"],
        output_path.stat().st_size,
    )
    return output_path


def render_case_graph(case: Case, output_dir: Path, title: str | None = None) -> Path:
    """One-call convenience: build graph data from case, render HTML.

    Returns the output path (cases/<id>/graph_ui.html).
    """
    graph_data = build_graph_data(case)
    output_path = output_dir / "graph_ui.html"
    return render_graph_html(graph_data, output_path, title=title)


__all__ = (
    "GraphNode",
    "GraphEdge",
    "build_graph_data",
    "render_graph_html",
    "render_case_graph",
)
