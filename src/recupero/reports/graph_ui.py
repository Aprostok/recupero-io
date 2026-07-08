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

from recupero._common import atomic_write_text as _atomic_write_text
from recupero._common import short_addr as _short_addr

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


# v0.38.0 (#6, Reactor-grade): risk_category → (risk level, node fill color).
# The level is the coarse band the UI legend + "color by risk" toggle use; the
# color is a severity ramp (red = sanctioned → amber = elevated). Keys are the
# risk_category values from risk_scoring.load_high_risk_db.
_RISK_BAND: dict[str, tuple[str, str]] = {
    "ofac_sanctioned":  ("sanctioned", "#C62828"),  # red
    "mixer_sanctioned": ("sanctioned", "#C62828"),
    "intl_sanctioned":  ("sanctioned", "#D84315"),  # deep orange-red
    "ransomware":       ("high",       "#E64A19"),  # orange-red
    "darknet_market":   ("high",       "#EF6C00"),  # orange
    "scam_drainer":     ("high",       "#F57C00"),  # amber-orange
    # internal_blacklist is a severity-3 "high" category (see
    # labels/internal_blacklist.py → screener verdict "high"). Without this key
    # it fell through to the "elevated"/amber default, under-colouring a
    # confirmed known-bad actor to the same band as a non-sanctioned mixer.
    "internal_blacklist": ("high",     "#E65100"),  # deep orange (high band)
    "mixer_high_risk":  ("elevated",   "#F9A825"),  # amber
}
# Fallback for an unknown-but-present risk_category (still flag it as risky).
_RISK_BAND_DEFAULT = ("elevated", "#F9A825")


def _risk_for_address(
    address: str, high_risk_db: dict[str, Any] | None,
) -> tuple[str, str | None, str | None, str | None]:
    """Resolve (risk_level, risk_category, risk_name, risk_color) for an
    address. Returns ('none', None, None, None) when the address is not a
    known high-risk address or the db is unavailable."""
    if not high_risk_db or not address:
        return "none", None, None, None
    from recupero._common import canonical_address_key as _ck
    entry = high_risk_db.get(_ck(address))
    if entry is None:
        return "none", None, None, None
    cat = (getattr(entry, "risk_category", "") or "").lower()
    level, color = _RISK_BAND.get(cat, _RISK_BAND_DEFAULT)
    return level, cat or None, getattr(entry, "name", None), color


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
    # v0.35.8 (F1): numeric USD fields for client-side filtering. Pre-F1 the
    # template re-parsed the formatted "$1,234.00" strings with a regex to get
    # a number for the min-USD filter + node radius; carrying clean numerics
    # (already NaN/Inf-guarded by _safe_usd_float) removes that fragile parse
    # and lets the filter threshold compare against an honest value.
    inbound_usd_numeric: float = 0.0
    outbound_usd_numeric: float = 0.0
    # v0.38.0 (#6, Reactor-grade): authoritative high-risk overlay. risk_level
    # is the legend band ('sanctioned'/'high'/'elevated'/'none'); risk_color is
    # the severity-ramp fill the "color by risk" toggle uses.
    risk_level: str = "none"
    risk_category: str | None = None
    risk_name: str | None = None
    risk_color: str | None = None

    def to_dict(self) -> dict[str, Any]:
        flow = self.inbound_usd_numeric + self.outbound_usd_numeric
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
            "inboundUsdNumeric": self.inbound_usd_numeric,
            "outboundUsdNumeric": self.outbound_usd_numeric,
            "flowUsdNumeric": flow,
            "isVictim": self.is_victim,
            "issuer": self.issuer,
            "explorerUrl": self.explorer_url,
            "risk": self.risk_level,
            "riskCategory": self.risk_category,
            "riskName": self.risk_name,
            "riskColor": self.risk_color,
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


def _safe_usd_decimal(v: Any) -> Decimal:
    """Coerce a (maybe-Decimal) USD value to a finite, non-negative Decimal.

    RIGOR-Jacob Z11: ``node.inbound_usd`` / ``edge.total_usd`` may
    arrive as ``Decimal('NaN')`` / ``Decimal('Infinity')`` (price-
    oracle glitch). The pre-fix code formatted these as the literal
    text ``$NaN`` / ``$Infinity`` in node tooltips + the graph header,
    AND piped float('nan') into ``totalUsdNumeric`` which breaks the
    browser's strict JSON.parse on the embedded data blob.
    """
    if v is None:
        return Decimal(0)
    if isinstance(v, Decimal):
        if not v.is_finite():
            return Decimal(0)
        if v < 0:
            return Decimal(0)
        return v
    try:
        d = Decimal(str(v))
    except Exception:  # noqa: BLE001
        return Decimal(0)
    if not d.is_finite():
        return Decimal(0)
    if d < 0:
        return Decimal(0)
    return d


def _safe_usd_float(v: Any) -> float:
    """Float variant of ``_safe_usd_decimal`` for D3 line-thickness
    scaling. NaN / Inf collapse to 0.0 so ``json.dumps(allow_nan=False)``
    accepts the result."""
    d = _safe_usd_decimal(v)
    try:
        return float(d)
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _explorer_url(chain: str, address: str) -> str:
    """Best-effort chain → explorer URL mapping. Sources the prefix
    table from `recupero._common` so adding a chain happens in one
    place."""
    if not address:
        return ""
    from recupero._common import ADDRESS_EXPLORER_BY_CHAIN
    prefix = ADDRESS_EXPLORER_BY_CHAIN.get((chain or "").lower())
    return f"{prefix}{address}" if prefix else ""


def build_graph_data(
    case: Case, *, high_risk_db: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Walk the case via the same aggregation pass the Graphviz
    renderer uses, then return a JSON-serializable graph dict.

    v0.38.0 (#6): each node carries an authoritative high-risk overlay
    (``risk``/``riskCategory``/``riskName``/``riskColor``) resolved from
    ``high_risk_db`` (``risk_scoring.load_high_risk_db``). When not supplied,
    it is loaded lazily best-effort — a load failure degrades to no risk
    overlay (every node ``risk='none'``) rather than failing the render.

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

    # Best-effort high-risk db load for the node risk overlay. A failure here
    # (seed files unreadable, etc.) must not fail the graph — degrade to no
    # overlay (every node risk='none').
    if high_risk_db is None:
        try:
            from recupero.trace.risk_scoring import load_high_risk_db
            high_risk_db = load_high_risk_db()
        except Exception as exc:  # noqa: BLE001
            log.debug("graph_ui: high-risk db load failed (%s); no risk overlay", exc)
            high_risk_db = {}

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
        # Z11: sanitize NaN / Infinity USD values so the operator-
        # shared HTML never renders "$NaN" / "$Infinity" in a tooltip
        # AND the embedded JSON blob is JSON.parse-safe.
        safe_inbound = _safe_usd_decimal(attrs.inbound_usd)
        safe_outbound = _safe_usd_decimal(attrs.outbound_usd)
        risk_level, risk_cat, risk_name, risk_color = _risk_for_address(
            addr, high_risk_db,
        )
        node = GraphNode(
            id=addr,
            label=label,
            short=_short_addr(addr),
            chain=chain,
            chain_color=_CHAIN_COLOR.get(chain.lower(), "#9E9E9E"),
            category=category,
            identity=identity,
            inbound_usd=f"${safe_inbound:,.2f}",
            outbound_usd=f"${safe_outbound:,.2f}",
            inbound_usd_numeric=_safe_usd_float(attrs.inbound_usd),
            outbound_usd_numeric=_safe_usd_float(attrs.outbound_usd),
            is_victim=is_victim,
            issuer=attrs.issuer,
            explorer_url=_explorer_url(chain, addr),
            risk_level=risk_level,
            risk_category=risk_cat,
            risk_name=risk_name,
            risk_color=risk_color,
        )
        json_nodes.append(node.to_dict())

    json_edges: list[dict[str, Any]] = []
    total_usd = Decimal(0)
    for e in edges_list:
        # Z11: sanitize NaN / Infinity edge totals (price-oracle glitch
        # propagated through aggregation). Without this:
        #   * tooltip renders ``$NaN`` (confidence hit)
        #   * totalUsdNumeric becomes float('nan') → JSON.parse on the
        #     embedded blob throws SyntaxError → graph never loads
        #   * the running ``total_usd`` Decimal poisons meta.total_usd_traced
        safe_edge_total = _safe_usd_decimal(e.total_usd)
        usd_num = _safe_usd_float(e.total_usd)
        total_usd += safe_edge_total
        edge = GraphEdge(
            source=e.src,
            target=e.dst,
            total_usd=f"${safe_edge_total:,.2f}",
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

    # v0.35.8 (F1): the distinct chains + categories present in this case so
    # the interactive UI can build its multi-chain + category filter controls
    # from data (no hardcoded chip list that drifts from the actual graph).
    # Sorted for deterministic output (test-stable + reproducible HTML).
    chains_present = sorted({str(n["chain"]) for n in json_nodes if n.get("chain")})
    categories_present = sorted(
        {str(n["category"]) for n in json_nodes if n.get("category")}
    )
    # v0.38.0 (#6): risk overlay rollup so the UI can build a risk legend +
    # "color by risk" toggle from data and badge the high-risk count.
    risk_nodes = [n for n in json_nodes if n.get("risk") and n["risk"] != "none"]
    risk_categories_present = sorted(
        {str(n["riskCategory"]) for n in risk_nodes if n.get("riskCategory")}
    )

    return {
        "nodes": json_nodes,
        "edges": json_edges,
        "meta": {
            "case_id": case.case_id,
            "seed_address": case.seed_address,
            "node_count": len(json_nodes),
            "edge_count": len(json_edges),
            "total_usd_traced": f"${_safe_usd_decimal(total_usd):,.2f}",
            "chain": case.chain.value,
            "chains": chains_present,
            "categories": categories_present,
            "risk_node_count": len(risk_nodes),
            "risk_categories": risk_categories_present,
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
    # XSS defense-in-depth filters.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    # v0.18.2 (round-11 sec-CRIT-001): defense-in-depth escape for
    # `</script>` substrings in node labels. The template now embeds
    # graph_data inside `<script type="application/json">` which
    # browsers don't execute, but escaping the dangerous sequence at
    # the data layer too means even a non-strict HTML parser can't be
    # tricked. Also escapes HTML comment sequences <!-- / --> which
    # can interact with old HTML4 quirks.
    template = env.get_template("interactive_graph.html.j2")
    # Z11: ``allow_nan=False`` makes json.dumps RAISE on NaN/Inf
    # rather than emit the JS-literal ``NaN`` / ``Infinity`` that
    # ``JSON.parse`` rejects with SyntaxError. The graph builder
    # already sanitizes per-node/edge values; this is defense-in-
    # depth in case a future caller threads a raw float in.
    try:
        safe_json = (
            json.dumps(graph_data, separators=(",", ":"), allow_nan=False)
            # W11-03 hardening: `<\!--` and `-\->` are NOT valid JSON
            # escapes (`\!`/`\-` are undefined in the JSON spec), so a
            # strict JSON.parse on the browser side would reject the
            # whole block — silently breaking the graph the moment any
            # label contained `<!--` or `-->`. Use Unicode escapes
            # (`<!--` / `-->`) instead. These are valid JSON
            # AND avoid producing the literal byte sequence the HTML
            # parser would special-case in legacy script-data states.
            # `<\/` is preserved because `\/` IS a valid JSON escape.
            .replace("</", "<\\/")
            .replace("<!--", "\\u003c!--")
            .replace("-->", "--\\u003e")
        )
    except ValueError:
        # Last-resort: walk the structure and replace every non-finite
        # float with 0 BEFORE re-serializing. The `default=` hook isn't
        # enough — json.dumps only consults it for types it doesn't
        # already know how to encode, and `float` is built-in, so a
        # nested `float("inf")` would slip past as the bare JS literal
        # `Infinity` (defeating the defense entirely).
        import math

        def _walk(o: Any) -> Any:
            if isinstance(o, float) and not math.isfinite(o):
                return 0
            if isinstance(o, dict):
                return {k: _walk(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [_walk(v) for v in o]
            return o

        scrubbed = _walk(graph_data)
        safe_json = (
            json.dumps(scrubbed, separators=(",", ":"), allow_nan=False)
            # W11-03 hardening: `<\!--` and `-\->` are NOT valid JSON
            # escapes (`\!`/`\-` are undefined in the JSON spec), so a
            # strict JSON.parse on the browser side would reject the
            # whole block — silently breaking the graph the moment any
            # label contained `<!--` or `-->`. Use Unicode escapes
            # (`<!--` / `-->`) instead. These are valid JSON
            # AND avoid producing the literal byte sequence the HTML
            # parser would special-case in legacy script-data states.
            # `<\/` is preserved because `\/` IS a valid JSON escape.
            .replace("</", "<\\/")
            .replace("<!--", "\\u003c!--")
            .replace("-->", "--\\u003e")
        )
    html = template.render(
        title=title or f"Fund-flow graph — {graph_data['meta']['case_id']}",
        graph_data_json=safe_json,
        meta=graph_data["meta"],
    )
    _atomic_write_text(output_path, html)
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
