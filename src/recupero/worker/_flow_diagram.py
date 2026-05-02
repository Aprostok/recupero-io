"""Premium-styled fund-flow SVG diagram for freeze briefs / LE handoffs.

Aim is to look closer to TRM Forensics / Chainalysis Reactor than to a
default Graphviz diagram. We use Graphviz's `dot` engine for layout —
it's well-developed and battle-tested — and then heavily override the
default styling with HTML node labels, modern fonts, and a clean
palette so the output reads as a premium product asset, not an
engineering tool dump.

Output is inline-SVG so it embeds in HTML deliverables (and survives
PDF rendering downstream).

Design choices:
  * Left-to-right layout (rankdir=LR) because hop progression reads
    naturally as a timeline.
  * Nodes are rounded rectangles, never plain circles — easier to
    fit a 0x… address + identity label readably.
  * Color by entity category (see _NODE_PALETTE):
        victim          soft blue
        exchange        green     ← labeled CEX deposit / hot wallet
        mixer           red       ← Tornado Cash etc; trace stops here
        bridge          orange    ← cross-chain hop; trace stops here
        defi/contract   purple    ← unlabeled contract
        wallet          neutral grey
        perpetrator     dark red  ← if explicitly labeled as such
  * Edge labels show USD value + token symbol; line thickness scales
    log10(USD) so a $1M edge is visibly thicker than a $1k edge.
  * Inter font (or DejaVu Sans fallback inside Docker) for clean
    typography. Graphviz default fonts are bitmap-y and look cheap.

If `dot` isn't on the PATH (e.g., a dev box without the binary), the
render call falls back to a small SVG placeholder so the rest of the
deliverable pipeline still completes — the operator just sees a
"flow diagram unavailable" notice instead of a hard failure.
"""

from __future__ import annotations

import logging
import math
import shutil
from decimal import Decimal
from pathlib import Path

from recupero.models import Case, LabelCategory, Transfer

log = logging.getLogger(__name__)


# ----- Visual design system ----- #

# Font stack with no embedded quotes — multi-word font names like
# "DejaVu Sans" unfortunately can't be inside Graphviz HTML labels
# without breaking the XML parser. Stick to single-word names; the
# browser/PDF renderer will pick whichever is available locally.
_FONT_FACE = "Inter,Helvetica,Arial,sans-serif"
_MONO_FACE = "Menlo,Consolas,monospace"

_GRAPH_BG = "#FAFAFA"
_TITLE_COLOR = "#0F172A"
_SUBTITLE_COLOR = "#64748B"

# Per-category fill / border / text colors. Keys map LabelCategory →
# (fill, border, label_color). Unknown categories fall through to the
# neutral wallet style.
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
    "wallet":               ("#F1F5F9", "#94A3B8", "#1E293B"),
}


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

    g = Digraph("flow", format="svg", strict=True)

    # Top-of-graph title block + global attrs.
    g.attr(
        rankdir="LR",
        bgcolor=_GRAPH_BG,
        labelloc="t",
        label=_html_title_label(case, title),
        fontname=_FONT_FACE,
        fontsize="14",
        nodesep="0.35",
        ranksep="0.65",
        pad="0.4",
    )
    g.attr(
        "node",
        shape="box",
        style="rounded,filled",
        fontname=_FONT_FACE,
        fontsize="11",
        margin="0.18,0.10",
        penwidth="1.5",
    )
    g.attr(
        "edge",
        fontname=_FONT_FACE,
        fontsize="10",
        color="#475569",
        fontcolor="#475569",
        arrowsize="0.7",
        penwidth="1.0",
    )

    # The seed (victim) node is added explicitly so it's always present
    # even if the case has no transfers from it directly.
    seed_id = _node_id(case.seed_address)
    g.node(seed_id, **_node_style(
        address=case.seed_address,
        identity="Victim wallet",
        category="victim",
    ))

    # Add nodes for each unique counterparty across all transfers.
    seen: set[str] = {seed_id}
    for t in case.transfers:
        from_id = _node_id(t.from_address)
        to_id = _node_id(t.to_address)
        if from_id not in seen:
            g.node(from_id, **_node_style(
                address=t.from_address,
                identity=None,  # intermediate from-address; usually internal
                category="wallet",
            ))
            seen.add(from_id)
        if to_id not in seen:
            cat_name, identity = _classify_counterparty(t)
            g.node(to_id, **_node_style(
                address=t.to_address,
                identity=identity,
                category=cat_name,
            ))
            seen.add(to_id)

    # Add edges with USD labels + thickness scaled by log USD.
    for t in case.transfers:
        from_id = _node_id(t.from_address)
        to_id = _node_id(t.to_address)
        edge_label = _edge_label(t)
        penwidth = _edge_penwidth(t.usd_value_at_tx)
        g.edge(
            from_id, to_id,
            label=edge_label,
            penwidth=f"{penwidth:.2f}",
        )

    output_svg.parent.mkdir(parents=True, exist_ok=True)
    # graphviz writes <stem>.svg — pass the stem (no extension) so it
    # doesn't double up to flow_id.svg.svg.
    stem = output_svg.with_suffix("")
    try:
        g.render(filename=str(stem), cleanup=True)
    except Exception as e:  # noqa: BLE001
        log.warning("flow diagram render failed: %s", e)
        _write_placeholder_svg(output_svg, "Flow diagram render failed")
        return None

    log.info("rendered flow diagram → %s", output_svg)
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


def _node_style(
    *,
    address: str,
    identity: str | None,
    category: str,
) -> dict[str, str]:
    """Build a Graphviz node attr dict using HTML-table labels for richer
    typography than plain string labels allow."""
    fill, border, text_color = _NODE_PALETTE.get(category, _NODE_PALETTE["wallet"])
    short = _short_addr(address)

    # Two-line HTML label: identity on top (or empty), short address below.
    # Address always rendered in monospace; identity in the body font.
    if identity:
        label = (
            f'<<table border="0" cellspacing="0" cellpadding="2">'
            f'<tr><td><b>{_escape(identity)}</b></td></tr>'
            f'<tr><td><font face="{_MONO_FACE}" '
            f'point-size="9" color="{text_color}">{_escape(short)}</font></td></tr>'
            f'</table>>'
        )
    else:
        label = (
            f'<<font face="{_MONO_FACE}" '
            f'point-size="10">{_escape(short)}</font>>'
        )

    return {
        "label": label,
        "fillcolor": fill,
        "color": border,
        "fontcolor": text_color,
    }


def _edge_label(t: Transfer) -> str:
    """USD-and-symbol formatted edge label, e.g. '$12,300 USDC'."""
    usd = t.usd_value_at_tx
    sym = t.token.symbol or "?"
    if usd is not None and usd > 0:
        usd_str = f"${usd:,.0f}" if usd >= 1 else f"${usd:.2f}"
        return f"{usd_str} {sym}"
    # Fall back to token amount when USD pricing was unavailable.
    return f"{_fmt_amount(t.amount_decimal)} {sym}"


def _fmt_amount(d: Decimal | None) -> str:
    if d is None:
        return "?"
    if d >= 1_000_000:
        return f"{d/1_000_000:.2f}M"
    if d >= 1_000:
        return f"{d/1_000:.2f}K"
    return f"{d:.4f}".rstrip("0").rstrip(".")


def _edge_penwidth(usd: Decimal | None) -> float:
    """Scale edge thickness by log10(USD). $0–$100 = 0.8pt, $1k = 1.5pt,
    $10k = 2.2pt, $100k = 2.9pt, $1M+ = 3.6pt."""
    if usd is None or usd <= 0:
        return 0.8
    return max(0.8, 0.8 + 0.7 * math.log10(float(usd) + 1))


def _html_title_label(case: Case, title: str | None) -> str:
    """The graph-level title block (HTML-style label allowed by Graphviz
    when the value is wrapped in <...>)."""
    primary = title or "Stolen Funds — Trace"
    sub = (
        f"Case {_escape(case.case_id)} • "
        f"{len(case.transfers)} transfer(s) • "
        f"{case.chain.value}"
    )
    return (
        f'<<font face="{_FONT_FACE}" point-size="16" color="{_TITLE_COLOR}">'
        f'<b>{_escape(primary)}</b></font><br/>'
        f'<font face="{_FONT_FACE}" point-size="10" color="{_SUBTITLE_COLOR}">'
        f'{_escape(sub)}</font>>'
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
