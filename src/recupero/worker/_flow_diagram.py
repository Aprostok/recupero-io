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
# so each box in the diagram links to its own Etherscan/Solscan/etc. page.
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

    # Global graph attributes — premium styling.
    # splines=spline gives smooth curved edges (vs default ortho/line);
    # closer in feel to TRM Reactor's hand-drawn edge style.
    g.attr(
        rankdir="LR",
        bgcolor=_BG_COLOR,
        labelloc="t",
        labeljust="l",
        label=_html_title_label(case, title),
        fontname=_FONT_FACE,
        fontsize="14",
        nodesep="0.5",
        ranksep="0.85",
        pad="0.5",
        splines="spline",
        concentrate="true",
    )
    g.attr(
        "node",
        shape="box",
        style="rounded,filled",
        fontname=_FONT_FACE,
        fontsize="11",
        margin="0.22,0.14",
        penwidth="1.4",
    )
    g.attr(
        "edge",
        fontname=_FONT_FACE,
        fontsize="9",
        color="#94A3B8",
        fontcolor="#475569",
        arrowsize="0.7",
        arrowhead="vee",
        penwidth="1.1",
    )

    chain_str = case.chain.value

    # The seed (victim) node is added explicitly so it's always present
    # even if the case has no transfers from it directly.
    seed_id = _node_id(case.seed_address)
    g.node(seed_id, **_node_style(
        address=case.seed_address,
        identity="Victim wallet",
        category="victim",
        chain=chain_str,
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
                chain=chain_str,
            ))
            seen.add(from_id)
        if to_id not in seen:
            cat_name, identity = _classify_counterparty(t)
            g.node(to_id, **_node_style(
                address=t.to_address,
                identity=identity,
                category=cat_name,
                chain=chain_str,
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
    chain: str = "ethereum",
) -> dict[str, str]:
    """Build a Graphviz node attr dict using HTML-table labels for richer
    typography than plain string labels allow.

    For known entities, prepends a colored letter-mark badge (e.g. a
    yellow "B" for Binance) so the node reads at a glance the way it
    would in a Chainalysis Reactor / TRM Forensics graph.

    Every node also gets a clickable URL pointing at the appropriate
    chain explorer for ``address`` so operators can drill in directly
    from the rendered diagram.
    """
    fill, border, text_color = _NODE_PALETTE.get(category, _NODE_PALETTE["wallet"])
    short = _short_addr(address)
    badge = _entity_badge(identity)
    url = _explorer_url(chain, address)

    if identity and badge:
        letter, badge_fill, badge_text = badge
        # Two-row HTML label:
        #   row 1: [colored letter-mark badge] [identity text]
        #   row 2: [           short address (mono)         ]
        # Letting the badge cell self-size — fixedsize cells warn when
        # content overflows. The padding makes the badge visually square-ish
        # without forcing a brittle pixel size.
        label = (
            f'<<table border="0" cellspacing="0" cellpadding="0">'
            f'<tr>'
            f'<td bgcolor="{badge_fill}" cellpadding="6" valign="middle">'
            f'<font color="{badge_text}" face="{_FONT_FACE}" point-size="13">'
            f'<b>&nbsp;{_escape(letter)}&nbsp;</b></font></td>'
            f'<td cellpadding="6" valign="middle">'
            f'<font face="{_FONT_FACE}" point-size="11" color="{text_color}">'
            f'<b>{_escape(identity)}</b></font></td>'
            f'</tr>'
            f'<tr><td colspan="2" cellpadding="2"><font face="{_MONO_FACE}" '
            f'point-size="8" color="{text_color}">{_escape(short)}</font></td></tr>'
            f'</table>>'
        )
    elif identity:
        # Identity but no recognized badge — show identity + short address
        label = (
            f'<<table border="0" cellspacing="0" cellpadding="2">'
            f'<tr><td><font face="{_FONT_FACE}" point-size="11" '
            f'color="{text_color}"><b>{_escape(identity)}</b></font></td></tr>'
            f'<tr><td><font face="{_MONO_FACE}" '
            f'point-size="8" color="{text_color}">{_escape(short)}</font></td></tr>'
            f'</table>>'
        )
    else:
        # Bare wallet — just the short hex address in monospace.
        label = (
            f'<<font face="{_MONO_FACE}" '
            f'point-size="10" color="{text_color}">{_escape(short)}</font>>'
        )

    attrs: dict[str, str] = {
        "label": label,
        "fillcolor": fill,
        "color": border,
        "fontcolor": text_color,
    }
    if url:
        attrs["URL"] = url
        attrs["target"] = "_blank"
        attrs["tooltip"] = f"{identity or short} — open on chain explorer"
    return attrs


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
    """The graph-level title block. HTML-style label (allowed when the
    label value is wrapped in ``<...>``).

    Layout matches the document letterhead aesthetic: serif "Recupero"
    wordmark on the left, the diagram subject on the right.
    """
    primary = title or "Fund Flow Analysis"
    sub = (
        f"Case {_escape(case.case_id)} · "
        f"{len(case.transfers)} transfer(s) · "
        f"{case.chain.value}"
    )
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
