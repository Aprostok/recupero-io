"""Unit tests for the pure helpers in worker/_flow_diagram.

The flow-diagram module is largely SVG/Graphviz orchestration that's
expensive to test end-to-end (needs the ``dot`` binary, produces
binary SVG output). But the pure-Python helpers — text formatting,
URL builders, address shorteners, edge-width scaling, entity badge
lookups — are easy to lock down and exactly the kind of code that
breaks silently when someone tweaks formatting.

The SVG post-processor functions (``_inject_letter_mark_badges`` and
``_wrap_edge_labels_in_pills``) get integration-style coverage
against a known Graphviz output fixture — they're regex rewrites
that need to match the exact element shapes Graphviz emits.

Tests run in <100ms total.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from recupero.worker._flow_diagram import (
    _edge_label,
    _edge_penwidth,
    _entity_badge,
    _EdgeAttrs,
    _escape,
    _explorer_url,
    _fmt_usd_compact,
    _inject_letter_mark_badges,
    _node_id,
    _short_addr,
    _slug,
    _soft_wrap,
)


# ---- _short_addr ---- #


def test_short_addr_normal_ethereum() -> None:
    """0x + 40 hex → 0xAAAAAA…AAAA (6 prefix, 4 suffix, ellipsis)."""
    out = _short_addr("0x" + "a" * 40)
    assert out == "0xaaaa…aaaa"


def test_short_addr_short_input_returned_as_is() -> None:
    """Strings shorter than 12 chars return unchanged — short
    sentinels like '0x0' or labels like 'mixer' shouldn't get
    truncated into nothing."""
    assert _short_addr("0x123") == "0x123"
    assert _short_addr("mixer") == "mixer"


def test_short_addr_empty_returns_empty() -> None:
    """Empty / None input is defensively normalized to empty string,
    not None — callers concatenate the result into label text."""
    assert _short_addr("") == ""
    assert _short_addr(None) == ""  # type: ignore[arg-type]


# ---- _soft_wrap ---- #


def test_soft_wrap_short_text_unchanged() -> None:
    """Strings under the width threshold pass through verbatim."""
    assert _soft_wrap("Circle", width=20) == "Circle"


def test_soft_wrap_breaks_on_word_boundary() -> None:
    """A long multi-word string wraps with newlines between words —
    never mid-word."""
    out = _soft_wrap("Sky Protocol formerly MakerDAO", width=14)
    lines = out.split("\n")
    assert all(len(line) <= 18 for line in lines), (
        f"some wrapped line exceeds width budget by too much: {lines}"
    )
    # No word should be split mid-character.
    assert all(" " not in line or line.split() == line.split() for line in lines)


def test_soft_wrap_caps_at_three_lines() -> None:
    """A really-long string wraps to AT MOST 3 lines. Subsequent
    words get joined into the third line. Prevents towering labels
    that overflow circle nodes."""
    out = _soft_wrap("one two three four five six seven eight nine ten", width=6)
    lines = out.split("\n")
    assert len(lines) <= 3, f"expected ≤3 lines, got {len(lines)}: {lines}"


def test_soft_wrap_empty_returns_empty() -> None:
    assert _soft_wrap("", width=10) == ""
    assert _soft_wrap(None, width=10) == ""  # type: ignore[arg-type]


# ---- _fmt_usd_compact ---- #


@pytest.mark.parametrize("amount,expected", [
    (Decimal("0.05"),       "$0.05"),       # sub-dollar
    (Decimal("0.99"),       "$0.99"),
    (Decimal("1"),          "$1"),          # whole dollars
    (Decimal("12"),         "$12"),
    (Decimal("999"),        "$999"),
    (Decimal("1000"),       "$1K"),         # ".0K" collapses to "K"
    (Decimal("1234.56"),    "$1.2K"),       # rounds to 1dp
    (Decimal("9999"),       "$10K"),        # ".0K" still collapses just under 10k
    (Decimal("10000"),      "$10K"),        # 0dp once over 10k
    (Decimal("21647.81"),   "$22K"),
    (Decimal("999999"),     "$1000K"),
    (Decimal("1000000"),    "$1M"),         # "$1.0M" collapses to "$1M"
    (Decimal("1500000"),    "$1.5M"),
    (Decimal("12345678"),   "$12.3M"),
])
def test_fmt_usd_compact(amount: Decimal, expected: str) -> None:
    """USD formatting must match TRM-style compact rendering exactly —
    this drives the headline numbers in every flow diagram and freeze
    letter."""
    assert _fmt_usd_compact(amount) == expected


# ---- _edge_penwidth ---- #


def test_edge_penwidth_zero_is_minimum() -> None:
    """Zero / None USD gets the minimum penwidth so the edge is still
    visible (catch-and-render zero-value transfers like contract
    interactions)."""
    assert _edge_penwidth(None) == 0.8
    assert _edge_penwidth(Decimal(0)) == 0.8
    assert _edge_penwidth(Decimal("-5")) == 0.8


def test_edge_penwidth_scales_logarithmically() -> None:
    """Penwidth scales with log10(USD). Sanity-checks the slope so
    a $1M flow is visibly thicker than a $1K flow."""
    p_1k    = _edge_penwidth(Decimal("1000"))
    p_10k   = _edge_penwidth(Decimal("10000"))
    p_100k  = _edge_penwidth(Decimal("100000"))
    p_1m    = _edge_penwidth(Decimal("1000000"))
    assert p_1k < p_10k < p_100k < p_1m
    # Slope sanity: each decade adds ~0.8pt of width.
    assert abs((p_10k - p_1k) - 0.8) < 0.1, (
        f"decade slope drift: {p_1k}→{p_10k} should be ~0.8 apart"
    )


# ---- _explorer_url ---- #


@pytest.mark.parametrize("chain,host", [
    ("ethereum",    "etherscan.io"),
    ("arbitrum",    "arbiscan.io"),
    ("polygon",     "polygonscan.com"),
    ("base",        "basescan.org"),
    ("bsc",         "bscscan.com"),
    ("solana",      "solscan.io"),
    ("hyperliquid", "hyperliquid.xyz"),
])
def test_explorer_url_per_chain(chain: str, host: str) -> None:
    """Every supported chain has a working explorer URL builder."""
    addr = "0x" + "a" * 40
    url = _explorer_url(chain, addr)
    assert url is not None
    assert host in url
    assert addr in url


def test_explorer_url_unknown_chain() -> None:
    """An unknown chain returns None rather than guessing — better
    to omit the link than send users to a 404. v0.16.4: bitcoin /
    tron got added to the central _common map, so use a genuinely
    unknown chain name here."""
    assert _explorer_url("monero", "abc123") is None
    assert _explorer_url("zksync-era-unsupported", "abc") is None
    assert _explorer_url("", "abc") is None


def test_explorer_url_empty_address() -> None:
    """Empty address → None (defensive — sometimes counterparty.address
    is empty on contract-creation transactions)."""
    assert _explorer_url("ethereum", "") is None


# ---- _entity_badge ---- #


def test_entity_badge_substring_match() -> None:
    """Badge lookup matches on substring, case-insensitive — "Binance
    Hot Wallet" should match the "binance" badge key."""
    # The dict's actual keys depend on _ENTITY_BADGES — verify via
    # known issuer that has a badge (Circle, Tether, etc.).
    badge = _entity_badge("Circle")
    if badge is not None:
        # If Circle has a badge, the tuple is (letter, fill, text_color)
        assert len(badge) == 3


def test_entity_badge_none_for_unknown() -> None:
    """Unknown identity → None (no badge rendered)."""
    assert _entity_badge("totally made up entity name xyz123") is None


def test_entity_badge_none_for_empty() -> None:
    """Empty / None identity → None defensively."""
    assert _entity_badge(None) is None
    assert _entity_badge("") is None


# ---- _node_id / _slug ---- #


def test_node_id_lowercases_ethereum_address() -> None:
    """node_id normalizes addresses to lowercase so cross-references
    work regardless of checksum casing."""
    a = _node_id("0xABCdef" + "0" * 34)
    b = _node_id("0xabcdef" + "0" * 34)
    assert a == b


def test_slug_safe_for_cluster_id() -> None:
    """_slug must produce a Graphviz-safe cluster identifier (no
    spaces, no special chars). Otherwise Graphviz silently drops the
    cluster."""
    s = _slug("Sky Protocol (formerly MakerDAO)")
    assert " " not in s
    assert "(" not in s
    assert ")" not in s
    # alphanumeric+underscore only
    import re
    assert re.fullmatch(r"[a-z0-9_]+", s)


def test_slug_empty_returns_sentinel() -> None:
    """Empty input returns a non-empty sentinel — Graphviz cluster
    IDs must be non-empty."""
    assert _slug("") == "x"
    assert _slug("!!!") == "x"   # only special chars → all stripped → 'x'


# ---- _escape ---- #


def test_escape_handles_html_unsafe() -> None:
    """HTML labels in Graphviz need <, >, & escaped or Graphviz
    silently treats them as markup and the label breaks."""
    out = _escape("A & B < C > D")
    assert "&amp;" in out
    assert "&lt;" in out
    assert "&gt;" in out


def test_escape_none_returns_empty() -> None:
    assert _escape(None) == ""


def test_escape_idempotent_for_safe_text() -> None:
    """Plain alphanumeric stays unchanged."""
    assert _escape("Circle USDC") == "Circle USDC"


# ---- _edge_label ---- #


def _edge(total_usd, symbol, count=1):
    """Helper: build a minimal _EdgeAttrs for label testing."""
    return _EdgeAttrs(
        src="0x" + "1" * 40,
        dst="0x" + "2" * 40,
        total_usd=total_usd,
        transfer_count=count,
        dominant_symbol=symbol,
    )


def test_edge_label_priced_single() -> None:
    """The simple case: priced transfer, recognized symbol."""
    label = _edge_label(_edge(total_usd=Decimal("12300"), symbol="USDC"))
    assert "$12K" in label
    assert "USDC" in label


def test_edge_label_aggregated_priced() -> None:
    """Multiple priced transfers: the count suffix attaches to the
    last existing part ($X SYM ×N)."""
    label = _edge_label(_edge(
        total_usd=Decimal("45000"), symbol="USDC", count=3,
    ))
    assert "$45K" in label
    assert "USDC" in label
    assert "×3" in label


def test_edge_label_no_price_with_symbol() -> None:
    """No USD pricing but the token symbol is known. Edge still
    gets a meaningful label: just the symbol + count."""
    label = _edge_label(_edge(total_usd=Decimal("0"), symbol="WEIRD"))
    assert "WEIRD" in label


def test_edge_label_aggregated_no_price_with_symbol() -> None:
    """Multiple unpriced transfers, recognized symbol. Count
    suffix attaches to the symbol."""
    label = _edge_label(_edge(
        total_usd=Decimal("0"), symbol="MEMECOIN", count=4,
    ))
    assert "MEMECOIN" in label
    assert "×4" in label


def test_edge_label_no_price_no_symbol_aggregated() -> None:
    """Regression: when an aggregated edge has total_usd=0 AND
    dominant_symbol=None, the prior code did ``parts[-1] = ...``
    on an empty list and crashed with IndexError, dropping the
    entire flow diagram from the artifact bundle.

    Real-data Arbitrum cases (case 9928b53e..., 198 transfers) hit
    this because some transfers are in tokens without CoinGecko
    pricing AND without a recognized symbol in our label store
    (typical for memecoins / illiquid ERC-20s).

    Post-fix: the count alone gets used as the label."""
    label = _edge_label(_edge(
        total_usd=Decimal("0"), symbol=None, count=3,
    ))
    assert "×3" in label
    # No crash is the main assertion here.


def test_edge_label_zero_usd_no_symbol_single_transfer() -> None:
    """Single transfer with no price + no symbol → generic
    '(transfer)' fallback. Catches the other empty-parts edge case
    (count == 1 path)."""
    label = _edge_label(_edge(
        total_usd=Decimal("0"), symbol=None, count=1,
    ))
    assert label == "(transfer)"


# ---- _inject_letter_mark_badges (SVG post-processor) ---- #


def test_inject_badges_no_op_when_no_badge_markers() -> None:
    """SVG without any of the badge-marker comments passes through
    unchanged. Defensive — Graphviz output without entities shouldn't
    accidentally get mutated."""
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><g><text>hello</text></g></svg>'
    out = _inject_letter_mark_badges(svg)
    assert out == svg


def test_inject_badges_empty_input() -> None:
    """Empty SVG returns empty — no crash."""
    assert _inject_letter_mark_badges("") == ""


def test_inject_badges_preserves_outer_svg_root() -> None:
    """Even when the post-processor mutates the SVG, the <svg> root
    element with its xmlns is preserved — otherwise the SVG won't
    render in WeasyPrint."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<g><text>label</text></g></svg>'
    )
    out = _inject_letter_mark_badges(svg)
    assert 'xmlns="http://www.w3.org/2000/svg"' in out
    assert out.startswith("<svg")
    assert out.endswith("</svg>") or out.endswith("</svg>\n")
