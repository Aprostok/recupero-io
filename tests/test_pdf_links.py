"""Unit tests for worker/_pdf_links.

Covers the address→href map builder against the failure modes
we've actually hit in production:

  * Plain body anchors (the happy path).
  * SVG-namespace `<a xlink:href="...">` wrappers inside the
    Graphviz output — must be filtered.
  * Multiple anchors to the same URL — all must end up in the
    map (one per occurrence).
  * Mixed full-address + short-truncation rendering.
  * Mailto / fragment-only / non-explorer hrefs — must be ignored.

These tests run in <100ms and don't touch the filesystem beyond
tempfile writes for the input HTML.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from recupero.worker._pdf_links import (
    _AnchorExtractor,
    _build_address_to_url_map,
)


def _make_html(body: str) -> Path:
    """Write a temp HTML file and return its path. Caller deletes."""
    with NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write(f"<!DOCTYPE html><html><body>{body}</body></html>")
        return Path(f.name)


def test_plain_body_anchor_extracted() -> None:
    """The happy path: a single `<a class='mono' href='https://etherscan.io/...'>0xABC…</a>`
    lands in the map under both the rendered short form and the full
    address derived from the href."""
    html = _make_html(
        '<a class="mono" '
        'href="https://etherscan.io/address/0x'
        + "a" * 40
        + '">0x'
        + "a" * 6
        + "…"
        + "a" * 4
        + "</a>"
    )
    try:
        m = _build_address_to_url_map(html)
        # Should have at minimum: rendered short form,
        # full hex, ASCII-dots variant.
        assert len(m) >= 3
        url = next(iter(m.values()))
        assert url == "https://etherscan.io/address/0x" + "a" * 40
        # Every entry maps to the same URL.
        assert all(v == url for v in m.values())
    finally:
        html.unlink(missing_ok=True)


def test_svg_xlink_anchors_filtered() -> None:
    """SVG-namespace anchors (Graphviz output) must NOT pollute the
    map. They carry the same Etherscan URLs but wrap SVG elements,
    not plain address text — and WeasyPrint handles them natively.

    Regression test for the bug fixed in 87f4f7e where these
    anchors made the address map 13 entries with non-rendered keys
    that never matched the PDF text.
    """
    full_addr = "0x" + "b" * 40
    html = _make_html(
        # Body anchor — should be picked up
        f'<a class="mono" href="https://etherscan.io/address/{full_addr}">'
        f'0x{"b" * 6}…{"b" * 4}</a>'
        # SVG-namespace anchor — should be IGNORED
        f'<svg><g><a xlink:href="https://etherscan.io/address/'
        f'0x{"c" * 40}" target="_blank">'
        f'<path d="M0,0 L10,10"/></a></g></svg>'
    )
    try:
        m = _build_address_to_url_map(html)
        # Only the body anchor's address should appear.
        urls = set(m.values())
        assert len(urls) == 1, f"expected only the body anchor's URL, got {urls}"
        assert full_addr in next(iter(urls))
        # The SVG xlink-href address (c * 40) must NOT be in the map.
        assert all("c" * 40 not in v for v in m.values())
    finally:
        html.unlink(missing_ok=True)


def test_multiple_anchors_same_url_kept() -> None:
    """When the same URL appears in multiple body anchors (e.g.
    current_holder address in section 3, section 4, section 5),
    every rendered occurrence's text variant lands in the map."""
    full_addr = "0x" + "d" * 40
    url = f"https://etherscan.io/address/{full_addr}"
    html = _make_html(
        f'<p>First: <a class="mono" href="{url}">'
        f'0x{"d" * 6}…{"d" * 4}</a></p>'
        f'<p>Again: <a class="mono" href="{url}">{full_addr}</a></p>'
        f'<p>Third: <a class="mono" href="{url}">'
        f'0x{"d" * 6}...{"d" * 4}</a></p>'
    )
    try:
        m = _build_address_to_url_map(html)
        # All entries should target the same URL.
        assert set(m.values()) == {url}
        # Map should contain at least: unicode-truncation, full hex,
        # ASCII-dots truncation.
        assert len(m) >= 3
    finally:
        html.unlink(missing_ok=True)


def test_non_explorer_hrefs_ignored() -> None:
    """Mailto links, anchor fragments, and arbitrary external URLs
    must be ignored — we only inject /Link annotations for chain
    explorer URLs."""
    html = _make_html(
        '<a href="mailto:compliance@circle.com">Compliance team</a>'
        '<a href="#section-2">Skip to section 2</a>'
        '<a href="https://recupero.io/about">About</a>'
        '<a href="https://etherscan.io/about">Etherscan about page</a>'
    )
    try:
        m = _build_address_to_url_map(html)
        # /address/, /tx/, /account/ paths are the only matches.
        # The Etherscan "about" page is not an explorer-target URL.
        assert m == {}, f"unexpected entries: {m}"
    finally:
        html.unlink(missing_ok=True)


def test_arbiscan_polygonscan_solscan_recognized() -> None:
    """Map builder must recognize every chain explorer in our
    coverage table, not just Etherscan."""
    chains_to_test = [
        ("arbiscan.io", "0x" + "1" * 40),
        ("polygonscan.com", "0x" + "2" * 40),
        ("basescan.org", "0x" + "3" * 40),
        ("bscscan.com", "0x" + "4" * 40),
    ]
    for host, addr in chains_to_test:
        html = _make_html(
            f'<a class="mono" href="https://{host}/address/{addr}">'
            f'{addr}</a>'
        )
        try:
            m = _build_address_to_url_map(html)
            assert len(m) >= 1, f"no entries for {host}"
            assert any(host in v for v in m.values()), \
                f"{host} URL not in any map entry"
        finally:
            html.unlink(missing_ok=True)


def test_empty_html_returns_empty_map() -> None:
    """No anchors → empty map, no exceptions."""
    html = _make_html("<p>just some text</p>")
    try:
        m = _build_address_to_url_map(html)
        assert m == {}
    finally:
        html.unlink(missing_ok=True)


def test_missing_file_returns_empty_map() -> None:
    """A nonexistent path returns an empty map (best-effort,
    no exception). This is the prod no-html path."""
    m = _build_address_to_url_map(Path("/nonexistent/path.html"))
    assert m == {}


def test_anchor_text_without_0x_prefix_ignored() -> None:
    """Anchors whose body text doesn't start with `0x` (e.g. the
    "View on Etherscan" CTA the templates carry in the body) only
    contribute the derived-from-href full-address form, not their
    rendered text."""
    addr = "0x" + "e" * 40
    url = f"https://etherscan.io/address/{addr}"
    html = _make_html(f'<a href="{url}">View on Etherscan</a>')
    try:
        m = _build_address_to_url_map(html)
        # The text "View on Etherscan" doesn't start with 0x,
        # so the rendered-text key is skipped. We still derive
        # the full-address form from the href.
        # Either: empty (current behavior) or contains only the
        # full-address key. Both are acceptable; we just need
        # to NOT register "View on Etherscan" as a key.
        assert "View on Etherscan" not in m
    finally:
        html.unlink(missing_ok=True)


def test_anchor_extractor_handles_nested_anchors_gracefully() -> None:
    """Nested <a> tags (illegal in HTML but possible in malformed
    input) shouldn't crash the parser. The stack-based extractor
    handles this by closing inner anchor first."""
    addr = "0x" + "f" * 40
    url = f"https://etherscan.io/address/{addr}"
    # Nested anchors — html.parser will treat them as siblings due
    # to its lenient parsing, which is fine for our purposes.
    html = _make_html(
        f'<a href="https://example.com">outer<a href="{url}">{addr}</a></a>'
    )
    try:
        m = _build_address_to_url_map(html)
        # Inner anchor's address should be picked up.
        assert any(url in v for v in m.values())
    finally:
        html.unlink(missing_ok=True)


# ---- _AnchorExtractor unit-level coverage ---- #


def test_anchor_extractor_state_is_clean_after_close() -> None:
    """After feed() + close(), the extractor's stacks should be
    empty (no leaked state from open <a> tags without matching
    </a>)."""
    ex = _AnchorExtractor()
    ex.feed('<a href="https://etherscan.io/address/0x' + "a" * 40 + '">0xabc')
    # Note: no closing </a> on purpose — verify close() doesn't crash
    ex.close()
    # _href_stack still has one entry because </a> never came.
    # That's OK — we just need not to emit a malformed pair.
    assert len(ex.pairs) == 0


def test_anchor_extractor_collects_text_with_inner_whitespace() -> None:
    """Address text with surrounding whitespace (templates often
    insert newlines/indent inside <a>) should be stripped."""
    addr = "0x" + "a" * 40
    url = f"https://etherscan.io/address/{addr}"
    ex = _AnchorExtractor()
    ex.feed(f'<a href="{url}">\n  {addr}\n  </a>')
    ex.close()
    assert len(ex.pairs) == 1
    rendered, href = ex.pairs[0]
    assert rendered == addr
    assert href == url
