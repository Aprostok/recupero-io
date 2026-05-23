"""Client-side XSS audit for ``interactive_graph.html.j2`` (wave-6).

The interactive graph template embeds case data inside a
``<script type="application/json">`` block, then a D3 client-side
script ``JSON.parse``s it and injects node/edge labels back into the
DOM. Even though the embed shape blocks the ``</script>`` breakout
(v0.18.2) and tooltip fields flow through ``.textContent`` rather
than ``.html()`` / ``.innerHTML`` (v0.19.2), several client-side sinks
remain attractive XSS surfaces that a future drive-by edit could
accidentally re-introduce:

  1. ``element.innerHTML = node.label``     — must stay textContent
  2. ``a.href = node.explorer_url``         — must go through allowlist
  3. ``el.setAttribute("on...", ...)``      — never set event handlers
  4. ``selection.html(d => d.label)``       — D3 ``.html()`` is innerHTML
  5. ``<image href=...>`` in SVG            — fetches external resources
  6. ``console.log(d.<attacker field>)``    — devtools log leak

Each test below fully renders the template via the real
``render_graph_html`` path with adversarial node/edge fields, then
string-greps the rendered output (which contains the entire JS
source verbatim, since the template embeds it inline) for the unsafe
patterns. The tests pass on the current hardened template; they
serve as a regression gate against future ``innerHTML`` /
``.html()`` re-introductions.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.reports.graph_ui import build_graph_data, render_graph_html

VICTIM = "0x" + "a" * 40
PERP = "0x" + "b" * 40

# Adversarial payload that exploits every known sink in one string:
#   - <script> breakout
#   - HTML-comment open/close
#   - <img onerror=> (innerHTML sink)
#   - javascript: URL (href sink)
#   - quote / backtick / template-literal breakout
ADVERSARIAL_LABEL = (
    """</script><img src=x onerror=alert(1)>"""
    """<!--xss--><a href="javascript:alert(1)">x</a>"""
    """`${alert(1)}` " '"""
)


def _transfer(*, from_addr: str, to_addr: str,
              counterparty_label: Label | None = None) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    tx_hash = "0x" + "1" * 64
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=counterparty_label, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDT", decimals=6, coingecko_id="tether",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=Decimal("1000"),
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _case_with_evil_label() -> Case:
    evil_label = Label(
        address=PERP,
        name=ADVERSARIAL_LABEL,
        category=LabelCategory.exchange_deposit,
        source="evil-vendor",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    transfers = [_transfer(
        from_addr=VICTIM, to_addr=PERP, counterparty_label=evil_label,
    )]
    return Case(
        case_id="V-XSS01",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


def _render() -> str:
    """Render the template with adversarial labels and return the HTML."""
    case = _case_with_evil_label()
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        return out_path.read_text(encoding="utf-8")


# ---- 1. innerHTML sink ---- #


def test_no_innerhtml_assignment_in_template() -> None:
    """Every DOM field is written via ``.textContent`` / D3 ``.text()``.
    Any ``.innerHTML =`` assignment — especially one with a template-
    literal RHS — would re-open the XSS hole that v0.19.2 closed."""
    html = _render()
    # Hard ban: innerHTML LHS anywhere in the embedded JS.
    assert not re.search(r"\.innerHTML\s*=", html), (
        "interactive_graph.html.j2 contains an .innerHTML assignment — "
        "this is the canonical vendor-label XSS sink (v0.19.2). Use "
        ".textContent or D3 .text() instead."
    )
    # Specifically: no template-literal RHS that interpolates a node field.
    assert not re.search(r"innerHTML\s*=\s*`[^`]*\$\{", html), (
        "innerHTML assigned from a template literal with interpolation — "
        "this is the worst-case XSS shape."
    )


def test_no_d3_html_call() -> None:
    """D3's ``selection.html(...)`` is ``innerHTML`` under the hood.
    The pre-v0.19.2 tooltip used ``tooltip.html(\\`...\\${d.label}...\\`)``
    which let any vendor-controlled label inject markup. Ban it."""
    html = _render()
    # D3 .html() chained off a selection — match `.html(` not preceded
    # by a word char (so e.g. `outerHTML(` is fine, but `tooltip.html(` is not).
    # Allow `.html(` only inside the leading <html ...> tag, which is
    # text not JS; we restrict the search to within <script>...</script>.
    script_blocks = re.findall(
        r"<script[^>]*>(.*?)</script>", html, re.DOTALL,
    )
    joined_js = "\n".join(script_blocks)
    # Strip JS comments before grepping so a comment that documents the
    # historical bug (``// pre-v0.19.2 every interpolated field flowed
    # through D3's .html() — innerHTML under the hood``) doesn't trip
    # the regression check. We only care about actual CALLS to .html().
    no_line_comments = re.sub(r"//[^\n]*", "", joined_js)
    no_block_comments = re.sub(r"/\*.*?\*/", "", no_line_comments, flags=re.DOTALL)
    assert ".html(" not in no_block_comments, (
        "interactive_graph.html.j2 calls a D3 selection's .html() — "
        "this is innerHTML under the hood and would defeat the "
        "v0.19.2 textContent hardening."
    )


# ---- 2. Anchor href injection ---- #


def test_explorer_anchor_href_goes_through_safe_allowlist() -> None:
    """Every ``a.href = ...`` / ``a.setAttribute('href', ...)`` that
    threads a node field MUST flow through ``_safeExplorerUrl`` first,
    which rejects ``javascript:`` / ``data:`` / ``vbscript:`` URLs.
    A bare ``a.href = d.explorerUrl`` would let a vendor-controlled
    label feed a ``javascript:alert(...)`` URL through to operator-
    browser execution."""
    html = _render()
    # The hardened path: _safeExplorerUrl helper must exist and be
    # called before any href setAttribute on a node-derived field.
    assert "_safeExplorerUrl" in html, (
        "the _safeExplorerUrl URL-scheme allowlist helper is missing — "
        "every href interpolation in the JS must go through it."
    )
    # No bare-attribute href assignment from a `d.` (node-data) field.
    # The hardened code only ever sets href from `safeUrl` (the
    # allowlisted local), never from `d.explorerUrl` directly.
    assert not re.search(
        r"""setAttribute\(\s*["']href["']\s*,\s*d\.""", html,
    ), (
        "an href setAttribute is being fed a raw node-data field "
        "(d.something) without passing through _safeExplorerUrl — "
        "this re-opens the javascript:-URL XSS vector."
    )
    # No bare `a.href = ` assignment (the .href DOM setter applies
    # URL-context decoding but does NOT block javascript: schemes).
    assert not re.search(r"""\.href\s*=\s*["']?\$?\{""", html), (
        ".href is being assigned from a template literal or "
        "interpolation — go through setAttribute + _safeExplorerUrl."
    )


# ---- 3. Event-handler attribute injection ---- #


def test_no_setattribute_for_event_handlers() -> None:
    """``setAttribute('onclick', ...)`` / ``setAttribute('onerror', ...)``
    let any attacker-controlled string become an event handler. Even
    static handler names with attacker-controlled values are XSS:
    ``el.setAttribute('onclick', d.label)``."""
    html = _render()
    # Any setAttribute whose first argument starts with "on" (event
    # handler) is banned outright in this template.
    matches = re.findall(
        r"""setAttribute\(\s*["']on[a-z]+["']""", html, re.IGNORECASE,
    )
    assert matches == [], (
        f"interactive_graph.html.j2 sets an event-handler attribute "
        f"via setAttribute: {matches!r}. Event-handler attribute "
        f"injection is XSS regardless of value source."
    )


# ---- 4. SVG <text> safety + svg <image> external-fetch ---- #


def test_svg_text_uses_d3_text_not_html() -> None:
    """D3 ``.text(d => d.label)`` calls ``textContent`` under the
    hood — safe. Any switch to ``.html(d => d.label)`` for SVG
    ``<text>`` would render attacker markup. Spot-check the node-
    label append site."""
    html = _render()
    # The hardened sites use .text(d => ...). Confirm at least one
    # such call exists and that none use .html() for node labels.
    assert re.search(r"""\.text\(\s*d\s*=>\s*d\.label""", html), (
        "the SVG <text> node-label append no longer uses .text(d => "
        "d.label) — verify the new sink is still textContent-safe."
    )


def test_no_svg_image_external_href() -> None:
    """SVG ``<image href="...">`` fetches external resources at
    render time — same exfil risk as WeasyPrint's external CSS. The
    template must not append any ``<image>`` element with an
    attacker-controllable href."""
    html = _render()
    script_blocks = re.findall(
        r"<script[^>]*>(.*?)</script>", html, re.DOTALL,
    )
    joined_js = "\n".join(script_blocks)
    # No D3 .append("image") and no createElementNS for an <image>.
    assert not re.search(r"""append\(\s*["']image["']""", joined_js), (
        "the template appends an SVG <image> element — these fetch "
        "external resources on render and are an exfil vector."
    )
    assert "createElementNS" not in joined_js or "image" not in joined_js, (
        "the template may be creating an SVG <image> via "
        "createElementNS — audit the call site for exfil risk."
    )


# ---- 5. console.log of attacker-controllable fields ---- #


def test_no_console_log_of_node_fields() -> None:
    """``console.log(d)`` of a node object dumps every vendor-
    controlled field into devtools — not XSS per se, but a passive
    leak (label feeds, internal addresses) that future operators
    might paste into a bug report or support ticket."""
    html = _render()
    script_blocks = re.findall(
        r"<script[^>]*>(.*?)</script>", html, re.DOTALL,
    )
    joined_js = "\n".join(script_blocks)
    assert "console.log" not in joined_js, (
        "interactive_graph.html.j2 contains console.log — operator-"
        "facing builds should not leak node data into devtools."
    )
    assert "console.debug" not in joined_js
    assert "console.warn" not in joined_js


# ---- 6. JSON.parse of the graph-data block ---- #


def test_embedded_json_is_parseable_with_adversarial_labels() -> None:
    """The client does ``JSON.parse(textContent)`` with no try/catch
    around it — if the producer ever emits malformed JSON (because a
    label contained a stray ``</script>`` that ate the closing tag,
    or a NaN that ``JSON.parse`` rejects), the whole graph silently
    fails to load. Verify the embedded JSON survives an adversarial
    label round-trip."""
    html = _render()
    match = re.search(
        r'<script id="graph-data" type="application/json">(.*?)</script>',
        html, re.DOTALL,
    )
    assert match is not None, (
        "the application/json embed block is missing — the v0.18.2 "
        "XSS-mitigation embed shape has regressed."
    )
    # Must parse cleanly.
    parsed = json.loads(match.group(1))
    # The adversarial label must round-trip as data (not markup).
    perp_node = next(n for n in parsed["nodes"] if n["id"] == PERP)
    assert "onerror" in perp_node["label"], (
        "the adversarial label string was stripped — this test no "
        "longer exercises the XSS surface it claims to."
    )
    # And the </script> sequence must have been escaped at the
    # data-embed layer (v0.18.2) so the surrounding <script> block
    # can't be broken out of even by non-strict HTML parsers.
    raw_block = match.group(1)
    assert "</script>" not in raw_block, (
        "raw </script> sequence leaked into the JSON block — the "
        "v0.18.2 `.replace('</', '<\\/')` defense-in-depth escape "
        "is no longer being applied."
    )
