"""Adversarial XSS tests for Recupero Jinja templates (XSS Phase B).

Feeds attacker-controlled payloads into every rendered template and
asserts the output is XSS-safe. The threat model:

  1. A brief PDF / HTML is opened in a law-firm operator's browser.
  2. Some fields in the brief come from attacker-controlled paths —
     freeze-outcome responses (issuer compliance teams), on-chain
     labels (Etherscan tag set, attacker-controlled), intake form
     fields the user fills in (display name, addresses), or
     destination labels the trace stage attaches to a perp's wallet.
  3. If any of these field values escape into executable HTML —
     `<script>`, attribute-context escape, `javascript:` URL — the
     attacker hijacks the operator's session.

What we assert per template:
  * Output never contains a literal `<script>` injected from a
    user-controlled field (i.e., any payload string we fed in must
    have its `<` HTML-encoded to `&lt;`).
  * Output never contains a `href="javascript:..."` or
    `href="data:..."` URL. The ``safe_url`` filter must rewrite
    these to ``#``.
  * Output never contains `Infinity` / `NaN` as bare HTML — those
    are valid JS literals and would corrupt downstream JSON parsing
    or display as literal "Infinity" in dollar amounts.
  * CRLF in attacker-controlled fields does NOT inject linebreaks
    into single-line attribute contexts (Jinja's default behavior
    is to preserve them; safe_url strips CR/LF before emitting).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from jinja2 import (
    ChainableUndefined,
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from recupero.reports._jinja_filters import register_safe_filters

_TEMPLATES = (
    Path(__file__).resolve().parent.parent
    / "src" / "recupero" / "reports" / "templates"
)


# ---------- Adversarial payload corpus ---------- #


XSS_SCRIPT = "<script>alert(1)</script>"
XSS_SVG = '"><svg onload=alert(1)>'
XSS_TD_BREAK = "</td><script>alert(1)</script>"
URL_JAVASCRIPT = "javascript:alert(1)"
URL_DATA = "data:text/html,<script>alert(1)</script>"
URL_VBSCRIPT = "vbscript:msgbox(1)"
CRLF = "foo\r\n\r\n<malicious-tag>"
BIDI = "alice‮evil"
SQL_QUOTE = "'); DROP TABLE addresses;--"
INFINITY = float("inf")


def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        # ChainableUndefined: missing vars render as empty string and
        # don't crash on attribute access (foo.bar.baz). This lets us
        # exercise the XSS interpolations without supplying every dict
        # key the production renderers compute — what matters for this
        # suite is that supplied attacker payloads are sanitized; gaps
        # in the test fixture should NOT mask a real injection.
        undefined=ChainableUndefined,
    )
    register_safe_filters(env)
    return env


def _assert_no_xss(html: str, payloads: list[str], *, fmt_label: str) -> None:
    """Generic XSS gate: every payload must be HTML-escaped or stripped
    (no executable injection)."""
    # 1) No raw `<script>` from a user-supplied field.
    #    We allow `<script src="cdn..." />` or
    #    `<script id="graph-data" type="application/json">`
    #    that the template itself emits, but NO user-injected one.
    # The payloads we fed all start with `<` and contain `script` /
    # `svg`, so the assertion is: those exact byte sequences must not
    # appear verbatim.
    for p in payloads:
        if p.startswith("<") and p in html:
            pytest.fail(
                f"{fmt_label}: injected payload {p!r} survived unescaped "
                f"into rendered HTML."
            )

    # 2) No `javascript:` or `data:` URL in any href/src.
    bad_url_in_attr = re.search(
        r'(?:href|src|action|formaction)\s*=\s*"\s*(?:javascript|data|vbscript)\s*:',
        html,
        flags=re.IGNORECASE,
    )
    assert not bad_url_in_attr, (
        f"{fmt_label}: dangerous-scheme URL in attribute: "
        f"{bad_url_in_attr.group(0)!r}"
    )

    # 3) No bare `Infinity` / `NaN` from a USD-value field. These
    # would render as literal text in the legal letter — embarrassing
    # and a signal of corrupted upstream data.
    assert "Infinity" not in html, (
        f"{fmt_label}: 'Infinity' rendered as plain text — check that "
        f"USD-value fields sanitize non-finite floats."
    )
    assert "NaN" not in html, f"{fmt_label}: 'NaN' rendered as plain text."


# ---------- safe_url filter direct tests ---------- #


@pytest.mark.parametrize(
    "url,expected_prefix",
    [
        ("https://etherscan.io/address/0xabc", "https://"),
        ("http://example.com", "http://"),
        ("mailto:le@dept.gov", "mailto:"),
        ("tel:+15551234", "tel:"),
        ("/portal/abc", "/"),  # site-relative
        ("#anchor", "#"),  # in-page anchor
    ],
)
def test_safe_url_passes_legitimate(url: str, expected_prefix: str):
    from recupero.reports._jinja_filters import safe_url
    assert safe_url(url).startswith(expected_prefix)


@pytest.mark.parametrize(
    "url",
    [
        URL_JAVASCRIPT,
        URL_DATA,
        URL_VBSCRIPT,
        "JaVaScRiPt:alert(1)",  # case-mixed
        "  javascript:alert(1)",  # leading whitespace
        "java\tscript:alert(1)",  # whitespace inside scheme
        "\x00javascript:alert(1)",  # nul byte prefix
        "file:///etc/passwd",
        "ftp://attacker.example",
    ],
)
def test_safe_url_blocks_dangerous_schemes(url: str):
    from recupero.reports._jinja_filters import safe_url
    out = safe_url(url)
    assert out == "#", (
        f"safe_url should reject {url!r}, got {out!r}"
    )


def test_safe_url_strips_crlf():
    from recupero.reports._jinja_filters import safe_url
    out = safe_url("https://etherscan.io/tx/0xabc\r\nLocation: evil")
    assert "\r" not in out
    assert "\n" not in out


# ---------- Per-template adversarial render ---------- #


def _addr_ctx(addr: str = "0xDEADBEEFcafebabe1234567890abcdef12345678"):
    """Build a minimal address-dict shape used by several templates."""
    return {
        "address": addr,
        "address_short": addr[:10] + "…" + addr[-6:],
        "explorer_url": URL_JAVASCRIPT,  # adversarial!
    }


def test_le_template_blocks_javascript_url_in_explorer_link():
    """The LE handoff template renders dozens of
    `href="{{ explorer_url }}"` interpolations. A javascript: URL
    must NOT survive into the final HTML."""
    env = _build_env()
    tmpl = env.get_template("le.html.j2")
    # le.html.j2 has a large context. Build only what we need to
    # exercise the href interpolations.
    ctx = _minimal_le_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="le.html.j2")


def test_issuer_freeze_template_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("issuer_freeze_request.html.j2")
    ctx = _minimal_le_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="issuer_freeze_request.html.j2")


def test_maple_template_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("maple.html.j2")
    ctx = _minimal_le_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="maple.html.j2")


def test_trace_report_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("trace_report.html.j2")
    ctx = _minimal_trace_report_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="trace_report.html.j2")


def test_mini_freeze_digest_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("mini_freeze_digest.html.j2")
    ctx = _minimal_mini_freeze_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="mini_freeze_digest.html.j2")


def test_exchange_subpoena_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("exchange_subpoena_request.html.j2")
    ctx = _minimal_exchange_subpoena_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(
        html, _all_payloads(), fmt_label="exchange_subpoena_request.html.j2"
    )


def test_mlat_request_blocks_javascript_url():
    env = _build_env()
    tmpl = env.get_template("mlat_request.html.j2")
    ctx = _minimal_mlat_context()
    html = tmpl.render(**ctx)
    _assert_no_xss(html, _all_payloads(), fmt_label="mlat_request.html.j2")


def test_engagement_letter_attacker_email_does_not_break_out():
    """An attacker-controlled investigator.email shouldn't be able to
    inject HTML even though it's interpolated into a `mailto:` href."""
    env = _build_env()
    tmpl = env.get_template("engagement_letter.html.j2")
    ctx = _minimal_engagement_letter_context()
    # Attacker email tries to break out of mailto: attribute.
    ctx["investigator"]["email"] = '"><script>alert(1)</script>'
    html = tmpl.render(**ctx)
    assert "<script>alert(1)</script>" not in html
    assert ">alert(1)</script>" not in html


def test_interactive_graph_user_label_cannot_break_out_of_json_script_tag():
    """sec-CRIT-001 regression: a node label containing `</script>` MUST
    NOT close the data block and run arbitrary JS in the operator's
    browser."""
    # Use the actual renderer so we exercise the </script> escaping
    # that lives in graph_ui.py, not just the template.
    from recupero.reports.graph_ui import render_graph_html
    import tempfile
    import json as _json

    graph_data = {
        "nodes": [
            {"id": "n1", "label": "alice</script><script>alert(1)</script>",
             "chain": "ethereum", "address": "0xabc", "kind": "seed",
             "explorer_url": None, "outflow_count": 0, "inflow_count": 0,
             "total_inflow_usd": 0, "total_outflow_usd": 0,
             "labels": [], "edges_out": [], "edges_in": []},
        ],
        "edges": [],
        "meta": {
            "case_id": "CASE-XSS-001",
            "case_number": "CASE-XSS-001",
            "seed_address": "0xabc",
            "node_count": 1,
            "edge_count": 0,
            "total_usd_traced": "$0.00",
            "chain": "ethereum",
        },
    }
    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")

    # The literal `</script><script>` must NOT appear — graph_ui.py
    # escapes `</` to `<\/` before embedding.
    assert "</script><script>alert(1)" not in html

    # The escaped form must appear inside the data block.
    assert "alice<\\/script><script>alert(1)<\\/script>" in html


def test_interactive_graph_rejects_infinity_in_json():
    """A node carrying ``Infinity`` as a USD value must NOT render as
    the bare JS literal ``Infinity`` (which would break JSON.parse on
    load AND betray data corruption in the deliverable)."""
    from recupero.reports.graph_ui import render_graph_html
    import tempfile

    graph_data = {
        "nodes": [],
        "edges": [],
        "meta": {
            "case_id": "CASE-INF",
            "case_number": "CASE-INF",
            "seed_address": "0xabc",
            "node_count": 0,
            "edge_count": 0,
            "total_usd_traced": "$0.00",
            "chain": "ethereum",
            "evil_field": INFINITY,
        },
    }
    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")

    # `Infinity` must NOT be present as a bare JSON literal.
    # We don't ban the substring globally — `Infinity` could appear in
    # boilerplate prose someday — but in this test the only place it
    # could come from is the meta field we fed in.
    # The graph_ui.py code falls back to default=_scrub which maps
    # non-finite floats to 0.
    assert ": Infinity" not in html
    assert ":Infinity" not in html


# ---------- Portal templates (live HTTP target) ---------- #


def test_portal_status_attacker_client_name_does_not_inject_html():
    env = Environment(
        loader=FileSystemLoader(
            str(Path(__file__).resolve().parent.parent
                / "src" / "recupero" / "portal" / "templates")
        ),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    register_safe_filters(env)
    tmpl = env.get_template("status.html.j2")
    html = tmpl.render(
        case={
            "case_number": XSS_TD_BREAK,
            "client_name": XSS_SCRIPT,
            "client_email": XSS_SVG,
            "estimated_value_usd": 1000,
            "quoted_fee_usd": 500,
        },
        engagement={
            "status": "not_engaged",
            "days_remaining": None,
            "started_at": None,
            "fee_paid_usd": None,
            "closed_at": None,
        },
        artifacts=[],
        token="tok-{}".format(BIDI),
        expires_at=None,
    )
    assert XSS_SCRIPT not in html
    assert XSS_TD_BREAK not in html
    assert XSS_SVG not in html


# ---------- Helper context builders ---------- #


def _all_payloads() -> list[str]:
    return [XSS_SCRIPT, XSS_SVG, XSS_TD_BREAK, URL_JAVASCRIPT, URL_DATA]


def _minimal_le_context() -> dict:
    """Minimal context covering all sections of le.html.j2 and
    issuer_freeze_request.html.j2. Every URL field carries an
    adversarial javascript: payload so we can assert it's neutered."""
    adversarial_url = URL_JAVASCRIPT
    return {
        "case_id": "CASE-001",
        "case_number": "CASE-001",
        "investigator": {
            "name": "Test Investigator",
            "entity": "Recupero",
            "email": "investigator@example.com",
            "address": "1 Main St, Berlin",
            "jurisdiction": "DE",
        },
        "victim": {
            "name": "Alice " + BIDI,
            "wallet_address": "0xVictim" + ("0" * 36),
            "jurisdiction": "US",
        },
        "victim_wallet_explorer_url": adversarial_url,
        "asset_contract_explorer_url": adversarial_url,
        "asset": {
            "symbol": "USDT",
            "contract": SQL_QUOTE,
            "amount_human": "1,000.00",
            "total_amount_human": "1,000.00",
            "usd_value_at_theft": "1,000.00",
            "total_usd_value_at_theft": "1,000.00",
            "is_multi_event": False,
            "theft_event_count": 1,
            "issuer_known_freezable": True,
        },
        "theft_event": {
            "timestamp_human": "2025-01-01 00:00:00",
            "block_number": 1,
            "tx_hash": "0xtx" + ("1" * 60),
            "explorer_url": adversarial_url,
            "from_address": "0xfrom" + ("0" * 35),
            "from_explorer_url": adversarial_url,
            "to_address": "0xto" + ("0" * 37),
            "to_explorer_url": adversarial_url,
        },
        "hops": [
            {
                "timestamp_human": "2025-01-01 00:01:00",
                "tx_hash": "0xhop" + ("2" * 60),
                "explorer_url": adversarial_url,
                "from_address": "0xhf" + ("0" * 38),
                "from_explorer_url": adversarial_url,
                "to_address": "0xht" + ("0" * 38),
                "to_explorer_url": adversarial_url,
                "amount_human": "999.0",
                "symbol": "USDT",
            },
        ],
        "current_holder": {
            "address": "0xCurrent" + ("0" * 35),
            "explorer_url": adversarial_url,
        },
        "primary_chain_explorer_name": "Etherscan",
        "verified_at": "2025-05-22T00:00:00Z",
        "outbound_count_of_stolen_asset": 0,
        "forwarding_observed": False,
        "issuer": {
            "name": "Tether Limited",
            "short_name": "Tether",
            "compliance_address": "compliance@tether.to",
            "freeze_capability": "freezable",
            "asset_class": "stablecoin",
        },
        "evidence_mode": "current_holding",
        "freeze_brief": {},
        "case": {
            "case_id": "CASE-001",
            "case_number": "CASE-001",
            "chain": "ethereum",
        },
        "freezable_holdings": [
            {
                "address": "0xH" + ("0" * 39),
                "explorer_url": URL_DATA,  # different payload variant
                "balance_human": "500.0",
                "balance_usd_human": "$500.00",
                "issuer": "Tether",
                "symbol": "USDT",
                "evidence_type": "current_holding",
            },
        ],
        "frozen_holdings": [],
        "holdings_by_wallet": [],
        "wallets_with_holdings": [],
        "history_of_funds_after_theft": [],
        "le_routing": {
            "us_federal_routes": [
                {
                    "name": "FBI IC3",
                    "jurisdiction": "US-Federal",
                    "url": URL_JAVASCRIPT,
                    "email": "ic3@fbi.gov",
                    "phone": "+1-555-0100",
                    "expected_response": "30 days",
                    "description": "Internet crime portal",
                },
            ],
            "state_routes": [],
            "escalation_routes": [],
        },
        "preservation_summary": {
            "letters_sent": 0,
            "letters_pending": 0,
            "cex_targets": [],
        },
        "exchange_targets": [],
        "downstream_exchanges": [],
        "software_version": "test",
        "generated_at": "2025-05-22T00:00:00Z",
        "brief_id": "BRIEF-001",
        "report_title": "Test Brief",
    }


def _minimal_trace_report_context() -> dict:
    return {
        "case_id": "CASE-002",
        "case_number": "CASE-002",
        "case": {
            "case_id": "CASE-002",
            "case_number": "CASE-002",
            "chain": "ethereum",
            "client_name": "Alice",
        },
        "victim": {
            "name": "Alice",
            "wallet_address": "0xvictim" + ("0" * 33),
        },
        "wallet_address": "0xvictim" + ("0" * 33),
        "wallet_explorer_url": URL_JAVASCRIPT,
        "label": "Test Label",
        "investigation_id": "INV-001",
        "generated_at": "2025-05-22T00:00:00Z",
        "software_version": "test",
        "report_id": "REP-001",
        "destinations": [
            {
                "address_short": "0xdest…abc",
                "explorer_url": URL_DATA,
                "total_received_usd": "$100.00",
                "label": XSS_SCRIPT,
                "kind": "cex",
            },
        ],
        "freezable_destinations": [
            {
                "address_short": "0xfree…abc",
                "explorer_url": URL_JAVASCRIPT,
                "balance_usd": "$500.00",
                "label": "Tether",
            },
        ],
        "handoffs": [
            {
                "source_address": "0xsrc" + ("0" * 36),
                "tx_explorer_url": URL_JAVASCRIPT,
                "follow_up_url": URL_DATA,
                "exchange_name": XSS_TD_BREAK,
                "deposit_address": "0xdep" + ("0" * 36),
            },
        ],
        "summary": {
            "total_usd_traced": "$1,000.00",
            "destination_count": 1,
            "hop_count": 1,
            "freezable_count": 1,
            "frozen_count": 0,
        },
        "trace_summary": {
            "total_usd_traced": "$1,000.00",
            "destination_count": 1,
            "hop_count": 1,
        },
        "flow_filename": "flow.svg",
        "asset": {
            "symbol": "USDT",
            "contract": "0xcontract" + ("0" * 31),
            "amount_human": "1000.0",
            "usd_value_at_theft": "$1,000.00",
        },
        "theft_event": {
            "timestamp_human": "2025-01-01",
            "tx_hash": "0xtx" + ("1" * 60),
            "explorer_url": URL_JAVASCRIPT,
            "from_address": "0xfrom",
            "to_address": "0xto",
        },
    }


def _minimal_mini_freeze_context() -> dict:
    return {
        "digest_id": "DIGEST-001",
        "generated_at_human": "2025-05-22 00:00 UTC",
        "tick_date": "2025-05-22",
        "now_iso": "2025-05-22T00:00:00Z",
        "candidates": [
            {
                "address": "0xcand" + ("0" * 35),
                "address_short": "0xcand…abc",
                "explorer_url": URL_JAVASCRIPT,
                "balance_usd_human": "$500.00",
                "balance_token_human": "500 USDT",
                "chain": "ethereum",
                "issuer": "Tether",
                "label": XSS_SCRIPT,
                "case_id": "CASE-001",
                "freeze_recommended": True,
                "victim_name": "Alice",
                "deposit_to_cex_tx_hash": None,
                "cex_deposit_match": False,
                "explanation": "test",
                "symbol": "USDT",
                "token_contract": "0xtoken",
                "balance_token": "500",
                "balance_usd": 500,
                "score": 0.9,
                "scoring_factors": [],
                "first_seen_at": "2025-05-21",
                "last_seen_at": "2025-05-22",
            },
        ],
        "total_watched": 1,
        "stats": {
            "n_candidates": 1,
            "n_recommended_freeze": 1,
            "total_usd_at_risk_human": "$500.00",
        },
        "software_version": "test",
        # The mini-freeze digest template uses these as scalar counters in
        # `{% if x > 0 %}` comparisons — ChainableUndefined supports
        # attribute access but not arithmetic, so supply real ints.
        "freezeable_count": 1,
        "recoverable_count": 0,
        "unrecoverable_count": 0,
        "total_candidates": 1,
        "material_count": 1,
        "low_value_count": 0,
        "dust_count": 0,
    }


def _minimal_exchange_subpoena_context() -> dict:
    return {
        "case_id": "CASE-003",
        "case_number": "CASE-003",
        "investigator": {
            "name": "Investigator",
            "entity": "Recupero",
            "email": "i@example.com",
            "jurisdiction": "DE",
            "address": "Berlin",
        },
        "victim": {
            "name": "Alice",
            "wallet_address": "0xvictim",
            "jurisdiction": "US",
        },
        "case": {
            "case_id": "CASE-003",
            "case_number": "CASE-003",
            "chain": "ethereum",
        },
        "asset": {"symbol": "USDT", "contract": "0xcontract"},
        "theft_event": {
            "timestamp_human": "2025-01-01",
            "tx_hash": "0xtx",
            "explorer_url": URL_JAVASCRIPT,
        },
        "perpetrator": {
            "exchange_name": XSS_TD_BREAK,
            "exchange_legal_name": "Test CEX Inc.",
            "exchange_jurisdiction": "Seychelles",
            "exchange_compliance_email": "compliance@cex.example",
            "deposit_addresses": ["0xdep" + ("0" * 36)],
            "total_usd_to_exchange_human": "$500.00",
            "earliest_deposit_human": "2025-01-02",
            "latest_deposit_human": "2025-01-03",
            "n_deposits": 1,
        },
        "flows": [
            {
                "upstream_address": "0xupstream" + ("0" * 31),
                "upstream_explorer_url": URL_JAVASCRIPT,
                "cex_address": "0xcex" + ("0" * 36),
                "cex_explorer_url": URL_DATA,
                "exchange": XSS_TD_BREAK,
                "flow_usd_value": "$500.00",
                "earliest_deposit_human": "2025-01-02",
                "n_deposits": 1,
                "tx_hash": "0xflow" + ("0" * 60),
            },
        ],
        "generated_at": "2025-05-22T00:00:00Z",
        "software_version": "test",
        "request_id": "EXSUB-001",
    }


def _minimal_mlat_context() -> dict:
    return {
        "case_id": "CASE-004",
        "case_number": "CASE-004",
        "investigator": {
            "name": "Investigator",
            "entity": "Recupero",
            "email": "i@example.com",
            "jurisdiction": "DE",
            "address": "Berlin",
        },
        "victim": {
            "name": "Alice",
            "wallet_address": "0xvictim",
            "jurisdiction": "US",
        },
        "asset": {
            "symbol": "USDT",
            "contract": "0xcontract",
            "usd_value_at_theft": "$1,000.00",
            "amount_human": "1000.0",
        },
        "theft_event": {
            "timestamp_human": "2025-01-01",
            "tx_hash": "0xtx",
            "explorer_url": URL_JAVASCRIPT,
        },
        "case": {
            "case_id": "CASE-004",
            "case_number": "CASE-004",
            "chain": "ethereum",
        },
        "perpetrator": {
            "exchange_name": "Test CEX",
            "exchange_legal_name": "Test CEX Inc.",
            "exchange_jurisdiction": "Seychelles",
            "exchange_compliance_email": "compliance@cex.example",
            "deposit_addresses": ["0xdep" + ("0" * 36)],
            "total_usd_to_exchange_human": "$500.00",
            "earliest_deposit_human": "2025-01-02",
            "latest_deposit_human": "2025-01-03",
            "n_deposits": 1,
        },
        "transactions": [
            {
                "tx_hash": "0xtx1" + ("0" * 60),
                "explorer_url": URL_JAVASCRIPT,
                "timestamp_human": "2025-01-02",
                "from_address": "0xfrom",
                "to_address": "0xto",
                "amount_human": "100.0",
                "symbol": "USDT",
            },
        ],
        "generated_at": "2025-05-22T00:00:00Z",
        "software_version": "test",
        "request_id": "MLAT-001",
    }


def _minimal_engagement_letter_context() -> dict:
    return {
        "case_id": "CASE-005",
        "case_number": "CASE-005",
        "case": {
            "case_id": "CASE-005",
            "case_number": "CASE-005",
            "client_name": "Alice",
            "quoted_fee_usd": 500,
            "estimated_value_usd": 10000,
        },
        "investigator": {
            "name": "Investigator",
            "entity": "Recupero",
            "email": "investigator@example.com",
            "address": "Berlin",
        },
        "client_name": "Alice",
        "client_email": "alice@example.com",
        "fee_paid_usd": 500,
        "initial_fee_usd": 500,
        "engagement_fee_usd": 500,
        "total_freezable_usd": 1000,
        "total_suspected_usd": 5000,
        "contingency_pct": 15,
        "generated_at": "2025-05-22T00:00:00Z",
        "software_version": "test",
        "investigator_jurisdiction": "DE",
        "freeze_brief": {},
        "victim": {"name": "Alice", "jurisdiction": "US"},
    }
