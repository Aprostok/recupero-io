"""Tests for v0.13.6 interactive graph UI renderer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import Case, Chain, Counterparty, Label, LabelCategory, TokenRef, Transfer
from recupero.reports.graph_ui import (
    GraphEdge,
    GraphNode,
    build_graph_data,
    render_graph_html,
)


VICTIM = "0x" + "a" * 40
PERP = "0x" + "b" * 40
EXCH = "0x" + "c" * 40


def _label(addr: str, *, category: LabelCategory, name: str) -> Label:
    return Label(
        address=addr, name=name, category=category,
        source="test", confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal = Decimal("1000"),
    tx_hash: str | None = None,
    counterparty_label: Label | None = None,
    chain: Chain = Chain.ethereum,
) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tx_hash = tx_hash or "0x" + "1" * 64
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=counterparty_label, is_contract=False,
        ),
        token=TokenRef(
            chain=chain,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDT", decimals=6, coingecko_id="tether",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="V-CFI01",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


# ---- build_graph_data ---- #


def test_build_graph_data_produces_nodes_and_edges() -> None:
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(from_addr=PERP, to_addr=EXCH, usd=Decimal("45000"),
                  tx_hash="0x" + "2" * 64,
                  counterparty_label=_label(
                      EXCH, category=LabelCategory.exchange_deposit,
                      name="Binance Hot Wallet")),
    ]
    case = _case(transfers)
    data = build_graph_data(case)
    assert "nodes" in data
    assert "edges" in data
    assert "meta" in data
    node_ids = {n["id"] for n in data["nodes"]}
    assert VICTIM in node_ids
    assert PERP in node_ids
    assert EXCH in node_ids


def test_victim_node_has_victim_category() -> None:
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP)]
    case = _case(transfers)
    data = build_graph_data(case)
    victim_node = next(n for n in data["nodes"] if n["id"] == VICTIM)
    assert victim_node["isVictim"] is True
    assert victim_node["category"] == "victim"


def test_chain_color_set_per_node() -> None:
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP)]
    case = _case(transfers)
    data = build_graph_data(case)
    # Ethereum chain → blue (#5B6CFF).
    assert all(n["chainColor"] == "#5B6CFF" for n in data["nodes"])


def test_edge_usd_formatted_and_numeric() -> None:
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("12500.50")),
    ]
    case = _case(transfers)
    data = build_graph_data(case)
    edge = data["edges"][0]
    assert edge["totalUsd"] == "$12,500.50"
    assert edge["totalUsdNumeric"] == 12500.50


def test_explorer_url_set_for_ethereum() -> None:
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP)]
    case = _case(transfers)
    data = build_graph_data(case)
    perp_node = next(n for n in data["nodes"] if n["id"] == PERP)
    assert perp_node["explorerUrl"] == f"https://etherscan.io/address/{PERP}"


def test_meta_carries_case_aggregates() -> None:
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("1000")),
        _transfer(from_addr=PERP, to_addr=EXCH, usd=Decimal("900"),
                  tx_hash="0x" + "2" * 64),
    ]
    case = _case(transfers)
    data = build_graph_data(case)
    meta = data["meta"]
    assert meta["case_id"] == "V-CFI01"
    assert meta["seed_address"] == VICTIM
    assert meta["node_count"] == 3
    assert meta["edge_count"] == 2
    assert meta["chain"] == "ethereum"


def test_empty_case_produces_only_victim_node() -> None:
    """A case with no transfers should still emit at least the
    victim node so the rendered graph doesn't be entirely empty."""
    case = _case([])
    data = build_graph_data(case)
    # Aggregator may or may not include victim when no transfers; both
    # outcomes are valid — but the meta should be coherent.
    assert data["meta"]["node_count"] == len(data["nodes"])
    assert data["meta"]["edge_count"] == len(data["edges"])


# ---- render_graph_html ---- #


def test_render_html_writes_file_with_embedded_data() -> None:
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("1000"))]
    case = _case(transfers)
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        assert out_path.exists()
        html = out_path.read_text(encoding="utf-8")
        # Self-contained HTML.
        assert "<html" in html
        assert "</html>" in html
        # D3.js CDN reference.
        assert "d3.min.js" in html
        # Embedded graph data — search for the case_id string.
        assert "V-CFI01" in html
        # Both node IDs appear (data embedded as JSON).
        assert VICTIM in html
        assert PERP in html


def test_render_html_includes_explorer_links() -> None:
    """The tooltip surfaces explorer URLs — verify they make it
    into the rendered HTML."""
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP)]
    case = _case(transfers)
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")
        assert "etherscan.io/address/" in html


def test_render_html_includes_chain_legend() -> None:
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP)]
    case = _case(transfers)
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")
        # Chain pills in the legend.
        assert "Ethereum" in html
        assert "Bitcoin" in html
        assert "Tron" in html
        assert "Solana" in html


def test_embedded_graph_data_is_valid_json() -> None:
    """The rendered HTML embeds graph data as a JSON literal — it
    must parse back as valid JSON when extracted.

    v0.18.2 (round-11 sec-CRIT-001): the embed shape changed from
    `const graphData = {...};` (inside <script>, XSS vulnerable) to
    `<script id="graph-data" type="application/json">{...}</script>`
    (browser does NOT execute these; JSON.parse'd at runtime). The
    JSON content is identical; only the wrapping changed.
    """
    transfers = [_transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("1234.56"))]
    case = _case(transfers)
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")
        # Extract between the new application/json script tag.
        import re
        match = re.search(
            r'<script id="graph-data" type="application/json">(.*?)</script>',
            html, re.DOTALL,
        )
        assert match is not None, (
            "graph data not found inside application/json script block "
            "— v0.18.2 XSS-mitigation embed shape regressed"
        )
        json_text = match.group(1)
        parsed = json.loads(json_text)
        assert parsed["meta"]["case_id"] == "V-CFI01"
        assert len(parsed["nodes"]) == 2  # victim + perp


def test_graph_data_escapes_script_breakout() -> None:
    """v0.18.2 (round-11 sec-CRIT-001): the data-layer escape
    replaces `</script>` substrings with `<\\/script>` so even a
    non-strict HTML parser that ignored the application/json
    type can't be tricked. We pin this defense-in-depth here so
    a future refactor doesn't accidentally remove it.
    """
    # Build a Label with the dangerous substring and inject via
    # counterparty_label so it flows into the graph_data labels.
    xss_label = Label(
        address=PERP,
        name="</script><img src=x>",  # XSS attempt in label
        category=LabelCategory.exchange_deposit,
        source="test",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    transfers = [_transfer(
        from_addr=VICTIM, to_addr=PERP, usd=Decimal("100"),
        counterparty_label=xss_label,
    )]
    case = _case(transfers)
    graph_data = build_graph_data(case)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.html"
        render_graph_html(graph_data, out_path)
        html = out_path.read_text(encoding="utf-8")
        # The dangerous substring must be escaped in the embedded JSON.
        import re
        match = re.search(
            r'<script id="graph-data" type="application/json">(.*?)</script>',
            html, re.DOTALL,
        )
        assert match is not None
        # The escaped form `<\/script>` should NOT contain a literal `</script>`.
        assert "</script>" not in match.group(1), (
            "unescaped </script> inside graph-data block — XSS regression"
        )


# ---- GraphNode / GraphEdge to_dict ---- #


def test_graph_node_to_dict_shape() -> None:
    n = GraphNode(
        id="0xabc", label="Test", short="0xabc…",
        chain="ethereum", chain_color="#5B6CFF",
        category="wallet", identity=None,
        inbound_usd="$1,000.00", outbound_usd="$500.00",
        is_victim=False, issuer=None,
        explorer_url="https://etherscan.io/address/0xabc",
    )
    d = n.to_dict()
    assert d["id"] == "0xabc"
    assert d["chainColor"] == "#5B6CFF"
    assert d["isVictim"] is False
    assert d["explorerUrl"] == "https://etherscan.io/address/0xabc"


def test_graph_edge_to_dict_shape() -> None:
    e = GraphEdge(
        source="0xabc", target="0xdef",
        total_usd="$1,234.56", total_usd_numeric=1234.56,
        transfer_count=3, dominant_symbol="USDT",
        first_time="2026-01-01T00:00:00Z",
        last_time="2026-01-02T00:00:00Z",
        is_cross_chain=False,
    )
    d = e.to_dict()
    assert d["source"] == "0xabc"
    assert d["totalUsd"] == "$1,234.56"
    assert d["totalUsdNumeric"] == 1234.56
    assert d["isCrossChain"] is False
