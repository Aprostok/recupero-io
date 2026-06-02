"""Tests for the client-safe fund-flow journey builder + portal route.

The journey projection (``reports.client_journey.build_journey_data``)
must (a) never leak operator-internal identity strings for plain
intermediary wallets, (b) map classifier categories to client-facing
recoverability buckets, (c) cluster same-entity addresses, and (d)
stay JSON-serializable with ``allow_nan=False``. The portal ``/graph``
route must serve the embedded page under a nonce-scoped CSP (the global
portal CSP is ``script-src 'none'``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.reports.client_journey import build_journey_data

VICTIM = "0x" + "a" * 40
PERP = "0x" + "b" * 40
EXCH1 = "0x" + "c" * 40
EXCH2 = "0x" + "d" * 40
MIX = "0x" + "e" * 40


def _label(addr: str, *, category: LabelCategory, name: str) -> Label:
    return Label(
        address=addr, name=name, category=category,
        source="test", confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal = Decimal("1000"),
    tx_hash: str | None = None,
    counterparty_label: Label | None = None,
    chain: Chain = Chain.ethereum,
    ts_day: int = 1,
) -> Transfer:
    ts = datetime(2026, 1, ts_day, tzinfo=UTC)
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
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


# ---- builder shape ---- #


def test_journey_has_expected_shape() -> None:
    case = _case([_transfer(from_addr=VICTIM, to_addr=PERP)])
    j = build_journey_data(case)
    for key in ("nodes", "edges", "clusters", "statusTotals", "meta"):
        assert key in j, key
    assert j["meta"]["chain"] == "ethereum"


def test_victim_is_origin_status() -> None:
    case = _case([_transfer(from_addr=VICTIM, to_addr=PERP)])
    j = build_journey_data(case)
    v = next(n for n in j["nodes"] if n["id"] == VICTIM)
    assert v["status"] == "origin"
    assert v["label"] == "Your funds (origin)"


def test_exchange_node_uses_identity_and_exchange_status() -> None:
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit,
                name="Binance Hot Wallet"),
        ),
    ])
    j = build_journey_data(case)
    ex = next(n for n in j["nodes"] if n["id"] == EXCH1)
    assert ex["status"] == "exchange"
    # Endpoint entities keep their identity label so the client knows
    # WHERE recovery is actionable.
    assert ex["label"] == "Binance Hot Wallet"


def test_intermediary_wallet_is_sanitized() -> None:
    """A plain pass-through wallet must never surface a raw identity —
    only the generic friendly label."""
    case = _case([_transfer(from_addr=VICTIM, to_addr=PERP)])
    j = build_journey_data(case)
    perp = next(n for n in j["nodes"] if n["id"] == PERP)
    assert perp["status"] == "intermediary"
    assert perp["label"] == "Intermediary wallet"


def test_mixer_is_unrecoverable() -> None:
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("9000")),
        _transfer(
            from_addr=PERP, to_addr=MIX, usd=Decimal("8500"),
            tx_hash="0x" + "3" * 64,
            counterparty_label=_label(
                MIX, category=LabelCategory.mixer, name="Tornado Cash"),
        ),
    ])
    j = build_journey_data(case)
    mix = next(n for n in j["nodes"] if n["id"] == MIX)
    assert mix["status"] == "unrecoverable"


def test_status_totals_terminal_only_and_ordered() -> None:
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit,
                name="Binance"),
        ),
        _transfer(
            from_addr=PERP, to_addr=MIX, usd=Decimal("4000"),
            tx_hash="0x" + "3" * 64,
            counterparty_label=_label(
                MIX, category=LabelCategory.mixer, name="Tornado Cash"),
        ),
    ])
    j = build_journey_data(case)
    statuses = [s["status"] for s in j["statusTotals"]]
    # Terminal buckets only — origin / intermediary are excluded.
    assert "origin" not in statuses
    assert "intermediary" not in statuses
    assert "exchange" in statuses and "unrecoverable" in statuses
    # Ordered by the metadata order field (exchange before unrecoverable).
    assert statuses.index("exchange") < statuses.index("unrecoverable")


def test_same_entity_addresses_cluster() -> None:
    """Two exchange addresses sharing an identity collapse into one
    expandable cluster the client can open/close."""
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("25000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit,
                name="Binance"),
        ),
        _transfer(
            from_addr=PERP, to_addr=EXCH2, usd=Decimal("20000"),
            tx_hash="0x" + "4" * 64,
            counterparty_label=_label(
                EXCH2, category=LabelCategory.exchange_deposit,
                name="Binance"),
        ),
    ])
    j = build_journey_data(case)
    assert len(j["clusters"]) == 1
    cl = j["clusters"][0]
    assert cl["size"] == 2
    assert cl["status"] == "exchange"
    member_ids = set(cl["memberIds"])
    assert member_ids == {EXCH1, EXCH2}
    for n in j["nodes"]:
        if n["id"] in member_ids:
            assert n["clusterId"] == cl["id"]


def test_summary_line_present_when_terminal_funds() -> None:
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit,
                name="Binance"),
        ),
    ])
    j = build_journey_data(case)
    assert j["meta"]["summaryLine"]
    assert "exchange" in j["meta"]["summaryLine"].lower()


def test_hop_depths_increase_from_origin() -> None:
    """Flow-layout depth: victim at 0, its counterparty at 1, the next
    hop at 2."""
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit, name="Binance"),
        ),
    ])
    j = build_journey_data(case)
    depth = {n["id"]: n["depth"] for n in j["nodes"]}
    assert depth[VICTIM] == 0
    assert depth[PERP] == 1
    assert depth[EXCH1] == 2
    assert j["meta"]["maxDepth"] == 2


def test_edges_carry_time_and_meta_has_range_and_assets() -> None:
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("9000"),
                  ts_day=1),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("8000"),
            tx_hash="0x" + "2" * 64, ts_day=15,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit, name="Binance"),
        ),
    ])
    j = build_journey_data(case)
    assert all("firstTime" in e and "lastTime" in e for e in j["edges"])
    assert j["meta"]["assets"] == ["USDT"]
    tr = j["meta"]["timeRange"]
    assert tr and tr["min"] == "2026-01-01" and tr["max"] == "2026-01-15"


def test_edges_carry_capped_transactions() -> None:
    """Edge drill-down: each edge exposes its transactions (top-N by USD)
    with a disclosed remainder count."""
    txs = [
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal(str(1000 + i)),
                  tx_hash="0x" + f"{i:064x}", ts_day=(i % 27) + 1)
        for i in range(20)
    ]
    j = build_journey_data(_case(txs))
    edge = next(e for e in j["edges"] if e["source"] == VICTIM and e["target"] == PERP)
    assert len(edge["transfers"]) == 12          # _MAX_EDGE_TX
    assert edge["txMore"] == 8                    # 20 - 12 disclosed
    # Sorted by USD descending; each tx is sanitized public data.
    usds = [t["usd"] for t in edge["transfers"]]
    assert usds == sorted(usds, reverse=True)
    assert all("txUrl" in t and "date" in t and "token" in t for t in edge["transfers"])


def test_node_exposure_breakdown_by_neighbor_category() -> None:
    """A wallet's received-from / sent-to USD is split by the neighbor's
    recoverability status — the data behind the exposure donut."""
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit, name="Binance"),
        ),
        _transfer(
            from_addr=PERP, to_addr=MIX, usd=Decimal("4000"),
            tx_hash="0x" + "3" * 64,
            counterparty_label=_label(
                MIX, category=LabelCategory.mixer, name="Tornado Cash"),
        ),
    ])
    j = build_journey_data(case)
    perp = next(n for n in j["nodes"] if n["id"] == PERP)
    assert perp["inByCategory"] == {"origin": 50000.0}
    assert perp["outByCategory"]["exchange"] == 45000.0
    assert perp["outByCategory"]["unrecoverable"] == 4000.0


def test_journey_json_serializable_allow_nan_false() -> None:
    """The whole projection must serialize with allow_nan=False so the
    embedded <script type=application/json> block is JSON.parse-safe."""
    case = _case([
        _transfer(from_addr=VICTIM, to_addr=PERP, usd=Decimal("50000")),
        _transfer(
            from_addr=PERP, to_addr=EXCH1, usd=Decimal("45000"),
            tx_hash="0x" + "2" * 64,
            counterparty_label=_label(
                EXCH1, category=LabelCategory.exchange_deposit,
                name="Binance"),
        ),
    ])
    j = build_journey_data(case)
    # Must not raise.
    json.dumps(j, allow_nan=False)


def test_empty_case_has_only_origin_and_no_terminal_totals() -> None:
    j = build_journey_data(_case([]))
    assert len(j["nodes"]) >= 1
    assert all(n["status"] == "origin" for n in j["nodes"])
    assert j["statusTotals"] == []


# ---- portal /graph route ---- #


def _mk_verified(**overrides):
    from recupero.portal.tokens import VerifiedToken
    base = {
        "token_id": uuid4(),
        "case_id": uuid4(),
        "case_number": "V-GRAPH1",
        "client_name": "Map Viewer",
        "client_email": "v@example.com",
        "case_status": "complete",
        "case_state": None,
        "estimated_value_usd": Decimal("50000"),
        "quoted_fee_usd": Decimal("10000"),
        "investigation_id": uuid4(),
        "engagement_started_at": None,
        "engagement_closed_at": None,
        "engagement_fee_paid_usd": None,
        "expires_at": datetime.now(UTC) + timedelta(days=30),
        "label": None,
    }
    base.update(overrides)
    return VerifiedToken(**base)


_FAKE_JOURNEY = {
    "nodes": [
        {"id": VICTIM, "label": "Your funds (origin)", "short": "0xaa…aaaa",
         "status": "origin", "statusLabel": "Your funds (origin)",
         "statusColor": "#1D4ED8", "chain": "ethereum", "chainColor": "#5B6CFF",
         "inboundUsd": "$0.00", "outboundUsd": "$50,000.00",
         "explorerUrl": f"https://etherscan.io/address/{VICTIM}",
         "clusterId": None},
    ],
    "edges": [],
    "clusters": [],
    "statusTotals": [
        {"status": "exchange", "label": "At a regulated exchange",
         "color": "#15803D", "blurb": "…", "usd": 45000.0,
         "usdLabel": "$45,000.00", "count": 1},
    ],
    "meta": {"nodeCount": 1, "edgeCount": 0, "totalUsdTraced": "$45,000.00",
             "chain": "ethereum", "truncated": False, "hiddenNodeCount": 0,
             "summaryLine": "The largest traced share of your funds is at a regulated exchange."},
}


def test_graph_route_renders_with_nonce_csp() -> None:
    from recupero.portal.server import handle_portal
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._load_journey", return_value=_FAKE_JOURNEY), \
         patch("recupero.portal.server._fetch_run_activity", return_value=[]):
        code, body, headers = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/graph",
            body_bytes=b"", headers={},
        )
    assert code == 200
    assert headers["Content-Type"].startswith("text/html")
    csp = headers["Content-Security-Policy"]
    # Global portal CSP is script-src 'none'; this route must relax to a
    # nonce — and that exact nonce must appear on the page's <script>.
    assert "script-src 'nonce-" in csp
    nonce = csp.split("script-src 'nonce-", 1)[1].split("'", 1)[0]
    assert nonce
    assert f'nonce="{nonce}"'.encode() in body
    assert b"script-src 'none'" not in csp.encode()
    assert b"journey-data" in body
    assert b"V-GRAPH1" in body


def test_graph_route_empty_state_when_no_journey() -> None:
    from recupero.portal.server import handle_portal
    verified = _mk_verified()
    with patch("recupero.portal.server.verify_token", return_value=verified), \
         patch("recupero.portal.server._get_dsn", return_value="fake-dsn"), \
         patch("recupero.portal.server._load_journey", return_value=None), \
         patch("recupero.portal.server._fetch_run_activity", return_value=[]):
        code, body, _ = handle_portal(
            method="GET",
            path="/portal/some-43-char-valid-token-for-this-test/graph",
            body_bytes=b"", headers={},
        )
    assert code == 200
    assert b"will appear here once your" in body
    # No data block / inline graph script when there's no map yet.
    assert b"journey-data" not in body


def test_safe_journey_json_escapes_script_close() -> None:
    from recupero.portal.server import _safe_journey_json
    malicious = {"nodes": [{"label": "</script><img src=x onerror=alert(1)>"}]}
    out = _safe_journey_json(malicious)
    assert "</script>" not in out
    assert "<\\/script>" in out
    # Still valid JSON.
    assert "img src=x" in out  # content preserved, just escaped boundary
