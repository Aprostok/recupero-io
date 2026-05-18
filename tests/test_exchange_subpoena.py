"""Tests for v0.14.11 exchange-subpoena letter rendering."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.reports.legal_requests import (
    LEGAL_REQUEST_TYPES,
    render_legal_request,
)


def _flow(
    *,
    upstream: str = "0x" + "a" * 40,
    cex: str = "0x" + "b" * 40,
    exchange: str = "Binance",
    token: str = "USDT",
    usd: str = "45000",
    tx_hash: str = "0x" + "1" * 64,
) -> dict:
    return {
        "upstream_address": upstream,
        "cex_address": cex,
        "chain": "ethereum",
        "exchange": exchange,
        "label_name": f"{exchange}: Hot Wallet",
        "label_category": "exchange_hot_wallet",
        "token_symbol": token,
        "flow_usd_value": usd,
        "flow_amount_decimal": usd,
        "transfer_count": 1,
        "first_flow_at": "2025-10-14T00:00:00Z",
        "last_flow_at": "2025-10-14T00:00:00Z",
        "upstream_explorer_url": f"https://etherscan.io/address/{upstream}",
        "cex_explorer_url": f"https://etherscan.io/address/{cex}",
        "tx_hashes": [tx_hash],
    }


def _brief_with_flows(flows: list[dict]) -> dict:
    return {
        "CASE_ID": "V-CFI01",
        "VICTIM_NAME": "Jane Doe",
        "VICTIM_JURISDICTION": "California, USA",
        "INVESTIGATOR_NAME": "Test Investigator",
        "INVESTIGATOR_EMAIL": "test@recupero.io",
        "INVESTIGATOR_ENTITY_FULL": "Recupero LLC",
        "INCIDENT_DATE": "2025-10-09",
        "INCIDENT_TYPE": "seed-phrase compromise",
        "TOTAL_LOSS_USD": "$3,121,241.25",
        "IC3_CASE_ID": None,
        "_freeze_asks": {
            "by_issuer": {}, "exchange_deposits": [],
            "onward_cex_flows": flows,
        },
    }


# ---- Type registered ---- #


def test_exchange_subpoena_in_legal_request_types() -> None:
    """The new type must be in the type tuple so the CLI accepts it."""
    assert "exchange-subpoena" in LEGAL_REQUEST_TYPES


# ---- Per-exchange consolidation ---- #


def test_one_flow_one_exchange_produces_one_letter() -> None:
    brief = _brief_with_flows([
        _flow(exchange="Binance", usd="45000"),
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        assert len(renders) == 1
        r = renders[0]
        assert r.exchange_name == "Binance"
        assert r.output_path.exists()
        html = r.output_path.read_text(encoding="utf-8")
        # Cover page mentions Binance + the upstream + the flow USD.
        assert "Binance" in html
        assert "$45,000.00" in html
        assert "USDT" in html


def test_multiple_flows_same_exchange_consolidate_into_one_letter() -> None:
    """Jacob's pattern: 3 USDT addresses all forwarding to Binance hot
    wallets should produce ONE Binance letter listing all 3 flows."""
    brief = _brief_with_flows([
        _flow(upstream="0xup1", exchange="Binance", usd="170687",
              tx_hash="0xtx1"),
        _flow(upstream="0xup2", exchange="Binance", usd="82277",
              tx_hash="0xtx2"),
        _flow(upstream="0xup3", exchange="Binance", usd="1597",
              tx_hash="0xtx3"),
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        assert len(renders) == 1
        html = renders[0].output_path.read_text(encoding="utf-8")
        # Total banner sums all 3.
        assert "$254,561.00" in html
        # All 3 tx hashes appear (verification section).
        assert "0xtx1" in html
        assert "0xtx2" in html
        assert "0xtx3" in html


def test_multiple_exchanges_produce_separate_letters() -> None:
    """Flows to Binance + Coinbase + Kraken → 3 separate letters."""
    brief = _brief_with_flows([
        _flow(exchange="Binance", usd="45000"),
        _flow(exchange="Coinbase", usd="120000", upstream="0xup2"),
        _flow(exchange="Kraken", usd="30000", upstream="0xup3"),
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        assert len(renders) == 3
        names = {r.exchange_name for r in renders}
        assert names == {"Binance", "Coinbase", "Kraken"}


# ---- Empty / no flows ---- #


def test_empty_onward_flows_returns_empty() -> None:
    """No onward-CEX flows in freeze_asks → no letters generated."""
    brief = _brief_with_flows([])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        assert renders == []


# ---- Exchange filter ---- #


def test_exchange_filter_narrows_to_one() -> None:
    brief = _brief_with_flows([
        _flow(exchange="Binance", usd="45000"),
        _flow(exchange="Coinbase", usd="120000", upstream="0xup2"),
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
            exchange_filter="binance",
        )
        assert len(renders) == 1
        assert renders[0].exchange_name == "Binance"


# ---- Compliance contact lookup ---- #


def test_known_exchange_resolves_compliance_email() -> None:
    """Binance / Coinbase / Kraken etc. should have hardcoded
    compliance emails in the letter."""
    brief = _brief_with_flows([_flow(exchange="Binance", usd="45000")])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "compliance@binance.com" in html


def test_unknown_exchange_emits_todo_placeholder() -> None:
    """A novel exchange not in the lookup table gets a TODO
    placeholder for the compliance email."""
    brief = _brief_with_flows([
        _flow(exchange="ObscureNewExchange", usd="45000"),
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "TODO" in html


# ---- LE reference rendering ---- #


def test_ic3_case_id_renders_as_le_reference() -> None:
    """When IC3_CASE_ID is set in the brief, it appears as the LE
    reference in the cover-meta + section 1."""
    brief = _brief_with_flows([_flow(exchange="Binance", usd="45000")])
    brief["IC3_CASE_ID"] = "IC3-2025-1234567"
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "IC3-2025-1234567" in html


# ---- HTML shape ---- #


def test_html_includes_required_sections() -> None:
    """Acceptance: the letter must include the 7 numbered sections
    (1 — Nature of Underlying Matter through 7 — Response Window)."""
    brief = _brief_with_flows([_flow(exchange="Binance", usd="45000")])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        for section in ("1. Nature", "2. On-Chain Evidence",
                         "3. Transaction Hashes", "4. Records Requested",
                         "5. Use and Confidentiality",
                         "6. Point of Contact", "7. Response Window"):
            assert section in html


def test_safe_filename_for_exchange_with_period() -> None:
    """Crypto.com / Gate.io etc. — period must NOT appear in the
    output filename (shell / URL safety)."""
    brief = _brief_with_flows([_flow(exchange="Crypto.com", usd="45000")])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="exchange-subpoena",
            output_dir=Path(tmp),
        )
        assert "." not in renders[0].output_path.stem
        assert renders[0].output_path.name == "exchange_subpoena_cryptocom.html"
