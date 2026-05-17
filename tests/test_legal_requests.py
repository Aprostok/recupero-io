"""Tests for v0.13.1 legal-request renderer."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.reports.legal_requests import (
    LEGAL_REQUEST_TYPES,
    render_legal_request,
)


def _minimal_brief(**overrides) -> dict:
    """A minimum-viable brief dict for rendering."""
    base = {
        "CASE_ID": "V-CFI-001",
        "VICTIM_NAME": "Jane Doe",
        "VICTIM_JURISDICTION": "California, USA",
        "INVESTIGATOR_NAME": "Test Investigator",
        "INVESTIGATOR_EMAIL": "test@recupero.io",
        "INVESTIGATOR_ENTITY_FULL": "Recupero LLC",
        "INCIDENT_DATE": "2026-04-01",
        "INCIDENT_TYPE": "wire-fraud scam",
        "TOTAL_LOSS_USD": "$48,200.00",
        "EXCHANGES": [
            {
                "exchange": "Binance",
                "exchange_legal_name": "Binance Holdings Ltd",
                "exchange_address": "Cayman Islands",
                "address": "0xbnb12345",
                "total_received_usd": "$25,000",
                "country": "Cayman Islands",
            },
            {
                "exchange": "Coinbase",
                "address": "0xcoinbase",
                "total_received_usd": "$15,000",
            },
        ],
        "CROSS_CHAIN_HANDOFFS": [],
        "DEX_SWAPS": [],
    }
    base.update(overrides)
    return base


# ---- Render basics ---- #


def test_renders_all_exchanges_by_default() -> None:
    """No exchange_filter → one document per exchange in the brief."""
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
        )
    assert len(renders) == 2
    exchange_names = {r.exchange_name for r in renders}
    assert exchange_names == {"Binance", "Coinbase"}


def test_exchange_filter_narrows_to_one() -> None:
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
            exchange_filter="binance",  # case-insensitive
        )
    assert len(renders) == 1
    assert renders[0].exchange_name == "Binance"


def test_invalid_request_type_raises() -> None:
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        with pytest.raises(ValueError, match="request_type must be"):
            render_legal_request(
                brief, request_type="bogus",
                output_dir=Path(tmp),
            )


@pytest.mark.parametrize("rtype", LEGAL_REQUEST_TYPES)
def test_each_template_renders(rtype: str) -> None:
    """Each of the three templates must render without exception
    against the minimal-brief fixture.

    Note: the subpoena template intentionally does NOT name the
    victim (proper drafting practice — the victim is identified
    in a sealed motion, not the served subpoena). MLAT and 314(b)
    DO name the victim because they're not served on the
    perpetrator.
    """
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type=rtype,
            output_dir=Path(tmp),
        )
        # Assertions must run INSIDE the with block — Windows cleans
        # up the temp dir on __exit__ which would invalidate the paths.
        assert len(renders) == 2
        for r in renders:
            assert r.output_path.exists()
            assert r.html_size_bytes > 1000  # real document, not stub
            html = r.output_path.read_text(encoding="utf-8")
            assert "Recupero" in html
            assert brief["CASE_ID"] in html
            if rtype in ("mlat", "314b"):
                # Victim is named in these. Subpoena intentionally omits.
                assert brief["VICTIM_NAME"] in html


# ---- Content checks ---- #


def test_mlat_includes_destination_country() -> None:
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="mlat",
            output_dir=Path(tmp),
            exchange_filter="binance",
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        # The Binance fixture has country=Cayman Islands
        assert "Cayman Islands" in html
        # MLAT-specific phrases
        assert "Mutual Legal Assistance" in html
        assert "Office of International Affairs" in html


def test_314b_includes_registration_id_placeholder() -> None:
    """314(b) requests show the requesting org's registration ID.
    When not in the brief, the template falls back to a TODO."""
    brief = _minimal_brief()  # no FINCEN_314B_ID set
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="314b",
            output_dir=Path(tmp),
            exchange_filter="coinbase",
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "314(b)" in html
        assert "TODO" in html  # ID placeholder surfaces


def test_subpoena_includes_predicate_evidence() -> None:
    """A subpoena should include the tx_evidence table for the
    AUSA's predicate-act section."""
    brief = _minimal_brief(
        CROSS_CHAIN_HANDOFFS=[{
            "tx_hash": "0xabc",
            "block_time": "2026-04-01T12:00:00Z",
            "amount_usd": "$5,000",
            "tx_explorer_url": "https://etherscan.io/tx/0xabc",
        }],
    )
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
            exchange_filter="binance",
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "0xabc" in html
        assert "$5,000" in html
        assert "Rule 17(c)" in html


def test_empty_exchanges_still_renders_template_stub() -> None:
    """When the brief has no EXCHANGES (e.g. early-pipeline cases),
    render ONE document with placeholder exchange info so the
    operator has a starting point."""
    brief = _minimal_brief(EXCHANGES=[])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
        )
        assert len(renders) == 1
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "[exchange name]" in html or "[deposit address]" in html


def test_exchange_filter_with_no_match_returns_empty() -> None:
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
            exchange_filter="kraken-not-in-brief",
        )
        assert renders == []


def test_output_path_uses_safe_filename() -> None:
    """An exchange name with spaces should produce a filename without
    spaces (so URLs / shell expansion don't break)."""
    brief = _minimal_brief(EXCHANGES=[
        {"exchange": "Crypto Dot Com", "address": "0xabc", "total_received_usd": "$1"},
    ])
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
        )
        assert renders[0].output_path.name == "subpoena_crypto_dot_com.html"


def test_html_includes_generation_timestamp() -> None:
    brief = _minimal_brief()
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            brief, request_type="subpoena",
            output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        # Timestamp should be ISO-shape; we don't lock the year because
        # tests can run at any future date.
        assert "Z" in html  # UTC marker from isoformat
