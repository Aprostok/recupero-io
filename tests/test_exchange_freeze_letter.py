"""Exchange ASSET-FREEZE request rendering (freeze-track P0).

render_legal_request(..., request_type="exchange-freeze") produces a
time-critical freeze letter per CEX that received funds, using the
verified-aware exchange-freeze contact resolver. Distinct from the records
subpoena. Reads onward_cex_flows from the brief's _freeze_asks injection seam.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.reports.legal_requests import (
    LEGAL_REQUEST_TYPES,
    render_legal_request,
)

_CEX_ADDR = "0x4444444444444444444444444444444444444444"
_UP_ADDR = "0x5555555555555555555555555555555555555555"


def _brief(flows: list[dict] | None = None) -> dict:
    return {
        "CASE_ID": "FREEZE-TEST-01",
        "VICTIM_NAME": "Acme Corp",
        "VICTIM_JURISDICTION": "US",
        "INCIDENT_DATE": "2026-05-01",
        "TOTAL_LOSS_USD": "$250,000.00",
        "INVESTIGATOR_NAME": "Inv One",
        "INVESTIGATOR_EMAIL": "inv@recupero.example",
        "_freeze_asks": {"onward_cex_flows": flows if flows is not None else []},
    }


def _flow(exchange: str = "Binance", usd: str = "$70,000.00") -> dict:
    return {
        "exchange": exchange,
        "upstream_address": _UP_ADDR,
        "cex_address": _CEX_ADDR,
        "token_symbol": "USDC",
        "flow_usd_value": usd,
        "transfer_count": 2,
        "first_flow_at": "2026-05-01T12:00:00Z",
        "last_flow_at": "2026-05-02T12:00:00Z",
        "tx_hashes": ["0xfeed0001", "0xfeed0002"],
        "upstream_explorer_url": "https://etherscan.io/address/" + _UP_ADDR,
        "cex_explorer_url": "https://etherscan.io/address/" + _CEX_ADDR,
    }


def test_exchange_freeze_is_a_registered_type() -> None:
    assert "exchange-freeze" in LEGAL_REQUEST_TYPES


def test_renders_freeze_letter_per_exchange() -> None:
    with TemporaryDirectory() as tmp:
        out = Path(tmp)
        renders = render_legal_request(
            _brief([_flow("Binance"), _flow("Kraken", "$30,000.00")]),
            request_type="exchange-freeze", output_dir=out,
        )
        assert len(renders) == 2
        # _safe_filename_segment lowercases, so filenames are lowercase even
        # though the exchange display names are title-cased.
        names = sorted(r.output_path.name for r in renders)
        assert names == ["exchange_freeze_binance.html", "exchange_freeze_kraken.html"]
        for r in renders:
            assert r.request_type == "exchange-freeze"
            html = r.output_path.read_text(encoding="utf-8")
            # It's a FREEZE/hold ask, not a records subpoena.
            assert "Asset-Freeze" in html
            assert "hold" in html.lower()
            assert _CEX_ADDR[:10] in html  # short_address prefix of the deposit
            assert "USDC" in html


def test_unverified_contact_shows_warning_banner() -> None:
    # Binance is only in the unverified starter dict (no verified override
    # shipped), so the letter must carry the confirm-channel banner.
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            _brief([_flow("Binance")]),
            request_type="exchange-freeze", output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "UNVERIFIED CONTACT CHANNEL" in html
        assert "before sending" in html.lower()


def test_no_flows_returns_empty() -> None:
    with TemporaryDirectory() as tmp:
        assert render_legal_request(
            _brief([]), request_type="exchange-freeze", output_dir=Path(tmp),
        ) == []


def test_filter_narrows_to_one_exchange() -> None:
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            _brief([_flow("Binance"), _flow("Kraken")]),
            request_type="exchange-freeze", output_dir=Path(tmp),
            exchange_filter="kraken",
        )
        assert len(renders) == 1
        assert renders[0].exchange_name == "Kraken"


def test_inf_nan_flow_value_sanitized() -> None:
    with TemporaryDirectory() as tmp:
        renders = render_legal_request(
            _brief([_flow("Binance", usd="Infinity")]),
            request_type="exchange-freeze", output_dir=Path(tmp),
        )
        html = renders[0].output_path.read_text(encoding="utf-8")
        assert "Infinity" not in html  # raw bad value never typeset
        assert "$0.00" in html  # sanitized to zero
