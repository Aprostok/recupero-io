"""Pipeline auto-wiring of the exchange-freeze letter + time-sensitivity advisory.

``_maybe_emit_litigation_artifacts`` (gated by RECUPERO_AUTO_LITIGATION_ARTIFACTS
at the pipeline level) now also renders, per case:
  * one verified-aware asset-FREEZE letter per CEX that received funds, and
  * the statute-of-limitations / time-sensitivity advisory (always).
Both read the documented onward-CEX flows from freeze_asks.json. This locks
that they land under legal_requests/ and are tracked in `written` (so the
signed custody attestation covers them).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import Case, Chain
from recupero.worker._deliverables import _maybe_emit_litigation_artifacts

_CEX = "0x" + "4" * 40
_UP = "0x" + "5" * 40


def _case() -> Case:
    return Case(
        case_id="LIT-TEST-01",
        seed_address="0x" + "b" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 5, 1, tzinfo=UTC),
        transfers=[],
        exchange_endpoints=[],
        unlabeled_counterparties=[],
        software_version="test",
        trace_started_at=datetime(2026, 5, 1, tzinfo=UTC),
        trace_completed_at=datetime(2026, 5, 1, tzinfo=UTC),
    )


def _brief() -> dict:
    return {
        "CASE_ID": "LIT-TEST-01",
        "VICTIM_NAME": "Acme Corp",
        "VICTIM_JURISDICTION": "US",
        "INCIDENT_DATE": "2026-05-01",
        "TOTAL_LOSS_USD": "$250,000.00",
        "INVESTIGATOR_NAME": "Inv One",
        "INVESTIGATOR_EMAIL": "inv@recupero.example",
        "FREEZABLE": [],
        "DESTINATIONS": [],
    }


def _write_freeze_asks(case_dir: Path) -> None:
    (case_dir / "freeze_asks.json").write_text(json.dumps({
        "by_issuer": {}, "exchange_deposits": [],
        "onward_cex_flows": [
            {"exchange": "Binance", "upstream_address": _UP, "cex_address": _CEX,
             "token_symbol": "USDC", "flow_usd_value": "$70,000.00",
             "transfer_count": 2, "first_flow_at": "2026-05-02T00:00:00Z",
             "last_flow_at": "2026-05-03T00:00:00Z", "tx_hashes": ["0xabc"]},
            {"exchange": "Kraken", "upstream_address": _UP, "cex_address": _CEX,
             "token_symbol": "USDC", "flow_usd_value": "$30,000.00",
             "transfer_count": 1, "first_flow_at": "2026-05-04T00:00:00Z",
             "last_flow_at": "2026-05-04T00:00:00Z", "tx_hashes": ["0xdef"]},
        ],
    }), encoding="utf-8")


def test_litigation_emits_freeze_letters_and_time_sensitivity() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _write_freeze_asks(case_dir)
        written: list[Path] = []
        _maybe_emit_litigation_artifacts(
            case=_case(), case_dir=case_dir, freeze_brief=_brief(),
            operator="test", written=written,
        )
        lr = case_dir / "legal_requests"
        assert (lr / "exchange_freeze_binance.html").is_file()
        assert (lr / "exchange_freeze_kraken.html").is_file()
        ts = lr / "legal_time_sensitivity.html"
        assert ts.is_file()
        # Both tracked in `written` so the custody attestation covers them.
        names = {p.name for p in written}
        assert "exchange_freeze_binance.html" in names
        assert "legal_time_sensitivity.html" in names
        # Advisory carries the not-advice framing + a real citation.
        html = ts.read_text(encoding="utf-8")
        assert "NOT LEGAL ADVICE" in html
        assert "18 U.S.C. § 3282(a)" in html


def test_time_sensitivity_renders_without_cex_flows() -> None:
    # No freeze_asks.json -> no freeze letters, but the advisory STILL renders
    # (the legal clock doesn't depend on onward-CEX flows).
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        written: list[Path] = []
        _maybe_emit_litigation_artifacts(
            case=_case(), case_dir=case_dir, freeze_brief=_brief(),
            operator="test", written=written,
        )
        lr = case_dir / "legal_requests"
        assert (lr / "legal_time_sensitivity.html").is_file()
        assert not list(lr.glob("exchange_freeze_*.html"))
