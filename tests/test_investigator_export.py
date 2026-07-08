"""Tests for v0.9.2 investigator CSV/JSON export.

These are the government-tester-facing files. Contract is:
  * One row per actionable finding (no fluff entries)
  * Wide schema (every field every government tool expects)
  * Severity-sorted (critical first, info last)
  * Both CSV and JSON ship with identical content / shape
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.reports.investigator_export import (
    _CSV_COLUMNS,
    InvestigatorFinding,
    build_findings,
    write_csv,
    write_json,
)


def _stub_brief(**overrides) -> dict:
    """Minimal brief with the v0.9.x sections empty by default."""
    base = {
        "PRIMARY_CHAIN": "Ethereum",
        "CROSS_CHAIN_HANDOFFS": [],
        "ENTITY_CLUSTERS": {"clusters": [], "unclustered_addresses": []},
        "RISK_ASSESSMENT": {
            "addresses": {},
            "summary": {
                "addresses_assessed": 0,
                "ofac_exposed_count": 0,
                "mixer_exposed_count": 0,
                "highest_score": 0,
                "highest_score_address": None,
            },
        },
        "FREEZABLE": [],
        "DESTINATIONS": [],
    }
    base.update(overrides)
    return base


# ---- build_findings — empty case ---- #


def test_empty_brief_yields_no_findings() -> None:
    """Brief with all sections empty → no findings. Correct
    behavior for a wallet-trace investigation (no victim, no
    enforcement context)."""
    assert build_findings(_stub_brief()) == []


# ---- Risk → findings ---- #


def test_risk_assessment_yields_critical_findings() -> None:
    """An OFAC-exposed address → finding with severity='critical'."""
    brief = _stub_brief(RISK_ASSESSMENT={
        "addresses": {
            "0x" + "1" * 40: {
                "score": 4,
                "verdict": "SANCTIONED — direct exposure to OFAC SDN List",
                "exposures": [{
                    "counterparty": "0x" + "f" * 40,
                    "counterparty_name": "Lazarus Group",
                    "risk_category": "ofac_sanctioned",
                    "severity": 4,
                    "direction": "outflow",
                    "tx_count": 1,
                    "total_usd": "$50,000.00",
                }],
            },
        },
        "summary": {
            "addresses_assessed": 1, "ofac_exposed_count": 1,
            "mixer_exposed_count": 0, "highest_score": 4,
            "highest_score_address": "0x" + "1" * 40,
        },
    })
    out = build_findings(brief)
    risk_findings = [f for f in out if f.finding_type == "risk_exposure"]
    assert len(risk_findings) == 1
    f = risk_findings[0]
    assert f.severity == "critical"
    assert "SANCTIONED" in f.headline
    assert f.counterparty_name == "Lazarus Group"
    assert f.risk_category == "ofac_sanctioned"
    assert f.amount_usd == "$50,000.00"


def test_risk_assessment_severity_mapping() -> None:
    """Integer severity from the risk-scorer maps to the CSV
    severity strings expected by government tools."""
    brief = _stub_brief(RISK_ASSESSMENT={
        "addresses": {
            "0x1": {
                "score": 12, "verdict": "CRITICAL",
                "exposures": [
                    {"counterparty": "0xa", "counterparty_name": "x",
                     "risk_category": "scam_drainer", "severity": 3,
                     "direction": "outflow", "tx_count": 1,
                     "total_usd": "$1.00"},
                    {"counterparty": "0xb", "counterparty_name": "y",
                     "risk_category": "advisory", "severity": 1,
                     "direction": "outflow", "tx_count": 1,
                     "total_usd": "$1.00"},
                ],
            },
        },
        "summary": {
            "addresses_assessed": 1, "ofac_exposed_count": 0,
            "mixer_exposed_count": 0, "highest_score": 12,
            "highest_score_address": "0x1",
        },
    })
    out = build_findings(brief)
    severities = sorted({f.severity for f in out})
    assert "high" in severities  # severity=3
    assert "low" in severities   # severity=1


# ---- Cross-chain handoffs → findings ---- #


def test_cross_chain_handoff_yields_high_finding() -> None:
    """Cross-chain handoffs always get severity='high' since
    they're a fork-in-the-investigation requiring follow-up on
    another chain. Even a small handoff is high-priority for
    investigators because it splits attention across chains."""
    brief = _stub_brief(CROSS_CHAIN_HANDOFFS=[{
        "source_chain": "ethereum",
        "source_address": "0x" + "a" * 40,
        "tx_hash": "0x" + "1" * 64,
        "tx_explorer_url": "https://etherscan.io/tx/0x111...",
        "bridge_name": "Wormhole",
        "bridge_protocol": "Wormhole (TokenBridge)",
        "bridge_address": "0xfeed",
        "amount_usd": "$120,000.00",
        "amount_decimal": "120000",
        "token_symbol": "USDC",
        "block_time": "2026-01-01T10:00:00Z",
        "follow_up_url": "https://wormholescan.io",
        "destination_chain_candidates": ["solana"],
        "investigator_note": "Bridged $120,000 via Wormhole",
    }])
    out = build_findings(brief)
    cc_findings = [f for f in out if f.finding_type == "cross_chain_handoff"]
    assert len(cc_findings) == 1
    f = cc_findings[0]
    assert f.severity == "high"
    assert f.counterparty_name == "Wormhole"
    assert f.follow_up_url == "https://wormholescan.io"
    assert "solana" in f.headline


# ---- Freezable holdings → findings ---- #


def test_freezable_high_capability_yields_high() -> None:
    """A FREEZABLE entry with HIGH capability → severity='high'."""
    brief = _stub_brief(FREEZABLE=[{
        "issuer": "Circle",
        "token": "USDC",
        "freeze_capability": "HIGH",
        "holdings": [{
            "address": "0x" + "1" * 40,
            "usd": "$50,000.00",
        }],
    }])
    out = build_findings(brief)
    fz = [f for f in out if f.finding_type == "freezable"]
    assert len(fz) == 1
    assert fz[0].severity == "high"
    assert fz[0].counterparty_name == "Circle"


# ---- Entity clusters → findings ---- #


def test_cluster_yields_medium_finding() -> None:
    """Entity clusters → severity='medium' (informational —
    helps investigator broaden their subpoena scope)."""
    brief = _stub_brief(ENTITY_CLUSTERS={
        "clusters": [{
            "cluster_id": "C-1",
            "addresses": ["0x" + "1" * 40, "0x" + "2" * 40],
            "size": 2,
            "total_balance_usd": "$100,000.00",
            "evidence": [{
                "heuristic": "common_funding",
                "details": "Both funded by 0xabc within 4h",
                "confidence": "high",
                "related_address": "0xabc",
            }],
        }],
        "unclustered_addresses": [],
    })
    out = build_findings(brief)
    cluster_findings = [f for f in out if f.finding_type == "entity_cluster"]
    assert len(cluster_findings) == 1
    f = cluster_findings[0]
    assert f.severity == "medium"
    assert "C-1" in f.headline
    assert "$100,000" in f.headline


# ---- Sort order ---- #


def test_findings_sorted_by_severity_descending() -> None:
    """Critical first, info last. Investigators read top-down
    and need the most-actionable findings at the top."""
    brief = _stub_brief(
        RISK_ASSESSMENT={
            "addresses": {
                "0x1": {
                    "score": 4, "verdict": "SANCTIONED",
                    "exposures": [{
                        "counterparty": "0xa", "counterparty_name": "OFAC",
                        "risk_category": "ofac_sanctioned",
                        "severity": 4, "direction": "outflow",
                        "tx_count": 1, "total_usd": "$1.00",
                    }],
                },
            },
            "summary": {
                "addresses_assessed": 1, "ofac_exposed_count": 1,
                "mixer_exposed_count": 0, "highest_score": 4,
                "highest_score_address": "0x1",
            },
        },
        DESTINATIONS=[
            {"address": "0x" + "9" * 40, "total_usd": "$1.00"},
        ],
    )
    out = build_findings(brief)
    severities = [f.severity for f in out]
    # Critical (OFAC) comes before info (destination)
    crit_idx = severities.index("critical")
    info_idx = severities.index("info")
    assert crit_idx < info_idx


# ---- CSV write ---- #


def test_csv_write_round_trips() -> None:
    """CSV write produces a file that csv.DictReader can read
    back with the same data. Tests our header schema lock."""
    findings = [
        InvestigatorFinding(
            finding_type="risk_exposure",
            address="0x1",
            chain="ethereum",
            severity="critical",
            headline="Test critical finding",
            counterparty="0xa",
            counterparty_name="Lazarus",
            risk_category="ofac_sanctioned",
            amount_usd="$50,000.00",
            tx_hash="0x1" + "0" * 63,
            explorer_url="https://etherscan.io/tx/...",
            timestamp_iso="2026-01-01T10:00:00Z",
            follow_up_url="",
            notes="OFAC SDN List",
        ),
    ]
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "findings.csv"
        write_csv(findings, out_path)
        with out_path.open() as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    # All required columns present.
    for col in _CSV_COLUMNS:
        assert col in row
    assert row["severity"] == "critical"
    assert row["counterparty_name"] == "Lazarus"


def test_csv_column_order_locked() -> None:
    """The CSV column order is the contract with government
    tools. Lock the position of each column so a future
    refactor that re-orders them is caught explicitly."""
    expected = (
        "finding_type", "address", "chain", "severity", "headline",
        "counterparty", "counterparty_name", "risk_category",
        "amount_usd", "tx_hash", "explorer_url", "timestamp_iso",
        "follow_up_url", "notes",
    )
    assert expected == _CSV_COLUMNS


# ---- JSON write ---- #


def test_json_write_includes_metadata_header() -> None:
    """JSON export has schema_version + generated_by + count
    so downstream tools know what they're parsing."""
    findings = [InvestigatorFinding(
        finding_type="risk_exposure", address="0x1", chain="ethereum",
        severity="critical", headline="test", counterparty="",
        counterparty_name="", risk_category="ofac_sanctioned",
        amount_usd="$1.00", tx_hash="", explorer_url="",
        timestamp_iso="", follow_up_url="", notes="",
    )]
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "findings.json"
        write_json(findings, out_path)
        payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["generated_by"] == "recupero"
    assert payload["findings_count"] == 1
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["severity"] == "critical"


def test_prior_cases_note_reports_dropped_count() -> None:
    """A recidivist with >5 prior cases must show '(+N more)' — an analyst
    subpoenaing prior cases needs to know the list was trimmed."""
    from recupero.reports.investigator_export import build_findings
    addr = "0x" + "a" * 40
    brief = {"CROSS_CASE_CORRELATION": {"addresses": {
        addr: {
            "total_prior_cases": 7,
            "prior_case_appearances": [
                {"case_id": f"c{i}", "role": "hop", "usd_flowed": "100"}
                for i in range(7)
            ],
        },
    }}}
    findings = build_findings(brief)
    notes = " ".join(getattr(f, "notes", "") or "" for f in findings)
    assert "+2 more prior case(s)" in notes
