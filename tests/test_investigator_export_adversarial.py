"""Adversarial-input regression tests for investigator_export.py.

These tests lock down hostile fields in the brief that flow into the
investigator CSV/JSON (the FBI/IRS-CI/OFAC ingestion artifact). The
trigger paths are real:

  * brief.RISK_ASSESSMENT[*].verdict + exposures[*].counterparty_name
    derive from external label data (Chainalysis-style category tags +
    counterparty registry). An attacker who plants a malicious counterparty
    label can land a formula string into the CSV.
  * brief.FREEZABLE[*].freeze_note / .holdings[*].evidence_type funnel
    operator + issuer-registry text directly into the CSV `notes` column.
  * brief.DEX_SWAPS[*].router_name / investigator_note are external data.
  * brief.CROSS_CASE_CORRELATION[*].prior_total_usd_flowed is aggregated
    from prior cases — a single poisoned prior case can inject NaN.

CWE-1236 (CSV formula injection) is pre-fixed in case_store.py via
CaseStore._csv_safe — investigator_export.write_csv MUST use the same
sanitizer (or an equivalent) because government tools ingest THIS file
into Excel-family case-management spreadsheets.
"""

from __future__ import annotations

import csv
import json
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.reports.investigator_export import (
    InvestigatorFinding,
    build_findings,
    write_csv,
    write_json,
)

# ---- Bug 1: CSV formula injection in operator-controlled cells ----


@pytest.mark.parametrize(
    "payload",
    [
        '=HYPERLINK("https://phish.example/x","Click here")',
        '+cmd|"/c calc"!A1',
        '-2+3+cmd',
        '@SUM(1+2)',
        '\tinjection',
        '\rinjection',
    ],
)
def test_csv_formula_injection_in_counterparty_name(payload: str) -> None:
    """A counterparty_name like ``=HYPERLINK(...)`` lands in the CSV
    `counterparty_name` column. Pre-fix the cell renders as a live
    Excel formula on the analyst's machine the moment they open
    investigator_findings.csv. The sanitizer must prefix a single
    quote (CWE-1236, OWASP-standard mitigation; same pattern as
    CaseStore._csv_safe in storage/case_store.py).
    """
    brief = {
        "PRIMARY_CHAIN": "Ethereum",
        "RISK_ASSESSMENT": {
            "addresses": {
                "0x" + "a" * 40: {
                    "verdict": "high risk — counterparty hit",
                    "exposures": [
                        {
                            "severity": 4,
                            "risk_category": "ofac_direct",
                            "counterparty": "0x" + "b" * 40,
                            "counterparty_name": payload,
                            "direction": "outflow",
                            "total_usd": "$1000",
                        },
                    ],
                },
            },
        },
        "FREEZABLE": [], "DESTINATIONS": [],
        "ENTITY_CLUSTERS": {"clusters": []},
        "CROSS_CHAIN_HANDOFFS": [], "DEX_SWAPS": [],
    }
    findings = build_findings(brief)
    assert len(findings) == 1
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.csv"
        write_csv(findings, out_path)
        with out_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        cell = rows[0]["counterparty_name"]
        # The dangerous cell MUST be neutralized — either by prepending
        # a single quote, or by stripping the leading trigger char.
        assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), (
            f"unsafe CSV cell: {cell!r}"
        )


def test_csv_formula_injection_in_freezable_notes() -> None:
    """A poisoned issuer freeze_note plants a formula in the notes
    column. Same class of bug — operator opens investigator_findings.csv
    in Excel and triggers code execution.
    """
    brief = {
        "PRIMARY_CHAIN": "Ethereum",
        "FREEZABLE": [
            {
                "issuer": "Circle",
                "token": "USDC",
                "freeze_capability": "yes",
                "freeze_note": '=cmd|"/c calc"!A1',
                "holdings": [
                    {
                        "address": "0x" + "c" * 40,
                        "usd": "$500",
                        "evidence_type": "current_balance",
                    },
                ],
            },
        ],
        "RISK_ASSESSMENT": {"addresses": {}},
        "DESTINATIONS": [], "ENTITY_CLUSTERS": {"clusters": []},
        "CROSS_CHAIN_HANDOFFS": [], "DEX_SWAPS": [],
    }
    findings = build_findings(brief)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.csv"
        write_csv(findings, out_path)
        with out_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            for col, cell in row.items():
                if not cell:
                    continue
                assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), (
                    f"unsafe CSV cell in column={col}: {cell!r}"
                )


def test_csv_formula_injection_in_headline_via_verdict() -> None:
    """The RISK_ASSESSMENT verdict is concatenated into the headline
    column. A verdict starting with `=` poisons the headline cell.
    """
    brief = {
        "PRIMARY_CHAIN": "Ethereum",
        "RISK_ASSESSMENT": {
            "addresses": {
                "0x" + "d" * 40: {
                    "verdict": '=HYPERLINK("https://phish.example","ATTACK")',
                    "exposures": [
                        {
                            "severity": 3,
                            "risk_category": "ofac_direct",
                            "counterparty": "0x" + "e" * 40,
                            "counterparty_name": "OFAC entity",
                            "direction": "outflow",
                            "total_usd": "$100",
                        },
                    ],
                },
            },
        },
        "FREEZABLE": [], "DESTINATIONS": [],
        "ENTITY_CLUSTERS": {"clusters": []},
        "CROSS_CHAIN_HANDOFFS": [], "DEX_SWAPS": [],
    }
    findings = build_findings(brief)
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.csv"
        write_csv(findings, out_path)
        with out_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert not rows[0]["headline"].startswith(
            ("=", "+", "-", "@", "\t", "\r")
        ), f"unsafe headline cell: {rows[0]['headline']!r}"


# ---- Bug 2: NaN/Inf in amount_usd renders as `nan`/`inf` in CSV ----


def test_csv_rejects_nan_in_amount_usd() -> None:
    """A poisoned amount_usd value ``"nan"`` would render as a bare
    ``nan`` token in the CSV. Government ingestion pipelines may
    treat that as a numeric NaN; analysts opening in Excel see
    `#NUM!`. Either way the row is unusable. Reject upstream — emit
    an empty string instead.
    """
    findings = [
        InvestigatorFinding(
            finding_type="risk_exposure",
            address="0x" + "a" * 40,
            chain="ethereum",
            severity="high",
            headline="poisoned amount",
            counterparty="",
            counterparty_name="Test",
            risk_category="ofac_direct",
            amount_usd="nan",
            tx_hash="", explorer_url="", timestamp_iso="",
            follow_up_url="", notes="",
        ),
        InvestigatorFinding(
            finding_type="risk_exposure",
            address="0x" + "b" * 40,
            chain="ethereum",
            severity="high",
            headline="inf amount",
            counterparty="",
            counterparty_name="Test",
            risk_category="ofac_direct",
            amount_usd="Infinity",
            tx_hash="", explorer_url="", timestamp_iso="",
            follow_up_url="", notes="",
        ),
    ]
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.csv"
        write_csv(findings, out_path)
        text = out_path.read_text(encoding="utf-8")
        # Re-parse the column to ensure we don't ship a literal
        # 'nan'/'inf' token to government ingestion.
        with out_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            amt = row["amount_usd"].strip().lower()
            assert amt not in ("nan", "inf", "infinity", "-inf", "-infinity"), (
                f"unsafe numeric token in amount_usd: {row['amount_usd']!r} "
                f"(full CSV: {text!r})"
            )


def test_json_rejects_nan_in_amount_usd_via_aggregation() -> None:
    """The JSON export uses ``allow_nan=False`` for json.dumps, which
    raises ValueError on a Python float NaN. But the InvestigatorFinding
    schema types ``amount_usd`` as ``str`` and the brief feeds string
    values straight through — so an ``"nan"`` string serializes fine
    and lands in the JSON. Re-parsing it with pandas / json.loads in
    a downstream tool then yields a real NaN. Reject the string
    representation too.
    """
    findings = [
        InvestigatorFinding(
            finding_type="dex_swap",
            address="0x" + "f" * 40,
            chain="ethereum",
            severity="high",
            headline="poisoned swap",
            counterparty="",
            counterparty_name="Uniswap",
            risk_category="dex_swap",
            amount_usd="NaN",
            tx_hash="0x" + "1" * 64,
            explorer_url="", timestamp_iso="",
            follow_up_url="", notes="",
        ),
    ]
    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.json"
        write_json(findings, out_path)
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        amt = payload["findings"][0]["amount_usd"].strip().lower()
        assert amt not in ("nan", "inf", "infinity", "-inf", "-infinity"), (
            f"unsafe numeric token in JSON amount_usd: "
            f"{payload['findings'][0]['amount_usd']!r}"
        )


# ---- Bug 3: concurrent write races on shared `.tmp` sibling ----


def test_concurrent_write_csv_does_not_corrupt_output() -> None:
    """Two operators (or two pipeline retries) write the same case's
    investigator CSV concurrently. Pre-fix both writers share the
    same ``{out_path}.tmp`` sibling — writer A opens it, writer B
    truncates it mid-stream, the os.replace race leaves a corrupted
    or empty CSV in place. After the race, the file MUST still parse
    as a valid CSV with the expected header.
    """
    findings_a = [
        InvestigatorFinding(
            finding_type="risk_exposure",
            address="0x" + "a" * 40,
            chain="ethereum",
            severity="high",
            headline="writer-a row",
            counterparty="", counterparty_name="A",
            risk_category="ofac_direct",
            amount_usd="$1",
            tx_hash="", explorer_url="", timestamp_iso="",
            follow_up_url="", notes="",
        ),
    ] * 200
    findings_b = [
        InvestigatorFinding(
            finding_type="risk_exposure",
            address="0x" + "b" * 40,
            chain="ethereum",
            severity="high",
            headline="writer-b row",
            counterparty="", counterparty_name="B",
            risk_category="ofac_direct",
            amount_usd="$2",
            tx_hash="", explorer_url="", timestamp_iso="",
            follow_up_url="", notes="",
        ),
    ] * 200

    with TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "investigator_findings.csv"
        errors: list[BaseException] = []

        def _run(findings):
            try:
                for _ in range(8):
                    write_csv(findings, out_path)
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        t1 = threading.Thread(target=_run, args=(findings_a,))
        t2 = threading.Thread(target=_run, args=(findings_b,))
        t1.start(); t2.start(); t1.join(); t2.join()
        # No CORRUPTION-class exceptions; one PermissionError on
        # Windows during the rename race is acceptable as long as
        # the file lands well-formed. Windows can't rename over an
        # open handle and the unique-pid+uuid tmp name makes the
        # race extremely tight but not impossible — the security
        # property (no corruption / no orphan tmp leak) is what
        # matters; whether the LOSER of the race raises is OS-level
        # ceremony.
        import sys
        if sys.platform == "win32":
            errors = [e for e in errors
                      if not isinstance(e, PermissionError)]
        assert not errors, f"concurrent write raised: {errors!r}"
        assert out_path.exists(), "output CSV missing after race"
        with out_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        # Whichever writer won, the file is well-formed (header present
        # via DictReader.fieldnames + every row has all columns).
        from recupero.reports.investigator_export import _CSV_COLUMNS
        assert rows, "output CSV empty after race"
        for row in rows:
            assert set(row.keys()) == set(_CSV_COLUMNS), (
                f"corrupted row keys: {row.keys()!r}"
            )
        # No stray .tmp left behind (the loser should clean up).
        leftover = list(Path(tmp).glob("*.tmp"))
        assert not leftover, f"leftover tmp files: {leftover!r}"
