"""Tests for v0.14.10 recupero-ops diagnose-case.

DB-free, network-free. Reads only on-disk artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.ops.commands.diagnose_case import (
    CaseDiagnostic,
    diagnose_artifacts,
)


def _write(case_dir: Path, name: str, data) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        (case_dir / name).write_text(data, encoding="utf-8")
    else:
        (case_dir / name).write_text(
            json.dumps(data), encoding="utf-8",
        )


# Jacob's V-CFI01 transfer fixtures (subset) — USDT, USDC at the
# real Tether/Circle contract addresses so the diagnostic's freezable-
# symbol filter recognizes them.
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def _transfer(*, from_addr: str, to_addr: str, symbol: str = "USDT",
              contract: str = USDT, usd: str = "50000",
              tx_hash: str = "0x" + "1" * 64) -> dict:
    return {
        "transfer_id": f"ethereum:{tx_hash}:1",
        "chain": "ethereum",
        "tx_hash": tx_hash,
        "block_number": 1,
        "block_time": "2025-10-09T00:29:00Z",
        "from_address": from_addr,
        "to_address": to_addr,
        "counterparty": {
            "address": to_addr, "label": None, "is_contract": False,
        },
        "token": {
            "chain": "ethereum", "contract": contract,
            "symbol": symbol, "decimals": 6, "coingecko_id": None,
        },
        "amount_raw": "1000000000",
        "amount_decimal": "1000",
        "usd_value_at_tx": usd,
        "hop_depth": 1,
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
        "fetched_at": "2025-10-09T00:29:00Z",
    }


def _case_json(transfers: list[dict]) -> dict:
    return {
        "schema_version": "1.0",
        "case_id": "test-case",
        "seed_address": "0x" + "a" * 40,
        "chain": "ethereum",
        "incident_time": "2025-10-09T00:29:00Z",
        "transfers": transfers,
        "exchange_endpoints": [],
        "unlabeled_counterparties": [],
        "total_usd_out": None,
        "config_used": {},
        "software_version": "test",
        "trace_started_at": "2025-10-09T00:29:00Z",
        "trace_completed_at": None,
    }


# ---- Case dir missing ---- #


def test_missing_case_dir_recommends_trace() -> None:
    with TemporaryDirectory() as tmp:
        diag = diagnose_artifacts(
            Path(tmp) / "nope", case_id="V-CFI01",
        )
    assert diag.case_dir_exists is False
    assert any("recupero trace" in c for c in diag.recommended_commands)


# ---- Artifacts inventory ---- #


def test_lists_artifacts_present_and_missing() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(from_addr="0xperp", to_addr="0xdest", usd="50000"),
        ]))
        # victim.json + others missing
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert diag.artifacts_present["case.json"] is True
    assert diag.artifacts_present["victim.json"] is False
    assert diag.artifacts_present["freeze_asks.json"] is False
    assert diag.artifacts_present["brief_editorial.json"] is False
    assert diag.artifacts_present["freeze_brief.json"] is False


# ---- Freezable destination enumeration ---- #


def test_enumerates_usdt_destinations() -> None:
    """V-CFI01 shape: a USDT transfer to a destination address gets
    surfaced in freezable_destinations_in_trace."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(
                from_addr="0xperp",
                to_addr="0x00000688768803Bbd44095770895ad27ad6b0d95",
                symbol="USDT", contract=USDT, usd="170687.26",
            ),
        ]))
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert len(diag.freezable_destinations_in_trace) == 1
    dest = diag.freezable_destinations_in_trace[0]
    assert dest["symbol"] == "USDT"
    assert dest["total_usd"] == 170687.26


def test_aggregates_multiple_transfers_to_same_destination() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(from_addr="0xperp", to_addr="0xdest1",
                      usd="50000", tx_hash="0xt1"),
            _transfer(from_addr="0xperp", to_addr="0xdest1",
                      usd="30000", tx_hash="0xt2"),
        ]))
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    dests = diag.freezable_destinations_in_trace
    assert len(dests) == 1
    assert dests[0]["total_usd"] == 80000
    assert dests[0]["transfer_count"] == 2


def test_non_freezable_token_filtered() -> None:
    """ETH and DAI shouldn't appear in freezable_destinations because
    they're not in the freezable-symbol allowlist."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(
                from_addr="0xperp", to_addr="0xdai_dest",
                symbol="DAI", contract="0xdai", usd="100000",
            ),
            _transfer(
                from_addr="0xperp", to_addr="0xeth_dest",
                symbol="ETH", contract="", usd="100000",
            ),
        ]))
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert diag.freezable_destinations_in_trace == []


def test_seed_address_excluded() -> None:
    """If perp sends USDT BACK to victim (dust), victim's own
    address must not surface as a freezable destination."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        seed = "0x" + "a" * 40
        _write(case_dir, "case.json", _case_json([
            _transfer(from_addr="0xperp", to_addr=seed,
                      usd="5000"),
        ]))
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    addrs = {d["address"] for d in diag.freezable_destinations_in_trace}
    assert seed.lower() not in addrs


# ---- Gap detection: missing from freeze_asks ---- #


def test_detects_freezable_destinations_missing_from_freeze_asks() -> None:
    """The headline diagnostic: a destination received USDT but the
    freeze_asks.json doesn't have it. Diagnostic flags + recommends
    re-running list-freeze-targets with --include-historical."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(
                from_addr="0xperp",
                to_addr="0x00000688768803Bbd44095770895ad27ad6b0d95",
                symbol="USDT", contract=USDT, usd="170687",
            ),
        ]))
        # Empty freeze_asks — the v0.13.4 / pre-v0.14.8 state.
        _write(case_dir, "freeze_asks.json", {
            "case_id": "V-CFI01",
            "by_issuer": {},
            "exchange_deposits": [],
        })
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert len(diag.missing_from_freeze_asks) == 1
    assert any(
        "CRITICAL" in f for f in diag.findings
    )
    assert any(
        "--include-historical" in c
        for c in diag.recommended_commands
    )


def test_present_in_freeze_asks_not_flagged_as_missing() -> None:
    """If freeze_asks ALREADY has the destination, the diagnostic
    must NOT flag it as missing."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        addr = "0x00000688768803Bbd44095770895ad27ad6b0d95"
        _write(case_dir, "case.json", _case_json([
            _transfer(from_addr="0xperp", to_addr=addr,
                      symbol="USDT", contract=USDT, usd="170687"),
        ]))
        _write(case_dir, "freeze_asks.json", {
            "case_id": "V-CFI01",
            "by_issuer": {
                "Tether": [
                    {
                        "address": addr.lower(),
                        "chain": "ethereum",
                        "symbol": "USDT",
                        "amount": "170687",
                        "usd_value": "170687",
                        "evidence_type": "historical_inflow",
                        "freeze_capability": "yes",
                    },
                ],
            },
            "exchange_deposits": [],
        })
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert diag.missing_from_freeze_asks == []
    assert diag.freeze_asks_summary["has_historical_evidence"] is True
    # Healthy-case finding present.
    assert any(
        "ask(s) across" in f for f in diag.findings
    )


def test_below_threshold_not_flagged() -> None:
    """A $500 destination is below the $1K threshold — not flagged
    as missing even if freeze_asks doesn't have it."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([
            _transfer(from_addr="0xperp", to_addr="0xtinydest",
                      symbol="USDT", contract=USDT, usd="500"),
        ]))
        _write(case_dir, "freeze_asks.json", {
            "case_id": "V-CFI01", "by_issuer": {},
            "exchange_deposits": [],
        })
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert diag.missing_from_freeze_asks == []


# ---- Pipeline-stage recommendations ---- #


def test_recommends_emit_brief_when_freeze_brief_missing() -> None:
    """case + freeze_asks + editorial all present but no
    freeze_brief — recommend emit-brief."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([]))
        _write(case_dir, "freeze_asks.json", {
            "case_id": "V-CFI01", "by_issuer": {}, "exchange_deposits": [],
        })
        _write(case_dir, "brief_editorial.json", {})
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert any(
        "emit-brief" in c for c in diag.recommended_commands
    )


def test_recommends_ai_editorial_when_editorial_missing() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "V-CFI01"
        _write(case_dir, "case.json", _case_json([]))
        diag = diagnose_artifacts(case_dir, case_id="V-CFI01")
    assert any(
        "ai-editorial" in c for c in diag.recommended_commands
    )


# ---- CaseDiagnostic shape ---- #


def test_to_dict_is_json_safe() -> None:
    diag = CaseDiagnostic(case_id="x")
    diag.findings.append("test")
    diag.recommended_commands.append("recupero trace x")
    d = diag.to_dict()
    json.dumps(d)  # must not raise
    assert d["case_id"] == "x"
    assert d["findings"] == ["test"]
