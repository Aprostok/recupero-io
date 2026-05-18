"""recupero-ops diagnose-case <case_id>

Pre-flight diagnostic for a case: walks the existing artifacts on
disk, identifies why the brief looks the way it does, and recommends
the next command to run.

Designed to answer questions like:
  - "Why is freeze_asks.json empty even though the trace clearly shows
     USDT/USDC transfers?"
  - "The brief says FREEZABLE=[] — what would I need to do to populate it?"
  - "Which destinations would yield freeze asks if I re-ran
     list-freeze-targets with --include-historical?"

Doesn't mutate anything. Read-only walks of the case directory.

Output: human-friendly report with pass/fail markers + concrete
"run THIS command next" recommendations.

Exit code: 0 — diagnostics complete (regardless of findings)
           2 — operational error (case not found, bad arg)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# Threshold below which "missing freeze ask" isn't really a problem —
# matches the historical-inflow synthesizer's $1K default.
_HISTORICAL_MIN_INFLOW_USD = Decimal("1000")


@dataclass
class CaseDiagnostic:
    """Structured diagnostic output. Printed by the CLI but also
    importable for testing + automation."""
    case_id: str
    case_dir_exists: bool = False
    artifacts_present: dict[str, bool] = field(default_factory=dict)
    transfers_total: int = 0
    chain: str = ""
    freeze_asks_summary: dict[str, Any] = field(default_factory=dict)
    freezable_destinations_in_trace: list[dict] = field(default_factory=list)
    missing_from_freeze_asks: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    recommended_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_dir_exists": self.case_dir_exists,
            "artifacts_present": self.artifacts_present,
            "transfers_total": self.transfers_total,
            "chain": self.chain,
            "freeze_asks_summary": self.freeze_asks_summary,
            "freezable_destinations_in_trace": self.freezable_destinations_in_trace,
            "missing_from_freeze_asks": self.missing_from_freeze_asks,
            "findings": self.findings,
            "recommended_commands": self.recommended_commands,
        }


# ---- Core diagnostic logic (pure, testable) ---- #


def diagnose_artifacts(case_dir: Path, case_id: str) -> CaseDiagnostic:
    """Read whatever artifacts exist on disk; emit a structured
    diagnostic. Does NOT make API calls or hit the DB — strictly
    on-disk analysis so the diagnostic runs offline."""
    diag = CaseDiagnostic(case_id=case_id, case_dir_exists=case_dir.exists())
    if not diag.case_dir_exists:
        diag.findings.append(f"Case directory not found: {case_dir}")
        diag.recommended_commands.append(
            f"recupero trace --case-id {case_id} --chain ethereum "
            "--address <victim-addr> --incident-time <iso>"
        )
        return diag

    # ---- Inventory artifacts ---- #
    artifact_files = [
        "case.json", "victim.json", "freeze_asks.json",
        "brief_editorial.json", "freeze_brief.json",
    ]
    for name in artifact_files:
        diag.artifacts_present[name] = (case_dir / name).exists()

    if not diag.artifacts_present.get("case.json"):
        diag.findings.append(
            "case.json is missing — the trace stage hasn't produced "
            "any output for this case."
        )
        diag.recommended_commands.append(
            f"recupero trace --case-id {case_id} ..."
        )
        return diag

    # ---- Read case.json ---- #
    try:
        case_data = json.loads(
            (case_dir / "case.json").read_text(encoding="utf-8-sig")
        )
    except (json.JSONDecodeError, OSError) as e:
        diag.findings.append(f"case.json unreadable: {e}")
        return diag
    diag.transfers_total = len(case_data.get("transfers") or [])
    diag.chain = case_data.get("chain") or ""

    # ---- Walk transfers for freezable-token destinations ---- #
    freezable_dests = _enumerate_freezable_destinations(case_data)
    diag.freezable_destinations_in_trace = freezable_dests

    # ---- Read freeze_asks.json ---- #
    freeze_asks: dict[str, Any] = {}
    if diag.artifacts_present.get("freeze_asks.json"):
        try:
            freeze_asks = json.loads(
                (case_dir / "freeze_asks.json").read_text(encoding="utf-8-sig")
            )
        except (json.JSONDecodeError, OSError):
            freeze_asks = {}

    by_issuer = freeze_asks.get("by_issuer") or {}
    exchange_deposits = freeze_asks.get("exchange_deposits") or []
    total_asks = sum(len(v) for v in by_issuer.values())
    diag.freeze_asks_summary = {
        "by_issuer_count": len(by_issuer),
        "by_issuer_total_asks": total_asks,
        "exchange_deposits_count": len(exchange_deposits),
        "by_issuer_names": sorted(by_issuer.keys()),
        "has_historical_evidence": _any_historical_evidence(by_issuer),
    }

    # ---- Identify freezable destinations missing from freeze_asks ---- #
    covered_addrs = set()
    for asks in by_issuer.values():
        for a in asks:
            covered_addrs.add((a.get("address") or "").lower())

    diag.missing_from_freeze_asks = [
        dest for dest in freezable_dests
        if dest["address"].lower() not in covered_addrs
        and dest["total_usd"] >= float(_HISTORICAL_MIN_INFLOW_USD)
    ]

    # ---- Findings + recommendations ---- #
    _generate_findings(diag, freeze_asks, case_data)

    return diag


def _enumerate_freezable_destinations(case_data: dict) -> list[dict]:
    """Walk transfers, identify destinations that received tokens
    with known issuer freeze pathways. Read-only on the case dict.

    Returns one row per (address, token_symbol) pair with aggregated
    USD. Sorted by USD desc.
    """
    # Hardcoded "freezable token" symbol set — matches what
    # synthesize_historical_freeze_asks would emit via the issuer DB.
    # Keeping it as a flat list here keeps the diagnostic
    # zero-dependency (doesn't need to load issuers.json).
    _FREEZABLE_SYMBOLS = {
        "USDT", "USDC", "PYUSD", "USDP", "TUSD", "BUSD", "FDUSD",
        "cbBTC", "WBTC", "EURC",
        "msyrupUSDp", "msyrupUSDe", "msyrupUSD",
        "syrupUSDC", "syrupUSDT",
    }
    agg: dict[tuple[str, str], dict] = {}
    seed_addr = (case_data.get("seed_address") or "").lower()
    for t in case_data.get("transfers") or []:
        to_addr = (t.get("to_address") or "").lower()
        if not to_addr or to_addr == seed_addr:
            continue
        token = t.get("token") or {}
        symbol = token.get("symbol", "")
        if symbol not in _FREEZABLE_SYMBOLS:
            continue
        contract = (token.get("contract") or "").lower()
        if not contract:
            continue
        key = (to_addr, symbol)
        bucket = agg.setdefault(key, {
            "address": to_addr,
            "symbol": symbol,
            "contract": contract,
            "total_usd": 0.0,
            "transfer_count": 0,
        })
        try:
            usd_val = float(t.get("usd_value_at_tx") or 0)
        except (TypeError, ValueError):
            usd_val = 0.0
        bucket["total_usd"] += usd_val
        bucket["transfer_count"] += 1

    out = list(agg.values())
    out.sort(key=lambda r: r["total_usd"], reverse=True)
    return out


def _any_historical_evidence(by_issuer: dict) -> bool:
    for asks in by_issuer.values():
        for a in asks:
            if a.get("evidence_type") == "historical_inflow":
                return True
    return False


def _generate_findings(
    diag: CaseDiagnostic,
    freeze_asks: dict[str, Any],
    case_data: dict,
) -> None:
    """Apply diagnostic rules and emit findings + recommendations."""
    case_id = diag.case_id
    artifacts = diag.artifacts_present

    if not artifacts.get("freeze_asks.json"):
        diag.findings.append(
            "freeze_asks.json is missing. The freeze-target identification "
            "stage hasn't run for this case yet."
        )
        diag.recommended_commands.append(
            f"recupero list-freeze-targets {case_id} --include-historical"
        )

    if not artifacts.get("brief_editorial.json"):
        diag.findings.append(
            "brief_editorial.json is missing. Run AI editorial drafting "
            "(or write the editorial template by hand)."
        )
        diag.recommended_commands.append(
            f"recupero ai-editorial {case_id}"
        )

    if not artifacts.get("freeze_brief.json"):
        diag.findings.append(
            "freeze_brief.json is missing. Run emit-brief to assemble it "
            "from case + editorial + freeze_asks."
        )
        diag.recommended_commands.append(
            f"recupero emit-brief {case_id}"
        )

    # Critical check: freezable destinations identified by the trace
    # but absent from freeze_asks.
    missing = diag.missing_from_freeze_asks
    if missing:
        total_missing_usd = sum(d["total_usd"] for d in missing)
        diag.findings.append(
            f"CRITICAL: {len(missing)} destination(s) received "
            f"freezable tokens totaling ${total_missing_usd:,.2f} but "
            f"are NOT in freeze_asks.json. The brief will NOT generate "
            f"freeze letters for them."
        )
        # Diagnose WHY they're missing.
        has_freeze_asks = artifacts.get("freeze_asks.json") is True
        has_historical_evidence = diag.freeze_asks_summary.get(
            "has_historical_evidence", False,
        )
        if has_freeze_asks and not has_historical_evidence:
            diag.findings.append(
                "LIKELY CAUSE: list-freeze-targets was run before v0.14.8, "
                "or with --no-include-historical. The dormant detector "
                "returned empty (funds likely moved on-chain) and no "
                "historical-inflow path was used to fall back."
            )
            diag.recommended_commands.append(
                f"recupero list-freeze-targets {case_id} --include-historical"
            )
            diag.recommended_commands.append(
                f"recupero ai-editorial {case_id}  # re-run after freeze_asks updates"
            )
            diag.recommended_commands.append(
                f"recupero emit-brief {case_id}"
            )
        elif has_historical_evidence:
            diag.findings.append(
                "freeze_asks contains historical-inflow entries already, "
                f"but {len(missing)} destination(s) are still missing — "
                "may be below the threshold, on a chain other than "
                "Ethereum, or use tokens not in the freezable-symbol "
                "diagnostic list. Manual review required."
            )

    # Healthy case path.
    if (
        not missing
        and artifacts.get("freeze_asks.json")
        and diag.freeze_asks_summary.get("by_issuer_total_asks", 0) > 0
    ):
        diag.findings.append(
            f"freeze_asks.json contains "
            f"{diag.freeze_asks_summary['by_issuer_total_asks']} ask(s) "
            f"across {diag.freeze_asks_summary['by_issuer_count']} issuer(s). "
            "Brief should generate per-issuer freeze letters."
        )


# ---- CLI entry point ---- #


def run(*, case_id: str, case_dir: Path) -> int:
    """Print the diagnostic + return exit code."""
    diag = diagnose_artifacts(case_dir, case_id)
    print(f"=== Recupero case diagnostic: {case_id} ===")
    print()
    print(f"Case directory: {case_dir}  ({'EXISTS' if diag.case_dir_exists else 'MISSING'})")
    if not diag.case_dir_exists:
        print()
        for f in diag.findings:
            print(f"  [!] {f}")
        if diag.recommended_commands:
            print()
            print("Recommended commands:")
            for cmd in diag.recommended_commands:
                print(f"  $ {cmd}")
        return 0

    print()
    print("Artifacts:")
    for name, present in diag.artifacts_present.items():
        marker = "OK " if present else "MISSING"
        print(f"  {marker}  {name}")
    print()
    print(f"Trace: {diag.transfers_total} transfer(s) on {diag.chain or '(chain unknown)'}")
    print()

    if diag.freezable_destinations_in_trace:
        print(
            f"Freezable destinations detected in trace: "
            f"{len(diag.freezable_destinations_in_trace)}"
        )
        for dest in diag.freezable_destinations_in_trace[:10]:
            print(
                f"  - {dest['address']}  "
                f"${dest['total_usd']:>12,.2f} {dest['symbol']}  "
                f"({dest['transfer_count']} transfer(s))"
            )
        if len(diag.freezable_destinations_in_trace) > 10:
            print(
                f"  … +{len(diag.freezable_destinations_in_trace) - 10} more"
            )
        print()
    else:
        print("No freezable-token destinations detected in this trace.")
        print()

    if diag.freeze_asks_summary:
        s = diag.freeze_asks_summary
        print(
            f"freeze_asks.json: {s.get('by_issuer_total_asks', 0)} ask(s) "
            f"across {s.get('by_issuer_count', 0)} issuer(s); "
            f"{s.get('exchange_deposits_count', 0)} exchange deposit(s); "
            f"historical-inflow evidence: "
            f"{'present' if s.get('has_historical_evidence') else 'absent'}"
        )
        if s.get("by_issuer_names"):
            print(f"  issuers: {', '.join(s['by_issuer_names'])}")
        print()

    if diag.missing_from_freeze_asks:
        print(
            f"GAP: {len(diag.missing_from_freeze_asks)} freezable "
            f"destination(s) totaling "
            f"${sum(d['total_usd'] for d in diag.missing_from_freeze_asks):,.2f} "
            "are NOT in freeze_asks.json:"
        )
        for dest in diag.missing_from_freeze_asks[:10]:
            print(
                f"  - {dest['address']}  "
                f"${dest['total_usd']:>12,.2f} {dest['symbol']}"
            )
        print()

    if diag.findings:
        print("Findings:")
        for f in diag.findings:
            print(f"  - {f}")
        print()

    if diag.recommended_commands:
        print("Recommended commands:")
        for cmd in diag.recommended_commands:
            print(f"  $ {cmd}")
        print()

    return 0


__all__ = (
    "CaseDiagnostic",
    "diagnose_artifacts",
    "run",
)
