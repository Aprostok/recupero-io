#!/usr/bin/env python3
"""Phase 1 acceptance test: run a trace against the Zigha victim address and
diff against expected anchor transactions.

Inputs:
    tests/fixtures/zigha_inputs.json   — seed address, incident_time, case_id
    tests/fixtures/zigha_expected.json — list of anchor transactions to verify

Outputs:
    data/cases/<case_id>/                — full case folder
    Pass/fail report on stdout

Usage:
    python scripts/verify_zigha.py

The acceptance bar is deliberately loose:
    - For each expected anchor, find the matching transfer in case.json by tx_hash.
    - Assert it's present.
    - Assert label category (if specified) matches.
    - Assert USD value within tolerance_pct of expected (if specified).

This is a sanity test, not a bit-for-bit equality check. Historical price
sources differ slightly. The point is to catch regressions, not perfection.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from recupero.config import load_config  # noqa: E402
from recupero.logging_setup import setup_logging  # noqa: E402
from recupero.models import Chain  # noqa: E402
from recupero.storage.case_store import CaseStore  # noqa: E402
from recupero.trace.tracer import run_trace  # noqa: E402

ROOT = Path(__file__).parents[1]
INPUTS = ROOT / "tests" / "fixtures" / "zigha_inputs.json"
EXPECTED = ROOT / "tests" / "fixtures" / "zigha_expected.json"

console = Console()


def main() -> int:
    if not INPUTS.exists():
        console.print(f"[bold red]Missing inputs:[/] {INPUTS}")
        return 2
    inputs = json.loads(INPUTS.read_text())

    cfg, env = load_config()
    if not env.ETHERSCAN_API_KEY:
        console.print("[bold red]Missing ETHERSCAN_API_KEY in .env[/]")
        return 2

    case_id = inputs["case_id"]
    seed = inputs["seed_address"]
    incident_time = datetime.fromisoformat(inputs["incident_time"].replace("Z", "+00:00"))

    store = CaseStore(cfg)
    case_dir = store.case_dir(case_id)
    setup_logging(cfg.logging.level, case_dir)

    console.print(f"\n[bold cyan]Tracing {seed} from {incident_time.isoformat()}...[/]\n")
    case = run_trace(
        chain=Chain.ethereum,
        seed_address=seed,
        incident_time=incident_time,
        case_id=case_id,
        config=cfg,
        env=env,
        case_dir=case_dir,
    )
    store.write_case(case)

    if not EXPECTED.exists():
        console.print(f"\n[yellow]No expected fixture at {EXPECTED} — wrote case, no anchors checked.[/]")
        console.print(f"Output: {case_dir}/case.json")
        _summarize_findings(case)
        return 0

    expected = json.loads(EXPECTED.read_text())
    if not expected:
        console.print("\n[yellow]Expected fixture is empty — wrote case, no anchors to check.[/]")
        _summarize_findings(case)
        return 0

    by_hash = {t.tx_hash.lower(): t for t in case.transfers}
    results = []
    for anchor in expected:
        tx_hash = anchor["tx_hash"].lower()
        t = by_hash.get(tx_hash)
        if t is None:
            results.append((anchor, "MISSING", "tx not found in case"))
            continue
        # Label category check
        exp_cat = anchor.get("expected_label_category")
        if exp_cat:
            actual_cat = t.counterparty.label.category.value if t.counterparty.label else "unknown"
            if actual_cat != exp_cat:
                results.append((anchor, "FAIL", f"label_category {actual_cat} != {exp_cat}"))
                continue
        # USD check
        exp_usd = anchor.get("approx_usd")
        if exp_usd is not None:
            tol = float(anchor.get("approx_usd_tolerance_pct", 5.0))
            if t.usd_value_at_tx is None:
                results.append((anchor, "FAIL", "usd_value_at_tx is None"))
                continue
            actual = float(t.usd_value_at_tx)
            diff_pct = abs(actual - exp_usd) / exp_usd * 100
            if diff_pct > tol:
                results.append((anchor, "FAIL", f"usd ${actual:,.0f} vs expected ${exp_usd:,.0f} ({diff_pct:.1f}% off)"))
                continue
        results.append((anchor, "PASS", ""))

    # Render
    table = Table(title="Zigha verification anchors")
    table.add_column("Status", style="bold")
    table.add_column("Tx hash")
    table.add_column("Source in report")
    table.add_column("Note")
    passes = 0
    for anchor, status, note in results:
        style = {"PASS": "green", "FAIL": "red", "MISSING": "red"}[status]
        table.add_row(
            f"[{style}]{status}[/]",
            anchor["tx_hash"][:14] + "...",
            anchor.get("source_in_zigha_report", "")[:40],
            note,
        )
        if status == "PASS":
            passes += 1
    console.print(table)
    console.print(f"\n[bold]{passes}/{len(results)} anchors passed.[/]")
    _summarize_findings(case)
    return 0 if passes == len(results) else 1


def _summarize_findings(case) -> None:
    console.print(f"\n[bold]Total transfers:[/] {len(case.transfers)}")
    console.print(f"[bold]Total USD out:[/] {case.total_usd_out}")
    console.print(f"[bold]Exchange endpoints:[/] {len(case.exchange_endpoints)}")
    if case.exchange_endpoints:
        for ep in case.exchange_endpoints:
            console.print(
                f"  • [cyan]{ep.exchange}[/] {ep.address} — "
                f"${ep.total_received_usd or '?'} across {len(ep.transfer_ids)} deposits"
            )
    console.print(f"[bold]Unlabeled counterparties:[/] {len(case.unlabeled_counterparties)}")


if __name__ == "__main__":
    sys.exit(main())
