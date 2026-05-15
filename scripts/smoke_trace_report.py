"""Local smoke test for the trace_report renderer.

Reads the ALEC-TEST-2026 fixture and renders trace_report.html into
a temp directory so we can eyeball the new internal artifact before
the next Railway redeploy.

Run:
    python scripts/smoke_trace_report.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parent
sys.path.insert(0, str(WORKTREE / "src"))

from recupero.models import Case  # noqa: E402
from recupero.worker._trace_report import render_trace_report  # noqa: E402


def main() -> int:
    fixture = Path(
        r"C:\Users\apros\Downloads\recupero-io\data\cases\ALEC-TEST-2026"
    )
    if not fixture.exists():
        print(f"FAIL: fixture not found at {fixture}")
        return 1

    out_root = HERE / "_smoke_trace_report_out"
    if out_root.exists():
        shutil.rmtree(out_root)
    briefs_dir = out_root / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)

    case = Case.model_validate_json(
        (fixture / "case.json").read_text(encoding="utf-8")
    )
    freeze_brief = json.loads(
        (fixture / "freeze_brief.json").read_text(encoding="utf-8")
    )

    print(f"case_id={case.case_id} transfers={len(case.transfers)}")
    print(f"FREEZABLE entries: {len(freeze_brief.get('FREEZABLE') or [])}")

    path = render_trace_report(
        case=case,
        freeze_brief=freeze_brief,
        briefs_dir=briefs_dir,
        flow_filename="flow_demo.svg",
        investigation_id="11111111-2222-3333-4444-555555555555",
        label="Smoke test — wallet trace",
    )
    if path is None:
        print("FAIL: render returned None")
        return 1

    print(f"\nwrote: {path}")
    print(f"size: {path.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
