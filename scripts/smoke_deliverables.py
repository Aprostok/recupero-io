"""Local smoke test for the full deliverables stage.

Exercises ``build_all_deliverables`` end-to-end against the bundled
ALEC-TEST-2026 fixture so we can eyeball the new TRM-style flow
diagram embedded as Appendix A in the rendered HTML + PDF outputs.

The pipeline normally runs this inside the worker after the freeze
stage, so a fixture-based test avoids any Postgres / bucket plumbing.
Writes results to ``scripts/_smoke_deliverables_out/`` and prints the
paths so you can open them.

Run:
    python scripts/smoke_deliverables.py
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
from recupero.reports.victim import VictimInfo  # noqa: E402
from recupero.worker._deliverables import build_all_deliverables  # noqa: E402


def main() -> int:
    fixture = Path(r"C:\Users\apros\Downloads\recupero-io\data\cases\ALEC-TEST-2026")
    if not fixture.exists():
        print(f"FAIL: fixture not found at {fixture}")
        return 1

    out_root = HERE / "_smoke_deliverables_out"
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    # Copy the fixture into a writable case_dir — build_all_deliverables
    # writes its outputs under case_dir/briefs/, and we don't want to
    # mutate the canonical fixture.
    case_dir = out_root / "ALEC-TEST-2026"
    shutil.copytree(fixture, case_dir)
    # Drop the pre-existing briefs/ if any so we only see new output.
    for stale in (case_dir / "briefs",):
        if stale.exists():
            shutil.rmtree(stale)

    case = Case.model_validate_json((case_dir / "case.json").read_text(encoding="utf-8"))
    victim = VictimInfo.model_validate_json(
        (case_dir / "victim.json").read_text(encoding="utf-8")
    )
    freeze_brief = json.loads((case_dir / "freeze_brief.json").read_text(encoding="utf-8"))

    print(f"loaded fixture case_id={case.case_id} transfers={len(case.transfers)}")
    print(f"FREEZABLE entries: {len(freeze_brief.get('FREEZABLE') or [])}")

    written = build_all_deliverables(
        case=case,
        victim=victim,
        freeze_brief=freeze_brief,
        case_dir=case_dir,
    )
    print(f"\nwrote {len(written)} file(s):")
    for p in written:
        size = p.stat().st_size if p.exists() else -1
        print(f"  {p.name}  ({size} bytes)")

    print(f"\nOpen one of the HTMLs / PDFs under:\n  {case_dir / 'briefs'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
