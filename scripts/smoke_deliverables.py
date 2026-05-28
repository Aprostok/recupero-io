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
    # v0.30.2 (V030_2_SELF_AUDIT T1-B): pre-v0.30.2 the fixture path was
    # hardcoded to the author's Windows laptop, making the preflight
    # CI-broken and Railway-broken — `scripts/deploy_preflight.py`
    # subprocess-invokes this script, and on any host that isn't the
    # original author's laptop the smoke gate fails with "fixture not
    # found" 100% of the time.
    # Resolution order:
    #   1. $RECUPERO_FIXTURES_DIR/ALEC-TEST-2026   (operator override)
    #   2. <worktree>/data/cases/ALEC-TEST-2026     (in-repo)
    #   3. <worktree>/../data/cases/ALEC-TEST-2026  (sibling layout)
    #   4. ~/data/cases/ALEC-TEST-2026              (user-home fallback)
    #   5. legacy author-laptop path (kept for back-compat; harmless
    #      when absent on every other machine)
    import os
    candidates: list[Path] = []
    env_dir = os.environ.get("RECUPERO_FIXTURES_DIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir) / "ALEC-TEST-2026")
    candidates.append(WORKTREE / "data" / "cases" / "ALEC-TEST-2026")
    candidates.append(WORKTREE.parent / "data" / "cases" / "ALEC-TEST-2026")
    candidates.append(Path.home() / "data" / "cases" / "ALEC-TEST-2026")
    candidates.append(Path(r"C:\Users\apros\Downloads\recupero-io\data\cases\ALEC-TEST-2026"))

    fixture: Path | None = None
    for cand in candidates:
        if cand.exists():
            fixture = cand
            break
    if fixture is None:
        print(
            "FAIL: ALEC-TEST-2026 fixture not found in any of the "
            "candidate locations:\n  "
            + "\n  ".join(str(c) for c in candidates)
            + "\nSet RECUPERO_FIXTURES_DIR to override, or stage the "
            "fixture under data/cases/ in the repo / worker pod."
        )
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
