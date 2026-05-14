"""Local smoke test for the redesigned TRM-style flow diagram renderer.

Run from the worktree:
    python scripts/smoke_flow_diagram.py [path/to/case.json]

Defaults to data/cases/ALEC-TEST-2026/case.json from the parent repo.

Writes the rendered SVG (and a small HTML wrapper showing the inline-SVG
embed treatment used by Appendix A) to ./_smoke_flow_out/. Open the
HTML in a browser to inspect what the compliance reader will see.

This script doesn't require Postgres or any worker plumbing — it just
exercises the renderer end-to-end with a real serialized case so we
can verify the new compact layout before pushing to main.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the worktree's src/ importable without installing.
HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parent
sys.path.insert(0, str(WORKTREE / "src"))

from recupero.models import Case  # noqa: E402
from recupero.worker._flow_diagram import (  # noqa: E402
    read_inline_svg,
    render_flow_diagram,
)


def main() -> int:
    default_case = Path(
        r"C:\Users\apros\Downloads\recupero-io\data\cases\ALEC-TEST-2026\case.json"
    )
    case_path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_case
    if not case_path.exists():
        print(f"FAIL: case.json not found at {case_path}")
        return 1

    raw = json.loads(case_path.read_text(encoding="utf-8"))
    case = Case.model_validate(raw)
    print(
        f"loaded case {case.case_id}: "
        f"seed={case.seed_address} chain={case.chain.value} "
        f"transfers={len(case.transfers)}"
    )

    out_dir = HERE / "_smoke_flow_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    svg_path = out_dir / "flow.svg"
    render_flow_diagram(case, svg_path)

    if not svg_path.exists():
        print("FAIL: SVG was not written")
        return 1

    size = svg_path.stat().st_size
    inline = read_inline_svg(svg_path)
    print(f"svg written ({size} bytes); inline svg len = {len(inline or '')}")

    # Quick check: did we end up with a reasonable aspect ratio in the
    # rendered viewBox? Print it so we can eyeball the result.
    import re
    m = re.search(r'viewBox="([\d.\s]+)"', inline or "")
    if m:
        parts = m.group(1).split()
        if len(parts) == 4:
            w, h = float(parts[2]), float(parts[3])
            print(f"viewBox aspect ratio: {w:.0f}x{h:.0f} = {w / max(h, 1):.2f}:1")

    # Drop a minimal HTML wrapper that mirrors the appendix treatment so
    # we can preview in a browser.
    html_path = out_dir / "preview.html"
    html_path.write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>"
        "body { font-family: Inter, system-ui, sans-serif; margin: 2em; }"
        ".appendix-eyebrow { color: #B8924A; letter-spacing: 0.18em; "
        "  font-size: 11px; text-transform: uppercase; }"
        ".appendix-flow-frame { border: 1px solid #E2E8F0; padding: 12px; "
        "  background: #fff; margin: 16px 0; }"
        ".appendix-flow-frame svg { display: block; width: 100%; height: auto; "
        "  max-height: 7in; }"
        "h1 { font-family: Georgia, serif; margin: 0.2em 0 0.5em; }"
        "</style></head><body>"
        "<div class='appendix-eyebrow'>Appendix A</div>"
        "<h1>Fund Flow Diagram</h1>"
        "<div class='appendix-flow-frame'>"
        f"{inline}"
        "</div>"
        "</body></html>",
        encoding="utf-8",
    )
    print(f"preview html: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
