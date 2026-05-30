"""v0.34 #8 — reclassify Tornado Cash from OFAC-sanctioned to high-risk mixer.

OFAC DELISTED the Tornado Cash protocol smart contracts on 2025-03-21, after
the Fifth Circuit (Van Loon v. Treasury, Nov 2024) held that immutable smart
contracts are not the "property" of a foreign national and thus not
sanctionable. (Co-founder Roman Semenov remains designated under the North
Korea program; DOJ criminal prosecution of the founders continues.) Verified
against the live OFAC SDN feed (sha-pinned download 2026-05-30): NO "Tornado
Cash" entity entry remains; only Semenov (an Individual) and his personal
addresses are still listed.

Our seeds still treated the Tornado PROTOCOL contracts as currently
OFAC-sanctioned: high_risk.json carried risk_category "mixer_sanctioned", and
the mixers.json loader auto-promotes any entry whose notes mention OFAC to
"mixer_sanctioned" — which routes a hit to a SANCTIONED screener verdict and an
OFAC freeze letter. For a law-enforcement deliverable, asserting a CURRENT OFAC
sanction on a DELISTED protocol is a forensic-accuracy defect.

Per the operator decision (legally-precise posture): reclassify the Tornado
PROTOCOL contracts as high-risk mixers (still flagged prominently, with the
full sanctions history) but NOT currently OFAC-sanctioned (no OFAC letter). The
loader change in risk_scoring.py (delisting markers in notes demote
"sanctioned" -> "high_risk") does the runtime work; this script corrects the
seed notes so the facts are right AND the loader demotes them.

Idempotent (skips notes already mentioning the delisting). Re-runnable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_SEEDS = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds"
_DELISTED = "2025-03-21"


def _corrected_note(detail: str) -> str:
    d = f" ({detail})" if detail else ""
    return (
        f"Tornado Cash mixer{d}. OFAC-sanctioned 2022-08-08; DELISTED "
        f"{_DELISTED} (Fifth Circuit held immutable smart contracts are not "
        "sanctionable property). Still a high-risk laundering mixer and DOJ "
        "prosecution of the founders continues, but the protocol is NOT "
        "currently OFAC-sanctioned."
    )


def _detail_from(note: str) -> str:
    """Preserve any distinguishing detail after an 'OFAC SANCTIONED' prefix
    (e.g. 'alternate deployment', 'BSC deployment')."""
    m = re.search(r"OFAC\s*SANCTIONED", note, re.I)
    if not m:
        return ""
    # strip leading separators/dashes/colons before the distinguishing detail.
    return note[m.end():].lstrip(" \t-:|—–─━").strip()


def _is_tornado(e: dict) -> bool:
    blob = f"{e.get('name', '')} {e.get('notes') or ''}".lower()
    return "tornado" in blob


def main() -> int:
    # mixers.json — correct notes so the loader demotes (delisting marker).
    mx = _SEEDS / "mixers.json"
    d = json.loads(mx.read_text(encoding="utf-8-sig"))
    rows = d if isinstance(d, list) else d.get("addresses", [])
    mx_changed = 0
    for e in rows:
        if not isinstance(e, dict) or not _is_tornado(e):
            continue
        note = e.get("notes") or ""
        if "delisted" in note.lower():
            continue  # idempotent
        e["notes"] = _corrected_note(_detail_from(note))
        mx_changed += 1
    if mx_changed:
        mx.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # high_risk.json — reclassify mixer_sanctioned -> mixer_high_risk + dates.
    hr = _SEEDS / "high_risk.json"
    d2 = json.loads(hr.read_text(encoding="utf-8-sig"))
    rows2 = d2.get("addresses", []) if isinstance(d2, dict) else d2
    hr_changed = 0
    for e in rows2:
        if not isinstance(e, dict) or not _is_tornado(e):
            continue
        if (e.get("notes") or "").lower().count("delisted"):
            continue  # idempotent
        if e.get("risk_category") == "mixer_sanctioned":
            e["risk_category"] = "mixer_high_risk"
        e["ofac_delisted_date"] = _DELISTED
        e["notes"] = _corrected_note("")
        hr_changed += 1
    if hr_changed:
        hr.write_text(json.dumps(d2, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"mixers.json: {mx_changed} Tornado notes corrected; "
          f"high_risk.json: {hr_changed} entries reclassified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
