"""Cross-check every hardcoded 'sanctioned' seed address against the live OFAC
SDN list. A leading tracer must show ONLY real, correctly-attributed wallets:
this proves, per address, whether our hardcoded label matches OFAC's actual
designation (or whether the address is sanctioned at all). Report-only.

Usage: python scripts/_v034_sdn_crosscheck.py <path-to-sdn.xml>
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SEEDS = _ROOT / "src" / "recupero" / "labels" / "seeds"


def build_sdn_index(xml_path: Path) -> dict[str, list[tuple[str, str, str]]]:
    xml = xml_path.read_text(encoding="utf-8", errors="replace")
    xml = re.sub(r'\sxmlns="[^"]+"', "", xml, count=1)
    root = ET.fromstring(xml)
    idx: dict[str, list[tuple[str, str, str]]] = {}
    for e in root.iter("sdnEntry"):
        uid = (e.findtext("uid") or "").strip()
        name = f"{(e.findtext('firstName') or '').strip()} {(e.findtext('lastName') or '').strip()}".strip()
        prog = ";".join(p.text or "" for p in e.iter("program"))
        for idd in e.iter("id"):
            if "Digital Currency" in (idd.findtext("idType") or ""):
                n = (idd.findtext("idNumber") or "").strip().lower()
                if n:
                    idx.setdefault(n, []).append((uid, name, prog))
    return idx


def _norm(tok: object) -> str:
    return str(tok).strip().lower() if tok else ""


def main() -> int:
    if len(sys.argv) < 2:
        print("need SDN xml path")
        return 2
    idx = build_sdn_index(Path(sys.argv[1]))
    print(f"SDN digital-currency addresses indexed: {len(idx)}\n")

    def claims_sanctioned(entry: dict) -> bool:
        cat = _norm(entry.get("risk_category"))
        notes = _norm(entry.get("notes"))
        if cat.startswith("ofac") or cat == "mixer_sanctioned":
            return True
        return ("ofac" in notes or "sanction" in notes) and not any(
            m in notes for m in ("delisted", "overturned", "vacated", "no longer sanctioned")
        )

    for fname in ("high_risk.json", "mixers.json", "ransomware.json"):
        path = _SEEDS / fname
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("addresses", data) if isinstance(data, dict) else data
        print(f"=== {fname} ===")
        for e in rows:
            if not isinstance(e, dict) or "address" not in e:
                continue
            if not claims_sanctioned(e):
                continue
            addr = _norm(e.get("address"))
            name = e.get("name", "")
            hits = idx.get(addr)
            if hits:
                sdn_names = "; ".join(f"{n} [{p}]" for _, n, p in hits)
                print(f"  IN-SDN   {addr}  seed={name!r}  ->  SDN={sdn_names}")
            else:
                print(f"  NOT-SDN  {addr}  seed={name!r}  (claims sanctioned but NOT in current SDN)")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
