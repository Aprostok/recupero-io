"""Score a produced case against the Zigha ground-truth: did the trace REACH
each of the 4 curated endpoints? (Reach = the address appears on any transfer
leg / counterparty / current-holder in case.json, on any chain.)
"""
from __future__ import annotations

import json
import pathlib
import sys

_CASE_ID = sys.argv[1] if len(sys.argv) > 1 else "ZIGHA-VERIFY"
CASE = pathlib.Path(f"data/cases/{_CASE_ID}/case.json")
GT = pathlib.Path("tests/fixtures/zigha_ground_truth.json")

case = json.loads(CASE.read_text(encoding="utf-8"))
gt = json.loads(GT.read_text(encoding="utf-8"))

# Collect every address that appears anywhere in the trace, lowercased.
seen: set[str] = set()
chain_of: dict[str, set[str]] = {}


def _add(addr, chain=None):
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42:
        a = addr.lower()
        seen.add(a)
        if chain:
            chain_of.setdefault(a, set()).add(chain)


transfers = case.get("transfers") or []
for t in transfers:
    ch = t.get("chain")
    for key in ("from_address", "to_address", "from", "to", "recipient",
                "counterparty", "counterparty_address", "current_holder"):
        _add(t.get(key), ch)
# bridge confirmations (cross-chain recipients)
cu = case.get("config_used") or {}
for c in (cu.get("bridge_confirmations") or []):
    _add(c.get("recipient"), c.get("dst_chain"))

print(f"case transfers: {len(transfers)}   distinct addresses seen: {len(seen)}")
cov = cu.get("coverage") or {}
print(f"coverage.complete={cov.get('complete')} poisoning={cov.get('poisoning_detected')} "
      f"cap_truncations={len(cov.get('per_address_cap_truncations') or [])} "
      f"value_matched_hops={len(cov.get('value_matched_hops') or [])}")
bc = cu.get("bridge_confirmations") or []
print(f"bridge_confirmations recorded: {len(bc)}")
for c in bc:
    print(f"   - {c.get('protocol')} {c.get('source_chain')}->{c.get('dst_chain')} "
          f"recipient={c.get('recipient')} order_id={str(c.get('order_id'))[:18]}…")

print("\n=== GROUND TRUTH REACH ===")
hit = 0
for item in gt.get("expected_destinations") or []:
    a = (item.get("address") or "").lower()
    reached = a in seen
    hit += reached
    mark = "REACHED [OK]" if reached else "MISSED  [--]"
    ch = ",".join(sorted(chain_of.get(a, []))) or "—"
    print(f"  [{mark}] {item.get('address')}  ({item.get('chain')}, ~${item.get('approx_usd'):,}) "
          f"{item.get('role')}  seen_on={ch}")
print(f"\nREACHED {hit}/{len(gt.get('expected_destinations') or [])} ground-truth endpoints")
sys.exit(0)
