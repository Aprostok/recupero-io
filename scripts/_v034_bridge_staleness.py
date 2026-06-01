"""Bridge-spec staleness monitor (v0.34.3) — crisp 3-way classification.

The fresh-input generalization test caught the DLN destination fill event going
silent (the protocol upgraded its event after our spec was verified vs the
Oct-2025 Zigha pair). A "verified vs one real pair" spec is a point-in-time
snapshot — it works on the case you tuned it to and quietly fails on a fresh one
as the protocol drifts. This monitor closes that gap.

For EVERY BridgePairSpec it checks the SOURCE event topic0 + DESTINATION fill
event topic0(s) over a WIDE recent window, and classifies:

  OK       — source live AND >=1 dest fill event live. Confirms current cases.
  STALE    — our event(s) silent, BUT a spec CONTRACT still emits OTHER events
             (the protocol changed its event at a live contract) → REAL BUG: a
             live case would silently return UNCONFIRMED. Must refresh the spec.
  DORMANT  — our events silent AND the spec's contracts emit nothing (protocol
             deprecated / no volume). The spec is still correct for HISTORICAL
             cases; not a bug, informational only.

Exit code != 0 only on STALE (deploy-blocking); DORMANT is allowed.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request

from recupero.trace.bridge_pairings import _REGISTRY

# Protocols whose staleness/dormancy is KNOWN + documented (in the spec notes).
# The monitor still reports them, but only NEW (unacknowledged) drift fails CI —
# so this stays a useful gate without going permanently red on a deprecated rail.
_ACKNOWLEDGED = {
    "Synapse": "CLASSIC rail — source TokenDeposit silent; current volume MOVED to "
               "Synapse RFQ (now covered + verified); dest mint still confirms historical cases",
    "Synapse RFQ": "intent rail at 0x5523… — low source volume so BridgeRequested may be "
                   "silent in-window, but signature VERIFIED vs a real OP→ETH pair and dest "
                   "BridgeRelayed is live; confirms when used",
    "Connext": "Amarok deprecated (→Everclear); contracts dormant; historical cases confirm",
}

with open(".env") as _f:
    _KEY = re.search(r'ETHERSCAN_API_KEY\s*=\s*"?([^"\n]+)', _f.read()).group(1).strip()
PROBE_CHAINS = {"ethereum": 1, "arbitrum": 42161, "base": 8453,
                "optimism": 10, "polygon": 137, "bsc": 56}
# WIDE window (~weeks) so a low-volume-but-current protocol isn't false-flagged.
SPAN = {1: 300000, 42161: 4000000, 8453: 2000000, 10: 2000000, 137: 1200000, 56: 800000}


def _call(cid, **p):
    p.update(chainid=cid, apikey=_KEY)
    u = "https://api.etherscan.io/v2/api?" + "&".join(f"{k}={v}" for k, v in p.items())
    try:
        return json.loads(urllib.request.urlopen(u, timeout=45).read())
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


_HEADS: dict[int, int] = {}
def _head(cid):
    if cid not in _HEADS:
        _HEADS[cid] = int(_call(cid, module="proxy", action="eth_blockNumber").get("result", "0x0"), 16)
    return _HEADS[cid]


def _emits(topic0, *, address="") -> str | None:
    """First chain where topic0 (optionally from address) emits in the window."""
    for nm, cid in PROBE_CHAINS.items():
        cur = _head(cid)
        if not cur:
            continue
        p = {"module": "logs", "action": "getLogs", "topic0": topic0,
             "fromBlock": cur - SPAN[cid], "toBlock": cur, "page": 1, "offset": 3}
        if address:
            p["address"] = address
        r = _call(cid, **p).get("result")
        if isinstance(r, list) and r:
            return nm
    return None


def _contract_active(addr) -> str | None:
    """First chain where this contract emits ANY event recently (=> live)."""
    for nm, cid in PROBE_CHAINS.items():
        cur = _head(cid)
        r = _call(cid, module="logs", action="getLogs", address=addr,
                  fromBlock=cur - SPAN[cid] // 4, toBlock=cur, page=1, offset=3).get("result")
        if isinstance(r, list) and r:
            return nm
    return None


print("=== BRIDGE-SPEC STALENESS MONITOR (wide window, 3-way) ===")
stale: list[str] = []
dormant: list[str] = []
for spec in _REGISTRY:
    src = _emits(spec.source_event_topic0)
    dests = {dt: _emits(dt) for dt in (spec.dest_event_topic0, *spec.dest_event_topics)}
    any_dest = any(dests.values())
    if src and any_dest:
        live_dest = next(d for d, v in dests.items() if v)
        print(f"[OK     ] {spec.protocol:9} source live@{src}; dest live ({live_dest[:10]}…)")
        continue
    # something silent — is any spec contract still active?
    addrs = list(spec.source_contracts)[:1] + list((spec.dest_contracts or {}).values())[:1]
    if spec.dest_contract:
        addrs.append(spec.dest_contract)
    active = next((c for a in addrs if a for c in [_contract_active(a)] if c), None)
    why = f"source={'live@'+src if src else 'SILENT'}, dest={'live' if any_dest else 'SILENT'}"
    if active:
        print(f"[STALE  ] {spec.protocol:9} {why} — but a contract is LIVE@{active} (event changed → refresh spec)")
        stale.append(spec.protocol)
    else:
        print(f"[DORMANT] {spec.protocol:9} {why} — contracts emit nothing (deprecated/no volume; spec ok for historical)")
        dormant.append(spec.protocol)

print()
print(f"OK={len(_REGISTRY)-len(stale)-len(dormant)}  STALE={stale}  DORMANT={dormant}")
new_stale = [p for p in stale if p not in _ACKNOWLEDGED]
new_dormant = [p for p in dormant if p not in _ACKNOWLEDGED]
if new_stale or new_dormant:
    print(f"NEW (unacknowledged) drift — FAIL: stale={new_stale} dormant={new_dormant}")
    print("  → refresh the spec, then add to _ACKNOWLEDGED with a note once handled.")
    sys.exit(1)
if stale or dormant:
    print(f"All flagged specs are ACKNOWLEDGED/documented: {sorted(set(stale)|set(dormant))} — OK.")
sys.exit(0)
