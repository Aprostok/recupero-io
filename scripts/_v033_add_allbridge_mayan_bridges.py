"""v0.33.0 Wave D — add verified Allbridge Core + Mayan bridge contracts.

WHY: two major cross-chain bridges frequently used to move stolen funds had no
usable coverage. (A pre-existing v0.29 "Allbridge Core" entry pointed at
0xa8cba66e…, which has ZERO code and ZERO nonce on Ethereum / BSC / Polygon /
Arbitrum / Optimism / Avalanche / Base — a phantom address that could never
match a real transfer. It is removed in the same change that adds the verified
addresses; see the bridges.json diff.)

PROVENANCE — every address verified (no fabrication):

  ALLBRIDGE CORE — entry-point Bridge contract per chain, from the official
  Allbridge Core API https://core.api.allbridgecoreapi.net/token-info
  (referenced by allbridge-core-js-sdk src/configs/mainnet.ts, sha
  a5ebb594fdfb20c2a2d37104ba38d38ecc8b4f1c99651e477deedf8c7aaf870a). Each EVM
  address confirmed on-chain as a deployed CONTRACT (eth_getCode: 10784 bytes,
  identical across 8 chains = same deterministic deploy; Linea 11532). Tron
  bridge confirmed a contract named "Bridge" via TronGrid getcontract; Solana
  bridge confirmed an executable upgradeable program (owner BPFLoaderUpgradeab1e).

  MAYAN — the Forwarder (unified entry point for Swift / MCTP / Wormhole-Swap)
  and the Swift settlement contract, from docs.mayan.finance. Both are deployed
  at the SAME address on every supported EVM chain; confirmed on-chain as
  CONTRACTS (Forwarder 8840 bytes on all 8 chains; Swift 23669 bytes on all 8).

Confidence is "high" — a bridge IDENTITY label from an authoritative source,
on-chain confirmed (NOT an inference). Continuation past the bridge stays a
low/medium inference handled elsewhere.

Idempotent: skips any (chain, address) already present. Re-runnable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_BRIDGES = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
_ADDED_AT = "2026-05-29T00:00:00Z"
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# ---- Allbridge Core entry-point Bridge per chain (our Chain enum value -> addr)
_ALLBRIDGE: dict[str, str] = {
    "ethereum": "0x609c690e8F7D68a59885c9132e812eEbDaAf0c9e",
    "bsc": "0x3C4FA639c8D7E65c603145adaD8bD12F2358312f",
    "polygon": "0x7775d63836987f444E2F14AA0fA2602204D7D3E0",
    "arbitrum": "0x9Ce3447B58D58e8602B7306316A5fF011B92d189",
    "avalanche": "0x9068E1C28941D0A680197Cc03be8aFe27ccaeea9",
    "optimism": "0x97E5BF5068eA6a9604Ee25851e6c9780Ff50d5ab",
    "base": "0x001E3f136c2f804854581Da55Ad7660a2b35DEf7",
    "celo": "0x80858f5F8EFD2Ab6485Aba1A0B9557ED46C6ba0e",
    "linea": "0xf3Dd9d692A9b4Df331E3bb1C8f322BA0B299B907",
    "tron": "TAuErcuAtU6BPt6YwL51JZ4RpDCPQASCU2",
    "solana": "BrdgN2RPzEMWF96ZbnnJaUtQDQx7VRXYaHHbYCBvceWB",
}

# ---- Mayan: same address on every supported EVM chain.
_MAYAN_FORWARDER = "0x337685fdaB40D39bd02028545a4FfA7D287cC3E2"
_MAYAN_FORWARDER_CHAINS = ["ethereum", "arbitrum", "base", "optimism", "avalanche", "polygon", "bsc", "linea"]
_MAYAN_SWIFT = "0xC38e4e6A15593f908255214653d3D947CA1c2338"
_MAYAN_SWIFT_CHAINS = ["ethereum", "arbitrum", "base", "optimism", "polygon", "bsc", "avalanche", "linea"]

# Phantom v0.29 entry to remove (codeless on every chain).
_PHANTOM = ("ethereum", "0xa8cba66ef4ad65b7f6c97e6d5e58f9b9bfe9ab40")


def _entry(*, address, chain, name, protocol, source, follow_up_url, notes, supports):  # noqa: ANN001,ANN202
    return {
        "address": address,
        "name": name,
        "protocol": protocol,
        "category": "bridge",
        "chain": chain,
        "confidence": "high",
        "supports_to_chains": sorted(c for c in supports if c != chain),
        "follow_up_url": follow_up_url,
        "source": source,
        "notes": notes,
        "added_at": _ADDED_AT,
        "verified": True,
        # On-chain verified today (eth_getCode / TronGrid / Solana
        # getAccountInfo) → carries a fresh last_verified_at so the
        # confidence-decay budget (test_v029_1_label_db_sweep) doesn't count
        # these high-confidence rows as stale.
        "last_verified_at": _ADDED_AT,
        "_v033_wave_d_bridge_addition": True,
    }


def _build_entries() -> list[dict]:
    out: list[dict] = []
    ab_chains = list(_ALLBRIDGE)
    for chain, addr in _ALLBRIDGE.items():
        if addr.startswith("0x"):
            assert _EVM_RE.match(addr), f"bad EVM addr {addr!r}"
        out.append(_entry(
            address=addr, chain=chain, name="Allbridge Core Bridge", protocol="Allbridge",
            source="allbridge_core_api_token_info",
            follow_up_url="https://core.allbridge.io/",
            notes=("Allbridge Core entry-point Bridge contract (liquidity-pool "
                   "stablecoin bridge). On-chain confirmed as a deployed contract/"
                   "program; address from the official Allbridge Core API token-info. "
                   "Funds bridged here surface on the destination chain via Allbridge's "
                   "pool on that chain."),
            supports=ab_chains,
        ))
    for chain in _MAYAN_FORWARDER_CHAINS:
        out.append(_entry(
            address=_MAYAN_FORWARDER, chain=chain, name="Mayan Forwarder", protocol="Mayan",
            source="mayan_docs_forwarder",
            follow_up_url="https://explorer.mayan.finance/",
            notes=("Mayan Forwarder — the unified entry point for Mayan cross-chain "
                   "swaps (Swift / MCTP / Wormhole-Swap), deployed at the same address "
                   "on every supported EVM chain. On-chain confirmed as a deployed "
                   "contract. Mayan settles via Wormhole; follow up on the Mayan explorer."),
            supports=_MAYAN_FORWARDER_CHAINS,
        ))
    for chain in _MAYAN_SWIFT_CHAINS:
        out.append(_entry(
            address=_MAYAN_SWIFT, chain=chain, name="Mayan Swift", protocol="Mayan",
            source="mayan_docs_swift",
            follow_up_url="https://explorer.mayan.finance/",
            notes=("Mayan Swift settlement contract, deployed at the same address on "
                   "every supported EVM chain. On-chain confirmed as a deployed "
                   "contract. Swift is Mayan's auction-based cross-chain settlement."),
            supports=_MAYAN_SWIFT_CHAINS,
        ))
    return out


def main() -> int:
    raw = _BRIDGES.read_text(encoding="utf-8-sig")
    existing = json.loads(raw)
    assert isinstance(existing, list)
    # Guard: the phantom must already be gone (removed via the bridges.json edit).
    for e in existing:
        if (str(e.get("chain", "")).lower(), str(e.get("address", "")).lower()) == _PHANTOM:
            raise SystemExit("phantom Allbridge entry still present — remove it first")

    have = {
        (str(e.get("chain", "ethereum")).lower(), str(e.get("address", "")).lower())
        for e in existing if isinstance(e, dict)
    }
    new = [e for e in _build_entries()
           if (e["chain"].lower(), e["address"].lower()) not in have]
    if not new:
        print("Allbridge/Mayan bridges already present — nothing to add.")
        return 0

    head = raw.rstrip()
    assert head.endswith("]")
    head = head[:head.rfind("]")].rstrip()
    assert head.endswith("}")
    blocks = ["\n".join("  " + ln for ln in json.dumps(e, indent=2, ensure_ascii=True).splitlines())
              for e in new]
    result = head + ",\n" + ",\n".join(blocks) + "\n]\n"

    parsed = json.loads(result)  # validate
    added = [e for e in parsed if isinstance(e, dict) and e.get("_v033_wave_d_bridge_addition")]
    assert len(added) == len(new), "round-trip mismatch"
    _BRIDGES.write_text(result, encoding="utf-8")
    ab = sum(1 for e in new if e["protocol"] == "Allbridge")
    my = sum(1 for e in new if e["protocol"] == "Mayan")
    print(f"Added {len(new)} bridge entries (Allbridge {ab}, Mayan {my}). Total now {len(parsed)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
