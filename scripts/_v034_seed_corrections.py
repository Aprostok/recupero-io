"""v0.34 — correct hardcoded seed addresses against AUTHORITATIVE evidence.

Driven by scripts/_v034_sdn_crosscheck.py (OFAC SDN) + on-chain eth_getCode/
eth_call. The hardcoded high_risk.json 'sanctioned' labels were systematically
mis-attributed; OFAC's own feed (now generated into ofac_crypto_live.csv by
scripts/_v034_gen_ofac_feed.py) carries the correct attribution. We REMOVE the
wrong hardcoded entries so the authoritative feed wins (the loader lets a
curated high_risk.json entry override the feed, so a wrong curated label must
be deleted, not left to shadow OFAC's truth).

high_risk.json removals (address -> why):
  0xa7e5d5a720f06526557c513402f2e6b5fa20b008  seed 'Lazarus/Harmony'  -> OFAC: Artem LIFSHITS (CYBER2)
  0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b  seed 'DPRK/Lazarus'      -> OFAC: Dmitrii KARASAVIDI (CYBER2)
  0x7f367cc41522ce07553e823bf3be79a889debe1b  seed 'DPRK/Lazarus'      -> OFAC: Danil POTEKHIN (CYBER2)
  0xb6f5ec1a0a9cd1526536d3f0426c429529471f40  seed 'Hydra Marketplace' -> OFAC: Sang Man KIM (DPRK4)
  0x308ed4b7b49797e1a98d3818bff6fe5385410370  seed 'Garantex'          -> OFAC: SUEX OTC, S.R.O. (CYBER2)
  (all five are STILL sanctioned via the feed, just under their CORRECT OFAC entry.)
  0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963  seed 'Blender.io'        -> NOT in current SDN (unverifiable)
  0xb1c8094b234dce6e03f10a5b673c1d8c69739a00  seed 'Sinbad.io'         -> NOT Sinbad: on-chain bytecode is a Tornado ERC20 pool; not in SDN
  bcrw1fjrwsonyrbn5uxbvksksxdnrwgsqbf5kacduwfv seed 'Lazarus Solana'   -> malformed address + NOT in SDN

mixers.json:
  0x07687e702b410Fa43f4cB4Af7FA097918ffD2730  chain bsc->ethereum, name '40 BNB (BSC)' -> '10,000 DAI'
       (on-chain: eth_getCode = 15KB contract on Ethereum, token() = DAI 0x6b17..271d0f; NO code on BSC.
        Reverses the erroneous v0.30 'BSC deployment' relabel that trusted a bad name over the real chain.)
  0xfac583c0cf07ea434052c49115a4682172ab6b4f  REMOVE 'Sinbad.io (Treasury hash)' -> OFAC: Mingming WANG
       (fentanyl/ILLICIT-DRUGS, not Sinbad, not a mixer; the feed carries it correctly.)

Idempotent. Re-runnable.
"""

from __future__ import annotations

import json
from pathlib import Path

_SEEDS = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds"

_HIGH_RISK_REMOVE = {
    "0xa7e5d5a720f06526557c513402f2e6b5fa20b008",
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b",
    "0xb6f5ec1a0a9cd1526536d3f0426c429529471f40",
    "0x308ed4b7b49797e1a98d3818bff6fe5385410370",
    "0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963",
    "0xb1c8094b234dce6e03f10a5b673c1d8c69739a00",
    "bcrw1fjrwsonyrbn5uxbvksksxdnrwgsqbf5kacduwfv",
}
_MIXERS_REMOVE = {"0xfac583c0cf07ea434052c49115a4682172ab6b4f"}
_TC_DAI = "0x07687e702b410fa43f4cb4af7fa097918ffd2730"

_TC_DAI_NOTE = (
    "Tornado Cash mixer (10,000 DAI pool). OFAC-sanctioned 2022-08-08; DELISTED "
    "2025-03-21 (Fifth Circuit held immutable smart contracts are not "
    "sanctionable property). Still a high-risk laundering mixer and DOJ "
    "prosecution of the founders continues, but the protocol is NOT currently "
    "OFAC-sanctioned. CHAIN/DENOMINATION CORRECTED v0.34: on-chain eth_getCode "
    "shows a 15KB contract on Ethereum and token() returns DAI "
    "(0x6b175474e89094c44da98b954eedeac495271d0f); eth_getCode on BSC returns "
    "0x (no code) -- reversing the erroneous v0.30 'BSC deployment' relabel that "
    "trusted a bad name over the real chain."
)


def _addr(e: dict) -> str:
    return str(e.get("address", "")).strip().lower()


def main() -> int:
    # high_risk.json
    hr = _SEEDS / "high_risk.json"
    d = json.loads(hr.read_text(encoding="utf-8"))
    rows = d["addresses"]
    before = len(rows)
    d["addresses"] = [
        e for e in rows
        if not (isinstance(e, dict) and _addr(e) in _HIGH_RISK_REMOVE)
    ]
    hr_removed = before - len(d["addresses"])
    hr.write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # mixers.json
    mx = _SEEDS / "mixers.json"
    rows2 = json.loads(mx.read_text(encoding="utf-8"))
    out = []
    mx_removed = mx_fixed = 0
    for e in rows2:
        a = _addr(e)
        if a in _MIXERS_REMOVE:
            mx_removed += 1
            continue
        if a == _TC_DAI:
            e["name"] = "Tornado Cash: 10,000 DAI"
            e["chain"] = "ethereum"
            e["notes"] = _TC_DAI_NOTE
            e.pop("_v030_chain_corrected", None)
            e["_v034_onchain_verified"] = (
                "eth_getCode: contract on Ethereum (token()=DAI), no code on BSC"
            )
            mx_fixed += 1
        out.append(e)
    mx.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"high_risk.json: removed {hr_removed} mis-attributed/unverifiable entries; "
          f"mixers.json: removed {mx_removed}, corrected {mx_fixed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
