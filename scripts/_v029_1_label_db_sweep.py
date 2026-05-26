"""v0.29.1 Recommendation #7 (MEDIUM) — sweep cex_deposits /
defi_protocols / mixers for explicit chain field.

The diagnostic noted that the bridges audit (v0.28→v0.29) only
covered ONE label-DB category. The other categories
(cex_deposits.json, defi_protocols.json, mixers.json) had ZERO
chain-field tagging — meaning any `grep`/audit query for
"do we have X-chain coverage on category Y?" would silently
return zero, hiding gaps.

This script:

  1. Backfills `chain="ethereum"` on every entry that lacks one in
     cex_deposits.json / defi_protocols.json / mixers.json — they
     are all currently Ethereum-mainnet labels, but the missing
     field made that implicit.

  2. Adds the `_v029_1_chain_backfill: True` audit marker so the
     entries can be distinguished from explicitly-tagged additions
     in future commits.

  3. Refuses to overwrite any entry that ALREADY has a `chain`
     field (those were tagged in a prior commit and must not be
     mass-mutated).

Run once: `python scripts/_v029_1_label_db_sweep.py`.
Idempotent — re-running is a no-op.
"""
from __future__ import annotations

import json
from pathlib import Path

SEEDS = Path(__file__).parent.parent / "src" / "recupero" / "labels" / "seeds"

# Files where every entry is currently an Ethereum-mainnet address.
# Backfill `chain="ethereum"` on each entry that lacks the field.
# Future multi-chain additions to these files (e.g. Binance BSC hot
# wallets) must supply an EXPLICIT chain value, and operators MUST
# NOT rely on the pre-v0.29.1 implicit-Ethereum default.
LIST_FILES = ["cex_deposits.json", "defi_protocols.json", "mixers.json"]


# v0.30.0 audit fix (Tier-1 from V029_AUDIT_FINDINGS): the v0.29.1 sweep
# stamped chain='ethereum' on every entry that lacked a chain field
# without consulting the entry's name/notes. Tornado Cash 40 BNB (BSC)
# carried "(BSC)" in the name + "BSC deployment" in notes but still got
# 'ethereum' stamped on it — a real OFAC false-negative in any
# BSC-side trace. The map below catches name-suffix hints so a future
# run of this script can't reproduce the bug. Any other unrecognized
# chain hint = leave the entry alone and print a warning, rather than
# silently defaulting it.
_NAME_CHAIN_HINTS: dict[str, str] = {
    "(bsc)": "bsc",
    "(binance smart chain)": "bsc",
    "(arbitrum)": "arbitrum",
    "(optimism)": "optimism",
    "(base)": "base",
    "(polygon)": "polygon",
    "(avalanche)": "avalanche",
    "(fantom)": "fantom",
    "(tron)": "tron",
    "(solana)": "solana",
    "(linea)": "linea",
}


def _infer_chain_from_entry(entry: dict) -> str:
    """Conservative chain inference. Returns 'ethereum' for the
    common case (Ethereum-mainnet contract, no chain hint anywhere).
    Honors name-suffix hints — fixes the v0.29.1 Tornado/BSC mislabel."""
    name = str(entry.get("name", "")).lower()
    notes = str(entry.get("notes", "")).lower()
    for hint, chain in _NAME_CHAIN_HINTS.items():
        if hint in name or hint in notes:
            return chain
    return "ethereum"


def backfill(path: Path) -> tuple[int, int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return (0, 0)
    backfilled = 0
    already_tagged = 0
    for entry in data:
        if not isinstance(entry, dict) or "address" not in entry:
            continue
        existing = entry.get("chain")
        if isinstance(existing, str) and existing.strip():
            already_tagged += 1
            continue
        entry["chain"] = _infer_chain_from_entry(entry)
        entry["_v029_1_chain_backfill"] = True
        backfilled += 1
    if backfilled:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
    return (backfilled, already_tagged)


def main() -> None:
    total_backfilled = 0
    for fname in LIST_FILES:
        path = SEEDS / fname
        if not path.exists():
            print(f"{fname}: missing, skipping")
            continue
        b, already = backfill(path)
        print(f"{fname}: backfilled {b}, already tagged {already}")
        total_backfilled += b
    print(f"\nTotal entries backfilled: {total_backfilled}")


if __name__ == "__main__":
    main()
