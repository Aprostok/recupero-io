"""recupero-ops ofac-sync

Downloads the latest OFAC SDN List XML feed from treasury.gov,
extracts all crypto-address entries, and writes them to a
local CSV that the risk-scoring module loads automatically.

Recommended cadence: weekly, via cron.

Output:
  - Writes ~labels/seeds/ofac_crypto_live.csv (atomic rename)
  - Prints summary: # entries by chain
  - Exit codes:
      0 = success
      1 = unreachable / parse failed (existing CSV preserved)
      2 = succeeded with empty result (suspicious — feed format
          may have changed)
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from recupero.trace.ofac_sync import (
    DEFAULT_OFAC_CSV_PATH,
    OFAC_SDN_XML_URL,
    load_ofac_csv,
    sync_ofac_sdn,
)

log = logging.getLogger(__name__)


def run(*, output_path: Path | None = None) -> int:
    """Run the OFAC sync. Returns exit code per the module docstring."""
    out_path = output_path or DEFAULT_OFAC_CSV_PATH

    print(f"Fetching OFAC SDN List from: {OFAC_SDN_XML_URL}")
    print("(Treasury feed is ~50MB; this takes 30-60 seconds.)")
    print()

    result = sync_ofac_sdn(output_path=out_path)

    if not result.success:
        if result.stale:
            print(
                f"ERROR: OFAC feed unreachable — {result.error_message}\n"
                "  The existing local CSV at "
                f"{out_path} (if any) will continue to be used.\n"
                "  Try again later; Treasury occasionally takes the feed "
                "offline for maintenance."
            )
        else:
            print(f"ERROR: OFAC sync failed — {result.error_message}")
        return 1

    if result.entries_written == 0:
        print(
            "WARN: sync succeeded but no crypto-address entries were "
            "extracted from the feed.\n"
            "  This is suspicious — the OFAC feed format may have changed. "
            "Check the XML schema at:\n"
            f"  {OFAC_SDN_XML_URL}\n"
            "  Existing data preserved."
        )
        return 2

    # Reload + summarize
    entries = load_ofac_csv(out_path)
    chains = Counter(e.chain for e in entries)

    print(f"OK — synced {result.entries_written} OFAC crypto-address entries.")
    print(f"     Written to: {out_path}")
    print(f"     Fetched at: {result.fetched_at}")
    print()
    print("By chain:")
    for chain, n in sorted(chains.items(), key=lambda x: -x[1]):
        print(f"  {chain:15s} {n}")
    print()
    print(
        "These entries are now part of the risk-scoring DB and "
        "will appear in the next investigation's RISK_ASSESSMENT.\n"
        "No code deploy required."
    )
    return 0


__all__ = ("run",)
