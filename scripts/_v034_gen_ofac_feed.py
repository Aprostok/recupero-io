"""Generate labels/seeds/ofac_crypto_live.csv from the authoritative OFAC SDN
feed, using the repo's OWN parser (trace.ofac_sync._extract_crypto_entries) so
the format matches what risk_scoring.load_high_risk_db() consumes.

WHY: sanctioned-address coverage must come from OFAC's authoritative feed, NOT
hand-maintained hardcoded labels. A cross-check (scripts/_v034_sdn_crosscheck.py)
proved the hardcoded high_risk.json sanctioned labels were systematically
mis-attributed (e.g. an address OFAC lists under "SUEX OTC" was hardcoded as
"Garantex"; one under "Mingming Wang / fentanyl" was hardcoded as "Sinbad.io").
The live feed carries OFAC's own correct attribution for every entry.

Run:
  python scripts/_v034_gen_ofac_feed.py                 # downloads the live SDN
  python scripts/_v034_gen_ofac_feed.py <local_sdn.xml> # uses a local copy

Re-runnable. In production this is refreshed by `recupero-ops ofac-sync`
(weekly cron); this script is the one-shot baseline generator.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

from recupero.trace.ofac_sync import (
    DEFAULT_OFAC_CSV_PATH,
    OFAC_SDN_XML_URL,
    _extract_crypto_entries,
    _write_csv_atomic,
)


def main() -> int:
    if len(sys.argv) > 1:
        xml_bytes = Path(sys.argv[1]).read_bytes()
        src = sys.argv[1]
    else:
        with urllib.request.urlopen(OFAC_SDN_XML_URL, timeout=120) as r:  # noqa: S310
            xml_bytes = r.read()
        src = OFAC_SDN_XML_URL
    entries = _extract_crypto_entries(xml_bytes)
    _write_csv_atomic(DEFAULT_OFAC_CSV_PATH, entries)
    print(f"wrote {len(entries)} OFAC crypto entries to {DEFAULT_OFAC_CSV_PATH} (source: {src})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
