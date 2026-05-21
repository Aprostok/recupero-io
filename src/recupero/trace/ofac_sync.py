"""Live OFAC SDN List sync (v0.9.4).

Treasury's Office of Foreign Assets Control publishes the
Specially Designated Nationals (SDN) List as a downloadable
XML feed updated multiple times per week:

  https://www.treasury.gov/ofac/downloads/sdn.xml         (full feed)
  https://www.treasury.gov/ofac/downloads/sdnlist.txt     (plain text)
  https://www.treasury.gov/ofac/downloads/cons_advanced.xml (consolidated)

Crypto addresses appear as ``<id idType="Digital Currency Address - <CHAIN>" idNumber="<ADDRESS>">``
sub-elements within each entry. We parse the XML, extract all
crypto-address entries, and merge into the local high-risk DB.

Why live sync vs static seed?
-----------------------------

The high_risk.json file ships a curated snapshot of the most
significant OFAC additions (Lazarus, Garantex, Hydra, Tornado
Cash). Live sync ensures:

  * New additions land in the next investigation (OFAC adds
    addresses weekly; static seeds drift).
  * Removals propagate (occasionally addresses are de-listed;
    Tornado Cash's partial 2024 ruling, for example).
  * Full coverage of digital-asset SDN entries, not just the
    ones we manually curated.

The sync is operator-triggered, not automatic — Treasury's
feed is large (~50MB XML) and we don't want to refresh on every
investigation. Recommended cadence: weekly via cron, or manually
via `recupero-ops ofac-sync` (added in v0.9.4).

Output format
-------------

Writes a CSV at the configured path
(default `data/ofac_crypto_sdn.csv`) with columns:

    address, chain, sdn_entry_name, sdn_entry_id, listing_date

The risk_scoring module loads this CSV in addition to
high_risk.json/ransomware.json/mixers.json so live additions
flow into the brief's RISK_ASSESSMENT section without a code
deploy.

Defensive design
----------------

  * If the OFAC feed is unreachable (network down, Treasury
    server outage), the sync logs a warning and returns
    "stale=true". Existing data continues to be used.
  * The XML parser is permissive — Treasury occasionally
    changes the schema slightly (added/removed sub-elements).
    Parser skips entries it can't interpret rather than
    failing the whole sync.
  * The CSV is written atomically (temp file + rename) so a
    sync that fails mid-write doesn't leave a half-written
    file blocking risk_scoring from loading it.
"""

from __future__ import annotations

import csv
import logging
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# RIGOR-2a: defusedxml is a hard dependency. The OFAC SDN feed is an
# external untrusted input (MITM-able CDN, supply-chain risk). Stdlib
# xml.etree is vulnerable to billion-laughs / XXE / external-entity
# attacks; a hostile feed could expand a small XML file into a
# multi-gigabyte memory bomb that crashes the sync process (or worse,
# leaks files via XXE).
#
# Pre-RIGOR-2a this module had a try/except fallback to stdlib with a
# runtime WARNING. The "soft" pattern was indistinguishable from
# "defusedxml not in prod" because nobody monitors deploy-time WARN
# logs. Now we fail-closed at import — if defusedxml is missing, the
# sync simply cannot run.
from defusedxml import ElementTree as ET  # type: ignore[import-untyped]
# Compatibility alias retained for any downstream code reading the
# old flag (always True now). Will be removed in a future cleanup.
_XML_PARSER_HARDENED = True

log = logging.getLogger(__name__)


# Treasury OFAC SDN XML feed URLs. The "consolidated_advanced"
# feed is the most complete (includes non-SDN OFAC programs too:
# SSI, MBS, NS-PLC, etc.). We default to the SDN feed because
# that's what crypto compliance reviews against.
OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OFAC_CONS_ADVANCED_URL = "https://www.treasury.gov/ofac/downloads/cons_advanced.xml"

# Default sync output path. Risk_scoring loads it from here.
DEFAULT_OFAC_CSV_PATH = (
    Path(__file__).parent.parent / "labels" / "seeds" / "ofac_crypto_live.csv"
)

# RIGOR-2a: removed _PARSER_HARDENING_WARNED state. defusedxml is
# now a hard dependency (see pyproject.toml + the top-of-file
# import); the runtime WARN-fallback path no longer exists.

# Chains we care about — the OFAC feed labels are like
# "Digital Currency Address - ETH" or "Digital Currency Address - XBT".
# We map their codes to our internal Chain values.
_OFAC_CHAIN_MAP = {
    "ETH": "ethereum",
    "USDC": "ethereum",  # OFAC sometimes labels by stablecoin
    "USDT": "ethereum",
    "BTC": "bitcoin",
    "XBT": "bitcoin",
    "XMR": "monero",
    "SOL": "solana",
    "TRX": "tron",
    "ARB": "arbitrum",
    "DASH": "dash",
    "LTC": "litecoin",
    "ZEC": "zcash",
    "BSC": "bsc",
    "BNB": "bsc",
    "MATIC": "polygon",
    "AVAX": "avalanche",
}


@dataclass(frozen=True)
class OFACCryptoEntry:
    """One crypto address extracted from the OFAC SDN feed."""
    address: str           # lowercased for ETH-family; verbatim for BTC/etc.
    chain: str             # our internal chain identifier
    sdn_entry_name: str    # e.g., "LAZARUS GROUP" or the SDN's primary name
    sdn_entry_id: str      # OFAC's UID for the entry
    listing_date: str      # ISO date if available; "" otherwise


@dataclass(frozen=True)
class SyncResult:
    """Outcome of a sync operation."""
    success: bool
    entries_written: int
    output_path: Path
    fetched_at: str
    error_message: str | None = None
    stale: bool = False  # true if we couldn't reach the feed


def sync_ofac_sdn(
    *,
    url: str = OFAC_SDN_XML_URL,
    output_path: Path | None = None,
    timeout_sec: int = 60,
) -> SyncResult:
    """Download the OFAC SDN XML, extract crypto-address entries,
    and write to a CSV.

    Returns a SyncResult. Does NOT raise — failures log a warning
    and return success=False. The caller (CLI / cron) decides
    whether to retry.

    Use:
      from recupero.trace.ofac_sync import sync_ofac_sdn
      result = sync_ofac_sdn()
      if result.success:
          print(f"Wrote {result.entries_written} entries to {result.output_path}")
    """
    out_path = output_path or DEFAULT_OFAC_CSV_PATH
    fetched_at = datetime.now(UTC).isoformat()

    try:
        log.info("ofac sync: fetching %s", url)
        req = urllib.request.Request(
            url, headers={"User-Agent": "recupero-ofac-sync/0.9.4"},
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            xml_bytes = resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        log.warning("ofac sync: feed unreachable (%s) — using stale data", exc)
        return SyncResult(
            success=False,
            entries_written=0,
            output_path=out_path,
            fetched_at=fetched_at,
            error_message=str(exc),
            stale=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("ofac sync: unexpected error (%s)", exc)
        return SyncResult(
            success=False,
            entries_written=0,
            output_path=out_path,
            fetched_at=fetched_at,
            error_message=str(exc),
        )

    try:
        entries = _extract_crypto_entries(xml_bytes)
    except Exception as exc:  # noqa: BLE001
        log.warning("ofac sync: XML parse failed (%s)", exc)
        return SyncResult(
            success=False,
            entries_written=0,
            output_path=out_path,
            fetched_at=fetched_at,
            error_message=f"parse failed: {exc}",
        )

    try:
        _write_csv_atomic(out_path, entries)
    except Exception as exc:  # noqa: BLE001
        log.warning("ofac sync: CSV write failed (%s)", exc)
        return SyncResult(
            success=False,
            entries_written=len(entries),
            output_path=out_path,
            fetched_at=fetched_at,
            error_message=f"write failed: {exc}",
        )

    log.info(
        "ofac sync: wrote %d crypto-address entries to %s",
        len(entries), out_path,
    )
    return SyncResult(
        success=True,
        entries_written=len(entries),
        output_path=out_path,
        fetched_at=fetched_at,
    )


def load_ofac_csv(
    csv_path: Path | None = None,
    *,
    staleness_warn_days: int = 30,
) -> list[OFACCryptoEntry]:
    """Load the previously-synced OFAC CSV. Returns ``[]`` when
    the file doesn't exist (no prior sync run).

    risk_scoring.load_high_risk_db() calls this so live OFAC
    entries flow into the brief without a code deploy.

    v0.17.6 (round-10 security HIGH): logs a WARN when the CSV file's
    mtime is older than ``staleness_warn_days`` (default 30). Treasury
    updates the SDN list multiple times per week; running with a
    months-old CSV is the silent failure mode of "this case missed
    a newly-listed Lazarus wallet because the sync cron broke 6 weeks
    ago." Operators see this warning in Railway logs and can
    investigate. Set staleness_warn_days=0 to disable (tests).
    """
    path = csv_path or DEFAULT_OFAC_CSV_PATH
    if not path.exists():
        log.debug("ofac csv not present at %s (no prior sync)", path)
        return []
    if staleness_warn_days > 0:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            age_days = (datetime.now(UTC) - mtime).days
            if age_days > staleness_warn_days:
                log.warning(
                    "ofac_csv: file at %s is %d days old (threshold %d). "
                    "Treasury updates the SDN list ~3x/week; this deploy "
                    "may be missing recent additions. Re-run "
                    "`recupero-ops ofac-sync` to refresh.",
                    path, age_days, staleness_warn_days,
                )
        except OSError:
            pass
    try:
        out: list[OFACCryptoEntry] = []
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                addr = (row.get("address") or "").strip()
                if not addr:
                    continue
                out.append(OFACCryptoEntry(
                    address=addr.lower() if _is_evm_address(addr) else addr,
                    chain=(row.get("chain") or "ethereum").lower(),
                    sdn_entry_name=row.get("sdn_entry_name", ""),
                    sdn_entry_id=row.get("sdn_entry_id", ""),
                    listing_date=row.get("listing_date", ""),
                ))
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("ofac csv load failed: %s", exc)
        return []


# ----- internals ----- #


def _extract_crypto_entries(xml_bytes: bytes) -> list[OFACCryptoEntry]:
    """Parse the OFAC SDN XML and extract crypto address entries.

    v0.17.6: when defusedxml is unavailable, log a one-time WARNING
    so ops knows the deploy is using the less-hardened parser. The
    runtime risk is small (we only consume Treasury's signed-TLS
    feed), but defense-in-depth.

    Treasury's SDN feed structure (simplified):

      <sdnList>
        <sdnEntry>
          <uid>12345</uid>
          <firstName>...</firstName>
          <lastName>LAZARUS GROUP</lastName>
          <idList>
            <id>
              <uid>67890</uid>
              <idType>Digital Currency Address - ETH</idType>
              <idNumber>0xabcdef...</idNumber>
            </id>
          </idList>
          <publishInformation>
            <Publish_Date>2022-04-14</Publish_Date>
          </publishInformation>
        </sdnEntry>
      </sdnList>

    XML namespacing varies; we use .iter() to find elements
    regardless of namespace prefix.
    """
    # RIGOR-2a: defusedxml-only — fail-closed at import time, so by
    # the time we reach here the parser is provably hardened against
    # billion-laughs / XXE / external-entity expansion attacks.
    root = ET.fromstring(xml_bytes)
    entries: list[OFACCryptoEntry] = []

    # Strip namespaces by replacing '{ns}tag' with 'tag'
    def _local_tag(elem: ET.Element) -> str:
        return elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag

    # Iterate sdnEntry nodes
    for sdn_entry in root.iter():
        if _local_tag(sdn_entry) != "sdnEntry":
            continue

        # Pull the SDN-level metadata
        sdn_uid = ""
        sdn_name_parts: list[str] = []
        publish_date = ""
        id_list_elem: ET.Element | None = None

        for child in sdn_entry:
            tag = _local_tag(child)
            if tag == "uid":
                sdn_uid = (child.text or "").strip()
            elif tag == "firstName":
                first = (child.text or "").strip()
                if first:
                    sdn_name_parts.append(first)
            elif tag == "lastName":
                last = (child.text or "").strip()
                if last:
                    sdn_name_parts.append(last)
            elif tag == "publishInformation":
                for pub_child in child:
                    if _local_tag(pub_child) == "Publish_Date":
                        publish_date = (pub_child.text or "").strip()
            elif tag == "idList":
                id_list_elem = child

        if id_list_elem is None:
            continue

        sdn_name = " ".join(sdn_name_parts).strip() or "(unnamed SDN)"

        # Walk the idList for Digital Currency Address entries
        for id_elem in id_list_elem:
            if _local_tag(id_elem) != "id":
                continue
            id_type = ""
            id_number = ""
            for id_child in id_elem:
                tag = _local_tag(id_child)
                if tag == "idType":
                    id_type = (id_child.text or "").strip()
                elif tag == "idNumber":
                    id_number = (id_child.text or "").strip()
            if not id_type.startswith("Digital Currency Address"):
                continue
            # Extract chain code from the id_type string
            # e.g., "Digital Currency Address - ETH" → "ETH"
            chain_code = ""
            if " - " in id_type:
                chain_code = id_type.rsplit(" - ", 1)[-1].strip().upper()
            internal_chain = _OFAC_CHAIN_MAP.get(chain_code, chain_code.lower())
            if not id_number:
                continue
            entries.append(OFACCryptoEntry(
                address=(
                    id_number.lower() if _is_evm_address(id_number)
                    else id_number
                ),
                chain=internal_chain,
                sdn_entry_name=sdn_name,
                sdn_entry_id=sdn_uid,
                listing_date=publish_date,
            ))

    return entries


def _is_evm_address(addr: str) -> bool:
    """Heuristic: is this an EVM-style 0x address?"""
    return addr.startswith("0x") and len(addr) == 42


def _write_csv_atomic(out_path: Path, entries: list[OFACCryptoEntry]) -> None:
    """Write the CSV via temp-file-rename to avoid leaving a half-
    written file if the process crashes mid-write."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix="ofac_sdn_",
        suffix=".csv.tmp",
        dir=str(out_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "address", "chain", "sdn_entry_name",
                "sdn_entry_id", "listing_date",
            ])
            for e in entries:
                writer.writerow([
                    e.address, e.chain, e.sdn_entry_name,
                    e.sdn_entry_id, e.listing_date,
                ])
        os.replace(tmp_name, out_path)
    except Exception:
        # Clean up the temp file on failure so we don't leak.
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


__all__ = (
    "OFACCryptoEntry",
    "SyncResult",
    "sync_ofac_sdn",
    "load_ofac_csv",
    "OFAC_SDN_XML_URL",
    "DEFAULT_OFAC_CSV_PATH",
)
