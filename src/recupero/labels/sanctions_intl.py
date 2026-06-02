"""Multi-regime international sanctions ingest (v0.35.6 — roadmap E5).

OFAC is only one sanctions authority. EU, UN, UK (HMT/OFSI), Israel (NBCTF),
Japan (MoF), France, and others now name crypto wallets too — and all three
incumbents (Chainalysis/TRM/Elliptic) screen against the full set. This module
ingests those regimes from **OpenSanctions** (free, no-login bulk data; the
``CryptoWallet`` schema), parallel to ``ofac_sync`` (which stays the authoritative
OFAC feed), so a wallet sanctioned by the EU/UK but not OFAC still flags.

Pipeline (operator-driven, like ofac-sync):
  1. Download the OpenSanctions crypto bulk file (FtM entities JSON / NDJSON or
     CSV) — free for non-commercial; a data licence is required for commercial
     use (a procurement decision, not a code one).
  2. ``recupero-ops import-sanctions --file <download>`` parses it →
     ``labels/seeds/sanctions_intl_live.csv``.
  3. ``risk_scoring.load_high_risk_db`` loads that CSV alongside the OFAC feed:
     each address becomes a severity-4 ``intl_sanctioned`` exposure (flagged +
     SANCTIONED-class verdict) — but NOT ``ofac_sanctioned``, so it does NOT
     mis-route an OFAC freeze letter; the regime (EU/UK/UN/…) is carried for
     glass-box provenance + correct legal routing.

Forensic posture: every entry carries its source regime + dataset (glass-box);
addresses are never fabricated — only real ``CryptoWallet.publicKey`` values that
carry the ``sanction`` topic are ingested. EVM addresses are lowercased; non-EVM
(BTC/Tron/Solana base58) are preserved verbatim.
"""

from __future__ import annotations

import contextlib
import csv
import json
import logging
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_INTL_SANCTIONS_CSV = (
    Path(__file__).parent / "seeds" / "sanctions_intl_live.csv"
)

# Map OpenSanctions/FtM CryptoWallet `currency` (or address shape) → our chain id.
_CURRENCY_CHAIN = {
    "eth": "ethereum", "ethereum": "ethereum", "weth": "ethereum",
    "usdt": "ethereum", "usdc": "ethereum", "dai": "ethereum",
    "btc": "bitcoin", "bitcoin": "bitcoin",
    "trx": "tron", "tron": "tron",
    "sol": "solana", "solana": "solana",
    "bnb": "bsc", "bsc": "bsc",
    "matic": "polygon", "pol": "polygon", "polygon": "polygon",
}

_CSV_COLUMNS = (
    "address", "chain", "entity_name", "regime", "source_dataset",
    "listing_date", "removed_at_utc",
)


@dataclass(frozen=True)
class IntlSanctionEntry:
    """One sanctioned crypto wallet from a non-OFAC (or multi-regime) authority."""
    address: str
    chain: str
    entity_name: str
    regime: str            # e.g. "gb_hmt_sanctions", "eu_fsf", "un_sc_sanctions"
    source_dataset: str    # the OpenSanctions dataset id(s) it came from
    listing_date: str = ""
    removed_at_utc: str = ""


def _is_evm_address(addr: str) -> bool:
    return (
        isinstance(addr, str)
        and addr.startswith("0x")
        and len(addr) == 42
        and all(c in "0123456789abcdefABCDEF" for c in addr[2:])
    )


def _first(value: Any) -> str:
    """FtM properties are lists; take the first scalar, else ''."""
    if isinstance(value, list):
        return str(value[0]).strip() if value else ""
    if value is None:
        return ""
    return str(value).strip()


def _chain_for(currency: str, address: str) -> str:
    cur = (currency or "").strip().lower()
    if cur in _CURRENCY_CHAIN:
        return _CURRENCY_CHAIN[cur]
    return "ethereum" if _is_evm_address(address) else "unknown"


def parse_opensanctions_crypto(
    records: Iterable[dict[str, Any]],
) -> list[IntlSanctionEntry]:
    """PURE: OpenSanctions FtM ``CryptoWallet`` entity dicts → sanction entries.

    A record is ingested only if it is a ``CryptoWallet`` carrying a wallet
    address (``properties.publicKey``) AND the ``sanction`` topic (we ingest
    sanctions, not the broader risk topics like ``crime``/``role.pep``). The
    regime is taken from ``properties.program`` else the entity's ``datasets``.
    Never fabricates — a record missing an address is skipped.
    """
    out: list[IntlSanctionEntry] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if (rec.get("schema") or "") != "CryptoWallet":
            continue
        props = rec.get("properties") or {}
        if not isinstance(props, dict):
            continue
        topics = props.get("topics") or []
        if isinstance(topics, str):
            topics = [topics]
        if "sanction" not in {str(t).strip().lower() for t in topics}:
            continue  # only true sanctions (not generic risk tags)
        addr = _first(props.get("publicKey"))
        if not addr:
            continue
        norm = addr.lower() if _is_evm_address(addr) else addr
        chain = _chain_for(_first(props.get("currency")), addr)
        datasets = rec.get("datasets") or []
        if isinstance(datasets, str):
            datasets = [datasets]
        regime = _first(props.get("program")) or (
            ", ".join(str(d) for d in datasets) if datasets else "opensanctions"
        )
        key = (norm, chain)
        if key in seen:
            continue
        seen.add(key)
        out.append(IntlSanctionEntry(
            address=norm,
            chain=chain,
            entity_name=(rec.get("caption") or _first(props.get("name"))
                         or "(sanctioned wallet)"),
            regime=regime,
            source_dataset=", ".join(str(d) for d in datasets) or "opensanctions",
            listing_date=_first(props.get("createdAt")),
        ))
    return out


def _iter_records(path: Path) -> Iterable[dict[str, Any]]:
    """Read FtM entities from a .json array OR .ndjson/.jsonl (one per line)."""
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        yield from (r for r in data if isinstance(r, dict))
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            yield rec


def write_intl_sanctions_csv(path: Path, entries: list[IntlSanctionEntry]) -> None:
    """Atomic write (temp + rename) — same discipline as ofac_sync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".csv.tmp")
    os.close(fd)  # close the mkstemp handle (Windows lock) before reopening
    try:
        with Path(tmp).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(_CSV_COLUMNS))
            w.writeheader()
            for e in entries:
                w.writerow({
                    "address": e.address, "chain": e.chain,
                    "entity_name": e.entity_name, "regime": e.regime,
                    "source_dataset": e.source_dataset,
                    "listing_date": e.listing_date,
                    "removed_at_utc": e.removed_at_utc,
                })
        Path(tmp).replace(path)
    finally:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()


def load_intl_sanctions_csv(
    csv_path: Path | None = None,
) -> list[IntlSanctionEntry]:
    """Load the imported multi-regime sanctions CSV. ``[]`` if absent."""
    path = csv_path or DEFAULT_INTL_SANCTIONS_CSV
    if not path.exists():
        return []
    try:
        out: list[IntlSanctionEntry] = []
        with path.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                addr = (row.get("address") or "").strip()
                if not addr:
                    continue
                out.append(IntlSanctionEntry(
                    address=addr.lower() if _is_evm_address(addr) else addr,
                    chain=(row.get("chain") or "ethereum").lower(),
                    entity_name=row.get("entity_name", ""),
                    regime=row.get("regime", ""),
                    source_dataset=row.get("source_dataset", ""),
                    listing_date=row.get("listing_date", ""),
                    removed_at_utc=(row.get("removed_at_utc") or "").strip(),
                ))
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("intl sanctions csv load failed: %s", exc)
        return []


def import_opensanctions_file(
    in_path: Path, out_path: Path | None = None,
) -> int:
    """Parse an OpenSanctions crypto bulk file → write the intl-sanctions CSV.
    Returns the number of entries written."""
    out = out_path or DEFAULT_INTL_SANCTIONS_CSV
    entries = parse_opensanctions_crypto(_iter_records(in_path))
    write_intl_sanctions_csv(out, entries)
    log.info("imported %d intl-sanctioned wallets → %s", len(entries), out)
    return len(entries)


__all__ = (
    "IntlSanctionEntry",
    "parse_opensanctions_crypto",
    "load_intl_sanctions_csv",
    "write_intl_sanctions_csv",
    "import_opensanctions_file",
    "DEFAULT_INTL_SANCTIONS_CSV",
)
