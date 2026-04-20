"""LabelStore: address → Label resolution.

Loads from two layers:
  1. Seed lists shipped in src/recupero/labels/seeds/*.json (curated, version-controlled)
  2. Local user-supplied lists in {data_dir}/labels/local_*.json (gitignored)

Seed-list and local entries are merged; local wins on conflicts (so investigators
can override our defaults without editing checked-in files).

The store is keyed by lowercase address for case-insensitive lookup but stores
addresses checksummed for output.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from eth_utils import to_checksum_address

from recupero.config import RecuperoConfig
from recupero.models import Address, Chain, Label, LabelCategory

log = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent / "seeds"


class LabelStore:
    def __init__(self) -> None:
        self._by_addr_lower: dict[str, Label] = {}

    @classmethod
    def load(cls, config: RecuperoConfig) -> "LabelStore":
        store = cls()

        # 1. Seed lists (shipped with the code)
        if SEEDS_DIR.exists():
            for path in sorted(SEEDS_DIR.glob("*.json")):
                store._load_file(path, source_prefix=f"local_seed:{path.name}")

        # 2. User-supplied overrides
        local_dir = Path(config.storage.data_dir) / "labels"
        if local_dir.exists():
            for path in sorted(local_dir.glob("local_*.json")):
                store._load_file(path, source_prefix=f"user:{path.name}")

        log.info("loaded %d labels", len(store._by_addr_lower))
        return store

    def lookup(self, address: Address, chain: Chain = Chain.ethereum) -> Label | None:
        # For Ethereum we normalize to checksum then lowercase for the key.
        # For non-EVM chains add normalization here.
        try:
            normalized = to_checksum_address(address) if chain == Chain.ethereum else address
        except (ValueError, TypeError):
            return None
        return self._by_addr_lower.get(normalized.lower())

    def add(self, label: Label) -> None:
        try:
            normalized = to_checksum_address(label.address)
        except (ValueError, TypeError):
            normalized = label.address
        # Replace address with checksum form in the stored label
        stored = label.model_copy(update={"address": normalized})
        self._by_addr_lower[normalized.lower()] = stored

    # ----- internals -----

    def _load_file(self, path: Path, source_prefix: str) -> None:
        try:
            with path.open() as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            log.error("invalid JSON in label file %s: %s", path, e)
            return

        if not isinstance(data, list):
            # Not all JSON files in seeds/ are label arrays. issuers.json (added
            # in v15) is an object with _meta + tokens. Skip silently — it's
            # consumed by recupero.freeze, not the label store.
            log.debug(
                "skipping non-array seed file %s (probably consumed by another module)",
                path,
            )
            return

        for entry in data:
            try:
                label = Label(
                    address=entry["address"],
                    name=entry["name"],
                    category=LabelCategory(entry.get("category", "unknown")),
                    exchange=entry.get("exchange"),
                    source=entry.get("source", source_prefix),
                    confidence=entry.get("confidence", "medium"),
                    notes=entry.get("notes"),
                    added_at=_parse_dt(entry.get("added_at")),
                )
            except (KeyError, ValueError) as e:
                log.warning("skipping malformed label in %s: %s", path, e)
                continue
            self.add(label)


def _parse_dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
