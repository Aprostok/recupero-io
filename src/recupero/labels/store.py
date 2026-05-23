"""LabelStore: address → Label resolution.

Loads from two layers:
  1. Seed lists shipped in src/recupero/labels/seeds/*.json (curated, version-controlled)
  2. Local user-supplied lists in {data_dir}/labels/local_*.json (gitignored)

Seed-list and local entries are merged; local wins on conflicts (so investigators
can override our defaults without editing checked-in files).

The store is keyed by a CHAIN-AWARE normalization:
  * EVM hex addresses (0x... 42 chars) → lowercased (hex is case-insensitive)
  * Everything else (Solana/Tron/Bitcoin base58, base58check) → case-preserved

v0.16.6 and earlier lowercased ALL addresses, mangling base58 keys. A mixed-
case Solana mint pasted into a user-supplied label file would never match the
canonical-case form returned by Helius during a live trace, so counterparty
labels silently went missing on non-EVM cases. Surfaced in the round-9 audit.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from eth_utils import to_checksum_address

from recupero.config import RecuperoConfig
from recupero.models import Address, Chain, Label, LabelCategory

log = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent / "seeds"


def _label_key(address: str) -> str:
    """Compute the dict key used to store/look up a label.

    v0.17.9: delegates to recupero._common.canonical_address_key —
    single source of truth for EVM-lower / base58-preserve heuristic
    across risk_scoring, correlation, indirect_exposure, clustering,
    drainer_detection, perpetrator_trace, cross_chain, and the
    label store.

    EVM hex addresses (0x... 42 chars) are case-insensitive: lowercased so
    "0xABCD..." and "0xabcd..." match. Base58 (Solana / Tron T-prefix /
    Bitcoin) and any other non-EVM form is case-SENSITIVE on-chain — keys
    must preserve case verbatim.
    """
    from recupero._common import canonical_address_key
    return canonical_address_key(address)


class LabelStore:
    def __init__(self) -> None:
        # Internal attr name preserved for back-compat with any test/tooling
        # that introspected the store; semantics are now chain-aware (see
        # _label_key) rather than always-lowercased.
        self._by_addr_lower: dict[str, Label] = {}

    @classmethod
    def load(cls, config: RecuperoConfig) -> LabelStore:
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
        # For EVM chains, checksum-normalize first so a mixed-case input
        # matches a stored checksum form. For non-EVM, pass through (base58
        # case must be preserved exactly).
        if chain in (Chain.ethereum, Chain.arbitrum, Chain.bsc, Chain.base, Chain.polygon):
            try:
                normalized = to_checksum_address(address)
            except (ValueError, TypeError):
                return None
        else:
            normalized = address
        return self._by_addr_lower.get(_label_key(normalized))

    def add(self, label: Label) -> None:
        # Try checksum (EVM); if that fails it's a non-EVM address and we
        # keep the verbatim string. The stored Label always reflects the
        # canonical-case form for output.
        try:
            normalized = to_checksum_address(label.address)
        except (ValueError, TypeError):
            normalized = label.address
        stored = label.model_copy(update={"address": normalized})
        self._by_addr_lower[_label_key(normalized)] = stored

    # ----- internals -----

    def _load_file(self, path: Path, source_prefix: str) -> None:
        try:
            with path.open(encoding="utf-8") as f:
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
            # RIGOR-Jacob W: a corrupted or operator-mistyped labels.json
            # may contain non-dict entries (lists, strings, numbers,
            # nulls). Constructing a Label from those raises TypeError
            # on subscription, which used to abort the entire load and
            # break startup. Guard the shape and broaden the except so
            # bad entries are logged + skipped, not fatal.
            if not isinstance(entry, dict):
                log.warning(
                    "skipping non-dict label entry in %s: %r", path, entry,
                )
                continue
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
            except (KeyError, ValueError, TypeError, AttributeError) as e:
                log.warning("skipping malformed label in %s: %s", path, e)
                continue
            try:
                self.add(label)
            except (ValueError, TypeError, AttributeError) as e:
                log.warning(
                    "skipping label that failed to add in %s: %s", path, e,
                )
                continue


def _parse_dt(s: str | None) -> datetime:
    if not s:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)
