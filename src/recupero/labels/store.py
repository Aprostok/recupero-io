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

    def lookup(
        self,
        address: Address,
        chain: Chain = Chain.ethereum,
        *,
        point_in_time: datetime | None = None,
    ) -> Label | None:
        """Resolve ``address`` to a Label, optionally as of ``point_in_time``.

        v0.31.2 (Gap #5 — point-in-time labels): if ``point_in_time`` is
        ``None`` (default) the lookup uses current-state semantics — a
        label is considered active forever from its ``added_at`` — which
        is the behavior every caller relied on before this version.

        When ``point_in_time`` is given the store filters labels so only
        those active at that timestamp are returned:
          * ``added_at  >  point_in_time`` → label didn't exist yet
          * ``valid_from > point_in_time`` (when set) → not yet active
          * ``valid_until < point_in_time`` (when set) → already expired

        Returns ``None`` if no active label is found.
        """
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
        label = self._by_addr_lower.get(_label_key(normalized))
        if label is None:
            return None

        if point_in_time is None:
            # Default: current-state semantics, every existing caller
            # gets the same behavior they had before v0.31.2.
            return label

        # Point-in-time filtering. Compare via _coerce_aware_utc so a
        # naive `point_in_time` doesn't crash against the timezone-aware
        # added_at / valid_from / valid_until on the stored Label.
        pit = _coerce_aware_utc(point_in_time)
        added_at = _coerce_aware_utc(label.added_at)
        if added_at is not None and pit is not None and added_at > pit:
            # The label didn't exist yet at point_in_time.
            return None
        if label.valid_from is not None:
            vf = _coerce_aware_utc(label.valid_from)
            if vf is not None and pit is not None and vf > pit:
                # Not yet active at point_in_time.
                return None
        if label.valid_until is not None:
            vu = _coerce_aware_utc(label.valid_until)
            if vu is not None and pit is not None and vu < pit:
                # Already expired at point_in_time.
                return None
        return label

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
            # v0.31.4: structured section-divider rows like
            # ``{"_section": "Hop Protocol"}`` are intentional
            # documentation aids inside bridges.json. They carry no
            # address (and no name); silently skip rather than logging
            # a "malformed" warning that floods every load.
            if "address" not in entry and "_section" in entry:
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
                    # v0.31.2 (Gap #5): optional validity window. Pass
                    # through only when the entry actually has the
                    # field; absent fields stay None and preserve the
                    # legacy "labeled forever after added_at" semantics.
                    valid_from=_parse_dt_optional(entry.get("valid_from")),
                    valid_until=_parse_dt_optional(entry.get("valid_until")),
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


def _parse_dt_optional(s: str | None) -> datetime | None:
    """Parse an optional ISO-8601 string. Unlike _parse_dt, returns None
    when the field is missing rather than defaulting to now() — for
    valid_from / valid_until, "not specified" must mean "no constraint"
    not "constraint = now"."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        # Bad ISO string in the optional window → treat as absent
        # rather than crashing the whole load. Already-failing labels
        # get logged + skipped at the outer try/except in _load_file.
        return None


def _coerce_aware_utc(dt: datetime | None) -> datetime | None:
    """Promote a naive datetime to UTC-aware. Aware values pass through.

    Without this, comparing a naive `point_in_time` (common in tests
    and ad-hoc CLI use) to the timezone-aware datetimes stored on
    Label would raise ``TypeError: can't compare offset-naive and
    offset-aware datetimes`` and crash the lookup. Coercion to UTC
    matches the rest of the codebase's "datetimes are always UTC"
    invariant from models.py.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.4 (Gap 1a — point-in-time graceful degradation)
# ─────────────────────────────────────────────────────────────────────────────


def lookup_pit_safe(
    label_store: object,
    address: str,
    chain: object = None,
    *,
    point_in_time: object = None,
) -> object | None:
    """Best-effort point-in-time lookup against any label-store-shape.

    Production callers should USE THIS instead of calling
    ``label_store.lookup(...)`` directly. It honors point-in-time
    on the canonical LabelStore (which supports the kwarg) and
    degrades cleanly to current-state on any label-store
    implementation that doesn't (test fakes, minimal stubs, etc.).

    Fallback chain:
      1. ``lookup(addr, chain=chain, point_in_time=pit)`` — full
         signature.
      2. On TypeError → ``lookup(addr, chain=chain)`` — drop PIT.
      3. On further TypeError → ``lookup(addr)`` — minimal shape.

    Any non-TypeError exception inside the lookup returns ``None``;
    label resolution must NEVER fail the trace.
    """
    if label_store is None or not address:
        return None
    try:
        if chain is None:
            return label_store.lookup(address, point_in_time=point_in_time)  # type: ignore[attr-defined]
        return label_store.lookup(  # type: ignore[attr-defined]
            address, chain=chain, point_in_time=point_in_time,
        )
    except TypeError:
        pass
    except Exception:  # noqa: BLE001
        return None
    try:
        if chain is None:
            return label_store.lookup(address)  # type: ignore[attr-defined]
        return label_store.lookup(address, chain=chain)  # type: ignore[attr-defined]
    except TypeError:
        pass
    except Exception:  # noqa: BLE001
        return None
    try:
        return label_store.lookup(address)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None
