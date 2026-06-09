"""MEV / sandwich-attack obfuscation DETECTION (v0.31.0, Gap #9).

Detection-only forensic flag. Honest "trace continuity broken here,
investigator follow-up needed" instead of silently following a
misleading on-chain trail. Design + heuristics + builder-verification:
docs/V031_MEV_DETECTION.md. Pure trace post-processor; no new RPC.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

# v0.39 (activation sweep): the builder-direct branch now reads the CANONICAL
# ~14-entry registry in trace.mev_builders (Flashbots x2 / beaverbuild / Titan /
# rsync / Builder0x69 / bloXroute x3 / eth-builder / payload.de / Manifold /
# penguinbuild / Lightspeedbuilder) instead of the prior local 4-entry list.
# The old four were a strict subset, so no coverage is lost — Reactor-parity
# builder recognition means bundle-shaped txs from the other ten are flagged as
# builder-direct (trace-continuity break) instead of mislabeled as regular flow.
from recupero.trace.mev_builders import KNOWN_MEV_BUILDERS as _MEV_BUILDERS

if TYPE_CHECKING:
    from recupero.models import Case

log = logging.getLogger(__name__)

# 1 gwei. Real bundle txs are exactly 0 wei; the buffer absorbs L1
# system-tx edge cases.
_BUNDLE_GAS_PRICE_MAX_WEI = 1_000_000_000

# Render threshold (per spec): brief panels show signals ≥ 0.5.
BRIEF_RENDER_CONFIDENCE_FLOOR = 0.5


@dataclass(frozen=True)
class MEVSignal:
    """One MEV-obfuscation signal on a specific tx-hop.

    signal_type: 'flashbots_bundle' | 'sandwich' | 'jit_lp' | 'mev_source'.
    """
    tx_hash: str
    signal_type: str
    confidence: float
    forensic_note: str
    address: str | None = None
    builder_name: str | None = None


def _canon(addr: str | None) -> str:
    """Lowercase + strip for EVM set comparison."""
    return addr.strip().lower() if isinstance(addr, str) else ""


def _safe_int(val: Any) -> int | None:
    """Coerce to int when finite; NaN/Inf/bool/None/garbage → None."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        if val != val or val in (float("inf"), float("-inf")):
            return None
    elif isinstance(val, Decimal):
        try:
            if not val.is_finite():
                return None
        except (AttributeError, TypeError):
            return None
    else:
        return None
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return None


def _group_by_block(transfers: list[Any]) -> dict[int, list[Any]]:
    """Group transfers by block_number (skipping non-int), sorted by
    log_index within each group."""
    by_block: dict[int, list[Any]] = defaultdict(list)
    for t in transfers:
        bn = getattr(t, "block_number", None)
        if isinstance(bn, int):
            by_block[bn].append(t)
    for bn in by_block:
        try:
            by_block[bn].sort(key=lambda x: (getattr(x, "log_index", 0) or 0))
        except TypeError:
            pass
    return by_block


def _detect_flashbots_bundle(
    transfers: list[Any],
    tx_metadata: dict[str, dict[str, Any]] | None,
) -> list[MEVSignal]:
    """Bundle-shape: gas_price ≤ 1 gwei OR tx_metadata.builder ∈ known."""
    out: list[MEVSignal] = []
    seen: set[str] = set()
    meta = tx_metadata if isinstance(tx_metadata, dict) else {}

    for t in transfers:
        tx = getattr(t, "tx_hash", None)
        if not isinstance(tx, str) or tx in seen:
            continue
        seen.add(tx)
        row = meta.get(tx)
        if not isinstance(row, dict):
            continue
        builder = row.get("builder")
        # Builder-direct: stronger signal.
        if isinstance(builder, str) and _canon(builder) in _MEV_BUILDERS:
            name = _MEV_BUILDERS[_canon(builder)]
            note = (
                f"Tx built by known MEV builder ({name}). Bundle-shape "
                "transaction; trace continuity through the builder wallet "
                "is not interpretable on-chain — manual investigator "
                "follow-up needed."
            )
            out.append(MEVSignal(tx, "flashbots_bundle", 0.8, note, builder_name=name))
            continue
        # Gas-price-zero: weaker (L1 system txs also qualify).
        gas_price = _safe_int(row.get("gas_price"))
        if gas_price is not None and gas_price <= _BUNDLE_GAS_PRICE_MAX_WEI:
            note = (
                f"Tx gas_price = {gas_price} wei (≤ 1 gwei). Characteristic "
                "of MEV bundle txs paid via coinbase.transfer() to the "
                "validator rather than gas fees. Investigator follow-up "
                "recommended."
            )
            out.append(MEVSignal(tx, "flashbots_bundle", 0.7, note))
    return out


def _detect_sandwich(transfers: list[Any], seed: str) -> list[MEVSignal]:
    """Three-tx sandwich: outer pair share from_address, middle is seed."""
    out: list[MEVSignal] = []
    seed_c = _canon(seed)
    if not seed_c:
        return out
    for bn, txs in _group_by_block(transfers).items():
        if len(txs) < 3:
            continue
        for i in range(len(txs) - 2):
            a, b, c = txs[i], txs[i + 1], txs[i + 2]
            a_from = _canon(getattr(a, "from_address", ""))
            if not a_from or a_from != _canon(getattr(c, "from_address", "")):
                continue
            if _canon(getattr(b, "from_address", "")) != seed_c:
                continue
            note = (
                f"Sandwich pattern in block {bn}: outer txs from "
                f"{a_from[:10]}… flank victim's swap at log_index "
                f"{getattr(b, 'log_index', '?')}. Funds at the victim's "
                "swap output reflect MEV extraction; investigator follow-up "
                "needed to attribute the searcher wallet."
            )
            out.append(MEVSignal(
                getattr(b, "tx_hash", ""), "sandwich", 0.85, note,
                address=a_from,
            ))
    return out


def _detect_jit_lp(transfers: list[Any], seed: str) -> list[MEVSignal]:
    """JIT-LP shape: outer pair targets same counterparty from DIFFERENT
    addresses (distinguishes from sandwich). Sub-threshold (0.4) —
    structural only until LP-event ingestion ships."""
    out: list[MEVSignal] = []
    seed_c = _canon(seed)
    if not seed_c:
        return out
    for bn, txs in _group_by_block(transfers).items():
        if len(txs) < 3:
            continue
        for i in range(len(txs) - 2):
            a, b, c = txs[i], txs[i + 1], txs[i + 2]
            if _canon(getattr(b, "from_address", "")) != seed_c:
                continue
            a_to = _canon(getattr(a, "to_address", ""))
            c_to = _canon(getattr(c, "to_address", ""))
            if not a_to or a_to != c_to:
                continue
            if _canon(getattr(a, "from_address", "")) == _canon(getattr(c, "from_address", "")):
                continue  # sandwich shape, not JIT
            note = (
                f"Possible JIT-liquidity shape in block {bn}: two distinct "
                f"addresses interact with pool {a_to[:10]}… on either side "
                "of the victim's swap. Low-confidence structural signal — "
                "confirm by inspecting LP-add / LP-remove events at the pool."
            )
            out.append(MEVSignal(
                getattr(b, "tx_hash", ""), "jit_lp", 0.4, note, address=a_to,
            ))
    return out


def _detect_mev_source(transfers: list[Any], seed: str) -> list[MEVSignal]:
    """Seed received funds directly from a known MEV-builder address."""
    out: list[MEVSignal] = []
    seed_c = _canon(seed)
    if not seed_c:
        return out
    for t in transfers:
        if _canon(getattr(t, "to_address", "")) != seed_c:
            continue
        from_c = _canon(getattr(t, "from_address", ""))
        if from_c not in _MEV_BUILDERS:
            continue
        name = _MEV_BUILDERS[from_c]
        note = (
            f"Seed wallet received funds directly from {name} ({from_c}). "
            "MEV-source funds — perpetrator's wallet was funded by a "
            "builder's MEV-profit distribution. Off-chain attribution "
            "required to identify the original searcher."
        )
        out.append(MEVSignal(
            getattr(t, "tx_hash", ""), "mev_source", 0.9, note,
            address=from_c, builder_name=name,
        ))
    return out


def detect_mev_signals(
    case: Case,
    *,
    tx_metadata: dict[str, dict[str, Any]] | None = None,
) -> list[MEVSignal]:
    """Run all heuristics; dedupe (tx_hash, signal_type) keeping highest
    confidence. Defensive: None case / empty transfers / NaN/Inf → []."""
    if case is None:
        return []
    transfers = getattr(case, "transfers", None) or []
    seed = getattr(case, "seed_address", "") or ""

    signals: list[MEVSignal] = []
    try:
        signals.extend(_detect_flashbots_bundle(transfers, tx_metadata))
        signals.extend(_detect_sandwich(transfers, seed))
        signals.extend(_detect_jit_lp(transfers, seed))
        signals.extend(_detect_mev_source(transfers, seed))
    except Exception as exc:  # noqa: BLE001 — defensive
        log.warning("mev_detection: heuristic pass failed: %s", exc)
        return []

    best: dict[tuple[str, str], MEVSignal] = {}
    for s in signals:
        key = (s.tx_hash, s.signal_type)
        if key not in best or s.confidence > best[key].confidence:
            best[key] = s
    return sorted(
        best.values(),
        key=lambda s: (-s.confidence, s.signal_type, s.tx_hash),
    )


def mev_signals_to_brief_section(
    signals: list[MEVSignal],
    *,
    confidence_floor: float = BRIEF_RENDER_CONFIDENCE_FLOOR,
) -> dict[str, Any]:
    """Serialize for the brief's MEV_SIGNALS section. Renders only
    signals ≥ confidence_floor; sub-threshold count rolls into
    ``suppressed_low_confidence_count`` for transparency."""
    rendered = [s for s in signals if s.confidence >= confidence_floor]
    suppressed = [s for s in signals if s.confidence < confidence_floor]
    return {
        "detected": bool(rendered),
        "signal_count": len(rendered),
        "suppressed_low_confidence_count": len(suppressed),
        "signals": [
            {
                "tx_hash": s.tx_hash,
                "signal_type": s.signal_type,
                "confidence": round(s.confidence, 3),
                "forensic_note": s.forensic_note,
                "address": s.address,
                "builder_name": s.builder_name,
            }
            for s in rendered
        ],
    }


__all__ = (
    "MEVSignal",
    "detect_mev_signals",
    "mev_signals_to_brief_section",
    "BRIEF_RENDER_CONFIDENCE_FLOOR",
)
