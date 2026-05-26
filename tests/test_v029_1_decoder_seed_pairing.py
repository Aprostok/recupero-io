"""v0.29.1 Recommendation #3 (HIGH) — decoder ↔ seed pairing audit.

The v0.29 diagnostic flagged that the decoder layer
(``src/recupero/trace/bridge_calldata.py``) and the seed layer
(``src/recupero/labels/seeds/bridges.json``) can drift out of sync:

  * If a protocol has seed entries but no decoder, the trace
    surfaces a bridge handoff with no extracted destination —
    forensically inert (operator must follow up via the external
    explorer manually).

  * If a protocol has a decoder but no seed entries, the decoder
    never runs because ``identify_cross_chain_handoffs`` matches
    on the seed-supplied label first.

Pre-v0.29.1 these were conceptually paired but mechanically
independent — no test enforced the contract. This file ships the
test.

Two invariants are pinned:

  1. Every decoder-recognized protocol (Wormhole / Across / Stargate
     / DeBridge / 1inch) has at least one seed entry whose ``name``
     matches the protocol.

  2. Every decoder, called with a canonical fixture payload + the
     protocol name, returns a non-None ``BridgeDecodeResult`` —
     i.e. the decoder is wired up and at least reaches the
     method-id-recognition step. This catches the "decoder file
     accidentally deleted" / "method-id table emptied" regression.

The 'high'-confidence assertion is reserved for tests in
``test_bridge_calldata.py`` that ship hand-crafted canonical
payloads for the bridges we fully decode (Wormhole / Across /
Stargate). For DeBridge + 1inch the conservative-stub decoders
return ``confidence='low'`` by design (no destination extraction
yet) — those still satisfy the "decoder reached + recognized
method" invariant we want here.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from recupero.trace.bridge_calldata import decode_bridge_calldata

_SEEDS_DIR = (
    Path(__file__).parent.parent
    / "src" / "recupero" / "labels" / "seeds"
)
_BRIDGES_PATH = _SEEDS_DIR / "bridges.json"
_DEFI_PATH = _SEEDS_DIR / "defi_protocols.json"


def _load_entries() -> list[dict]:
    data = json.loads(_BRIDGES_PATH.read_text(encoding="utf-8"))
    return [e for e in data if isinstance(e, dict) and "address" in e]


def _load_defi_entries() -> list[dict]:
    """Some decoder-recognized protocols (notably 1inch) deliberately
    live in defi_protocols.json rather than bridges.json — they are
    DEX aggregators, not bridges. The decoder is still reachable via
    operator-curated label override (see v0.28.0 architecture)."""
    data = json.loads(_DEFI_PATH.read_text(encoding="utf-8"))
    return [e for e in data if isinstance(e, dict) and "address" in e]


# ──────────────────────────────────────────────────────────────────────
# Decoder ↔ protocol catalogue — bridge_calldata.py protocols and the
# canonical method-id calldata we expect to recognize. Each row:
#   (display_name, name_regex_in_seed, calldata_with_known_method_id,
#    expected_confidence_at_least)
#
# The calldata payloads are minimum-length right-padded blobs that
# carry a recognized method ID for that protocol. We do NOT assert
# correctness of the decoded destination here — that's covered by
# ``test_bridge_calldata.py`` with hand-crafted ABI-correct blobs.
# We only assert: "the decoder dispatched, recognized the method
# ID, and returned a result rather than crashing or returning None".
# ──────────────────────────────────────────────────────────────────────


# Helper: build a calldata blob with a known method-id followed by
# enough zero-padded args that the decoder doesn't bail on "too
# short". Each protocol's decoder has a min-length check (Wormhole
# needs 192 bytes of args; Across-depositV3 needs 224; Stargate
# needs 32; DeBridge/1inch no min beyond the 4-byte method).
def _padded(method_id_hex: str, n_arg_bytes: int) -> str:
    return "0x" + method_id_hex + ("00" * n_arg_bytes)


# Wormhole: transferTokens 0x0f5287b0; needs ≥192 arg bytes
_WORMHOLE_PAYLOAD = _padded("0f5287b0", 224)
# Across: depositV3 0x7b939232; needs ≥224 arg bytes
_ACROSS_PAYLOAD = _padded("7b939232", 256)
# Stargate: swap 0x9fbf10fc; needs ≥32 arg bytes
_STARGATE_PAYLOAD = _padded("9fbf10fc", 64)
# DeBridge: createOrder 0xfaee513f; no min
_DEBRIDGE_PAYLOAD = _padded("faee513f", 32)
# 1inch: swap 0x12aa3caf; no min
_1INCH_PAYLOAD = _padded("12aa3caf", 32)


DECODER_PROTOCOLS: list[tuple[str, re.Pattern[str], str]] = [
    ("Wormhole", re.compile(r"\bwormhole\b", re.I), _WORMHOLE_PAYLOAD),
    ("Across", re.compile(r"\bacross\b", re.I), _ACROSS_PAYLOAD),
    ("Stargate", re.compile(r"\bstargate\b", re.I), _STARGATE_PAYLOAD),
    ("DeBridge", re.compile(r"\bdebridge\b", re.I), _DEBRIDGE_PAYLOAD),
    ("1inch", re.compile(r"\b1inch\b", re.I), _1INCH_PAYLOAD),
]


@pytest.mark.parametrize(
    "protocol,name_pattern,canonical_payload",
    DECODER_PROTOCOLS,
    ids=[p for p, _, _ in DECODER_PROTOCOLS],
)
def test_decoder_protocol_has_seed_entry(
    protocol: str,
    name_pattern: re.Pattern[str],
    canonical_payload: str,
) -> None:
    """Each protocol the decoder claims to recognize must have ≥1
    seed entry SOMEWHERE in the labels DB — bridges.json for the
    bridge-classified protocols, defi_protocols.json for the
    aggregators (1inch). Catches the "decoder added but seed
    forgotten" drift — the BFS only reaches a decoder via a
    seed-label hit, so a decoder with zero seed entries anywhere
    is dead code.
    """
    bridge_matches = [
        e for e in _load_entries()
        if name_pattern.search(str(e.get("name", "")))
    ]
    defi_matches = [
        e for e in _load_defi_entries()
        if name_pattern.search(str(e.get("name", "")))
    ]
    assert bridge_matches or defi_matches, (
        f"DECODER-SEED DRIFT: bridge_calldata.py recognizes {protocol!r} "
        f"but neither bridges.json nor defi_protocols.json has any entries "
        f"matching the protocol name. Either add a seed entry (with "
        f"externally verified address) or delete the decoder's method-ID "
        f"table (and remove from this test). v0.29.1 Recommendation #3 "
        f"contract."
    )


@pytest.mark.parametrize(
    "protocol,name_pattern,canonical_payload",
    DECODER_PROTOCOLS,
    ids=[p for p, _, _ in DECODER_PROTOCOLS],
)
def test_decoder_recognizes_canonical_method_id(
    protocol: str,
    name_pattern: re.Pattern[str],
    canonical_payload: str,
) -> None:
    """For every decoder protocol, calling ``decode_bridge_calldata``
    with that protocol's canonical method-id calldata must return a
    non-None BridgeDecodeResult. The reverse direction of the
    pairing invariant: a seed entry whose decoder was silently
    deleted would fail here."""
    result = decode_bridge_calldata(
        bridge_protocol=protocol,
        input_data=canonical_payload,
    )
    assert result is not None, (
        f"DECODER-METHOD-ID DRIFT: bridge_calldata.py was called with "
        f"protocol={protocol!r} and a payload carrying a known method "
        f"ID, but the decoder returned None — likely the method-ID "
        f"table for {protocol!r} was emptied. v0.29.1 Recommendation "
        f"#3 contract."
    )
    # The bridge_method field carries the resolved method name —
    # also pin that it's non-empty.
    assert result.bridge_method, (
        f"{protocol!r} decoder returned a result but bridge_method "
        f"was empty. Either the method-id table was corrupted or "
        f"the decoder is returning a malformed result."
    )


def test_decoder_returns_none_for_unrecognized_protocol_string() -> None:
    """Negative sanity check — the decoder dispatches by protocol
    name. A protocol we haven't shipped a decoder for must return
    None (graceful degradation; the trace falls back to the
    candidates list). Confirms the dispatch logic isn't accepting
    arbitrary protocols and accidentally claiming decode success."""
    out = decode_bridge_calldata(
        bridge_protocol="SomeMadeUpProtocolNotInTheDispatchTable",
        input_data=_STARGATE_PAYLOAD,
    )
    assert out is None
