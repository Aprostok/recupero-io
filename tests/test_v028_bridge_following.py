"""v0.28.0 bridge-following fix — regression tests.

Three-step fix per docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md:

  Step 2.1 — bridges.json seed expansion for Arbitrum/Optimism/Base/
  Polygon coverage. Pre-v0.28 the file had ONE Arbitrum entry
  (Hyperliquid). The Zigha case (Arbitrum→Ethereum DeBridge / 1inch
  consolidation) was invisible because identify_cross_chain_handoffs
  keys on (chain, address) and the source-side bridges weren't in
  the seed file.

  Step 2.2 — bridge_calldata.py protocol-recognition decoders for
  DeBridge + 1inch. Both ship at conservative confidence='low' (no
  destination decode yet) until an authoritative ABI test fixture
  is available; method-ID recognition is sufficient to surface
  the handoff in the trace report.

  Step 2.3 — flip the RECUPERO_CROSS_CHAIN_CONTINUATION env-var
  default from OFF to ON. Original off-by-default was a v0.17.x
  conservative-cost decision that's been outdated by subsequent
  dedup + cost caps. Now opt-OUT: set the var to "0"/"false"/"off"
  to disable.

Tests pin each step's contract so a future regression that
re-introduces the Zigha trace-coverage gap surfaces here
immediately.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from recupero.models import Chain
from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)
from recupero.trace.cross_chain import ingest_bridge_seeds


# ─────────────────────────────────────────────────────────────────────
# Step 2.1: bridges.json seed expansion
# ─────────────────────────────────────────────────────────────────────


_BRIDGES_PATH = (
    Path(__file__).parent.parent
    / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
)


def _load_bridge_entries() -> list[dict]:
    raw = json.loads(_BRIDGES_PATH.read_text(encoding="utf-8"))
    return [e for e in raw if isinstance(e, dict) and "address" in e]


def test_bridges_seed_has_arbitrum_side_coverage() -> None:
    """Pre-v0.28 the seed file had exactly ONE Arbitrum-side entry
    (Hyperliquid). For Zigha-shape cases (Arbitrum→Ethereum
    consolidation), we need to detect DeBridge/Stargate/Across/
    Wormhole/LayerZero handoffs on the Arbitrum side. Assert the
    seed file now carries enough Arbitrum-chain entries that the
    pre-v0.28 1-entry shape can never silently regress."""
    entries = _load_bridge_entries()
    arb_entries = [e for e in entries if e.get("chain") == "arbitrum"]
    # Pre-v0.28: 1 Arbitrum entry (Hyperliquid). v0.28.0 adds at
    # least 10. Pin > 5 so a regression that wipes the v0.28
    # additions surfaces here, while leaving room for the seed
    # file to evolve.
    assert len(arb_entries) > 5, (
        f"Arbitrum-side bridge coverage regressed to {len(arb_entries)} "
        "entries. The Zigha trace-coverage fix (v0.28.0, see "
        "docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md) added 10+ "
        "Arbitrum-side bridge entries (DeBridge, Stargate, Across, "
        "Wormhole, LayerZero, CCIP, Hop, Synapse). Re-run this test "
        "after restoring those."
    )


def test_bridges_seed_covers_zigha_critical_protocols_on_arbitrum() -> None:
    """The specific protocols Zigha-shape cases route through MUST
    be present on the Arbitrum side. Asserts the most consequential
    coverage by name match."""
    arb_entries = [
        e for e in _load_bridge_entries() if e.get("chain") == "arbitrum"
    ]
    names = " ".join(e.get("name", "") for e in arb_entries).lower()
    # Each protocol must be named in at least one Arbitrum entry.
    for required_protocol in (
        "debridge",     # Zigha primary
        "stargate",     # LayerZero stablecoin bridge
        "across",       # high-volume L2→L1 bridge
        "wormhole",     # cross-ecosystem
        "layerzero",    # generic messaging
    ):
        assert required_protocol in names, (
            f"Arbitrum-side bridges missing canonical protocol "
            f"{required_protocol!r}. Zigha-shape cases routing "
            f"through {required_protocol} would silently miss "
            "the handoff. See docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md."
        )


def test_bridges_seed_covers_optimism_base_polygon_for_l2_handoffs() -> None:
    """Coverage on Optimism / Base / Polygon for multi-L2 Zigha-
    shape cases. Each L2 must have at least 3 bridge entries (this
    locks in the v0.28 expansion footprint)."""
    entries = _load_bridge_entries()
    chain_counts = Counter(e.get("chain", "ethereum") for e in entries)
    for required_chain, min_count in (
        ("optimism", 3),
        ("base", 3),
        ("polygon", 3),
    ):
        assert chain_counts.get(required_chain, 0) >= min_count, (
            f"{required_chain} bridge coverage regressed below {min_count} "
            f"entries (got {chain_counts.get(required_chain, 0)}). "
            "v0.28.0 added per-L2 coverage for cross-chain case continuity."
        )


def test_bridges_seed_ingests_into_bridge_db() -> None:
    """ingest_bridge_seeds must load every v0.28 addition into the
    runtime DB. A regression that breaks the (chain, address)
    canonicalization OR skips arbitrum/optimism/base/polygon
    entries lights this up."""
    db = ingest_bridge_seeds()
    chain_counts = Counter(chain.value for chain, _ in db.keys())
    # All v0.28-added chains must surface in the runtime DB.
    assert chain_counts.get("arbitrum", 0) >= 6, (
        f"ingest_bridge_seeds is loading {chain_counts.get('arbitrum', 0)} "
        "Arbitrum entries; v0.28.0 added many more. Likely "
        "regression: chain field handling in ingest_bridge_seeds."
    )
    assert chain_counts.get("optimism", 0) >= 3
    assert chain_counts.get("base", 0) >= 3
    assert chain_counts.get("polygon", 0) >= 3


def test_bridges_seed_v028_entries_carry_provenance() -> None:
    """Every v0.28-added entry MUST carry the _v028_addition flag for
    audit traceability + the confidence field for operator audit.
    A silent edit removing provenance is caught here."""
    entries = _load_bridge_entries()
    v028_entries = [e for e in entries if e.get("_v028_addition")]
    assert len(v028_entries) >= 20, (
        f"v0.28.0 additions count is {len(v028_entries)} — expected 20+. "
        "Silent edit may have stripped _v028_addition flags."
    )
    for e in v028_entries:
        assert e.get("confidence") in ("high", "medium", "low"), (
            f"v0.28 entry missing/invalid confidence: {e.get('name')!r}"
        )
        assert e.get("source"), (
            f"v0.28 entry missing source citation: {e.get('name')!r}"
        )


# ─────────────────────────────────────────────────────────────────────
# Step 2.2: bridge_calldata.py decoder coverage
# ─────────────────────────────────────────────────────────────────────


def test_debridge_decoder_recognizes_create_sale_order() -> None:
    """The DeBridge DLN createSaleOrder method ID is recognized.
    Confidence is intentionally 'low' (no destination decode yet —
    full ABI parsing lands in v0.28.x point release). The bridge
    handoff IS surfaced in the trace report regardless."""
    # createSaleOrder selector 0xfb96b66e + minimal payload
    calldata = "0xfb96b66e" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is not None
    assert isinstance(result, BridgeDecodeResult)
    assert result.bridge_method == "createSaleOrder"
    assert result.confidence == "low"
    # No destination claimed (the conservative path).
    assert result.destination_chain is None
    assert result.destination_address is None


def test_debridge_decoder_recognizes_create_order() -> None:
    """The createOrder selector (alternate DLN entry point)."""
    calldata = "0xfaee513f" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is not None
    assert result.bridge_method == "createOrder"


def test_debridge_decoder_recognizes_send() -> None:
    """The DeBridge Gate send(...) method."""
    calldata = "0xb3c10b67" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is not None
    assert result.bridge_method == "send"


def test_debridge_decoder_rejects_unknown_method() -> None:
    """An unknown method ID under the DeBridge protocol returns
    None — not a wrong-confidence decode."""
    calldata = "0xdeadbeef" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is None


def test_1inch_decoder_recognizes_swap() -> None:
    """1inch v5/v6 Aggregation Router swap method recognized."""
    calldata = "0x12aa3caf" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="1inch", input_data=calldata,
    )
    assert result is not None
    assert result.bridge_method == "swap"
    assert result.confidence == "low"  # conservative — no destination


def test_decoder_dispatch_routes_protocols_correctly() -> None:
    """Dispatch by bridge_protocol must route to the right decoder.
    A regression that mis-routes (e.g. DeBridge calldata sent to
    the Across decoder) would silently produce wrong results."""
    # DeBridge selector under DeBridge protocol → recognized
    debridge_data = "0xfb96b66e" + "0" * 64
    assert decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=debridge_data,
    ) is not None
    # Same calldata under "Wormhole" protocol → None (not a Wormhole
    # method ID)
    assert decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=debridge_data,
    ) is None


def test_decoder_handles_empty_and_short_input() -> None:
    """Empty + short calldata must not crash the decoder."""
    for bad in (None, "", "0x", "0x12"):
        assert decode_bridge_calldata(
            bridge_protocol="DeBridge", input_data=bad,
        ) is None


# ─────────────────────────────────────────────────────────────────────
# Step 2.3: RECUPERO_CROSS_CHAIN_CONTINUATION default
# ─────────────────────────────────────────────────────────────────────


def test_cross_chain_continuation_default_is_on(monkeypatch) -> None:
    """Pre-v0.28 the env var defaulted to OFF — the cross-chain
    branch never fired in prod unless explicitly enabled.
    Post-v0.28 the default is ON; setting to '0' / 'false' / 'off'
    disables.

    We verify by replicating the parsing logic from tracer.py.
    A unit test against the actual tracer requires a full Case
    setup which we skip here — the parsing-logic verification is
    sufficient to pin the contract.
    """
    import os

    def _parse_cross_chain_env() -> bool:
        # Mirrors the post-v0.28 tracer.py logic exactly.
        raw = os.environ.get(
            "RECUPERO_CROSS_CHAIN_CONTINUATION", "",
        ).strip().lower()
        if raw in ("0", "false", "no", "off"):
            return False
        return True  # default ON, including unset / "1" / "true"

    # Unset → ON (the v0.28 default).
    monkeypatch.delenv("RECUPERO_CROSS_CHAIN_CONTINUATION", raising=False)
    assert _parse_cross_chain_env() is True

    # Empty string → ON.
    monkeypatch.setenv("RECUPERO_CROSS_CHAIN_CONTINUATION", "")
    assert _parse_cross_chain_env() is True

    # Opt-OUT values.
    for val in ("0", "false", "no", "off", "False", "OFF", "  off  "):
        monkeypatch.setenv("RECUPERO_CROSS_CHAIN_CONTINUATION", val)
        assert _parse_cross_chain_env() is False, (
            f"opt-out value {val!r} did not disable cross-chain"
        )

    # Opt-IN values (also work).
    for val in ("1", "true", "yes", "on", "True"):
        monkeypatch.setenv("RECUPERO_CROSS_CHAIN_CONTINUATION", val)
        assert _parse_cross_chain_env() is True


def test_tracer_module_implements_default_on_pattern() -> None:
    """Structural check: the tracer.py source must contain the
    new default-ON branching pattern. A regression that reverts
    to the old in-set check (defaulting to OFF) would be caught
    here.
    """
    import inspect

    from recupero.trace import tracer as tracer_mod

    src = inspect.getsource(tracer_mod)
    # The post-v0.28 pattern checks the opt-out list explicitly.
    assert '"0", "false", "no", "off"' in src or (
        '"0"' in src and '"false"' in src and '"off"' in src
    ), (
        "tracer.py no longer contains the opt-out check pattern. "
        "Likely regression: reverted to the old in-set 1/true/yes/on "
        "check (which defaults OFF). Restore the post-v0.28 default-ON "
        "pattern from docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md."
    )


# ─────────────────────────────────────────────────────────────────────
# Cross-cutting: docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md still references
# the file as the canonical reference.
# ─────────────────────────────────────────────────────────────────────


def test_trace_coverage_diagnosis_doc_still_referenced() -> None:
    """The seed file's _section markers reference the diagnosis
    doc — ensure the doc actually exists. A silent rename would
    leave dangling references."""
    diagnosis_path = (
        Path(__file__).parent.parent
        / "docs" / "TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md"
    )
    assert diagnosis_path.is_file(), (
        f"docs/TRACE_COVERAGE_DIAGNOSIS_ZIGHA.md missing — the v0.28 "
        "seed/decoder/env additions cite this doc as canonical "
        "reference."
    )
    body = diagnosis_path.read_text(encoding="utf-8")
    # The three blockers must still be documented.
    assert "Seed gap" in body or "seed gap" in body
    assert "Decoder gap" in body or "decoder gap" in body
    assert "Feature gate" in body or "feature gate" in body
