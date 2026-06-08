"""Circle CCTP calldata decoder (v0.39, Activation Sprint #3 — restores the rail
lost despite task #247).

Verified against live mainnet TokenMessenger txs: selectors 0x6fd3504e
(depositForBurn) / 0xf856ddb6 (depositForBurnWithCaller); layout word0=amount,
word1=destinationDomain (Circle domain id), word2=mintRecipient (bytes32),
word3=burnToken. Pins: domain→chain mapping, EVM recipient extraction, non-EVM
(Solana) recipient correctly None (never fabricated), withCaller variant, dispatch
routing by protocol name, NEVER high confidence, and the verified seed entries.
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.trace.bridge_calldata import decode_bridge_calldata

_USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
# Real Base recipient from a verified live depositForBurn (domain 6).
_BASE_RECIP = "f70da97812cb96acdf810712aa562db8dfa3dbef"


def _mk_cctp(domain: int, recipient_hex: str, *, selector: str = "0x6fd3504e",
            amount: int = 13722541698) -> str:
    """Build depositForBurn calldata. recipient_hex is a 40-char EVM address or a
    64-char bytes32 (non-EVM)."""
    r = recipient_hex.lower().removeprefix("0x")
    recip_w = r.rjust(64, "0")  # EVM addr → left-padded bytes32; bytes32 → as-is
    return (
        selector
        + format(amount, "064x")            # amount
        + format(domain, "064x")            # destinationDomain
        + recip_w                           # mintRecipient (bytes32)
        + _USDC.removeprefix("0x").rjust(64, "0")  # burnToken
    )


def test_decodes_evm_destination_recipient_and_chain() -> None:
    cd = _mk_cctp(6, _BASE_RECIP)  # domain 6 = Base
    r = decode_bridge_calldata(bridge_protocol="Circle CCTP TokenMessenger", input_data=cd)
    assert r is not None
    assert r.destination_chain == "base"
    assert r.destination_address == "0x" + _BASE_RECIP
    assert r.bridge_method == "depositForBurn"
    assert r.confidence == "medium"  # calldata intent → medium, NEVER high


def test_domain_map_arbitrum_optimism_polygon() -> None:
    for domain, chain in [(3, "arbitrum"), (2, "optimism"), (7, "polygon"),
                          (0, "ethereum"), (1, "avalanche")]:
        r = decode_bridge_calldata(
            bridge_protocol="cctp", input_data=_mk_cctp(domain, _BASE_RECIP))
        assert r is not None and r.destination_chain == chain


def test_non_evm_solana_recipient_is_none_chain_still_reported() -> None:
    # domain 5 = Solana; mintRecipient is a 32-byte pubkey (top bytes non-zero) →
    # _extract_addr_slot returns None (we never fabricate an EVM address), but the
    # destination CHAIN is still reported.
    solana_key = "11" * 32
    r = decode_bridge_calldata(bridge_protocol="cctp", input_data=_mk_cctp(5, solana_key))
    assert r is not None
    assert r.destination_chain == "solana"
    assert r.destination_address is None
    assert r.confidence == "medium"  # have_chain


def test_with_caller_variant_decodes() -> None:
    cd = _mk_cctp(6, _BASE_RECIP, selector="0xf856ddb6")
    r = decode_bridge_calldata(bridge_protocol="Circle CCTP", input_data=cd)
    assert r is not None
    assert r.bridge_method == "depositForBurnWithCaller"
    assert r.destination_chain == "base"


def test_unknown_domain_no_chain_but_recipient() -> None:
    r = decode_bridge_calldata(bridge_protocol="cctp", input_data=_mk_cctp(99, _BASE_RECIP))
    assert r is not None
    assert r.destination_chain is None
    assert r.destination_address == "0x" + _BASE_RECIP
    assert r.confidence == "medium"  # have_recipient


def test_never_high_confidence() -> None:
    for dom in (0, 3, 6, 99):
        r = decode_bridge_calldata(bridge_protocol="cctp", input_data=_mk_cctp(dom, _BASE_RECIP))
        assert r is None or r.confidence in ("medium", "low")


def test_seed_entries_present_and_verified() -> None:
    seeds = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    entries = json.loads(seeds.read_text(encoding="utf-8-sig"))
    cctp = [e for e in entries if e.get("name") == "Circle CCTP TokenMessenger"]
    assert len(cctp) == 6  # ethereum/avalanche/optimism/arbitrum/base/polygon
    assert {e["chain"] for e in cctp} == {
        "ethereum", "avalanche", "optimism", "arbitrum", "base", "polygon"}
    assert all(e["category"] == "bridge" and e["confidence"] == "high" for e in cctp)
    # the Ethereum TokenMessenger we decoded a live tx from
    assert any(e["address"].lower() == "0xbd3fa81b58ba92a82136038b25adec7066af3155"
               for e in cctp)
