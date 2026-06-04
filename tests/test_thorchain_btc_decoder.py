"""v0.37.3 (deep-reach #4) — THORChain Router memo decoder: extract the
cross-chain destination (incl. native Bitcoin) from the swap memo.

The THORChain Router was already a verified bridge seed (bridges.json,
v0.34, on-chain confirmed) but had NO calldata decoder — so a deposit to it
was detected as a handoff with no destination, dead-ending the trace. THORChain
encodes the destination in the swap MEMO (the 4th calldata arg, a string):

    "<fn>:<CHAIN.ASSET>:<destination_addr>:<limits>:<affiliate>:<fee>"
    e.g. "=:BTC.BTC:bc1q...:0/1/0"  ->  bridge to the bitcoin address bc1q…

This pins the decoder. Confidence is intentionally capped at 'medium' (the memo
address is on-chain + deterministic, but the decoder is verified here only
against a SPEC-ACCURATE SYNTHETIC fixture, not an authoritative on-chain swap) —
so the destination is SURFACED as a handoff candidate without the BFS auto-
crossing (which requires 'high'). Promote to 'high' once a real THORChain
EVM→BTC swap fixture lands; the existing v0.37.1 continuation then follows it
onto Bitcoin via the already-registered BitcoinAdapter.
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.trace.bridge_calldata import decode_bridge_calldata

_THOR = "THORChain Router"
_FIXTURE = Path(__file__).parent / "fixtures" / "thorchain_btc_swap.json"


def _u256(n: int) -> str:
    return f"{n:064x}"


def _addr_word(addr_hex: str) -> str:
    return addr_hex.lower().replace("0x", "").rjust(64, "0")


def _encode_thorchain_deposit(memo: str, *, with_expiry: bool = True) -> str:
    """Build spec-accurate THORChain Router calldata.

    depositWithExpiry(address vault, address asset, uint256 amount,
                      string memo, uint256 expiry)   selector 0x44bc937b
    deposit(address vault, address asset, uint256 amount, string memo)
                                                       selector 0x1fece7b4
    The memo is arg index 3 (a dynamic string) in both.
    """
    selector = "44bc937b" if with_expiry else "1fece7b4"
    vault = _addr_word("0x" + "11" * 20)
    asset = _addr_word("0x" + "00" * 20)  # native ETH sentinel
    amount = _u256(10**18)
    # head = N static/offset slots; the dynamic memo data follows the head.
    n_args = 5 if with_expiry else 4
    head_bytes = n_args * 32
    memo_offset = _u256(head_bytes)
    head = vault + asset + amount + memo_offset
    if with_expiry:
        head += _u256(99_999_999)  # expiry
    memo_b = memo.encode()
    pad = (32 - (len(memo_b) % 32)) % 32
    tail = _u256(len(memo_b)) + (memo_b + b"\x00" * pad).hex()
    return "0x" + selector + head + tail


_BTC_ADDR = "bc1qexampledestinationaddr00000000000000xy"


def test_thorchain_btc_memo_decodes_to_bitcoin_destination() -> None:
    calldata = _encode_thorchain_deposit(f"=:BTC.BTC:{_BTC_ADDR}:0/1/0")
    res = decode_bridge_calldata(bridge_protocol=_THOR, input_data=calldata)
    assert res is not None
    assert res.destination_chain == "bitcoin"
    assert res.destination_address == _BTC_ADDR
    assert res.bridge_method == "depositWithExpiry"
    # v0.36: a bech32 BTC destination decoded from calldata is 'medium' (decoded
    # intent, not observed receipt). The BFS still auto-crosses onto BTC — the
    # continuation gate follows {high, medium} — it just no longer over-claims.
    assert res.confidence == "medium"


def test_thorchain_real_onchain_calldata_decodes_medium() -> None:
    """THE authoritative check: decode the REAL THORChain depositWithExpiry tx
    (Ethereum mainnet, fetched via Etherscan) and confirm we recover the exact
    native-Bitcoin destination from its on-chain memo. v0.36: a destination
    decoded from the source calldata is 'medium' (decoded intent, not observed
    receipt) — never 'high'."""
    fx = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    res = decode_bridge_calldata(bridge_protocol=_THOR, input_data=fx["input"])
    assert res is not None
    assert res.destination_chain == fx["expected_destination_chain"] == "bitcoin"
    assert res.destination_address == fx["expected_destination_address"]
    assert res.bridge_method == fx["expected_bridge_method"]
    assert res.confidence == fx["expected_confidence"] == "medium"


def test_thorchain_deposit_variant_also_decodes() -> None:
    calldata = _encode_thorchain_deposit(
        f"SWAP:BTC.BTC:{_BTC_ADDR}", with_expiry=False,
    )
    res = decode_bridge_calldata(bridge_protocol=_THOR, input_data=calldata)
    assert res is not None
    assert res.destination_chain == "bitcoin"
    assert res.destination_address == _BTC_ADDR
    assert res.bridge_method == "deposit"


def test_thorchain_non_btc_chain_surfaced_raw() -> None:
    # DOGE has no adapter; the raw chain code is surfaced for the candidates
    # list, and (no adapter) it won't auto-cross anyway.
    calldata = _encode_thorchain_deposit("=:DOGE.DOGE:DQA5xxxxxxxxxxxxxxxxxxxxxxx:0/1/0")
    res = decode_bridge_calldata(bridge_protocol=_THOR, input_data=calldata)
    assert res is not None
    assert res.destination_chain == "doge"


def test_thorchain_malformed_memo_is_low_confidence() -> None:
    # No ':' grammar → can't extract a destination → low (recognized only).
    calldata = _encode_thorchain_deposit("garbage memo without grammar")
    res = decode_bridge_calldata(bridge_protocol=_THOR, input_data=calldata)
    assert res is not None
    assert res.confidence == "low"
    assert res.destination_address is None


def test_mayan_is_not_decoded_as_thorchain() -> None:
    # Guard: "Mayan" (a Wormhole-based bridge in bridges.json) must NOT be
    # routed to the THORChain decoder — the dispatch matches "thorchain" only.
    calldata = _encode_thorchain_deposit(f"=:BTC.BTC:{_BTC_ADDR}:0/1/0")
    res = decode_bridge_calldata(bridge_protocol="Mayan", input_data=calldata)
    # Mayan has no THORChain-style decoder path; it must not claim a BTC dest.
    assert res is None or res.destination_chain != "bitcoin"
