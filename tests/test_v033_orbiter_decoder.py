"""v0.33.0 Wave B — Orbiter amount-suffix destination decoder.

Verifies the decoder against Orbiter's encoding as confirmed BOTH by the
orbiter-sdk spec AND by 454 real inbound deposits to the highest-volume Maker:
the destination is encoded as the last four digits of the smallest-unit
integer amount, of the form 9000 + internalId (9002→Arbitrum, 9021→Base,
9007→Optimism, 9019→Scroll, 9023→Linea, ...). Realistic full-length wei
amounts are used. Also pins the safe-degradation paths (no 9xxx marker, limit
source chains, unknown codes, short amounts) and the never-"high" invariant.
"""

from __future__ import annotations

from recupero.trace.orbiter import (
    ORBITER_CODE_TO_CHAIN,
    decode_orbiter_destination,
)


def _wei_with_code(code: int) -> str:
    """A realistic 18-decimal wei amount whose trailing 4 digits are 9000+code
    (e.g. ~0.01 ETH bridged to Base -> ...9021)."""
    return "1000000000000" + f"{9000 + code:04d}"


def test_decodes_arbitrum_from_real_shape_wei() -> None:
    # 0.01 ETH to Arbitrum: trailing 4 == 9002 (most common in real data).
    d = decode_orbiter_destination("10000000000009002", source_chain="ethereum")
    assert d is not None
    assert d.code == 2
    assert d.orbiter_chain == "Arbitrum"
    assert d.our_chain == "arbitrum"
    assert d.confidence == "medium"


def test_decodes_real_data_high_volume_codes() -> None:
    # The codes actually observed on-chain, incl. the ones the old SDK map
    # missed (Base=21 was the single highest-volume destination).
    cases = {
        2: ("Arbitrum", "arbitrum"),
        7: ("Optimism", "optimism"),
        21: ("Base", "base"),
        19: ("Scroll", "scroll"),
        23: ("Linea", "linea"),
        14: ("zkSync Era", "zksync"),
        15: ("BNB Chain", "bsc"),
        1: ("Ethereum", "ethereum"),
        6: ("Polygon", "polygon"),
        10: ("Metis", "metis"),
        17: ("Polygon zkEVM", "polygon_zkevm"),
        31: ("Manta", "manta"),
    }
    for code, (orb, ours) in cases.items():
        d = decode_orbiter_destination(_wei_with_code(code), source_chain="ethereum")
        assert d is not None, code
        assert d.code == code
        assert d.orbiter_chain == orb
        assert d.our_chain == ours


def test_requires_9xxx_marker_bare_code_is_rejected() -> None:
    """REGRESSION: real Orbiter deposits carry the 9000 marker. A bare code in
    the last 4 digits (e.g. ...0002) is NOT an Orbiter identification code and
    must NOT decode — this is what a coincidental amount looks like."""
    assert decode_orbiter_destination("10000000000000002") is None
    assert decode_orbiter_destination("10000000000000021") is None


def test_known_orbiter_chain_but_untracked_gives_none_our_chain() -> None:
    # Starknet (code 4) is a real Orbiter chain but not in our Chain enum.
    d = decode_orbiter_destination(_wei_with_code(4), source_chain="ethereum")
    assert d is not None
    assert d.orbiter_chain == "Starknet"
    assert d.our_chain is None


def test_marker_present_but_unknown_code_confirms_deposit_without_chain() -> None:
    """A 9xxx marker with an internalId we don't map (a chain Orbiter added
    that we don't track) still CONFIRMS an Orbiter deposit — return the object
    with no chain rather than fabricate or drop the handoff."""
    assert 40 not in ORBITER_CODE_TO_CHAIN
    d = decode_orbiter_destination("10000000000009040", source_chain="ethereum")
    assert d is not None
    assert d.code == 40
    assert d.orbiter_chain is None
    assert d.our_chain is None


def test_zero_flag_and_no_marker_return_none() -> None:
    assert decode_orbiter_destination("10000000000000000") is None   # 0000
    assert decode_orbiter_destination("12340000000005000") is None   # 5000, no 9 marker


def test_short_amount_returns_none() -> None:
    assert decode_orbiter_destination("12") is None
    assert decode_orbiter_destination("9002") is not None            # exactly 4 digits, valid marker


def test_limit_source_chains_degrade_to_none() -> None:
    for src in ("zksync", "immutablex", "dydx", "ZKSYNC", "zksync_era"):
        assert decode_orbiter_destination(_wei_with_code(21), source_chain=src) is None


def test_non_digit_and_negative_return_none() -> None:
    assert decode_orbiter_destination("-10000000000009002") is None
    assert decode_orbiter_destination("0x123abc") is None
    assert decode_orbiter_destination("12.34") is None


def test_accepts_integer_input() -> None:
    d = decode_orbiter_destination(10000000000009021, source_chain="ethereum")
    assert d is not None and d.our_chain == "base"


def test_never_high_confidence() -> None:
    for code in (1, 2, 7, 21, 40):
        d = decode_orbiter_destination(_wei_with_code(code))
        assert d is not None
        assert d.confidence != "high"
        assert d.confidence == "medium"


def test_no_source_chain_still_decodes_non_limit() -> None:
    d = decode_orbiter_destination(_wei_with_code(6))
    assert d is not None and d.our_chain == "polygon"


# ---------------------------------------------------------------------------
# Integration: the decoder is wired into identify_cross_chain_handoffs so an
# Orbiter Maker handoff surfaces its decoded destination chain in the brief.
# ---------------------------------------------------------------------------


def _orbiter_case(amount_raw: str):  # noqa: ANN202 - test helper
    from datetime import UTC, datetime
    from decimal import Decimal

    from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer

    maker = "0x80C67432656d59144cEFf962E8fAF8926599bCF8"  # verified Orbiter Maker
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    tx = "0x" + "9" * 64
    t = Transfer(
        transfer_id=f"ethereum:{tx}:1",
        chain=Chain.ethereum,
        tx_hash=tx,
        block_number=1,
        block_time=ts,
        from_address="0x" + "ab" * 20,
        to_address=maker,
        counterparty=Counterparty(address=maker, label=None, is_contract=False),
        token=TokenRef(chain=Chain.ethereum, contract="0x0000000000000000000000000000000000000000",
                       symbol="ETH", decimals=18, coingecko_id="ethereum"),
        amount_raw=amount_raw,
        amount_decimal=Decimal("0.01"),
        usd_value_at_tx=Decimal("25"),
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx}",
        fetched_at=ts,
    )
    return Case(
        case_id="orbiter-test", seed_address="0x" + "ab" * 20, chain=Chain.ethereum,
        incident_time=ts, transfers=[t], trace_started_at=ts,
        software_version="test", config_used={},
    )


def test_handoff_surfaces_decoded_destination_for_orbiter() -> None:
    from recupero.trace.cross_chain import identify_cross_chain_handoffs

    # 0.01 ETH into the Maker with the Base marker (9021).
    case = _orbiter_case("10000000000009021")
    handoffs = identify_cross_chain_handoffs(case)
    orb = [h for h in handoffs if "orbiter" in h.bridge_protocol.lower()]
    assert orb, "Orbiter Maker handoff not recognized"
    h = orb[0]
    assert h.decoded_destination_chain == "base"
    assert h.decoded_confidence == "medium"
    # CRITICAL: address left None so the same-address lock-mint matcher runs.
    assert h.decoded_destination_address is None


def test_handoff_no_decode_for_non_orbiter_amount() -> None:
    from recupero.trace.cross_chain import identify_cross_chain_handoffs

    # A bare (non-9xxx) amount -> no decode, but the handoff is still found
    # via the Maker label (continuation handled by the lock-mint matcher).
    case = _orbiter_case("10000000000000021")
    handoffs = identify_cross_chain_handoffs(case)
    orb = [h for h in handoffs if "orbiter" in h.bridge_protocol.lower()]
    assert orb
    assert orb[0].decoded_destination_chain is None
    assert orb[0].decoded_confidence is None
