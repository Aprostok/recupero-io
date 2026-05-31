"""v0.34 receipt-log swap-output resolver (0x Protocol / Matcha settler swaps).

A 0x swap pays out the converted token (e.g. DAI) from a SETTLER / pool the BFS
never traverses, so the output is absent from case.transfers and the trace
dead-ends at the router. ``parse_erc20_transfers`` + ``resolve_swap_output``
recover the output from the tx receipt's ERC-20 Transfer logs.

These tests model the exact Zigha shape: input token X enters the settler;
DAI flows settler → proxy → terminal recipient. The resolver must return the
TERMINAL recipient (not the internal settler→proxy hop), of the OUTPUT token
(DAI, not the input), at calibrated `medium` confidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

from recupero.trace.swap_output import (
    ERC20_TRANSFER_TOPIC,
    parse_erc20_transfers,
    resolve_swap_output,
)

DAI = "0x6b175474e89094c44da98b954eedeac495271d0f"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SETTLER = "0x207e1074858a7e78f17002075739ed2745dbaece"  # 0x MainnetSettler
PROXY = "0x663dc15d3c1ac63ff12e45ab68fea3f0a883c251"    # 0x router proxy
SWAPPER = "0x1111111111111111111111111111111111111111"  # perp hub
RECIPIENT = "0xc1ee32fac1d9a0ce63021467e34164df3078289b"  # terminal (intermediate)


def _topic_addr(a: str) -> str:
    return "0x" + "0" * 24 + a.removeprefix("0x")


def _log(token, frm, to, amount_wei):
    return {
        "address": token,
        "topics": [ERC20_TRANSFER_TOPIC, _topic_addr(frm), _topic_addr(to)],
        "data": hex(amount_wei),
    }


def _receipt(*logs):
    return {"logs": list(logs)}


# --------------------------- parse_erc20_transfers --------------------------


def test_parse_basic_transfers() -> None:
    rc = _receipt(
        _log(DAI, SETTLER, PROXY, 10**18),
        _log(DAI, PROXY, RECIPIENT, 10**18),
    )
    parsed = parse_erc20_transfers(rc)
    assert len(parsed) == 2
    assert parsed[0].token == DAI
    assert parsed[0].frm == SETTLER
    assert parsed[1].to == RECIPIENT
    assert parsed[1].amount == 10**18


def test_parse_ignores_non_transfer_logs_and_malformed() -> None:
    rc = {"logs": [
        {"address": DAI, "topics": ["0xdeadbeef"], "data": "0x1"},  # not Transfer
        {"address": DAI, "topics": [ERC20_TRANSFER_TOPIC], "data": "0x1"},  # <3 topics
        {"address": DAI, "topics": [ERC20_TRANSFER_TOPIC,
                                    _topic_addr(SETTLER), _topic_addr(RECIPIENT)],
         "data": "0xnothex"},  # bad amount
        _log(DAI, SETTLER, RECIPIENT, 5),  # valid
    ]}
    parsed = parse_erc20_transfers(rc)
    assert len(parsed) == 1
    assert parsed[0].amount == 5


def test_parse_no_logs() -> None:
    assert parse_erc20_transfers({}) == []
    assert parse_erc20_transfers(None) == []
    assert parse_erc20_transfers({"logs": "garbage"}) == []


# --------------------------- resolve_swap_output ----------------------------


def test_resolves_terminal_dai_recipient_through_settler_chain() -> None:
    """The Zigha shape: USDC in -> settler; DAI flows settler->proxy->recipient.
    The output is the TERMINAL recipient (DAI), not the internal proxy hop."""
    parsed = parse_erc20_transfers(_receipt(
        _log(USDC, SWAPPER, SETTLER, 3_000_000 * 10**6),     # input: USDC -> settler
        _log(DAI, SETTLER, PROXY, 2_919_869 * 10**18),        # internal settler->proxy
        _log(DAI, PROXY, RECIPIENT, 2_919_869 * 10**18),      # OUTPUT -> terminal recipient
    ))
    out = resolve_swap_output(
        parsed,
        swapper=SWAPPER,
        input_token_contracts={USDC},
        infra_addresses={SETTLER, PROXY},
    )
    assert out is not None
    assert out.output_token_contract == DAI
    assert out.output_recipient == RECIPIENT  # NOT the proxy (internal hop)
    assert out.confidence == "medium"


def test_does_not_return_input_token_or_infra_or_swapper() -> None:
    # Only an input-token movement + an infra->infra hop -> no qualifying output.
    parsed = parse_erc20_transfers(_receipt(
        _log(USDC, SWAPPER, SETTLER, 100),       # input token
        _log(DAI, SETTLER, PROXY, 100),          # infra->infra (proxy re-sends below)
        _log(DAI, PROXY, SETTLER, 100),          # back to infra (not terminal)
    ))
    out = resolve_swap_output(
        parsed, swapper=SWAPPER,
        input_token_contracts={USDC}, infra_addresses={SETTLER, PROXY},
    )
    assert out is None


def test_output_back_to_swapper_is_not_an_onward_hop() -> None:
    # Swap returns DAI to the swapper itself -> not a NEW recipient to follow.
    parsed = parse_erc20_transfers(_receipt(
        _log(USDC, SWAPPER, SETTLER, 100),
        _log(DAI, SETTLER, SWAPPER, 100),
    ))
    out = resolve_swap_output(
        parsed, swapper=SWAPPER,
        input_token_contracts={USDC}, infra_addresses={SETTLER},
    )
    assert out is None


def test_picks_dominant_output_token_when_multiple() -> None:
    """Fee dust in a third token must not beat the main DAI output."""
    other = "0x000000000000000000000000000000000000fee5"
    r2 = "0x2222222222222222222222222222222222222222"
    parsed = parse_erc20_transfers(_receipt(
        _log(USDC, SWAPPER, SETTLER, 100),
        _log(DAI, SETTLER, RECIPIENT, 5_000_000 * 10**18),   # main output
        _log(other, SETTLER, r2, 1),                          # dust fee, diff token
    ))
    out = resolve_swap_output(
        parsed, swapper=SWAPPER,
        input_token_contracts={USDC}, infra_addresses={SETTLER},
    )
    assert out.output_token_contract == DAI
    assert out.output_recipient == RECIPIENT


def test_empty_returns_none() -> None:
    assert resolve_swap_output(
        [], swapper=SWAPPER, input_token_contracts={USDC}, infra_addresses=set(),
    ) is None


# --------------------- detect_dex_swaps adapter integration -----------------


def test_detect_dex_swaps_recovers_0x_output_via_receipt_logs() -> None:
    """End-to-end: input USDC -> 0x MainnetSettler (in case.transfers), output
    DAI paid settler->proxy->recipient (NOT in case.transfers). With an adapter,
    detect_dex_swaps recovers the recipient from the swap tx's receipt logs and
    marks it output_source='receipt_logs' so the continuation follows it."""
    from recupero.trace.dex_swaps import detect_dex_swaps

    in_t = SimpleNamespace(
        tx_hash="0xswaptx",
        to_address=SETTLER,
        from_address=SWAPPER,
        token=SimpleNamespace(symbol="USDC", contract=USDC),
        amount_decimal=Decimal("3000000"),
        usd_value_at_tx=Decimal("3000000"),
        explorer_url="https://etherscan.io/tx/0xswaptx",
        block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    case = SimpleNamespace(transfers=[in_t])
    receipt = _receipt(
        _log(USDC, SWAPPER, SETTLER, 3_000_000 * 10**6),     # input leg
        _log(DAI, SETTLER, PROXY, 2_900_000 * 10**18),        # internal hop
        _log(DAI, PROXY, RECIPIENT, 2_900_000 * 10**18),      # output -> terminal
    )
    adapter = SimpleNamespace(
        fetch_evidence_receipt=lambda _tx: SimpleNamespace(raw_receipt=receipt)
    )

    swaps = detect_dex_swaps(
        case, {SETTLER: {"name": "0x: MainnetSettler"}}, adapter=adapter,
    )
    assert len(swaps) == 1
    s = swaps[0]
    assert s.output_recipient == RECIPIENT
    assert s.output_source == "receipt_logs"
    assert s.confidence == "medium"


def test_detect_dex_swaps_without_adapter_still_dead_ends() -> None:
    """Without an adapter, a settler swap with no in-trace output stays
    unresolved (output_recipient None) — proving the adapter is what unlocks it
    and that default behavior is unchanged."""
    from recupero.trace.dex_swaps import detect_dex_swaps

    in_t = SimpleNamespace(
        tx_hash="0xswaptx", to_address=SETTLER, from_address=SWAPPER,
        token=SimpleNamespace(symbol="USDC", contract=USDC),
        amount_decimal=Decimal("3000000"), usd_value_at_tx=Decimal("3000000"),
        explorer_url="x", block_time=datetime(2025, 10, 9, tzinfo=UTC),
    )
    case = SimpleNamespace(transfers=[in_t])
    swaps = detect_dex_swaps(case, {SETTLER: {"name": "0x: MainnetSettler"}})
    assert len(swaps) == 1
    assert swaps[0].output_recipient is None
    assert swaps[0].output_source == "in_trace"
