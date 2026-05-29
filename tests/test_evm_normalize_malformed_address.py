"""RIGOR-Jacob N: EVM adapter defense against malformed addresses
from Alchemy / Etherscan.

``_normalize_native`` and ``_normalize_erc20`` call
``to_checksum_address(tx["from"])`` / ``tx["to"])`` / ``tx["contractAddress"]``
on data from Alchemy / Etherscan. If the external API returns a
malformed hex string (truncated, non-hex chars, wrong length),
``eth_utils.to_checksum_address`` raises ``InvalidAddress``
uncaught — the entire BFS hop dies.

The ``_keep()`` filter checks that ``from_l == addr_l`` (lowercased
comparison to the query address), which DROPS rows from other
addresses. But it doesn't validate the SHAPE of the from/to fields
— a row where ``from`` happens to match our query but ``to`` is
malformed still reaches ``_normalize_native``.

Lock the contract: a malformed `to` field doesn't crash the whole
loop; the row is silently dropped + logged.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _build_adapter():
    """Construct an EvmAdapter without network setup."""
    from recupero.chains.evm.adapter import EvmAdapter, _profile_for
    from recupero.config import RecuperoConfig
    from recupero.models import Chain

    cfg = RecuperoConfig()
    adapter = EvmAdapter.__new__(EvmAdapter)
    adapter.cfg = cfg
    adapter.profile = _profile_for(Chain.ethereum, cfg)
    adapter.chain = Chain.ethereum
    adapter.client = MagicMock()
    adapter._is_contract_cache = {}
    return adapter


def test_fetch_native_outflows_skips_malformed_to_address() -> None:
    """A malformed `to` address from Alchemy / Etherscan must NOT
    crash the whole fetch loop. The row is dropped + logged."""

    adapter = _build_adapter()
    addr = "0x" + "a" * 40

    # Mock the client to return a row with malformed `to`. Etherscan
    # rows have specific keys.
    good_row = {
        "hash": "0x" + "1" * 64,
        "blockNumber": "18000000",
        "timeStamp": "1700000000",
        "from": addr,
        "to": "0x" + "b" * 40,
        "value": "1000000000000000000",
        "isError": "0",
        "txreceipt_status": "1",
        "contractAddress": "",
    }
    malformed_row = {
        "hash": "0x" + "2" * 64,
        "blockNumber": "18000001",
        "timeStamp": "1700000001",
        "from": addr,
        "to": "0xNOT_A_HEX_ADDRESS_AT_ALL_!!",  # malformed
        "value": "1000000000000000000",
        "isError": "0",
        "txreceipt_status": "1",
        "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [
        good_row, malformed_row,
    ]
    adapter.client.get_internal_transactions.return_value = []
    adapter.client.get_erc20_transfers.return_value = []

    try:
        result = adapter.fetch_native_outflows(addr, start_block=0)
    except Exception as e:
        raise AssertionError(
            f"fetch_native_outflows raised {type(e).__name__} on "
            f"a malformed `to` field: {e}. The malformed row must be "
            f"silently dropped — Alchemy/Etherscan is external; a "
            f"single bad row must not crash the BFS hop."
        ) from e

    # Should have produced ONE result (the good row).
    # The malformed row should be silently dropped.
    assert len(result) == 1, (
        f"Expected 1 transfer (good row only), got {len(result)}. "
        f"Either the malformed row leaked through OR the good row "
        f"was dropped along with the bad one."
    )


def test_fetch_native_outflows_skips_truncated_to_address() -> None:
    """A truncated EVM address (39 chars instead of 42) must drop
    cleanly."""

    adapter = _build_adapter()
    addr = "0x" + "a" * 40
    truncated_row = {
        "hash": "0x" + "3" * 64,
        "blockNumber": "18000002",
        "timeStamp": "1700000002",
        "from": addr,
        "to": "0x" + "b" * 38,  # too short by 2
        "value": "1000000000000000000",
        "isError": "0",
        "txreceipt_status": "1",
        "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [truncated_row]
    adapter.client.get_internal_transactions.return_value = []
    adapter.client.get_erc20_transfers.return_value = []

    try:
        result = adapter.fetch_native_outflows(addr, start_block=0)
    except Exception as e:
        raise AssertionError(
            f"fetch_native_outflows raised {type(e).__name__} on a "
            f"truncated `to` field: {e}"
        ) from e
    # Should have dropped the only row → empty result.
    assert result == []


def test_fetch_erc20_outflows_skips_malformed_contract_address() -> None:
    """ERC-20 path: malformed `contractAddress` field crashes
    `to_checksum_address` inside `_normalize_erc20`. Pre-fix this
    propagates uncaught."""

    adapter = _build_adapter()
    addr = "0x" + "a" * 40
    malformed = {
        "hash": "0x" + "4" * 64,
        "blockNumber": "18000003",
        "timeStamp": "1700000003",
        "from": addr,
        "to": "0x" + "c" * 40,
        "value": "100000000",
        "tokenSymbol": "USDT",
        "tokenDecimal": "6",
        "contractAddress": "NOT-A-CONTRACT-ADDRESS",  # garbage
        "isError": "0",
    }
    adapter.client.get_erc20_transfers.return_value = [malformed]

    try:
        result = adapter.fetch_erc20_outflows(addr, start_block=0)
    except Exception as e:
        raise AssertionError(
            f"fetch_erc20_outflows raised {type(e).__name__} on a "
            f"malformed contractAddress: {e}"
        ) from e
    assert result == [], (
        "Malformed contractAddress row should be dropped; got "
        f"{result!r}"
    )


def test_good_row_still_works_alongside_malformed() -> None:
    """Sanity: a good row in the same batch as a malformed one still
    produces a valid Transfer output."""

    adapter = _build_adapter()
    addr = "0x" + "a" * 40
    good_row = {
        "hash": "0x" + "5" * 64,
        "blockNumber": "18000005",
        "timeStamp": "1700000005",
        "from": addr,
        "to": "0x" + "d" * 40,
        "value": "1000000000000000000",
        "isError": "0",
        "txreceipt_status": "1",
        "contractAddress": "",
    }
    malformed_row = {
        "hash": "0x" + "6" * 64,
        "blockNumber": "18000006",
        "timeStamp": "1700000006",
        "from": addr,
        "to": "garbage_to_field",
        "value": "500000000000000000",
        "isError": "0",
        "txreceipt_status": "1",
        "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [
        good_row, malformed_row,
    ]
    adapter.client.get_internal_transactions.return_value = []

    result = adapter.fetch_native_outflows(addr, start_block=0)
    assert len(result) == 1
    assert result[0]["tx_hash"] == good_row["hash"]
