"""RIGOR-Jacob X: EVM _keep filter survives malformed numeric fields.

The ``_keep`` inner function in EvmAdapter.fetch_native_outflows
runs unprotected ``int(tx.get("value", "0"))`` and
``int(tx.get("blockNumber", "0"))`` on every row from Etherscan /
Alchemy. A row with ``value="not-a-number"`` raises ValueError
which propagates OUT of the for loop, killing the BFS hop.

The N-phase per-row try/except wraps ``_normalize_native`` but NOT
``_keep`` — the value-parse happens BEFORE normalization.

Lock the contract: _keep returns False on any unparseable field
rather than raising.
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


def test_fetch_native_outflows_handles_unparseable_value() -> None:
    """A row with value="garbage" must NOT crash the loop."""
    adapter = _build_adapter()
    addr = "0x" + "a" * 40

    good_row = {
        "hash": "0x" + "1" * 64, "blockNumber": "18000000",
        "timeStamp": "1700000000", "from": addr, "to": "0x" + "b" * 40,
        "value": "1000000000000000000", "isError": "0",
        "txreceipt_status": "1", "contractAddress": "",
    }
    bad_row = {
        "hash": "0x" + "2" * 64, "blockNumber": "18000001",
        "timeStamp": "1700000001", "from": addr, "to": "0x" + "c" * 40,
        "value": "not-a-number",  # unparseable
        "isError": "0", "txreceipt_status": "1", "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [good_row, bad_row]
    adapter.client.get_internal_transactions.return_value = []

    try:
        result = adapter.fetch_native_outflows(addr, start_block=0)
    except ValueError as e:
        raise AssertionError(
            f"fetch_native_outflows leaked ValueError on garbage "
            f"value field: {e}. The _keep filter must defensively "
            f"reject the row rather than raise."
        ) from e
    assert len(result) == 1, (
        f"Expected good row to survive (1 transfer), got {len(result)}"
    )


def test_fetch_native_outflows_handles_unparseable_block_number() -> None:
    """A row with blockNumber="abc" must NOT crash the loop."""
    adapter = _build_adapter()
    # Force the client-side block filter to engage.
    adapter.profile = adapter.profile.__class__(  # rebuild as Arbitrum
        chain=adapter.profile.chain,
        chain_id=42161,  # Arbitrum — triggers client-side filter
        api_base=adapter.profile.api_base,
        native_symbol=adapter.profile.native_symbol,
        native_decimals=adapter.profile.native_decimals,
        explorer_base=adapter.profile.explorer_base,
        coingecko_native_id=adapter.profile.coingecko_native_id,
        coingecko_platform=adapter.profile.coingecko_platform,
    )
    addr = "0x" + "a" * 40
    bad_row = {
        "hash": "0x" + "3" * 64,
        "blockNumber": "abc",  # unparseable
        "timeStamp": "1700000000", "from": addr, "to": "0x" + "d" * 40,
        "value": "1000000000000000000", "isError": "0",
        "txreceipt_status": "1", "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [bad_row]
    adapter.client.get_internal_transactions.return_value = []

    try:
        adapter.fetch_native_outflows(addr, start_block=1000)
    except ValueError as e:
        raise AssertionError(
            f"fetch_native_outflows leaked ValueError on garbage "
            f"blockNumber: {e}"
        ) from e


def test_fetch_native_outflows_normal_path_unaffected() -> None:
    """Sanity: normal rows still pass through."""
    adapter = _build_adapter()
    addr = "0x" + "a" * 40
    good = {
        "hash": "0x" + "5" * 64, "blockNumber": "18000005",
        "timeStamp": "1700000005", "from": addr, "to": "0x" + "d" * 40,
        "value": "1000000000000000000", "isError": "0",
        "txreceipt_status": "1", "contractAddress": "",
    }
    adapter.client.get_normal_transactions.return_value = [good]
    adapter.client.get_internal_transactions.return_value = []
    result = adapter.fetch_native_outflows(addr, start_block=0)
    assert len(result) == 1
