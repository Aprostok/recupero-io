"""Lock the RIGOR-Jacob A contract: ``max_transfers_per_address`` propagates
into the FETCH layer (adapter + pagination), not just post-fetch.

Why this matters: pre-RIGOR-Jacob A the tracer fetched ALL outflows
for a wallet, then sliced to `max_transfers_per_address`. For an
exchange hot wallet (1M+ historical txs) this meant:

  * ~1M tx Etherscan pagination requests (API budget burn).
  * Multiple minutes of wall-clock fetch time per BFS node.
  * The slice happened post-pricing, post-normalization — wasted
    CPU + memory on rows that would be immediately discarded.

The fix wires ``max_results`` through:
  ChainAdapter.fetch_{native,erc20}_outflows
    → EvmAdapter (and Solana/Bitcoin/Tron) accept max_results kwarg
    → EtherscanClient.get_*_transactions accept max_results kwarg
    → _paginate_account_action breaks the page loop early.

These tests assert the contract at each layer. A regression that
drops the kwarg or stops honoring it will fail here immediately.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_etherscan_paginate_breaks_on_max_results() -> None:
    """The pagination loop must short-circuit when max_results is
    satisfied. Mock 3 full pages; assert only 1 is fetched when
    max_results equals offset."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = EtherscanClient.__new__(EtherscanClient)  # bypass __init__
    client._ETHERSCAN_MAX_PAGES = 10
    client._ETHERSCAN_PAGE_SIZE_CAP = 10_000

    call_count = {"n": 0}

    def fake_call(**kwargs):
        call_count["n"] += 1
        # Return a full page of dummy rows.
        return {"result": [{"hash": f"0x{i:064x}"} for i in range(1000)]}

    client._call = fake_call  # type: ignore[attr-defined]
    client._coerce_list = lambda data: list(data.get("result", []))  # type: ignore[attr-defined]

    result = client._paginate_account_action(
        action="txlist",
        address="0xabc",
        start_block=0,
        end_block=99_999_999,
        page=1,
        offset=1000,
        max_results=1000,
    )

    assert call_count["n"] == 1, (
        f"max_results=1000 with page offset=1000 should stop after page 1; "
        f"got {call_count['n']} pages"
    )
    assert len(result) == 1000


def test_etherscan_paginate_unbounded_when_max_results_none() -> None:
    """The cap is opt-in. When max_results is None (the default for
    callers not threading it through), pagination behaves as it did
    pre-RIGOR-Jacob A — walks to the end-of-data or page cap."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = EtherscanClient.__new__(EtherscanClient)
    client._ETHERSCAN_MAX_PAGES = 10
    client._ETHERSCAN_PAGE_SIZE_CAP = 10_000

    pages_served = {"n": 0}

    def fake_call(**kwargs):
        pages_served["n"] += 1
        # Return 3 full pages then empty (so the loop naturally exits).
        if pages_served["n"] <= 3:
            return {"result": [{"hash": f"0x{i:064x}"} for i in range(1000)]}
        return {"result": []}

    client._call = fake_call  # type: ignore[attr-defined]
    client._coerce_list = lambda data: list(data.get("result", []))  # type: ignore[attr-defined]

    result = client._paginate_account_action(
        action="txlist", address="0xabc", start_block=0,
        end_block=99_999_999, page=1, offset=1000,
        max_results=None,
    )

    assert len(result) == 3000
    assert pages_served["n"] == 4  # 3 full + 1 empty


def test_get_normal_transactions_threads_max_results() -> None:
    """The public client method must forward max_results down to
    _paginate_account_action."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = EtherscanClient.__new__(EtherscanClient)
    captured = {}

    def fake_paginate(**kwargs):
        captured.update(kwargs)
        return []

    client._paginate_account_action = fake_paginate  # type: ignore[attr-defined]

    client.get_normal_transactions(
        "0xabc", start_block=0, max_results=2500,
    )

    assert captured["max_results"] == 2500
    assert captured["action"] == "txlist"


def test_get_erc20_transfers_threads_max_results() -> None:
    """Same contract on the ERC-20 endpoint."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = EtherscanClient.__new__(EtherscanClient)
    captured = {}

    def fake_paginate(**kwargs):
        captured.update(kwargs)
        return []

    client._paginate_account_action = fake_paginate  # type: ignore[attr-defined]

    client.get_erc20_transfers(
        "0xabc", start_block=0, max_results=750,
    )

    assert captured["max_results"] == 750
    assert captured["action"] == "tokentx"


def test_evm_adapter_threads_max_results_to_client() -> None:
    """The EvmAdapter.fetch_native_outflows must pass max_results to
    BOTH client.get_normal_transactions and client.get_internal_transactions
    — and fetch_erc20_outflows to client.get_erc20_transfers."""
    from recupero.chains.evm.adapter import EvmAdapter

    # Build a stub adapter.
    adapter = EvmAdapter.__new__(EvmAdapter)
    mock_client = MagicMock()
    mock_client.get_normal_transactions.return_value = []
    mock_client.get_internal_transactions.return_value = []
    mock_client.get_erc20_transfers.return_value = []
    adapter.client = mock_client
    adapter._WRAPPED_NATIVE_CONTRACTS = set()  # required by erc20 path
    adapter._needs_client_side_start_block_filter = lambda: False

    # Real EVM address (just any checksum-valid hex).
    addr = "0x" + "0" * 39 + "1"

    adapter.fetch_native_outflows(addr, start_block=0, max_results=500)
    assert mock_client.get_normal_transactions.call_args.kwargs["max_results"] == 500
    assert mock_client.get_internal_transactions.call_args.kwargs["max_results"] == 500

    adapter.fetch_erc20_outflows(addr, start_block=0, max_results=200)
    assert mock_client.get_erc20_transfers.call_args.kwargs["max_results"] == 200


def test_tracer_propagates_cap_with_safety_margin() -> None:
    """The tracer must pass a (1.5x) cap to the adapter so an
    asymmetric mix (1500 native + 5 token, etc.) doesn't truncate
    one leg below the configured `max_transfers_per_address`."""
    import recupero.trace.tracer as tracer_mod

    captured = {}

    class FakeAdapter:
        chain = "ethereum"  # str ok for this stub
        def block_at_or_before(self, ts):
            return 1
        def fetch_native_outflows(self, from_address, start_block, *, max_results=None):
            captured["native_max"] = max_results
            return []
        def fetch_erc20_outflows(self, from_address, start_block, *, max_results=None):
            captured["erc20_max"] = max_results
            return []

    from datetime import UTC, datetime

    from recupero.config import RecuperoConfig
    cfg = RecuperoConfig()
    cfg.trace.max_transfers_per_address = 500
    cfg.trace.incident_buffer_minutes = 0

    # _trace_one_hop has many required collaborators; we mock minimally.
    label_store = MagicMock()
    label_store.lookup.return_value = None
    price_client = MagicMock()
    policy = MagicMock()
    policy.service_wallet_outflow_threshold = 1_000_000
    policy.should_include.return_value = False  # drops everything

    from pathlib import Path
    tracer_mod._trace_one_hop(
        adapter=FakeAdapter(),
        label_store=label_store,
        price_client=price_client,
        policy=policy,
        from_address="0xabc",
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        config=cfg,
        hop_depth=0,
        parent_transfer_id=None,
        evidence_dir=Path("/tmp"),
    )

    # 500 * 1.5 = 750
    assert captured["native_max"] == 750, (
        f"tracer should propagate 1.5x cap (500 → 750), got {captured['native_max']}"
    )
    assert captured["erc20_max"] == 750


def test_tracer_passes_none_when_cap_disabled() -> None:
    """Setting max_transfers_per_address=0 (or negative) disables the
    cap — adapter receives None and reverts to unbounded fetch."""
    import recupero.trace.tracer as tracer_mod

    captured = {}

    class FakeAdapter:
        def block_at_or_before(self, ts):
            return 1
        def fetch_native_outflows(self, from_address, start_block, *, max_results=None):
            captured["native_max"] = max_results
            return []
        def fetch_erc20_outflows(self, from_address, start_block, *, max_results=None):
            captured["erc20_max"] = max_results
            return []

    from datetime import UTC, datetime
    from pathlib import Path

    from recupero.config import RecuperoConfig
    cfg = RecuperoConfig()
    cfg.trace.max_transfers_per_address = 0  # disable
    cfg.trace.incident_buffer_minutes = 0

    label_store = MagicMock()
    label_store.lookup.return_value = None
    price_client = MagicMock()
    policy = MagicMock()
    policy.service_wallet_outflow_threshold = 1_000_000
    policy.should_include.return_value = False

    tracer_mod._trace_one_hop(
        adapter=FakeAdapter(),
        label_store=label_store,
        price_client=price_client,
        policy=policy,
        from_address="0xabc",
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        config=cfg,
        hop_depth=0,
        parent_transfer_id=None,
        evidence_dir=Path("/tmp"),
    )

    assert captured["native_max"] is None
    assert captured["erc20_max"] is None
