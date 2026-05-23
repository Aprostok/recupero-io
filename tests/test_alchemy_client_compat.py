"""Lock the RIGOR-Jacob B contract: AlchemyClient is Etherscan-shape.

The AlchemyClient must return rows with the SAME dict keys the rest
of the EvmAdapter normalization code expects from EtherscanClient.
Any divergence breaks the adapter silently — the trace would emit a
case with wrong block numbers, missing token decimals, etc.

These tests:
  * Lock the normalization → Etherscan-shape mapping with golden
    examples derived from the Alchemy docs sample responses.
  * Lock the DualBackendClient.build() decision matrix (prefer +
    chain supported → DualBackend; otherwise → plain Etherscan).
  * Lock the auto-fallback: AlchemyRateLimitError on
    get_normal_transactions → Etherscan is called as a fallback.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def test_normalize_external_to_etherscan_keys() -> None:
    """An Alchemy external transfer must produce all the keys
    EvmAdapter._normalize_native + _keep depend on:
    hash, blockNumber, timeStamp, from, to, value, isError,
    txreceipt_status, contractAddress."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    row = {
        "blockNum": "0x1234ab",
        "hash": "0xabc",
        "from": "0xAAA",
        "to": "0xBBB",
        "value": 0.5,
        "asset": "ETH",
        "category": "external",
        "rawContract": {
            "address": None,
            "value": "0x6f05b59d3b20000",  # 0.5 ETH = 5e17 wei
            "decimal": "0x12",
        },
        "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
    }
    out = AlchemyClient._normalize_external_to_etherscan(row)
    required = {
        "hash", "blockNumber", "timeStamp", "from", "to",
        "value", "isError", "txreceipt_status", "contractAddress",
    }
    missing = required - set(out)
    assert not missing, f"missing keys: {missing}"
    # Spot-check correctness
    assert out["hash"] == "0xabc"
    assert out["blockNumber"] == "1193131"  # 0x1234ab
    assert out["from"] == "0xaaa"
    assert out["to"] == "0xbbb"
    assert out["value"] == "500000000000000000"  # 0.5 ETH in wei
    assert out["isError"] == "0"
    assert out["txreceipt_status"] == "1"


def test_normalize_erc20_to_etherscan_keys() -> None:
    """ERC-20 normalization adds tokenName / tokenSymbol /
    tokenDecimal / contractAddress (rest matches the native shape).
    EvmAdapter._normalize_erc20 reads ALL these — any miss is silent
    skew."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    row = {
        "blockNum": "0x5",
        "hash": "0xdef",
        "from": "0xCCC",
        "to": "0xDDD",
        "value": 100.0,
        "asset": "USDT",
        "category": "erc20",
        "rawContract": {
            "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "value": "0x5f5e100",   # 100,000,000 raw (USDT has 6 decimals → 100.0)
            "decimal": "0x6",
        },
        "metadata": {"blockTimestamp": "2025-06-01T12:00:00Z"},
    }
    out = AlchemyClient._normalize_erc20_to_etherscan(row)
    required = {
        "hash", "blockNumber", "timeStamp", "from", "to",
        "value", "tokenName", "tokenSymbol", "tokenDecimal",
        "contractAddress", "isError", "txreceipt_status",
    }
    missing = required - set(out)
    assert not missing, f"missing keys: {missing}"
    assert out["tokenSymbol"] == "USDT"
    assert out["tokenDecimal"] == "6"
    assert out["value"] == "100000000"
    assert out["contractAddress"] == "0xdac17f958d2ee523a2206206994597c13d831ec7"


def test_normalize_erc20_handles_integer_decimal() -> None:
    """Older Alchemy responses pass rawContract.decimal as a JSON
    integer (not hex string). The normalizer must accept both."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    row = {
        "blockNum": "0x1", "hash": "0x1",
        "from": "0xA", "to": "0xB", "value": 1.0,
        "asset": "TKN", "category": "erc20",
        "rawContract": {
            "address": "0xCONTRACT",
            "value": "0x1",
            "decimal": 6,  # ← integer, not hex string
        },
        "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
    }
    out = AlchemyClient._normalize_erc20_to_etherscan(row)
    assert out["tokenDecimal"] == "6"


def test_dual_backend_build_with_alchemy_disabled_returns_etherscan() -> None:
    """prefer_alchemy=False → plain EtherscanClient (no wrapper). The
    wrapper has overhead; opt-in only."""
    from recupero.chains.ethereum.etherscan import EtherscanClient
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    result = DualBackendClient.build(
        etherscan_api_key="fake_es_key",
        etherscan_api_base="https://api.etherscan.io/v2/api",
        chain_id=1,
        alchemy_api_key="fake_al_key",
        prefer_alchemy=False,
    )
    assert isinstance(result, EtherscanClient)


def test_dual_backend_build_returns_etherscan_when_no_alchemy_key() -> None:
    """--prefer-alchemy WITHOUT an ALCHEMY_API_KEY logs a warning and
    falls through to Etherscan-only — must not crash."""
    from recupero.chains.ethereum.etherscan import EtherscanClient
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    result = DualBackendClient.build(
        etherscan_api_key="fake_es_key",
        etherscan_api_base="https://api.etherscan.io/v2/api",
        chain_id=1,
        alchemy_api_key="",  # ← empty
        prefer_alchemy=True,
    )
    assert isinstance(result, EtherscanClient)


def test_dual_backend_build_returns_etherscan_on_unsupported_chain() -> None:
    """Some EVM chains aren't on Alchemy (Linea on free tier, etc.).
    The factory must fall through gracefully — don't crash, don't
    refuse to trace."""
    from recupero.chains.ethereum.etherscan import EtherscanClient
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    # 99999 isn't in the supported set.
    result = DualBackendClient.build(
        etherscan_api_key="fake_es_key",
        etherscan_api_base="https://api.etherscan.io/v2/api",
        chain_id=99999,
        alchemy_api_key="fake_al_key",
        prefer_alchemy=True,
    )
    assert isinstance(result, EtherscanClient)


def test_dual_backend_build_returns_wrapper_when_supported() -> None:
    """The happy path: --prefer-alchemy + key set + supported chain →
    DualBackendClient wrapper is returned."""
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    result = DualBackendClient.build(
        etherscan_api_key="fake_es_key",
        etherscan_api_base="https://api.etherscan.io/v2/api",
        chain_id=1,  # Ethereum mainnet
        alchemy_api_key="fake_al_key",
        prefer_alchemy=True,
    )
    assert isinstance(result, DualBackendClient)


def test_dual_backend_fallback_on_alchemy_rate_limit() -> None:
    """When Alchemy raises AlchemyRateLimitError, the wrapper must
    fall back to Etherscan WITHOUT propagating the exception. Logs
    the fallback at WARN."""
    from recupero.chains.evm.alchemy_client import AlchemyRateLimitError
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    mock_etherscan = MagicMock()
    mock_etherscan.get_normal_transactions.return_value = [{"hash": "0xfallback"}]
    mock_alchemy = MagicMock()
    mock_alchemy.get_normal_transactions.side_effect = AlchemyRateLimitError("quota")

    client = DualBackendClient(etherscan=mock_etherscan, alchemy=mock_alchemy)
    rows = client.get_normal_transactions("0xabc", start_block=0, max_results=100)

    assert rows == [{"hash": "0xfallback"}]
    mock_alchemy.get_normal_transactions.assert_called_once()
    mock_etherscan.get_normal_transactions.assert_called_once()


def test_dual_backend_fallback_on_alchemy_generic_error() -> None:
    """Same fallback semantics on non-rate-limit AlchemyError."""
    from recupero.chains.evm.alchemy_client import AlchemyError
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    mock_etherscan = MagicMock()
    mock_etherscan.get_erc20_transfers.return_value = [{"hash": "0xerc"}]
    mock_alchemy = MagicMock()
    mock_alchemy.get_erc20_transfers.side_effect = AlchemyError("bad json")

    client = DualBackendClient(etherscan=mock_etherscan, alchemy=mock_alchemy)
    rows = client.get_erc20_transfers("0xabc", start_block=0, max_results=100)

    assert rows == [{"hash": "0xerc"}]


def test_dual_backend_passthrough_methods_use_etherscan() -> None:
    """Non-account-transfer methods (block_by_time, contract_source,
    etc.) MUST route through Etherscan via __getattr__. Otherwise
    EvmAdapter.is_contract / block_at_or_before silently break under
    --prefer-alchemy."""
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    mock_etherscan = MagicMock()
    mock_etherscan.get_block_number_by_time.return_value = 99999
    mock_etherscan.get_contract_source.return_value = {"ContractName": "Foo"}
    mock_alchemy = MagicMock()

    client = DualBackendClient(etherscan=mock_etherscan, alchemy=mock_alchemy)

    assert client.get_block_number_by_time(1234567890, closest="before") == 99999
    assert client.get_contract_source("0xabc") == {"ContractName": "Foo"}
    # Alchemy mock was never called for these
    assert not mock_alchemy.get_block_number_by_time.called
    assert not mock_alchemy.get_contract_source.called


def test_dual_backend_close_releases_both() -> None:
    """close() must release both underlying clients (httpx connection
    pools are precious and leaking them surfaces as the same FD-
    exhaustion bug v0.17.4 hit in the cross-chain continuation pass)."""
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    mock_etherscan = MagicMock()
    mock_alchemy = MagicMock()
    client = DualBackendClient(etherscan=mock_etherscan, alchemy=mock_alchemy)
    client.close()
    mock_etherscan.close.assert_called_once()
    mock_alchemy.close.assert_called_once()


def test_normalize_erc20_missing_decimal_does_not_silently_emit_zero() -> None:
    """RIGOR-Jacob D adversarial: when rawContract.decimal is absent
    or unparseable, the normalizer MUST NOT silently emit
    tokenDecimal="0".

    The EVM adapter's _normalize_erc20 treats tokenDecimal as
    authoritative — accepting 0 would silently inflate amounts by
    10^N (USDT/USDC have 6 decimals; treating them as 0 would 10^6×
    every transfer). Etherscan returns "" for unenriched tokens; that
    sentinel causes the EVM adapter to raise+log+skip. Alchemy
    normalize MUST match the same sentinel behavior.
    """
    from recupero.chains.evm.alchemy_client import AlchemyClient

    bad_decimal_rows = [
        # No decimal field at all
        {
            "blockNum": "0x1", "hash": "0xa",
            "from": "0xA", "to": "0xB", "value": 1.0,
            "asset": "TKN", "category": "erc20",
            "rawContract": {
                "address": "0xCONTRACT",
                "value": "0x1",
                # decimal: omitted
            },
            "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
        },
        # Non-hex, non-numeric string
        {
            "blockNum": "0x1", "hash": "0xb",
            "from": "0xA", "to": "0xB", "value": 1.0,
            "asset": "TKN", "category": "erc20",
            "rawContract": {
                "address": "0xCONTRACT",
                "value": "0x1",
                "decimal": "garbage",
            },
            "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
        },
        # decimal is None (Alchemy occasionally emits this)
        {
            "blockNum": "0x1", "hash": "0xc",
            "from": "0xA", "to": "0xB", "value": 1.0,
            "asset": "TKN", "category": "erc20",
            "rawContract": {
                "address": "0xCONTRACT",
                "value": "0x1",
                "decimal": None,
            },
            "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
        },
    ]

    for row in bad_decimal_rows:
        out = AlchemyClient._normalize_erc20_to_etherscan(row)
        # Must NOT be "0" — Etherscan uses "" as the missing-sentinel
        # which the EVM adapter raises on. Either "" or absence of the
        # key is acceptable; "0" silently corrupts.
        td = out.get("tokenDecimal", "")
        assert td != "0", (
            f"row {row['hash']!r}: tokenDecimal silently set to '0' on "
            f"missing decimal — this would 10^N-inflate USDT/USDC. "
            f"Use '' to trigger Etherscan-shape skip behavior."
        )


def test_normalize_native_missing_timestamp_does_not_silently_emit_1970() -> None:
    """RIGOR-Jacob D adversarial: a row with no blockTimestamp must
    NOT produce a row that parses to 1970-01-01 downstream.

    _decode_block_time rejects future-dated rows but not past ones —
    if my Alchemy normalize sets timeStamp='0' the EVM adapter would
    accept block_time = 1970-01-01 which would silently end up in
    case.json. Better: emit timeStamp='' so _decode_block_time raises
    and the row is skipped + logged."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    bad_metadata_rows = [
        # No metadata block at all
        {
            "blockNum": "0x1", "hash": "0xa",
            "from": "0xA", "to": "0xB", "value": 0.5,
            "asset": "ETH", "category": "external",
            "rawContract": {"address": None, "value": "0x1", "decimal": "0x12"},
        },
        # metadata present but blockTimestamp missing
        {
            "blockNum": "0x1", "hash": "0xb",
            "from": "0xA", "to": "0xB", "value": 0.5,
            "asset": "ETH", "category": "external",
            "rawContract": {"address": None, "value": "0x1", "decimal": "0x12"},
            "metadata": {},
        },
        # blockTimestamp is unparseable
        {
            "blockNum": "0x1", "hash": "0xc",
            "from": "0xA", "to": "0xB", "value": 0.5,
            "asset": "ETH", "category": "external",
            "rawContract": {"address": None, "value": "0x1", "decimal": "0x12"},
            "metadata": {"blockTimestamp": "not-a-date"},
        },
    ]

    for row in bad_metadata_rows:
        out = AlchemyClient._normalize_external_to_etherscan(row)
        ts = out.get("timeStamp", "")
        # Must NOT be "0" — that decodes to 1970-01-01.
        assert ts != "0", (
            f"row {row['hash']!r}: timeStamp silently set to '0' which "
            f"decodes to 1970-01-01 in the EVM adapter — the row would "
            f"land in case.json with a 55-year-old block_time."
        )


def test_normalize_external_missing_to_yields_skippable_row() -> None:
    """Contract-creation transactions have to=null on Etherscan; the
    EVM adapter's _keep() function filters these via 'if not to_l or
    to_l == "0x": return False'. My Alchemy normalize must produce a
    to-field that triggers the same skip path."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    row = {
        "blockNum": "0x1", "hash": "0xa",
        "from": "0xA", "to": None,  # contract-creation
        "value": 0.5,
        "asset": "ETH", "category": "external",
        "rawContract": {"address": None, "value": "0x1", "decimal": "0x12"},
        "metadata": {"blockTimestamp": "2025-01-01T00:00:00Z"},
    }
    out = AlchemyClient._normalize_external_to_etherscan(row)
    # Either empty string or "0x" — both trigger _keep's skip path.
    assert out["to"] in ("", "0x"), (
        f"to=None alchemy row produced to={out['to']!r}; expected '' or "
        f"'0x' so _keep() filters it. Otherwise to_checksum_address('') "
        f"raises during normalization."
    )


def test_pagination_handles_non_list_transfers_field() -> None:
    """RIGOR-Jacob D adversarial: if Alchemy returns
    ``{"result": {"transfers": "garbage"}}`` (string instead of list),
    the previous code did ``all_rows.extend("garbage")`` which adds
    each CHAR ('g', 'a', 'r', ...) as a "transfer". Catastrophic
    failure shape — every row would then crash the normalizer when
    accessed as a dict.

    Hardened behavior: reject non-list ``transfers`` field and stop
    pagination silently."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    client = AlchemyClient.__new__(AlchemyClient)
    client._ALCHEMY_MAX_PAGE_SIZE = 1000
    client._ALCHEMY_MAX_PAGES = 20

    def fake_rpc(method, params):
        return {"transfers": "not-a-list-but-truthy-string"}

    client._rpc = fake_rpc  # type: ignore[attr-defined]

    rows = client._get_asset_transfers(
        from_address="0xabc", to_address=None,
        category=["external"],
        from_block_hex="0x0",
        max_results=None,
    )
    assert rows == [], (
        f"Non-list transfers field should yield empty result, got: "
        f"{rows[:5]} (len={len(rows)})"
    )


def test_pagination_handles_null_transfers_field() -> None:
    """Defensive: ``{"transfers": null}`` should yield empty list, not
    crash on .extend(None)."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    client = AlchemyClient.__new__(AlchemyClient)
    client._ALCHEMY_MAX_PAGE_SIZE = 1000
    client._ALCHEMY_MAX_PAGES = 20

    def fake_rpc(method, params):
        return {"transfers": None, "pageKey": None}

    client._rpc = fake_rpc  # type: ignore[attr-defined]

    rows = client._get_asset_transfers(
        from_address="0xabc", to_address=None,
        category=["external"],
        from_block_hex="0x0",
        max_results=None,
    )
    assert rows == []


def test_alchemy_client_max_results_breaks_pagination() -> None:
    """The Alchemy paginator must honor max_results — same contract
    as the Etherscan paginator (locked in test_max_transfers_cap_fetch_layer)."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    client = AlchemyClient.__new__(AlchemyClient)
    client._ALCHEMY_MAX_PAGE_SIZE = 1000
    client._ALCHEMY_MAX_PAGES = 20

    rpc_calls = {"n": 0}

    def fake_rpc(method, params):
        rpc_calls["n"] += 1
        # Always return 500 rows + a pageKey so we'd keep paginating
        # without the cap.
        return {
            "transfers": [{"hash": f"0x{i:064x}"} for i in range(500)],
            "pageKey": "next-page",
        }

    client._rpc = fake_rpc  # type: ignore[attr-defined]

    rows = client._get_asset_transfers(
        from_address="0xabc", to_address=None,
        category=["external"],
        from_block_hex="0x0",
        max_results=500,
    )

    # 500 rows after 1 call — should stop immediately.
    assert rpc_calls["n"] == 1
    assert len(rows) == 500
