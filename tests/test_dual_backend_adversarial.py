"""Adversarial-input audit of DualBackendClient + AlchemyClient.

These tests prove specific failure modes that bypass the existing
fallback machinery and either hang the worker, corrupt the row stream,
or burn the per-call cap:

  1. Malformed JSON from a 200 response → ``resp.json()`` raises
     ``json.JSONDecodeError`` (a ``ValueError``) that is NOT caught
     by ``_rpc``'s ``httpx.HTTPError`` handler and is NOT wrapped to
     ``AlchemyError``. The exception bubbles unwrapped and the
     ``_alchemy_or_fallback`` wrapper never falls through to Etherscan
     — the worker crashes.
  2. Stuck pageKey: if Alchemy returns the SAME ``pageKey`` twice in
     a row, the loop has no break condition. We waste the full
     ``_ALCHEMY_MAX_PAGES`` budget AND emit ``maxCount*maxPages =
     20,000`` duplicated rows. Hardened behavior: break on repeated
     pageKey.
  3. DualBackendClient.build does not propagate ``requests_per_second``
     to the Alchemy client — Alchemy always gets the 2.0 default
     regardless of operator config. (Documented behavior; not all
     callers expect this — locking it is a regression net.)

All tests are mocked at the ``_rpc`` boundary; no network is
exercised.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# ---------- Bug 1: malformed JSON bubbles unwrapped ----------


def test_alchemy_rpc_wraps_json_decode_error_as_alchemy_error() -> None:
    """A 200 OK with non-JSON body (Alchemy's edge proxy can serve an
    HTML error page during incidents) must not bubble an unwrapped
    ``ValueError`` / ``json.JSONDecodeError`` past ``_rpc``.

    The DualBackend fallback only catches ``AlchemyError`` /
    ``AlchemyRateLimitError`` — anything else propagates and kills the
    worker. Wrap parse failures as ``AlchemyError`` so the fallback
    triggers.
    """
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
    )

    client = AlchemyClient.__new__(AlchemyClient)
    client.api_url = "http://test"

    class _FakeLimiter:
        def wait(self) -> None:
            pass

    client.limiter = _FakeLimiter()

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.text = "<html>503 Service Unavailable</html>"
    fake_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
    client._client = MagicMock()
    client._client.post.return_value = fake_resp

    with pytest.raises(AlchemyError):
        client._rpc("alchemy_getAssetTransfers", [{}])


def test_dual_backend_falls_back_on_malformed_json() -> None:
    """End-to-end: when Alchemy returns malformed JSON, the dual-backend
    wrapper must fall back to Etherscan, not propagate the parse error.

    Without the wrap-as-AlchemyError fix above, this test fails because
    ``_alchemy_or_fallback`` only catches AlchemyError variants.
    """
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
    )
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    # Build a real AlchemyClient with a mocked transport that returns
    # garbage JSON.
    alchemy = AlchemyClient.__new__(AlchemyClient)
    alchemy.api_url = "http://test"

    class _FakeLimiter:
        def wait(self) -> None:
            pass

    alchemy.limiter = _FakeLimiter()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.text = "garbage"
    fake_resp.json.side_effect = ValueError("not json")
    alchemy._client = MagicMock()
    alchemy._client.post.return_value = fake_resp

    mock_etherscan = MagicMock()
    mock_etherscan.get_normal_transactions.return_value = [{"hash": "0xfallback"}]

    client = DualBackendClient(etherscan=mock_etherscan, alchemy=alchemy)
    # If the bug exists, this raises ValueError; after the fix it
    # falls back cleanly.
    try:
        rows = client.get_normal_transactions("0xabc", start_block=0)
    except ValueError as e:
        pytest.fail(
            f"DualBackendClient leaked a raw ValueError instead of "
            f"falling back to Etherscan: {e}"
        )
    except AlchemyError as e:
        pytest.fail(
            f"DualBackendClient leaked AlchemyError instead of "
            f"falling back to Etherscan: {e}"
        )
    assert rows == [{"hash": "0xfallback"}]
    mock_etherscan.get_normal_transactions.assert_called_once()


# ---------- Bug 2: stuck pageKey duplicates rows ----------


def test_pagination_breaks_on_repeated_page_key() -> None:
    """RIGOR-Jacob D adversarial: if the upstream returns the SAME
    pageKey twice in a row, the paginator must break — not loop the
    full _ALCHEMY_MAX_PAGES budget emitting the same N rows 20×.

    Stuck-cursor failure shape: a single 1k-row page gets emitted 20
    times, producing 20k rows that the downstream dedupe by tx hash
    must then absorb. Wastes ~3k CU and trips the per-call cap.
    """
    from recupero.chains.evm.alchemy_client import AlchemyClient

    client = AlchemyClient.__new__(AlchemyClient)
    client._ALCHEMY_MAX_PAGE_SIZE = 1000
    client._ALCHEMY_MAX_PAGES = 20

    rpc_calls = {"n": 0}

    def fake_rpc(method, params):
        rpc_calls["n"] += 1
        # ALWAYS returns the same pageKey — a stuck cursor.
        return {
            "transfers": [{"hash": f"0x{i:064x}"} for i in range(3)],
            "pageKey": "stuck-cursor-abc123",
        }

    client._rpc = fake_rpc  # type: ignore[attr-defined]

    rows = client._get_asset_transfers(
        from_address="0xabc",
        to_address=None,
        category=["external"],
        from_block_hex="0x0",
        max_results=None,
    )

    # The paginator must detect the stuck cursor by the THIRD call
    # at the latest (one initial call + at most one repeat before
    # detection). Critically, it must NOT burn the full
    # ``_ALCHEMY_MAX_PAGES`` budget. Pre-fix this was 20 calls + 60
    # duplicate rows; post-fix ≤ 2 calls + ≤ 6 rows.
    assert rpc_calls["n"] <= 2, (
        f"stuck-cursor not detected — paginator made {rpc_calls['n']} "
        f"calls before bailing (expected ≤ 2). This wastes the full "
        f"page budget on a repeating cursor."
    )
    assert len(rows) <= 6, (
        f"stuck-cursor emitted {len(rows)} rows — the same page was "
        f"concatenated through the full _ALCHEMY_MAX_PAGES budget."
    )


# ---------- Bug 3: timeout / rps propagation ----------


def test_dual_backend_build_propagates_timeout_to_alchemy() -> None:
    """A hung Alchemy connection must time out — the operator's
    ``timeout_seconds`` argument should configure the Alchemy httpx
    client, not be silently dropped.

    Pre-fix this might pass already (timeout IS passed through), but
    we lock it so a future refactor that drops the kwarg surfaces as
    a test failure rather than a worker hang.
    """
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    result = DualBackendClient.build(
        etherscan_api_key="fake_es_key",
        etherscan_api_base="https://api.etherscan.io/v2/api",
        chain_id=1,
        alchemy_api_key="fake_al_key",
        timeout_seconds=12.5,
        prefer_alchemy=True,
    )
    assert isinstance(result, DualBackendClient)
    assert result.alchemy is not None
    # httpx.Client.timeout is a Timeout instance; .read holds the value.
    timeout = result.alchemy._client.timeout
    # httpx.Timeout(12.5) — verify any of the per-op timeouts matches.
    timeout_val = getattr(timeout, "read", None) or getattr(timeout, "connect", None)
    assert timeout_val == 12.5, (
        f"timeout_seconds=12.5 was not propagated to the Alchemy "
        f"httpx client (got {timeout!r}). A hung request would block "
        f"the worker forever on the default."
    )


# ---------- JSON-RPC error mapping ----------


def test_rpc_invalid_params_error_raises_alchemy_error_not_silent() -> None:
    """JSON-RPC code -32602 (invalid params) must raise AlchemyError —
    NOT AlchemyRateLimitError. The distinction matters:
      * RateLimitError → operator sees "alchemy quota exhausted"
      * Error          → operator sees "alchemy rejected our params"
    Misclassifying -32602 as a rate-limit hides a programming bug
    behind a fallback warning."""
    from recupero.chains.evm.alchemy_client import (
        AlchemyClient,
        AlchemyError,
        AlchemyRateLimitError,
    )

    client = AlchemyClient.__new__(AlchemyClient)
    client.api_url = "http://test"

    class _FakeLimiter:
        def wait(self) -> None:
            pass

    client.limiter = _FakeLimiter()

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32602, "message": "invalid params: bad fromAddress"},
    }
    client._client = MagicMock()
    client._client.post.return_value = fake_resp

    with pytest.raises(AlchemyError) as exc_info:
        client._rpc("alchemy_getAssetTransfers", [{}])
    # Must NOT be misclassified as a rate-limit
    assert not isinstance(exc_info.value, AlchemyRateLimitError)


# ---------- Pagination max_results threading ----------


def test_dual_backend_threads_max_results_to_alchemy() -> None:
    """max_results must propagate through DualBackendClient to the
    underlying Alchemy method. A drop here means the operator's
    ``--max-transfers-per-account`` cap is ignored on the Alchemy path
    and the worker fetches the full 20k-row safety ceiling."""
    from recupero.chains.evm.dual_backend_client import DualBackendClient

    mock_etherscan = MagicMock()
    mock_alchemy = MagicMock()
    mock_alchemy.get_erc20_transfers.return_value = [{"hash": "0xa"}]

    client = DualBackendClient(etherscan=mock_etherscan, alchemy=mock_alchemy)
    client.get_erc20_transfers("0xabc", start_block=0, max_results=42)

    _args, kwargs = mock_alchemy.get_erc20_transfers.call_args
    assert kwargs.get("max_results") == 42, (
        f"max_results=42 was not threaded to Alchemy "
        f"(call: args={_args!r} kwargs={kwargs!r}). The fetch-layer "
        f"cap would be silently ignored."
    )


# ---------- Empty result handling ----------


def test_pagination_handles_non_dict_result() -> None:
    """If ``_rpc`` returns a non-dict result (e.g., None on a
    well-formed JSON-RPC response with ``result: null``), pagination
    must not crash on ``result.get(...)``."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    client = AlchemyClient.__new__(AlchemyClient)
    client._ALCHEMY_MAX_PAGE_SIZE = 1000
    client._ALCHEMY_MAX_PAGES = 20

    def fake_rpc(method, params):
        return None

    client._rpc = fake_rpc  # type: ignore[attr-defined]

    rows = client._get_asset_transfers(
        from_address="0xabc",
        to_address=None,
        category=["external"],
        from_block_hex="0x0",
        max_results=None,
    )
    assert rows == []
