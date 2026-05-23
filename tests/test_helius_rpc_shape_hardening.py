"""RIGOR-Jacob R: harden Helius _rpc_call against malformed responses.

The Helius JSON-RPC endpoint returns a dict on success but can
return a string (HTML error page), a list, or a non-dict JSON on
upstream failure. ``_rpc_call`` returns ``resp.json()`` verbatim;
callers like ``get_account_info`` then do ``data.get("result", {})``
which crashes with ``AttributeError`` on non-dict responses.

The Solana adapter's ``is_contract`` calls ``get_account_info`` for
every traced address. A single bad RPC response from Helius (e.g.,
an HTML 502 page from a Cloudflare incident) crashes the entire
BFS hop.

Lock the contract: ``_rpc_call`` MUST return a dict, raising
``HeliusError`` if the response isn't shape-correct.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _build_client():
    """Bypass __init__ — minimal HeliusClient shell."""
    from recupero.chains.solana.helius import HeliusClient

    client = HeliusClient.__new__(HeliusClient)
    client._client = MagicMock()
    client.api_key = "fake"
    client.RPC = "https://fake-rpc"
    client.limiter = MagicMock()
    client.limiter.wait = lambda: None
    return client


def test_rpc_call_list_response_raises_clean_error() -> None:
    """A list-shape JSON response must produce HeliusError, NOT
    propagate AttributeError into the adapter."""
    from recupero.chains.solana.helius import HeliusClient, HeliusError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = ["unexpected", "list", "shape"]
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        result = fn(client, "getAccountInfo", ["addr"])
    except HeliusError:
        return  # documented contract
    except AttributeError as e:
        raise AssertionError(
            f"_rpc_call returned a non-dict ({type(result).__name__}); "
            f"downstream get_account_info would AttributeError on .get(). "
            f"Raise HeliusError instead. Got: {e}"
        ) from e
    raise AssertionError(
        f"_rpc_call silently returned non-dict: {result!r}"
    )


def test_rpc_call_string_response_raises_clean_error() -> None:
    """An HTML / string response (Cloudflare error page) must raise."""
    from recupero.chains.solana.helius import HeliusClient, HeliusError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = "<html>cloudflare error</html>"
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        result = fn(client, "getAccountInfo", ["addr"])
    except HeliusError:
        return
    raise AssertionError(
        f"_rpc_call silently returned a string: {result!r}"
    )


def test_rpc_call_dict_response_passes_through() -> None:
    """Sanity: well-formed dict response passes through."""
    from recupero.chains.solana.helius import HeliusClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "jsonrpc": "2.0", "id": 1,
        "result": {"value": {"executable": False}},
    }
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    result = fn(client, "getAccountInfo", ["addr"])
    assert isinstance(result, dict)
    assert result["result"]["value"]["executable"] is False
