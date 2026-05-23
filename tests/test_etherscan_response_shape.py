"""RIGOR-Jacob U: harden Etherscan _call against non-dict responses.

``_call`` returns ``resp.json()`` after checking
``isinstance(data, dict) and data.get("status") == "0"``. If the
response is not a dict at all (Cloudflare HTML error, JSON array),
the function returns the raw value and the downstream
``_coerce_list(data)`` crashes on ``data.get("result", [])``
with AttributeError.

This kills the BFS hop. Lock the contract: ``_call`` raises
``EtherscanError`` on non-dict responses.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _build_client():
    """Bypass __init__ — minimal EtherscanClient shell."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = EtherscanClient.__new__(EtherscanClient)
    client.api_key = "fake"
    client.api_base = "https://fake-etherscan/api"
    client.chain_id = 1
    client._client = MagicMock()
    client.limiter = MagicMock()
    client.limiter.wait = lambda: None
    return client


def test_call_list_response_does_not_crash_coerce_list() -> None:
    """A JSON array response (instead of dict) crashes _coerce_list
    on ``.get(...)``. Either _call rejects up-front or _coerce_list
    handles non-dict input."""
    from recupero.chains.ethereum.etherscan import (
        EtherscanClient,
        EtherscanError,
    )

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = ["unexpected", "list"]
    client._client.get.return_value = fake_resp

    try:
        data = client._call(module="account", action="txlist", address="0xabc")
    except EtherscanError:
        return  # documented behavior — acceptable
    except AttributeError as e:
        raise AssertionError(
            f"_call returned non-dict; would crash _coerce_list: {e}"
        ) from e

    # If _call returned the data, _coerce_list MUST handle it.
    try:
        result = EtherscanClient._coerce_list(data)
    except AttributeError as e:
        raise AssertionError(
            f"_coerce_list crashed on non-dict input: {e}"
        ) from e
    assert isinstance(result, list)


def test_coerce_list_handles_non_dict_input_gracefully() -> None:
    """_coerce_list must accept any input and return a list. Pre-fix
    a list/string/None input crashed with AttributeError on .get()."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    for bad in ([1, 2, 3], "string", None, 42, True):
        try:
            result = EtherscanClient._coerce_list(bad)  # type: ignore[arg-type]
        except (AttributeError, TypeError) as e:
            raise AssertionError(
                f"_coerce_list({bad!r}) crashed: {e}"
            ) from e
        assert isinstance(result, list)


def test_call_string_response_does_not_crash() -> None:
    """A string response (e.g., Cloudflare HTML interpreted as
    JSON literal) must not crash."""
    from recupero.chains.ethereum.etherscan import (
        EtherscanClient,
        EtherscanError,
    )

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = "rate limit exceeded"
    client._client.get.return_value = fake_resp

    try:
        data = client._call(module="account", action="txlist", address="0xabc")
    except EtherscanError:
        return
    except (AttributeError, TypeError) as e:
        raise AssertionError(
            f"_call crashed on string response: {e}"
        ) from e
    # Pass-through is OK as long as _coerce_list handles it.
    EtherscanClient._coerce_list(data)


def test_normal_dict_response_passes() -> None:
    """Sanity: a normal dict response with status='1' passes through."""
    from recupero.chains.ethereum.etherscan import EtherscanClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "status": "1", "message": "OK",
        "result": [{"hash": "0xabc"}],
    }
    client._client.get.return_value = fake_resp

    data = client._call(module="account", action="txlist", address="0xabc")
    assert data["status"] == "1"
    rows = EtherscanClient._coerce_list(data)
    assert rows == [{"hash": "0xabc"}]
