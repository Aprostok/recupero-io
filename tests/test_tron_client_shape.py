"""RIGOR-Jacob Z14: harden TronGridClient._get against list-shape responses.

Bug: ``_get`` is typed ``-> dict[str, Any]`` but returns whatever
``resp.json()`` parses. If a misbehaving TronGrid mirror or CDN
returns a top-level JSON list (e.g. cached error array, partial-JSON
recovery), the caller ``body.get("data")`` in
``get_trc20_transfers`` raises ``AttributeError: 'list' object has
no attribute 'get'`` and kills the trace branch.

Symmetric to the v0.18.5 work done on _fetch_page / _rpc_call in
the Helius client — same shape bug, different chain.
"""

from __future__ import annotations

import httpx
import respx

from recupero.chains.tron.client import (
    TRONGRID_BASE_MAINNET,
    TronGridClient,
    TronGridError,
)


def _new_client() -> TronGridClient:
    return TronGridClient(requests_per_second=10_000.0)


@respx.mock
def test_get_list_top_level_raises_tron_grid_error_in_account() -> None:
    """A list-shape top-level response on get_account must raise
    TronGridError, NOT propagate AttributeError into the adapter."""
    client = _new_client()
    addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}"
    ).mock(return_value=httpx.Response(200, json=["unexpected", "list"]))

    try:
        client.get_account(addr)
    except TronGridError:
        return
    except AttributeError as e:
        raise AssertionError(
            f"TronGrid _get returned a list to caller; "
            f".get('Error') raised AttributeError. Got: {e}"
        ) from e
    raise AssertionError("get_account silently accepted non-dict body")


@respx.mock
def test_trc20_transfers_list_top_level_raises_cleanly() -> None:
    """A list-shape top-level response on the TRC-20 endpoint must
    raise TronGridError instead of AttributeError downstream."""
    client = _new_client()
    addr = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
    respx.get(
        f"{TRONGRID_BASE_MAINNET}/v1/accounts/{addr}/transactions/trc20"
    ).mock(return_value=httpx.Response(200, json=["weird", "list"]))

    try:
        client.get_trc20_transfers(addr)
    except TronGridError:
        return
    except AttributeError as e:
        raise AssertionError(
            f"get_trc20_transfers leaked AttributeError on list-shape body: {e}"
        ) from e
    raise AssertionError("get_trc20_transfers silently accepted list body")
