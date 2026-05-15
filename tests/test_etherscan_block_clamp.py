"""Unit tests for the pre-genesis block-clamp fix in EtherscanClient.

The original bug:

  * ``get_block_number_by_time(ts_unix)`` called Etherscan's
    ``getblocknobytime`` with ``closest=before``.
  * For timestamps before the chain's first block (e.g., when
    wallet-trace defaults to chain-genesis), Etherscan's API returns
    ``result: "Error! No closest block found"`` as a STRING — not
    an error response.
  * The old code did ``int(data["result"])`` and crashed with
    ``ValueError: invalid literal for int() with base 10``.
  * The tracer caught the exception as a "trace hop failure" and
    returned 0 transfers — a silently misleading "found nothing"
    result on wallets that actually had history.

The fix clamps to block 1 in this case, which is the semantically
correct interpretation: "give me the earliest block before this
timestamp" against a pre-genesis timestamp should return the
earliest block, not crash.

These tests use a tiny stub for ``_call`` to avoid hitting the
real Etherscan API. The HTTP layer is otherwise unchanged so we
don't need to mock httpx.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from recupero.chains.ethereum.etherscan import EtherscanClient


@pytest.fixture
def client() -> EtherscanClient:
    """A real EtherscanClient instance — only _call is stubbed in each
    test, so the rate-limiter / chain_id / API-key plumbing stays real."""
    return EtherscanClient(api_key="test-key-fake")


def test_normal_block_lookup_unchanged(client: EtherscanClient) -> None:
    """Sanity: a normal numeric response still returns the integer."""
    with patch.object(client, "_call", return_value={"result": "12345"}):
        assert client.get_block_number_by_time(1700000000) == 12345


def test_pre_genesis_clamps_to_block_1(client: EtherscanClient) -> None:
    """The exact error string Etherscan returns gets clamped to block 1
    instead of raising ValueError."""
    err_response = {"result": "Error! No closest block found"}
    with patch.object(client, "_call", return_value=err_response):
        assert client.get_block_number_by_time(0) == 1


def test_pre_genesis_case_insensitive_match(client: EtherscanClient) -> None:
    """Etherscan's casing has historically wobbled — match
    case-insensitively so a future API tweak doesn't reintroduce
    the bug."""
    for variant in [
        "Error! No closest block found",
        "Error! NO CLOSEST BLOCK FOUND",
        "no closest block",
        "error! no closest block found",
    ]:
        with patch.object(client, "_call", return_value={"result": variant}):
            assert client.get_block_number_by_time(0) == 1, (
                f"variant {variant!r} should clamp to block 1"
            )


def test_other_error_strings_still_raise(client: EtherscanClient) -> None:
    """Don't accidentally swallow OTHER errors as "no closest block".
    A genuinely-broken response should still surface so the operator
    can investigate."""
    with patch.object(client, "_call", return_value={"result": "Rate limit exceeded"}):
        with pytest.raises(ValueError):
            client.get_block_number_by_time(1700000000)


def test_clamp_works_with_closest_after(client: EtherscanClient) -> None:
    """The clamp behavior is independent of the closest direction —
    closest=after with a pre-genesis timestamp would semantically
    return block 1 anyway."""
    err_response = {"result": "Error! No closest block found"}
    with patch.object(client, "_call", return_value=err_response):
        assert client.get_block_number_by_time(0, closest="after") == 1


def test_block_zero_request_does_not_special_case(client: EtherscanClient) -> None:
    """Block 0 has a null timestamp on Ethereum and the API may legitimately
    return block 0 for some queries. If Etherscan returns "0" we should
    respect that — only the literal error string triggers the clamp."""
    with patch.object(client, "_call", return_value={"result": "0"}):
        # int("0") works fine — no special case needed
        assert client.get_block_number_by_time(1700000000) == 0
