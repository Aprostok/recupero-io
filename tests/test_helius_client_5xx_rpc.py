"""RIGOR-Jacob Z14: harden Helius _rpc_call against 5xx upstream errors.

Bug: ``_rpc_call`` only catches ``status_code == 429`` then calls
``resp.raise_for_status()``. A transient 502/503/504 from
mainnet.helius-rpc.com (Cloudflare incident, capacity bounce, AWS
region rotation) raises ``httpx.HTTPStatusError`` — which is NOT in
the retry decorator's allow-list (HeliusRateLimitError, TransportError).

``_fetch_page`` correctly classifies 5xx as retryable (line 191-194
with the v0.18.5 chains-CRIT-004 comment). The exact same fix was
missed for ``_rpc_call`` — the JSON-RPC endpoint is a different host
(mainnet.helius-rpc.com vs api.helius.xyz), so an outage of just the
RPC tier silently bypasses retry and kills the entire Solana trace.

Concrete trigger: Cloudflare returns 503 from mainnet.helius-rpc.com
during a regional incident. ``get_account_info`` raises
``httpx.HTTPStatusError`` which propagates up, terminating the BFS hop.
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


def test_rpc_call_503_raises_retryable_error() -> None:
    """A 503 from the RPC endpoint must raise HeliusRateLimitError
    (retryable), not bare httpx.HTTPStatusError that breaks the trace.

    This mirrors the v0.18.5 fix already shipped for _fetch_page —
    just propagated to _rpc_call which has the same code path but
    lacked the 5xx guard.
    """
    from recupero.chains.solana.helius import HeliusClient, HeliusRateLimitError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 503
    fake_resp.text = "upstream timeout"
    # raise_for_status would raise httpx.HTTPStatusError on a real response
    import httpx
    fake_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "503", request=MagicMock(), response=fake_resp,
    )
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        fn(client, "getAccountInfo", ["addr"])
    except HeliusRateLimitError:
        return  # documented contract — retryable
    except httpx.HTTPStatusError as e:
        raise AssertionError(
            f"_rpc_call should classify 5xx as retryable "
            f"(HeliusRateLimitError) so tenacity retries, but raised raw "
            f"httpx.HTTPStatusError: {e}"
        ) from e
    raise AssertionError("_rpc_call silently swallowed 503")


def test_rpc_call_502_raises_retryable_error() -> None:
    """Same contract for 502."""
    from recupero.chains.solana.helius import HeliusClient, HeliusRateLimitError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 502
    fake_resp.text = "bad gateway"
    import httpx
    fake_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "502", request=MagicMock(), response=fake_resp,
    )
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        fn(client, "getAccountInfo", ["addr"])
    except HeliusRateLimitError:
        return
    raise AssertionError("_rpc_call did not classify 502 as retryable")


def test_rpc_call_401_raises_non_retryable() -> None:
    """401 (bad API key) must NOT loop forever — non-retryable."""
    from recupero.chains.solana.helius import HeliusClient, HeliusError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 401
    fake_resp.text = "unauthorized"
    import httpx
    fake_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "401", request=MagicMock(), response=fake_resp,
    )
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        fn(client, "getAccountInfo", ["addr"])
    except HeliusError:
        return  # OK — surface as terminal error
    except httpx.HTTPStatusError:
        return  # OK — also terminal (caller handles)
    raise AssertionError("_rpc_call silently swallowed 401")
