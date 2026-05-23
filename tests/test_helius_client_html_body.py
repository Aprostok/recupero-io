"""RIGOR-Jacob Z14: harden Helius _fetch_page / _rpc_call against
HTML response bodies returned with HTTP 200.

Concrete trigger: Cloudflare in front of api.helius.xyz returns 200
with an HTML "challenge / error" body during a regional incident.
Both ``_fetch_page`` and ``_rpc_call`` call ``resp.json()``
unconditionally on the 200 path; ``resp.json()`` raises
``json.JSONDecodeError`` (a ValueError) which is NOT in the
retry decorator's allow-list — propagates as a raw ValueError that
breaks downstream callers and kills the trace branch.

Fix: catch ValueError on the .json() call and surface as the
documented HeliusError so the adapter's broad-except cleanup runs.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock


def _build_client():
    from recupero.chains.solana.helius import HeliusClient

    client = HeliusClient.__new__(HeliusClient)
    client._client = MagicMock()
    client.api_key = "fake"
    client.BASE = "https://fake-api"
    client.RPC = "https://fake-rpc"
    client.limiter = MagicMock()
    client.limiter.wait = lambda: None
    return client


def test_fetch_page_html_body_raises_helius_error() -> None:
    """200-status with HTML body must produce HeliusError."""
    from recupero.chains.solana.helius import HeliusClient, HeliusError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.text = "<html>Cloudflare error</html>"
    fake_resp.json.side_effect = json.JSONDecodeError("Expecting value", "<html>", 0)
    client._client.get.return_value = fake_resp

    fn = HeliusClient._fetch_page
    fn = getattr(fn, "__wrapped__", fn)
    try:
        fn(client, "addr", limit=10, before=None)
    except HeliusError:
        return
    except ValueError as e:
        raise AssertionError(
            f"_fetch_page leaked JSONDecodeError to caller "
            f"instead of raising HeliusError. Got: {type(e).__name__}: {e}"
        ) from e
    raise AssertionError("_fetch_page silently returned on HTML body")


def test_rpc_call_html_body_raises_helius_error() -> None:
    """Same contract for _rpc_call — HTML response on the RPC tier."""
    from recupero.chains.solana.helius import HeliusClient, HeliusError

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.text = "<html>Cloudflare error</html>"
    fake_resp.json.side_effect = json.JSONDecodeError("Expecting value", "<html>", 0)
    client._client.post.return_value = fake_resp

    fn = HeliusClient._rpc_call
    fn = getattr(fn, "__wrapped__", fn)
    try:
        fn(client, "getAccountInfo", ["addr"])
    except HeliusError:
        return
    except ValueError as e:
        raise AssertionError(
            f"_rpc_call leaked JSONDecodeError to caller. "
            f"Got: {type(e).__name__}: {e}"
        ) from e
    raise AssertionError("_rpc_call silently returned on HTML body")
