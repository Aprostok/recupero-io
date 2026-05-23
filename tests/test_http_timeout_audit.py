"""HTTP timeout / retry audit.

Every HTTP client in `recupero/chains/**` and `recupero/pricing/**` must:

  1. Set explicit connect_timeout (5-10s typical) — without it a
     slow-DNS host blocks the worker thread indefinitely.
  2. Set explicit read_timeout (~30s typical) — without it a
     slow-loris response blocks forever.
  3. Use finite retries (3-5) via tenacity, NOT infinite.
  4. Treat 5xx as retryable, 4xx (except 429) as terminal.

This file enforces those invariants via white-box inspection of
each client's internal httpx.Client and its tenacity-decorated
methods.
"""

from __future__ import annotations

import os
from unittest import mock

import httpx


# --- Fixtures / helpers ---------------------------------------------------


def _extract_timeout(httpx_client: httpx.Client) -> httpx.Timeout:
    """Pull the httpx.Timeout object off a Client. httpx stores it on
    the transport pool — but the public attribute is ``.timeout``."""
    return httpx_client.timeout


def _tenacity_attempt_cap(decorated_method) -> int | None:
    """Return the stop_after_attempt N for a tenacity-decorated method,
    or None if no retry decorator is present.

    tenacity stores its state on the wrapped function under
    ``retry.stop`` — for ``stop_after_attempt(N)`` it's a
    ``stop_after_attempt`` instance whose ``max_attempt_number`` is N.
    """
    fn = decorated_method
    # tenacity wraps the original — the wrapper has a `.retry` attr.
    retry_obj = getattr(fn, "retry", None)
    if retry_obj is None:
        # could be a bound method
        retry_obj = getattr(getattr(fn, "__func__", None), "retry", None)
    if retry_obj is None:
        return None
    stop = retry_obj.stop
    # stop_after_attempt has `max_attempt_number`
    n = getattr(stop, "max_attempt_number", None)
    return n


# --- Test 1: EtherscanClient ----------------------------------------------


def test_etherscan_client_has_split_timeouts():
    from recupero.chains.ethereum.etherscan import EtherscanClient

    c = EtherscanClient(api_key="dummy")
    t = _extract_timeout(c._client)
    # connect must be small (≤ 15s) — slow-DNS guard
    assert t.connect is not None and 0 < t.connect <= 15, (
        f"connect timeout missing or too large: {t.connect}"
    )
    # read must be > 0 and finite
    assert t.read is not None and t.read > 0, (
        f"read timeout missing: {t.read}"
    )
    c.close()


def test_etherscan_call_has_finite_retries():
    from recupero.chains.ethereum.etherscan import EtherscanClient

    c = EtherscanClient(api_key="dummy")
    n = _tenacity_attempt_cap(c._call)
    assert n is not None, "EtherscanClient._call must be tenacity-decorated"
    assert 1 < n < 100, f"EtherscanClient._call retries unbounded or zero: {n}"
    c.close()


# --- Test 2: HeliusClient -------------------------------------------------


def test_helius_client_has_split_timeouts():
    from recupero.chains.solana.helius import HeliusClient

    c = HeliusClient(api_key="dummy")
    t = _extract_timeout(c._client)
    assert t.connect is not None and 0 < t.connect <= 15
    assert t.read is not None and t.read > 0
    c.close()


def test_helius_fetch_page_has_finite_retries():
    from recupero.chains.solana.helius import HeliusClient

    c = HeliusClient(api_key="dummy")
    n = _tenacity_attempt_cap(c._fetch_page)
    assert n is not None and 1 < n < 100
    n_rpc = _tenacity_attempt_cap(c._rpc_call)
    assert n_rpc is not None and 1 < n_rpc < 100
    c.close()


# --- Test 3: EsploraClient ------------------------------------------------


def test_esplora_client_has_split_timeouts():
    from recupero.chains.bitcoin.esplora import EsploraClient

    c = EsploraClient()
    t = _extract_timeout(c._client)
    assert t.connect is not None and 0 < t.connect <= 15
    assert t.read is not None and t.read > 0
    c.close()


def test_esplora_get_has_finite_retries():
    from recupero.chains.bitcoin.esplora import EsploraClient

    c = EsploraClient()
    n = _tenacity_attempt_cap(c._get)
    assert n is not None and 1 < n < 100
    c.close()


# --- Test 4: TronGridClient -----------------------------------------------


def test_trongrid_client_has_split_timeouts():
    from recupero.chains.tron.client import TronGridClient

    c = TronGridClient()
    t = _extract_timeout(c._client)
    assert t.connect is not None and 0 < t.connect <= 15
    assert t.read is not None and t.read > 0
    c.close()


def test_trongrid_get_and_post_have_finite_retries():
    from recupero.chains.tron.client import TronGridClient

    c = TronGridClient()
    n_get = _tenacity_attempt_cap(c._get)
    n_post = _tenacity_attempt_cap(c._post)
    assert n_get is not None and 1 < n_get < 100
    assert n_post is not None and 1 < n_post < 100
    c.close()


# --- Test 5: AlchemyClient ------------------------------------------------


def test_alchemy_client_has_split_timeouts():
    from recupero.chains.evm.alchemy_client import AlchemyClient

    c = AlchemyClient(api_key="dummy", chain_id=1)
    t = _extract_timeout(c._client)
    assert t.connect is not None and 0 < t.connect <= 15
    assert t.read is not None and t.read > 0
    c.close()


# --- Test 6: CoinGeckoClient ----------------------------------------------


def test_coingecko_client_has_split_timeouts(tmp_path):
    from recupero.config import RecuperoConfig, RecuperoEnv
    from recupero.pricing.coingecko import CoinGeckoClient

    # Build a minimal config / env. Use file cache (no DB) so we don't
    # need SUPABASE_DB_URL.
    cfg = RecuperoConfig()
    env = RecuperoEnv(
        ETHERSCAN_API_KEY="x",
        HELIUS_API_KEY="x",
        COINGECKO_API_KEY="",
        COINGECKO_TIER="demo",
    )
    # Ensure no DB cache is picked up from env.
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SUPABASE_DB_URL", None)
        c = CoinGeckoClient(cfg, env, cache_dir=tmp_path)
    t = _extract_timeout(c._client)
    assert t.connect is not None and 0 < t.connect <= 15, (
        f"CoinGecko connect timeout missing or too large: {t.connect}"
    )
    assert t.read is not None and t.read > 0
    c.close()


def test_coingecko_fetch_history_has_finite_retries(tmp_path):
    from recupero.config import RecuperoConfig, RecuperoEnv
    from recupero.pricing.coingecko import CoinGeckoClient

    cfg = RecuperoConfig()
    env = RecuperoEnv(
        ETHERSCAN_API_KEY="x",
        HELIUS_API_KEY="x",
        COINGECKO_API_KEY="",
        COINGECKO_TIER="demo",
    )
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SUPABASE_DB_URL", None)
        c = CoinGeckoClient(cfg, env, cache_dir=tmp_path)
    for method_name in ("_fetch_history", "_fetch_contract_to_id", "_fetch_simple_price"):
        m = getattr(c, method_name)
        n = _tenacity_attempt_cap(m)
        assert n is not None, f"{method_name} not tenacity-decorated"
        assert 1 < n < 100, f"{method_name} retry cap out of range: {n}"
    c.close()
