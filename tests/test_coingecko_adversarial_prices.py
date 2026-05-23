"""RIGOR-Jacob F adversarial: defend against pathological CoinGecko
responses corrupting case.json USD values.

CoinGecko's API is the source of every USD value in case.json. The
tracer applies a $2B per-transfer sanity ceiling (defense-in-depth),
but the ceiling uses ``abs(value) > 2B`` — which is False for
``Decimal('NaN')`` (NaN comparisons always return False). A
``{"usd": "NaN"}`` response would pass the ceiling and land NaN in
the LE handoff's Section 4 "Total stolen" line.

Same for negative prices. A corrupted cache file or a spoofed
upstream response with ``{"usd": -1.5}`` produces negative dollar
amounts that aren't caught by ANY downstream check; they render in
freeze letters as "-$1,500.00 lost" which is operationally
nonsensical.

Lock the contract: ``_fetch_history`` must reject non-finite and
negative prices at the parse boundary — return ``None`` so the
downstream "no price data" path runs.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, patch


def _build_client():
    """Construct a CoinGeckoClient without the __init__ side-effects."""
    from recupero.pricing.coingecko import CoinGeckoClient
    client = CoinGeckoClient.__new__(CoinGeckoClient)
    client._client = MagicMock()
    client._base_url = lambda: "https://fake.coingecko"
    client._auth_params = lambda: {}
    client._headers = lambda: {}
    client.limiter = MagicMock()
    client.limiter.wait = lambda: None
    return client


def test_fetch_history_rejects_nan_price() -> None:
    """A CoinGecko response with ``{"usd": "NaN"}`` must NOT produce
    a NaN price. Pre-fix this passed through Decimal('NaN') and was
    not caught by the $2B ceiling (NaN comparisons always False)."""
    from recupero.pricing.coingecko import CoinGeckoClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "market_data": {"current_price": {"usd": "NaN"}},
    }
    client._client.get.return_value = fake_resp

    # Bypass tenacity decorator by calling __wrapped__ directly if present
    fn = CoinGeckoClient._fetch_history
    fn = getattr(fn, "__wrapped__", fn)
    result = fn(client, "bitcoin", date(2024, 1, 1))

    # Acceptable outputs: None (rejected) or a finite Decimal. Reject NaN.
    assert result is None or (
        isinstance(result, Decimal) and result.is_finite()
    ), (
        f"CoinGecko NaN price was returned as {result!r} — would "
        f"propagate into case.json as a non-finite USD value, bypassing "
        f"the $2B sanity ceiling."
    )


def test_fetch_history_rejects_infinity_price() -> None:
    """``{"usd": "Infinity"}`` would compute as inf*amount=inf, which
    IS caught by the >$2B ceiling but only AFTER the value lands in
    Transfer.usd_value_at_tx and is pricing-rejected. Belt-and-
    suspenders: reject at parse time."""
    from recupero.pricing.coingecko import CoinGeckoClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "market_data": {"current_price": {"usd": "Infinity"}},
    }
    client._client.get.return_value = fake_resp

    fn = CoinGeckoClient._fetch_history
    fn = getattr(fn, "__wrapped__", fn)
    result = fn(client, "bitcoin", date(2024, 1, 1))

    assert result is None or (
        isinstance(result, Decimal) and result.is_finite()
    ), f"CoinGecko Infinity price returned as {result!r}"


def test_fetch_history_rejects_negative_price() -> None:
    """A negative USD price is operationally nonsense (it'd render
    in freeze letters as "-$1,500 lost"). Reject and treat as "no
    price"."""
    from recupero.pricing.coingecko import CoinGeckoClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "market_data": {"current_price": {"usd": -1.5}},
    }
    client._client.get.return_value = fake_resp

    fn = CoinGeckoClient._fetch_history
    fn = getattr(fn, "__wrapped__", fn)
    result = fn(client, "bitcoin", date(2024, 1, 1))

    assert result is None or (isinstance(result, Decimal) and result >= 0), (
        f"CoinGecko returned negative price {result!r}; would propagate "
        f"as negative dollar amounts in the LE handoff."
    )


def test_fetch_history_accepts_normal_price() -> None:
    """Sanity: hardening must NOT break the happy path. A legitimate
    positive price flows through."""
    from recupero.pricing.coingecko import CoinGeckoClient

    client = _build_client()
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "market_data": {"current_price": {"usd": 42_000.50}},
    }
    client._client.get.return_value = fake_resp

    fn = CoinGeckoClient._fetch_history
    fn = getattr(fn, "__wrapped__", fn)
    result = fn(client, "bitcoin", date(2024, 1, 1))

    assert result == Decimal("42000.50")


def test_price_at_rejects_cached_nan() -> None:
    """RIGOR-Jacob F: even if a cache file got corrupted with a NaN
    value, the price_at path must not return a NaN. Models a hostile
    cache scenario (older code wrote {'usd': None, 'error': ...} on
    fetch failure → a future tampered cache could write
    {'usd': 'NaN'} to bypass the fetch path entirely)."""
    from recupero.models import Chain, TokenRef
    from recupero.pricing.coingecko import CoinGeckoClient

    client = _build_client()
    # Mock the cache to return a corrupted "NaN" entry.
    fake_cache = MagicMock()
    fake_cache.get.return_value = {"usd": "NaN"}
    client.cache = fake_cache
    client._contract_id_cache = {}

    token = TokenRef(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        decimals=18, coingecko_id="ethereum",
    )
    # Patch the _resolve_cg_id to short-circuit on the hint.
    with patch.object(client, "_resolve_cg_id", return_value="ethereum"):
        from datetime import UTC, datetime
        result = client.price_at(token, datetime(2024, 1, 1, tzinfo=UTC))

    if result.usd_value is not None:
        assert result.usd_value.is_finite(), (
            f"Cached NaN propagated as {result.usd_value!r} — cache "
            f"poison surfaces as a NaN USD value in case.json."
        )
