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


def test_skip_contract_api_does_not_call_resolution_api() -> None:
    """v0.34 value-trace fast path: ``price_at(skip_contract_api=True)`` must
    NOT make a per-token contract->id resolution API call for an unmapped
    ERC-20 — it returns unpriced fast. This is what lets value-directed tracing
    rank a high-fan-out node's thousands of outflows cheaply. (The normal pass,
    without the flag, still resolves via API.)"""
    from datetime import UTC, datetime

    from recupero.models import Chain, TokenRef

    client = _build_client()
    client._contract_id_cache = {}  # empty -> no static-map short-circuit
    client.cache = MagicMock()
    client.cache.get.return_value = None

    def _boom(*_a, **_k):
        raise AssertionError(
            "_fetch_contract_to_id was called despite skip_contract_api=True"
        )

    client._fetch_contract_to_id = _boom

    token = TokenRef(
        chain=Chain.ethereum,
        contract="0x000000000000000000000000000000000000dEaD",
        symbol="SCAM",          # not a stablecoin symbol
        decimals=18,
        coingecko_id=None,       # no hint -> would normally hit the API
    )
    result = client.price_at(
        token, datetime(2024, 1, 1, tzinfo=UTC), skip_contract_api=True,
    )
    assert result.usd_value is None
    assert result.error == "no_coingecko_mapping"


def test_skip_contract_api_off_does_resolve_via_api() -> None:
    """Sanity counter-test: WITHOUT the flag, the same unmapped token DOES go
    through the resolution API path (so the fast path is a real divergence,
    not a no-op)."""
    from datetime import UTC, datetime

    from recupero.models import Chain, TokenRef

    client = _build_client()
    client._contract_id_cache = {}
    client.cache = MagicMock()
    client.cache.get.return_value = None
    called = {"n": 0}

    def _resolve(_chain, _canon):
        # pretend CoinGecko 404 (unknown token) — implicit None return
        called["n"] += 1

    client._fetch_contract_to_id = _resolve

    token = TokenRef(
        chain=Chain.ethereum,
        contract="0x000000000000000000000000000000000000dEaD",
        symbol="SCAM",
        decimals=18,
        coingecko_id=None,
    )
    client.price_at(token, datetime(2024, 1, 1, tzinfo=UTC))  # no skip flag
    assert called["n"] == 1, "normal pass must attempt API contract resolution"


# ---- v0.34.2: contract-first stablecoin pricing (L2 USDC.e fix) ----


def _tok(chain, contract, symbol):
    from recupero.models import TokenRef
    return TokenRef(chain=chain, contract=contract, symbol=symbol,
                    decimals=6, coingecko_id=None)


def test_bridged_usdc_e_labeled_usdc_prices_at_par() -> None:
    """The Zigha L2-blindness fix: bridged Arbitrum USDC.e is frequently labeled
    "USDC" by explorers, but its contract != the (arbitrum,"USDC") canonical
    (native USDC). The symbol-keyed check rejected it as a spoof → unpriced →
    value-trace blind on L2. Contract-first identity prices it at $1."""
    from datetime import UTC, datetime

    from recupero.models import Chain
    client = _build_client()
    # USDC.e contract, mislabeled "USDC"
    tok = _tok(Chain.arbitrum, "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", "USDC")
    r = client.price_at(tok, datetime(2025, 10, 9, tzinfo=UTC), skip_contract_api=True)
    assert r.usd_value == Decimal("1.00")
    assert r.source == "stablecoin_par"


def test_canonical_usdc_still_prices_by_contract() -> None:
    from datetime import UTC, datetime

    from recupero.models import Chain
    client = _build_client()
    tok = _tok(Chain.arbitrum, "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "USDC")
    r = client.price_at(tok, datetime(2025, 10, 9, tzinfo=UTC), skip_contract_api=True)
    assert r.usd_value == Decimal("1.00")


def test_poison_contract_labeled_usdc_not_priced_at_par() -> None:
    """A poison/spoof token using a FAKE contract but labeled "USDC" must NEVER
    price at par — contract membership is the identity, not the symbol."""
    from datetime import UTC, datetime

    from recupero.models import Chain
    client = _build_client()
    client._contract_id_cache = {}
    client.cache = MagicMock()
    client.cache.get.return_value = None
    tok = _tok(Chain.arbitrum, "0xb4094bd2ba706361ee9064f97a3bfaaf9b2f7715", "USDC")
    r = client.price_at(tok, datetime(2025, 10, 9, tzinfo=UTC), skip_contract_api=True)
    assert r.usd_value is None  # not $1 — spoof contract not in legit set


def test_legit_stablecoin_contract_helper() -> None:
    from recupero.models import Chain
    from recupero.pricing.coingecko import _legit_stablecoin_contract
    # native + bridged USDC, mixed case, both legit:
    assert _legit_stablecoin_contract(Chain.arbitrum, "0xAF88D065E77C8cc2239327C5EDb3A432268e5831")
    assert _legit_stablecoin_contract(Chain.arbitrum, "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8")
    assert not _legit_stablecoin_contract(Chain.arbitrum, "0xb4094bd2ba706361ee9064f97a3bfaaf9b2f7715")
    assert not _legit_stablecoin_contract(Chain.arbitrum, None)
