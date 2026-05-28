"""v0.31.5 — DeFiLlama secondary pricing provider + fallback chain.

When CoinGecko's free tier rate-limits or returns ``None`` during a
high-traffic incident, the brief's Section 4 USD column reads
``(unpriced)`` for every transfer because there's no secondary
provider. RIGOR-Jacob F (v0.30.3) hardened against NaN/Inf/negative
responses but never added a fallback chain.

This module wires DeFiLlama as the canonical second provider and
locks the contract:

  1. Happy-path lookups produce a valid Decimal price.
  2. Defensive contract: NaN / Inf / negative / low-confidence /
     HTTP-error / unsupported-chain inputs all return ``None`` (the
     caller falls through to "(unpriced)").
  3. The fallback chain in ``CoinGeckoClient.price_at`` uses DeFiLlama
     ONLY when CoinGecko returns ``None`` — a CoinGecko price is the
     last-write-wins primary, never short-circuited by the fallback.
  4. ``RECUPERO_PRICING_FALLBACK=none`` disables the fallback entirely.
  5. Successful fetches are cached under
     ``<cache_dir>/defillama/`` — second call is free.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from recupero.models import Chain, TokenRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _eth_token() -> TokenRef:
    """Native ETH — DeFiLlama uses `coingecko:ethereum` for natives."""
    return TokenRef(
        chain=Chain.ethereum,
        contract=None,
        symbol="ETH",
        decimals=18,
        coingecko_id="ethereum",
    )


def _erc20_token(contract: str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") -> TokenRef:
    """ERC-20 token (USDC) — DeFiLlama uses `ethereum:0x...` form."""
    return TokenRef(
        chain=Chain.ethereum,
        contract=contract,
        symbol="USDC",
        decimals=6,
        coingecko_id="usd-coin",
    )


def _build_llama_client(tmp_path: Path):
    """Construct a DeFiLlamaClient bound to a per-test file cache."""
    from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
    from recupero.pricing.defillama import DeFiLlamaClient

    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    env = RecuperoEnv()
    # Force file cache (no Postgres) regardless of ambient env.
    return DeFiLlamaClient(cfg, env, tmp_path, dsn="")


def _patch_fetch(client, *, price, confidence):
    """Replace _fetch so we don't need real HTTP in the happy path."""
    return patch.object(
        client,
        "_fetch",
        return_value=(price, confidence),
    )


def _make_resp(status_code: int, payload: dict | None = None) -> MagicMock:
    """Build a stand-in httpx.Response without real HTTP."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = payload if payload is not None else {}
    return r


# ---------------------------------------------------------------------------
# 1. DeFiLlama happy path
# ---------------------------------------------------------------------------


def test_defillama_happy_path_returns_price(tmp_path: Path) -> None:
    client = _build_llama_client(tmp_path)
    with _patch_fetch(client, price=Decimal("3500.50"), confidence=0.95):
        result = client.get_price_at(
            chain=Chain.ethereum,
            contract=None,
            symbol="ETH",
            ts=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
            coingecko_id="ethereum",
        )
    assert result is not None
    assert result.usd_value == Decimal("3500.50")
    assert result.source is not None
    assert "defillama" in result.source


def test_defillama_erc20_happy_path(tmp_path: Path) -> None:
    """ERC-20 path uses `ethereum:0x...` form, lowercased."""
    client = _build_llama_client(tmp_path)
    # Capture _fetch to confirm the coin_key shape.
    captured: dict[str, str] = {}

    def fake_fetch(coin_key: str, ts: int):
        captured["coin_key"] = coin_key
        return Decimal("1.00"), 0.99

    with patch.object(client, "_fetch", side_effect=fake_fetch):
        result = client.get_price_at(
            chain=Chain.ethereum,
            contract="0xA0b86991C6218b36c1d19D4a2e9Eb0cE3606eB48",  # mixed-case
            symbol="USDC",
            ts=datetime(2024, 6, 1, tzinfo=UTC),
        )
    assert result is not None
    assert result.usd_value == Decimal("1.00")
    assert captured["coin_key"] == "ethereum:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


# ---------------------------------------------------------------------------
# 2. Defensive contract — NaN / Inf / negative all rejected
# ---------------------------------------------------------------------------


def test_defillama_nan_price_rejected_at_parse(tmp_path: Path) -> None:
    """A response with ``{"price": "NaN"}`` must be rejected; NaN
    propagating into case.json would slip past the $2B sanity ceiling
    (NaN comparisons return False)."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": "NaN", "confidence": 0.9,
    }}})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or result.usd_value is None


def test_defillama_infinity_price_rejected(tmp_path: Path) -> None:
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": "Infinity", "confidence": 0.9,
    }}})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or result.usd_value is None


def test_defillama_negative_price_rejected(tmp_path: Path) -> None:
    """Negative dollar amounts would render in freeze letters as
    "-$1,500 lost" — operationally nonsensical."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": -1.5, "confidence": 0.9,
    }}})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or (
        result.usd_value is None or result.usd_value >= 0
    )


# ---------------------------------------------------------------------------
# 3. Confidence floor — low confidence rejected, high accepted
# ---------------------------------------------------------------------------


def test_defillama_low_confidence_rejected(tmp_path: Path) -> None:
    """DeFiLlama's `confidence` field rates source coverage. Below
    0.5 we treat as a miss rather than a real price."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": 3500.0, "confidence": 0.3,
    }}})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None


def test_defillama_high_confidence_accepted(tmp_path: Path) -> None:
    """Symmetric: 0.95 confidence flows through to a clean price."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": 3500.0, "confidence": 0.95,
    }}})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is not None
    assert result.usd_value == Decimal("3500.0")


# ---------------------------------------------------------------------------
# 4. Error handling — HTTP 404 / 500 / timeout / shape mismatch
# ---------------------------------------------------------------------------


def test_defillama_404_returns_none(tmp_path: Path) -> None:
    client = _build_llama_client(tmp_path)
    fake = _make_resp(404, {})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or result.usd_value is None


def test_defillama_500_returns_none(tmp_path: Path) -> None:
    client = _build_llama_client(tmp_path)
    fake = _make_resp(500, {})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or result.usd_value is None


def test_defillama_timeout_returns_none(tmp_path: Path) -> None:
    client = _build_llama_client(tmp_path)
    client._client.get = MagicMock(side_effect=httpx.TimeoutException("slow"))

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None


def test_defillama_shape_mismatch_returns_none(tmp_path: Path) -> None:
    """Response that isn't the documented {'coins': {...}} shape."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"unexpected": "shape"})
    client._client.get = MagicMock(return_value=fake)

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id="ethereum",
    )
    assert result is None or result.usd_value is None


# ---------------------------------------------------------------------------
# 5. Unsupported chain / missing key returns None
# ---------------------------------------------------------------------------


def test_defillama_native_without_coingecko_id_returns_none(tmp_path: Path) -> None:
    """Native token with no `coingecko_id` hint can't form a coin key."""
    client = _build_llama_client(tmp_path)
    # _fetch shouldn't even be called — guard at the key-building step.
    client._fetch = MagicMock(side_effect=AssertionError("must not call _fetch"))

    result = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=datetime(2024, 6, 1, tzinfo=UTC), coingecko_id=None,
    )
    assert result is None


def test_defillama_unsupported_chain_returns_none(tmp_path: Path) -> None:
    """Hyperliquid isn't in DeFiLlama's chain map → key cannot be built."""
    client = _build_llama_client(tmp_path)
    client._fetch = MagicMock(side_effect=AssertionError("must not call _fetch"))

    result = client.get_price_at(
        chain=Chain.hyperliquid, contract="0xabc", symbol="X",
        ts=datetime(2024, 6, 1, tzinfo=UTC),
    )
    assert result is None


# ---------------------------------------------------------------------------
# 6. Cache — second call hits cache, no HTTP
# ---------------------------------------------------------------------------


def test_defillama_cache_hit_skips_http(tmp_path: Path) -> None:
    """A successful first fetch is cached; the second call returns
    the same value without hitting the network."""
    client = _build_llama_client(tmp_path)
    fake = _make_resp(200, {"coins": {"coingecko:ethereum": {
        "price": 1500.25, "confidence": 0.9,
    }}})
    get_mock = MagicMock(return_value=fake)
    client._client.get = get_mock

    ts = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
    first = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=ts, coingecko_id="ethereum",
    )
    second = client.get_price_at(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        ts=ts, coingecko_id="ethereum",
    )
    assert first is not None and first.usd_value == Decimal("1500.25")
    assert second is not None and second.usd_value == Decimal("1500.25")
    # Second call must NOT have touched HTTP — the cache file exists.
    assert get_mock.call_count == 1, (
        f"defillama HTTP called {get_mock.call_count}x; cache should "
        "short-circuit the second lookup"
    )


# ---------------------------------------------------------------------------
# 7. Fallback chain wired through CoinGeckoClient
# ---------------------------------------------------------------------------


def _build_coingecko_client(tmp_path: Path):
    from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
    from recupero.pricing.coingecko import CoinGeckoClient

    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    env = RecuperoEnv(COINGECKO_API_KEY="")
    # dsn="" forces file cache regardless of ambient SUPABASE_DB_URL.
    return CoinGeckoClient(cfg, env, tmp_path, dsn="")


def test_fallback_chain_coingecko_miss_defillama_hit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CoinGecko returns None → DeFiLlama returns a price → brief gets price."""
    monkeypatch.setenv("RECUPERO_PRICING_FALLBACK", "defillama")
    client = _build_coingecko_client(tmp_path)

    # CoinGecko miss: _fetch_history returns None (cleanly "no data").
    with patch.object(client, "_fetch_history", return_value=None):
        # Stub the lazy-loaded DeFiLlama path with a sentinel that
        # returns a valid Decimal.
        from recupero.pricing.defillama import PriceResult as LlamaResult

        fake_llama = MagicMock()
        fake_llama.get_price_at.return_value = LlamaResult(
            usd_value=Decimal("3500.00"),
            source="defillama:coingecko:ethereum:1717200000",
            error=None,
        )
        client._defillama_client = fake_llama  # type: ignore[assignment]

        result = client.price_at(
            _eth_token(), datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )

    assert result.usd_value == Decimal("3500.00")
    assert result.source is not None and "defillama" in result.source


def test_fallback_chain_coingecko_hit_skips_defillama(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CoinGecko returns a price → DeFiLlama MUST NOT be called.

    Cost optimization: every DeFiLlama HTTP call we avoid is real
    money saved at scale + a stricter audit trail.
    """
    monkeypatch.setenv("RECUPERO_PRICING_FALLBACK", "defillama")
    client = _build_coingecko_client(tmp_path)

    fake_llama = MagicMock()
    client._defillama_client = fake_llama  # type: ignore[assignment]

    with patch.object(
        client, "_fetch_history", return_value=Decimal("3501.99"),
    ):
        result = client.price_at(
            _eth_token(), datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )

    assert result.usd_value == Decimal("3501.99")
    # Source must be the CoinGecko key, not a DeFiLlama key.
    assert "coingecko" in (result.source or "")
    assert "defillama" not in (result.source or "")
    fake_llama.get_price_at.assert_not_called()


def test_fallback_disabled_via_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`RECUPERO_PRICING_FALLBACK=none` → DeFiLlama never called even on miss."""
    monkeypatch.setenv("RECUPERO_PRICING_FALLBACK", "none")
    client = _build_coingecko_client(tmp_path)

    fake_llama = MagicMock()
    # Bind the sentinel even though the flag should keep us from using it.
    client._defillama_client = fake_llama  # type: ignore[assignment]

    with patch.object(client, "_fetch_history", return_value=None):
        result = client.price_at(
            _eth_token(), datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )

    assert result.usd_value is None
    fake_llama.get_price_at.assert_not_called()


def test_fallback_chain_both_miss_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CoinGecko None + DeFiLlama None → brief gets `(unpriced)`."""
    monkeypatch.setenv("RECUPERO_PRICING_FALLBACK", "defillama")
    client = _build_coingecko_client(tmp_path)

    fake_llama = MagicMock()
    fake_llama.get_price_at.return_value = None
    client._defillama_client = fake_llama  # type: ignore[assignment]

    with patch.object(client, "_fetch_history", return_value=None):
        result = client.price_at(
            _eth_token(), datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )

    assert result.usd_value is None
    assert result.error == "no_price_data"


def test_fallback_chain_coingecko_exception_triggers_defillama(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient CoinGecko exception (rate-limit, network) must still
    flow through to DeFiLlama — it's the most common reason the
    brief's Section 4 USD column goes dark."""
    monkeypatch.setenv("RECUPERO_PRICING_FALLBACK", "defillama")
    client = _build_coingecko_client(tmp_path)

    from recupero.pricing.defillama import PriceResult as LlamaResult

    fake_llama = MagicMock()
    fake_llama.get_price_at.return_value = LlamaResult(
        usd_value=Decimal("3500.00"),
        source="defillama:coingecko:ethereum:1717200000",
        error=None,
    )
    client._defillama_client = fake_llama  # type: ignore[assignment]

    with patch.object(
        client, "_fetch_history",
        side_effect=httpx.TransportError("rate limited"),
    ):
        result = client.price_at(
            _eth_token(), datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        )

    assert result.usd_value == Decimal("3500.00")
    assert result.source is not None and "defillama" in result.source
