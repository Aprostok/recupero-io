"""MistTrack keyed attribution provider — env-gated, defensive, doctrine-safe.

The provider is INERT without MISTTRACK_API_KEY (no network call → None). With a
key it resolves an address to a LOW-confidence CandidateLabel for the
review→promote pipeline. Response shapes here mirror MistTrack's documented
envelope ({"success", "data"|"msg"}); the auth-error shape was verified live.
"""

from __future__ import annotations

import httpx
import respx

from recupero.labels.providers import misttrack

LABELS_URL = "https://openapi.misttrack.io/v1/address_labels"
ADDR = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def test_inert_without_key(monkeypatch) -> None:
    monkeypatch.delenv("MISTTRACK_API_KEY", raising=False)
    assert misttrack.misttrack_enabled() is False
    # No key → returns None and (asserted by respx.mock absence) makes no call.
    assert misttrack.resolve_attribution(ADDR, chain="ethereum") is None
    assert misttrack.enrich_addresses([ADDR], chain="ethereum") == []


@respx.mock
def test_unmapped_chain_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    assert misttrack.resolve_attribution(ADDR, chain="hyperliquid") is None


@respx.mock
def test_exchange_label_resolves_via_documented_shape(monkeypatch) -> None:
    """Documented address_labels shape: data = {label_list, label_type}."""
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    route = respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": True,
        "data": {"label_list": ["Binance"], "label_type": "exchange"},
    }))
    c = misttrack.resolve_attribution(ADDR, chain="ethereum")
    assert c is not None
    assert c.proposed_category == "exchange_hot_wallet"
    assert c.source == "misttrack"
    assert c.proposed_confidence == "low"
    assert c.address == ADDR.lower()
    assert "Binance" in c.proposed_name
    # The request MUST carry the api_key param (MistTrack's documented auth) —
    # the field-name bug the deep-research caught (was api_token).
    req_url = str(route.calls[0].request.url)
    assert "api_key=k" in req_url
    assert "coin=ETH" in req_url


@respx.mock
def test_exchange_label_resolves_from_list_shape(monkeypatch) -> None:
    """Defensive: a bare list of label strings still resolves via name scan."""
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": True, "data": ["Kraken Hot Wallet"],
    }))
    c = misttrack.resolve_attribution(ADDR, chain="ethereum")
    assert c is not None and c.proposed_category == "exchange_hot_wallet"


@respx.mock
def test_malicious_label_resolves_to_scam_drainer(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": True, "data": [{"label": "Phishing/Drainer"}],
    }))
    c = misttrack.resolve_attribution(ADDR, chain="ethereum")
    assert c is not None
    assert c.proposed_category == "scam_drainer"


@respx.mock
def test_no_usable_label_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": True, "data": ["Some Random DApp"],
    }))
    assert misttrack.resolve_attribution(ADDR, chain="ethereum") is None


@respx.mock
def test_invalid_key_response_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    # The live-verified auth-error envelope.
    respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": False, "msg": "InvalidApiKey",
    }))
    assert misttrack.resolve_attribution(ADDR, chain="ethereum") is None


@respx.mock
def test_http_error_degrades_to_none(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    respx.get(LABELS_URL).mock(return_value=httpx.Response(503))
    assert misttrack.resolve_attribution(ADDR, chain="ethereum") is None


@respx.mock
def test_enrich_addresses_batch(monkeypatch) -> None:
    monkeypatch.setenv("MISTTRACK_API_KEY", "k")
    respx.get(LABELS_URL).mock(return_value=httpx.Response(200, json={
        "success": True, "data": ["Kraken"],
    }))
    out = misttrack.enrich_addresses([ADDR, ADDR], chain="ethereum")  # dup collapses
    assert len(out) == 1
    assert out[0].proposed_category == "exchange_hot_wallet"
