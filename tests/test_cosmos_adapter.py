"""Tests for the Cosmos / IBC adapter (v0.32.1+ Cap-C).

Covers:
  * Zone resolution by bech32 prefix.
  * LCD tx_response -> Transfer normalization.
  * Native vs IBC denom filtering.
  * Bech32 structural validation.
  * Adapter wiring with an injected http_get callable.
  * Explorer URL composition.
"""

from __future__ import annotations

from datetime import UTC

from recupero.chains.cosmos.adapter import (
    CosmosAdapter,
    _bech32_basic_check,
    _extract_transfers_from_tx_response,
    _is_native_denom,
    _maybe_b64_decode_attr,
    _parse_lcd_timestamp,
)
from recupero.chains.cosmos.client import (
    ZONE_ENDPOINTS,
    CosmosLCDClient,
    base_denom_for,
    resolve_zone,
)
from recupero.models import Chain

# -----------------------------------------------------------------------------
# Chain enum registration
# -----------------------------------------------------------------------------


def test_chain_enum_has_cosmos():
    """The Chain enum exposes Chain.cosmos for Case / Transfer records."""
    assert Chain.cosmos.value == "cosmos"


# -----------------------------------------------------------------------------
# Zone resolution
# -----------------------------------------------------------------------------


def test_resolve_zone_cosmos_hub():
    zi = resolve_zone("cosmos1abcdefghjklmnp")
    assert zi is not None
    assert zi.zone == "cosmos-hub"
    assert zi.prefix == "cosmos"


def test_resolve_zone_osmosis():
    zi = resolve_zone("osmo1xyz1234567890abcde")
    assert zi is not None
    assert zi.zone == "osmosis"


def test_resolve_zone_injective():
    zi = resolve_zone("inj1abcd1234567890efghj")
    assert zi is not None
    assert zi.zone == "injective"


def test_resolve_zone_unknown_returns_none():
    zi = resolve_zone("unknownprefix1foobar")
    assert zi is None


def test_resolve_zone_zone_endpoints_size():
    """We ship at least 7 zone entries (Cosmos Hub, Osmosis, Injective, +)."""
    assert len(ZONE_ENDPOINTS) >= 7


# -----------------------------------------------------------------------------
# bech32 structural check
# -----------------------------------------------------------------------------


def test_bech32_basic_check_valid():
    assert _bech32_basic_check("cosmos1qpqr3xkc8jzwc4hjk5lmnp")


def test_bech32_basic_check_too_short():
    assert not _bech32_basic_check("cos1ab")


def test_bech32_basic_check_no_separator():
    assert not _bech32_basic_check("cosmosabcdef")


def test_bech32_basic_check_invalid_charset():
    # 'b' and 'i' are NOT in bech32 charset.
    assert not _bech32_basic_check("cosmos1ibibibibibi")


def test_bech32_basic_check_evm_address_rejected():
    assert not _bech32_basic_check("0x742d35cc6634c0532925a3b844bc9e7595f0beb1")


# -----------------------------------------------------------------------------
# Timestamp parsing
# -----------------------------------------------------------------------------


def test_parse_lcd_timestamp_with_fraction():
    dt = _parse_lcd_timestamp("2024-04-12T07:23:11.456Z")
    assert dt is not None
    assert dt.year == 2024
    assert dt.tzinfo == UTC


def test_parse_lcd_timestamp_no_fraction():
    dt = _parse_lcd_timestamp("2024-04-12T07:23:11Z")
    assert dt is not None
    assert dt.year == 2024


def test_parse_lcd_timestamp_garbage_returns_none():
    assert _parse_lcd_timestamp("not a date") is None


def test_parse_lcd_timestamp_none_returns_none():
    assert _parse_lcd_timestamp(None) is None


# -----------------------------------------------------------------------------
# Transfer extraction
# -----------------------------------------------------------------------------


_SAMPLE_TX_RESPONSE = {
    "txhash": "ABC123",
    "height": "12345678",
    "timestamp": "2024-04-12T07:23:11.456Z",
    "tx": {
        "body": {
            "messages": [
                {
                    "@type": "/cosmos.bank.v1beta1.MsgSend",
                    "from_address": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "to_address": "cosmos1recipient0aaaaaaaaaaaaaaaaaaaaaaaaa",
                    "amount": [{"denom": "uatom", "amount": "1000000"}],
                }
            ]
        }
    },
    "logs": [
        {
            "events": [
                {
                    "type": "transfer",
                    "attributes": [
                        {"key": "recipient", "value": "cosmos1recipient0aaaaaaaaaaaaaaaaaaaaaaaaa"},
                        {"key": "sender", "value": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                        {"key": "amount", "value": "1000000uatom"},
                    ],
                }
            ]
        }
    ],
}


def test_extract_transfer_basic():
    transfers = _extract_transfers_from_tx_response(_SAMPLE_TX_RESPONSE)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.tx_hash == "ABC123"
    assert t.block_height == 12345678
    assert t.from_address == "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert t.to_address == "cosmos1recipient0aaaaaaaaaaaaaaaaaaaaaaaaa"
    assert t.denom == "uatom"
    assert t.amount_raw == 1_000_000
    assert t.is_ibc is False
    assert "MsgSend" in t.msg_type


def test_extract_transfer_ibc_denom():
    """IBC-prefixed denom -> is_ibc=True."""
    resp = dict(_SAMPLE_TX_RESPONSE)
    resp = {**_SAMPLE_TX_RESPONSE}
    resp["logs"] = [
        {
            "events": [
                {
                    "type": "transfer",
                    "attributes": [
                        {"key": "recipient", "value": "osmo1recipient00000000000000000000000000"},
                        {"key": "sender", "value": "osmo1senderxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
                        {"key": "amount", "value": "500000ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2"},
                    ],
                }
            ]
        }
    ]
    transfers = _extract_transfers_from_tx_response(resp)
    assert len(transfers) == 1
    assert transfers[0].is_ibc is True
    assert transfers[0].denom.startswith("ibc/")


def test_extract_transfer_multiple_in_one_event():
    """An event with multiple recipient/sender/amount triples splits cleanly."""
    resp = {
        "txhash": "MULTI",
        "height": "1",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "cosmos1r1aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1s1aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "100uatom"},
                            {"key": "recipient", "value": "cosmos1r2aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1s2aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "200uatom"},
                        ],
                    }
                ]
            }
        ],
    }
    transfers = _extract_transfers_from_tx_response(resp)
    assert len(transfers) == 2
    assert transfers[0].amount_raw == 100
    assert transfers[1].amount_raw == 200


def test_extract_transfer_multi_denom_amount():
    """Comma-separated amount -> multiple Transfers."""
    resp = {
        "txhash": "MULTIDENOM",
        "height": "1",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "cosmos1rx0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1sx0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "100uatom,200ibc/ABCD"},
                        ],
                    }
                ]
            }
        ],
    }
    transfers = _extract_transfers_from_tx_response(resp)
    assert len(transfers) == 2
    denoms = {t.denom for t in transfers}
    assert "uatom" in denoms
    assert any(d.startswith("ibc/") for d in denoms)


def test_extract_transfer_empty_response():
    assert _extract_transfers_from_tx_response({}) == []
    assert _extract_transfers_from_tx_response({"logs": []}) == []
    assert _extract_transfers_from_tx_response({"logs": [{"events": []}]}) == []


# -----------------------------------------------------------------------------
# CosmosAdapter end-to-end with mocked http_get
# -----------------------------------------------------------------------------


def _mock_http_get_with_response(response_body: dict):
    """Build a mock http_get callable that always returns response_body."""
    calls: list[tuple] = []

    def _get(url, params=None, headers=None):
        calls.append((url, params, headers))
        return {"status_code": 200, "json": response_body}

    _get.calls = calls
    return _get


def test_adapter_fetch_native_outflows_with_mock():
    """Wire a mock LCD response and verify normalization."""
    lcd_body = {"tx_responses": [_SAMPLE_TX_RESPONSE], "pagination": {"total": "1"}}
    http_get = _mock_http_get_with_response(lcd_body)
    client = CosmosLCDClient(http_get=http_get)
    adapter = CosmosAdapter(client=client)

    outflows = adapter.fetch_native_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert len(outflows) == 1
    row = outflows[0]
    assert row["chain"] == "cosmos"
    assert row["zone"] == "cosmos-hub"
    assert row["token"] == "uatom"
    assert row["amount_raw"] == 1_000_000
    assert row["is_ibc"] is False
    assert row["explorer_url"].startswith("https://www.mintscan.io/cosmos-hub/txs/")


def test_adapter_fetch_erc20_outflows_includes_ibc():
    """The 'erc20' surface for Cosmos returns IBC denoms too."""
    ibc_tx = {
        "txhash": "IBCTX",
        "height": "100",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "osmo1recipient00000000000000000000000000"},
                            {"key": "sender", "value": "osmo1senderxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
                            {"key": "amount", "value": "500000ibc/27394FB"},
                        ],
                    }
                ]
            }
        ],
    }
    http_get = _mock_http_get_with_response({"tx_responses": [ibc_tx]})
    client = CosmosLCDClient(http_get=http_get)
    adapter = CosmosAdapter(client=client)

    outflows = adapter.fetch_erc20_outflows(
        "osmo1senderxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    )
    assert len(outflows) == 1
    assert outflows[0]["is_ibc"] is True


def test_adapter_invalid_address_returns_empty():
    """An EVM-shape (not bech32) address returns [] without HTTP."""
    adapter = CosmosAdapter()
    assert adapter.fetch_native_outflows("0xdeadbeef") == []
    assert adapter.fetch_erc20_outflows("0xdeadbeef") == []


def test_adapter_explorer_address_url_resolves_zone():
    adapter = CosmosAdapter()
    url = adapter.explorer_address_url("osmo1xyz1234567890abcde")
    assert "osmosis" in url
    assert "osmo1xyz1234567890abcde" in url


def test_adapter_explorer_tx_url_default_zone():
    adapter = CosmosAdapter()
    url = adapter.explorer_tx_url("ABC123")
    assert "ABC123" in url
    assert "mintscan.io" in url


# -----------------------------------------------------------------------------
# Retry behavior
# -----------------------------------------------------------------------------


def test_client_retries_on_429():
    """A 429 response triggers retry; the second 200 succeeds."""
    attempts = [0]

    def _http_get(url, params=None, headers=None):
        attempts[0] += 1
        if attempts[0] == 1:
            return {"status_code": 429, "json": {}}
        return {"status_code": 200, "json": {"ok": True}}

    client = CosmosLCDClient(
        http_get=_http_get,
        max_retries=2,
        initial_backoff_sec=0.0,  # no real sleep in tests
    )
    result = client.get_json("https://example.com/x")
    assert result == {"ok": True}
    assert attempts[0] == 2


def test_client_non_retryable_error_surfaces():
    """A 404 surfaces immediately without retry."""
    def _http_get(url, params=None, headers=None):
        return {"status_code": 404, "json": {}}

    client = CosmosLCDClient(http_get=_http_get, max_retries=3, initial_backoff_sec=0.0)
    result = client.get_json("https://example.com/x")
    assert "_error" in result
    assert result["_status_code"] == 404


# -----------------------------------------------------------------------------
# Finding 1: modern SDK >= v0.46 top-level `events` array (logs == [])
# -----------------------------------------------------------------------------


_MODERN_TX_RESPONSE = {
    "txhash": "MODERN1",
    "height": "20000000",
    "timestamp": "2025-01-02T03:04:05Z",
    "tx": {"body": {"messages": [{"@type": "/cosmos.bank.v1beta1.MsgSend"}]}},
    # SDK >= v0.46: logs empty, events flattened to the top level.
    "logs": [],
    "events": [
        {
            "type": "transfer",
            "attributes": [
                {"key": "recipient", "value": "cosmos1recipient0aaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"key": "sender", "value": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"key": "amount", "value": "7000000uatom"},
            ],
        },
    ],
}


def test_extract_transfer_modern_top_level_events():
    """SDK >= v0.46: logs == [] but events live at the top level."""
    transfers = _extract_transfers_from_tx_response(_MODERN_TX_RESPONSE)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.tx_hash == "MODERN1"
    assert t.amount_raw == 7_000_000
    assert t.denom == "uatom"
    assert t.from_address == "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_extract_transfer_modern_events_base64_attributes():
    """Some LCD versions base64-encode the top-level event attributes."""
    import base64 as _b64

    def b(s: str) -> str:
        return _b64.b64encode(s.encode()).decode()

    resp = {
        "txhash": "B64TX",
        "height": "21000000",
        "timestamp": None,
        "logs": [],
        "events": [
            {
                "type": "transfer",
                "attributes": [
                    {"key": b("recipient"), "value": b("cosmos1recipient0aaaaaaaaaaaaaaaaaaaaaaaaa")},
                    {"key": b("sender"), "value": b("cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
                    {"key": b("amount"), "value": b("123456uatom")},
                ],
            }
        ],
    }
    transfers = _extract_transfers_from_tx_response(resp)
    assert len(transfers) == 1
    assert transfers[0].amount_raw == 123456
    assert transfers[0].denom == "uatom"


def test_extract_transfer_legacy_logs_still_works():
    """Old chains with populated `logs` are unaffected (no double-count)."""
    transfers = _extract_transfers_from_tx_response(_SAMPLE_TX_RESPONSE)
    assert len(transfers) == 1
    assert transfers[0].amount_raw == 1_000_000


def test_extract_transfer_prefers_logs_no_double_count():
    """If BOTH logs and top-level events are present, don't double-count."""
    resp = {**_SAMPLE_TX_RESPONSE}
    resp["events"] = _MODERN_TX_RESPONSE["events"]  # add top-level too
    transfers = _extract_transfers_from_tx_response(resp)
    # logs has 1 transfer; we must NOT also emit the top-level one.
    assert len(transfers) == 1
    assert transfers[0].amount_raw == 1_000_000


def test_maybe_b64_decode_passthrough_plaintext():
    """Plaintext attribute values are returned verbatim where ambiguous."""
    # "recipient" happens to be valid base64 charset but is not real b64
    # round-trip of a meaningful key, so it should pass through unchanged.
    assert _maybe_b64_decode_attr("recipient") == "recipient"
    assert _maybe_b64_decode_attr("uatom") == "uatom"
    assert _maybe_b64_decode_attr(None) is None


def test_adapter_modern_events_end_to_end():
    """Adapter normalizes a modern (logs==[]) response correctly."""
    http_get = _mock_http_get_with_response({"tx_responses": [_MODERN_TX_RESPONSE]})
    client = CosmosLCDClient(http_get=http_get)
    adapter = CosmosAdapter(client=client)
    outflows = adapter.fetch_native_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert len(outflows) == 1
    assert outflows[0]["token"] == "uatom"
    assert outflows[0]["amount_raw"] == 7_000_000


# -----------------------------------------------------------------------------
# Finding 2: native-denom classification (no length heuristic)
# -----------------------------------------------------------------------------


def test_is_native_denom_base_denom_matches():
    assert _is_native_denom("uatom", "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert _is_native_denom("uosmo", "osmo1senderxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    assert _is_native_denom("inj", "inj1abcd1234567890efghj")


def test_is_native_denom_short_non_native_rejected():
    """`uusdc` is short but is NOT the Cosmos Hub base denom → not native."""
    assert not _is_native_denom("uusdc", "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_is_native_denom_ibc_factory_cw20_rejected():
    addr = "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert not _is_native_denom("ibc/27394FB", addr)
    assert not _is_native_denom("factory/cosmos1xyz/utoken", addr)
    assert not _is_native_denom("cw20:cosmos1contract", addr)


def test_is_native_denom_unknown_zone_conservative():
    """Unknown zone → cannot prove native → treated as non-native."""
    assert not _is_native_denom("ufoo", "unknownprefix1foobar")


def test_base_denom_for_resolution():
    assert base_denom_for("cosmos1abc") == "uatom"
    assert base_denom_for("osmo1abc") == "uosmo"
    assert base_denom_for("unknownprefix1foo") is None


def test_native_outflows_excludes_short_non_native_denom():
    """A uusdc transfer must NOT appear in the native-outflow surface."""
    tx = {
        "txhash": "USDC1",
        "height": "5",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "cosmos1rx0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "9000000uusdc"},
                        ],
                    }
                ]
            }
        ],
    }
    http_get = _mock_http_get_with_response({"tx_responses": [tx]})
    adapter = CosmosAdapter(client=CosmosLCDClient(http_get=http_get))
    native = adapter.fetch_native_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert native == []
    # but it DOES show up in the token (erc20) surface
    tokens = adapter.fetch_erc20_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert len(tokens) == 1
    assert tokens[0]["token"] == "uusdc"


# -----------------------------------------------------------------------------
# Finding 3: pagination across LCD next_key pages
# -----------------------------------------------------------------------------


def _tx_with_hash(h: str) -> dict:
    return {
        "txhash": h,
        "height": "1",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "cosmos1rx0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "1uatom"},
                        ],
                    }
                ]
            }
        ],
    }


def test_client_paginates_until_next_key_exhausted():
    """fetch_all_txs_by_sender follows pagination.next_key across pages."""
    pages = [
        {"tx_responses": [_tx_with_hash("P1")], "pagination": {"next_key": "KEY2"}},
        {"tx_responses": [_tx_with_hash("P2")], "pagination": {"next_key": "KEY3"}},
        {"tx_responses": [_tx_with_hash("P3")], "pagination": {"next_key": None}},
    ]
    state = {"i": 0}

    def _http_get(url, params=None, headers=None):
        body = pages[state["i"]]
        state["i"] = min(state["i"] + 1, len(pages) - 1)
        return {"status_code": 200, "json": body}

    client = CosmosLCDClient(http_get=_http_get)
    merged = client.fetch_all_txs_by_sender("cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    hashes = [t["txhash"] for t in merged["tx_responses"]]
    assert hashes == ["P1", "P2", "P3"]


def test_client_pagination_stuck_cursor_guard():
    """A non-advancing next_key breaks early instead of looping forever."""
    calls = {"n": 0}

    def _http_get(url, params=None, headers=None):
        calls["n"] += 1
        # Always returns the SAME next_key → stuck cursor.
        return {
            "status_code": 200,
            "json": {"tx_responses": [_tx_with_hash("X")], "pagination": {"next_key": "SAME"}},
        }

    client = CosmosLCDClient(http_get=_http_get)
    merged = client.fetch_all_txs_by_sender(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", max_pages=50
    )
    # First page sets next_key=SAME; second page echoes SAME → stuck → break.
    assert calls["n"] == 2
    assert len(merged["tx_responses"]) == 2


def test_client_pagination_max_pages_cap():
    """The max_pages cap bounds total requests even with infinite pages."""
    calls = {"n": 0}

    def _http_get(url, params=None, headers=None):
        calls["n"] += 1
        # Each page advances the key so the stuck-guard never trips.
        return {
            "status_code": 200,
            "json": {
                "tx_responses": [_tx_with_hash(f"T{calls['n']}")],
                "pagination": {"next_key": f"KEY{calls['n']}"},
            },
        }

    client = CosmosLCDClient(http_get=_http_get)
    client.fetch_all_txs_by_sender(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", max_pages=3
    )
    assert calls["n"] == 3


def test_client_pagination_page0_error_surfaces():
    """A page-0 LCD error surfaces as an _error dict (caller degrades)."""
    def _http_get(url, params=None, headers=None):
        return {"status_code": 500, "json": {}}

    client = CosmosLCDClient(http_get=_http_get, max_retries=1, initial_backoff_sec=0.0)
    merged = client.fetch_all_txs_by_sender("cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert "_error" in merged


# -----------------------------------------------------------------------------
# Finding 4: start_block sentinel (-1) must not filter rows
# -----------------------------------------------------------------------------


def test_block_at_or_before_sentinel_does_not_filter():
    """A -1 (or 0) start_block must behave as 'no filter'."""
    tx = _tx_with_hash("BLOCKED")
    tx["height"] = "100"
    http_get = _mock_http_get_with_response({"tx_responses": [tx]})
    adapter = CosmosAdapter(client=CosmosLCDClient(http_get=http_get))
    # -1 is the block_at_or_before sentinel; must not drop the row.
    rows = adapter.fetch_erc20_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", start_block=-1
    )
    assert len(rows) == 1
    # A real positive start_block above the tx height DOES filter it.
    rows2 = adapter.fetch_erc20_outflows(
        "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", start_block=200
    )
    assert rows2 == []


def test_block_at_or_before_returns_sentinel():
    adapter = CosmosAdapter()
    from datetime import datetime

    assert adapter.block_at_or_before(datetime(2024, 1, 1, tzinfo=UTC)) == -1


# -----------------------------------------------------------------------------
# Guardrails: adversarial / malformed LCD bodies degrade gracefully
# -----------------------------------------------------------------------------


def test_extract_transfer_non_dict_tx_response():
    assert _extract_transfers_from_tx_response("not a dict") == []  # type: ignore[arg-type]
    assert _extract_transfers_from_tx_response(None) == []  # type: ignore[arg-type]


def test_extract_transfer_garbage_height_and_amount():
    resp = {
        "txhash": "JUNK",
        "height": "not-a-number",
        "timestamp": None,
        "logs": [
            {
                "events": [
                    {
                        "type": "transfer",
                        "attributes": [
                            {"key": "recipient", "value": "cosmos1rx0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "sender", "value": "cosmos1sender0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"key": "amount", "value": "notanumberuatom"},
                        ],
                    }
                ]
            }
        ],
    }
    # height parse failure → 0, malformed amount → skipped, no crash.
    transfers = _extract_transfers_from_tx_response(resp)
    assert transfers == []


def test_extract_transfer_events_not_a_list():
    resp = {"txhash": "X", "height": "1", "logs": [], "events": "garbage"}
    assert _extract_transfers_from_tx_response(resp) == []
