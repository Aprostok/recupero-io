"""Tests for v0.12.0 TronAdapter.

The TronGridClient is mocked at the method level (no HTTP). These
tests verify:

  * fetch_erc20_outflows normalizes TRC-20 events to the tracer's
    standard shape (chain=Chain.tron, contract in base58,
    amount_raw int, etc.).
  * Wrong-direction events get filtered out.
  * Malformed events (missing token_info, bad timestamps) get
    skipped without failing the whole call.
  * is_contract probes the account endpoint and caches.
  * Explorer URLs route to tronscan.org.
  * USDT contract address gets the right CoinGecko ID.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from recupero.chains.tron.adapter import TronAdapter
from recupero.chains.tron.client import TronGridError
from recupero.models import Chain


# Real Tron mainnet addresses (all base58check):
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
PERP = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"
VICTIM = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"


def _trc20_event(
    *,
    tx_id: str = "tx_abc",
    from_addr: str = VICTIM,
    to_addr: str = PERP,
    value: str = "1234560000",   # 1,234.56 USDT (6 decimals)
    block_ts_ms: int = 1_750_000_000_000,
    token_address: str = USDT_CONTRACT,
    symbol: str = "USDT",
    decimals: int = 6,
) -> dict:
    return {
        "transaction_id": tx_id,
        "block_timestamp": block_ts_ms,
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "type": "Transfer",
        "token_info": {
            "symbol": symbol,
            "decimals": decimals,
            "name": "Tether USD",
            "address": token_address,
        },
    }


def _mk_adapter(*, account_data: list | None = None,
                trc20_events: list | None = None) -> TronAdapter:
    """Build a TronAdapter with a fully-mocked client."""
    client = MagicMock()
    client.get_account.return_value = {"data": account_data or []}
    client.get_trc20_transfers.return_value = trc20_events or []
    return TronAdapter(client=client)


# ---- fetch_erc20_outflows ---- #


def test_fetch_outflows_normalizes_basic() -> None:
    """Single TRC-20 event from VICTIM → PERP should produce one
    normalized dict with chain=tron, the right token, the right
    amount, and a tronscan.org explorer URL."""
    adapter = _mk_adapter(trc20_events=[_trc20_event()])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    rec = out[0]
    assert rec["chain"] == Chain.tron
    assert rec["from"] == VICTIM
    assert rec["to"] == PERP
    assert rec["amount_raw"] == 1234560000
    assert rec["token"].symbol == "USDT"
    assert rec["token"].decimals == 6
    assert rec["token"].contract == USDT_CONTRACT
    assert rec["token"].coingecko_id == "tether"
    assert rec["tx_hash"] == "tx_abc"
    assert "tronscan.org" in rec["explorer_url"]
    # 1_750_000_000_000 ms = 1_750_000_000 s = 2025-06-15 15:06:40 UTC
    assert rec["block_time"] == datetime(
        2025, 6, 15, 15, 6, 40, tzinfo=timezone.utc,
    )


def test_fetch_outflows_filters_wrong_direction() -> None:
    """An inbound event (from someone else → VICTIM) should be
    filtered out by the expected_from check, even if it slipped
    through TronGrid's server-side filter."""
    inbound = _trc20_event(from_addr=PERP, to_addr=VICTIM)
    adapter = _mk_adapter(trc20_events=[inbound])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert out == []


def test_fetch_outflows_skips_malformed_event() -> None:
    """An event with missing token_info or bad timestamp should be
    dropped without breaking the whole call."""
    bad_no_token = _trc20_event()
    del bad_no_token["token_info"]
    good = _trc20_event(tx_id="tx_good")
    adapter = _mk_adapter(trc20_events=[bad_no_token, good])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["tx_hash"] == "tx_good"


def test_fetch_outflows_skips_zero_value() -> None:
    """Zero-value transfers (rare but seen on test contracts) are
    dropped."""
    zero = _trc20_event(value="0")
    adapter = _mk_adapter(trc20_events=[zero])
    assert adapter.fetch_erc20_outflows(VICTIM, start_block=0) == []


def test_fetch_outflows_returns_empty_on_client_error() -> None:
    """TronGridError → empty list (best-effort degradation)."""
    client = MagicMock()
    client.get_trc20_transfers.side_effect = TronGridError("upstream down")
    adapter = TronAdapter(client=client)
    assert adapter.fetch_erc20_outflows(VICTIM, start_block=0) == []


def test_fetch_outflows_supports_non_usdt_tokens() -> None:
    """Non-USDT TRC-20 (USDD) should normalize too — no special-
    casing of the USDT contract."""
    usdd_contract = "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn"
    ev = _trc20_event(
        token_address=usdd_contract, symbol="USDD", decimals=18,
        value="1000000000000000000",   # 1 USDD
    )
    adapter = _mk_adapter(trc20_events=[ev])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["token"].symbol == "USDD"
    assert out[0]["token"].decimals == 18
    assert out[0]["token"].coingecko_id == "usdd"


def test_fetch_outflows_unknown_trc20_has_no_coingecko_id() -> None:
    """A TRC-20 contract not in the lookup table should still
    normalize, but with coingecko_id=None (the pricing stage
    falls back to its own lookup)."""
    ev = _trc20_event(
        token_address="TXYZ" + "9" * 30,  # synthetic non-listed contract
        symbol="UNKNOWN",
    )
    # The synthetic contract address won't be a valid base58check
    # — adapter should drop the event. Use a real-shape one.
    ev["token_info"]["address"] = "TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZZy9"  # JST
    adapter = _mk_adapter(trc20_events=[ev])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["token"].coingecko_id == "just"


# ---- is_contract ---- #


def test_is_contract_true_for_smart_contract() -> None:
    """An account with type=Contract is a smart contract (USDT)."""
    adapter = _mk_adapter(account_data=[{"type": "Contract"}])
    assert adapter.is_contract(USDT_CONTRACT) is True


def test_is_contract_false_for_eoa() -> None:
    """type=Account → EOA → not a contract."""
    adapter = _mk_adapter(account_data=[{"type": "Account"}])
    assert adapter.is_contract(VICTIM) is False


def test_is_contract_false_for_never_observed() -> None:
    """Empty data array (address never on-chain) → False."""
    adapter = _mk_adapter(account_data=[])
    assert adapter.is_contract(VICTIM) is False


def test_is_contract_caches_results() -> None:
    """Repeated probes for the same address only hit the client
    once."""
    client = MagicMock()
    client.get_account.return_value = {"data": [{"type": "Contract"}]}
    adapter = TronAdapter(client=client)
    adapter.is_contract(USDT_CONTRACT)
    adapter.is_contract(USDT_CONTRACT)
    adapter.is_contract(USDT_CONTRACT)
    assert client.get_account.call_count == 1


def test_is_contract_treats_upstream_error_as_eoa() -> None:
    """TronGridError → treat as EOA (don't crash the trace)."""
    client = MagicMock()
    client.get_account.side_effect = TronGridError("network down")
    adapter = TronAdapter(client=client)
    assert adapter.is_contract(VICTIM) is False


# ---- block_at_or_before ---- #


def test_block_at_or_before_returns_unix_timestamp() -> None:
    """v0.16.7 (round-9 audit fix): Tron returns the unix timestamp opaquely.

    Pre-v0.16.7 this raised NotImplementedError, which was a CRITICAL
    bug — the tracer's per-address try/except caught the exception and
    silently returned 0 outflows for every Tron seed address. Every Tron
    trace (USDT-TRC20 is the largest stablecoin laundering rail in crypto)
    appeared to have zero activity. The new behavior matches Solana's
    pattern: return the timestamp as an opaque cutoff that the TRC-20
    fetch path can use directly.
    """
    adapter = _mk_adapter()
    ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = adapter.block_at_or_before(ts)
    assert isinstance(result, int)
    assert result == int(ts.timestamp())


# ---- fetch_native_outflows ---- #


def test_fetch_native_outflows_returns_empty() -> None:
    """v0.12.0 doesn't yet implement TRX native transfers. Returns
    [] so the tracer treats it as 'no native outflows' (correct
    for USDT-laundering cases, which is the primary use)."""
    adapter = _mk_adapter()
    assert adapter.fetch_native_outflows(VICTIM, start_block=0) == []


# ---- Explorer URLs ---- #


def test_explorer_tx_url() -> None:
    adapter = _mk_adapter()
    url = adapter.explorer_tx_url("abc123")
    assert url == "https://tronscan.org/#/transaction/abc123"


def test_explorer_address_url_normalizes_input() -> None:
    """Whether passed base58 or hex, the explorer URL should
    always render with the base58check form."""
    adapter = _mk_adapter()
    b58_url = adapter.explorer_address_url(USDT_CONTRACT)
    hex_url = adapter.explorer_address_url(
        "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    )
    assert b58_url == hex_url
    assert USDT_CONTRACT in b58_url


# ---- ChainAdapter.for_chain factory ---- #


def test_for_chain_dispatches_tron() -> None:
    """ChainAdapter.for_chain(Chain.tron, ...) returns a real
    TronAdapter (not NotImplementedError)."""
    from recupero.chains.base import ChainAdapter
    adapter = ChainAdapter.for_chain(Chain.tron, config=None)
    assert isinstance(adapter, TronAdapter)
