"""Unit tests for pure Solana adapter helpers.

The Solana adapter's main surface (Helius RPC, transaction fetching,
SPL token parsing) is I/O-bound and not worth mocking out at the
unit level — it gets integration coverage via end-to-end runs. But
the pure helpers are easy to lock in and exactly the kind of code
that breaks silently when a mint changes coingecko_id or a new
stablecoin lands:

  * ``_symbol_from_mint`` — known-SPL-mint → human symbol mapping.
    These are calendar facts (USDC's mint won't change), but adding
    a new mint without testing is the regression class to guard
    against.
  * ``_MINT_TO_COINGECKO_ID`` — the same idea for pricing lookups.
    If this gets out of sync with reality, pricing fails silently
    and the case shows $0 for all SPL transfers.
  * ``SolanaAdapter.block_at_or_before`` — pure timestamp conversion,
    no network. Verifies tz handling.

Tests run in <50ms, zero network, zero DB.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from recupero.chains.solana.adapter import (
    USDC_SOLANA_MINT,
    USDT_SOLANA_MINT,
    WRAPPED_SOL_MINT,
    SolanaAdapter,
    _MINT_TO_COINGECKO_ID,
    _symbol_from_mint,
)


# ---- _symbol_from_mint ---- #


def test_symbol_usdc() -> None:
    """USDC mint → 'USDC'. Compliance teams scan for the symbol when
    deciding whether to route a freeze letter."""
    assert _symbol_from_mint(USDC_SOLANA_MINT) == "USDC"


def test_symbol_usdt() -> None:
    assert _symbol_from_mint(USDT_SOLANA_MINT) == "USDT"


def test_symbol_wsol() -> None:
    """Wrapped SOL → 'WSOL'. Native SOL doesn't go through SPL token
    program; only wrapped variant has a mint."""
    assert _symbol_from_mint(WRAPPED_SOL_MINT) == "WSOL"


def test_symbol_jito_staked() -> None:
    """JitoSOL LST. Important for tracing through liquid-staking
    activity — operators see JitoSOL holdings in the trace report."""
    assert _symbol_from_mint("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn") == "JitoSOL"


def test_symbol_marinade() -> None:
    assert _symbol_from_mint("mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So") == "mSOL"


def test_symbol_bonk() -> None:
    assert _symbol_from_mint("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263") == "BONK"


def test_symbol_jup() -> None:
    assert _symbol_from_mint("JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN") == "JUP"


def test_symbol_unknown_falls_back_to_first_4_chars() -> None:
    """Unknown mints return the first 4 chars rather than empty —
    keeps the trace report's destinations table non-empty when an
    operator points at a wallet holding an unrecognized token. The
    operator can still see "Aaaaa…" and look up the full mint
    manually."""
    fake_mint = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdef"
    assert _symbol_from_mint(fake_mint) == "AbCd"


def test_symbol_empty_mint_returns_question_mark() -> None:
    """Empty / None mint → '?' rather than crashing. Defensive
    against malformed Helius responses."""
    assert _symbol_from_mint("") == "?"


# ---- _MINT_TO_COINGECKO_ID ---- #


def test_coingecko_mapping_covers_top_tokens() -> None:
    """The coingecko_id lookup must cover the top SPL stablecoins +
    native-equivalent tokens. Without these, pricing falls back to
    on-the-fly contract lookups and slows the trace to a crawl."""
    assert _MINT_TO_COINGECKO_ID[USDC_SOLANA_MINT] == "usd-coin"
    assert _MINT_TO_COINGECKO_ID[USDT_SOLANA_MINT] == "tether"
    assert _MINT_TO_COINGECKO_ID[WRAPPED_SOL_MINT] == "solana"


def test_coingecko_mapping_lst_tokens() -> None:
    """Liquid staking tokens have their own coingecko IDs (price
    diverges from SOL during slashing or fee accrual)."""
    assert (_MINT_TO_COINGECKO_ID["J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"]
            == "jito-staked-sol")
    assert (_MINT_TO_COINGECKO_ID["mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"]
            == "msol")


def test_coingecko_mapping_meme_tokens() -> None:
    """BONK / JUP — meme + governance tokens we've seen in real
    cases. Locked in because adding/removing them silently would
    change every trace's pricing accuracy."""
    assert _MINT_TO_COINGECKO_ID["DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"] == "bonk"
    assert (_MINT_TO_COINGECKO_ID["JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"]
            == "jupiter-exchange-solana")


def test_coingecko_mapping_all_real_mints() -> None:
    """Sanity: every key in the mapping is plausibly a real SPL mint
    (32+ base58 chars). Catches typos / fat-finger additions."""
    for mint, cg_id in _MINT_TO_COINGECKO_ID.items():
        assert len(mint) >= 32, f"mint too short: {mint!r}"
        assert cg_id, f"empty coingecko_id for mint {mint!r}"
        # base58 charset: alphanumeric except 0, O, I, l
        assert not any(c in mint for c in "0OIl"), (
            f"mint contains a non-base58 char: {mint!r}"
        )


# ---- SolanaAdapter.block_at_or_before ---- #


def _make_adapter() -> SolanaAdapter:
    """Helper: build a SolanaAdapter with a stub env that has a
    HELIUS_API_KEY (the constructor errors without one). We don't
    actually use the client in these tests — just the timestamp
    conversion logic."""
    from recupero.config import RecuperoConfig, RecuperoEnv
    cfg = RecuperoConfig()
    env = RecuperoEnv(HELIUS_API_KEY="test-key-not-used")
    return SolanaAdapter(bundle=(cfg, env))


def test_block_at_or_before_returns_unix_timestamp() -> None:
    """Solana adapter treats start_block as a unix timestamp, not a
    slot. This is a key design decision (Solana has no reliable
    "slot at timestamp" API) — locking it down so a future
    refactor doesn't accidentally change semantics."""
    a = _make_adapter()
    ts = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    out = a.block_at_or_before(ts)
    assert out == int(ts.timestamp())
    # Sanity: 2026-05-15 12:00 UTC = around 1.76 billion seconds.
    assert 1_700_000_000 < out < 1_900_000_000


def test_block_at_or_before_naive_datetime_assumed_utc() -> None:
    """A naive datetime (no tzinfo) should be treated as UTC, not
    local. This was the bug in earlier tracer.py versions where naive
    incident_times produced wrong block lookups."""
    a = _make_adapter()
    naive = datetime(2026, 5, 15, 12, 0)  # no tzinfo
    aware = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    assert a.block_at_or_before(naive) == a.block_at_or_before(aware)


def test_block_at_or_before_idempotent() -> None:
    """Same input → same output, every time. No clock drift
    (block_at_or_before isn't supposed to read NOW())."""
    a = _make_adapter()
    ts = datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert a.block_at_or_before(ts) == a.block_at_or_before(ts)


def test_block_at_or_before_monotonic() -> None:
    """Later timestamps produce strictly-larger return values.
    Defensive sanity — if this ever regresses, the tracer's
    block-window filtering breaks."""
    a = _make_adapter()
    early = datetime(2024, 1, 1, tzinfo=timezone.utc)
    later = datetime(2026, 5, 15, tzinfo=timezone.utc)
    assert a.block_at_or_before(early) < a.block_at_or_before(later)


# ---- ChainAdapter contract ---- #


def test_solana_adapter_requires_helius_key() -> None:
    """The constructor must fail loudly if HELIUS_API_KEY is missing.
    A worker started without the key would otherwise crash mid-trace
    with a less-clear "401 Unauthorized" — fail at construction
    instead."""
    from recupero.config import RecuperoConfig, RecuperoEnv
    cfg = RecuperoConfig()
    env = RecuperoEnv(HELIUS_API_KEY="")
    with pytest.raises(ValueError, match="HELIUS_API_KEY"):
        SolanaAdapter(bundle=(cfg, env))


def test_solana_adapter_chain_is_solana() -> None:
    """ChainAdapter.chain is what the dispatch logic in tracer.py
    keys on. Locking to Chain.solana so refactors can't silently
    swap it."""
    from recupero.models import Chain
    assert SolanaAdapter.chain == Chain.solana
