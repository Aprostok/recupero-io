"""#253 follow-up: address-poisoning AIRDROP-SPAM token filter.

A real no-answer-key trace of the OFAC-sanctioned Ronin exploiter found ONE
unpriceable contract ("Dream Cash"/CASH) accounting for 5,980 of 6,000 sampled
outflow rows — spoofed `from`, tiny repetitive amounts, no CoinGecko price. These
bypass the zero-value poison prune (non-zero amount) AND the USD dust floor
(usd=None). `prune_airdrop_spam` drops high-volume / phishing unpriceable tokens
WITHOUT regressing the "follow the largest UNPRICED leg" doctrine (a real unpriced
stolen leg appears too few times to trip the per-contract threshold).
"""

from __future__ import annotations

from typing import Any

from recupero.models import Chain, TokenRef
from recupero.trace.address_poisoning import (
    SPAM_TOKEN_MIN_TRANSFERS,
    classify_airdrop_spam_contracts,
    prune_airdrop_spam,
)

_CASH = "0x" + "c" * 40          # the spam broadcaster contract
_MSYRUP = "0x" + "5" * 40        # a real-but-unpriced stolen token (msyrupUSDp-like)
_USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def _t(contract: str | None, *, symbol: str, coingecko_id: str | None,
       as_model: bool = False) -> dict[str, Any]:
    """A transfer-shaped dict whose ``token`` is a dict (default) or a real
    TokenRef object (``as_model``) — the classifier must handle both."""
    if as_model:
        token: Any = TokenRef(
            chain=Chain.ethereum, contract=contract, symbol=symbol,
            decimals=18, coingecko_id=coingecko_id,
        )
    else:
        token = {"contract": contract, "symbol": symbol,
                 "coingecko_id": coingecko_id}
    return {"from_address": "0xseed", "to_address": "0xdest", "token": token}


def _many(n: int, **kw) -> list[dict[str, Any]]:
    return [_t(**kw) for _ in range(n)]


# ---- the dominant case: a high-volume unpriceable broadcaster ----

def test_high_volume_unpriced_contract_flagged_and_pruned() -> None:
    transfers = _many(30, contract=_CASH, symbol="CASH", coingecko_id=None)
    spam = classify_airdrop_spam_contracts(transfers)
    assert _CASH in spam
    kept, dropped = prune_airdrop_spam(transfers)
    assert kept == [] and len(dropped) == 30


def test_default_threshold_is_25() -> None:
    assert SPAM_TOKEN_MIN_TRANSFERS == 25
    # 24 is below the default threshold; 25 trips it.
    assert classify_airdrop_spam_contracts(
        _many(24, contract=_CASH, symbol="CASH", coingecko_id=None)) == set()
    assert _CASH in classify_airdrop_spam_contracts(
        _many(25, contract=_CASH, symbol="CASH", coingecko_id=None))


# ---- THE doctrine guard: a real unpriced stolen leg is preserved ----

def test_real_unpriced_leg_preserved() -> None:
    # msyrupUSDp arrives unpriced but only a couple of times — must NOT be spam.
    transfers = _many(2, contract=_MSYRUP, symbol="msyrupUSDp", coingecko_id=None)
    assert classify_airdrop_spam_contracts(transfers) == set()
    kept, dropped = prune_airdrop_spam(transfers)
    assert len(kept) == 2 and dropped == []


def test_priced_token_never_flagged_even_at_volume() -> None:
    # USDC has a coingecko id → priceable → never spam, regardless of count.
    transfers = _many(500, contract=_USDC, symbol="USDC", coingecko_id="usd-coin")
    assert classify_airdrop_spam_contracts(transfers) == set()
    assert prune_airdrop_spam(transfers)[1] == []


def test_native_asset_never_flagged() -> None:
    # Native ETH (no contract) at high volume is never spam-classified.
    transfers = _many(300, contract=None, symbol="ETH", coingecko_id="ethereum")
    assert classify_airdrop_spam_contracts(transfers) == set()
    assert prune_airdrop_spam(transfers)[1] == []


# ---- phishing-symbol marker (catches low-count overt phishing) ----

def test_phishing_symbol_flagged_low_count() -> None:
    # A single unpriced transfer whose symbol is an overt phishing lure.
    transfers = [_t(_CASH, symbol="claim-rewards.com", coingecko_id=None)]
    assert _CASH in classify_airdrop_spam_contracts(transfers)


def test_phishing_marker_gated_to_unpriceable() -> None:
    # A PRICED token whose symbol happens to contain a marker substring is NOT
    # flagged — the phishing check only runs on unpriceable tokens.
    transfers = _many(3, contract=_USDC, symbol="visit.io", coingecko_id="usd-coin")
    assert classify_airdrop_spam_contracts(transfers) == set()


# ---- realistic mixed set (the Ronin shape) ----

def test_mixed_set_drops_only_spam() -> None:
    transfers = (
        _many(40, contract=_CASH, symbol="CASH", coingecko_id=None)      # spam
        + _many(2, contract=_MSYRUP, symbol="msyrupUSDp", coingecko_id=None)  # real unpriced
        + _many(5, contract=_USDC, symbol="USDC", coingecko_id="usd-coin")    # real priced
        + _many(6, contract=None, symbol="ETH", coingecko_id="ethereum")     # native
    )
    kept, dropped = prune_airdrop_spam(transfers)
    assert len(dropped) == 40
    assert len(kept) == 13
    assert all((t["token"]["contract"] or "").lower() != _CASH for t in kept)


def test_no_spam_returns_all_kept() -> None:
    transfers = _many(5, contract=_USDC, symbol="USDC", coingecko_id="usd-coin")
    kept, dropped = prune_airdrop_spam(transfers)
    assert kept == transfers and dropped == []


def test_handles_tokenref_object_shape() -> None:
    # The classifier must read a real TokenRef object's .contract / .coingecko_id.
    transfers = _many(30, contract=_CASH, symbol="CASH", coingecko_id=None,
                      as_model=True)
    assert _CASH in classify_airdrop_spam_contracts(transfers)
    assert len(prune_airdrop_spam(transfers)[1]) == 30


def test_empty_and_garbage_safe() -> None:
    assert prune_airdrop_spam([]) == ([], [])
    junk = [{"token": None}, {}, {"token": {"contract": None}}]
    kept, dropped = prune_airdrop_spam(junk)
    assert dropped == [] and len(kept) == 3
