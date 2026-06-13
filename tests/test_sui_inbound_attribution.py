"""Sui inbound source-attribution: prefer the on-chain payer over the tx signer.

For an inbound edge the forensically-correct 'from' is whoever's balance of that
coin DECREASED (the real payer), not the tx signer — a DEX router / relayer /
sponsor signs but is often not the fund source. These tests lock in that the
single unambiguous decreaser wins over ``sender``, with the signer only a
fallback when the payer is ambiguous.
"""
from __future__ import annotations

from recupero.chains.sui.adapter import SuiAdapter

F = "0x" + "f" * 64        # focus (receiver)
P = "0x" + "1" * 64        # the real payer (balance decreaser)
R = "0x" + "2" * 64        # a router/relayer/sponsor (tx signer, NOT a payer)
Q = "0x" + "3" * 64        # a second payer
_attr = SuiAdapter._attribute_source


def test_single_payer_wins_over_signer():
    # Router R signs, but wallet P is the sole coin decreaser → source is P.
    by_addr = {F: 100, P: -100}
    assert _attr(R, F, by_addr) == P


def test_signer_used_when_it_is_the_payer():
    # The common simple-transfer case: signer P is also the sole decreaser.
    by_addr = {F: 100, P: -100}
    assert _attr(P, F, by_addr) == P


def test_no_addressowner_payer_falls_back_to_signer():
    # Coin came from a pool/object (no non-focus decreaser); the signer R is the
    # best available attribution.
    by_addr = {F: 100}
    assert _attr(R, F, by_addr) == R


def test_no_payer_and_self_signed_is_unknown():
    # focus initiated a swap (signer == focus), coin from a pool → unknown source,
    # never a fabricated address.
    by_addr = {F: 100}
    assert _attr(F, F, by_addr) == "sui:unknown_source"


def test_ambiguous_payers_prefer_signer_if_among_them():
    # Two payers P and Q; the signer Q is one of them → most specific honest pick.
    by_addr = {F: 150, P: -100, Q: -50}
    assert _attr(Q, F, by_addr) == Q


def test_ambiguous_payers_signer_not_a_payer_uses_largest():
    # Two payers; signer R isn't one of them → fall back to the largest payer (P).
    by_addr = {F: 150, P: -100, Q: -50}
    assert _attr(R, F, by_addr) == P


def test_invalid_signer_with_single_payer():
    by_addr = {F: 100, P: -100}
    assert _attr(None, F, by_addr) == P
    assert _attr("not-an-address", F, by_addr) == P


# --- end-to-end: the corrected attribution flows through an inbound fetch --- #
_USDC = ("0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7"
         "::usdc::USDC")


class _StubClient:
    def __init__(self, page):
        self._page = page

    def query_transaction_blocks(self, tx_filter, *, cursor=None, limit=50,
                                 descending=True):
        return {"data": self._page, "nextCursor": None, "hasNextPage": False}

    def get_coin_metadata(self, coin_type):
        return None

    def close(self):
        pass


def test_inbound_edge_uses_payer_not_router_end_to_end():
    # Router R signs; P pays 100 USDC to focus F. The inbound edge's 'from' must
    # be P (the payer), not R (the signer).
    tx = {
        "digest": "DIGX", "timestampMs": "1781311239440",
        "transaction": {"data": {"sender": R}},
        "balanceChanges": [
            {"owner": {"AddressOwner": P}, "coinType": _USDC, "amount": "-100000000"},
            {"owner": {"AddressOwner": F}, "coinType": _USDC, "amount": "100000000"},
        ],
    }
    ad = SuiAdapter(client=_StubClient([tx]), max_pages=1)
    rows = ad.fetch_erc20_inflows(F)
    assert len(rows) == 1
    assert rows[0]["from"] == P and rows[0]["to"] == F
    assert rows[0]["amount_raw"] == 100000000
