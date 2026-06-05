"""StellarAdapter (#9) — native XLM + issued-asset (USDC/USDT) payment outflows.

Fixtures mirror REAL horizon.stellar.org payment records captured before
implementation. Adapter logic uses an injected fake client; one respx test
covers the Horizon transport.
"""

from __future__ import annotations

import httpx
import respx

from recupero.chains.stellar.adapter import StellarAdapter
from recupero.chains.stellar.address import (
    is_stellar_address,
    normalize_stellar_address,
)
from recupero.chains.stellar.client import HorizonClient
from recupero.models import Chain

A = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
B = "GBF2VV4VTXG6VNFY54D7MUXZPTSMBDF3XHM73BXXF3VNZJQGATFYIHYD"
USDC_ISSUER = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4FAKE"
START = 1_600_000_000
LATER = "2026-01-01T00:00:00Z"
EARLY = "2019-01-01T00:00:00Z"


class _FakeClient:
    def __init__(self, records=None) -> None:
        self._records = records or []

    def get_payments(self, account, *, limit=100, cursor=None):  # noqa: ANN001
        return self._records

    def close(self) -> None:
        pass


def _payment(*, frm=A, to=B, amount="100.0000000", native=True, code=None,
             issuer=None, ok=True, created=LATER, txhash="abc123",
             ptype="payment"):
    rec = {
        "type": ptype, "transaction_successful": ok, "from": frm, "to": to,
        "amount": amount, "created_at": created, "transaction_hash": txhash,
    }
    if native:
        rec["asset_type"] = "native"
    else:
        rec["asset_type"] = "credit_alphanum4"
        rec["asset_code"] = code
        rec["asset_issuer"] = issuer
    return rec


def _adapter(records) -> StellarAdapter:
    return StellarAdapter(client=_FakeClient(records))


# ---- address ---- #


def test_address_validation() -> None:
    assert is_stellar_address(A)
    assert normalize_stellar_address(A) == A
    assert not is_stellar_address("0x" + "a" * 40)
    assert not is_stellar_address("MA5ZSEJYB")  # muxed/short → rejected


# ---- native XLM ---- #


def test_native_outflow_7_decimal_amount() -> None:
    a = _adapter([_payment(amount="4164.6400000")])
    rows = a.fetch_native_outflows(A, START)
    assert len(rows) == 1
    r = rows[0]
    assert r["chain"] == Chain.stellar
    assert r["from"] == A and r["to"] == B
    assert r["amount_raw"] == 41646400000  # 4164.64 * 1e7
    assert r["token"].symbol == "XLM" and r["token"].decimals == 7
    assert r["token"].coingecko_id == "stellar"
    assert r["explorer_url"].startswith("https://stellar.expert/explorer/public/tx/")


def test_native_filters_failed_inbound_self_old_and_nonpayment() -> None:
    recs = [
        _payment(ok=False),                       # failed
        _payment(frm=B),                          # inbound (from != account)
        _payment(to=A),                           # self
        _payment(created=EARLY),                  # before cutoff
        _payment(ptype="path_payment_strict_send"),  # not a plain payment
    ]
    assert _adapter(recs).fetch_native_outflows(A, START) == []


def test_asset_filtered_out_of_native() -> None:
    a = _adapter([_payment(native=False, code="USDC", issuer=USDC_ISSUER)])
    assert a.fetch_native_outflows(A, START) == []  # asset, not native


# ---- issued assets ---- #


def test_usdc_outflow_priced_and_identified() -> None:
    a = _adapter([_payment(native=False, code="USDC", issuer=USDC_ISSUER,
                           amount="500.0000000")])
    rows = a.fetch_erc20_outflows(A, START)
    assert len(rows) == 1
    tok = rows[0]["token"]
    assert tok.symbol == "USDC" and tok.decimals == 7
    assert tok.coingecko_id == "usd-coin"
    assert tok.contract == f"USDC-{USDC_ISSUER}"
    assert rows[0]["amount_raw"] == 5000000000


def test_unknown_asset_still_emitted_unpriced() -> None:
    a = _adapter([_payment(native=False, code="WXYZ", issuer=USDC_ISSUER)])
    rows = a.fetch_erc20_outflows(A, START)
    assert len(rows) == 1
    assert rows[0]["token"].symbol == "WXYZ"
    assert rows[0]["token"].coingecko_id is None  # priced by contract-resolution


def test_asset_missing_issuer_skipped() -> None:
    a = _adapter([_payment(native=False, code="USDC", issuer="")])
    assert a.fetch_erc20_outflows(A, START) == []


# ---- misc ---- #


def test_block_at_or_before_and_is_contract() -> None:
    from datetime import UTC, datetime
    a = _adapter([])
    assert a.is_contract(A) is False
    assert a.block_at_or_before(datetime(2026, 1, 1, tzinfo=UTC)) == int(
        datetime(2026, 1, 1, tzinfo=UTC).timestamp()
    )


@respx.mock
def test_client_get_payments_unwraps_embedded_records() -> None:
    c = HorizonClient(requests_per_second=10_000.0)
    respx.get(f"https://horizon.stellar.org/accounts/{A}/payments").mock(
        return_value=httpx.Response(200, json={
            "_embedded": {"records": [{"type": "payment", "amount": "1.0"}]},
        }),
    )
    out = c.get_payments(A, limit=1)
    assert out == [{"type": "payment", "amount": "1.0"}]


@respx.mock
def test_client_404_account_returns_empty() -> None:
    c = HorizonClient(requests_per_second=10_000.0)
    respx.get(f"https://horizon.stellar.org/accounts/{A}").mock(
        return_value=httpx.Response(404, json={"status": 404}),
    )
    assert c.get_account(A) == {}
