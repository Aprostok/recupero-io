"""Tests for v0.32.1 CEX deposit-address attribution (#209 step 2).

infer_cex_deposit_addresses() attributes an UNLABELED address that sweeps
funds into a known CEX hot wallet to the exchange behind it — a subpoena
LEAD for the per-user deposit address. Forensic invariant: an inferred
attribution is never "high" confidence (only label-DB hits are); the
sweep heuristic emits "medium" for a clean full-balance sweep to a single
hot wallet, "low" otherwise.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.cex_attribution import (
    InferredCexDeposit,
    infer_cex_deposit_addresses,
)

PERP = "0x" + "a" * 40
DEPOSIT = "0x" + "d" * 40          # unlabeled per-user deposit address
BINANCE_HOT = "0x" + "c" * 40      # known CEX hot wallet
COINBASE_HOT = "0x" + "f" * 40     # another known CEX hot wallet
OTHER = "0x" + "e" * 40            # unlabeled, not a hot wallet
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _label(addr: str, *, exchange: str) -> Label:
    return Label(
        address=addr, name=f"{exchange} hot wallet",
        category=LabelCategory.exchange_hot_wallet,
        exchange=exchange, source="test", confidence="high",
        added_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _mk_transfer(
    *, from_addr: str, to_addr: str, usd: Decimal,
    block_time: datetime = T0, tx_suffix: str = "1",
    chain: Chain = Chain.ethereum,
) -> Transfer:
    tx_hash = "0x" + (tx_suffix * 64)[:64]
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:0",
        chain=chain, tx_hash=tx_hash, block_number=1, block_time=block_time,
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                       symbol="USDC", decimals=6, coingecko_id="usd-coin"),
        amount_raw=str(int(usd * 10**6)), amount_decimal=usd,
        usd_value_at_tx=usd, hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}", fetched_at=block_time,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="cex-attr-test", seed_address=PERP, chain=Chain.ethereum,
        incident_time=T0, transfers=transfers, trace_started_at=T0,
        software_version="test", config_used={},
    )


class _FakeLabelStore:
    def __init__(self, labels: dict[str, Label]) -> None:
        self._labels = {k.lower(): v for k, v in labels.items()}

    def lookup(self, address: str, chain=None) -> Label | None:  # noqa: ARG002
        return self._labels.get(address.lower())


# ───────────────────────── core sweep attribution ──────────────────────


def test_clean_full_sweep_to_single_hot_wallet_is_medium() -> None:
    """perp → D → Binance, D forwards 100% to a single hot wallet → the
    classic per-user deposit sweep → confidence MEDIUM (never high)."""
    store = _FakeLabelStore({BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance")})
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("100000"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("100000"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert len(out) == 1
    dep = out[0]
    assert isinstance(dep, InferredCexDeposit)
    assert dep.deposit_address == DEPOSIT
    assert dep.exchange == "Binance"
    assert dep.hot_wallet_address == BINANCE_HOT
    assert dep.heuristic == "sweep_to_hot_wallet"
    assert dep.confidence == "medium"
    assert dep.swept_usd == Decimal("100000")
    assert dep.swept_ratio is not None and dep.swept_ratio >= 0.99
    assert dep.supporting_tx_hashes == ("0x" + ("2" * 64)[:64],)


def test_partial_forward_is_low_confidence() -> None:
    """D forwards only 40% of its inflow to the hot wallet (keeps/sends
    the rest elsewhere) → ambiguous → LOW confidence."""
    store = _FakeLabelStore({BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance")})
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("100000"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("40000"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=OTHER, usd=Decimal("60000"),
                     block_time=T0 + timedelta(hours=2), tx_suffix="3"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert len(out) == 1
    assert out[0].confidence == "low"
    assert out[0].swept_ratio is not None and out[0].swept_ratio < 0.5


def test_sweep_to_two_hot_wallets_is_low_even_if_full() -> None:
    """D forwarding to TWO different hot wallets is not a clean single-
    deposit sweep → LOW even though the full balance is forwarded."""
    store = _FakeLabelStore({
        BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance"),
        COINBASE_HOT: _label(COINBASE_HOT, exchange="Coinbase"),
    })
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("100000"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("50000"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=COINBASE_HOT, usd=Decimal("50000"),
                     block_time=T0 + timedelta(hours=2), tx_suffix="3"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert {d.exchange for d in out} == {"Binance", "Coinbase"}
    assert all(d.confidence == "low" for d in out)


def test_labeled_sender_is_excluded() -> None:
    """A labeled sender (CEX hot wallet rebalancing into another CEX) is
    infra-to-infra, NOT a user deposit — must not be attributed."""
    store = _FakeLabelStore({
        BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance"),
        COINBASE_HOT: _label(COINBASE_HOT, exchange="Coinbase"),
    })
    case = _mk_case([
        _mk_transfer(from_addr=COINBASE_HOT, to_addr=BINANCE_HOT,
                     usd=Decimal("500000"), tx_suffix="2"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert out == []


def test_dust_sweep_excluded() -> None:
    """A sub-$100 forward to a hot wallet is noise, not a subpoena-worthy
    deposit."""
    store = _FakeLabelStore({BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance")})
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("50"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("50"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert out == []


def test_no_label_store_returns_empty() -> None:
    """Without a label store we can't identify hot wallets → empty."""
    case = _mk_case([
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("100000")),
    ])
    assert infer_cex_deposit_addresses(case, label_store=None) == []


def test_empty_case_returns_empty() -> None:
    store = _FakeLabelStore({BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance")})
    assert infer_cex_deposit_addresses(_mk_case([]), label_store=store) == []


def test_inferred_confidence_is_never_high() -> None:
    """FORENSIC INVARIANT: an inferred attribution is a LEAD, never proof.
    Across every shape, confidence must be low/medium — never high."""
    store = _FakeLabelStore({
        BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance"),
        COINBASE_HOT: _label(COINBASE_HOT, exchange="Coinbase"),
    })
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("1000000"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("1000000"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
        _mk_transfer(from_addr=PERP, to_addr=OTHER, usd=Decimal("500000"), tx_suffix="3"),
        _mk_transfer(from_addr=OTHER, to_addr=COINBASE_HOT, usd=Decimal("250000"),
                     block_time=T0 + timedelta(hours=3), tx_suffix="4"),
    ])
    out = infer_cex_deposit_addresses(case, label_store=store)
    assert out, "expected at least one inferred deposit"
    assert all(d.confidence in ("low", "medium") for d in out)
    assert not any(d.confidence == "high" for d in out)


def test_to_dict_shape_for_subpoena_wiring() -> None:
    """to_dict() emits the shape extract_subpoena_targets consumes:
    source prefixed 'inferred:', attribution_confidence/heuristic, and
    tx_hashes for the evidence."""
    store = _FakeLabelStore({BINANCE_HOT: _label(BINANCE_HOT, exchange="Binance")})
    case = _mk_case([
        _mk_transfer(from_addr=PERP, to_addr=DEPOSIT, usd=Decimal("100000"), tx_suffix="1"),
        _mk_transfer(from_addr=DEPOSIT, to_addr=BINANCE_HOT, usd=Decimal("100000"),
                     block_time=T0 + timedelta(hours=1), tx_suffix="2"),
    ])
    d = infer_cex_deposit_addresses(case, label_store=store)[0].to_dict()
    assert d["address"] == DEPOSIT
    assert d["exchange"] == "Binance"
    assert d["source"] == "inferred:sweep_to_hot_wallet"
    assert d["attribution_heuristic"] == "sweep_to_hot_wallet"
    assert d["attribution_confidence"] == "medium"
    assert d["chain"] == "ethereum"
    assert d["tx_hashes"] == ["0x" + ("2" * 64)[:64]]
