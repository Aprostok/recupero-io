"""Tests for v0.14.10 onward-CEX subpoena synthesis.

The pattern Jacob's V-CFI01 review surfaced: when a freezable-token
destination forwards to a CEX-labeled address, we want BOTH the
freeze letter to the issuer AND the subpoena letter to the CEX,
citing the same flow. synthesize_onward_cex_subpoenas() emits the
linkage records.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.freeze.asks import (
    OnwardCEXFlow,
    group_onward_cex_flows_by_exchange,
    synthesize_onward_cex_subpoenas,
)
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)

VICTIM = "0x" + "a" * 40
FREEZABLE_DEST = "0x" + "b" * 40   # holds USDT — upstream freeze target
BINANCE_HOT = "0x" + "c" * 40      # CEX-labeled
COINBASE_HOT = "0x" + "d" * 40     # also CEX-labeled
UNLABELED = "0x" + "e" * 40        # no label


USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def _label(addr: str, *, category: LabelCategory, name: str,
           exchange: str | None = None) -> Label:
    return Label(
        address=addr,
        name=name,
        category=category,
        exchange=exchange,
        source="test",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    counterparty_label: Label | None = None,
    usd: Decimal = Decimal("50000"),
    tx_hash: str | None = None,
    block_time: datetime | None = None,
    token_symbol: str = "USDT",
) -> Transfer:
    block_time = block_time or datetime(2025, 10, 14, tzinfo=UTC)
    tx_hash = tx_hash or "0x" + "1" * 64
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=counterparty_label, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract=USDT_CONTRACT, symbol=token_symbol,
            decimals=6, coingecko_id="tether",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="V-CFI01-test",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2025, 10, 9, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 5, 18, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


class _FakeLabelStore:
    """Minimal LabelStore stub — looks up by address, returns Label.

    v0.18.0 (round-11 freeze.asks-CRIT-007): accepts optional
    `chain=` kwarg to match the real LabelStore.lookup signature.
    Existing tests pass EVM hex (lowercased) so we still key on
    `address.lower()` for back-compat; a chain-aware fake would
    canonical-key. Tests that need base58 chain-aware lookups should
    use the real LabelStore.
    """
    def __init__(self, labels: dict[str, Label]) -> None:
        self._labels = {k.lower(): v for k, v in labels.items()}

    def lookup(self, address: str, chain=None) -> Label | None:  # noqa: ARG002
        return self._labels.get(address.lower())


# ---- Headline V-CFI01 acceptance ---- #


def test_freezable_destination_forwarding_to_cex_emits_subpoena() -> None:
    """The headline pattern: address A holds USDT (freezable),
    forwards $45K USDT to Binance hot wallet B. Synthesizer emits
    OnwardCEXFlow(A → B, $45K, Binance)."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4", exchange="Binance",
    )
    transfers = [
        # Victim → freezable destination (sets up the upstream).
        _mk_transfer(from_addr=VICTIM, to_addr=FREEZABLE_DEST,
                     usd=Decimal("50000"), tx_hash="0xupstream"),
        # Freezable destination → Binance (the onward flow).
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
            usd=Decimal("45000"), tx_hash="0xonward",
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_label})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert len(flows) == 1
    flow = flows[0]
    assert flow.upstream_address == FREEZABLE_DEST.lower()
    assert flow.cex_address == BINANCE_HOT.lower()
    assert flow.exchange == "Binance"
    assert flow.flow_usd_value == Decimal("45000")
    assert flow.transfer_count == 1
    assert flow.token_symbol == "USDT"
    assert flow.tx_hashes == ["0xonward"]


def test_no_upstream_targets_returns_empty() -> None:
    """If upstream_freeze_target_addresses is empty, no flows emit
    regardless of CEX activity in the trace."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4", exchange="Binance",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_label})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses=set(),
        label_store=label_store,
    )
    assert flows == []


def test_non_cex_destinations_filtered() -> None:
    """Transfer from upstream to an unlabeled / non-CEX address →
    not a subpoena candidate. Tested by checking that no flow emits
    when the to_address has no CEX label."""
    transfers = [
        _mk_transfer(from_addr=FREEZABLE_DEST, to_addr=UNLABELED,
                     usd=Decimal("50000")),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({})  # nothing labeled
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert flows == []


def test_below_threshold_filtered() -> None:
    """A $500 onward flow is below the $1K threshold → no
    subpoena record."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4", exchange="Binance",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
            usd=Decimal("500"),
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_label})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
        min_flow_usd=Decimal("1000"),
    )
    assert flows == []


def test_aggregates_multiple_transfers_to_same_cex() -> None:
    """Three $10K USDT transfers from A → Binance aggregate into
    one OnwardCEXFlow(A→Binance, $30K, count=3)."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4", exchange="Binance",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
            usd=Decimal("10000"), tx_hash=f"0xtx{i}",
            block_time=datetime(2025, 10, 14 + i, tzinfo=UTC),
        )
        for i in range(3)
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_label})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert len(flows) == 1
    flow = flows[0]
    assert flow.flow_usd_value == Decimal("30000")
    assert flow.transfer_count == 3
    assert len(flow.tx_hashes) == 3
    # First / last flow times reflect the temporal spread.
    assert flow.first_flow_at == datetime(2025, 10, 14, tzinfo=UTC)
    assert flow.last_flow_at == datetime(2025, 10, 16, tzinfo=UTC)


def test_multiple_cex_destinations_emit_separately() -> None:
    """Flows to Binance + Coinbase get separate OnwardCEXFlow rows
    so per-exchange subpoenas can be drafted independently."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4", exchange="Binance",
    )
    coinbase_label = _label(
        COINBASE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Coinbase: Hot Wallet 1", exchange="Coinbase",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
            usd=Decimal("45000"), tx_hash="0xbnb",
        ),
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=COINBASE_HOT,
            counterparty_label=coinbase_label,
            usd=Decimal("120000"), tx_hash="0xcb",
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({
        BINANCE_HOT: binance_label,
        COINBASE_HOT: coinbase_label,
    })
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert len(flows) == 2
    exchanges = {f.exchange for f in flows}
    assert exchanges == {"Binance", "Coinbase"}


def test_sorted_by_flow_usd_descending() -> None:
    """Highest USD first — operator sees the most consequential
    subpoena candidate at the top."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance", exchange="Binance",
    )
    coinbase_label = _label(
        COINBASE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Coinbase", exchange="Coinbase",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label,
            usd=Decimal("45000"), tx_hash="0xbnb",
        ),
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=COINBASE_HOT,
            counterparty_label=coinbase_label,
            usd=Decimal("120000"), tx_hash="0xcb",
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({
        BINANCE_HOT: binance_label, COINBASE_HOT: coinbase_label,
    })
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert flows[0].exchange == "Coinbase"
    assert flows[1].exchange == "Binance"


def test_exchange_deposit_category_also_qualifies() -> None:
    """Both 'exchange_hot_wallet' AND 'exchange_deposit' categories
    qualify as subpoena targets — they're different lookup types
    but both routes lead to CEX compliance subpoena."""
    binance_deposit = _label(
        BINANCE_HOT, category=LabelCategory.exchange_deposit,
        name="Binance: User Deposit 14582", exchange="Binance",
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_deposit,
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_deposit})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert len(flows) == 1
    assert flows[0].label_category == "exchange_deposit"


def test_exchange_name_parsed_from_label_when_no_exchange_field() -> None:
    """When label.exchange is None, fall back to parsing from
    label.name (the 'Binance: ...' convention). Older labels may
    lack the exchange field."""
    binance_label = _label(
        BINANCE_HOT, category=LabelCategory.exchange_hot_wallet,
        name="Binance: Hot Wallet 4",  # no exchange= kwarg
    )
    # Strip the exchange field manually for the test.
    binance_label_no_exch = Label(
        address=BINANCE_HOT,
        name="Binance: Hot Wallet 4",
        category=LabelCategory.exchange_hot_wallet,
        exchange=None,
        source="test",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    transfers = [
        _mk_transfer(
            from_addr=FREEZABLE_DEST, to_addr=BINANCE_HOT,
            counterparty_label=binance_label_no_exch,
        ),
    ]
    case = _mk_case(transfers)
    label_store = _FakeLabelStore({BINANCE_HOT: binance_label_no_exch})
    flows = synthesize_onward_cex_subpoenas(
        case,
        upstream_freeze_target_addresses={FREEZABLE_DEST},
        label_store=label_store,
    )
    assert flows[0].exchange == "Binance"


# ---- group_onward_cex_flows_by_exchange ---- #


def test_group_by_exchange() -> None:
    binance = OnwardCEXFlow(
        upstream_address="0xa", cex_address="0xb",
        chain=Chain.ethereum, exchange="Binance",
        label_name="x", label_category="exchange_hot_wallet",
        token_symbol="USDT", flow_usd_value=Decimal("10000"),
        flow_amount_decimal=Decimal("10000"),
        transfer_count=1,
        first_flow_at=datetime(2025, 10, 14, tzinfo=UTC),
        last_flow_at=datetime(2025, 10, 14, tzinfo=UTC),
        upstream_explorer_url="", cex_explorer_url="",
        tx_hashes=["0x1"],
    )
    coinbase = OnwardCEXFlow(
        upstream_address="0xa", cex_address="0xc",
        chain=Chain.ethereum, exchange="Coinbase",
        label_name="x", label_category="exchange_hot_wallet",
        token_symbol="USDT", flow_usd_value=Decimal("5000"),
        flow_amount_decimal=Decimal("5000"),
        transfer_count=1,
        first_flow_at=datetime(2025, 10, 14, tzinfo=UTC),
        last_flow_at=datetime(2025, 10, 14, tzinfo=UTC),
        upstream_explorer_url="", cex_explorer_url="",
        tx_hashes=["0x2"],
    )
    grouped = group_onward_cex_flows_by_exchange([binance, coinbase])
    assert set(grouped.keys()) == {"Binance", "Coinbase"}
    assert grouped["Binance"] == [binance]
    assert grouped["Coinbase"] == [coinbase]


# ---- short_summary ---- #


def test_short_summary_includes_essentials() -> None:
    flow = OnwardCEXFlow(
        upstream_address="0x" + "a" * 40, cex_address="0x" + "b" * 40,
        chain=Chain.ethereum, exchange="Binance",
        label_name="x", label_category="exchange_hot_wallet",
        token_symbol="USDT", flow_usd_value=Decimal("45000"),
        flow_amount_decimal=Decimal("45000"),
        transfer_count=3,
        first_flow_at=datetime(2025, 10, 14, tzinfo=UTC),
        last_flow_at=datetime(2025, 10, 16, tzinfo=UTC),
        upstream_explorer_url="", cex_explorer_url="",
        tx_hashes=["0x1", "0x2", "0x3"],
    )
    summary = flow.short_summary()
    assert "$45,000.00" in summary
    assert "USDT" in summary
    assert "Binance" in summary
    assert "3 transfer(s)" in summary
