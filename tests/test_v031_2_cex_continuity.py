"""v0.31.2 — CEX trace continuity heuristic tests (Gap #15).

Covers `recupero.trace.cex_continuity.identify_cex_continuity_leads`
and the env-var parsing in the same module.

The heuristic surfaces INVESTIGATIVE LEADS when funds land at a labeled
CEX hot wallet AND the same hot wallet emits an amount-matched outflow
within a short time window. Output is confidence='low' by design —
operators decide whether to follow up.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import pytest

from recupero.labels.store import LabelStore
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.cex_continuity import (
    CexContinuityLead,
    env_continuity_enabled,
    env_min_usd,
    env_window_hours,
    identify_cex_continuity_leads,
    leads_to_brief_section,
)


# ─────────────────────────────────────────────────────────────────────────────
# Test fixtures
# ─────────────────────────────────────────────────────────────────────────────


_INCIDENT_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_BINANCE_HOT = "0x28C6c06298d514Db089934071355E5743bf21d60"  # real seed entry
_COINBASE_HOT = "0x71660c4005BA85c37ccec55d0C4493E66Fe775d3"  # real seed entry
_VICTIM = "0x1111111111111111111111111111111111111111"
_PERP = "0x2222222222222222222222222222222222222222"
_NEW_ADDR_A = "0x3333333333333333333333333333333333333333"
_NEW_ADDR_B = "0x4444444444444444444444444444444444444444"


def _mk_token(symbol: str, decimals: int = 6) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        symbol=symbol,
        decimals=decimals,
        coingecko_id=symbol.lower(),
    )


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal | None,
    token_symbol: str = "WBTC",
    decimals: int = 8,
    amount_decimal: Decimal | None = None,
    block_time: datetime | None = None,
    log_index: int = 0,
    block_number: int = 1_000_000,
) -> Transfer:
    """Synthetic transfer for the deposit side."""
    tx_hash = "0x" + f"{abs(hash((from_addr, to_addr, token_symbol, log_index, block_number))):x}".rjust(64, "0")[:64]
    amount = amount_decimal if amount_decimal is not None else Decimal("1")
    amount_raw = str(int(amount * (Decimal(10) ** decimals)))
    bt = block_time or _INCIDENT_TIME
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:{log_index}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=block_number,
        block_time=bt,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=_mk_token(token_symbol, decimals=decimals),
        amount_raw=amount_raw,
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=bt,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="01234567-89ab-cdef-0123-456789abcdef",
        seed_address=_VICTIM,
        chain=Chain.ethereum,
        incident_time=_INCIDENT_TIME,
        transfers=transfers,
        trace_started_at=_INCIDENT_TIME,
    )


def _mk_label_store(*entries: tuple[str, str, str]) -> LabelStore:
    """Build a tiny in-memory label store. Each entry: (address, name, exchange).
    Category is exchange_hot_wallet by default."""
    store = LabelStore()
    for addr, name, exch in entries:
        lbl = Label(
            address=addr,
            name=name,
            category=LabelCategory.exchange_hot_wallet,
            exchange=exch,
            source="test:fixture",
            confidence="high",
            added_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        store.add(lbl)
    return store


def _mk_outflow_row(
    *,
    to_addr: str,
    block_time: datetime,
    token_symbol: str,
    decimals: int,
    amount_decimal: Decimal,
    tx_hash: str | None = None,
) -> dict[str, Any]:
    """Mimic the dict shape returned by adapter.fetch_native_outflows /
    fetch_erc20_outflows (see chains/base.py docstring + chains/evm/adapter.py
    _normalize_native/_normalize_erc20)."""
    th = tx_hash or "0x" + f"{abs(hash((to_addr, token_symbol, amount_decimal, block_time))):x}".rjust(64, "0")[:64]
    return {
        "chain": Chain.ethereum,
        "tx_hash": th,
        "block_number": 1_001_000,
        "block_time": block_time,
        "log_index": 0,
        "from": _BINANCE_HOT,
        "to": to_addr,
        "token": _mk_token(token_symbol, decimals=decimals),
        "amount_raw": int(amount_decimal * (Decimal(10) ** decimals)),
        "explorer_url": f"https://etherscan.io/tx/{th}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Core happy-path: amount-matched outflow in window → 1 lead
# ─────────────────────────────────────────────────────────────────────────────


def test_amount_matched_outflow_in_window_yields_one_lead() -> None:
    """$250K WBTC deposit to Binance hot wallet → $245K WBTC outflow 2h
    later. Match within 5% tolerance → 1 lead with confidence='low'."""
    deposit_time = _INCIDENT_TIME
    # $250K of WBTC at $50K each = 5 WBTC
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
        block_time=deposit_time,
    )
    case = _mk_case([deposit])

    # 4.9 WBTC outflow 2h later → ~$245K (2% below deposit)
    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_A,
        block_time=deposit_time + timedelta(hours=2),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("4.9"),
    )

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))

    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) == 1
    lead = leads[0]
    assert isinstance(lead, CexContinuityLead)
    assert lead.confidence == "low"
    assert lead.cex_name == "Binance"
    assert lead.candidate_withdrawal_to == _NEW_ADDR_A
    assert lead.delta_hours == pytest.approx(2.0, abs=1e-3)
    assert lead.amount_match_pct < 0.05
    assert lead.deposit_token_symbol == "WBTC"


# ─────────────────────────────────────────────────────────────────────────────
# Amount mismatch: $250K deposit, $1M outflow → 0 leads
# ─────────────────────────────────────────────────────────────────────────────


def test_amount_mismatch_outside_tolerance_yields_zero_leads() -> None:
    """$250K WBTC deposit → 20 WBTC ($1M) outflow 2h later. Way over 5%
    tolerance → no leads."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_A,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("20"),  # 4x the deposit
    )

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Stale time: deposit at T0, outflow at T0+30h (window=6h default) → 0 leads
# ─────────────────────────────────────────────────────────────────────────────


def test_outflow_outside_window_yields_zero_leads() -> None:
    """$250K WBTC deposit → matching outflow 30h later (default window=6h)
    → no leads."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_A,
        block_time=_INCIDENT_TIME + timedelta(hours=30),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("4.9"),
    )

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Noisy token: USDC deposit → 0 leads (USDC is in default noisy_tokens)
# ─────────────────────────────────────────────────────────────────────────────


def test_noisy_token_usdc_yields_zero_leads() -> None:
    """$250K USDC deposit to Binance — USDC is in default noisy_tokens.
    Even with a matching outflow, no leads should be generated."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("250000"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_A,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("245000"),
    )

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    # The adapter should NOT be called when the only candidate is noisy.
    adapter.fetch_erc20_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Below threshold: $50K deposit (default min $100K) → 0 leads
# ─────────────────────────────────────────────────────────────────────────────


def test_below_min_usd_threshold_yields_zero_leads() -> None:
    """$50K WBTC deposit — below the default $100K threshold. Even with
    a matching outflow, no leads."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("50000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("1"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_A,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("0.98"),
    )

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    # No deposit qualified → no adapter calls.
    adapter.fetch_erc20_outflows.assert_not_called()
    adapter.fetch_native_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# No labeled CEX: deposit to unlabeled address → 0 leads, no adapter call
# ─────────────────────────────────────────────────────────────────────────────


def test_no_labeled_cex_in_case_yields_zero_leads_no_adapter_call() -> None:
    """Deposit goes to an unlabeled address (not a CEX hot wallet). The
    adapter must NOT be called — qualifying CEX deposits is the entry
    gate. No leads."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_NEW_ADDR_A,  # not labeled
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    adapter = MagicMock()
    label_store = LabelStore()  # empty
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    adapter.fetch_native_outflows.assert_not_called()
    adapter.fetch_erc20_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Adapter raises: 0 leads, no crash
# ─────────────────────────────────────────────────────────────────────────────


def test_adapter_raises_yields_zero_leads_no_crash() -> None:
    """Adapter raising on outflow fetch must not crash; just return []."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    adapter = MagicMock()
    adapter.fetch_native_outflows.side_effect = RuntimeError("etherscan down")
    adapter.fetch_erc20_outflows.side_effect = RuntimeError("etherscan down")

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# NaN amount in case.transfers: the transfer is skipped
# ─────────────────────────────────────────────────────────────────────────────


def test_nan_usd_value_in_transfer_is_skipped() -> None:
    """A transfer with Decimal('NaN') usd_value_at_tx must be skipped —
    NaN compared to min_usd silently returns False and would otherwise
    poison the filter."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),  # placeholder; will be overwritten below
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    # Bypass pydantic finite-validator (which would normally block NaN)
    # — defense in depth, mirror the dust_attack test pattern.
    object.__setattr__(deposit, "usd_value_at_tx", Decimal("NaN"))
    case = _mk_case([deposit])

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = []

    label_store = _mk_label_store((_BINANCE_HOT, "Binance: Hot Wallet 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    # No qualifying deposit → no adapter call.
    adapter.fetch_erc20_outflows.assert_not_called()
    adapter.fetch_native_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Top-5 cap: 7 matching deposits → only 5 leads
# ─────────────────────────────────────────────────────────────────────────────


def test_top_5_cap_returns_at_most_five_leads() -> None:
    """7 qualifying deposits each with a matching outflow → leads list
    capped at 5 (per-case API-budget guard)."""
    transfers: list[Transfer] = []
    outflows_by_address: dict[str, list[dict[str, Any]]] = {}

    # 7 deposits of $200K each to 7 distinct (but all Binance-labeled)
    # hot wallets so each gets its own outflow lookup.
    cex_addrs = [
        "0x" + f"{0xCE0 + i:040x}" for i in range(7)
    ]
    label_store = LabelStore()
    for i, addr in enumerate(cex_addrs):
        label_store.add(Label(
            address=addr,
            name=f"Binance Hot {i}",
            category=LabelCategory.exchange_hot_wallet,
            exchange="Binance",
            source="test:fixture",
            confidence="high",
            added_at=datetime(2025, 1, 1, tzinfo=UTC),
        ))
        deposit = _mk_transfer(
            from_addr=_PERP,
            to_addr=addr,
            usd=Decimal("200000"),
            token_symbol="WBTC",
            decimals=8,
            amount_decimal=Decimal("4"),
            block_number=1_000_000 + i,
            log_index=i,
        )
        transfers.append(deposit)
        # Each gets a matching outflow.
        outflow = _mk_outflow_row(
            to_addr="0x" + f"{0xDEAD + i:040x}",
            block_time=_INCIDENT_TIME + timedelta(hours=1),
            token_symbol="WBTC",
            decimals=8,
            amount_decimal=Decimal("3.95"),
        )
        outflows_by_address[addr] = [outflow]

    case = _mk_case(transfers)

    def _fetch_erc20(addr: str, _start: int) -> list[dict[str, Any]]:
        # The adapter is called per CEX hot wallet; route the response.
        for k, v in outflows_by_address.items():
            if k.lower() == addr.lower():
                return v
        return []

    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.side_effect = _fetch_erc20

    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) == 5  # capped at the v0.31.2 default _MAX_LEADS_PER_CASE


# ─────────────────────────────────────────────────────────────────────────────
# Brief-section serializer
# ─────────────────────────────────────────────────────────────────────────────


def test_leads_to_brief_section_explicit_lead_only_framing() -> None:
    """The serialized brief entries must carry the 'lead_only' framing
    and never use 'destination_chain' / 'destination_address' (which
    would imply we proved it)."""
    lead = CexContinuityLead(
        deposit_tx_hash="0xabc",
        deposit_address=_BINANCE_HOT,
        deposit_amount_usd=Decimal("250000"),
        deposit_token_symbol="WBTC",
        deposit_block_time=_INCIDENT_TIME,
        cex_name="Binance",
        candidate_withdrawal_tx_hash="0xdef",
        candidate_withdrawal_to=_NEW_ADDR_A,
        candidate_amount_usd=Decimal("245000"),
        candidate_block_time=_INCIDENT_TIME + timedelta(hours=2),
        delta_hours=2.0,
        amount_match_pct=0.02,
        confidence="low",
    )
    section = leads_to_brief_section([lead])
    assert len(section) == 1
    entry = section[0]
    assert entry["lead_only"] is True
    assert entry["confidence"] == "low"
    assert "LEAD ONLY" in entry["framing"]
    assert "not proven re-emergence" in entry["framing"]
    # Critical: never use 'destination_chain' or 'destination_address' —
    # those keys would imply we proved this is a destination.
    assert "destination_chain" not in entry
    assert "destination_address" not in entry
    assert entry["candidate_withdrawal_to"] == _NEW_ADDR_A
    assert entry["cex_name"] == "Binance"


def test_leads_to_brief_section_empty_yields_empty_list() -> None:
    """Empty leads → empty list — emit_brief OMITS the section key on
    empty so brief-key-set tests stay green."""
    assert leads_to_brief_section([]) == []


# ─────────────────────────────────────────────────────────────────────────────
# Defensive: empty / no-transfer case
# ─────────────────────────────────────────────────────────────────────────────


def test_empty_transfers_case_yields_zero_leads_no_adapter_call() -> None:
    """A case with no transfers must short-circuit without calling the
    adapter."""
    case = _mk_case([])
    adapter = MagicMock()
    label_store = LabelStore()
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    adapter.fetch_native_outflows.assert_not_called()
    adapter.fetch_erc20_outflows.assert_not_called()


def test_adapter_none_yields_zero_leads() -> None:
    """Passing adapter=None must return [] (defense-in-depth — env-var
    gate normally short-circuits before we get here)."""
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])
    label_store = _mk_label_store((_BINANCE_HOT, "Binance Hot", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=None, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Env-var parsing
# ─────────────────────────────────────────────────────────────────────────────


def test_env_continuity_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.31.4 (Gap 6): default-ON. Was default-OFF in v0.31.2."""
    monkeypatch.delenv("RECUPERO_CEX_CONTINUITY", raising=False)
    assert env_continuity_enabled() is True


def test_env_continuity_enabled_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for enable in ("1", "true", "yes", "on", "TRUE", "Yes", "", "garbage"):
        # v0.31.4: anything-not-explicit-off enables (default-ON contract).
        monkeypatch.setenv("RECUPERO_CEX_CONTINUITY", enable)
        assert env_continuity_enabled() is True, f"{enable!r} should enable"


def test_env_continuity_disabled_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.31.4: ONLY explicit opt-out values disable. Empty/garbage now enables."""
    for disable in ("0", "false", "no", "off", "FALSE", "OFF"):
        monkeypatch.setenv("RECUPERO_CEX_CONTINUITY", disable)
        assert env_continuity_enabled() is False, f"{disable!r} should disable"


def test_env_window_hours_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", raising=False)
    assert env_window_hours() == 6.0


def test_env_window_hours_nan_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """NaN/Inf must fall back to default — math.isfinite gate."""
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "NaN")
    assert env_window_hours() == 6.0
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "Infinity")
    assert env_window_hours() == 6.0
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "-Infinity")
    assert env_window_hours() == 6.0


def test_env_window_hours_clamped_low(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "0.1")
    assert env_window_hours() == 0.5
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "-5")
    assert env_window_hours() == 0.5


def test_env_window_hours_clamped_high(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "1000")
    assert env_window_hours() == 168.0


def test_env_window_hours_normal_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "12")
    assert env_window_hours() == 12.0


def test_env_window_hours_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "abc")
    assert env_window_hours() == 6.0
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_WINDOW_HOURS", "")
    assert env_window_hours() == 6.0


def test_env_min_usd_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECUPERO_CEX_CONTINUITY_MIN_USD", raising=False)
    assert env_min_usd() == Decimal("100000")


def test_env_min_usd_nan_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "NaN")
    assert env_min_usd() == Decimal("100000")
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "Infinity")
    assert env_min_usd() == Decimal("100000")


def test_env_min_usd_below_1k_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Below $1K must fall back to default — heuristic is for large
    matches only."""
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "500")
    assert env_min_usd() == Decimal("100000")
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "0")
    assert env_min_usd() == Decimal("100000")
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "-1000")
    assert env_min_usd() == Decimal("100000")


def test_env_min_usd_normal_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "50000")
    assert env_min_usd() == Decimal("50000.0")
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "1000000")
    assert env_min_usd() == Decimal("1000000.0")


def test_env_min_usd_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "abc")
    assert env_min_usd() == Decimal("100000")
    monkeypatch.setenv("RECUPERO_CEX_CONTINUITY_MIN_USD", "")
    assert env_min_usd() == Decimal("100000")
