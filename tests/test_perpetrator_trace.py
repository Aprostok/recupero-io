"""Tests for the v0.8.0 pass-2 perpetrator-forward trace logic.

Focus areas:
  * identify_pass2_candidates — the heuristic that decides which
    hubs are worth re-tracing
  * is_pass2_enabled — kill-switch env-var behavior
  * merge_perpetrator_findings — pass-1 + pass-2 stitching
  * _parse_usd helper edge cases (the freeze_brief holdings text
    is free-form and we have to parse $X.XM / $X,XXX.XX / etc.)

Live integration (actually running a pass-2 trace from a real
hub) is exercised by the canary verification at release time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.perpetrator_trace import (
    _parse_usd,
    identify_pass2_candidates,
    is_pass2_enabled,
    merge_perpetrator_findings,
)

# ---- _parse_usd ---- #


def test_parse_usd_plain_dollars() -> None:
    assert _parse_usd("$10,000.00") == Decimal("10000.00")
    assert _parse_usd("$655,000") == Decimal("655000")
    assert _parse_usd("$0.50") == Decimal("0.50")


def test_parse_usd_handles_suffixes() -> None:
    """The freeze_brief sometimes formats with K/M suffixes (e.g.,
    '$3.27M') for readability. Parser must handle both forms."""
    assert _parse_usd("$3.27M") == Decimal("3270000")
    assert _parse_usd("$655K") == Decimal("655000")
    assert _parse_usd("$1.5M") == Decimal("1500000")


def test_parse_usd_returns_none_on_garbage() -> None:
    assert _parse_usd(None) is None
    assert _parse_usd("") is None
    assert _parse_usd("not a number") is None
    assert _parse_usd("$") is None


# ---- is_pass2_enabled ---- #


def test_pass2_enabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_DISABLE_PASS2", raising=False)
    assert is_pass2_enabled() is True


def test_pass2_killable_via_env(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DISABLE_PASS2", "1")
    assert is_pass2_enabled() is False
    monkeypatch.setenv("RECUPERO_DISABLE_PASS2", "true")
    assert is_pass2_enabled() is True


# ---- Helpers for case construction ---- #


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    tx_suffix: str = "1",
    block: int = 1,
    hop_depth: int = 0,
    chain: Chain = Chain.ethereum,
) -> Transfer:
    """Build a valid Transfer with the v0.7+ Case model schema."""
    tx_hash = "0x" + tx_suffix * 64
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:{block}",
        chain=chain,
        tx_hash=tx_hash,
        block_number=block,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="1000000",
        amount_decimal=Decimal("1"),
        usd_value_at_tx=usd,
        hop_depth=hop_depth,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(*, seed: str, transfers: list[Transfer]) -> Case:
    return Case(
        case_id="test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


def _case_one_hub(*, seed: str, hub: str, inflow_usd: Decimal) -> Case:
    return _mk_case(
        seed=seed,
        transfers=[_mk_transfer(from_addr=seed, to_addr=hub, usd=inflow_usd)],
    )


# ---- identify_pass2_candidates ---- #


def test_identify_no_freeze_brief_returns_empty() -> None:
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub="0x" + "b" * 40,
        inflow_usd=Decimal("100"),
    )
    assert identify_pass2_candidates(case, freeze_brief=None) == []


def test_identify_no_freezable_returns_empty() -> None:
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub="0x" + "b" * 40,
        inflow_usd=Decimal("100"),
    )
    assert identify_pass2_candidates(case, freeze_brief={"FREEZABLE": []}) == []


def test_identify_below_balance_threshold_skipped() -> None:
    """Hub holding less than the balance threshold → skipped."""
    hub = "0x" + "b" * 40
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub=hub, inflow_usd=Decimal("1"),
    )
    freeze_brief = {"FREEZABLE": [{
        "token": "USDC",
        "holdings": [
            {"address": hub, "amount": "1000 USDC", "usd": "$1,000.00"},
        ],
    }]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert out == []


def test_identify_below_ratio_threshold_skipped() -> None:
    """Hub balance/inflow ratio below threshold → skipped."""
    hub = "0x" + "b" * 40
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub=hub, inflow_usd=Decimal("10000"),
    )
    freeze_brief = {"FREEZABLE": [{
        "token": "USDC",
        "holdings": [
            {"address": hub, "amount": "20000 USDC", "usd": "$20,000.00"},
        ],
    }]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert out == []


def test_identify_zigha_shape_hub_qualifies() -> None:
    """V-CFI01 case shape: small inflow, huge hub balance."""
    hub = "0x" + "f" * 40
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub=hub, inflow_usd=Decimal("101"),
    )
    freeze_brief = {"FREEZABLE": [{
        "token": "DAI",
        "holdings": [
            {"address": hub, "amount": "655000 DAI", "usd": "$655,000.00"},
        ],
    }]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert len(out) == 1
    cand = out[0]
    assert cand.address == hub
    assert cand.current_balance_usd == Decimal("655000.00")
    assert cand.balance_to_inflow_ratio > 6000
    assert cand.triggering_token == "DAI"


def test_identify_no_inflow_from_victim_skipped() -> None:
    """Freezable address with no inflow from victim → not a hub."""
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub="0x" + "b" * 40,
        inflow_usd=Decimal("100"),
    )
    other = "0x" + "c" * 40
    freeze_brief = {"FREEZABLE": [{
        "token": "USDC",
        "holdings": [
            {"address": other, "amount": "1M USDC", "usd": "$1,000,000.00"},
        ],
    }]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert out == []


def test_identify_sorts_by_balance_descending() -> None:
    """Largest position first, so the per-investigation cap doesn't
    drop the highest-impact pass-2 trace."""
    seed = "0x" + "a" * 40
    hub_small = "0x" + "1" * 40
    hub_large = "0x" + "2" * 40
    case = _mk_case(
        seed=seed,
        transfers=[
            _mk_transfer(from_addr=seed, to_addr=hub_small,
                         usd=Decimal("50"), tx_suffix="1", block=1),
            _mk_transfer(from_addr=seed, to_addr=hub_large,
                         usd=Decimal("100"), tx_suffix="2", block=2),
        ],
    )
    freeze_brief = {"FREEZABLE": [{
        "token": "USDC",
        "holdings": [
            {"address": hub_small, "amount": "10K", "usd": "$10,000.00"},
            {"address": hub_large, "amount": "500K", "usd": "$500,000.00"},
        ],
    }]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert len(out) == 2
    assert out[0].address == hub_large
    assert out[1].address == hub_small


def test_identify_caps_candidates() -> None:
    """Per-investigation cap defends against pathological cases."""
    seed = "0x" + "a" * 40
    transfers = []
    holdings = []
    for i in range(10):
        hub = f"0x{i:040x}"
        transfers.append(_mk_transfer(
            from_addr=seed, to_addr=hub, usd=Decimal("10"),
            tx_suffix=str(i + 1), block=i + 1,
        ))
        holdings.append({"address": hub, "amount": "100K",
                         "usd": "$100,000.00"})
    case = _mk_case(seed=seed, transfers=transfers)
    freeze_brief = {"FREEZABLE": [{"token": "USDC", "holdings": holdings}]}
    out = identify_pass2_candidates(case, freeze_brief)
    assert len(out) == 3  # default cap


def test_identify_respects_custom_thresholds() -> None:
    """Stricter overrides drop borderline candidates."""
    hub = "0x" + "b" * 40
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub=hub, inflow_usd=Decimal("100"),
    )
    freeze_brief = {"FREEZABLE": [{
        "token": "USDC",
        "holdings": [
            {"address": hub, "amount": "50K", "usd": "$50,000.00"},
        ],
    }]}
    out_default = identify_pass2_candidates(case, freeze_brief)
    assert len(out_default) == 1
    out_strict = identify_pass2_candidates(
        case, freeze_brief,
        ratio_threshold=10_000, balance_threshold=Decimal("100_000"),
    )
    assert len(out_strict) == 0


# ---- merge_perpetrator_findings ---- #


def test_merge_no_pass2_returns_pass1_unchanged() -> None:
    case = _case_one_hub(
        seed="0x" + "a" * 40, hub="0x" + "b" * 40,
        inflow_usd=Decimal("100"),
    )
    merged = merge_perpetrator_findings(case, [])
    assert merged is case


def test_merge_appends_pass2_transfers() -> None:
    """Pass-2 transfers get appended with hop_depth shifted
    relative to where the hub was reached in pass-1."""
    seed = "0x" + "a" * 40
    hub = "0x" + "b" * 40
    downstream = "0x" + "c" * 40
    pass1 = _case_one_hub(seed=seed, hub=hub, inflow_usd=Decimal("100"))
    pass2 = _mk_case(
        seed=hub,
        transfers=[
            _mk_transfer(
                from_addr=hub, to_addr=downstream,
                usd=Decimal("100000"), tx_suffix="9", block=2,
            ),
        ],
    )
    merged = merge_perpetrator_findings(pass1, [pass2])
    assert len(merged.transfers) == 2
    pass2_xfer = merged.transfers[-1]
    assert pass2_xfer.to_address.lower() == downstream
    # hub was at depth 0 in pass-1; pass-2 transfer (depth 0)
    # becomes depth 0 + 0 + 1 = 1 in merged.
    assert pass2_xfer.hop_depth == 1
