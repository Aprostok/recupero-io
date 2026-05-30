"""Unit tests for behavioral endpoint classification (trace-depth #2).

Covers the pure diversity classifier (high-both → infra, asymmetric/low →
inconclusive — the perp-hub-safety guard) and the broader-activity probe
(distinct-counterparty counting + dedup + truncation) via a fake adapter.
Locks the forensic invariant: behavioral classification NEVER returns
"high".
"""

from __future__ import annotations

from decimal import Decimal

from recupero.trace.endpoint_classifier import (
    classify_by_counterparty_diversity,
    infer_infrastructure_endpoints,
    probe_endpoint_diversity,
)

# ---- pure classifier ---- #


def test_high_diversity_both_sides_is_infrastructure() -> None:
    c = classify_by_counterparty_diversity(
        address="0xhot", distinct_inbound=120, distinct_outbound=95,
    )
    assert c.classification == "likely_exchange_infrastructure"
    assert c.confidence in ("medium", "low")
    assert c.confidence != "high"


def test_strongly_diverse_bumps_to_medium() -> None:
    c = classify_by_counterparty_diversity(
        address="0xhot", distinct_inbound=400, distinct_outbound=80,
    )
    assert c.classification == "likely_exchange_infrastructure"
    assert c.confidence == "medium"


def test_modest_both_sides_is_low_confidence_infra() -> None:
    c = classify_by_counterparty_diversity(
        address="0xhot", distinct_inbound=45, distinct_outbound=50,
    )
    assert c.classification == "likely_exchange_infrastructure"
    assert c.confidence == "low"


def test_asymmetric_one_directional_collector_is_inconclusive() -> None:
    """A many-in / few-out collector is the shape a PERPETRATOR consolidation
    hub also has — must NOT be flagged as exchange infrastructure."""
    c = classify_by_counterparty_diversity(
        address="0xperphub", distinct_inbound=300, distinct_outbound=2,
    )
    assert c.classification == "inconclusive"
    assert "NO exchange claim" in c.reason


def test_low_diversity_is_inconclusive_not_infra() -> None:
    """The classic perp consolidation hub: a handful of distinct
    counterparties (its split addresses). Never flagged as a CEX."""
    c = classify_by_counterparty_diversity(
        address="0xperphub", distinct_inbound=8, distinct_outbound=3,
    )
    assert c.classification == "inconclusive"


# ---- broader-activity probe (fake adapter) ---- #


class _FakeAdapter:
    def __init__(self, native_in, erc20_in, native_out, erc20_out) -> None:
        self._ni, self._ei, self._no, self._eo = (
            native_in, erc20_in, native_out, erc20_out,
        )

    def fetch_native_inflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return self._ni

    def fetch_erc20_inflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return self._ei

    def fetch_native_outflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return self._no

    def fetch_erc20_outflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return self._eo


def _rows(field: str, addrs: list[str]) -> list[dict]:
    return [{field: a} for a in addrs]


def test_probe_counts_distinct_counterparties_dedup_canonical() -> None:
    """Distinct counterparties are counted canonically — the same EVM
    address in mixed case counts once."""
    a1 = "0x" + "a" * 40
    a1_upper = "0x" + "A" * 40   # same address, checksum-ish case
    a2 = "0x" + "b" * 40
    adapter = _FakeAdapter(
        native_in=_rows("from", [a1, a2]),
        erc20_in=_rows("from", [a1_upper, "0x" + "c" * 40]),
        native_out=_rows("to", ["0x" + "d" * 40]),
        erc20_out=_rows("to", ["0x" + "d" * 40, "0x" + "e" * 40]),
    )
    div = probe_endpoint_diversity("0xhot", adapter=adapter, start_block=1)
    # inbound distinct: a1 (== a1_upper canonical), a2, c → 3
    assert div.distinct_inbound == 3
    # outbound distinct: d, e → 2
    assert div.distinct_outbound == 2
    assert div.total_inbound_txs == 4
    assert div.total_outbound_txs == 3


def test_probe_truncation_flag_set_when_cap_hit() -> None:
    big = _rows("from", [f"0x{i:040x}" for i in range(50)])
    adapter = _FakeAdapter(big, [], [], [])
    div = probe_endpoint_diversity(
        "0xhot", adapter=adapter, start_block=1, max_results=50,
    )
    assert div.probe_truncated is True


def test_probe_on_no_inbound_support_adapter_is_zero() -> None:
    """An adapter without inbound support (base default → []) yields zero
    inbound diversity rather than crashing — non-EVM endpoints just don't
    classify as infra."""
    adapter = _FakeAdapter([], [], [], [])
    div = probe_endpoint_diversity("0xhot", adapter=adapter, start_block=1)
    assert div.distinct_inbound == 0
    assert div.distinct_outbound == 0
    c = classify_by_counterparty_diversity(
        address="0xhot",
        distinct_inbound=div.distinct_inbound,
        distinct_outbound=div.distinct_outbound,
    )
    assert c.classification == "inconclusive"


def test_probe_end_to_end_classifies_high_diversity_as_infra() -> None:
    senders = _rows("from", [f"0x{i:040x}" for i in range(60)])
    recipients = _rows("to", [f"0x{(i + 1000):040x}" for i in range(60)])
    adapter = _FakeAdapter(senders, [], recipients, [])
    div = probe_endpoint_diversity("0xhot", adapter=adapter, start_block=1)
    c = classify_by_counterparty_diversity(
        address="0xhot",
        distinct_inbound=div.distinct_inbound,
        distinct_outbound=div.distinct_outbound,
    )
    assert c.classification == "likely_exchange_infrastructure"


# ---- infer_infrastructure_endpoints orchestrator ---- #


class _Chain:
    def __init__(self, v: str) -> None:
        self.value = v


class _Tx:
    def __init__(self, to_address, usd, chain="ethereum") -> None:  # noqa: ANN001
        self.to_address = to_address
        self.usd_value_at_tx = usd
        self.chain = _Chain(chain)


class _Case:
    def __init__(self, transfers, unlabeled) -> None:  # noqa: ANN001
        self.transfers = transfers
        self.unlabeled_counterparties = unlabeled


class _OrchAdapter(_FakeAdapter):
    chain = _Chain("ethereum")

    def block_at_or_before(self, ts):  # noqa: ANN001
        return 1


def test_infer_infrastructure_endpoints_flags_high_diversity_endpoint() -> None:
    hot = "0x" + "9" * 40
    case = _Case(
        transfers=[_Tx(hot, Decimal("250000"))],
        unlabeled=[hot],
    )
    adapter = _OrchAdapter(
        native_in=_rows("from", [f"0x{i:040x}" for i in range(60)]),
        erc20_in=[],
        native_out=_rows("to", [f"0x{(i + 1000):040x}" for i in range(60)]),
        erc20_out=[],
    )
    out = infer_infrastructure_endpoints(case, adapter=adapter, start_block=1)
    assert len(out) == 1
    assert out[0]["address"] == hot
    assert out[0]["classification"] == "likely_exchange_infrastructure"
    assert out[0]["attribution_confidence"] in ("medium", "low")


def test_infer_infrastructure_endpoints_skips_perp_hub() -> None:
    """A low-diversity unlabeled collector (perp consolidation hub) must NOT
    be flagged — the orchestrator returns nothing for it."""
    hub = "0x" + "7" * 40
    case = _Case(transfers=[_Tx(hub, Decimal("250000"))], unlabeled=[hub])
    adapter = _OrchAdapter(
        native_in=_rows("from", ["0x" + "a" * 40, "0x" + "b" * 40]),
        erc20_in=[], native_out=_rows("to", ["0x" + "c" * 40]), erc20_out=[],
    )
    out = infer_infrastructure_endpoints(case, adapter=adapter, start_block=1)
    assert out == []


def test_infer_infrastructure_endpoints_skips_low_inflow_and_other_chains() -> None:
    """Below the inflow floor, or on a chain other than the adapter's, are
    not probed."""
    poor = "0x" + "1" * 40       # below floor
    other = "0x" + "2" * 40      # on a different chain
    case = _Case(
        transfers=[_Tx(poor, Decimal("10")), _Tx(other, Decimal("999999"), chain="polygon")],
        unlabeled=[poor, other],
    )
    adapter = _OrchAdapter(
        native_in=_rows("from", [f"0x{i:040x}" for i in range(60)]),
        erc20_in=[], native_out=_rows("to", [f"0x{(i+1000):040x}" for i in range(60)]),
        erc20_out=[],
    )
    out = infer_infrastructure_endpoints(case, adapter=adapter, start_block=1)
    assert out == []
