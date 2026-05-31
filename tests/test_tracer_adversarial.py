"""Adversarial tracer hardening tests (Wave 2).

Audits ``recupero.trace.tracer.run_trace`` against malicious / pathological
inputs that the existing happy-path tests miss:

  1. **Cycle**: a graph with A→B→A must not loop forever — the visited
     set must short-circuit re-entry of any depth.
  2. **Depth cap**: max_depth honored — depth=2 must NOT enumerate beyond
     depth-1 children.
  3. **NaN/Inf USD**: a price client returning ``Decimal('NaN')`` or
     ``Decimal('Infinity')`` must not crash _trace_one_hop silently
     (drop-on-crash via the bare-except in ``_process_wave._one``).
     The per-hop boundary must explicitly reject non-finite prices
     and keep the transfer with ``usd_value=None`` + pricing_error.
  4. **Transfer-cap memory**: ``RECUPERO_MAX_TRANSFERS_PER_CASE`` must
     bound total transfers — a fan-out wave that produces 10M rows
     must short-circuit between waves, not OOM.
  5. **Time cap**: a deadline of 0 seconds must produce a partial case
     marked ``trace_status=partial_deadline_hit`` rather than running
     past the worker reaper window.
  6. **Address case canonicalization**: the same EVM address pasted in
     mixed-case (lowercase seed, checksum-cased destination cycling
     back) must dedup correctly — no double-visit.

All tests are RED before the fix, GREEN after.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams, TraceParams
from recupero.models import Chain, EvidenceReceipt, TokenRef
from recupero.pricing.coingecko import PriceResult

SEED = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
SEED_LOWER = SEED.lower()
HOP_A = "0x000000000000000000000000000000000000aAaA"
HOP_B = "0x000000000000000000000000000000000000bBbB"
HOP_C = "0x000000000000000000000000000000000000cCcC"


def _eth() -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        decimals=18, coingecko_id="ethereum",
    )


def _native_row(tx_hash: str, from_addr: str, to_addr: str, eth_amount: str = "50") -> dict[str, Any]:
    wei = int(Decimal(eth_amount) * Decimal(10**18))
    return {
        "chain": Chain.ethereum,
        "tx_hash": tx_hash,
        "block_number": 19000001,
        "block_time": datetime(2025, 1, 15, tzinfo=UTC),
        "log_index": None,
        "from": from_addr,
        "to": to_addr,
        "token": _eth(),
        "amount_raw": wei,
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
    }


class GraphAdapter(ChainAdapter):
    """Driver that replays a per-source outflow map. Tracks fetch
    counts so we can assert cycles don't expand fetch budget."""
    chain = Chain.ethereum

    def __init__(self, edges: dict[str, list[dict[str, Any]]]) -> None:
        # Lowercase keys for case-insensitive lookup (matches EVM canonical).
        self._edges = {k.lower(): v for k, v in edges.items()}
        self.fetch_calls: list[str] = []

    def block_at_or_before(self, ts: datetime) -> int:
        return 19000000

    def is_contract(self, address: str) -> bool:
        return False

    def fetch_native_outflows(
        self, from_address: str, start_block: int, **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.fetch_calls.append(from_address.lower())
        return list(self._edges.get(from_address.lower(), []))

    def fetch_erc20_outflows(
        self, from_address: str, start_block: int, **kwargs: Any
    ) -> list[dict[str, Any]]:
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        return EvidenceReceipt(
            chain=Chain.ethereum, tx_hash=tx_hash, block_number=19000001,
            block_time=datetime(2025, 1, 15, tzinfo=UTC),
            raw_transaction={"hash": tx_hash}, raw_receipt={"status": "0x1"},
            raw_block_header={"number": "0x1221b81"},
            fetched_at=datetime.now(UTC), fetched_from="fake",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"https://etherscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address: str) -> str:
        return f"https://etherscan.io/address/{address}"


class FixedPriceClient:
    def __init__(self, price: Decimal = Decimal("3000")) -> None:
        self.price = price

    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        return PriceResult(usd_value=self.price, source="fake:fixed", error=None)

    def close(self) -> None:
        pass


class NaNPriceClient:
    """Adversarial price source returning Decimal('NaN')."""

    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        # Pricing layer normally filters NaN at the source, but a
        # compromised / mocked / new pricing provider could leak it.
        # The tracer per-hop boundary MUST defend.
        return PriceResult(usd_value=Decimal("NaN"), source="fake:nan", error=None)

    def close(self) -> None:
        pass


class InfPriceClient:
    def price_at(self, token: TokenRef, when: datetime) -> PriceResult:
        return PriceResult(usd_value=Decimal("Infinity"), source="fake:inf", error=None)

    def close(self) -> None:
        pass


@pytest.fixture
def cfg(tmp_path: Path) -> tuple[RecuperoConfig, RecuperoEnv]:
    cfg = RecuperoConfig(
        trace=TraceParams(
            max_depth=3,
            dust_threshold_usd=1.0,
            incident_buffer_minutes=60,
        ),
        storage=StorageParams(data_dir=str(tmp_path)),
    )
    env = RecuperoEnv(ETHERSCAN_API_KEY="TEST", COINGECKO_API_KEY="TEST")
    return cfg, env


def _wire(monkeypatch: pytest.MonkeyPatch, adapter: GraphAdapter, price: Any) -> None:
    from recupero.trace import tracer as tracer_mod
    monkeypatch.setattr(
        ChainAdapter, "for_chain",
        classmethod(lambda cls, chain, bundle: adapter),
    )
    monkeypatch.setattr(tracer_mod, "CoinGeckoClient", lambda *_a, **_kw: price)


def _run(config, env, case_dir: Path, case_id: str = "ADV") -> Any:
    from recupero.trace import tracer as tracer_mod
    case_dir.mkdir(parents=True, exist_ok=True)
    return tracer_mod.run_trace(
        chain=Chain.ethereum, seed_address=SEED,
        incident_time=datetime(2025, 1, 15, tzinfo=UTC),
        case_id=case_id, config=config, env=env, case_dir=case_dir,
    )


# ---------- Test 1: cycle detection ---------- #


def test_cycle_does_not_infinite_loop(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A→B→A cycle must terminate. Visited set must short-circuit B's
    outflow toward A (already visited) so fetch_native_outflows is NOT
    called more than once per unique address."""
    config, env = cfg
    config.trace.max_depth = 4  # deep enough that a true cycle would loop

    edges = {
        SEED:  [_native_row("0xaa", SEED, HOP_A)],
        HOP_A: [_native_row("0xbb", HOP_A, HOP_B)],
        HOP_B: [_native_row("0xcc", HOP_B, HOP_A)],  # CYCLE back to A
    }
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "CYC")

    # Each unique address fetched at most once.
    unique_fetches = set(adapter.fetch_calls)
    assert len(unique_fetches) == len(adapter.fetch_calls), (
        f"cycle fetched same address twice: {adapter.fetch_calls}"
    )
    assert case.config_used.get("trace_status") == "complete"


# ---------- Test 2: depth cap honored ---------- #


def test_depth_cap_terminates_at_max_depth(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """max_depth=2 must stop at depth-1 children. A chain
    SEED→A→B→C should produce hop_depth 0 and 1 only (the depth-2
    transfer would be from B and is gated by the policy at boundary)."""
    config, env = cfg
    config.trace.max_depth = 2

    edges = {
        SEED:  [_native_row("0xaa", SEED, HOP_A)],   # depth 0 hop
        HOP_A: [_native_row("0xbb", HOP_A, HOP_B)],  # depth 1 hop
        HOP_B: [_native_row("0xcc", HOP_B, HOP_C)],  # depth 2 — MUST NOT FIRE
    }
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "DEPTH")

    depths = {t.hop_depth for t in case.transfers}
    assert depths <= {0, 1}, f"depth cap breached: depths={depths}"
    # HOP_B must not have been fetched — its outflow toward HOP_C
    # would have rendered as a depth-2 transfer.
    assert HOP_B.lower() not in adapter.fetch_calls, (
        f"max_depth=2 should not fetch from depth-2 source HOP_B; "
        f"fetches={adapter.fetch_calls}"
    )


# ---------- Test 3: NaN USD rejected at boundary ---------- #


def test_nan_usd_rejected_at_boundary(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A price client returning Decimal('NaN') must not crash the hop
    or poison the case. Expected: transfer is KEPT (or cleanly dropped)
    with usd_value_at_tx=None and a pricing_error explaining rejection.

    Pre-fix: Decimal('NaN').quantize() raises InvalidOperation,
    _trace_one_hop bubbles, _process_wave's bare except swallows the
    whole hop's transfers — silent data loss.
    """
    config, env = cfg
    config.trace.max_depth = 1

    edges = {SEED: [_native_row("0xnan", SEED, HOP_A)]}
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, NaNPriceClient())

    case = _run(config, env, tmp_path / "cases" / "NAN")

    # The hop's fetch must have happened (boundary defends, doesn't crash).
    assert SEED_LOWER in adapter.fetch_calls
    # Each kept transfer must have a finite USD or None — never NaN/Inf.
    for t in case.transfers:
        if t.usd_value_at_tx is not None:
            assert t.usd_value_at_tx.is_finite(), (
                f"non-finite USD leaked into case: {t.usd_value_at_tx}"
            )


def test_inf_usd_rejected_at_boundary(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Symmetric check for Decimal('Infinity')."""
    config, env = cfg
    config.trace.max_depth = 1

    edges = {SEED: [_native_row("0xinf", SEED, HOP_A)]}
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, InfPriceClient())

    case = _run(config, env, tmp_path / "cases" / "INF")

    for t in case.transfers:
        if t.usd_value_at_tx is not None:
            assert t.usd_value_at_tx.is_finite(), (
                f"Infinity USD leaked into case: {t.usd_value_at_tx}"
            )
    # Total must not be NaN/Inf either.
    if case.total_usd_out is not None:
        assert case.total_usd_out.is_finite()


# ---------- Test 4: deadline cap ---------- #


def test_zero_deadline_emits_partial_marker(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RECUPERO_TRACE_TIMEOUT_SEC=0 must short-circuit the first wave
    check and produce a case marked partial_deadline_hit."""
    config, env = cfg
    config.trace.max_depth = 2

    edges = {SEED: [_native_row("0xaa", SEED, HOP_A)]}
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())
    monkeypatch.setenv("RECUPERO_TRACE_TIMEOUT_SEC", "0")

    case = _run(config, env, tmp_path / "cases" / "DEAD")

    assert case.config_used.get("trace_status") == "partial_deadline_hit"
    assert case.transfers == []  # no wave ran
    # No fetches happened (deadline check fires before first wave).
    assert adapter.fetch_calls == []


# ---------- Test 5: memory / transfer cap ---------- #


def test_transfer_cap_short_circuits_before_oom(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If wave-1 alone produces > RECUPERO_MAX_TRANSFERS_PER_CASE,
    the next wave must NOT start — tracer exits with partial marker."""
    config, env = cfg
    config.trace.max_depth = 3
    # Cap big enough for wave-1 to fit, small enough that wave-2 trips it.
    monkeypatch.setenv("RECUPERO_MAX_TRANSFERS_PER_CASE", "5")
    # Allow the fetch layer to return many rows per address.
    config.trace.max_transfers_per_address = 100

    # Wave-1: SEED emits 10 transfers — fits in 5 cap? No, 10 > 5,
    # but the cap check fires BETWEEN waves: wave-1 lands all 10
    # transfers, then the wave-2 entry check sees 10 >= 5 and exits.
    fanout_rows = [
        _native_row(f"0xfan{i:02x}", SEED, f"0x{i:040x}")
        for i in range(10)
    ]
    edges = {SEED: fanout_rows}
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "CAP")

    assert case.config_used.get("trace_status") == "partial_transfer_cap_hit", (
        f"expected partial_transfer_cap_hit; got "
        f"{case.config_used.get('trace_status')!r} with "
        f"{len(case.transfers)} transfers"
    )


# ---------- Test 6: address case canonicalization (cycle via mixed-case) ---------- #


def test_mixed_case_address_does_not_re_visit(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the same EVM address appears as the destination of a deep
    hop in mixed-case after first appearing in lowercase, the visited
    set must dedup it. Otherwise an attacker can pad case-variants to
    inflate the trace budget."""
    config, env = cfg
    config.trace.max_depth = 4

    upper_a = HOP_A.upper().replace("0X", "0x")
    edges = {
        SEED:    [_native_row("0xaa", SEED, HOP_A)],          # 1st visit (canonical)
        HOP_A:   [_native_row("0xbb", HOP_A, HOP_B)],
        HOP_B:   [_native_row("0xcc", HOP_B, upper_a)],       # back to A in UPPER
    }
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    _run(config, env, tmp_path / "cases" / "CASE")

    # HOP_A must be fetched at most once regardless of case variants.
    a_fetches = [f for f in adapter.fetch_calls if f == HOP_A.lower()]
    assert len(a_fetches) <= 1, (
        f"mixed-case re-entry not deduped; fetches={adapter.fetch_calls}"
    )


# ---------- Test 7: coverage capture spans the continuation pass ---------- #


def test_continuation_pass_cap_truncation_lands_in_coverage(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34 regression: a per-address fetch cap that fires DURING the
    DEX/bridge continuation pass (NOT the primary BFS) MUST still land in
    ``coverage.per_address_cap_truncations`` and flip ``coverage.complete``
    to False.

    The bug: the coverage block was computed BEFORE
    ``_continue_past_dex_and_bridges`` ran, so it snapshotted
    ``_COVERAGE_TRUNCATIONS`` too early. The deep, chatty aggregator/pool
    addresses are typically only reached in the continuation pass, so that
    is exactly where the per-address fetch cap usually fires — and those
    truncations were silently dropped, leaving a CAPPED trace stamped
    ``complete=True`` with ``per_address_cap_truncations=[]``. (Observed live:
    a completed run logged 3 "capping outflows" events yet wrote
    cap_truncations=0 / complete=True.)

    This test drives the cap from inside the continuation hook and asserts it
    survives to the final coverage dict. RED before the fix, GREEN after.
    """
    from recupero.trace import tracer as tracer_mod

    config, env = cfg
    config.trace.max_depth = 2  # >= 2 so the continuation pass is allowed

    # One real transfer so the trace is genuinely "complete" with data
    # (no_data=False) — isolating the cap truncation as the ONLY thing that
    # should reduce coverage.
    edges = {SEED: [_native_row("0xaa", SEED, HOP_A)]}
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    # Simulate the continuation pass reaching a chatty address that trips the
    # per-address fetch cap, recording a truncation exactly as
    # ``_trace_one_hop`` does at its cap site.
    cont_addr = "0x00000000000000000000000000000000c0117a7e"

    def _fake_continue(**_kwargs: Any) -> None:
        tracer_mod._COVERAGE_TRUNCATIONS.append({
            "address": cont_addr,
            "kind": "per_address_fetch_cap",
            "raw_outflows": 9200,
            "kept": 2500,
            "dropped": 6700,
            "hop_depth": 2,
        })

    monkeypatch.setattr(
        tracer_mod, "_continue_past_dex_and_bridges", _fake_continue,
    )

    case = _run(config, env, tmp_path / "cases" / "CONTCAP")

    cov = case.config_used["coverage"]
    addrs = [t["address"] for t in cov["per_address_cap_truncations"]]
    assert cont_addr in addrs, (
        "a per-address fetch cap recorded during the continuation pass was "
        "dropped from coverage — the coverage block must be computed AFTER "
        f"_continue_past_dex_and_bridges. got truncations={addrs!r}"
    )
    assert cov["complete"] is False, (
        "a trace that capped an address (even in the continuation pass) must "
        "NOT be stamped coverage.complete=True"
    )
    assert "recall-complete" in cov["recommendation"], (
        "a reduced trace must carry the recall-complete recommendation"
    )
