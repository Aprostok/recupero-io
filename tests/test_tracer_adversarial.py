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

    def price_at(
        self, token: TokenRef, when: datetime, **_kwargs: Any,
    ) -> PriceResult:
        # **_kwargs absorbs skip_contract_api (v0.34 value-trace fast path).
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


# ---------- Test 8: service-wallet outflow threshold env override ---------- #


def _fanout_graph(n: int) -> tuple[dict[str, Any], list[str]]:
    """Seed → n children, each child → 1 grandchild. Lets a test detect
    whether the seed's children were TRAVERSED (fetched) or stopped at."""
    children = [f"0x{i + 1:040x}" for i in range(n)]
    edges: dict[str, Any] = {
        SEED: [_native_row(f"0xfeed{i:02x}", SEED, c) for i, c in enumerate(children)]
    }
    for i, c in enumerate(children):
        edges[c] = [_native_row(f"0xbeef{i:02x}", c, f"0x{i + 1000:040x}")]
    return edges, children


def _valued_fanout(amounts: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Seed → len(amounts) children with the given ETH amounts (so top-N-by-value
    is well-defined); each child → 1 grandchild (lets us see which were traversed)."""
    children = [f"0x{i + 1:040x}" for i in range(len(amounts))]
    edges: dict[str, Any] = {
        SEED: [
            _native_row(f"0xfeed{i:02x}", SEED, c, eth_amount=amt)
            for i, (c, amt) in enumerate(zip(children, amounts, strict=True))
        ]
    }
    for i, c in enumerate(children):
        edges[c] = [_native_row(f"0xbeef{i:02x}", c, f"0x{i + 1000:040x}")]
    return edges, children


def test_service_wallet_seed_follows_top_n_by_value(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34.5 (Lazarus/Ronin generalization fix): a high-fan-out SEED is the
    investigation subject — its every outflow is theft dispersal — so it must
    NEVER be skipped. Instead it FOLLOWS the top-N outflows BY VALUE (bounded so
    BFS stays finite). Here the seed emits 5 > threshold 3 → service wallet; with
    follow-top-N=2 the two HIGHEST-VALUE children are traversed and the three
    lowest are not. Top-N follow is gated on value-trace ("follow the money"):
    the enqueued children become value-directed, so the recursion stays bounded
    while never skipping the highest-value laundering legs."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)
    monkeypatch.setenv("RECUPERO_SEED_FOLLOW_TOPN", "2")

    # child i value = (i+1)*10 ETH → top-2 by value are children[4] (50) + [3] (40)
    edges, children = _valued_fanout(["10", "20", "30", "40", "50"])
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    _run(config, env, tmp_path / "cases" / "SW1")

    fetched = set(adapter.fetch_calls)
    assert children[4].lower() in fetched, "top-value child (50 ETH) not followed"
    assert children[3].lower() in fetched, "2nd-value child (40 ETH) not followed"
    for c in children[:3]:
        assert c.lower() not in fetched, (
            f"only the top-2 by value should be followed; {c} (lower value) was"
        )


def test_service_wallet_seed_follow_topn_zero_restores_legacy_skip(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RECUPERO_SEED_FOLLOW_TOPN=0 restores the legacy behavior: a high-fan-out
    seed keeps its transfers but traverses NO children. Value-trace is ON here so
    this exercises the explicit follow_n<=0 skip branch (not the value-trace-off
    skip)."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)
    monkeypatch.setenv("RECUPERO_SEED_FOLLOW_TOPN", "0")

    edges, children = _fanout_graph(5)
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    _run(config, env, tmp_path / "cases" / "SW1z")

    fetched = set(adapter.fetch_calls)
    for c in children:
        assert c.lower() not in fetched, (
            f"follow-topn=0 should skip; child {c} was traversed"
        )


def test_service_wallet_threshold_env_override_allows_traversal(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34: RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD raises the gate so a
    deep recall-complete run crosses a high-throughput aggregator/pool on the
    laundering path instead of silently stopping at it."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3  # config still low
    monkeypatch.setenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", "100")

    edges, children = _fanout_graph(5)
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    _run(config, env, tmp_path / "cases" / "SW2")

    fetched = set(adapter.fetch_calls)
    traversed = [c for c in children if c.lower() in fetched]
    assert traversed, (
        "env override to 100 should make the 5-outflow seed NOT a service "
        "wallet, so its children are traversed — none were"
    )


def test_service_wallet_threshold_env_bad_value_keeps_default(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-int / non-positive override is ignored (keeps the config
    default) rather than crashing or disabling the gate."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3
    # This test isolates THRESHOLD parsing. Value-trace is OFF (default), so a
    # high-fan-out seed stays a dead end (the v0.34.5 top-N follow is gated on
    # value-trace) — "children not traversed" is the correct observable.
    for bad in ("abc", "0", "-5", "  "):
        monkeypatch.setenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", bad)
        edges, children = _fanout_graph(5)
        adapter = GraphAdapter(edges)
        _wire(monkeypatch, adapter, FixedPriceClient())
        _run(config, env, tmp_path / "cases" / f"SW_{bad.strip() or 'blank'}")
        fetched = set(adapter.fetch_calls)
        for c in children:
            assert c.lower() not in fetched, (
                f"bad override {bad!r} should keep default(3); child {c} "
                "must not be traversed"
            )


# ---------- Test 9: value-directed tracing through a service wallet -------- #


def _aggregator_graph() -> tuple[dict[str, Any], str, list[str]]:
    """SEED --50 ETH--> N (a 5-outflow service wallet). N forwards exactly
    50 ETH to TARGET (the real onward hop) plus 4 decoy outflows of other
    amounts. Returns (edges, TARGET, decoys)."""
    target = HOP_B
    decoys = [f"0x{0xc1 + i:040x}" for i in range(4)]
    edges: dict[str, Any] = {
        SEED: [_native_row("0xseed1", SEED, HOP_A, eth_amount="50")],
        HOP_A: [
            _native_row("0xnmatch", HOP_A, target, eth_amount="50"),   # value match
            _native_row("0xn1", HOP_A, decoys[0], eth_amount="10"),
            _native_row("0xn2", HOP_A, decoys[1], eth_amount="20"),
            _native_row("0xn3", HOP_A, decoys[2], eth_amount="30"),
            _native_row("0xn4", HOP_A, decoys[3], eth_amount="40"),
        ],
        target: [_native_row("0xt1", target, decoys[0], eth_amount="5")],
    }
    return edges, target, decoys


def test_value_trace_follows_amount_matched_hop_through_service_wallet(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RECUPERO_VALUE_TRACE=1: at a high-fan-out node the tracer follows ONLY
    the outflow whose amount matches the inbound funds (50 ETH -> 50 ETH),
    NOT the decoys — isolating the real onward hop and recording it as a
    medium-confidence value match."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3  # N's 5 outflows trip it
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    edges, target, decoys = _aggregator_graph()
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "VT_ON")

    fetched = set(adapter.fetch_calls)
    assert target.lower() in fetched, (
        "value-matched onward hop was not traversed through the service wallet"
    )
    for d in decoys:
        assert d.lower() not in fetched, (
            f"decoy {d} (amount mismatch) must NOT be followed"
        )
    hops = case.config_used["coverage"]["value_matched_hops"]
    matched = [h for h in hops if h["matched_to"].lower() == target.lower()]
    assert matched, f"no value-match provenance recorded; got {hops}"
    assert matched[0]["kind"] == "same_asset_amount"
    assert matched[0]["confidence"] == "medium"  # sole same-asset match
    assert matched[0]["ambiguous"] is False


def test_value_trace_off_by_default_stops_at_service_wallet(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default (RECUPERO_VALUE_TRACE unset): a service wallet is still a dead
    end — no onward hop is followed and no value-match provenance is recorded.
    This keeps existing behavior byte-identical."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 3
    monkeypatch.delenv("RECUPERO_VALUE_TRACE", raising=False)
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    edges, target, decoys = _aggregator_graph()
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "VT_OFF")

    fetched = set(adapter.fetch_calls)
    assert target.lower() not in fetched, (
        "value-trace OFF must NOT follow past a service wallet"
    )
    assert case.config_used["coverage"]["value_matched_hops"] == []


def test_value_trace_is_directed_at_normal_nodes_too(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34 directed trace: with value-trace ON, even a NORMAL (non-service-
    wallet, < threshold outflows) node follows ONLY the value-matched onward
    hop — not all its outflows. This is what bounds the trace to the money path
    and stops the uncapped fan-out from exploding the whole graph. The seed
    (no inbound) still follows all of its outflows."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200  # M's 4 outflows < 200
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    target = HOP_B
    decoys = [f"0x{0xd1 + i:040x}" for i in range(3)]
    edges: dict[str, Any] = {
        SEED: [_native_row("0xseed1", SEED, HOP_A, eth_amount="50")],
        HOP_A: [  # 4 outflows — NOT a service wallet
            _native_row("0xmatch", HOP_A, target, eth_amount="50"),   # value match
            _native_row("0xd1", HOP_A, decoys[0], eth_amount="10"),
            _native_row("0xd2", HOP_A, decoys[1], eth_amount="20"),
            _native_row("0xd3", HOP_A, decoys[2], eth_amount="30"),
        ],
        target: [_native_row("0xt1", target, decoys[0], eth_amount="5")],
    }
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "VT_DIRECTED")

    fetched = set(adapter.fetch_calls)
    assert target.lower() in fetched, (
        "directed value-trace should follow the amount-matched hop at a normal node"
    )
    for d in decoys:
        assert d.lower() not in fetched, (
            f"decoy {d} (amount mismatch) must NOT be followed even at a normal node"
        )
    hops = case.config_used["coverage"]["value_matched_hops"]
    assert any(h["matched_to"].lower() == target.lower() for h in hops)


# ---------- v0.34.6: 1:N same-asset split / peel follow (opt-in) ---------- #


def _split_graph() -> tuple[dict[str, Any], list[str]]:
    """SEED --1000 ETH--> HOP_A, which PEELS it into 3 same-asset sends
    (400 + 350 + 260 = 1010 ETH, Δ1%) to X1/X2/X3 — no single outflow matches
    the 1000 ETH inbound, so the 1:1 matcher dead-ends here. Returns
    (edges, [X1, X2, X3])."""
    peels = [
        "0x00000000000000000000000000000000000000a1",
        "0x00000000000000000000000000000000000000a2",
        "0x00000000000000000000000000000000000000a3",
    ]
    edges: dict[str, Any] = {
        SEED: [_native_row("0xseed1", SEED, HOP_A, eth_amount="1000")],
        HOP_A: [
            _native_row("0xp1", HOP_A, peels[0], eth_amount="400"),
            _native_row("0xp2", HOP_A, peels[1], eth_amount="350"),
            _native_row("0xp3", HOP_A, peels[2], eth_amount="260"),
        ],
    }
    return edges, peels


def test_value_trace_follows_same_asset_split_when_enabled(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34.6: RECUPERO_VALUE_TRACE_FOLLOW_SPLITS=1 recovers a 1:N same-asset
    PEEL the 1:1 matcher misses — HOP_A split 1000 ETH into 400+350+260, and all
    three legs are followed (low confidence, kind=same_asset_split). This is what
    carries the Lazarus/Ronin trace past consolidation wallets that peel into
    mixer-denomination chunks instead of forwarding a single matching amount."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200  # HOP_A's 3 < 200
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_FOLLOW_SPLITS", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    edges, peels = _split_graph()
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "SPLIT_ON")

    fetched = set(adapter.fetch_calls)
    for p in peels:
        assert p.lower() in fetched, f"split-peel leg {p} was not followed"
    hops = case.config_used["coverage"]["value_matched_hops"]
    split_hops = [h for h in hops if h["kind"] == "same_asset_split"]
    assert len(split_hops) == 3, f"expected 3 split hops, got {hops}"
    assert all(h["confidence"] == "low" for h in split_hops)  # never medium/high


def test_value_trace_split_not_followed_by_default(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default (FOLLOW_SPLITS unset): a peel is NOT followed — the node is an
    honest value-dead-end, byte-identical to pre-v0.34.6 behavior. This keeps
    the opt-in opt-in (and Zigha 4/4 untouched)."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_VALUE_TRACE_FOLLOW_SPLITS", raising=False)
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    edges, peels = _split_graph()
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "SPLIT_OFF")

    fetched = set(adapter.fetch_calls)
    for p in peels:
        assert p.lower() not in fetched, (
            f"split leg {p} must NOT be followed when FOLLOW_SPLITS is off"
        )
    hops = case.config_used["coverage"]["value_matched_hops"]
    assert [h for h in hops if h["kind"] == "same_asset_split"] == []
    # HOP_A forwarded same-asset but nothing matched -> honest dead-end recorded.
    dead = case.config_used["coverage"]["value_dead_ends"]
    assert any(d["address"].lower() == HOP_A.lower() for d in dead)


# ---------- v0.34.7: label-aware terminal (stop-and-flag at a mixer) ---------- #

# Real Tornado Cash pool address from the shipped mixer seed list
# (src/recupero/labels/seeds/mixers.json) — LabelStore.load tags it
# category=mixer, so an outflow to it carries a mixer counterparty label.
TORNADO = "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"


def _mixer_peel_graph() -> dict[str, Any]:
    """SEED --100 ETH--> HOP_A, which PEELS into Tornado Cash as 30+30+40 ETH
    (no single outflow matches the 100 ETH inbound, so the 1:1 matcher
    dead-ends — the Ronin pattern in miniature)."""
    return {
        SEED: [_native_row("0xseed1", SEED, HOP_A, eth_amount="100")],
        HOP_A: [
            _native_row("0xm1", HOP_A, TORNADO, eth_amount="30"),
            _native_row("0xm2", HOP_A, TORNADO, eth_amount="30"),
            _native_row("0xm3", HOP_A, TORNADO, eth_amount="40"),
        ],
    }


def test_labeled_terminal_mixer_recorded_when_enabled(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34.7: RECUPERO_VALUE_TRACE_LABELED_TERMINALS=1 — at a directed node
    that peels its same-asset funds into a LABELED mixer (Tornado), the engine
    STOPS-AND-FLAGS: it records the mixer terminal (UNRECOVERABLE, aggregate
    100 ETH across 3 tx) and KEEPS the real deposit transfers on the case (so
    the brief classifies → Tornado → UNRECOVERABLE), instead of a generic
    dead-end. Mirrors TRM/Chainalysis mixer handling."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_LABELED_TERMINALS", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    adapter = GraphAdapter(_mixer_peel_graph())
    _wire(monkeypatch, adapter, FixedPriceClient())
    case = _run(config, env, tmp_path / "cases" / "TERM_ON")

    terms = case.config_used["coverage"]["labeled_terminals"]
    mix = [t for t in terms if t["terminal_address"].lower() == TORNADO.lower()]
    assert len(mix) == 1, f"expected one Tornado terminal record, got {terms}"
    assert mix[0]["status"] == "UNRECOVERABLE"
    assert mix[0]["label_category"] == "mixer"
    assert mix[0]["tx_count"] == 3
    assert mix[0]["agg_amount"] == "100"
    # the real deposit transfers are KEPT on the case (so the brief sees them)
    to_tornado = [t for t in case.transfers if t.to_address.lower() == TORNADO.lower()]
    assert len(to_tornado) == 3
    # ...and the node is NOT double-flagged as a generic dead-end
    dead = case.config_used["coverage"]["value_dead_ends"]
    assert not any(d["address"].lower() == HOP_A.lower() for d in dead)


def test_labeled_terminal_off_by_default(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default (LABELED_TERMINALS unset): the mixer peel is NOT recorded — the
    node is a generic value-dead-end and the deposit transfers are dropped
    (directed path keeps only matched hops). Preserves pre-v0.34.7 behavior /
    Zigha 4/4 byte-identically."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_VALUE_TRACE_LABELED_TERMINALS", raising=False)
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    adapter = GraphAdapter(_mixer_peel_graph())
    _wire(monkeypatch, adapter, FixedPriceClient())
    case = _run(config, env, tmp_path / "cases" / "TERM_OFF")

    assert case.config_used["coverage"]["labeled_terminals"] == []
    to_tornado = [t for t in case.transfers if t.to_address.lower() == TORNADO.lower()]
    assert to_tornado == []
    dead = case.config_used["coverage"]["value_dead_ends"]
    assert any(d["address"].lower() == HOP_A.lower() for d in dead)


def test_deep_reach_master_enables_recipe(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.35.4: RECUPERO_DEEP_REACH=1 alone (no individual knobs set) turns on
    the whole recipe — value-trace + split-follow + labeled-terminals + dormancy
    window — so the mixer peel is recorded as a labeled terminal."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200
    monkeypatch.setenv("RECUPERO_DEEP_REACH", "1")
    for k in ("RECUPERO_VALUE_TRACE", "RECUPERO_VALUE_TRACE_FOLLOW_SPLITS",
              "RECUPERO_VALUE_TRACE_LABELED_TERMINALS",
              "RECUPERO_VALUE_TRACE_WINDOW_HOURS",
              "RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD"):
        monkeypatch.delenv(k, raising=False)

    adapter = GraphAdapter(_mixer_peel_graph())
    _wire(monkeypatch, adapter, FixedPriceClient())
    case = _run(config, env, tmp_path / "cases" / "DEEP_ON")

    terms = case.config_used["coverage"]["labeled_terminals"]
    assert any(t["terminal_address"].lower() == TORNADO.lower() for t in terms), (
        "RECUPERO_DEEP_REACH should enable value-trace + labeled-terminals"
    )


def test_deep_reach_individual_override_wins(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit per-knob env var beats the master switch: DEEP_REACH=1 but
    LABELED_TERMINALS=0 → no terminal recorded (value-trace still on)."""
    config, env = cfg
    config.trace.max_depth = 3
    config.trace.service_wallet_outflow_threshold = 200
    monkeypatch.setenv("RECUPERO_DEEP_REACH", "1")
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_LABELED_TERMINALS", "0")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    adapter = GraphAdapter(_mixer_peel_graph())
    _wire(monkeypatch, adapter, FixedPriceClient())
    case = _run(config, env, tmp_path / "cases" / "DEEP_OVERRIDE")

    assert case.config_used["coverage"]["labeled_terminals"] == []


# ---------- v0.34 perf: prune-before-enrich (lightweight on high fan-out) ---------- #


class _CountingAdapter(ChainAdapter):
    """Adapter that returns a fixed outflow list and COUNTS the expensive
    per-outflow RPCs (is_contract, evidence-receipt) so a test can prove the
    lightweight (cheap-build) path engaged."""

    chain = Chain.ethereum

    def __init__(self, outflows: list[dict[str, Any]]) -> None:
        self._outflows = outflows
        self.is_contract_calls = 0
        self.evidence_calls = 0

    def block_at_or_before(self, ts: datetime) -> int:
        return 19000000

    def is_contract(self, address: str) -> bool:
        self.is_contract_calls += 1
        return False

    def fetch_native_outflows(
        self, from_address: str, start_block: int, **kwargs: Any
    ) -> list[dict[str, Any]]:
        return list(self._outflows)

    def fetch_erc20_outflows(
        self, from_address: str, start_block: int, **kwargs: Any
    ) -> list[dict[str, Any]]:
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        self.evidence_calls += 1
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


class _RecordingPrice:
    """Records the ``skip_contract_api`` flag of every price_at call."""

    def __init__(self) -> None:
        self.skip_flags: list[bool] = []

    def price_at(
        self, token: TokenRef, when: datetime, *, skip_contract_api: bool = False,
    ) -> PriceResult:
        self.skip_flags.append(skip_contract_api)
        return PriceResult(usd_value=Decimal("3000"), source="fake", error=None)

    def close(self) -> None:
        pass


def _hop_outflows(n: int) -> list[dict[str, Any]]:
    return [
        _native_row(f"0x{i:064x}", HOP_A, f"0x{(i + 1):040x}", eth_amount="1")
        for i in range(n)
    ]


def test_value_trace_lightweight_engages_for_high_fanout_nonseed(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34 perf: a NON-seed node with more outflows than
    RECUPERO_VALUE_TRACE_ENRICH_CEILING is built CHEAPLY under value-trace even
    when it is BELOW the service-wallet threshold — skipping the per-token
    CoinGecko contract API, the per-dest is_contract RPC, and the per-tx evidence
    fetch (the ~3-RPC-per-outflow wall that made a 10k-outflow node take hours).
    The aggregation finalizes the expensive ops for only the value-matched hops."""
    from recupero.trace import tracer as tracer_mod
    from recupero.trace.policies import TracePolicy

    config, _env = cfg
    monkeypatch.setattr(tracer_mod, "lookup_pit_safe", lambda *a, **k: None)
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_ENRICH_CEILING", "50")

    adapter = _CountingAdapter(_hop_outflows(60))   # 60 > 50 ceiling
    price = _RecordingPrice()
    policy = TracePolicy(max_depth=3, service_wallet_outflow_threshold=1000)  # 60 < 1000

    transfers, is_service = tracer_mod._trace_one_hop(
        adapter=adapter, label_store=object(), price_client=price, policy=policy,
        from_address=HOP_A, incident_time=datetime(2025, 1, 15, tzinfo=UTC),
        config=config, hop_depth=1, parent_transfer_id=None,
        evidence_dir=tmp_path, value_trace=True,
    )

    assert is_service is False                      # below the service-wallet bar
    assert len(transfers) == 60                     # lightweight skips dust filter
    assert all(price.skip_flags)                    # every price call skipped the contract API
    assert adapter.is_contract_calls == 0           # is_contract deferred to matched hops
    assert adapter.evidence_calls == 0              # evidence deferred to matched hops


def test_value_trace_full_path_when_below_enrich_ceiling(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A small non-seed node (<= ceiling, not a service wallet) keeps the full,
    fully-evidenced path — the cheap path must not silently swallow normal nodes."""
    from recupero.trace import tracer as tracer_mod
    from recupero.trace.policies import TracePolicy

    config, _env = cfg
    monkeypatch.setattr(tracer_mod, "lookup_pit_safe", lambda *a, **k: None)
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_ENRICH_CEILING", "50")

    adapter = _CountingAdapter(_hop_outflows(5))    # 5 <= 50 ceiling
    price = _RecordingPrice()
    policy = TracePolicy(max_depth=3, service_wallet_outflow_threshold=1000)

    transfers, is_service = tracer_mod._trace_one_hop(
        adapter=adapter, label_store=object(), price_client=price, policy=policy,
        from_address=HOP_A, incident_time=datetime(2025, 1, 15, tzinfo=UTC),
        config=config, hop_depth=1, parent_transfer_id=None,
        evidence_dir=tmp_path, value_trace=True,
    )

    assert is_service is False
    assert len(transfers) == 5
    assert not any(price.skip_flags)                # full pricing (contract API allowed)
    assert adapter.is_contract_calls == 5           # is_contract per destination
    assert adapter.evidence_calls == 5              # evidence per kept transfer


def test_value_trace_seed_never_lightweight_even_if_high_fanout(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The seed (hop_depth 0) is non-directed — every outflow is kept and must
    stay fully evidenced — so the count-based cheap trigger must NOT fire on it."""
    from recupero.trace import tracer as tracer_mod
    from recupero.trace.policies import TracePolicy

    config, _env = cfg
    monkeypatch.setattr(tracer_mod, "lookup_pit_safe", lambda *a, **k: None)
    monkeypatch.setenv("RECUPERO_VALUE_TRACE_ENRICH_CEILING", "50")

    adapter = _CountingAdapter(_hop_outflows(60))   # 60 > 50, but at the SEED
    price = _RecordingPrice()
    policy = TracePolicy(max_depth=3, service_wallet_outflow_threshold=1000)

    tracer_mod._trace_one_hop(
        adapter=adapter, label_store=object(), price_client=price, policy=policy,
        from_address=SEED, incident_time=datetime(2025, 1, 15, tzinfo=UTC),
        config=config, hop_depth=0, parent_transfer_id=None,
        evidence_dir=tmp_path, value_trace=True,
    )

    assert not any(price.skip_flags)                # seed fully priced
    assert adapter.is_contract_calls == 60          # seed fully enriched


def test_value_trace_matches_against_largest_inbound_not_first(
    cfg: tuple[RecuperoConfig, RecuperoEnv], tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.34 regression (live Zigha bug): a node funded by SEVERAL edges must
    value-match against the LARGEST (our funds), not whichever edge was seen
    first. Here the seed sends N a small 0.5 ETH leg FIRST, then a large 50 ETH
    leg. N forwards 50 ETH to TARGET and 0.5 ETH to a decoy. The trace must
    follow TARGET (matched to the 50 ETH inbound). Before the fix, only the
    first edge (0.5 ETH) was recorded as N's inbound, so the matcher chased the
    decoy and missed the real onward hop — exactly why the live trace stalled
    one hop after the seed."""
    config, env = cfg
    config.trace.max_depth = 3
    monkeypatch.setenv("RECUPERO_VALUE_TRACE", "1")
    monkeypatch.delenv("RECUPERO_SERVICE_WALLET_OUTFLOW_THRESHOLD", raising=False)

    target = HOP_B
    decoy = "0x00000000000000000000000000000000d3c0y000"
    edges: dict[str, Any] = {
        SEED: [
            _native_row("0xsmall", SEED, HOP_A, eth_amount="0.5"),  # small, FIRST
            _native_row("0xbig", SEED, HOP_A, eth_amount="50"),     # large, SECOND
        ],
        HOP_A: [
            _native_row("0xbigout", HOP_A, target, eth_amount="50"),    # == large in
            _native_row("0xsmallout", HOP_A, decoy, eth_amount="0.5"),  # == small in
        ],
        target: [_native_row("0xt1", target, decoy, eth_amount="1")],
    }
    adapter = GraphAdapter(edges)
    _wire(monkeypatch, adapter, FixedPriceClient())

    case = _run(config, env, tmp_path / "cases" / "VT_MULTI_IN")

    fetched = set(adapter.fetch_calls)
    assert target.lower() in fetched, (
        "must follow the hop matching the LARGEST inbound (50 ETH -> TARGET)"
    )
    assert decoy.lower() not in fetched, (
        "must NOT chase the small-inbound (0.5 ETH) decoy hop"
    )
    hops = case.config_used["coverage"]["value_matched_hops"]
    assert any(h["matched_to"].lower() == target.lower() for h in hops)


# ---- v0.34 audit fix: dust-aware inbound selection (_select_traced_inbound) ----


def test_select_traced_inbound_prefers_unpriced_real_over_priced_dust() -> None:
    """A tiny PRICED dust inbound must NOT displace the large UNPRICED real
    funds — otherwise the matcher chases the dust amount and misses the hop."""
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbound
    dust = SimpleNamespace(usd_value_at_tx=Decimal("5"), amount_decimal=Decimal("5"))
    real = SimpleNamespace(usd_value_at_tx=None, amount_decimal=Decimal("3000000"))
    assert _select_traced_inbound([dust, real], Decimal("10")) is real


def test_select_traced_inbound_meaningful_priced_wins() -> None:
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbound
    big = SimpleNamespace(usd_value_at_tx=Decimal("3000000"), amount_decimal=Decimal("3000000"))
    huge_unpriced = SimpleNamespace(usd_value_at_tx=None, amount_decimal=Decimal("9" * 18))
    # a genuinely-large PRICED inbound is "our funds" — it wins over a larger
    # raw-amount unpriced (likely a high-supply meme/poison) leg.
    assert _select_traced_inbound([huge_unpriced, big], Decimal("10")) is big


def test_select_traced_inbound_all_priced_dust_picks_largest() -> None:
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbound
    a = SimpleNamespace(usd_value_at_tx=Decimal("3"), amount_decimal=Decimal("3"))
    b = SimpleNamespace(usd_value_at_tx=Decimal("8"), amount_decimal=Decimal("8"))
    assert _select_traced_inbound([a, b], Decimal("10")) is b


def test_select_traced_inbound_empty_is_none() -> None:
    from recupero.trace.tracer import _select_traced_inbound
    assert _select_traced_inbound([], Decimal("10")) is None


# ---- v0.34.1: follow the UNPRICED same-asset leg too (Zigha msyrupUSDp gap) ----


def test_select_traced_inbounds_includes_unpriced_leg() -> None:
    """The Zigha case: a hub receives a tiny PRICED ETH leg + a large UNPRICED
    msyrupUSDp leg. The matcher must trace BOTH — the priced primary AND the
    unpriced leg — so the exact same-asset onward hop (unpriced) is followed."""
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbounds
    eth = SimpleNamespace(usd_value_at_tx=Decimal("2161"), amount_decimal=Decimal("0.477"))
    msyrup = SimpleNamespace(usd_value_at_tx=None, amount_decimal=Decimal("3109861.72"))
    out = _select_traced_inbounds([eth, msyrup], Decimal("10"))
    assert eth in out and msyrup in out
    assert out[0] is eth  # priced primary first
    assert len(out) == 2


def test_select_traced_inbounds_no_duplicate_when_primary_unpriced() -> None:
    """When every priced leg is dust, the primary IS the largest unpriced leg —
    it must not be added a second time."""
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbounds
    dust = SimpleNamespace(usd_value_at_tx=Decimal("3"), amount_decimal=Decimal("3"))
    real = SimpleNamespace(usd_value_at_tx=None, amount_decimal=Decimal("3000000"))
    out = _select_traced_inbounds([dust, real], Decimal("10"))
    assert out == [real]


def test_select_traced_inbounds_empty() -> None:
    from recupero.trace.tracer import _select_traced_inbounds
    assert _select_traced_inbounds([], Decimal("10")) == []


def test_select_traced_inbounds_skips_homoglyph_poison() -> None:
    """A large UNPRICED homoglyph-poison inbound (Lisu "USDC") must be ignored,
    and the REAL (smaller) unpriced USDC leg selected — otherwise the
    unpriced-same-asset follow chases address-poisoning spam (the Zigha
    Arbitrum failure mode)."""
    from types import SimpleNamespace

    from recupero.trace.tracer import _select_traced_inbounds
    poison = SimpleNamespace(
        usd_value_at_tx=None, amount_decimal=Decimal("9999999"),
        token=SimpleNamespace(symbol="ꓴꓢꓓС", contract="0xb4094bd2"),
    )
    real = SimpleNamespace(
        usd_value_at_tx=None, amount_decimal=Decimal("349999"),
        token=SimpleNamespace(symbol="USDC", contract="0xaf88d065"),
    )
    out = _select_traced_inbounds([poison, real], Decimal("10"))
    assert real in out
    assert poison not in out


# ---- v0.34.1: dead-end detection (coverage honesty) ----


def _tok(contract: str | None, symbol: str):
    from types import SimpleNamespace
    return SimpleNamespace(contract=contract, symbol=symbol)


def _xfer(token):
    from types import SimpleNamespace
    return SimpleNamespace(token=token)


def test_node_forwarded_inbound_asset_same_contract_true() -> None:
    from recupero.trace.tracer import _node_forwarded_inbound_asset
    inbound = _xfer(_tok("0x2fe058cc", "msyrupUSDp"))
    outs = [_xfer(_tok("0xdead", "USDC")), _xfer(_tok("0x2FE058CC", "msyrupUSDp"))]
    assert _node_forwarded_inbound_asset(inbound, outs) is True


def test_node_forwarded_inbound_asset_different_asset_false() -> None:
    """A resting terminal: the node received msyrupUSDp but only forwards OTHER
    assets (its own unrelated activity) → NOT a dead-end."""
    from recupero.trace.tracer import _node_forwarded_inbound_asset
    inbound = _xfer(_tok("0x2fe058cc", "msyrupUSDp"))
    outs = [_xfer(_tok("0xdead", "USDC")), _xfer(_tok("0xbeef", "PENDLE"))]
    assert _node_forwarded_inbound_asset(inbound, outs) is False


def test_node_forwarded_inbound_asset_native_symbol_match() -> None:
    from recupero.trace.tracer import _node_forwarded_inbound_asset
    inbound = _xfer(_tok(None, "ETH"))
    assert _node_forwarded_inbound_asset(inbound, [_xfer(_tok(None, "ETH"))]) is True
    assert _node_forwarded_inbound_asset(inbound, [_xfer(_tok("0xabc", "WETH"))]) is False
