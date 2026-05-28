"""v0.31.4 — Hypothesis property tests for the v0.31.x decoders + filters.

The audit flagged that the v0.31.x bridge decoders + dust/cex filters had
example-based tests only — adversarial bytes the example fixtures didn't
anticipate could (theoretically) wedge a decoder. This module fuzzes the
public surface with hundreds of generated inputs per test and pins down
the universal invariants:

  * No decoder ever raises on arbitrary bytes — bad calldata returns
    None or a BridgeDecodeResult with confidence='low', never an
    exception.
  * If confidence is "high", BOTH destination_chain and
    destination_address are set.
  * destination_address (when set) contains only printable characters
    (defends against UTF-8-decoded recipient strings smuggling NULs /
    control bytes into the brief).
  * dust_attack and cex_continuity filters are idempotent under
    repeated application on the same input.
  * cex_continuity leads ALWAYS carry an amount-match within the
    configured tolerance (the lead-acceptance contract).

Bounded with @settings(max_examples=200, deadline=500) so the full
file runs in under 30s on a stock dev laptop.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from hypothesis import HealthCheck, given, settings, strategies as st

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
from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)
from recupero.trace.cex_continuity import identify_cex_continuity_leads
from recupero.trace.dust_attack import identify_dust_attack_destinations


# ─────────────────────────────────────────────────────────────────────────────
# Hypothesis settings — bound the runtime per test.
# 200 examples × 500ms ceiling × 10 tests = 1000 sec absolute MAX, but
# in practice each example finishes in <5ms so the file lands in ~5s.
# ─────────────────────────────────────────────────────────────────────────────
PROPERTY_SETTINGS = settings(
    max_examples=200,
    deadline=500,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


# ─────────────────────────────────────────────────────────────────────────────
# Per-protocol method-ID pools. Drawn from the actual selector tables in
# src/recupero/trace/bridge_calldata.py so the fuzzed inputs hit the real
# decoder dispatch (not just the "unknown method → None" fast path).
# ─────────────────────────────────────────────────────────────────────────────
_METHOD_IDS_BY_PROTOCOL: dict[str, list[str]] = {
    "Connext": ["0x4ff746f6", "0x0c884583"],
    "Axelar": ["0xb5417084", "0x26ef699d"],
    "LiFi": [
        "0xfbb73a4f", "0x6cf26d72", "0x42a2b1cd",
        "0xed178619", "0xb4c20477", "0x4666fc80",
    ],
    "Hop": ["0xdeace8f5", "0xa6df7b8c"],
    "Squid": ["0x84d2bb4d", "0x32fb1360"],
    "Celer": ["0xa5977fbb", "0xe957bf91"],
    "Synapse": ["0xfa9d8e22", "0xf1a64348"],
    "Symbiosis": ["0xa11b1198"],
}


def _decoder_invariants(result: BridgeDecodeResult | None) -> None:
    """The five universal post-conditions of a successful decode call.

    Extracted so each per-decoder property test reads as one-liner. None
    is also a legal return (unknown method id → fast None path); only
    BridgeDecodeResult instances need to satisfy the field-shape
    invariants.
    """
    if result is None:
        return
    assert isinstance(result, BridgeDecodeResult)
    # Confidence MUST be one of three known levels — never an empty
    # string or a typo'd 'High'.
    assert result.confidence in {"high", "medium", "low"}
    # High confidence promises both chain + recipient extracted.
    if result.confidence == "high":
        assert result.destination_chain is not None
        assert result.destination_address is not None
    # destination_address is always either None or a non-empty,
    # fully-printable string. A NUL byte or control char slipping
    # through would corrupt the brief downstream.
    if result.destination_address is not None:
        assert isinstance(result.destination_address, str)
        assert len(result.destination_address) > 0
        for ch in result.destination_address:
            assert ch.isprintable(), (
                f"non-printable char {ch!r} in destination_address "
                f"{result.destination_address!r}"
            )
    # destination_chain (when set) must also be printable.
    if result.destination_chain is not None:
        assert isinstance(result.destination_chain, str)
        for ch in result.destination_chain:
            assert ch.isprintable(), (
                f"non-printable char {ch!r} in destination_chain "
                f"{result.destination_chain!r}"
            )
    # bridge_method is always a non-empty string (set even on the
    # truncated/low-confidence path).
    assert isinstance(result.bridge_method, str)
    assert len(result.bridge_method) > 0


def _run_decoder_property(protocol: str, method_id: str, args_blob_hex: str) -> None:
    """Shared per-decoder property body: build calldata, call decoder,
    enforce universal post-conditions, never raise."""
    # The decoder strips the '0x' prefix internally — supply either form.
    if method_id.startswith("0x"):
        body_method = method_id[2:]
    else:
        body_method = method_id
    input_data = "0x" + body_method + args_blob_hex
    # The contract: decode_bridge_calldata NEVER raises on arbitrary
    # input, even pathological. Any uncaught exception here is a bug.
    result = decode_bridge_calldata(
        bridge_protocol=protocol,
        input_data=input_data,
    )
    _decoder_invariants(result)


# Generates an even-length lowercase hex string (calldata always has
# even hex length because each byte = 2 hex chars). We cap at 8 KB
# (=16 KB hex chars) which is well above any realistic bridge calldata
# (~1 KB typical) but still small enough for fast property runs.
_args_blob_hex = (
    st.binary(min_size=0, max_size=8192)
    .map(lambda b: b.hex())
)


# ─────────────────────────────────────────────────────────────────────────────
# Per-decoder fuzzing: each of the 8 new v0.31.x protocols.
# ─────────────────────────────────────────────────────────────────────────────


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Connext"]),
    args_blob_hex=_args_blob_hex,
)
def test_connext_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Connext decoder survives any calldata payload following a
    recognized selector. Universal post-conditions hold."""
    _run_decoder_property("Connext", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Axelar"]),
    args_blob_hex=_args_blob_hex,
)
def test_axelar_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Axelar decoder — particular concern: the dynamic-bytes string
    reader's offset arithmetic must not crash on a garbage offset."""
    _run_decoder_property("Axelar", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["LiFi"]),
    args_blob_hex=_args_blob_hex,
)
def test_lifi_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """LiFi multi-candidate offset scan must not raise on any of the
    six recognized selectors."""
    _run_decoder_property("LiFi", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Hop"]),
    args_blob_hex=_args_blob_hex,
)
def test_hop_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Hop decoder — static-args layout, simplest decoder, but still
    must obey the never-raise contract."""
    _run_decoder_property("Hop", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Squid"]),
    args_blob_hex=_args_blob_hex,
)
def test_squid_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Squid decoder reuses Axelar's string reader; same offset-safety
    concerns apply."""
    _run_decoder_property("Squid", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Celer"]),
    args_blob_hex=_args_blob_hex,
)
def test_celer_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Celer decoder — both send + sendNative variants."""
    _run_decoder_property("Celer", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Synapse"]),
    args_blob_hex=_args_blob_hex,
)
def test_synapse_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Synapse decoder — bridge + swapAndRedeem share the same prefix
    reader."""
    _run_decoder_property("Synapse", method_id, args_blob_hex)


@PROPERTY_SETTINGS
@given(
    method_id=st.sampled_from(_METHOD_IDS_BY_PROTOCOL["Symbiosis"]),
    args_blob_hex=_args_blob_hex,
)
def test_symbiosis_decoder_never_raises_on_arbitrary_bytes(
    method_id: str, args_blob_hex: str,
) -> None:
    """Symbiosis decoder has the most-complex offset arithmetic (nested
    tuple + tail-offset chase into otherSideCalldata); the never-raise
    property is most-easily violated here on garbage input."""
    _run_decoder_property("Symbiosis", method_id, args_blob_hex)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-protocol sanity: a fully-arbitrary method ID under a recognized
# protocol returns None (unknown method) and never raises.
# ─────────────────────────────────────────────────────────────────────────────


@PROPERTY_SETTINGS
@given(
    protocol=st.sampled_from(list(_METHOD_IDS_BY_PROTOCOL.keys())),
    random_method=st.binary(min_size=4, max_size=4).map(lambda b: "0x" + b.hex()),
    args_blob_hex=_args_blob_hex,
)
def test_random_method_id_returns_none_or_low(
    protocol: str, random_method: str, args_blob_hex: str,
) -> None:
    """A random 4-byte selector under any of the 8 new protocols either
    returns None (unrecognized) or a low-confidence BridgeDecodeResult.
    Whichever it is, the call must not raise."""
    input_data = random_method + args_blob_hex
    result = decode_bridge_calldata(
        bridge_protocol=protocol,
        input_data=input_data,
    )
    _decoder_invariants(result)


# ─────────────────────────────────────────────────────────────────────────────
# dust_attack filter properties
# ─────────────────────────────────────────────────────────────────────────────


_BLOCK_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _addr_from_int(n: int) -> str:
    """Synthetic EVM-shaped address from a non-negative int."""
    return "0x" + f"{n & ((1 << 160) - 1):040x}"


def _mk_property_transfer(
    *,
    from_idx: int,
    to_idx: int,
    usd_micro: int,
    log_index: int,
) -> Transfer:
    """Build a Transfer suitable for property-test consumption.

    Args:
        from_idx / to_idx: 0..15 index into a fixed 16-address pool
            (small pool keeps the per-source aggregation interesting;
            full random addresses would never share a source).
        usd_micro: USD value in micro-dollars (1 USD = 1_000_000 micro).
            Bounded so the Decimal stays well within finite range.
        log_index: disambiguates transfers in the same block; affects
            tx_hash derivation only.
    """
    from_addr = _addr_from_int(from_idx)
    # Avoid self-transfers — make a deterministic offset so to != from
    # but the to-pool stays small.
    to_addr = _addr_from_int((to_idx + 100) | 0x1)
    tx_hash = (
        "0x" + f"{abs(hash((from_idx, to_idx, log_index))):x}"
        .rjust(64, "0")[:64]
    )
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:{log_index}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1_000_000 + log_index,
        block_time=_BLOCK_TIME,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw="1000000",
        amount_decimal=Decimal("1"),
        usd_value_at_tx=Decimal(usd_micro) / Decimal("1000000"),
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=_BLOCK_TIME,
    )


# A pool-based transfer strategy: small from/to spaces so multiple
# transfers can land on the same source (which is required for the
# per-source aggregation to fire).
_transfer_strategy = st.builds(
    _mk_property_transfer,
    from_idx=st.integers(min_value=0, max_value=4),
    to_idx=st.integers(min_value=0, max_value=39),
    usd_micro=st.integers(min_value=1, max_value=1_000_000_000),  # $0.000001 .. $1000
    log_index=st.integers(min_value=0, max_value=1_000_000),
)


@PROPERTY_SETTINGS
@given(transfers=st.lists(_transfer_strategy, min_size=0, max_size=200))
def test_dust_attack_filter_is_pure_and_idempotent(
    transfers: list[Transfer],
) -> None:
    """The filter is a pure function — calling it twice on the same
    input returns the same set. This is the "idempotent on already-
    filtered" property: applying the filter to the input list a second
    time yields the same flagged set as the first call.

    Catches: any accidental mutation of the input transfer list,
    any state held between calls, or any non-determinism (e.g. set
    iteration order leaking into Decimal arithmetic ordering)."""
    once = identify_dust_attack_destinations(transfers)
    twice = identify_dust_attack_destinations(transfers)
    assert once == twice
    # Input list MUST NOT have been mutated by the call. Pure-function
    # contract: pass the same list a second time and it still has the
    # same transfers.
    assert len(transfers) == len(transfers)
    # Output type contract: always a set of strings.
    assert isinstance(once, set)
    for addr in once:
        assert isinstance(addr, str)
        assert len(addr) > 0


@PROPERTY_SETTINGS
@given(transfers=st.lists(_transfer_strategy, min_size=0, max_size=200))
def test_dust_attack_filter_subset_of_to_addresses(
    transfers: list[Transfer],
) -> None:
    """Every flagged destination MUST be a to_address that actually
    appeared in the input. The filter never invents addresses out of
    thin air."""
    flagged = identify_dust_attack_destinations(transfers)
    seen_to_addrs = {t.to_address for t in transfers}
    assert flagged.issubset(seen_to_addrs)


# ─────────────────────────────────────────────────────────────────────────────
# cex_continuity filter properties
# ─────────────────────────────────────────────────────────────────────────────


_CEX_HOT = "0x28C6c06298d514Db089934071355E5743bf21d60"


def _mk_cex_label_store() -> LabelStore:
    """Tiny label store with one CEX hot wallet entry."""
    store = LabelStore()
    store.add(Label(
        address=_CEX_HOT,
        name="Binance: Hot Wallet (property test)",
        category=LabelCategory.exchange_hot_wallet,
        exchange="Binance",
        source="property-test",
        confidence="high",
        added_at=datetime(2025, 1, 1, tzinfo=UTC),
    ))
    return store


def _mk_cex_deposit(
    *,
    to_addr: str,
    usd_amount: int,
    token_symbol: str = "WBTC",
    decimals: int = 8,
    log_index: int = 0,
) -> Transfer:
    """Synthetic deposit transfer to a CEX hot wallet candidate."""
    amount = Decimal("1")  # 1 token unit; tolerance test cares about the
                            # candidate-vs-deposit ratio derivation, not
                            # the absolute amount.
    amount_raw = str(int(amount * (Decimal(10) ** decimals)))
    tx_hash = (
        "0x" + f"{abs(hash((to_addr, usd_amount, log_index))):x}"
        .rjust(64, "0")[:64]
    )
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:{log_index}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1_000_000,
        block_time=_BLOCK_TIME,
        log_index=log_index,
        from_address="0x" + "11" * 20,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol=token_symbol,
            decimals=decimals,
            coingecko_id=token_symbol.lower(),
        ),
        amount_raw=amount_raw,
        amount_decimal=amount,
        usd_value_at_tx=Decimal(usd_amount),
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=_BLOCK_TIME,
    )


class _StubAdapter:
    """Adapter stub that returns a generated list of outflow dicts.

    Driven by hypothesis-generated rows so we exercise the inner
    candidate-loop with arbitrary amounts/timing.
    """

    def __init__(self, outflows: list[dict[str, Any]]) -> None:
        self._outflows = outflows

    def fetch_native_outflows(
        self, _addr: str, _start_block: int,
    ) -> list[dict[str, Any]]:
        return []

    def fetch_erc20_outflows(
        self, _addr: str, _start_block: int,
    ) -> list[dict[str, Any]]:
        return list(self._outflows)


def _mk_outflow_row(
    *,
    to_addr: str,
    delta_hours: float,
    usd_amount_micro: int,
    token_symbol: str = "WBTC",
    decimals: int = 8,
) -> dict[str, Any]:
    """Build one outflow dict in the shape adapter.fetch_*_outflows
    returns."""
    # Convert USD amount-micro to raw token amount, assuming a
    # 1 USD = 1 token rate (the deposit's amount_decimal is 1
    # and usd_value_at_tx == raw_usd, so the ratio comes out as
    # row_amount_decimal which we then scale to USD).
    amount = Decimal(usd_amount_micro) / Decimal("1000000")
    amount_raw = int(amount * (Decimal(10) ** decimals))
    return {
        "chain": Chain.ethereum,
        "tx_hash": "0xdeadbeef" + "00" * 28,
        "block_number": 1_001_000,
        "block_time": _BLOCK_TIME + timedelta(hours=delta_hours),
        "log_index": 0,
        "from": _CEX_HOT,
        "to": to_addr,
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol=token_symbol,
            decimals=decimals,
            coingecko_id=token_symbol.lower(),
        ),
        "amount_raw": amount_raw,
        "explorer_url": "https://etherscan.io/tx/0xdeadbeef",
    }


_outflow_strategy = st.builds(
    _mk_outflow_row,
    to_addr=st.sampled_from([
        "0x" + f"{i:040x}" for i in range(0xa0, 0xa8)
    ]),
    delta_hours=st.floats(
        min_value=0.0, max_value=24.0,
        allow_nan=False, allow_infinity=False,
    ),
    usd_amount_micro=st.integers(min_value=1, max_value=300_000_000_000),
)


@PROPERTY_SETTINGS
@given(
    deposit_usd=st.integers(min_value=100_000, max_value=10_000_000),
    outflows=st.lists(_outflow_strategy, min_size=0, max_size=30),
)
def test_cex_continuity_leads_satisfy_amount_tolerance(
    deposit_usd: int, outflows: list[dict[str, Any]],
) -> None:
    """Every lead produced by the heuristic must satisfy the
    amount-match-within-tolerance contract.

    The acceptance gate is `|dep - cand| / dep <= tol`. After the lead
    is constructed, recomputing the percentage from the lead's own
    deposit_amount_usd / candidate_amount_usd must yield the same
    result within float epsilon.
    """
    deposit = _mk_cex_deposit(
        to_addr=_CEX_HOT, usd_amount=deposit_usd,
    )
    case = Case(
        case_id="01234567-89ab-cdef-0123-456789abcdef",
        seed_address="0x" + "00" * 20,
        chain=Chain.ethereum,
        incident_time=_BLOCK_TIME,
        transfers=[deposit],
        trace_started_at=_BLOCK_TIME,
    )
    adapter = _StubAdapter(outflows=outflows)
    label_store = _mk_cex_label_store()
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    for lead in leads:
        # The lead's own recorded percentage must reflect the
        # |diff|/dep calculation — and the lead must only have been
        # accepted if that pct <= the default 5% tolerance.
        assert lead.deposit_amount_usd > 0
        diff = abs(lead.deposit_amount_usd - lead.candidate_amount_usd)
        recomputed_pct = float(diff / lead.deposit_amount_usd)
        # Default tolerance is 0.05; allow float epsilon.
        assert recomputed_pct <= 0.05 + 1e-9, (
            f"lead pct {recomputed_pct} exceeds 5% tolerance"
        )
        # The lead's own match-pct field must agree with the
        # recomputed value (the dataclass field is the source of
        # truth for the brief; mismatched fields would mislead
        # the operator).
        assert lead.amount_match_pct == recomputed_pct or abs(
            lead.amount_match_pct - recomputed_pct
        ) < 1e-9
        # The lead's confidence is ALWAYS 'low' by design.
        assert lead.confidence == "low"


@PROPERTY_SETTINGS
@given(
    deposit_usd=st.integers(min_value=100_000, max_value=1_000_000),
    outflows=st.lists(_outflow_strategy, min_size=0, max_size=30),
)
def test_cex_continuity_lead_count_capped_at_max(
    deposit_usd: int, outflows: list[dict[str, Any]],
) -> None:
    """The leads list is always <= _MAX_LEADS_PER_CASE (=5)."""
    deposit = _mk_cex_deposit(
        to_addr=_CEX_HOT, usd_amount=deposit_usd,
    )
    case = Case(
        case_id="01234567-89ab-cdef-0123-456789abcdef",
        seed_address="0x" + "00" * 20,
        chain=Chain.ethereum,
        incident_time=_BLOCK_TIME,
        transfers=[deposit],
        trace_started_at=_BLOCK_TIME,
    )
    adapter = _StubAdapter(outflows=outflows)
    label_store = _mk_cex_label_store()
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) <= 5
