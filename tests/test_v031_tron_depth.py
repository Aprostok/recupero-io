"""v0.31.0 Tron USDT trace-depth regression tests (Gap #6).

Half of all USDT volume settles on Tron — making the Tron adapter
the single most-load-bearing non-EVM surface in the codebase. This
file pins behavior at three depth levels and locks in the documented
gaps so they cannot silently regress further.

Coverage layers:

1. **Adapter contract (offline)** — TRC-20 normalization, the
   TRX-native deferred-by-design behavior, and time-windowed
   pagination. These re-cover ground already tested in
   ``test_tron_adapter.py`` but at the depth angle: do we see what
   we think we see when the BFS hands the adapter realistic Tron
   shapes?

2. **Cross-chain handoff seam (offline)** — the cross_chain.py /
   bridges.json composition. The current bridges.json has **zero
   entries keyed to ``chain: "tron"``**, so any handoff initiated
   ON Tron (TRC-20 transfer landing at a Tron-side bridge program
   like JustBridge / Sun.io / AllBridge-Tron / Wormhole portal) is
   silently undetected. The opposite direction — Wormhole EVM-side
   transferTokens with recipientChain=18 (Tron) — IS decoded by
   bridge_calldata.py per v0.17.5. We pin both behaviors so the
   gap is visible in a CI report.

3. **Live verification stubs (skipped by default)** — placeholders
   for tests that would require a live TronGrid API call to
   verify (USDT contract address invariants, real CEX deposit
   address detection). Marked with ``@pytest.mark.skip`` and a
   docstring describing what live verification would prove; opt
   in with ``RECUPERO_LIVE_TRONGRID=1``.

Doc: docs/V031_TRON_SOLANA_DEPTH.md walks through the full
assessment + the small fixes landed alongside this file.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from recupero.chains.tron.adapter import TronAdapter
from recupero.models import Chain
from recupero.trace.cross_chain import (
    BridgeInfo,
    identify_cross_chain_handoffs,
)

# ---- Real Tron mainnet shapes used across the assertions ---- #

USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDC_TRC20 = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
# Real-shape Tron base58check addresses. Not tied to any specific
# entity — used purely as VICTIM / PERP placeholders.
VICTIM = "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX"
PERP = "TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9"


def _trc20_event(
    *,
    tx_id: str = "tx_abc",
    from_addr: str = VICTIM,
    to_addr: str = PERP,
    value: str = "1234560000",
    block_ts_ms: int = 1_750_000_000_000,
    block_number: int = 65_000_000,
    token_address: str = USDT_TRC20,
    symbol: str = "USDT",
    decimals: int = 6,
) -> dict:
    """Construct a Helius-shape TRC-20 transfer event for the adapter."""
    return {
        "transaction_id": tx_id,
        "block_timestamp": block_ts_ms,
        "block_number": block_number,
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "type": "Transfer",
        "token_info": {
            "symbol": symbol,
            "decimals": decimals,
            "name": "Tether USD",
            "address": token_address,
        },
    }


def _mk_adapter(*, account_data=None, trc20_events=None) -> TronAdapter:
    client = MagicMock()
    client.get_account.return_value = {"data": account_data or []}
    client.get_trc20_transfers.return_value = trc20_events or []
    return TronAdapter(client=client)


# ─────────────────────────────────────────────────────────────────────
# Layer 1 — adapter depth (offline)
# ─────────────────────────────────────────────────────────────────────


def test_usdt_trc20_outflow_carries_coingecko_id() -> None:
    """Tron's TRC-20 endpoint returns USDT events with the canonical
    contract; the adapter must wire coingecko_id=tether so the pricing
    stage doesn't fall back to slow on-the-fly lookups. Pre-v0.12.0 the
    map was missing → every Tron USDT trace silently priced at $0."""
    adapter = _mk_adapter(trc20_events=[_trc20_event()])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    rec = out[0]
    assert rec["token"].symbol == "USDT"
    assert rec["token"].coingecko_id == "tether"
    assert rec["chain"] == Chain.tron


def test_usdc_trc20_outflow_carries_coingecko_id() -> None:
    """USDC on Tron is the second-largest non-Tether stable on the
    chain. Its coingecko_id must be wired or the pricing stage falls
    through to a no-op."""
    adapter = _mk_adapter(trc20_events=[
        _trc20_event(token_address=USDC_TRC20, symbol="USDC"),
    ])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert len(out) == 1
    assert out[0]["token"].coingecko_id == "usd-coin"


def test_native_trx_outflows_returns_empty_by_design() -> None:
    """Pin the documented v0.12.0 design decision: native TRX outflows
    return ``[]``. USDT-TRC20 (the laundering surface) does NOT flow
    through native TRX — operators move stablecoins, and TRX gas dust
    is intentionally ignored.

    If a future patch flips this to return TRX transfers, the brief's
    "earliest/latest block" rollup behavior changes shape — bumping
    this assertion is the deliberate signal.
    """
    adapter = _mk_adapter()
    assert adapter.fetch_native_outflows(VICTIM, start_block=0) == []


def test_block_at_or_before_returns_unix_seconds_not_ms() -> None:
    """The v0.16.7 round-9 audit fix: Tron's block_at_or_before
    returns unix-SECONDS that the adapter then multiplies by 1000 to
    get the TronGrid min_timestamp (which is in ms). Pin the unit so
    a future refactor doesn't accidentally return ms here (causing
    the *1000 multiplication to over-shoot by 10^6 and silently
    fetch zero events)."""
    adapter = _mk_adapter()
    ts = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    result = adapter.block_at_or_before(ts)
    # 2026-01-01 12:00 UTC is ~1.767e9 seconds; ~1.767e12 ms.
    # We MUST be in the seconds range.
    assert 1_700_000_000 < result < 2_000_000_000
    assert result == int(ts.timestamp())


def test_min_timestamp_threaded_through_to_trongrid() -> None:
    """v0.18.5 round-11 chains-CRIT-006 fix: start_block (unix-seconds)
    must reach the TronGrid client as min_timestamp in MILLISECONDS.
    Pre-fix every Tron trace silently fetched full history → hit the
    10k pagination cap → truncated the OLDEST data (= the incident
    period). Pin the unit conversion."""
    client = MagicMock()
    client.get_trc20_transfers.return_value = []
    adapter = TronAdapter(client=client)
    adapter.fetch_erc20_outflows(VICTIM, start_block=1_700_000_000)
    call = client.get_trc20_transfers.call_args
    assert call.kwargs["min_timestamp"] == 1_700_000_000_000  # seconds → ms


def test_zero_start_block_passes_no_min_timestamp() -> None:
    """start_block=0 (i.e., trace full history) must not pass
    min_timestamp=0 — TronGrid would treat that as "events at epoch
    only" and return nothing."""
    client = MagicMock()
    client.get_trc20_transfers.return_value = []
    adapter = TronAdapter(client=client)
    adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    call = client.get_trc20_transfers.call_args
    assert call.kwargs["min_timestamp"] is None


def test_outflow_block_number_threaded_through() -> None:
    """v0.18.5 chains-HIGH-003: pre-fix every Tron transfer was
    pinned at block_number=0, which broke BFS cursor advance and
    cross-chain block ordering. Pin that we now propagate the event's
    block_number field."""
    ev = _trc20_event(block_number=65_123_456)
    adapter = _mk_adapter(trc20_events=[ev])
    out = adapter.fetch_erc20_outflows(VICTIM, start_block=0)
    assert out[0]["block_number"] == 65_123_456


# ─────────────────────────────────────────────────────────────────────
# Layer 2 — cross-chain handoff seam (offline)
# ─────────────────────────────────────────────────────────────────────


def _stub_case(transfers):
    case = MagicMock()
    case.case_id = "TRON-DEPTH-TEST"
    case.transfers = transfers
    return case


def _stub_transfer(
    *,
    chain: Chain = Chain.tron,
    to_address: str = "TXJgMdjVX5dKiQaUi9QobwNXtRBkQ7vrPp",
    tx_hash: str = "abc" * 21 + "f",
    amount_usd=Decimal("50000"),
) -> MagicMock:
    t = MagicMock()
    t.chain = chain
    t.to_address = to_address
    t.from_address = VICTIM
    t.tx_hash = tx_hash
    t.usd_value_at_tx = amount_usd
    t.amount_decimal = Decimal("50000")
    t.token = MagicMock()
    t.token.symbol = "USDT"
    t.block_time = datetime(2026, 1, 1, tzinfo=UTC)
    t.explorer_url = f"https://tronscan.org/#/transaction/{tx_hash}"
    return t


def test_tron_keyed_bridge_db_lookup_works_when_populated() -> None:
    """**Forward-compatibility lock.** ``ingest_bridge_seeds`` already
    accepts ``"chain": "tron"`` entries (the Chain enum has had
    ``Chain.tron`` since v0.12.0). This test pins that — if a future
    bridge-DB pass adds Tron-side bridge entries, the detection seam
    fires correctly.

    Today (v0.31.0) the JSON has ZERO Tron-keyed rows; see the
    ``test_tron_keyed_bridge_db_is_empty_today`` companion below
    which makes the gap visible in CI.
    """
    bridge_addr = "TXJgMdjVX5dKiQaUi9QobwNXtRBkQ7vrPp"  # placeholder b58
    bridge_db = {
        (Chain.tron, bridge_addr): BridgeInfo(
            chain=Chain.tron,
            address=bridge_addr,
            name="JustBridge (hypothetical Tron-side router)",
            protocol="just",
            confidence="medium",
            follow_up_url=None,
            supports_to_chains=("ethereum",),
        ),
    }
    case = _stub_case([_stub_transfer(to_address=bridge_addr)])
    handoffs = identify_cross_chain_handoffs(case, bridge_db=bridge_db)
    assert len(handoffs) == 1
    assert handoffs[0].source_chain == Chain.tron
    assert handoffs[0].bridge_name.startswith("JustBridge")
    # destination_chain_candidates is the v0.8.1 fallback shape — no
    # decoded_destination_chain because we passed no adapter.
    assert "ethereum" in handoffs[0].destination_chain_candidates


def test_tron_keyed_bridge_db_has_coverage() -> None:
    """v0.31.2 — was previously a "visible-gap pin" asserting the
    shipped bridges.json had ZERO Tron-keyed entries. Closed by the
    v0.31.2 Tron+Solana seed-expansion pass:
      * SunSwap Smart Router
      * JustLend jTRX
      * USDD PSM
    All three confirmed externally (Tronscan + JustLend docs); the
    Wormhole/Stargate/PolyNetwork bridges are deliberately NOT
    deployed on Tron (verified against Wormhole SDK constants +
    Stargate gitbook deployments + PolyNetwork config_mainnet.json),
    so the Tron-side cross-asset hops are DEX/lending/PSM contracts,
    which is why those are flagged ``category: "bridge"``.

    The test now LOCKS the coverage — if entries are accidentally
    removed, this trips. To add more, just bump the count.
    See ``docs/V031_2_TRON_SOLANA_SEEDS.md`` for the full provenance
    table.
    """
    from recupero.trace.cross_chain import ingest_bridge_seeds

    db = ingest_bridge_seeds()
    tron_keys = [k for k in db if k[0] == Chain.tron]
    assert len(tron_keys) >= 3, (
        f"Tron-keyed bridge coverage REGRESSED — expected >= 3 entries, "
        f"got {len(tron_keys)}. Check whether bridges.json entries were "
        f"accidentally removed since v0.31.2."
    )


def test_wormhole_eth_side_recipient_chain_18_decodes_to_tron() -> None:
    """The EVM-side Wormhole → Tron handoff IS decodable today.
    Verifies v0.17.5 round-10 forensic CRIT — recipientChain=18 in a
    Wormhole transferTokens call must produce a base58check Tron
    address (NOT a 0x-hex form the Tron adapter would reject)."""
    from recupero.trace.bridge_calldata import decode_bridge_calldata

    # Construct a synthetic Wormhole transferTokens calldata blob
    # with recipientChain=18 (Tron) and a 21-byte Tron payload
    # (prefix 0x41 + 20 address bytes) right-padded into bytes32.
    method_id = "0f5287b0"
    token = "0" * 24 + "a" * 40
    amount = "0" * 62 + "01"
    chain_id_slot = "0" * 60 + "0012"  # 0x12 = 18 = Wormhole's Tron
    # 21-byte Tron payload — first byte 0x41 + 20 random hex bytes,
    # right-padded into a bytes32 slot (= last 42 hex chars of the slot).
    tron_payload = "41" + "ab" * 20  # 21 bytes = 42 hex
    recipient_slot = "0" * (64 - 42) + tron_payload
    arbiter = "0" * 64
    nonce = "0" * 64
    calldata = (
        "0x" + method_id + token + amount + chain_id_slot
        + recipient_slot + arbiter + nonce
    )

    out = decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "tron"
    assert out.confidence == "high"
    # Tron base58check addresses start with 'T'. Verifies that the
    # 21-byte payload + 4-byte sha256d checksum encoder produced a
    # canonical-shape b58check string, not a 0x-hex form.
    assert out.destination_address is not None
    assert out.destination_address.startswith("T")
    # Length is the b58check envelope; Tron mainnet addresses are
    # 34 characters regardless of payload entropy.
    assert len(out.destination_address) == 34


def test_handoffs_are_sorted_by_usd_descending_for_tron_chain() -> None:
    """When multiple Tron-originated handoffs are detected (e.g.,
    operator pre-populates a bridge_db with several Tron-side
    entries), they must be sorted by amount_usd descending — matches
    the EVM behavior so the brief's CROSS_CHAIN_HANDOFFS section is
    investigator-priority ordered."""
    big_bridge = "TXJgMdjVX5dKiQaUi9QobwNXtRBkQ7vrPp"
    small_bridge = "TYyMxZqakBh8GFznqVfthFu3vTNeRTRXPa"
    bridge_db = {
        (Chain.tron, big_bridge): BridgeInfo(
            chain=Chain.tron, address=big_bridge, name="Big",
            protocol="just", confidence="medium",
            follow_up_url=None, supports_to_chains=("ethereum",),
        ),
        (Chain.tron, small_bridge): BridgeInfo(
            chain=Chain.tron, address=small_bridge, name="Small",
            protocol="allbridge", confidence="medium",
            follow_up_url=None, supports_to_chains=("ethereum",),
        ),
    }
    case = _stub_case([
        _stub_transfer(
            to_address=small_bridge, tx_hash="a" * 64,
            amount_usd=Decimal("1000"),
        ),
        _stub_transfer(
            to_address=big_bridge, tx_hash="b" * 64,
            amount_usd=Decimal("100000"),
        ),
    ])
    handoffs = identify_cross_chain_handoffs(case, bridge_db=bridge_db)
    assert [h.bridge_name for h in handoffs] == ["Big", "Small"]


# ─────────────────────────────────────────────────────────────────────
# Layer 3 — live-verification stubs (skipped by default)
# ─────────────────────────────────────────────────────────────────────


_LIVE = os.environ.get("RECUPERO_LIVE_TRONGRID") == "1"


@pytest.mark.skipif(
    not _LIVE,
    reason=(
        "Live TronGrid call. Opt-in via RECUPERO_LIVE_TRONGRID=1. "
        "What live verification would prove: the canonical USDT-TRC20 "
        "contract address has not changed (it has been stable since "
        "2019, but Tron Foundation has redeployed wrappers before), "
        "and TronGrid's parsed response still matches the v0.12.0 "
        "normalizer's shape expectations (token_info dict, from/to as "
        "base58check, value as raw integer string)."
    ),
)
def test_live_usdt_contract_returns_known_metadata() -> None:
    """LIVE: fetch the USDT-TRC20 contract metadata via TronGrid and
    assert decimals=6 + type=Contract. If this regresses Tether has
    redeployed the contract and the adapter's coingecko_id map needs
    refreshing."""
    from recupero.chains.tron.client import TronGridClient

    client = TronGridClient(
        api_key=os.environ.get("TRON_PRO_API_KEY") or "",
    )
    body = client.get_account(USDT_TRC20)
    data = body.get("data") or []
    assert data, "USDT-TRC20 account not found — has Tether redeployed?"
    assert data[0].get("type") == "Contract"


@pytest.mark.skipif(
    not _LIVE,
    reason=(
        "Live TronGrid call. What live verification would prove: a "
        "known Binance hot wallet on Tron (e.g., "
        "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8 from chain-coverage research) "
        "is reachable through the TRC-20 transfer endpoint and produces "
        "the high-volume row shape the BFS expects. Currently the "
        "labels/seeds/cex_deposits.json has ZERO Tron entries — this "
        "test would baseline a known-good Tron CEX deposit's response."
    ),
)
def test_live_binance_tron_hot_wallet_is_reachable() -> None:
    """LIVE: probe a documented Binance-on-Tron hot wallet. Confirms
    TronGrid serves the entity and the adapter can read its outflow
    history end-to-end."""
    from recupero.chains.tron.client import TronGridClient

    client = TronGridClient(api_key=os.environ.get("TRON_PRO_API_KEY") or "")
    # Public Binance Tron hot wallet (tronscan.org tag: "Binance")
    binance_tron = "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"
    transfers = client.get_trc20_transfers(
        binance_tron, only_from=True, limit=5, max_pages=1,
    )
    assert isinstance(transfers, list)
    # Binance's hot wallet should have >>1 historical outflow.
    assert len(transfers) > 0, (
        "no TRC-20 outflows from Binance Tron hot wallet — endpoint "
        "may have changed shape or wallet may be inactive"
    )
