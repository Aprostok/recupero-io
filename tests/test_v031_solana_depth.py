"""v0.31.0 Solana SPL trace-depth regression tests (Gap #7).

Solana's parsed-transactions surface is structurally different from
EVM (slots vs blocks, base58 vs hex, native SOL vs wrapped SOL,
classic Token program vs Token-2022). This file locks in the SPL
behavior we rely on at three depth layers, including a Token-2022
shape that the adapter has been passing through transparently
without an explicit test.

Coverage layers:

1. **Adapter depth (offline)** — SPL outflow normalization, mint
   identification (USDC / USDT / WSOL / BONK / JUP / JitoSOL), the
   wrapped-SOL vs native-SOL distinction, and Token-2022 program
   transfers (Helius normalizes both classic SPL Token and
   Token-2022 into the same ``tokenTransfers`` shape — pin that
   transparency).

2. **Cross-chain handoff seam (offline)** — Wormhole EVM→Solana
   pubkey decoding (regression coverage for the v0.17.5 base58
   forensic CRIT fix) and the same "no Solana-keyed bridges"
   visible-gap pin as Tron has.

3. **Live verification stubs (skipped by default)** — opt-in tests
   for the live Helius endpoint. ``RECUPERO_LIVE_HELIUS=1`` to run.

Doc: ``docs/V031_TRON_SOLANA_DEPTH.md``.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from recupero.chains.solana.adapter import (
    SOLANA_NATIVE_DECIMALS,
    USDC_SOLANA_MINT,
    USDT_SOLANA_MINT,
    WRAPPED_SOL_MINT,
    SolanaAdapter,
    _symbol_from_mint,
)
from recupero.models import Chain
from recupero.trace.bridge_calldata import (
    _b58encode_no_checksum,
    decode_bridge_calldata,
)
from recupero.trace.cross_chain import (
    BridgeInfo,
    identify_cross_chain_handoffs,
    ingest_bridge_seeds,
)


# Real Solana mainnet shapes — none tied to a specific entity.
VICTIM_SOL = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1"  # synthetic 32-byte
PERP_SOL = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"


def _build_adapter() -> SolanaAdapter:
    """Bypass __init__ to avoid the HELIUS_API_KEY requirement.
    Helper used by the existing test_solana_adapter_adversarial.py
    suite — pattern copied for consistency.
    """
    adapter = SolanaAdapter.__new__(SolanaAdapter)
    adapter.client = MagicMock()
    adapter.client.BASE = "https://fake-helius"
    adapter._is_program_cache = {}
    return adapter


def _spl_tx(
    *,
    signature: str = "sig-abc",
    timestamp: int = 1_750_000_000,
    slot: int = 250_000_000,
    transfers: list[dict] | None = None,
) -> dict:
    """Build a Helius-shape parsed transaction with tokenTransfers."""
    return {
        "signature": signature,
        "timestamp": timestamp,
        "slot": slot,
        "tokenTransfers": transfers or [],
        "nativeTransfers": [],
    }


def _spl_transfer(
    *,
    from_user: str = VICTIM_SOL,
    to_user: str = PERP_SOL,
    mint: str = USDC_SOLANA_MINT,
    raw_amount: str = "1000000",
    decimals: int = 6,
) -> dict:
    """Build a single tokenTransfers entry the way Helius emits one
    for both classic SPL Token and Token-2022 (the wire shape is the
    same; Helius normalizes program-id differences out at parse-
    time)."""
    return {
        "fromUserAccount": from_user,
        "toUserAccount": to_user,
        "mint": mint,
        "tokenAmount": str(int(raw_amount) / (10**decimals)),
        "rawTokenAmount": {
            "tokenAmount": raw_amount,
            "decimals": decimals,
        },
    }


# ─────────────────────────────────────────────────────────────────────
# Layer 1 — SPL adapter depth (offline)
# ─────────────────────────────────────────────────────────────────────


def test_spl_usdc_outflow_normalizes_to_canonical_shape() -> None:
    """USDC on Solana is the dominant stablecoin (USDT mint is smaller
    relative volume than EVM/Tron). Confirm the canonical mint
    produces the right normalized dict end-to-end."""
    adapter = _build_adapter()
    tx = _spl_tx(transfers=[_spl_transfer(mint=USDC_SOLANA_MINT)])
    adapter._fetch_all = lambda *a, **kw: [tx]  # type: ignore[assignment]

    import recupero.chains.solana.adapter as mod
    original = mod.normalize_solana_address
    mod.normalize_solana_address = lambda x: x
    try:
        out = adapter.fetch_erc20_outflows(VICTIM_SOL, start_block=0)
    finally:
        mod.normalize_solana_address = original

    assert len(out) == 1
    row = out[0]
    assert row["chain"] == Chain.solana
    assert row["from"] == VICTIM_SOL
    assert row["to"] == PERP_SOL
    assert row["amount_raw"] == 1_000_000
    assert row["token"].symbol == "USDC"
    assert row["token"].contract == USDC_SOLANA_MINT
    assert row["token"].coingecko_id == "usd-coin"


def test_spl_usdt_outflow_uses_solana_mint_not_evm_mint() -> None:
    """USDT on Solana has its OWN mint (``Es9vM...wNYB``) — distinct
    from USDT on Ethereum (``0xdac17...``) or USDT on Tron
    (``TR7NHq...``). The adapter must label by Solana-mint identity,
    not symbol — otherwise EVM-stablecoin freeze logic could route
    a Solana row to the wrong issuer."""
    adapter = _build_adapter()
    tx = _spl_tx(transfers=[_spl_transfer(mint=USDT_SOLANA_MINT)])
    adapter._fetch_all = lambda *a, **kw: [tx]  # type: ignore[assignment]

    import recupero.chains.solana.adapter as mod
    original = mod.normalize_solana_address
    mod.normalize_solana_address = lambda x: x
    try:
        out = adapter.fetch_erc20_outflows(VICTIM_SOL, start_block=0)
    finally:
        mod.normalize_solana_address = original

    assert out[0]["token"].symbol == "USDT"
    assert out[0]["token"].contract == USDT_SOLANA_MINT
    assert out[0]["token"].coingecko_id == "tether"
    # Critical: NOT the EVM USDT contract.
    assert not out[0]["token"].contract.startswith("0x")


def test_wrapped_sol_vs_native_sol_distinction() -> None:
    """Native SOL flows through ``nativeTransfers`` (lamports);
    wrapped SOL (mint ``So11...112``) flows through ``tokenTransfers``.
    The adapter MUST surface them as distinct token types — a freeze
    letter targeting native SOL would be a no-op against a wrapped-
    SOL holding."""
    adapter = _build_adapter()

    # Wrapped SOL: appears as a SPL token transfer.
    tx_wsol = _spl_tx(
        signature="sig-wsol",
        transfers=[_spl_transfer(
            mint=WRAPPED_SOL_MINT,
            raw_amount="1000000000",   # 1 WSOL = 10^9 base units
            decimals=9,
        )],
    )
    adapter._fetch_all = lambda *a, **kw: [tx_wsol]  # type: ignore[assignment]

    import recupero.chains.solana.adapter as mod
    original = mod.normalize_solana_address
    mod.normalize_solana_address = lambda x: x
    try:
        spl_out = adapter.fetch_erc20_outflows(VICTIM_SOL, start_block=0)
    finally:
        mod.normalize_solana_address = original

    assert len(spl_out) == 1
    assert spl_out[0]["token"].symbol == "WSOL"
    assert spl_out[0]["token"].contract == WRAPPED_SOL_MINT

    # Native SOL: same raw amount but routed through nativeTransfers
    # and produces a SOL TokenRef with contract=None.
    tx_native = {
        "signature": "sig-sol",
        "timestamp": 1_750_000_000,
        "slot": 250_000_000,
        "tokenTransfers": [],
        "nativeTransfers": [{
            "fromUserAccount": VICTIM_SOL,
            "toUserAccount": PERP_SOL,
            "amount": 1_000_000_000,    # 1 SOL in lamports
        }],
    }
    adapter._fetch_all = lambda *a, **kw: [tx_native]  # type: ignore[assignment]

    mod.normalize_solana_address = lambda x: x
    try:
        native_out = adapter.fetch_native_outflows(VICTIM_SOL, start_block=0)
    finally:
        mod.normalize_solana_address = original

    assert len(native_out) == 1
    assert native_out[0]["token"].symbol == "SOL"
    assert native_out[0]["token"].contract is None
    assert native_out[0]["token"].decimals == SOLANA_NATIVE_DECIMALS


def test_token_2022_transfer_normalizes_identically_to_classic_spl() -> None:
    """Helius's parsed transactions normalize SPL Token and Token-2022
    program transfers into the same ``tokenTransfers`` array shape.
    The recupero adapter consumes that shape WITHOUT inspecting the
    underlying program — meaning Token-2022 transfers pass through
    transparently today.

    This is the desired behavior for forensic tracing (we don't care
    which token program issued the transfer; we care about value
    movement). Pin it so a future refactor that adds program-ID
    filtering doesn't accidentally drop Token-2022 rows.

    Caveat (documented in V031_TRON_SOLANA_DEPTH.md): the adapter does
    NOT surface Token-2022 extensions (transfer fees, default account
    state, permanent delegate). A freeze letter targeting a Token-2022
    with a permanent delegate would route through a different legal
    path. For Phase-1 forensic tracing that's acceptable; flagged as
    future work.
    """
    # A Token-2022 transfer carries the same wire shape from Helius.
    # The marker (in a real Helius response) is a `tokenStandard` or
    # `programId` field that we currently ignore — confirm that
    # ignoring it produces the same normalized output.
    adapter = _build_adapter()
    token_2022_mint = "1nc1nerator11111111111111111111111111111111"
    tx = _spl_tx(
        transfers=[{
            "fromUserAccount": VICTIM_SOL,
            "toUserAccount": PERP_SOL,
            "mint": token_2022_mint,
            "tokenAmount": "1.0",
            "rawTokenAmount": {"tokenAmount": "1000000", "decimals": 6},
            # Helius emits this for Token-2022 specifically; the
            # adapter ignores it (by design — see docstring).
            "tokenStandard": "Fungible",
            "programId": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
        }],
    )
    adapter._fetch_all = lambda *a, **kw: [tx]  # type: ignore[assignment]

    import recupero.chains.solana.adapter as mod
    original = mod.normalize_solana_address
    mod.normalize_solana_address = lambda x: x
    try:
        out = adapter.fetch_erc20_outflows(VICTIM_SOL, start_block=0)
    finally:
        mod.normalize_solana_address = original

    assert len(out) == 1
    assert out[0]["amount_raw"] == 1_000_000
    assert out[0]["token"].contract == token_2022_mint
    # Adapter falls back to mint[:4] for unknown symbols — that's
    # the existing contract; pin it so the brief renderer keeps
    # treating unrecognized-mint Token-2022 transfers consistently.
    assert out[0]["token"].symbol == _symbol_from_mint(token_2022_mint)


def test_symbol_table_covers_top_solana_mints() -> None:
    """Sanity: the SPL → human-symbol map must cover the top mints
    investigators most often see. Locked in test_solana_helpers.py
    too — re-asserted here to make the depth-test file self-
    contained for the v0.31 audit."""
    assert _symbol_from_mint(USDC_SOLANA_MINT) == "USDC"
    assert _symbol_from_mint(USDT_SOLANA_MINT) == "USDT"
    assert _symbol_from_mint(WRAPPED_SOL_MINT) == "WSOL"


def test_block_at_or_before_returns_unix_seconds() -> None:
    """The Solana adapter treats start_block as a unix-seconds
    timestamp (Solana has no reliable slot-at-timestamp endpoint).
    Pin the unit so a refactor that returns ms here doesn't silently
    over-shoot the Helius cutoff filter by 10^3."""
    from recupero.config import RecuperoConfig, RecuperoEnv

    cfg = RecuperoConfig()
    env = RecuperoEnv(HELIUS_API_KEY="test-key-not-used")
    adapter = SolanaAdapter(bundle=(cfg, env))
    ts = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    out = adapter.block_at_or_before(ts)
    assert 1_700_000_000 < out < 2_000_000_000  # seconds, not ms
    assert out == int(ts.timestamp())


# ─────────────────────────────────────────────────────────────────────
# Layer 2 — cross-chain handoff seam (offline)
# ─────────────────────────────────────────────────────────────────────


def _stub_case(transfers):
    case = MagicMock()
    case.case_id = "SOLANA-DEPTH-TEST"
    case.transfers = transfers
    return case


def _stub_transfer(
    *,
    chain: Chain = Chain.solana,
    to_address: str = PERP_SOL,
    tx_hash: str = "sigabc" + "0" * 82,
    amount_usd=Decimal("50000"),
) -> MagicMock:
    t = MagicMock()
    t.chain = chain
    t.to_address = to_address
    t.from_address = VICTIM_SOL
    t.tx_hash = tx_hash
    t.usd_value_at_tx = amount_usd
    t.amount_decimal = Decimal("50000")
    t.token = MagicMock()
    t.token.symbol = "USDC"
    t.block_time = datetime(2026, 1, 1, tzinfo=UTC)
    t.explorer_url = f"https://solscan.io/tx/{tx_hash}"
    return t


def test_wormhole_solana_recipient_decodes_to_base58_pubkey() -> None:
    """Regression: Wormhole TokenBridge.transferTokens with
    recipientChain=1 (Solana) must produce a base58-encoded 32-byte
    pubkey (NOT a 0x-hex form). Pre-v0.17.5 the decoder returned a
    "0x" + 64-hex string that the Solana adapter's Helius client
    rejected → every Wormhole→Solana handoff silently dropped from
    the cross-chain BFS.

    This is the same property as the more-detailed
    test_wormhole_decode_solana_recipient in test_bridge_calldata.py;
    re-asserted here so the v0.31 depth-audit file independently
    verifies the path still works.
    """
    method_id = "0f5287b0"
    token_padded = "0" * 24 + "a" * 40
    amount = "0" * 62 + "01"
    chain_id_slot = "0" * 60 + "0001"  # 0x1 = 1 = Solana
    # 32-byte pubkey of 0xcc bytes.
    pubkey_hex = "c" * 64
    arbiter = "0" * 64
    nonce = "0" * 64
    calldata = (
        "0x" + method_id + token_padded + amount + chain_id_slot
        + pubkey_hex + arbiter + nonce
    )
    out = decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "solana"
    assert out.confidence == "high"
    # The encoder produces base58 of 32 bytes — must match the
    # round-trip through _b58encode_no_checksum so changes to the
    # encoder are caught here, not only in test_bridge_calldata.
    assert out.destination_address == _b58encode_no_checksum(
        bytes.fromhex(pubkey_hex),
    )
    # base58 of 32 bytes lands at 32-44 chars (per Solana address
    # validator bounds in chains/solana/address.py).
    assert 32 <= len(out.destination_address) <= 44


def test_solana_keyed_bridge_db_lookup_works_when_populated() -> None:
    """Forward-compatibility lock: ``ingest_bridge_seeds`` already
    accepts ``"chain": "solana"`` entries. When a future patch adds
    Solana-side bridge programs (Wormhole portal, deBridge solana
    program, AllBridge solana program), the detection seam fires.
    """
    bridge_addr = "wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb"
    bridge_db = {
        (Chain.solana, bridge_addr): BridgeInfo(
            chain=Chain.solana,
            address=bridge_addr,
            name="Wormhole Portal (hypothetical Solana-side program)",
            protocol="wormhole",
            confidence="high",
            follow_up_url="https://wormholescan.io",
            supports_to_chains=("ethereum", "bsc"),
        ),
    }
    case = _stub_case([_stub_transfer(to_address=bridge_addr)])
    handoffs = identify_cross_chain_handoffs(case, bridge_db=bridge_db)
    assert len(handoffs) == 1
    assert handoffs[0].source_chain == Chain.solana
    assert "wormhole" in handoffs[0].bridge_protocol.lower()


def test_solana_keyed_bridge_db_has_coverage() -> None:
    """v0.31.2 — was previously a visible-gap pin asserting zero
    Solana-keyed bridges.json entries. Closed by the v0.31.2
    Tron+Solana seed-expansion pass: Wormhole Token Bridge (=Portal),
    Wormhole Core Bridge, deBridge DLN Program. All three verified
    against the Wormhole SDK constants + deBridge Solana SDK.

    Test now LOCKS coverage — bump count to add more.
    See ``docs/V031_2_TRON_SOLANA_SEEDS.md`` for provenance.
    """
    db = ingest_bridge_seeds()
    solana_keys = [k for k in db if k[0] == Chain.solana]
    assert len(solana_keys) >= 3, (
        f"Solana-keyed bridge coverage REGRESSED — expected >= 3 entries, "
        f"got {len(solana_keys)}. Check whether bridges.json entries were "
        f"accidentally removed since v0.31.2."
    )


def test_cex_deposits_seed_has_solana_and_tron_coverage() -> None:
    """v0.31.2 — was previously a visible-gap pin asserting the
    cex_deposits.json seed had ZERO Solana / Tron entries. Closed by
    the v0.31.2 expansion: 7 Tron CEX hot wallets (Binance ×5,
    Bitfinex, Huobi/HTX) + 7 Solana CEX hot wallets (Coinbase ×2,
    OKX, HTX, Bybit, Kraken, Crypto.com). All sourced from
    OKLink / ClankApp / Bitquery / Solscan public tags.

    Test now LOCKS coverage.
    """
    import json
    from pathlib import Path

    seeds_path = (
        Path(__file__).resolve().parents[1]
        / "src" / "recupero" / "labels" / "seeds" / "cex_deposits.json"
    )
    entries = json.loads(seeds_path.read_text(encoding="utf-8-sig"))
    by_chain: dict[str, int] = {}
    for entry in entries:
        if isinstance(entry, dict):
            ch = entry.get("chain", "(unset)")
            by_chain[ch] = by_chain.get(ch, 0) + 1

    assert by_chain.get("solana", 0) >= 5, (
        f"Solana CEX deposit coverage REGRESSED — expected >= 5, got "
        f"{by_chain.get('solana', 0)}."
    )
    assert by_chain.get("tron", 0) >= 5, (
        f"Tron CEX deposit coverage REGRESSED — expected >= 5, got "
        f"{by_chain.get('tron', 0)}."
    )


# ─────────────────────────────────────────────────────────────────────
# Layer 3 — live verification stubs (skipped by default)
# ─────────────────────────────────────────────────────────────────────


_LIVE = os.environ.get("RECUPERO_LIVE_HELIUS") == "1"


@pytest.mark.skipif(
    not _LIVE,
    reason=(
        "Live Helius RPC call. Opt-in via RECUPERO_LIVE_HELIUS=1. "
        "What live verification would prove: the canonical Solana USDC "
        "mint (EPjFWdd5...) is still classified as a SPL token account "
        "(not a program), and Helius returns the documented "
        "Account/AccountInfo shape that the adapter's is_contract path "
        "consumes."
    ),
)
def test_live_usdc_mint_is_not_executable() -> None:
    """LIVE: the USDC mint account is not executable. If this
    regresses, Circle has redeployed the mint and the canonical mint
    constants need updating."""
    from recupero.chains.solana.helius import HeliusClient

    client = HeliusClient(
        api_key=os.environ.get("HELIUS_API_KEY") or "",
    )
    info = client.get_account_info(USDC_SOLANA_MINT)
    assert isinstance(info, dict)
    # Mint accounts are owned by the Token program; they are NOT
    # executable themselves.
    assert info.get("executable") is False


@pytest.mark.skipif(
    not _LIVE,
    reason=(
        "Live Helius call. What live verification would prove: a "
        "known Coinbase / Binance Solana hot wallet is reachable "
        "through the parsed-transactions endpoint, producing the "
        "row shape the BFS consumes. Currently labels/seeds/"
        "cex_deposits.json has ZERO Solana entries — this test "
        "would baseline a known-good Solana CEX deposit's response."
    ),
)
def test_live_binance_solana_hot_wallet_is_reachable() -> None:
    """LIVE: probe a documented Binance-on-Solana hot wallet. Confirms
    Helius serves the entity and SPL token transfers come back in
    the documented shape."""
    from recupero.chains.solana.helius import HeliusClient

    client = HeliusClient(api_key=os.environ.get("HELIUS_API_KEY") or "")
    # Public Binance Solana hot wallet (solscan.io tag: "Binance")
    binance_sol = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9"
    txs = client.get_parsed_transactions(
        binance_sol, limit=5, max_pages=1,
    )
    assert isinstance(txs, list)
    # Binance's hot wallet should have >>1 historical tx.
    assert len(txs) > 0, (
        "no parsed txs from Binance Solana hot wallet — endpoint "
        "may have changed shape or wallet may be inactive"
    )
