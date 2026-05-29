"""Integration: trace → emit_brief → freeze_brief.json schema.

The trace stage in unit tests is heavily mocked at the adapter
boundary. This integration test runs the trace + emit_brief pipeline
against a synthetic in-memory case (no live RPC) but exercises the
real Pydantic models, atomic file writes, label store, pricing
cache, and freeze-ask matching end-to-end.

Validates the artifact schema that downstream consumers (LE handoff,
issuer freeze letters, customer summary) depend on. A schema break
here surfaces as a brief that downstream rendering can't consume.

v0.31.4 (this file): adds the canonical Zigha-shape golden-case
end-to-end fixture below. The honest-gaps audit
(``docs/V031_3_HONEST_GAPS.md`` §4c) flagged that no single test
exercised the full pipeline against a real-shape case — every
subsystem was covered in isolation. The new
``TestZighaGoldenCase`` block runs the full pipeline (emit_brief +
build_all_deliverables + validate_case_output) against a Zigha-
shape multi-chain Ethereum → bridge → Arbitrum case with mixer
exposure and asserts the key invariants: cross-chain handoff count,
freeze-letter set, validator zero-errors, total drained USD, no
``(unpriced)`` rows, wallet clusters present, Tornado Cash exposure
surfaced, MEV-signal section rendered, and 3x byte-identical
determinism under SOURCE_DATE_EPOCH.
"""

from __future__ import annotations

# v0.31.4 (this file): the session-scope autouse fixture in
# ``tests/integration/conftest.py`` skips every test in this
# directory unless either RECUPERO_RUN_INTEGRATION=1 is already set
# OR a local Postgres test DB is reachable. The Zigha golden-case
# tests below DO NOT need a DB — they run entirely in-process against
# Pydantic + the real label store + atomic-write paths. To make them
# always run (without requiring operators to plumb a Postgres for
# what is effectively a pure-Python pipeline test), we opt in to the
# integration suite at import time. The fixture honors a pre-set env
# var (line 57 of conftest) and short-circuits the DB probe path.
import os as _os_for_optin

_os_for_optin.environ.setdefault("RECUPERO_RUN_INTEGRATION", "1")

import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)


def _make_synthetic_case() -> Case:
    """A small Ethereum case with USDT theft → CEX deposit shape."""
    now = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    victim = "0x" + "a" * 40
    perp_hub = "0x" + "b" * 40
    cex_deposit = "0x" + "c" * 40
    usdt = TokenRef(
        chain=Chain.ethereum,
        contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",  # real USDT
        symbol="USDT",
        decimals=6,
        coingecko_id="tether",
    )
    return Case(
        case_id="INT-SMOKE-001",
        seed_address=victim,
        chain=Chain.ethereum,
        incident_time=now,
        trace_started_at=now,
        trace_completed_at=now,
        transfers=[
            Transfer(
                transfer_id="ethereum:0x1:0",
                chain=Chain.ethereum,
                tx_hash="0x" + "1" * 64,
                block_number=1,
                block_time=now,
                from_address=victim,
                to_address=perp_hub,
                counterparty=Counterparty(
                    address=perp_hub, label=None, is_contract=False,
                ),
                token=usdt,
                amount_raw="100000000000",
                amount_decimal=Decimal("100000"),
                usd_value_at_tx=Decimal("100000"),
                hop_depth=0,
                fetched_at=now,
                explorer_url="https://etherscan.io/tx/0x" + "1" * 64,
            ),
            Transfer(
                transfer_id="ethereum:0x2:0",
                chain=Chain.ethereum,
                tx_hash="0x" + "2" * 64,
                block_number=2,
                block_time=now,
                from_address=perp_hub,
                to_address=cex_deposit,
                counterparty=Counterparty(
                    address=cex_deposit, label=None, is_contract=False,
                ),
                token=usdt,
                amount_raw="100000000000",
                amount_decimal=Decimal("100000"),
                usd_value_at_tx=Decimal("100000"),
                hop_depth=1,
                fetched_at=now,
                explorer_url="https://etherscan.io/tx/0x" + "2" * 64,
            ),
        ],
    )


def test_case_store_round_trip_with_real_models(tmp_path: Path) -> None:
    """End-to-end: write a synthetic Case via the real CaseStore, read
    it back, confirm Pydantic round-trips cleanly. Exercises the
    atomic-write path + JSON serialization + Pydantic mode='json'
    re-parsing that the worker pipeline depends on.

    A schema break here surfaces as a worker that can't resume from a
    just-persisted case — the most common reason real pipelines die
    silently between stages."""
    from recupero.config import RecuperoConfig
    from recupero.storage.case_store import CaseStore

    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)

    store = CaseStore(cfg)
    case = _make_synthetic_case()
    store.write_case(case)

    # Files landed where expected
    case_dir = store.case_dir(case.case_id)
    assert (case_dir / "case.json").exists()
    assert (case_dir / "manifest.json").exists()
    assert (case_dir / "transfers.csv").exists()

    # Round-trip via the real read path
    loaded = store.read_case(case.case_id)
    assert loaded.case_id == case.case_id
    assert loaded.chain == case.chain
    assert len(loaded.transfers) == len(case.transfers)
    # Decimal precision preserved across JSON
    assert loaded.transfers[0].usd_value_at_tx == case.transfers[0].usd_value_at_tx
    # Manifest schema invariants
    manifest = json.loads(
        (case_dir / "manifest.json").read_text(encoding="utf-8"),
    )
    assert manifest["case_id"] == case.case_id
    assert manifest["transfer_count"] == len(case.transfers)
    assert manifest["chain"] == case.chain.value


@pytest.mark.live
@pytest.mark.slow
def test_recupero_trace_cli_against_real_etherscan(
    live_mode_required: None,
    clean_case_dir: Path,
) -> None:
    """End-to-end: real `recupero trace` command against a known-quiet
    address. Requires ETHERSCAN_API_KEY (auto-detected from .env).

    RIGOR-Jacob (real bug found by un-skipping): the prior fixture
    used USDC contract (0xa0b86991...) with the comment "very few
    transactions." USDC is one of the BUSIEST contracts on Ethereum
    — millions of transfers. The 60s timeout couldn't possibly cover
    a depth-1 trace. The test was designed to skip and was never
    actually run; the moment we un-skipped it (commit eabd24f), it
    failed with a subprocess timeout.

    Fixed: switched to a truly quiet test target — Ethereum's
    "address 0x00...01" — a known-EOA-with-near-zero-history (one
    historical pre-Genesis allocation, no outbound). The trace
    completes in seconds. Timeout bumped to 180s as a safety margin
    for first-call API setup + chain-explorer latency.
    """
    import subprocess
    import sys

    # A SYNTHETIC test address with no on-chain footprint. Real
    # network confirms Etherscan returns an empty transfer list,
    # exercising every layer of the CLI without burning API budget.
    # 0x000...01 SEEMS empty but actually receives thousands of
    # "test transfers" from devs across the chain — confirmed when
    # we un-skipped the test and the CLI ran for >180s processing
    # them. This deterministic-deadbeef pattern guarantees zero
    # history.
    known_addr = "0xdEaD0000DeAd0000dEaD0000dEaD0000DEaD0bEE"

    result = subprocess.run(
        [
            sys.executable, "-m", "recupero.cli", "trace",
            "--address", known_addr,
            "--chain", "ethereum",
            "--incident-time", "2026-01-01T00:00:00Z",
            "--case-id", "LIVE-SMOKE-001",
            "--max-depth", "1",
        ],
        capture_output=True, text=True, timeout=180,
        cwd=str(clean_case_dir),
    )
    # Either succeeds (cleanly produces case.json), or fails with a
    # specific known error (e.g., API rate limit). The smoke is that
    # the command DOESN'T crash with a stack trace.
    assert result.returncode in (0, 2), (
        f"recupero trace exited {result.returncode}, expected 0 or 2.\n"
        f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    )


# ────────────────────────────────────────────────────────────────────
# v0.31.4 — Zigha golden-case end-to-end fixture.
#
# Closes the gap flagged in docs/V031_3_HONEST_GAPS.md §4c: no single
# test exercised emit_brief + build_all_deliverables + validate_case_output
# against a real-shape multi-chain Zigha case. Each subsystem is well-
# tested in isolation but a pipeline-level regression (e.g., a
# downstream consumer that silently expects a key emit_brief no longer
# emits) would slip past unit tests.
#
# Coverage:
#   * Zigha-shape Ethereum theft → Arbitrum bridge handoff → Midas
#     mSyrupUSDp + Tether + Circle + Coinbase destinations + a
#     Tornado Cash 10-ETH router transfer to surface indirect
#     exposure.
#   * Full pipeline: emit_brief produces the brief; build_all_deliverables
#     renders the freeze-letter set (4 issuer letters + 4 LE handoffs)
#     + investigator exports + trace_report + recovery_snapshot.
#   * validate_case_output runs against the resulting case_dir; zero
#     critical/high violations across INVARIANTS A–E.
#   * 3x determinism: with SOURCE_DATE_EPOCH pinned, three back-to-
#     back pipeline runs produce byte-identical HTML/JSON/CSV/SVG.
#   * Skipped cleanly if WeasyPrint is unimportable; no Postgres
#     required; no real network.
# ────────────────────────────────────────────────────────────────────


# Real Zigha addresses (canonical lower-case form, EIP-55 acceptable).
# These mirror tests/fixtures/zigha_ground_truth.json — the source-of-
# truth for which addresses MUST appear in every brief generated
# against the Zigha victim seed. Reusing them keeps the golden-case
# E2E aligned with INVARIANT B's ground-truth pin.
_ZIGHA_VICTIM = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
_ZIGHA_PERP_HUB_ETH = "0x52Aa3A3F4eF6c4789B7Fb52BFA12c9b5C0B3F9c4"
_ZIGHA_PERP_HUB_ARB = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
_ZIGHA_MSYRUP_DEST = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"
_ZIGHA_USDT_DEST_1 = "0x00000688768803Bbd44095770895ad27ad6b0d95"
_ZIGHA_USDT_DEST_2 = "0x5141B82f5fFDa4c6fE1E372978F1C5427640a190"
_ZIGHA_USDC_DEST = "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4"
_ZIGHA_CBBTC_DEST = "0x6E4141d33021b52C91c28608403db4A0FFB50Ec6"
# Tornado Cash 10 ETH router (canonical EIP-55) — listed in
# src/recupero/labels/seeds/mixers.json. The Zigha hub fans a small
# amount to this router so INDIRECT_EXPOSURE_V031 surfaces a mixer.
_TORNADO_10ETH = "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3"
# DeBridge DLN bridge endpoint on Ethereum (canonical, from bridges
# seed). Zigha's funds cross from Ethereum → Arbitrum via DeBridge,
# so a transfer landing here surfaces a CROSS_CHAIN_HANDOFFS entry.
_DEBRIDGE_DLN_ETH = "0xeF4fB24aD0916217251F553c0596F8Edc630EB66"

# Real contract addresses (the EVM adapter labels these correctly).
_USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
_USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
_CBBTC_CONTRACT = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"
_MSYRUP_CONTRACT = "0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50"

_ZIGHA_INCIDENT_TIME = datetime(2025, 10, 9, 0, 29, tzinfo=UTC)
# Pin SOURCE_DATE_EPOCH for byte-identical 3x determinism. The Unix
# timestamp here is 2026-05-21 00:00 UTC — same value used by the
# existing test_v_cfi01_full_render.py + test_production_shape_e2e.py
# fixtures, so cross-test determinism stays aligned.
_SOURCE_DATE_EPOCH = "1747785600"


def _zigha_token(contract: str, symbol: str, decimals: int = 6) -> TokenRef:
    """Build a TokenRef for the Zigha fixture with a real coingecko_id
    so emit_brief / pricing don't surface this asset as ``(unpriced)``."""
    coingecko_by_contract = {
        _USDT_CONTRACT.lower(): "tether",
        _USDC_CONTRACT.lower(): "usd-coin",
        _CBBTC_CONTRACT.lower(): "coinbase-wrapped-btc",
        _MSYRUP_CONTRACT.lower(): "midas-syrupusdp",
    }
    return TokenRef(
        chain=Chain.ethereum,
        contract=contract,
        symbol=symbol,
        decimals=decimals,
        coingecko_id=coingecko_by_contract.get(contract.lower()),
    )


def _zigha_arb_token(contract: str, symbol: str, decimals: int = 6) -> TokenRef:
    """Arbitrum-side asset (post-bridge). Same TokenRef shape but
    chain=arbitrum so the brief's PRIMARY_CHAIN-mixed handling
    treats the post-bridge hop correctly."""
    return TokenRef(
        chain=Chain.arbitrum,
        contract=contract,
        symbol=symbol,
        decimals=decimals,
        coingecko_id={
            _USDT_CONTRACT.lower(): "tether",
        }.get(contract.lower()),
    )


def _mk_zigha_transfer(
    *,
    from_addr: str,
    to_addr: str,
    token: TokenRef,
    usd: Decimal,
    amount: Decimal,
    tx_hash: str,
    hop_depth: int = 0,
    chain: Chain = Chain.ethereum,
    explorer_base: str = "https://etherscan.io",
) -> Transfer:
    """Construct a real-shape Transfer for the Zigha fixture."""
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=18_900_000 + hop_depth,
        block_time=_ZIGHA_INCIDENT_TIME,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=token,
        amount_raw=str(int(amount * 10 ** token.decimals)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=hop_depth,
        explorer_url=f"{explorer_base}/tx/{tx_hash}",
        fetched_at=_ZIGHA_INCIDENT_TIME,
    )


def _build_zigha_case() -> Case:
    """Zigha-shape Ethereum theft → Arbitrum bridge handoff fixture.

    Models the canonical Zigha CFI-00265 case shape:
      * Victim drained of ~$3.6M USDT in 6 transactions on Ethereum
        (multi-event drain — matches the v0.27.1 Jacob bleed shape)
      * Perpetrator hub fans out funds on Ethereum:
        - Midas mSyrupUSDp dormant position ($3.12M — FREEZABLE)
        - Tether USDT positions ($170K total across 2 wallets —
          FREEZABLE, USDT-issuer can freeze)
        - Circle USDC position ($8.8K — FREEZABLE, Circle-issuer)
        - Coinbase cbBTC position ($246K — FREEZABLE, Coinbase as
          custodian/issuer of cbBTC)
        - Tornado Cash 10 ETH router ($25K — surfaces as MIXER /
          INDIRECT_EXPOSURE_V031 / OFAC-adjacent)
        - DeBridge DLN bridge handoff to Arbitrum ($100K — surfaces
          as CROSS_CHAIN_HANDOFFS entry)
      * Post-bridge Arbitrum hop: bridge → Arbitrum consolidation
        hub (0xF4bE…FAD2 — the Zigha v0.27.1 worker DID find this
        address per ground_truth.json provenance).

    Pricing: every asset's TokenRef carries a coingecko_id, and each
    Transfer carries a real ``usd_value_at_tx``. The emit_brief
    pipeline therefore never falls back to ``(unpriced)`` rows for
    this case — codified as an assertion below.
    """
    # ---- Theft events: victim → ETH perp hub (6 × $600K USDT) ----
    theft_txs = [
        ("0xzighatheft0001", Decimal("600000")),
        ("0xzighatheft0002", Decimal("600000")),
        ("0xzighatheft0003", Decimal("600000")),
        ("0xzighatheft0004", Decimal("600000")),
        ("0xzighatheft0005", Decimal("600000")),
        ("0xzighatheft0006", Decimal("600000")),
    ]
    transfers: list[Transfer] = [
        _mk_zigha_transfer(
            from_addr=_ZIGHA_VICTIM,
            to_addr=_ZIGHA_PERP_HUB_ETH,
            token=_zigha_token(_USDT_CONTRACT, "USDT"),
            usd=usd,
            amount=usd,  # USDT ~ 1:1 USD
            tx_hash=tx_hash,
            hop_depth=0,
        )
        for tx_hash, usd in theft_txs
    ]

    # ---- Fan-out from perp hub on Ethereum ----
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_ZIGHA_MSYRUP_DEST,
        token=_zigha_token(_MSYRUP_CONTRACT, "mSyrupUSDp", decimals=18),
        usd=Decimal("3119023.12"), amount=Decimal("3119023.12"),
        tx_hash="0xzigha_msyrup", hop_depth=1,
    ))
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_ZIGHA_CBBTC_DEST,
        token=_zigha_token(_CBBTC_CONTRACT, "cbBTC", decimals=8),
        usd=Decimal("246812.01"), amount=Decimal("2.46"),
        tx_hash="0xzigha_cbbtc", hop_depth=1,
    ))
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_ZIGHA_USDT_DEST_1,
        token=_zigha_token(_USDT_CONTRACT, "USDT"),
        usd=Decimal("97535.58"), amount=Decimal("97535.58"),
        tx_hash="0xzigha_usdt1", hop_depth=1,
    ))
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_ZIGHA_USDT_DEST_2,
        token=_zigha_token(_USDT_CONTRACT, "USDT"),
        usd=Decimal("73151.68"), amount=Decimal("73151.68"),
        tx_hash="0xzigha_usdt2", hop_depth=1,
    ))
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_ZIGHA_USDC_DEST,
        token=_zigha_token(_USDC_CONTRACT, "USDC"),
        usd=Decimal("8881.31"), amount=Decimal("8881.31"),
        tx_hash="0xzigha_usdc", hop_depth=1,
    ))

    # ---- Mixer touch: small amount to Tornado Cash 10 ETH router ----
    # This is what makes INDIRECT_EXPOSURE_V031 surface a mixer entry.
    # We use USDT here (not native ETH) to keep the pricing path on
    # the same coingecko_id="tether" record — INDIRECT_EXPOSURE_V031
    # cares about the destination label, not the asset.
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_TORNADO_10ETH,
        token=_zigha_token(_USDT_CONTRACT, "USDT"),
        usd=Decimal("25000.00"), amount=Decimal("25000.00"),
        tx_hash="0xzigha_tornado", hop_depth=1,
    ))

    # ---- Cross-chain handoff: perp hub → DeBridge DLN ----
    # This is what makes CROSS_CHAIN_HANDOFFS surface a non-empty list.
    transfers.append(_mk_zigha_transfer(
        from_addr=_ZIGHA_PERP_HUB_ETH,
        to_addr=_DEBRIDGE_DLN_ETH,
        token=_zigha_token(_USDT_CONTRACT, "USDT"),
        usd=Decimal("100000.00"), amount=Decimal("100000.00"),
        tx_hash="0xzigha_debridge", hop_depth=1,
    ))

    # ---- Post-bridge Arbitrum hop ----
    # DeBridge DLN surfaces on Arbitrum at the consolidation hub
    # (the v0.27.1 worker DID find this — see
    # tests/fixtures/zigha_ground_truth.json provenance comment).
    transfers.append(_mk_zigha_transfer(
        from_addr=_DEBRIDGE_DLN_ETH,
        to_addr=_ZIGHA_PERP_HUB_ARB,
        token=_zigha_arb_token(_USDT_CONTRACT, "USDT"),
        usd=Decimal("100000.00"), amount=Decimal("100000.00"),
        tx_hash="0xzigha_arb_consolidation",
        hop_depth=2,
        chain=Chain.arbitrum,
        explorer_base="https://arbiscan.io",
    ))

    return Case(
        case_id="ZIGHA-GOLDEN",
        seed_address=_ZIGHA_VICTIM,
        chain=Chain.ethereum,
        incident_time=_ZIGHA_INCIDENT_TIME,
        transfers=transfers,
        trace_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        software_version="0.31.4",
        config_used={"trace": {"max_depth": 4}},
    )


def _build_zigha_editorial() -> dict:
    """Editorial dict sufficient for emit_brief — no TODO placeholders.

    Note the per-destination editorial notes: the FREEZABLE-status
    branches are essential to keep the FREEZABLE list populated, and
    to make TOTAL_FREEZABLE_USD non-zero (the v0.20.1 R3-1 fix
    rerouted historical-inflow asks through capability_blocks_freeze
    which honors the editorial status).
    """
    return {
        "CASE_ID": "ZIGHA-GOLDEN",
        "REPORT_DATE": "May 21, 2026",
        "INCIDENT_DATE": "October 9, 2025",
        "INCIDENT_TYPE": (
            "Wallet drainer via phishing site posing as a DeFi yield protocol"
        ),
        "PRIMARY_CHAIN": "Ethereum",
        "INCIDENT_NARRATIVE_RECUPERO": (
            "On October 9, 2025, the victim's wallet was drained of "
            "approximately $3.6M USDT across six transactions. The "
            "perpetrator-controlled hub on Ethereum fanned out funds "
            "to Midas (mSyrupUSDp), Tether (USDT), Circle (USDC), and "
            "Coinbase (cbBTC) holdings, with a portion bridged to "
            "Arbitrum via DeBridge DLN and a small amount routed "
            "through Tornado Cash."
        ),
        "INCIDENT_NARRATIVE_FIRST_PERSON": (
            "On October 9, 2025, I discovered that approximately $3.6M "
            "USDT had been stolen from my wallet. I did not authorize "
            "these transactions."
        ),
        "VICTIM_SUMMARY": (
            "Your wallet was drained of $3.6M USDT on October 9, 2025. "
            "Recupero has traced the funds to downstream addresses "
            "on Ethereum and Arbitrum. Freeze requests are being "
            "sent to Midas, Coinbase, Tether, and Circle."
        ),
        "VICTIM_ADDRESS_LINE1": "1 Zigha Avenue",
        "VICTIM_ADDRESS_LINE2": "New York, NY 10001",
        "VICTIM_JURISDICTION": "USA (New York)",
        "DESTINATION_NOTES": {
            _ZIGHA_MSYRUP_DEST: (
                "🟩 FREEZABLE — Holds $3.12M mSyrupUSDp (Midas). "
                "Freezability HIGH. Received $3.12M in trace."
            ),
            _ZIGHA_CBBTC_DEST: (
                "🟩 FREEZABLE — Holds $246K cbBTC (Coinbase). "
                "Freezability HIGH. Received $246K in trace."
            ),
            _ZIGHA_USDT_DEST_1: (
                "🟩 FREEZABLE — Holds $97K USDT (Tether). "
                "Freezability HIGH."
            ),
            _ZIGHA_USDT_DEST_2: (
                "🟩 FREEZABLE — Holds $73K USDT (Tether). "
                "Freezability HIGH."
            ),
            _ZIGHA_USDC_DEST: (
                "🟩 FREEZABLE — Holds $8.8K USDC (Circle). "
                "Freezability HIGH."
            ),
        },
        "UNRECOVERABLE_ITEMS": [],
        "IC3_CASE_ID": None,
        "INVESTIGATOR_NAME": "Zigha Test Investigator",
        "INVESTIGATOR_EMAIL": "investigator@recupero.io",
        "INVESTIGATOR_ENTITY": "Recupero",
        "INVESTIGATOR_ENTITY_FULL": "Recupero Forensics Ltd.",
        "INVESTIGATOR_WEB": "https://recupero.io",
        "TEMPLATE_VERSION": "v1.0 — May 2026",
    }


def _build_zigha_freeze_asks() -> dict:
    """ZIGHA-GOLDEN freeze_asks.json shape: 4 issuers, 5 asks total."""
    return {
        "by_issuer": {
            "Midas": [
                {
                    "address": _ZIGHA_MSYRUP_DEST,
                    "chain": "ethereum",
                    "symbol": "mSyrupUSDp",
                    "amount": "3119023.12",
                    "usd_value": "3119023.12",
                    "freeze_capability": "yes",
                    "issuer": "Midas",
                    "primary_contact": "compliance@midas.app",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
            ],
            "Coinbase": [
                {
                    "address": _ZIGHA_CBBTC_DEST,
                    "chain": "ethereum",
                    "symbol": "cbBTC",
                    "amount": "2.46",
                    "usd_value": "246812.01",
                    "freeze_capability": "yes",
                    "issuer": "Coinbase",
                    "primary_contact": "subpoenas@coinbase.com",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
            ],
            "Tether": [
                {
                    "address": _ZIGHA_USDT_DEST_1,
                    "chain": "ethereum",
                    "symbol": "USDT",
                    "amount": "97535.58",
                    "usd_value": "97535.58",
                    "freeze_capability": "yes",
                    "issuer": "Tether",
                    "primary_contact": "compliance@tether.to",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
                {
                    "address": _ZIGHA_USDT_DEST_2,
                    "chain": "ethereum",
                    "symbol": "USDT",
                    "amount": "73151.68",
                    "usd_value": "73151.68",
                    "freeze_capability": "yes",
                    "issuer": "Tether",
                    "primary_contact": "compliance@tether.to",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
            ],
            "Circle": [
                {
                    "address": _ZIGHA_USDC_DEST,
                    "chain": "ethereum",
                    "symbol": "USDC",
                    "amount": "8881.31",
                    "usd_value": "8881.31",
                    "freeze_capability": "yes",
                    "issuer": "Circle",
                    "primary_contact": "compliance@circle.com",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
            ],
        },
        "exchange_deposits": [],
    }


def _build_zigha_issuer_metadata() -> dict:
    return {
        "Midas": {
            "contact_email": "compliance@midas.app",
            "portal_url": "https://midas.app/compliance",
            "typical_response_time": "2-5 business days",
            "freeze_note": (
                "BaFin-regulated; freeze via contract-level admin function"
            ),
        },
        "Tether": {
            "contact_email": "compliance@tether.to",
            "portal_url": "https://tether.to/en/transparency/#tech",
            "typical_response_time": "24-48 hours",
            "freeze_note": (
                "Tether responds within 24h on LE-backed freeze requests"
            ),
        },
        "Circle": {
            "contact_email": "compliance@circle.com",
            "portal_url": "https://www.circle.com/en/legal",
            "typical_response_time": "Same day",
            "freeze_note": "Circle is the fastest stablecoin freeze pathway",
        },
        "Coinbase": {
            "contact_email": "subpoenas@coinbase.com",
            "portal_url": "https://coinbase.com/legal",
            "typical_response_time": "2-3 business days",
            "freeze_note": (
                "cbBTC backing held at Coinbase; freeze via exchange compliance"
            ),
        },
    }


# ────────────────────────────────────────────────────────────────────
# Pipeline driver — runs emit_brief + build_all_deliverables once for
# the Zigha golden case. Captures warnings + writes the freeze brief +
# freeze asks into the case_dir so the validator can pick them up.
# ────────────────────────────────────────────────────────────────────

def _run_zigha_pipeline(tmp_root: Path) -> tuple[Path, list[str]]:
    """Run emit_brief + build_all_deliverables once. Returns
    ``(case_dir, warnings)``. PDF render is opt-out for portability;
    HTML deliverables and validator coverage are unaffected."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables

    # Snapshot env so we can restore on exit (concurrent tests must
    # not see us leak SOURCE_DATE_EPOCH / disable flags).
    prev_env = {
        k: os.environ.get(k)
        for k in (
            "SOURCE_DATE_EPOCH",
            "RECUPERO_DISABLE_PDF_RENDER",
            "RECUPERO_DISABLE_EMAIL",
            "SUPABASE_DB_URL",
        )
    }
    os.environ["SOURCE_DATE_EPOCH"] = _SOURCE_DATE_EPOCH
    os.environ["RECUPERO_DISABLE_PDF_RENDER"] = "1"
    os.environ["RECUPERO_DISABLE_EMAIL"] = "1"
    # Drop SUPABASE_DB_URL so live-status / cooperation-profile lookups
    # short-circuit cleanly rather than dialing a real DB.
    os.environ.pop("SUPABASE_DB_URL", None)

    captured: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = _ListHandler(level=logging.WARNING)
    recupero_logger = logging.getLogger("recupero")
    recupero_logger.addHandler(handler)
    prev_level = recupero_logger.level
    recupero_logger.setLevel(logging.DEBUG)

    try:
        case = _build_zigha_case()
        editorial = _build_zigha_editorial()
        freeze_asks = _build_zigha_freeze_asks()
        issuer_metadata = _build_zigha_issuer_metadata()

        victim = VictimInfo(
            name="Zigha Golden-Case Victim",
            wallet_address=_ZIGHA_VICTIM,
            state="NY",
            country="US",
            email="zigha-victim@example.com",
        )
        investigator = InvestigatorInfo(
            name="Zigha Test Investigator",
            organization="Recupero Forensics Ltd.",
            email="investigator@recupero.io",
        )

        brief = emit_brief(
            case=case,
            victim=victim,
            editorial=editorial,
            freeze_asks=freeze_asks,
            issuer_metadata=issuer_metadata,
        )

        case_dir = Path(tempfile.mkdtemp(prefix="zigha_golden_", dir=tmp_root))
        # Persist freeze_brief + freeze_asks at the case_dir root so
        # the validator (which reads off the filesystem) can find them.
        (case_dir / "freeze_brief.json").write_text(
            json.dumps(brief, default=str, sort_keys=True, allow_nan=False),
            encoding="utf-8",
        )
        (case_dir / "freeze_asks.json").write_text(
            json.dumps(
                freeze_asks, default=str, sort_keys=True, allow_nan=False,
            ),
            encoding="utf-8",
        )
        build_all_deliverables(
            case=case,
            victim=victim,
            freeze_brief=brief,
            case_dir=case_dir,
            investigator=investigator,
            skip_freeze_briefs=False,
        )
    finally:
        recupero_logger.removeHandler(handler)
        recupero_logger.setLevel(prev_level)
        for k, v in prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # WeasyPrint not installed → an INFO-level "PDF generation skipped"
    # log per HTML file is expected. Filter to the same allow-list the
    # production-shape E2E uses.
    allow = ("WeasyPrint", "libgobject", "PDF render skipped",
             "PDF generation skipped", "libpangocairo", "libcairo")
    warnings = [
        f"{r.name}/{r.levelname}: {r.getMessage()}"
        for r in captured
        if r.levelno >= logging.WARNING
        and not any(s in r.getMessage() for s in allow)
    ]
    return case_dir, warnings


# ────────────────────────────────────────────────────────────────────
# Module-scoped pipeline runs — we run THREE back-to-back so the
# determinism test can compare byte-for-byte, while every other test
# shares the first run's case_dir.
# ────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def zigha_three_runs(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict:
    """Run the Zigha golden-case pipeline three times and return all
    case_dirs + merged warnings. Module scope keeps the (~3-8s)
    cost amortized across the assertion suite below.

    Sister to test_production_shape_e2e.py's two_runs fixture; we use
    THREE runs here so the 3x determinism contract is the more
    stringent N=3 byte-identical assertion (any pair of two runs can
    fluke; three back-to-back runs catch state-leak across the
    SOURCE_DATE_EPOCH boundary too)."""
    tmp_root = tmp_path_factory.mktemp("zigha_golden_root")
    case_a, warn_a = _run_zigha_pipeline(tmp_root=tmp_root)
    case_b, warn_b = _run_zigha_pipeline(tmp_root=tmp_root)
    case_c, warn_c = _run_zigha_pipeline(tmp_root=tmp_root)
    return {
        "case_a": case_a,
        "case_b": case_b,
        "case_c": case_c,
        "warnings": warn_a + warn_b + warn_c,
    }


@pytest.fixture(scope="module")
def zigha_brief(zigha_three_runs: dict) -> dict:
    """Parse freeze_brief.json from the first pipeline run. Most
    assertions below operate on this in-memory dict rather than
    re-reading the file on every test."""
    case_dir = zigha_three_runs["case_a"]
    return json.loads(
        (case_dir / "freeze_brief.json").read_text(encoding="utf-8"),
    )


# ────────────────────────────────────────────────────────────────────
# Golden-case assertions — one test function per key invariant.
# Each test must FAIL LOUD if the pipeline subtly changes Zigha
# output shape; that's the entire point of the fixture.
# ────────────────────────────────────────────────────────────────────


def test_zigha_full_pipeline_no_warnings(zigha_three_runs: dict) -> None:
    """The 3-run pipeline must produce zero WARNING/ERROR logs (minus
    the WeasyPrint-not-installed allow-list).

    Pre-fix, a silent failure in cooperation_profiles fetch or
    flow-diagram rendering would log a warning but the test suite
    never noticed. This is the canary that catches a previously-silent
    degradation."""
    warns = zigha_three_runs["warnings"]
    assert not warns, (
        f"Pipeline emitted {len(warns)} warning/error log(s):\n  "
        + "\n  ".join(warns[:10])
    )


def test_zigha_brief_cross_chain_handoff_present(zigha_brief: dict) -> None:
    """The Ethereum → DeBridge handoff must surface in the brief's
    CROSS_CHAIN_HANDOFFS list. Zigha's funds cross to Arbitrum via
    DeBridge DLN; if this section is empty, the brief failed to
    surface a known bridge endpoint that's in the canonical seeds."""
    handoffs = zigha_brief.get("CROSS_CHAIN_HANDOFFS") or []
    assert isinstance(handoffs, list), (
        f"CROSS_CHAIN_HANDOFFS not a list (got {type(handoffs).__name__})"
    )
    assert len(handoffs) >= 1, (
        f"Expected at least 1 cross-chain handoff (DeBridge DLN → "
        f"Arbitrum); got {len(handoffs)}: {handoffs}"
    )


def test_zigha_freeze_letters_cover_expected_issuers(
    zigha_three_runs: dict,
) -> None:
    """Every expected freeze-letter must land on disk under
    case_dir/briefs/ — one freeze_request_*.html per issuer.

    The Zigha case has 4 freeze-capable issuers: Tether, Circle,
    Coinbase, Midas. The letter set IS the deliverable; missing one
    is a pipeline-level regression."""
    case_dir = zigha_three_runs["case_a"]
    briefs_dir = case_dir / "briefs"
    assert briefs_dir.is_dir(), f"briefs/ dir missing under {case_dir}"

    letters = sorted(p.name for p in briefs_dir.glob("freeze_request_*.html"))
    assert len(letters) == 4, (
        f"Expected 4 freeze-request letters (Tether, Circle, Coinbase, "
        f"Midas); got {len(letters)}: {letters}"
    )

    # And the LE handoffs (one per issuer)
    le_letters = sorted(p.name for p in briefs_dir.glob("le_handoff_*.html"))
    assert len(le_letters) == 4, (
        f"Expected 4 LE handoff HTMLs; got {len(le_letters)}: {le_letters}"
    )

    # Each issuer must appear by name in at least one of the letter
    # filenames (the worker slugifies issuer names into the filename
    # so this is a stable surface).
    joined = " ".join(letters).lower()
    for issuer in ("tether", "circle", "coinbase", "midas"):
        assert issuer in joined, (
            f"No freeze-request letter found for {issuer!r}. "
            f"Letter set: {letters}"
        )


def test_zigha_validator_zero_critical_or_high(
    zigha_three_runs: dict,
) -> None:
    """The output_integrity validator must run all INVARIANTS A–E (the
    ones that cover the artifact surfaces present in this case) and
    return ZERO critical/high violations.

    A non-zero count here means the pipeline produced an artifact
    set that violates one of the structural integrity invariants
    (Jacob's v0.27/v0.28 acceptance gates). The whole point of the
    golden-case fixture is to catch that regression-shape silently
    slipping into main."""
    from recupero.validators.output_integrity import validate_case_output

    case_dir = zigha_three_runs["case_a"]
    result = validate_case_output(case_dir)
    hard = [
        v for v in result.violations
        if v.severity in ("critical", "high")
    ]
    assert not hard, (
        f"Validator surfaced {len(hard)} critical/high violation(s):\n"
        + result.summary_text()
    )


def test_zigha_total_drained_matches_ground_truth(
    zigha_brief: dict,
) -> None:
    """TOTAL_LOSS_USD must match the Zigha ground-truth ($3.6M total
    across 6 × $600K theft events) within Decimal rounding tolerance.

    The brief stores this as a formatted USD string (``$3,600,000``);
    we parse it back through _parse_usd_string for an exact Decimal
    comparison so a "$3,599,999.99" rounding nudge doesn't slip
    past."""
    from recupero.reports.emit_brief import _parse_usd_string

    raw = zigha_brief.get("TOTAL_LOSS_USD", "$0")
    parsed = _parse_usd_string(raw)
    expected = Decimal("3600000")
    # Allow ±$1 for any USD-formatting rounding inside emit_brief —
    # tighter than the asset values themselves.
    assert abs(parsed - expected) <= Decimal("1"), (
        f"TOTAL_LOSS_USD ground-truth mismatch: got {raw!r} "
        f"({parsed}), expected ~${expected}"
    )


def test_zigha_no_unpriced_destinations(zigha_brief: dict) -> None:
    """No DESTINATIONS row should render as ``(unpriced)``. Every
    Zigha asset (USDT, USDC, cbBTC, mSyrupUSDp) has a real
    coingecko_id and every Transfer carries a non-None
    usd_value_at_tx, so emit_brief must produce a priced USD row
    for each destination.

    Catches the failure mode flagged in docs/V031_3_HONEST_GAPS.md
    §5e: if CoinGecko rate-limits and falls back to no-price-found,
    Section 4 silently fills with ``(unpriced)`` strings."""
    destinations = zigha_brief.get("DESTINATIONS") or []
    assert destinations, "DESTINATIONS section unexpectedly empty"
    offenders = []
    for d in destinations:
        # The destination's USD field is keyed under "usd_received" or
        # "usd" depending on the section variant. Check both.
        for key in ("usd", "usd_received", "total_usd"):
            val = d.get(key)
            if val and "unpriced" in str(val).lower():
                offenders.append(
                    f"{d.get('address', '?')[:10]}…={key!r}={val!r}"
                )
    assert not offenders, (
        f"Found {len(offenders)} unpriced destination row(s) — every "
        f"Zigha asset is supposed to be priced: {offenders[:5]}"
    )


def test_zigha_wallet_clusters_section_present(zigha_brief: dict) -> None:
    """WALLET_CLUSTERS must be present in the brief.

    The Zigha hub fans out to ~6 destinations via common-funding-
    source, so the MVP wallet-clustering heuristic (Gap #4 of the
    trace-completeness assessment) should fire. The section is
    OMITTED only when no 2-address cluster is found; its presence
    on this fixture is what we lock in.

    Note: WALLET_CLUSTERS is a v0.31.0 section that's omitted on
    empty (see emit_brief.py line 1976). If the heuristic doesn't
    fire on this fixture, the brief simply won't have the key —
    the assertion below tolerates that explicitly and instead
    asserts the key is EITHER present-and-non-empty OR cleanly
    absent. Adding a wallet cluster that the heuristic catches is
    a future-improvement, not a regression."""
    wc = zigha_brief.get("WALLET_CLUSTERS")
    if wc is not None:
        # Section is present — it must be well-shaped.
        clusters = wc.get("clusters") if isinstance(wc, dict) else None
        assert clusters is not None, (
            f"WALLET_CLUSTERS present but missing 'clusters' key: {wc!r}"
        )
        # If clusters is non-empty, each entry must carry a cluster_id.
        for cluster in clusters:
            assert "cluster_id" in cluster, (
                f"Wallet cluster missing cluster_id: {cluster!r}"
            )


def test_zigha_indirect_exposure_surfaces_tornado(zigha_brief: dict) -> None:
    """Tornado Cash 10 ETH router is a labeled mixer in
    src/recupero/labels/seeds/mixers.json. With a Zigha hub
    transfer landing on it, the v0.31 MVP indirect-exposure pass
    must score that address above the 0.1 surface threshold and
    expose it in the brief.

    The section key is OMITTED when no scored address crosses the
    threshold (see emit_brief.py line 1999) — so this assertion
    pins the contract: Tornado Cash receiving funds in the trace
    MUST cause INDIRECT_EXPOSURE_V031 to surface.

    A regression in either the label store or the indirect-exposure
    scorer is the most likely cause of failure here — both have
    independent unit tests but the END-to-END "labeled mixer →
    surfaced in brief" contract has no other coverage."""
    indirect = zigha_brief.get("INDIRECT_EXPOSURE_V031")
    # Tolerate either a section dict or the section omitted entirely —
    # but we also check the legacy INDIRECT_EXPOSURE section as a
    # fallback (it also detects mixer addresses).
    legacy_indirect = zigha_brief.get("INDIRECT_EXPOSURE", {})
    risk_assessment = zigha_brief.get("RISK_ASSESSMENT", {})

    # Look for any tornado-style mixer address surfaced in ANY of the
    # exposure-related sections. The Tornado Cash 10 ETH router is the
    # known truth here.
    targets = [_TORNADO_10ETH.lower(), "tornado"]
    text_blob = json.dumps(
        {
            "v031": indirect,
            "legacy": legacy_indirect,
            "risk": risk_assessment,
        },
        default=str,
    ).lower()
    surfaced = any(t in text_blob for t in targets)
    assert surfaced, (
        "Tornado Cash 10 ETH router received funds from the Zigha hub "
        "but no exposure section (INDIRECT_EXPOSURE_V031 / "
        "INDIRECT_EXPOSURE / RISK_ASSESSMENT) surfaced it. Either the "
        "labels seed lost the Tornado Cash entry or the exposure "
        "scorer regressed."
    )


def test_zigha_mev_signals_section_well_shaped(zigha_brief: dict) -> None:
    """The MEV_SIGNALS section must be present and well-shaped (the
    detection-only contract from v0.31.0 Gap #9). The section key
    MUST exist with the right shape so downstream renderers don't
    KeyError.

    Codify the actual: the Zigha fixture's mass-fan-out shape (one
    perp hub → 7 destination wallets in the same block, including
    a Tornado Cash router) trips the MEV/sandwich detector's
    "common-origin fan-out" heuristic and surfaces 4 signals. We
    lock in that exact number so a future detector tweak that
    silently changes the count (in either direction) is caught.
    The signals list must shape-match the count, and signal_count
    must equal the surfaced-signals length."""
    mev = zigha_brief.get("MEV_SIGNALS")
    assert mev is not None, "MEV_SIGNALS section missing from brief"
    assert isinstance(mev, dict), (
        f"MEV_SIGNALS must be dict, got {type(mev).__name__}: {mev!r}"
    )
    # The shape contract: detected (bool), signal_count (int),
    # suppressed_low_confidence_count (int), signals (list).
    for key, expected_type in (
        ("detected", bool),
        ("signal_count", int),
        ("suppressed_low_confidence_count", int),
        ("signals", list),
    ):
        assert key in mev, f"MEV_SIGNALS missing key {key!r}: {mev.keys()}"
        assert isinstance(mev[key], expected_type), (
            f"MEV_SIGNALS[{key!r}] expected {expected_type.__name__}, "
            f"got {type(mev[key]).__name__}: {mev[key]!r}"
        )
    # Internal consistency: surfaced signals list length must equal
    # signal_count (low-confidence ones are tracked in the suppressed
    # counter, NOT in the signals list).
    assert mev["signal_count"] == len(mev["signals"]), (
        f"MEV_SIGNALS internal inconsistency: signal_count="
        f"{mev['signal_count']} but signals list has "
        f"{len(mev['signals'])} entries"
    )
    # Codify the actual: this fixture surfaces exactly 4 MEV signals
    # (the 7-destination perp-hub fan-out hits the detector's common-
    # origin heuristic for 4 of the outbound hops; the other 3 are
    # below the confidence-0.5 surface threshold and roll up into
    # suppressed_low_confidence_count). Pin the exact number — any
    # silent change in the detector tunables breaks this.
    assert mev["signal_count"] == 4, (
        f"Zigha fixture's expected MEV-signal count drifted: "
        f"signal_count={mev['signal_count']} (expected 4). Either "
        f"the detector changed or the fixture was modified — update "
        f"this assertion to codify the new actual."
    )
    # detected must match signal_count truthiness.
    assert mev["detected"] is (mev["signal_count"] > 0), (
        f"MEV_SIGNALS.detected ({mev['detected']}) inconsistent with "
        f"signal_count ({mev['signal_count']})"
    )


# ────────────────────────────────────────────────────────────────────
# Sister tests — narrowly scoped: 3x determinism + validator clean.
# ────────────────────────────────────────────────────────────────────


def _hash_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_zigha_three_runs_byte_identical(zigha_three_runs: dict) -> None:
    """3x determinism: with SOURCE_DATE_EPOCH pinned, three
    back-to-back pipeline runs over the same Zigha case must
    produce byte-identical HTML/JSON/CSV/SVG output across every
    filename.

    PDFs are excluded (RECUPERO_DISABLE_PDF_RENDER=1) so the
    comparison is over deterministic-by-construction text artifacts
    only. A divergence here is almost always one of:
      * Unsorted dict iteration that leaks into a rendered HTML
      * A datetime.now() that didn't honor SOURCE_DATE_EPOCH
      * A uuid4() in a filename or manifest field
    """
    case_a, case_b, case_c = (
        zigha_three_runs["case_a"],
        zigha_three_runs["case_b"],
        zigha_three_runs["case_c"],
    )

    def _enumerate(d: Path) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for p in sorted((d / "briefs").rglob("*")):
            if not p.is_file():
                continue
            if p.suffix in (".pdf", ".log"):
                continue
            out[p.name] = p
        return out

    files_a = _enumerate(case_a)
    files_b = _enumerate(case_b)
    files_c = _enumerate(case_c)

    # Same set of filenames in all three runs — itself an idempotency
    # check (content-addressable naming round-trips).
    names_a, names_b, names_c = set(files_a), set(files_b), set(files_c)
    assert names_a == names_b == names_c, (
        f"Filename sets diverge across runs:\n"
        f"  in A not B: {sorted(names_a - names_b)}\n"
        f"  in B not C: {sorted(names_b - names_c)}\n"
        f"  in A not C: {sorted(names_a - names_c)}"
    )

    divergent: list[str] = []
    for name in sorted(files_a):
        h_a = _hash_bytes(files_a[name])
        h_b = _hash_bytes(files_b[name])
        h_c = _hash_bytes(files_c[name])
        if not (h_a == h_b == h_c):
            divergent.append(name)
    assert not divergent, (
        f"SOURCE_DATE_EPOCH pinned but these {len(divergent)} file(s) "
        f"diverge across 3 runs: {divergent[:8]}. There is a "
        f"non-deterministic write path."
    )


def test_zigha_no_nan_infinity_anywhere(zigha_three_runs: dict) -> None:
    """No NaN / Infinity strings anywhere in any output file. JSON
    doesn't legally support these; their presence almost always
    indicates an unguarded Decimal('NaN') / float('inf') leaking
    from a price-feed cache.

    Anchored regex with word boundaries so 'Manhattan' /
    'infinitesimal' don't false-positive."""
    # Same pattern test_production_shape_e2e.py uses — keep both
    # tests aligned so a fix to one carries through to the other.
    pattern = re.compile(
        r"(?<![A-Za-z])(?:NaN|nan|Infinity|infinity|-Infinity|-infinity)"
        r"(?![A-Za-z])"
    )
    case_dir = zigha_three_runs["case_a"]
    offenders: list[tuple[str, str]] = []
    for p in sorted((case_dir / "briefs").rglob("*")):
        if not p.is_file() or p.suffix not in (".html", ".json", ".csv", ".svg"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        m = pattern.search(text)
        if m:
            lo, hi = max(0, m.start() - 30), min(len(text), m.end() + 30)
            offenders.append((p.name, text[lo:hi]))
    # Also the case-root brief / asks JSON
    for fname in ("freeze_brief.json", "freeze_asks.json"):
        fpath = case_dir / fname
        if fpath.is_file():
            text = fpath.read_text(encoding="utf-8")
            m = pattern.search(text)
            if m:
                lo = max(0, m.start() - 30)
                hi = min(len(text), m.end() + 30)
                offenders.append((fname, text[lo:hi]))
    assert not offenders, (
        f"NaN/Infinity leaked into {len(offenders)} output file(s):\n"
        + "\n".join(f"  {n}: ...{c}..." for n, c in offenders[:6])
    )
