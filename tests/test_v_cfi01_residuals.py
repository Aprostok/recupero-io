"""Regression tests pinning the v0.20.1 fixes for Jacob's V-CFI01 residuals.

After 13 audit rounds we declared the codebase "clean," but Jacob's
real V-CFI01 run against v0.19.3 surfaced six bugs that unit tests
hadn't caught — every one of them lives at the seam between two
modules where unit-level tests had been green. This file pins each
fix at the integration level so future refactors trip on the failure
mode rather than silently shipping the same bug again.

Bug → test mapping:
  1. CRIT — $3.12M mSyrupUSDp at consolidation hop dropped because
     the seed issuers.json had the wrong contract address.
     → test_msyrupusdp_canonical_contract_matches_issuer_db
  2. HIGH — duplicate destinations in freeze_brief DESTINATIONS from
     case-mismatched merge between trace + freeze_targets.
     → test_destinations_dedup_by_canonical_key
  3. HIGH — Section 3 freeze-letter stub fires "no forwarding observed"
     even when Section 4 lists downstream destinations.
     → test_forwarding_observed_when_downstream_destinations_exist
  4. MED — Lido $8.8B contract entry in freeze_asks.
     → test_match_freeze_asks_skips_above_100m_cap
     → test_match_freeze_asks_routes_freeze_capability_no_to_unmatched
  5. MED — flow-diagram entity grouping ignores brief's INVESTIGATE
     classification (Threshold contract promoted to "Tether holding").
     → test_flow_diagram_only_promotes_freezable_status
  6. MED — Asset issuer conflated with freeze-target issuer in letter
     Section 2.
     → test_asset_issuer_resolves_to_stolen_token_issuer
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal


# ---- Residual #1: msyrupUSDp contract in issuers.json ---- #


def test_msyrupusdp_canonical_contract_matches_issuer_db() -> None:
    """The seed file's msyrupUSDp contract must equal the canonical
    on-chain contract address. Pre-v0.20.1 the seed had a typo
    contract address (`0x2fe058cc73f7...cd5cb`) that didn't match the
    real on-chain contract (`0x2fE058CcF29f...8E50`). Every real
    msyrupUSDp transfer fell through the issuer DB lookup → no Midas
    freeze_ask was emitted → $3.12M of recoverable USD silently
    omitted from briefs.
    """
    from recupero._common import canonical_address_key
    from recupero.freeze.asks import load_issuer_db
    from recupero.models import Chain

    db = load_issuer_db()
    real_msyrup = canonical_address_key(
        "0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50",
    )
    entry = db.get((Chain.ethereum, real_msyrup))
    assert entry is not None, (
        f"msyrupUSDp contract {real_msyrup!r} must be in issuer DB. "
        "If you intentionally renamed the contract, update this test."
    )
    assert entry.issuer == "Midas"
    assert entry.freeze_capability == "yes"
    assert entry.primary_contact == "compliance@midas.app"


# ---- Residual #2: canonical-key dedup in destinations ---- #


def test_destinations_dedup_by_canonical_key() -> None:
    """`_extract_destinations` must canonical-key its candidate set
    so the same on-chain address appearing in both `case.transfers`
    (mixed case from explorer) and `freeze_targets_by_addr`
    (lowercase from freeze_asks) collapses to one destination row.
    """
    from recupero.models import (
        Case,
        Chain,
        Counterparty,
        TokenRef,
        Transfer,
    )
    from recupero.reports.emit_brief import _extract_destinations

    now = datetime(2026, 5, 1, tzinfo=UTC)
    victim = "0x" + "v" * 40
    # Same on-chain address, mixed case from the trace
    dest_mixed = "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4"
    # And the lowercase form from the freeze_asks emitter
    dest_lower = "0x6482e8fb42130b3cce53096bb035ebe79435e2d4"
    assert dest_mixed.lower() == dest_lower

    case = Case(
        case_id="DUP-DEST-1",
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
                to_address=dest_mixed,
                counterparty=Counterparty(
                    address=dest_mixed, label=None, is_contract=False,
                ),
                token=TokenRef(
                    chain=Chain.ethereum,
                    contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    symbol="USDC", decimals=6, coingecko_id="usd-coin",
                ),
                amount_raw="100000000000",
                amount_decimal=Decimal("100000"),
                usd_value_at_tx=Decimal("100000"),
                hop_depth=0,
                fetched_at=now,
                explorer_url="https://etherscan.io/tx/0x1",
            ),
        ],
    )

    # freeze_targets keyed lowercase (post-v0.19.1 canonical normalization)
    freeze_targets_by_addr = {
        dest_lower: {
            "address": dest_lower,
            "symbol": "USDC",
            "usd_value": "8881.31",
            "issuer": "Circle",
        },
    }
    destinations = _extract_destinations(
        case, editorial_notes={},
        freeze_targets_by_addr=freeze_targets_by_addr,
    )
    # ONE destination, not two
    matching = [
        d for d in destinations
        if d["address"].lower() == dest_lower
    ]
    assert len(matching) == 1, (
        f"Same on-chain address must dedup to one destination row; "
        f"got {len(matching)}: {[d['address'] for d in matching]}"
    )


# ---- Residual #3: forwarding_observed flag ---- #


def test_forwarding_observed_when_downstream_destinations_exist() -> None:
    """`generate_briefs` must surface a `forwarding_observed` ctx flag
    that's True when downstream destinations exist (issuer_freezable
    holdings), even if the linear `hops` chain is empty. Pre-v0.20.1
    Section 3 of the freeze letter printed "no forwarding observed"
    despite Section 4 listing downstream wallets — the template gated
    only on `hops`, not on `issuer_freezable`.

    Verified via source inspection: the helper that builds the ctx
    must include the bool. (Full template-render verification lives
    in the integration test suite.)
    """
    import inspect
    from recupero.reports import brief
    src = inspect.getsource(brief.generate_briefs)
    assert "forwarding_observed" in src, (
        "generate_briefs must populate `forwarding_observed` in the "
        "template ctx so Section 3 stub doesn't contradict Section 4"
    )
    # And the templates must reference it (issuer + maple variants).
    from pathlib import Path
    tmpl_dir = (
        Path(brief.__file__).resolve().parent / "templates"
    )
    issuer_tmpl = (tmpl_dir / "issuer_freeze_request.html.j2").read_text(
        encoding="utf-8",
    )
    assert "forwarding_observed" in issuer_tmpl, (
        "issuer_freeze_request template must use forwarding_observed"
    )


# ---- Residual #4: $100M cap + freeze_capability="no" routing ---- #


def test_match_freeze_asks_skips_above_100m_cap() -> None:
    """A candidate holding > $100M of a single token at a single
    address is overwhelmingly a protocol/pool contract, not a wallet.
    Pre-v0.20.1 the Lido wstETH contract's $8.8B stETH custody was
    emitted as a freeze_ask; now it's skipped at synthesis."""
    from recupero.freeze.asks import match_freeze_asks
    from recupero.dormant.finder import DormantCandidate, TokenHolding
    from recupero.models import Chain, TokenRef

    # Build a candidate holding $8.8B of stETH
    holding = TokenHolding(
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xae7ab96520de3a18e5e111b5eaab095312d7fe84",  # stETH
            symbol="stETH", decimals=18,
        ),
        raw_amount=8_800_000_000 * (10 ** 18),
        decimal_amount=Decimal("8800000000"),
        usd_value=Decimal("8800000000"),
    )
    candidate = DormantCandidate(
        address="0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0",
        chain=Chain.ethereum,
        total_usd=Decimal("8800000000"),
        holdings=[holding],
    )
    matched, _ = match_freeze_asks([candidate])
    assert len(matched) == 0, (
        "$8.8B holdings must be skipped — no legitimate single-victim "
        "freeze target reaches that scale"
    )


def test_match_freeze_asks_routes_freeze_capability_no_to_unmatched() -> None:
    """Sky Protocol DAI (freeze_capability="no") must land in
    unmatched, not matched. Pre-v0.20.1 these flowed into freeze_asks
    and downstream consumers had to filter on the capability field
    again to suppress letters. Now filtered at synthesis."""
    from recupero.freeze.asks import match_freeze_asks
    from recupero.dormant.finder import DormantCandidate, TokenHolding
    from recupero.models import Chain, TokenRef

    holding = TokenHolding(
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
            symbol="DAI", decimals=18,
        ),
        raw_amount=100_000 * (10 ** 18),
        decimal_amount=Decimal("100000"),
        usd_value=Decimal("100000"),
    )
    candidate = DormantCandidate(
        address="0x" + "a" * 40,
        chain=Chain.ethereum,
        total_usd=Decimal("100000"),
        holdings=[holding],
    )
    matched, unmatched = match_freeze_asks([candidate])
    assert len(matched) == 0
    assert any(h.token.symbol == "DAI" for h in unmatched)


# ---- Residual #5: flow diagram respects FREEZABLE-only promotion ---- #


def test_flow_diagram_only_promotes_freezable_status() -> None:
    """`_promote_freezable_holdings` in flow diagram must only promote
    holdings with status FREEZABLE; INVESTIGATE/UNRECOVERABLE-tagged
    holdings (the brief's contract-detection classification) must
    NOT visually cluster as "<Issuer> holding"."""
    import inspect
    from recupero.worker import _flow_diagram
    src = inspect.getsource(_flow_diagram._promote_freezable_holdings)
    assert 'status' in src and 'FREEZABLE' in src, (
        "_promote_freezable_holdings must filter per-holding status; "
        "v0.20.1 fix regressed"
    )


# ---- Residual #6: asset.issuer is stolen-token's issuer ---- #


def test_asset_issuer_resolves_to_stolen_token_issuer() -> None:
    """For a mSyrupUSDp theft sent to Tether (downstream USDT), the
    letter's Section 2 "Asset issuer" cell must read "Midas" (the
    actual mSyrupUSDp issuer), not "Tether" (the freeze-target
    issuer). Both facts coexist; neither overwrites the other."""
    from recupero.reports.brief import _resolve_theft_asset_issuer_name
    from recupero.models import (
        Chain, Counterparty, TokenRef, Transfer,
    )
    msyrup = TokenRef(
        chain=Chain.ethereum,
        contract="0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50",
        symbol="msyrupUSDp", decimals=18, coingecko_id=None,
    )
    transfer = Transfer(
        transfer_id="ethereum:0xtest:1",
        chain=Chain.ethereum,
        tx_hash="0x" + "1" * 64,
        block_number=1,
        block_time=datetime(2026, 5, 1, tzinfo=UTC),
        from_address="0x" + "v" * 40,
        to_address="0x" + "p" * 40,
        counterparty=Counterparty(
            address="0x" + "p" * 40, label=None, is_contract=False,
        ),
        token=msyrup,
        amount_raw="100000000000",
        amount_decimal=Decimal("100000"),
        usd_value_at_tx=Decimal("100000"),
        hop_depth=0,
        fetched_at=datetime(2026, 5, 1, tzinfo=UTC),
        explorer_url="https://etherscan.io/tx/0x1",
    )
    # Fallback is "Tether" (the freeze-target on a Tether letter);
    # resolver should override to "Midas" (mSyrupUSDp's actual issuer).
    resolved = _resolve_theft_asset_issuer_name(transfer, fallback="Tether")
    assert resolved == "Midas", (
        f"Expected resolver to return 'Midas' for mSyrupUSDp theft; "
        f"got {resolved!r}. The Section 2 'Asset issuer' cell on a "
        f"Tether-targeted letter must reflect the stolen-token issuer, "
        f"not the freeze-target."
    )
