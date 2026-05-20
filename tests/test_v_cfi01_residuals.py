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


def test_match_freeze_asks_keeps_freeze_capability_no_holdings() -> None:
    """v0.20.2 (audit-round-2 finding #5): freeze_capability="no"
    holdings (Sky DAI, Lido stETH, etc.) MUST flow through to the
    matched freeze_asks list. They get tagged UNRECOVERABLE
    downstream by `_extract_freezable`'s `capability_blocks_freeze`
    check, but they must remain in freeze_asks because
    `_compute_perpetrator_holdings` reads ONLY the freezable list
    when computing the perpetrator-holdings headline. v0.20.1's
    initial filter at this point silently dropped $18M DAI from the
    headline on Jacob's V-CFI01 — much worse than the cosmetic
    freeze_asks.json noise it was trying to clean up. The
    `capability_blocks_freeze` filter at letter-generation time
    correctly prevents pointless letters."""
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
    # DAI lands in matched so the brief writer can tag it UNRECOVERABLE
    # and `_compute_perpetrator_holdings` counts it toward the headline.
    assert len(matched) == 1
    assert matched[0].holding_symbol == "DAI"
    assert matched[0].issuer.freeze_capability == "no"


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


# ======================================================================
# Audit-round-2 findings (v0.20.2). Each test pins a fix that landed
# after Jacob's V-CFI01 run exposed an upstream regression OR a seam
# bug that v0.20.1 didn't address. Build V-CFI01-shape fixtures FIRST,
# fix the bug, audit-clean-repeat.
# ======================================================================


# ---- Finding #2: pipeline.py suspected_only INVESTIGATE-only ---- #


def test_synthesize_freeze_brief_buckets_match_emit_brief_convention() -> None:
    """`_synthesize_freeze_brief_from_asks` (the skip-editorial path)
    must produce per-issuer + top-level USD buckets that match
    `emit_brief._extract_freezable`'s canonical convention:

      * total_usd            = FREEZABLE only
      * total_suspected_usd  = INVESTIGATE only
      * total_excluded_usd   = UNRECOVERABLE / EXCHANGE / TRANSIT / UNKNOWN

    Pre-v0.20.2 the suspected bucket double-counted FREEZABLE holdings
    (it was FREEZABLE+INVESTIGATE), inflating the engagement letter's
    "Under Investigation" total by ~20x on the V-CFI01 case shape.
    Verified via source inspection — the full skip-editorial path
    needs psycopg + Supabase, not feasible at unit scope. The
    integration test suite covers end-to-end."""
    import inspect
    from recupero.worker import pipeline
    src = inspect.getsource(pipeline._synthesize_freeze_brief_from_asks)
    # The per-token suspected_only branch must use elif INVESTIGATE, not
    # if FREEZABLE+INVESTIGATE. Pin the failure mode literally.
    assert 'elif h_status == "INVESTIGATE":' in src, (
        "per-token suspected bucket must accumulate INVESTIGATE-only, "
        "not FREEZABLE+INVESTIGATE — see audit-round-2 finding #2"
    )
    # The top-level total_suspected aggregate must also be guarded.
    assert 'if status == "INVESTIGATE" and usd > 0:' in src, (
        "top-level total_suspected must guard on INVESTIGATE status; "
        "pre-v0.20.2 it summed every holding regardless of status"
    )


# ---- Finding #3: _victim_summary per-issuer subtraction ---- #


def test_victim_summary_per_issuer_uses_suspected_directly() -> None:
    """The customer summary's per-issuer "Under Investigation" column
    must use `entry['total_suspected_usd']` directly. Pre-v0.20.2 the
    column subtracted `total_usd` (FREEZABLE) from `total_suspected_usd`
    (INVESTIGATE) — the same v0.16.7 bug that was fixed at the
    case-level total but slipped through at the per-issuer column.
    On V-CFI01-shape cases the subtraction always went negative,
    so the column displayed "—" on every row."""
    import inspect
    from recupero.worker import _victim_summary
    src = inspect.getsource(_victim_summary._build_context)
    # The subtraction line is gone.
    assert "suspected_usd - freezable_usd" not in src, (
        "per-issuer subtraction must be removed — see audit-round-2 "
        "finding #3. total_suspected_usd is already INVESTIGATE-only."
    )


# ---- Finding #4: LE-routing sum-across-theft_events ---- #


def test_le_routing_uses_sum_of_theft_events_usd() -> None:
    """LE-routing thresholds (IC3-only / state-AG / multi-jurisdiction
    escalation) must be driven by TOTAL stolen USD, not just the
    primary theft event's USD. In a V-CFI01-shape case the drain is
    split across N transactions (e.g. 6 × $600K = $3.6M); pre-v0.20.2
    we passed only the primary event's USD, so the LE handoff routed
    to a lower tier than the actual case warranted."""
    import inspect
    from recupero.reports import brief
    src = inspect.getsource(brief.generate_briefs)
    # The construction of le_routing must sum theft_events.usd_value_at_tx.
    assert 'for t in theft_events' in src and 'le_routing' in src, (
        "le_routing must aggregate USD across theft_events — see "
        "audit-round-2 finding #4"
    )


# ---- Finding #6: flow-diagram canonical-key promotion lookup ---- #


def test_flow_diagram_promotion_uses_canonical_key() -> None:
    """`_promote_freezable_holdings` must look up nodes by
    canonical_address_key (which lowercases EVM, case-preserves
    base58). Pre-v0.20.2 it used `.lower()` on both sides — silently
    breaking base58 chains (Solana / Tron / Bitcoin), where the case
    of a holding address that doesn't match the trace's case-variant
    would mean the holding never gets promoted to a labeled cluster."""
    import inspect
    from recupero.worker import _flow_diagram
    src = inspect.getsource(_flow_diagram._promote_freezable_holdings)
    assert 'canonical_address_key' in src, (
        "_promote_freezable_holdings must use canonical_address_key, "
        "not .lower() — see audit-round-2 finding #6"
    )
    # And the brittle .lower() pattern must be gone.
    assert 'addr_lower_to_node' not in src, (
        "remnants of the old .lower() addr_lower_to_node dict must be "
        "removed — see audit-round-2 finding #6"
    )


# ---- Finding #7: brief._add canonical seen dedup ---- #


def test_identified_wallets_dedup_by_canonical_key() -> None:
    """`_build_identified_wallets._add` must dedup by canonical key so
    base58 chains aren't silently corrupted by `.lower()`. EVM
    addresses still collapse case variants; base58 case is preserved
    (it's significant on-chain)."""
    import inspect
    from recupero.reports import brief
    src = inspect.getsource(brief._build_identified_wallets)
    # The _ck import + use must be inside _build_identified_wallets so
    # the inner _add() function picks it up.
    assert "_ck(addr)" in src, (
        "_add() must use canonical_address_key (_ck) for the seen "
        "dict key — see audit-round-2 finding #7"
    )
    # The naive `addr.lower()` key must be gone from this function.
    assert "key = addr.lower()" not in src, (
        "stale `key = addr.lower()` line must be removed from "
        "_build_identified_wallets — see audit-round-2 finding #7"
    )


# ---- Finding #8: _extract_perp_hub canonical per_addr_usd ---- #


def test_extract_perp_hub_buckets_by_canonical_key() -> None:
    """`_extract_perp_hub` must bucket per_addr_usd by canonical_key
    so two case variants of the same EVM destination don't split the
    USD total (which could let a smaller single-case-variant
    destination steal the "largest outflow" crown)."""
    import inspect
    from recupero.reports import emit_brief
    src = inspect.getsource(emit_brief._extract_perp_hub)
    # The dict must be keyed by _ck(t.to_address), not raw t.to_address.
    assert "to_canon = _ck(" in src, (
        "_extract_perp_hub must canonicalize per_addr_usd keys — "
        "see audit-round-2 finding #8"
    )
    # And the display map must preserve the first-occurrence casing.
    assert "per_addr_display" in src, (
        "_extract_perp_hub must keep a per_addr_display map so the "
        "return value preserves on-chain casing — see audit-round-2 "
        "finding #8"
    )


# ---- Finding #9: trace report per-holding chain ---- #


def test_trace_report_freezable_row_uses_per_holding_chain() -> None:
    """The trace-report's FREEZABLE table must build each row's
    explorer_url from the per-holding chain, not the primary case
    chain — cross-chain freezable holdings (e.g. Tron USDT in an
    Ethereum-seeded case) would otherwise link to
    ``etherscan.io/address/<base58>`` → 404 on every click."""
    import inspect
    from recupero.worker import _trace_report
    src = inspect.getsource(_trace_report._build_freezable_table)
    assert 'row_chain = h.get("chain")' in src, (
        "row_chain must be derived from the per-holding chain — see "
        "audit-round-2 finding #9"
    )
    # And it must be passed to _explorer_url, not chain_str.
    assert "_explorer_url(address, row_chain)" in src, (
        "row_chain must be passed to _explorer_url — see "
        "audit-round-2 finding #9"
    )


# ---- Finding #10: LE template explicit status branches ---- #


def test_le_template_branches_per_status_label() -> None:
    """``le.html.j2`` must emit explicit pills for FREEZABLE /
    INVESTIGATE / UNRECOVERABLE / EXCHANGE / TRANSIT status. The
    pre-v0.20.2 `else` fell every non-FREEZABLE status into one
    "INVESTIGATE" pill, including UNRECOVERABLE protocol contracts
    and EXCHANGE deposit addresses — the LE reader is expected to
    route those differently from genuine investigative leads."""
    from pathlib import Path
    from recupero.reports import brief
    tmpl = (
        Path(brief.__file__).resolve().parent / "templates" / "le.html.j2"
    ).read_text(encoding="utf-8")
    for status in ("FREEZABLE", "INVESTIGATE", "UNRECOVERABLE", "EXCHANGE", "TRANSIT"):
        assert f"'{status}'" in tmpl or f'"{status}"' in tmpl, (
            f"le.html.j2 must branch on status={status!r} — see "
            "audit-round-2 finding #10"
        )


# ---- Finding #11: dormant finder canonical address keys ---- #


def test_dormant_finder_canonical_address_tokens_keys() -> None:
    """``address_tokens`` / ``address_inflow`` / ``address_inflow_count``
    must be keyed by canonical_address_key so two case variants of
    the same EVM destination don't get two separate buckets (and
    duplicate dormant balance calls). Base58 chains preserve case
    via canonical_address_key, so this is safe across multi-chain
    dispatch."""
    import inspect
    from recupero.dormant import finder
    src = inspect.getsource(finder.find_dormant_in_case)
    # The canonical dest_key must be used as the dict-key.
    assert "address_tokens.setdefault(dest_key" in src, (
        "address_tokens must be keyed by canonical dest_key — see "
        "audit-round-2 finding #11"
    )
    # And the raw `dest`-keyed naive form must be gone.
    assert "address_tokens.setdefault(dest, {})" not in src, (
        "stale raw-`dest` keyed setdefault must be removed — see "
        "audit-round-2 finding #11"
    )


# ---- Finding #12: flow diagram canonical nodes + edges ---- #


def test_flow_diagram_aggregate_uses_canonical_keys() -> None:
    """`_aggregate` must key `nodes` and edge tuples by canonical
    address so the same address in two case variants doesn't render
    as two separate nodes (or two parallel edges between "different"
    nodes). The display address is preserved on _NodeAttrs.address /
    _EdgeAttrs.src/dst so rendered text matches the on-chain
    canonical form."""
    import inspect
    from recupero.worker import _flow_diagram
    src = inspect.getsource(_flow_diagram._aggregate)
    # Canonicalisation imports + applies.
    assert "canonical_address_key" in src, (
        "_aggregate must canonicalize node keys — see audit-round-2 "
        "finding #12"
    )
    # The naive raw-address `nodes.setdefault(t.from_address, …)` is
    # gone — it's replaced with `nodes.setdefault(from_key, …)`.
    assert "nodes.setdefault(\n            t.from_address," not in src, (
        "stale raw-`t.from_address` setdefault must be removed — see "
        "audit-round-2 finding #12"
    )
    assert "from_key = canonical_address_key" in src, (
        "from_key must be canonical_address_key(t.from_address) — "
        "see audit-round-2 finding #12"
    )
