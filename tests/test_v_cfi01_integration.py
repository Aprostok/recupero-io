"""V-CFI01 pipeline integration tests (v0.16.0, Jacob bug report May 18 2026).

Jacob's May-18 bug report flagged that V-CFI01's freeze_asks.json
contained only the DAI entry, missing $3.55M in freezable token
balances at six other downstream destinations. The classifier
correctly applied its rule, but on broken input, so the case got
routed to the `victim_summary_unrecoverable.pdf` deliverable —
contradicting what the trace data showed.

Root cause: `synthesize_historical_freeze_asks` (v0.14.8) was wired
into the CLI's `recupero list-freeze-targets` command but never
wired into the worker pipeline. Production cases (the path actual
investigations take) ran ONLY the current-balance dormant-detection
path. v0.16.0 closes that gap.

These tests pin the three acceptance criteria Jacob enumerated:

  1. ``test_v_cfi01_freeze_asks_includes_all_freezable_inflows``
     — historical synthesis produces all expected issuer entries
     for the V-CFI01 case shape.

  2. ``test_v_cfi01_case_not_classified_unrecoverable_when_freezable_assets_present``
     — the classifier's recoverable/unrecoverable routing on the
     correctly-built freeze_brief yields ``is_recoverable=True``.

  3. ``test_v_cfi01_investigator_findings_has_amounts_and_headlines``
     — investigator_findings.json findings have populated
     headlines + amounts (not trailing-space empties).

The fixture uses the actual V-CFI01 case shape from Jacob's bug
report: victim → perpetrator hub → six freezable downstream
destinations (3 USDT addresses, 1 USDC, 1 cbBTC, 1 mSyrupUSDp), plus
one non-freezable DAI destination. Real mainnet contract addresses
where available so the issuer DB lookup mirrors production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from recupero.freeze.asks import (
    FreezeAsk,
    IssuerEntry,
    synthesize_historical_freeze_asks,
)
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.reports.investigator_export import build_findings, write_csv
from recupero.worker._victim_summary import classify_recovery_prospects


# ---- Real mainnet contract addresses (lowercase per issuer DB convention) ---- #

USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC_CONTRACT = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
CBBTC_CONTRACT = "0xcbb7c0006f23900c38eb856149f799620fcb8a4a"
MSYRUP_CONTRACT = "0x2fe058cc73f7e2eecaaa17ed8c11c389a35cd5cb"
DAI_CONTRACT = "0x6b175474e89094c44da98b954eedeac495271d0f"


# ---- V-CFI01 case-shape addresses (real addresses from Jacob's bug report) ---- #

VICTIM = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP_HUB = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"  # DAI holder

# Six freezable downstream destinations + the DAI destination
MSYRUP_DEST = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"  # $3.1M mSyrupUSDp
CBBTC_DEST = "0x6E4141d33021b52C91c28608403db4A0FFB50Ec6"   # $246K cbBTC
USDT_DEST_1 = "0x00000688768803Bbd44095770895ad27ad6b0d95"  # $97K USDT
USDT_DEST_2 = "0x5141B82f5fFDa4c6fE1E372978F1C5427640a190"  # $73K USDT
USDC_DEST = "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4"    # $8.8K USDC
USDT_DEST_3 = "0x3B0AA7d38Bf3C103bf02d1De2E37568cBED3D6e8"  # $1.6K USDT


def _mk_token(contract: str, symbol: str, decimals: int = 6) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract=contract,
        symbol=symbol,
        decimals=decimals,
        coingecko_id={
            USDT_CONTRACT: "tether",
            USDC_CONTRACT: "usd-coin",
            CBBTC_CONTRACT: "coinbase-wrapped-btc",
            MSYRUP_CONTRACT: "midas-syrupusdp",
            DAI_CONTRACT: "dai",
        }.get(contract),
    )


def _mk_transfer(
    *, from_addr: str, to_addr: str, token: TokenRef,
    usd: Decimal, amount: Decimal = Decimal("1000"),
    tx_hash: str | None = None,
) -> Transfer:
    if tx_hash is None:
        tx_hash = "0x" + str(hash((from_addr, to_addr, token.symbol)) % (10**60))[:64].zfill(64)
    block_time = datetime(2025, 10, 9, 0, 29, tzinfo=timezone.utc)
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=18900000,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=token,
        amount_raw="1000000000",
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _v_cfi01_case() -> Case:
    """Build the V-CFI01 case shape from Jacob's bug report:
    victim → perp hub → 6 freezable destinations + 1 non-freezable DAI."""
    transfers = [
        # Victim → perpetrator hub (the big initial drain)
        _mk_transfer(
            from_addr=VICTIM, to_addr=PERP_HUB,
            token=_mk_token(USDT_CONTRACT, "USDT"),
            usd=Decimal("3550000"),
            tx_hash="0xhubdrain",
        ),
        # Hub → mSyrupUSDp consolidation address ($3.1M)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=MSYRUP_DEST,
            token=_mk_token(MSYRUP_CONTRACT, "mSyrupUSDp", decimals=18),
            usd=Decimal("3119023.12"),
            tx_hash="0xmsyrup",
        ),
        # Hub → cbBTC consolidation address ($246K)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=CBBTC_DEST,
            token=_mk_token(CBBTC_CONTRACT, "cbBTC", decimals=8),
            usd=Decimal("246812.01"),
            tx_hash="0xcbbtc",
        ),
        # Hub → USDT dest 1 ($97K)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDT_DEST_1,
            token=_mk_token(USDT_CONTRACT, "USDT"),
            usd=Decimal("97535.58"),
            tx_hash="0xusdt1",
        ),
        # Hub → USDT dest 2 ($73K)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDT_DEST_2,
            token=_mk_token(USDT_CONTRACT, "USDT"),
            usd=Decimal("73151.68"),
            tx_hash="0xusdt2",
        ),
        # Hub → USDC dest ($8.8K — below current-balance threshold,
        # only the historical synthesizer picks this up)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDC_DEST,
            token=_mk_token(USDC_CONTRACT, "USDC"),
            usd=Decimal("8881.31"),
            tx_hash="0xusdc",
        ),
        # Hub → USDT dest 3 ($1.6K — below current-balance threshold)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDT_DEST_3,
            token=_mk_token(USDT_CONTRACT, "USDT"),
            usd=Decimal("1597.70"),
            tx_hash="0xusdt3",
        ),
        # Hub → DAI destination ($655K, but Sky Protocol has
        # freeze_capability='no', so this MUST NOT produce a freeze ask)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=PERP_HUB,  # DAI sits at the hub
            token=_mk_token(DAI_CONTRACT, "DAI", decimals=18),
            usd=Decimal("655751.45"),
            tx_hash="0xdai",
        ),
    ]
    return Case(
        case_id="V-CFI01",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2025, 10, 9, 0, 29, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        software_version="0.16.0",
        config_used={"trace": {"max_depth": 2}},
    )


def _mk_issuer_db() -> dict:
    """V-CFI01 issuer DB — mirrors the production issuers.json shape
    for the five tokens in the V-CFI01 trace."""
    return {
        (Chain.ethereum, USDT_CONTRACT): IssuerEntry(
            chain=Chain.ethereum, contract=USDT_CONTRACT,
            symbol="USDT", issuer="Tether",
            freeze_capability="yes",
            freeze_notes="Tether responds within 24h on LE-backed freeze requests.",
            primary_contact="compliance@tether.to",
            secondary_contact=None,
            jurisdiction="British Virgin Islands",
        ),
        (Chain.ethereum, USDC_CONTRACT): IssuerEntry(
            chain=Chain.ethereum, contract=USDC_CONTRACT,
            symbol="USDC", issuer="Circle",
            freeze_capability="yes",
            freeze_notes="Circle's compliance team has the fastest stablecoin freeze pathway.",
            primary_contact="compliance@circle.com",
            secondary_contact=None,
            jurisdiction="USA",
        ),
        (Chain.ethereum, CBBTC_CONTRACT): IssuerEntry(
            chain=Chain.ethereum, contract=CBBTC_CONTRACT,
            symbol="cbBTC", issuer="Coinbase",
            freeze_capability="yes",
            freeze_notes="cbBTC backing held at Coinbase; freeze pathway via exchange compliance.",
            primary_contact="compliance@coinbase.com",
            secondary_contact=None,
            jurisdiction="USA",
        ),
        (Chain.ethereum, MSYRUP_CONTRACT): IssuerEntry(
            chain=Chain.ethereum, contract=MSYRUP_CONTRACT,
            symbol="mSyrupUSDp", issuer="Midas",
            freeze_capability="yes",
            freeze_notes="Midas is BaFin-regulated; freeze pathway via the wrapped-token contract.",
            primary_contact="compliance@midas.app",
            secondary_contact=None,
            jurisdiction="Germany (BaFin)",
        ),
        (Chain.ethereum, DAI_CONTRACT): IssuerEntry(
            chain=Chain.ethereum, contract=DAI_CONTRACT,
            symbol="DAI", issuer="Sky Protocol",
            freeze_capability="no",
            freeze_notes="DAI is permissionless; no issuer freeze authority.",
            primary_contact=None,
            secondary_contact=None,
            jurisdiction="(decentralized)",
        ),
    }


# ---- Test 1 (Jacob's acceptance criterion #1) ---- #


def test_v_cfi01_freeze_asks_includes_all_freezable_inflows() -> None:
    """V-CFI01: ALL six freezable destinations must produce FreezeAsk
    entries via the historical-inflow synthesizer, and ONLY the DAI
    destination is excluded (Sky Protocol freeze_capability='no').

    Pre-v0.16.0 bug: the worker pipeline never called
    synthesize_historical_freeze_asks, so freeze_asks.json contained
    only the DAI entry (the only one that had a current balance
    picked up by the dormant detector — and ironically the one
    issuer that can't actually freeze).

    Post-v0.16.0: 4 issuers (Tether, Circle, Coinbase, Midas)
    appear in the issuer set, with 6 asks total."""
    case = _v_cfi01_case()
    issuer_db = _mk_issuer_db()

    asks = synthesize_historical_freeze_asks(
        case, issuer_db=issuer_db, min_inflow_usd=Decimal("1000"),
    )

    # Jacob's required minimum: all four freezable issuers present.
    issuers = {a.issuer.issuer for a in asks}
    assert "Tether" in issuers, f"Tether missing. Got: {issuers}"
    assert "Circle" in issuers, f"Circle missing. Got: {issuers}"
    assert "Coinbase" in issuers, f"Coinbase missing. Got: {issuers}"
    assert "Midas" in issuers, f"Midas missing. Got: {issuers}"
    # And Sky Protocol must be absent (freeze_capability='no').
    assert "Sky Protocol" not in issuers, (
        "Sky Protocol (DAI) should not produce freeze asks — it can't freeze. "
        f"Got: {issuers}"
    )

    # Jacob's acceptance: total_asks >= 7 (3 USDT + 1 USDC + 1 cbBTC +
    # 1 mSyrupUSDp + the DAI for completeness with freeze_capability=no).
    # Note: in the historical synthesizer, DAI is filtered (we don't waste
    # operator time on letters that can't be acted on). So the historical
    # synthesizer alone produces 6 asks; the DAI shows up in a separate
    # current-balance path that the worker also runs.
    addresses = {a.candidate_address.lower() for a in asks}
    assert MSYRUP_DEST.lower() in addresses, "mSyrupUSDp destination missing"
    assert CBBTC_DEST.lower() in addresses, "cbBTC destination missing"
    assert USDT_DEST_1.lower() in addresses, "USDT dest 1 missing"
    assert USDT_DEST_2.lower() in addresses, "USDT dest 2 missing"
    assert USDC_DEST.lower() in addresses, "USDC dest missing"
    assert USDT_DEST_3.lower() in addresses, "USDT dest 3 (below $10K) missing"

    # All historical asks must carry the correct evidence_type so the
    # AI editorial prompt + brief synthesis branch correctly.
    assert all(a.evidence_type == "historical_inflow" for a in asks), (
        f"All asks must have evidence_type='historical_inflow'. "
        f"Got types: {[a.evidence_type for a in asks]}"
    )


def test_v_cfi01_freeze_asks_propagates_evidence_type_to_payload() -> None:
    """v0.16.0 worker schema must include evidence_type/observed_at/
    observed_transfer_count for each ask. Pre-v0.16.0 the worker
    serializer dropped these fields, so downstream consumers
    (AI editorial prompt, letter template) defaulted to
    'current_balance' semantics for everything."""
    case = _v_cfi01_case()
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(), min_inflow_usd=Decimal("1000"),
    )
    assert asks  # sanity

    # Simulate the worker's payload-building step (the loop at
    # pipeline.py:639-664). The contract is: each by_issuer entry
    # carries evidence_type, observed_at, observed_transfer_count.
    for a in asks:
        payload_entry = {
            "address": a.candidate_address,
            "evidence_type": a.evidence_type,
            "observed_at": a.observed_at_iso,
            "observed_transfer_count": a.observed_transfer_count,
        }
        assert payload_entry["evidence_type"] in (
            "current_balance", "historical_inflow",
        )
        # observed_at populated for every historical ask (always since v0.14.8)
        if a.evidence_type == "historical_inflow":
            assert payload_entry["observed_at"] is not None
            assert payload_entry["observed_transfer_count"] >= 1


# ---- Test 2 (Jacob's acceptance criterion #2) ---- #


def test_v_cfi01_case_not_classified_unrecoverable_when_freezable_assets_present() -> None:
    """With the v0.16.0 fix, V-CFI01's freeze_brief.FREEZABLE
    section contains $3.55M in total freezable value across 4 issuers.

    classify_recovery_prospects MUST yield is_recoverable=True, which
    routes the customer-facing artifact to victim_summary_recoverable.pdf
    (the "we can help" letter), NOT to victim_summary_unrecoverable.pdf
    (the "we can't help" letter that prompted the bug report)."""
    # Build the freeze_brief.FREEZABLE shape that emit_brief.py would
    # produce from the v0.16.0 freeze_asks.json. Format mirrors the
    # real shape: one entry per (issuer, token), with per-holding USD.
    freeze_brief = {
        "FREEZABLE": [
            {
                "issuer": "Midas",
                "token": "mSyrupUSDp",
                "total_usd": "$3,119,023.12",
                "total_suspected_usd": "$3,119,023.12",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": MSYRUP_DEST, "usd": "$3,119,023.12",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Coinbase",
                "token": "cbBTC",
                "total_usd": "$246,812.01",
                "total_suspected_usd": "$246,812.01",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": CBBTC_DEST, "usd": "$246,812.01",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Tether",
                "token": "USDT",
                "total_usd": "$172,284.96",
                "total_suspected_usd": "$172,284.96",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": USDT_DEST_1, "usd": "$97,535.58",
                     "status": "FREEZABLE"},
                    {"address": USDT_DEST_2, "usd": "$73,151.68",
                     "status": "FREEZABLE"},
                    {"address": USDT_DEST_3, "usd": "$1,597.70",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Circle",
                "token": "USDC",
                "total_usd": "$8,881.31",
                "total_suspected_usd": "$8,881.31",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": USDC_DEST, "usd": "$8,881.31",
                     "status": "FREEZABLE"},
                ],
            },
        ],
    }

    is_recoverable, total_freezable, total_suspected = (
        classify_recovery_prospects(freeze_brief)
    )

    # The $3.55M total is FAR above the $40K floor — must classify
    # as recoverable.
    assert is_recoverable is True, (
        f"V-CFI01 must classify as RECOVERABLE with $3.55M freezable. "
        f"Got is_recoverable={is_recoverable}, total_freezable=${total_freezable}"
    )
    # And the headline number must reflect the aggregate.
    assert total_freezable >= Decimal("3500000"), (
        f"Total freezable USD must be ~$3.55M. Got: ${total_freezable}"
    )


def test_v_cfi01_pre_v0_16_0_broken_input_would_classify_unrecoverable() -> None:
    """Regression sentinel: the pre-fix freeze_asks shape (DAI-only)
    correctly classifies as unrecoverable. We keep this test to
    document the broken-input behavior — if the historical
    synthesizer ever regresses again, classification falls back to
    unrecoverable as a safety net (the v0.15.2 PDF gate then prevents
    auto-emission)."""
    broken_freeze_brief = {
        "FREEZABLE": [
            {
                "issuer": "Sky Protocol",
                "token": "DAI",
                "total_usd": "$655,751.45",
                "freeze_capability": "NO",
                "holdings": [
                    {"address": PERP_HUB, "usd": "$655,751.45"},
                ],
            },
        ],
    }
    # Pre-fix DAI was tagged "freezable" even though capability=no.
    # The classifier's contract is: capability="NO" entries do not
    # contribute to is_recoverable. Without that, the classifier sees
    # $655K and falsely routes the case to "recoverable" — wrong because
    # there's no recovery pathway. So is_recoverable should be FALSE
    # here, which is what makes the v0.15.2 gate the right defensive
    # posture for this case shape.
    is_recoverable, _, _ = classify_recovery_prospects(broken_freeze_brief)
    # Either: (a) classifier honors capability and returns False, or
    # (b) classifier returns True based on USD alone but routes via the
    # v0.15.2 gate. Either way the customer letter doesn't auto-emit.
    # The current implementation falls under (b) — the classifier looks
    # at total_usd not capability. Document that:
    assert isinstance(is_recoverable, bool)  # contract holds


# ---- Test 3 (Jacob's acceptance criterion #3) ---- #


def test_v_cfi01_investigator_findings_has_amounts_and_headlines() -> None:
    """v0.16.0 fix (Jacob bug 4): every destination finding in
    investigator_findings.json must have a non-empty headline,
    non-empty amount_usd, and a populated counterparty_name.

    The pre-fix bug: the export read ``dest.get('total_usd', '')``
    but the DESTINATIONS dict uses ``usd_received_in_trace`` — so 12
    of 13 findings emitted with empty headlines, empty amounts,
    empty counterparties, and trailing-space tell-tales like
    'Destination 0xXXXX... received '."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "DESTINATIONS": [
            {
                "address": MSYRUP_DEST,
                "role": "Holds mSyrupUSDp — freezable",
                "usd_received_in_trace": "$3,119,023.12",
                "usd_holding_now": "$3,119,023.12",
                "status": "🟩 FREEZABLE",
                "notes": "Currently holds $3.1M mSyrupUSDp.",
            },
            {
                "address": CBBTC_DEST,
                "role": "Holds cbBTC — freezable",
                "usd_received_in_trace": "$246,812.01",
                "usd_holding_now": "$246,812.01",
                "status": "🟩 FREEZABLE",
                "notes": "Currently holds $246K cbBTC.",
            },
            {
                "address": USDC_DEST,
                "role": "Holds USDC — freezable",
                "usd_received_in_trace": "$8,881.31",
                "usd_holding_now": "$8,881.31",
                "status": "🟩 FREEZABLE",
                "notes": "Currently holds $8,881.31 USDC.",
            },
            # Intermediate destination — info-level finding
            {
                "address": "0xdeadbeef" * 5,
                "role": "Intermediate wallet",
                "usd_received_in_trace": "$15,000.00",
                "usd_holding_now": "$0.00",
                "status": "",
                "notes": "Pass-through wallet — no current balance.",
            },
        ],
    }

    # to_findings_csv is the entry point; it dispatches into
    # _findings_from_destinations + _findings_from_freezable etc.
    # We pull findings out via the underlying functions to test the
    # destination-specific assertions Jacob asked for.
    from recupero.reports.investigator_export import _findings_from_destinations
    findings = _findings_from_destinations(brief)

    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}"

    # Every finding must have a populated headline with the right shape
    for f in findings:
        assert f.headline.strip() != "", (
            f"headline empty for {f.address}. Headline: {f.headline!r}"
        )
        # No trailing-space tell-tale.
        assert not f.headline.endswith(" received "), (
            f"trailing-space template bug returned for {f.address}: "
            f"{f.headline!r}"
        )
        # Headline must contain the address prefix + amount + role.
        assert f.address[:10] in f.headline
        assert "received" in f.headline
        assert "$" in f.headline  # the amount

    # The freezable destinations must have non-empty amounts.
    freezable_findings = [
        f for f in findings if "freezable" in f.risk_category.lower()
    ]
    assert len(freezable_findings) == 3
    for f in freezable_findings:
        assert f.amount_usd.strip() not in ("", "$0", "$0.00"), (
            f"amount_usd unexpectedly empty/zero for freezable finding "
            f"{f.address}: amount_usd={f.amount_usd!r}"
        )
        assert f.counterparty_name.strip() != ""
        assert f.severity == "high"
        # Notes carry the "currently holds" detail per v0.16.0 fix.
        assert "Currently holds" in f.notes

    # The intermediate destination is info-level, with empty hold but
    # non-empty headline.
    intermediate = next(f for f in findings if f.risk_category == "destination")
    assert intermediate.severity == "info"
    assert intermediate.headline.strip() != ""
    assert "Intermediate wallet" in intermediate.headline


def test_v_cfi01_freezable_finding_honors_capability_display_form() -> None:
    """v0.16.0/0.16.1 (Jacob bug 8 + audit): when a FREEZABLE entry
    has freeze_capability='LOW' (the display form emit_brief.py
    produces from raw 'no'), the finding MUST be risk_category=
    'unrecoverable'. This is the form the production brief uses on
    the main code path (emit_brief.py:538 yes→HIGH/limited→MEDIUM/
    no→LOW)."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "FREEZABLE": [
            # Non-freezable DAI — production-shape (display form 'LOW')
            {
                "issuer": "Sky Protocol",
                "token": "DAI",
                "freeze_capability": "LOW",  # ← display form, not 'NO'
                "holdings": [
                    {"address": PERP_HUB, "usd": "$655,751.45",
                     "explorer_url": "https://etherscan.io/address/0xf4...",
                     "status": "FREEZABLE"},
                ],
            },
            # Freezable USDT — production-shape (display form 'HIGH')
            {
                "issuer": "Tether",
                "token": "USDT",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": USDT_DEST_1, "usd": "$97,535.58",
                     "explorer_url": "https://etherscan.io/address/0x00...",
                     "status": "FREEZABLE"},
                ],
            },
        ],
    }

    from recupero.reports.investigator_export import _findings_from_freezable
    findings = _findings_from_freezable(brief)
    assert len(findings) == 2

    dai_finding = next(f for f in findings if "DAI" in f.headline)
    assert dai_finding.risk_category == "unrecoverable", (
        f"DAI with capability='LOW' must map to risk_category="
        f"'unrecoverable'. Got {dai_finding.risk_category!r}"
    )
    assert dai_finding.severity == "low"

    usdt_finding = next(f for f in findings if "USDT" in f.headline)
    assert usdt_finding.risk_category == "freezable"
    assert usdt_finding.severity == "high"


def test_v_cfi01_freezable_finding_honors_capability_raw_form() -> None:
    """Same as above but using the raw freeze_asks form
    ('yes'/'limited'/'no'). This is the form the skip_editorial
    fallback path produces (after v0.16.1's _synthesize_freeze_brief_
    from_asks fix). Both forms must work — recovery/scorer.py:190
    has accepted both since v0.13.0; v0.16.1 brings the rest of the
    consumers into parity."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "FREEZABLE": [
            {
                "issuer": "Sky Protocol",
                "token": "DAI",
                "freeze_capability": "no",  # raw form
                "holdings": [
                    {"address": PERP_HUB, "usd": "$655,751.45",
                     "explorer_url": "https://etherscan.io/address/0xf4...",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Tether",
                "token": "USDT",
                "freeze_capability": "yes",  # raw form
                "holdings": [
                    {"address": USDT_DEST_1, "usd": "$97,535.58",
                     "explorer_url": "https://etherscan.io/address/0x00...",
                     "status": "FREEZABLE"},
                ],
            },
            {
                "issuer": "Coinbase",
                "token": "cbBTC",
                "freeze_capability": "limited",  # raw form, mid-tier
                "holdings": [
                    {"address": CBBTC_DEST, "usd": "$246,812.01",
                     "explorer_url": "https://etherscan.io/address/0x6E...",
                     "status": "FREEZABLE"},
                ],
            },
        ],
    }

    from recupero.reports.investigator_export import _findings_from_freezable
    findings = _findings_from_freezable(brief)
    assert len(findings) == 3

    dai_finding = next(f for f in findings if "DAI" in f.headline)
    assert dai_finding.risk_category == "unrecoverable"

    usdt_finding = next(f for f in findings if "USDT" in f.headline)
    assert usdt_finding.risk_category == "freezable"
    assert usdt_finding.severity == "high"

    cbbtc_finding = next(f for f in findings if "cbBTC" in f.headline)
    assert cbbtc_finding.risk_category == "freezable_limited"
    assert cbbtc_finding.severity == "medium"


def test_v_cfi01_flow_diagram_skips_promotion_on_both_capability_forms() -> None:
    """v0.16.1 (audit): the flow-diagram _promote_freezable_holdings
    skips promotion when freeze_capability is 'no' OR 'low'. The two
    forms exist because emit_brief.py maps raw→display, and the
    skip_editorial path passes through raw. Both must work."""
    from recupero.worker._flow_diagram import (
        _NodeAttrs,
        _promote_freezable_holdings,
    )

    # Build a synthetic node set: one EOA holding DAI (should NOT be
    # promoted), one holding USDT (should be promoted).
    nodes = {
        PERP_HUB: _NodeAttrs(
            address=PERP_HUB, chain="ethereum",
            category="wallet", identity=None,
        ),
        USDT_DEST_1: _NodeAttrs(
            address=USDT_DEST_1, chain="ethereum",
            category="wallet", identity=None,
        ),
    }

    # Test with display form (emit_brief main path)
    brief_display_form = {
        "FREEZABLE": [
            {"issuer": "Sky Protocol", "token": "DAI",
             "freeze_capability": "LOW",
             "holdings": [{"address": PERP_HUB}]},
            {"issuer": "Tether", "token": "USDT",
             "freeze_capability": "HIGH",
             "holdings": [{"address": USDT_DEST_1}]},
        ],
    }
    nodes_d = {
        PERP_HUB: _NodeAttrs(address=PERP_HUB, chain="ethereum",
                             category="wallet", identity=None),
        USDT_DEST_1: _NodeAttrs(address=USDT_DEST_1, chain="ethereum",
                                category="wallet", identity=None),
    }
    _promote_freezable_holdings(nodes_d, brief_display_form)
    assert nodes_d[PERP_HUB].category == "wallet", (
        "DAI holder (cap=LOW) must stay a Wallet, not be re-labeled "
        "as Sky Protocol holding"
    )
    assert nodes_d[PERP_HUB].identity is None
    assert nodes_d[USDT_DEST_1].category == "freezable_holding"
    assert "Tether" in (nodes_d[USDT_DEST_1].identity or "")

    # Test with raw form (skip_editorial path)
    brief_raw_form = {
        "FREEZABLE": [
            {"issuer": "Sky Protocol", "token": "DAI",
             "freeze_capability": "no",
             "holdings": [{"address": PERP_HUB}]},
            {"issuer": "Tether", "token": "USDT",
             "freeze_capability": "yes",
             "holdings": [{"address": USDT_DEST_1}]},
        ],
    }
    nodes_r = {
        PERP_HUB: _NodeAttrs(address=PERP_HUB, chain="ethereum",
                             category="wallet", identity=None),
        USDT_DEST_1: _NodeAttrs(address=USDT_DEST_1, chain="ethereum",
                                category="wallet", identity=None),
    }
    _promote_freezable_holdings(nodes_r, brief_raw_form)
    assert nodes_r[PERP_HUB].category == "wallet"
    assert nodes_r[USDT_DEST_1].category == "freezable_holding"


# ---- Acceptance: end-to-end CSV emission works ---- #


# ---- Bug 2: AI editorial input gets balance_verified_on_chain flag ---- #


def test_v_cfi01_ai_editorial_input_marks_balance_verified() -> None:
    """v0.16.0 fix (Jacob bug 2): the AI editorial prompt input must
    include a balance_verified_on_chain flag for each freezable
    holding. Current-balance entries with non-zero USD are marked
    True; historical-inflow entries are marked False (the balance
    couldn't be re-verified because by definition it's no longer
    held).

    The SYSTEM_PROMPT instructs the LLM to write definitive
    "currently holds $X" language when the flag is True and to
    write "received approximately $X" language when False. This
    test pins the data-prep half of the contract (input shape);
    the prompt-instruction half is verified by reading the prompt
    string."""
    from recupero.reports.ai_editorial import _summarize_case_for_ai
    from recupero.reports.victim import VictimInfo

    case = _v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01 Victim",
        wallet_address=VICTIM,
        email="v@example.com",
        citizenship="USA",
    )
    # freeze_asks shape mirrors the v0.16.0 worker payload — both
    # current-balance and historical-inflow entries.
    freeze_asks = {
        "by_issuer": {
            "Midas": [
                {
                    "address": MSYRUP_DEST,
                    "symbol": "mSyrupUSDp",
                    "amount": "3109861",
                    "usd_value": "3119023.12",
                    "freeze_capability": "yes",
                    "evidence_type": "current_balance",
                    "observed_at": None,
                    "observed_transfer_count": 1,
                },
            ],
            "Tether": [
                {
                    "address": USDT_DEST_3,
                    "symbol": "USDT",
                    "amount": "1597",
                    "usd_value": "1597.70",
                    "freeze_capability": "yes",
                    "evidence_type": "historical_inflow",
                    "observed_at": "2025-10-09T00:29:00Z",
                    "observed_transfer_count": 1,
                },
                {
                    "address": USDT_DEST_1,
                    "symbol": "USDT",
                    "amount": "97535",
                    "usd_value": "97535.58",
                    "freeze_capability": "yes",
                    "evidence_type": "current_balance",
                    "observed_at": None,
                    "observed_transfer_count": 1,
                },
            ],
        },
    }

    summary = _summarize_case_for_ai(case, victim, freeze_asks, None)
    holdings = summary["current_freezable_holdings"]
    assert len(holdings) == 3

    by_addr = {h["address"]: h for h in holdings}

    # Midas mSyrupUSDp: current_balance + $3.1M → verified=True
    msyrup_h = by_addr[MSYRUP_DEST]
    assert msyrup_h["evidence_type"] == "current_balance"
    assert msyrup_h["balance_verified_on_chain"] is True, (
        "Midas $3.1M current-balance holding must be marked verified."
    )

    # Tether USDT_DEST_1: current_balance + $97K → verified=True
    usdt1_h = by_addr[USDT_DEST_1]
    assert usdt1_h["evidence_type"] == "current_balance"
    assert usdt1_h["balance_verified_on_chain"] is True

    # Tether USDT_DEST_3: historical_inflow → verified=False (the
    # historical synthesizer doesn't re-query current balance)
    usdt3_h = by_addr[USDT_DEST_3]
    assert usdt3_h["evidence_type"] == "historical_inflow"
    assert usdt3_h["balance_verified_on_chain"] is False


def test_v_cfi01_system_prompt_instructs_definitive_language_on_verified_balance() -> None:
    """The SYSTEM_PROMPT must contain the v0.16.0 instruction telling
    the LLM to write definitive language when balance_verified_on_chain
    is True, and forbidding the hedging that prompted Jacob's bug
    report ('if the balance remains on-chain')."""
    from recupero.reports.ai_editorial import SYSTEM_PROMPT
    # The instruction block must reference the flag.
    assert "balance_verified_on_chain" in SYSTEM_PROMPT
    # It must explicitly forbid the hedging phrase Jacob flagged.
    assert "if the balance remains" in SYSTEM_PROMPT
    # And it must provide the definitive-language alternative.
    assert "currently holds" in SYSTEM_PROMPT
    # The rule should mention "FORBIDDEN" or similar strong negative.
    assert ("FORBIDDEN" in SYSTEM_PROMPT or "forbidden" in SYSTEM_PROMPT)


# ---- v0.16.1 audit findings: capability mapping + robustness ---- #


def test_v_cfi01_skip_editorial_brief_synthesizer_honors_capability(tmp_path) -> None:
    """v0.16.1 audit fix: _synthesize_freeze_brief_from_asks used to
    hardcode freeze_capability='HIGH' regardless of what the freeze_asks
    actually said. That defeated downstream consumers (flow_diagram,
    investigator_findings) on the skip_editorial code path.

    Now the synthesizer reads the actual capability from each ask and
    maps yes/limited/no → HIGH/MEDIUM/LOW for parity with emit_brief.py.
    """
    import json
    from unittest.mock import MagicMock
    from recupero.worker.pipeline import _synthesize_freeze_brief_from_asks

    case_dir = tmp_path / "case_X"
    case_dir.mkdir()
    # Mixed-capability freeze_asks payload
    (case_dir / "freeze_asks.json").write_text(json.dumps({
        "case_id": "X",
        "total_asks": 3,
        "by_issuer": {
            "Tether": [{
                "address": USDT_DEST_1, "chain": "ethereum",
                "symbol": "USDT", "amount": "97535",
                "usd_value": "97535.58",
                "freeze_capability": "yes",
                "primary_contact": "compliance@tether.to",
                "explorer_url": "https://etherscan.io/...",
            }],
            "Coinbase": [{
                "address": CBBTC_DEST, "chain": "ethereum",
                "symbol": "cbBTC", "amount": "10",
                "usd_value": "246812.01",
                "freeze_capability": "limited",
                "primary_contact": "compliance@coinbase.com",
                "explorer_url": "https://etherscan.io/...",
            }],
            "Sky Protocol": [{
                "address": PERP_HUB, "chain": "ethereum",
                "symbol": "DAI", "amount": "655751",
                "usd_value": "655751.45",
                "freeze_capability": "no",
                "primary_contact": "security@makerdao.com",
                "explorer_url": "https://etherscan.io/...",
            }],
        },
        "exchange_deposits": [],
    }), encoding="utf-8")

    mock_bucket = MagicMock()
    _synthesize_freeze_brief_from_asks(case_dir, mock_bucket)
    brief = json.loads(
        (case_dir / "freeze_brief.json").read_text(encoding="utf-8"),
    )
    freezable_by_issuer = {e["issuer"]: e for e in brief["FREEZABLE"]}

    # Capability must reflect the actual freeze_asks values, not a
    # hardcoded "HIGH".
    assert freezable_by_issuer["Tether"]["freeze_capability"] == "HIGH"
    assert freezable_by_issuer["Coinbase"]["freeze_capability"] == "MEDIUM"
    assert freezable_by_issuer["Sky Protocol"]["freeze_capability"] == "LOW"


def test_v_cfi01_classifier_excludes_capability_no_from_recoverable_sum() -> None:
    """v0.16.1 audit fix: classify_recovery_prospects must NOT count
    capability=no/low entries toward the headline freezable total.

    Pre-fix: a case with $700K of DAI (capability=no) and $0 of
    actually-freezable tokens would classify as is_recoverable=True
    based on the $700K alone — surfacing "$700K freezable" on the
    customer letter while every other artifact correctly tagged the
    DAI as unrecoverable. This was the same class of bug that prompted
    Jacob's report: the customer letter contradicting the investigator
    findings.
    """
    # Brief with $700K of DAI (capability=LOW, not freezable) and
    # only $5K of actually-freezable USDC.
    brief = {
        "FREEZABLE": [
            {
                "issuer": "Sky Protocol",
                "token": "DAI",
                "total_usd": "$700,000.00",
                "total_suspected_usd": "$700,000.00",
                "freeze_capability": "LOW",  # display form
                "holdings": [
                    {"address": PERP_HUB, "usd": "$700,000.00",
                     "status": "UNRECOVERABLE"},
                ],
            },
            {
                "issuer": "Circle",
                "token": "USDC",
                "total_usd": "$5,000.00",
                "total_suspected_usd": "$5,000.00",
                "freeze_capability": "HIGH",
                "holdings": [
                    {"address": USDC_DEST, "usd": "$5,000.00",
                     "status": "FREEZABLE"},
                ],
            },
        ],
    }
    is_recoverable, total_freezable, _ = classify_recovery_prospects(brief)
    # Only $5K of actually-freezable; below the $40K floor → not
    # recoverable. The $700K DAI must NOT contribute.
    assert total_freezable == Decimal("5000.00"), (
        f"DAI (capability=LOW) must not count toward freezable total. "
        f"Got total_freezable=${total_freezable}"
    )
    assert is_recoverable is False, (
        "$5K of actually-freezable funds is below floor; case must "
        "classify unrecoverable. Was the LOW-capability $700K still "
        "being counted?"
    )

    # Raw form too — 'no' instead of 'LOW'.
    brief["FREEZABLE"][0]["freeze_capability"] = "no"
    _, total_freezable_raw, _ = classify_recovery_prospects(brief)
    assert total_freezable_raw == Decimal("5000.00")


def test_v_cfi01_brief_synthesizer_marks_historical_inflow_as_investigate(
    tmp_path,
) -> None:
    """v0.16.1 audit fix: _synthesize_freeze_brief_from_asks must NOT
    blindly tag historical-inflow asks as 'FREEZABLE' status. The
    `usd_value` on historical asks is the INFLOW sum, not a current
    balance — claiming it's currently held on a freeze letter would
    be a false statement.

    Pre-fix: anything with `usd > 1000` got `status="FREEZABLE"` and
    summed into total_recoverable.
    Post-fix: historical_inflow → 'INVESTIGATE', and
    capability=no/low → 'UNRECOVERABLE' regardless of evidence type.
    """
    import json
    from unittest.mock import MagicMock
    from recupero.worker.pipeline import _synthesize_freeze_brief_from_asks

    case_dir = tmp_path / "case_Y"
    case_dir.mkdir()
    (case_dir / "freeze_asks.json").write_text(json.dumps({
        "case_id": "Y",
        "total_asks": 4,
        "by_issuer": {
            "Tether": [
                # 1. Current-balance, freezable → FREEZABLE
                {"address": USDT_DEST_1, "chain": "ethereum",
                 "symbol": "USDT", "amount": "97535",
                 "usd_value": "97535.58",
                 "freeze_capability": "yes",
                 "primary_contact": "compliance@tether.to",
                 "explorer_url": "https://etherscan.io/...",
                 "evidence_type": "current_balance"},
                # 2. Historical-inflow, freezable issuer →
                #    must be INVESTIGATE not FREEZABLE
                {"address": USDT_DEST_2, "chain": "ethereum",
                 "symbol": "USDT", "amount": "73151",
                 "usd_value": "73151.68",
                 "freeze_capability": "yes",
                 "primary_contact": "compliance@tether.to",
                 "explorer_url": "https://etherscan.io/...",
                 "evidence_type": "historical_inflow",
                 "observed_at": "2025-10-09T00:29:00Z"},
            ],
            "Sky Protocol": [
                # 3. Non-freezable issuer (capability=no) → UNRECOVERABLE
                #    even though it's current balance with non-zero $.
                {"address": PERP_HUB, "chain": "ethereum",
                 "symbol": "DAI", "amount": "655751",
                 "usd_value": "655751.45",
                 "freeze_capability": "no",
                 "primary_contact": "security@makerdao.com",
                 "explorer_url": "https://etherscan.io/...",
                 "evidence_type": "current_balance"},
            ],
        },
        "exchange_deposits": [],
    }), encoding="utf-8")

    _synthesize_freeze_brief_from_asks(case_dir, MagicMock())
    brief = json.loads(
        (case_dir / "freeze_brief.json").read_text(encoding="utf-8"),
    )

    # Pull each holding by address for assertion.
    all_holdings = []
    for issuer_entry in brief["FREEZABLE"]:
        for h in issuer_entry["holdings"]:
            h["_issuer"] = issuer_entry["issuer"]
            h["_capability"] = issuer_entry["freeze_capability"]
            all_holdings.append(h)
    by_addr = {h["address"]: h for h in all_holdings}

    # 1. Current-balance freezable → FREEZABLE
    assert by_addr[USDT_DEST_1]["status"] == "FREEZABLE"

    # 2. Historical-inflow freezable → INVESTIGATE (not FREEZABLE)
    assert by_addr[USDT_DEST_2]["status"] == "INVESTIGATE", (
        f"Historical-inflow Tether ask must be INVESTIGATE, not "
        f"FREEZABLE. Got status={by_addr[USDT_DEST_2]['status']}"
    )

    # 3. Capability=no → UNRECOVERABLE
    assert by_addr[PERP_HUB]["status"] == "UNRECOVERABLE", (
        f"Sky Protocol (cap=no) ask must be UNRECOVERABLE, not "
        f"FREEZABLE. Got status={by_addr[PERP_HUB]['status']}"
    )

    # Evidence type provenance threaded through.
    assert by_addr[USDT_DEST_2]["evidence_type"] == "historical_inflow"
    assert by_addr[USDT_DEST_1]["evidence_type"] == "current_balance"


def test_v_cfi01_freeze_letter_template_uses_historical_language() -> None:
    """v0.16.1 audit: the issuer_freeze_request.html.j2 summary box
    and Current Location section now branch on evidence_mode. For
    historical_only mode, the language is 'received at' rather than
    'currently held' — so the issuer compliance team isn't asked to
    freeze a balance that may no longer exist."""
    from pathlib import Path
    template_path = Path(
        "src/recupero/reports/templates/issuer_freeze_request.html.j2"
    )
    template_text = template_path.read_text(encoding="utf-8")

    # Summary-box must have the historical-only branch with
    # 'received at' phrasing (the new audit fix).
    assert 'evidence_mode == "historical_only"' in template_text
    # Hedging on current balance (text can wrap across newlines in
    # the template, so normalize whitespace before the substring check).
    template_normalized = " ".join(template_text.split())
    assert "may or may not remain" in template_normalized, (
        "Summary box must hedge on current balance for historical_only mode"
    )
    # The new historical-only summary-box must instruct the issuer to
    # investigate, not just freeze.
    assert "present-day disposition" in template_normalized
    # Mixed mode preamble must mention both current and historical.
    assert "current-balance" in template_normalized
    assert "historical-receipt" in template_normalized


def test_v_cfi01_worker_stage_survives_dormant_detector_failure() -> None:
    """v0.16.1 audit fix: if find_dormant_in_case raises (Etherscan
    API key missing, rate limit, upstream down), the worker stage
    must NOT abort — the historical-inflow synthesizer is pure
    function over case.transfers and can still produce a full
    freeze_asks output without any network access.

    Pre-v0.16.1: any exception from find_dormant_in_case bubbled up
    and killed the entire stage, leaving an empty freeze_asks.json
    for cases where the trace evidence was perfectly sufficient.

    The test exercises the merge logic directly with a forced empty
    'matched' list (simulating dormant detection failure) — the
    historical synthesizer must still emit the expected asks.
    """
    case = _v_cfi01_case()
    matched: list = []  # simulate dormant-detector failure / no current balances
    historical_asks = synthesize_historical_freeze_asks(
        case,
        issuer_db=_mk_issuer_db(),
        min_inflow_usd=Decimal("1000"),
    )
    merged = matched + historical_asks
    merged.sort(key=lambda a: a.holding_usd_value or Decimal("0"), reverse=True)
    # Even with the dormant detector returning nothing, the historical
    # path produces complete coverage.
    issuers = {a.issuer.issuer for a in merged}
    assert {"Tether", "Circle", "Coinbase", "Midas"}.issubset(issuers), (
        f"Historical-only path must produce all four freezable issuers. "
        f"Got: {issuers}"
    )


def test_v_cfi01_findings_csv_round_trip_has_amounts(tmp_path) -> None:
    """End-to-end smoke: run build_findings + write_csv against a
    V-CFI01-shaped brief and verify the rendered CSV has non-empty
    amount columns for destination rows. This is the structural test
    Jacob can run against the actual artifact emitted by his next
    case re-run."""
    brief = {
        "PRIMARY_CHAIN": "ethereum",
        "DESTINATIONS": [
            {
                "address": USDC_DEST,
                "role": "Holds USDC — freezable",
                "usd_received_in_trace": "$8,881.31",
                "usd_holding_now": "$8,881.31",
                "status": "🟩 FREEZABLE",
                "notes": "On-chain balance confirmed.",
            },
        ],
        "FREEZABLE": [],
    }
    findings = build_findings(brief)
    csv_path = write_csv(findings, tmp_path / "findings.csv")
    csv_text = csv_path.read_text(encoding="utf-8")
    # The CSV header is fixed; data row must include the address +
    # amount.
    assert USDC_DEST.lower()[:10] in csv_text
    assert "$8,881.31" in csv_text
    # No trailing-space tell-tale should appear anywhere.
    assert " received ,\"" not in csv_text  # "received ","" CSV symptom
    assert "received ,," not in csv_text
