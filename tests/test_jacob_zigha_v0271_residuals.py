"""Lock the v0.27.1 Zigha review fixes (Jacob, item 1 / 0x52Aa bleed).

Pins five contracts so a future revert is caught immediately:

  1. INVESTIGATE-tagged addresses do NOT appear in freeze_request_*.html
     or le_handoff_*.html as FREEZABLE rows. The smart-contract
     reflective-liquidity bleed (0x52Aa…e497 on Zigha v0.27.1, four
     issuers, $145M total) is the canonical example.

  2. `_has_freezable_holding` requires at least one FREEZABLE-status
     holding. An issuer entry whose every holding is INVESTIGATE
     (BitGo + Threshold on Zigha v0.27.1) does NOT generate a letter.

  3. `_compute_perpetrator_holdings` sums FREEZABLE + UNRECOVERABLE
     only — NOT INVESTIGATE. The Zigha trace-report headline of
     $149,954,529.44 (21.6× inflation over the real $3.5M FREEZABLE
     + $4.4M UNRECOVERABLE = ~$7.9M) was the symptom of the regression.

  4. The freeze_asks builder drops "(none — canonical wrapper)"
     pseudo-issuer entries (WETH path). WETH holdings still appear in
     trace_report.html and investigator_findings.{csv,json}; they
     just are not freeze asks.

  5. INVARIANT A (validator):
     `freeze_ask_targets_not_investigate_tagged` catches a regression
     at output time. Companion to INVARIANT
     `issuer_letter_backed_by_freezable_row` (no $0 FREEZABLE letters).

These tests run against synthetic fixtures so they're fast (no DB,
no network) and they pin the contract independent of any specific
case shape. The actual Zigha ground-truth test (item B from the
v0.27.1 review) lives in test_zigha_ground_truth.py (step 4).
"""

from __future__ import annotations

from decimal import Decimal


# ─────────────────────────────────────────────────────────────────────
# Item 2: _has_freezable_holding
# ─────────────────────────────────────────────────────────────────────


def test_has_freezable_holding_true_when_freezable_row_present() -> None:
    from recupero.worker._deliverables import _has_freezable_holding
    entry = {
        "issuer": "Tether",
        "holdings": [
            {"address": "0x" + "a" * 40, "status": "FREEZABLE",
             "usd": "$245,000"},
            {"address": "0x" + "b" * 40, "status": "INVESTIGATE",
             "usd": "$65,000,000"},
        ],
    }
    assert _has_freezable_holding(entry) is True


def test_has_freezable_holding_false_when_only_investigate() -> None:
    """BitGo / Threshold Zigha v0.27.1 shape: every holding is the
    0x52Aa bleed (INVESTIGATE). No legitimate freeze ask exists for
    this issuer; the letter must NOT be generated."""
    from recupero.worker._deliverables import _has_freezable_holding
    entry = {
        "issuer": "BitGo",
        "holdings": [
            {"address": "0x52Aa899454998Be5b000Ad077a46Bbe360F4e497",
             "status": "INVESTIGATE", "usd": "$46,762,084.33"},
        ],
    }
    assert _has_freezable_holding(entry) is False


def test_has_freezable_holding_false_when_only_unrecoverable() -> None:
    """An issuer whose every holding is UNRECOVERABLE (e.g., Sky
    Protocol / DAI staking) gets no letter. This was the v0.21.x
    contract too; preserved here so the rename doesn't break it."""
    from recupero.worker._deliverables import _has_freezable_holding
    entry = {
        "issuer": "Sky Protocol",
        "holdings": [
            {"address": "0x" + "c" * 40, "status": "UNRECOVERABLE",
             "usd": "$655,000"},
        ],
    }
    assert _has_freezable_holding(entry) is False


def test_has_freezable_holding_false_when_holdings_empty() -> None:
    from recupero.worker._deliverables import _has_freezable_holding
    assert _has_freezable_holding({"issuer": "X", "holdings": []}) is False
    assert _has_freezable_holding({"issuer": "X"}) is False


def test_has_freezable_holding_false_on_malformed_input() -> None:
    """Adversarial-input audit: dict-with-non-list-holdings.
    Defensive: return False, don't crash."""
    from recupero.worker._deliverables import _has_freezable_holding
    assert _has_freezable_holding({"holdings": "not-a-list"}) is False
    assert _has_freezable_holding({"holdings": [{"status": None}]}) is False


def test_has_freezable_holding_status_is_case_insensitive() -> None:
    """Defense-in-depth: the canonical spec is 'FREEZABLE' (uppercase)
    but the source case-folds via .upper() so a lowercase writer
    (legacy R&D path) still gets the correct True classification."""
    from recupero.worker._deliverables import _has_freezable_holding
    assert _has_freezable_holding(
        {"holdings": [{"status": "freezable"}]}
    ) is True
    assert _has_freezable_holding(
        {"holdings": [{"status": "Freezable"}]}
    ) is True


def test_old_name_is_alias_for_back_compat() -> None:
    """`_has_actionable_holding` was renamed to `_has_freezable_holding`
    in v0.27.2. Keep the old name as an alias for one release window
    so any external/script callers don't break."""
    from recupero.worker._deliverables import (
        _has_actionable_holding,
        _has_freezable_holding,
    )
    assert _has_actionable_holding is _has_freezable_holding


# ─────────────────────────────────────────────────────────────────────
# Item 3: _compute_perpetrator_holdings excludes INVESTIGATE
# ─────────────────────────────────────────────────────────────────────


def test_perpetrator_holdings_excludes_investigate() -> None:
    """Zigha v0.27.1 symptom: trace-report headline at $149.9M
    (21.6× over the real $3.5M FREEZABLE). Root cause:
    _compute_perpetrator_holdings was summing FREEZABLE +
    INVESTIGATE. INVESTIGATE here was $145M of 1inch/Uniswap pool
    reflective liquidity, not perpetrator-controlled."""
    from recupero.reports.emit_brief import _compute_perpetrator_holdings
    freezable = [
        {
            "issuer": "Tether",
            "total_usd": "$245,000",
            "total_suspected_usd": "$65,000,000",  # the bleed
            "holdings": [
                {"address": "0x" + "a" * 40, "status": "FREEZABLE",
                 "usd": "$245,000"},
            ],
        },
        {
            "issuer": "BitGo",
            "total_usd": "$0",
            "total_suspected_usd": "$46,762,084",  # bleed-only
            "holdings": [
                {"address": "0x52Aa899454998Be5b000Ad077a46Bbe360F4e497",
                 "status": "INVESTIGATE", "usd": "$46,762,084"},
            ],
        },
    ]
    unrecoverable: list[dict] = []
    out = _compute_perpetrator_holdings(freezable, unrecoverable)
    # Expected: $245,000 FREEZABLE only. No INVESTIGATE.
    assert out == Decimal("245000"), (
        f"Expected $245,000 (FREEZABLE only); got ${out}. "
        "INVESTIGATE balances must NOT be in perpetrator-controlled "
        "holdings — they're leads, not confirmed."
    )


def test_perpetrator_holdings_includes_unrecoverable() -> None:
    """UNRECOVERABLE holdings (Sky DAI etc.) ARE perpetrator-
    controlled; they're just not issuer-freezable. They belong in
    this headline."""
    from recupero.reports.emit_brief import _compute_perpetrator_holdings
    freezable = [
        {
            "issuer": "Sky Protocol",
            "total_usd": "$0",
            "total_suspected_usd": "$0",
            "holdings": [
                {"address": "0x" + "c" * 40, "status": "UNRECOVERABLE",
                 "usd": "$655,751.45"},
            ],
        },
    ]
    unrecoverable: list[dict] = []
    out = _compute_perpetrator_holdings(freezable, unrecoverable)
    assert out == Decimal("655751.45")


def test_perpetrator_holdings_dedups_unrecoverable_sources() -> None:
    """The same UNRECOVERABLE holding can appear in BOTH the
    editorial UNRECOVERABLE_ITEMS list AND in a per-issuer entry's
    holdings array. De-dup on (issuer, address) so it's counted once."""
    from recupero.reports.emit_brief import _compute_perpetrator_holdings
    addr = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
    freezable = [
        {
            "issuer": "Sky Protocol",
            "total_usd": "$0",
            "holdings": [
                {"address": addr, "status": "UNRECOVERABLE",
                 "usd": "$655,751.45"},
            ],
        },
    ]
    unrecoverable = [
        {
            "issuer": "Sky Protocol",
            "address": addr,
            "asset": "$655,751.45 DAI at Sky Protocol",
        },
    ]
    out = _compute_perpetrator_holdings(freezable, unrecoverable)
    # NOT $1,311,502.90 — single $655,751.45 counted once.
    assert out == Decimal("655751.45")


# ─────────────────────────────────────────────────────────────────────
# Item 5: INVARIANT A — freeze-ask targets not INVESTIGATE-tagged
# ─────────────────────────────────────────────────────────────────────


def test_invariant_a_passes_when_no_investigate_in_letter(tmp_path) -> None:
    """Clean V-CFI01-shape letter: every FREEZABLE row's address is
    NOT in DESTINATION_NOTES with 🟧. Validator returns no
    violations."""
    from recupero.validators.output_integrity import (
        _check_freeze_ask_targets_not_investigate_tagged,
    )
    briefs = tmp_path / "briefs"
    briefs.mkdir()
    freezable_html = """
    <html><body>
    <table class="evidence">
    <tbody>
      <tr><td><span class="label-pill" style="color:#2F6B3E;">FREEZABLE</span></td>
          <td><a href="https://etherscan.io/address/0xAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">0xAa…aa</a></td></tr>
    </tbody>
    </table>
    </body></html>
    """
    (briefs / "freeze_request_tether_BRIEF-X.html").write_text(
        freezable_html, encoding="utf-8",
    )
    freeze_brief = {
        "DESTINATION_NOTES": {
            "0xAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
                "🟩 FREEZABLE — Confirmed Tether-held position",
        },
    }
    out = _check_freeze_ask_targets_not_investigate_tagged(briefs, freeze_brief)
    assert out == []


def test_invariant_a_fires_on_investigate_freeze_ask_target(tmp_path) -> None:
    """Zigha v0.27.1 0x52Aa shape: address renders as a FREEZABLE row
    in the freeze letter but the brief's DESTINATION_NOTES tags it
    🟧 INVESTIGATE. High-severity violation."""
    from recupero.validators.output_integrity import (
        _check_freeze_ask_targets_not_investigate_tagged,
    )
    briefs = tmp_path / "briefs"
    briefs.mkdir()
    bleed_addr = "0x52Aa899454998Be5b000Ad077a46Bbe360F4e497"
    bleed_html = f"""
    <html><body>
    <table class="evidence">
    <tbody>
      <tr><td><span class="label-pill" style="color:#2F6B3E;">FREEZABLE</span></td>
          <td><a href="https://etherscan.io/address/{bleed_addr}">0x52Aa…e497</a></td></tr>
    </tbody>
    </table>
    </body></html>
    """
    (briefs / "freeze_request_tether_BRIEF-X.html").write_text(
        bleed_html, encoding="utf-8",
    )
    freeze_brief = {
        "DESTINATION_NOTES": {
            bleed_addr:
                "🟧 INVESTIGATE — smart contract reflecting protocol "
                "liquidity; not plausibly perpetrator-controlled",
        },
    }
    out = _check_freeze_ask_targets_not_investigate_tagged(briefs, freeze_brief)
    assert len(out) == 1
    assert out[0].severity == "high"
    assert out[0].check == "freeze_ask_targets_not_investigate_tagged"
    assert bleed_addr.lower() in out[0].detail.lower() or "0x52aa" in out[0].detail.lower()


def test_invariant_a_canonical_address_match(tmp_path) -> None:
    """Address in DESTINATION_NOTES may be mixed-case (operator
    paste from etherscan); the letter HTML renders the on-chain
    display form. INVARIANT A must match canonical keys."""
    from recupero.validators.output_integrity import (
        _check_freeze_ask_targets_not_investigate_tagged,
    )
    briefs = tmp_path / "briefs"
    briefs.mkdir()
    # DESTINATION_NOTES key is mixed-case checksum
    checksum_addr = "0x52Aa899454998Be5b000Ad077a46Bbe360F4e497"
    # The letter renders the lowercase form
    lowercase_addr = checksum_addr.lower()
    (briefs / "le_handoff_tether_BRIEF-X.html").write_text(
        f"""<table class="evidence"><tbody>
        <tr><td><span>FREEZABLE</span></td>
            <td><a href="https://etherscan.io/address/{lowercase_addr}">{lowercase_addr}</a></td></tr>
        </tbody></table>""",
        encoding="utf-8",
    )
    freeze_brief = {
        "DESTINATION_NOTES": {checksum_addr: "🟧 INVESTIGATE — bleed"},
    }
    out = _check_freeze_ask_targets_not_investigate_tagged(briefs, freeze_brief)
    assert len(out) == 1, (
        "Canonical-key match failed: mixed-case DESTINATION_NOTES key "
        "did not match lowercase letter HTML."
    )


# ─────────────────────────────────────────────────────────────────────
# Item 5b: INVARIANT issuer_letter_backed_by_freezable_row
# ─────────────────────────────────────────────────────────────────────


def test_invariant_letter_must_have_freezable_row(tmp_path) -> None:
    """Zigha v0.27.1 BitGo / Threshold shape: letter shipped with $0
    FREEZABLE — section 6 read 'the 0 FREEZABLE addresses are the
    primary targets.' Critical violation."""
    from recupero.validators.output_integrity import (
        _check_issuer_letter_backed_by_freezable_row,
    )
    briefs = tmp_path / "briefs"
    briefs.mkdir()
    no_freezable_html = """
    <table class="evidence"><tbody>
      <tr><td><span>INVESTIGATE</span></td><td>0x52Aa…e497</td></tr>
    </tbody></table>
    """
    (briefs / "freeze_request_bitgo_BRIEF-X.html").write_text(
        no_freezable_html, encoding="utf-8",
    )
    out = _check_issuer_letter_backed_by_freezable_row(briefs, None)
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert "freeze_request_bitgo" in out[0].file


def test_invariant_letter_passes_with_freezable_row(tmp_path) -> None:
    from recupero.validators.output_integrity import (
        _check_issuer_letter_backed_by_freezable_row,
    )
    briefs = tmp_path / "briefs"
    briefs.mkdir()
    good_html = """
    <table class="evidence"><tbody>
      <tr><td><span>FREEZABLE</span></td><td>0xAa…aa</td></tr>
    </tbody></table>
    """
    (briefs / "freeze_request_tether_BRIEF-X.html").write_text(
        good_html, encoding="utf-8",
    )
    out = _check_issuer_letter_backed_by_freezable_row(briefs, None)
    assert out == []


# ─────────────────────────────────────────────────────────────────────
# Item 4: freeze_asks canonical-wrapper exclusion (WETH)
# ─────────────────────────────────────────────────────────────────────


def test_match_freeze_asks_skips_canonical_wrapper_issuer() -> None:
    """A holding matched to the WETH "(none — canonical wrapper)"
    pseudo-issuer must NOT produce a FreezeAsk. WETH has no real
    issuer freeze pathway; the holding's value still surfaces in
    trace_report and investigator_findings."""
    from decimal import Decimal as _D

    from recupero.dormant.finder import DormantCandidate, TokenHolding
    from recupero.freeze.asks import IssuerEntry, match_freeze_asks
    from recupero.models import Chain, TokenRef

    weth = TokenRef(
        chain=Chain.ethereum,
        contract="0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        symbol="WETH",
        decimals=18,
    )
    candidate = DormantCandidate(
        address="0x" + "9" * 40,
        chain=Chain.ethereum,
        total_usd=_D("250000"),
        holdings=[
            TokenHolding(
                token=weth,
                raw_amount=10**20,  # 100 WETH
                decimal_amount=_D("100"),
                usd_value=_D("250000"),
            ),
        ],
        explorer_url=None,
    )
    # Synthetic issuer_db carrying the canonical-wrapper sentinel
    canon_key = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".lower()
    db = {
        (Chain.ethereum, canon_key): IssuerEntry(
            chain=Chain.ethereum,
            contract=canon_key,
            symbol="WETH",
            issuer="(none — canonical wrapper)",
            freeze_capability="no",
            freeze_notes="WETH is a canonical wrapper contract for ETH...",
            primary_contact=None,
            secondary_contact=None,
            jurisdiction="decentralized",
        ),
    }
    matched, unmatched = match_freeze_asks(
        [candidate], issuer_db=db, min_holding_usd=_D("1000"),
    )
    assert matched == [], (
        "WETH-via-canonical-wrapper should NOT produce a FreezeAsk; "
        f"got {len(matched)} match(es): {matched}"
    )


def test_match_freeze_asks_still_emits_real_issuers() -> None:
    """Anti-regression: the canonical-wrapper filter must not over-
    reach. A legitimate Tether/Circle/Coinbase issuer is emitted as
    normal."""
    from decimal import Decimal as _D

    from recupero.dormant.finder import DormantCandidate, TokenHolding
    from recupero.freeze.asks import IssuerEntry, match_freeze_asks
    from recupero.models import Chain, TokenRef

    usdt = TokenRef(
        chain=Chain.ethereum,
        contract="0xdac17f958d2ee523a2206206994597c13d831ec7",
        symbol="USDT",
        decimals=6,
    )
    candidate = DormantCandidate(
        address="0x" + "8" * 40,
        chain=Chain.ethereum,
        total_usd=_D("245000"),
        holdings=[
            TokenHolding(
                token=usdt, raw_amount=245000 * 10**6,
                decimal_amount=_D("245000"), usd_value=_D("245000"),
            ),
        ],
        explorer_url=None,
    )
    canon_key = "0xdac17f958d2ee523a2206206994597c13d831ec7".lower()
    db = {
        (Chain.ethereum, canon_key): IssuerEntry(
            chain=Chain.ethereum, contract=canon_key, symbol="USDT",
            issuer="Tether", freeze_capability="yes",
            freeze_notes="Tether retains freeze auth.",
            primary_contact="compliance@tether.to",
            secondary_contact=None, jurisdiction="British Virgin Islands",
        ),
    }
    matched, _ = match_freeze_asks(
        [candidate], issuer_db=db, min_holding_usd=_D("1000"),
    )
    assert len(matched) == 1
    assert matched[0].issuer.issuer == "Tether"
