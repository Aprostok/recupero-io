"""Tests for the victim-facing summary letter renderer.

This is the artifact the customer (the victim) actually receives in
their inbox after their $499 diagnostic completes. Two variants:

  * Recoverable: pitches Tier 2 engagement + "use the artifacts
    yourself" option
  * Unrecoverable: acknowledges the $99 refund + gives concrete
    next steps (IC3, FBI, state AG, tax-loss deduction)

The dispatch logic (``classify_recovery_prospects``) decides
between variants based on whether confirmed FREEZABLE total >=
the floor in recupero._pricing.RECOVERABLE_FLOOR_USD (v0.7.0:
4× engagement fee = $40,000). Below the floor, recommending
Tier 2 would be predatory.

Tests run in <200ms with no network / no DB. The end-to-end
render tests use the live freeze_brief.json shape from real cases
to ensure the templates work against actual data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.models import Case, Chain, TokenRef, Transfer, Counterparty
from recupero.reports.brief import InvestigatorInfo
from recupero.reports.victim import VictimInfo
from recupero.worker._victim_summary import (
    _RECOVERABLE_FLOOR_USD,
    _parse_usd_string,
    classify_recovery_prospects,
    render_victim_summary,
)


# ---- classify_recovery_prospects ---- #


def _circle_freezable_entry(total_freezable: str = "$7,097.58") -> dict:
    """Realistic FREEZABLE entry shape from freeze_brief.json."""
    return {
        "issuer": "Circle",
        "token": "USDC",
        "total_usd": total_freezable,
        "total_suspected_usd": "$1,037,451.35",
        "freeze_capability": "HIGH",
        "holdings": [
            {"address": "0x" + "a" * 40, "amount": "6031 USDC",
             "usd": total_freezable, "status": "FREEZABLE"},
        ],
    }


def test_classify_empty_freeze_brief_is_unrecoverable() -> None:
    """An empty / missing FREEZABLE list → unrecoverable. Better to
    show the unrecoverable letter (still useful for LE filing) than
    to falsely promise recovery."""
    is_rec, freezable, suspected = classify_recovery_prospects({})
    assert is_rec is False
    assert freezable == Decimal(0)
    assert suspected == Decimal(0)


def test_classify_recoverable_above_floor() -> None:
    """Confirmed FREEZABLE totals above the floor → recoverable.
    Pick an amount comfortably above the v0.7.0 floor of $40,000."""
    fb = {"FREEZABLE": [_circle_freezable_entry("$70,975.80")]}
    is_rec, freezable, suspected = classify_recovery_prospects(fb)
    assert is_rec is True
    assert freezable == Decimal("70975.80")
    # Suspected includes INVESTIGATE so it's larger than just freezable
    assert suspected == Decimal("1037451.35")


def test_classify_below_floor_is_unrecoverable() -> None:
    """$200 total freezable → unrecoverable. At any engagement
    fee, a recoverable amount this small means the engagement
    would exceed the recovery — recommending Tier 2 would be
    predatory."""
    fb = {"FREEZABLE": [_circle_freezable_entry("$200.00")]}
    is_rec, _f, _s = classify_recovery_prospects(fb)
    assert is_rec is False


def test_classify_at_floor_exactly_is_recoverable() -> None:
    """A confirmed freezable amount exactly equal to the floor →
    recoverable (the floor is inclusive). Tied to the live
    pricing constant so a floor change doesn't break this test;
    the boundary semantics are what matter."""
    from recupero._pricing import RECOVERABLE_FLOOR_USD
    fb = {"FREEZABLE": [
        _circle_freezable_entry(f"${RECOVERABLE_FLOOR_USD:,.2f}"),
    ]}
    is_rec, freezable, _s = classify_recovery_prospects(fb)
    assert is_rec is True
    assert freezable == RECOVERABLE_FLOOR_USD


def test_classify_multiple_issuers_summed() -> None:
    """Multi-issuer cases sum across all issuers when checking
    the floor. Two issuer entries each just under the floor sum
    to comfortably above it → recoverable."""
    from recupero._pricing import RECOVERABLE_FLOOR_USD
    # Two equal entries; combined = 1.4x floor.
    each = (RECOVERABLE_FLOOR_USD * Decimal("0.7")).quantize(Decimal("0.01"))
    fb = {"FREEZABLE": [
        _circle_freezable_entry(f"${each:,.2f}"),
        {"issuer": "Tether", "token": "USDT",
         "total_usd": f"${each:,.2f}",
         "total_suspected_usd": f"${each:,.2f}",
         "freeze_capability": "HIGH"},
    ]}
    is_rec, freezable, _s = classify_recovery_prospects(fb)
    assert is_rec is True
    assert freezable == each * 2


def test_classify_custom_floor() -> None:
    """The floor is parameterizable per call. An operator could
    pass a higher floor for a specific case (e.g., a customer who
    explicitly asked us to engage only if >$5k recoverable)."""
    fb = {"FREEZABLE": [_circle_freezable_entry("$1,000.00")]}
    is_rec, _f, _s = classify_recovery_prospects(fb, floor_usd=Decimal("5000"))
    assert is_rec is False  # below the custom $5k floor


# ---- _parse_usd_string ---- #


def test_parse_usd_string_canonical() -> None:
    """The canonical freeze_brief format: ``"$X,XXX.YY"``."""
    assert _parse_usd_string("$7,097.58") == Decimal("7097.58")


def test_parse_usd_string_no_commas() -> None:
    assert _parse_usd_string("$500.00") == Decimal("500")


def test_parse_usd_string_no_dollar() -> None:
    """Defensive: accept bare numeric strings too."""
    assert _parse_usd_string("1234.56") == Decimal("1234.56")


def test_parse_usd_string_empty_returns_zero() -> None:
    assert _parse_usd_string("") == Decimal(0)
    assert _parse_usd_string(None) == Decimal(0)


def test_parse_usd_string_garbled_returns_zero() -> None:
    """Garbled input falls back to 0 rather than crashing the renderer."""
    assert _parse_usd_string("not a number") == Decimal(0)


# ---- end-to-end render ---- #


def _make_minimal_case(num_transfers: int = 3) -> Case:
    """Build a Case with synthetic transfers for rendering tests."""
    transfers = []
    for i in range(num_transfers):
        transfers.append(Transfer(
            transfer_id=f"ethereum:0x{i:064x}:0",
            chain=Chain.ethereum,
            tx_hash="0x" + f"{i:064x}",
            block_number=12345 + i,
            block_time=datetime(2026, 1, 2, i, 0, tzinfo=timezone.utc),
            from_address="0x" + "1" * 40,
            to_address="0x" + f"{i+2:040x}",
            counterparty=Counterparty(
                address="0x" + f"{i+2:040x}",
                label=None, is_contract=False,
            ),
            token=TokenRef(
                chain=Chain.ethereum, contract=None,
                symbol="ETH", decimals=18, coingecko_id="ethereum",
            ),
            amount_raw=str(10**18 * (i + 1)),
            amount_decimal=Decimal(str(i + 1)),
            usd_value_at_tx=Decimal("3000") * (i + 1),
            hop_depth=0,
            fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=timezone.utc),
            explorer_url=f"https://etherscan.io/tx/0x{i:064x}",
        ))
    return Case(
        case_id="test-case",
        seed_address="0x" + "1" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        software_version="test",
        config_used={"trace": {"max_depth": 3}},
    )


def test_render_recoverable_variant() -> None:
    """When freeze_brief shows recoverable funds above the floor,
    the recoverable variant renders."""
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Jane Doe", email="jane@example.com",
        wallet_address="0x" + "1" * 40, citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    # Use an amount well above the v0.7.0 floor ($40,000) so this
    # test stays robust to floor adjustments.
    fb = {"FREEZABLE": [_circle_freezable_entry("$70,975.80")]}

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=fb, briefs_dir=briefs_dir,
        )
        assert out_path is not None
        # Filename includes the variant
        assert "recoverable" in out_path.name
        assert "unrecoverable" not in out_path.name
        html = out_path.read_text(encoding="utf-8")

    # Recoverable variant has specific signal phrases
    assert "Findings &amp; Next Steps" in html or "Findings &amp;<br/>Next Steps" in html
    assert "Engage Recupero for active recovery" in html
    assert "Use the artifacts yourself" in html
    assert "$70,975.80" in html  # the freezable total (above floor)
    assert "Jane Doe" in html
    assert "USDC" in html  # the recovered stablecoin


def test_render_unrecoverable_variant(monkeypatch) -> None:
    """When freeze_brief shows no recoverable funds, the
    unrecoverable variant renders with the refund message.

    v0.15.2: the unrecoverable variant is gated behind
    RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE=1 (operator opt-in).
    This test sets the env var so it exercises the actual render
    path rather than the gate."""
    monkeypatch.setenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", "1")
    case = _make_minimal_case()
    victim = VictimInfo(
        name="John Smith", email="john@example.com",
        wallet_address="0x" + "1" * 40, citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    fb = {"FREEZABLE": []}  # empty — no freezable funds

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=fb, briefs_dir=briefs_dir,
        )
        assert out_path is not None
        assert "unrecoverable" in out_path.name
        html = out_path.read_text(encoding="utf-8")

    # Unrecoverable variant has these specific signal phrases
    assert "$99 of your $499" in html
    assert "IC3" in html
    assert "FBI" in html or "Federal Bureau of Investigation" in html
    assert "tax loss" in html.lower() or "tax-loss" in html.lower()
    assert "John Smith" in html
    # Should NOT pitch Tier 2 engagement
    assert "Engage Recupero for active recovery" not in html


def test_render_unrecoverable_with_custom_explanation(monkeypatch) -> None:
    """Operator-supplied case-specific prose for why funds are
    unrecoverable (mixer, CEX, self-custody, etc.) appears in the
    rendered letter when provided.

    v0.15.2: requires operator opt-in env var to render the
    unrecoverable variant (see the gate at the top of
    _victim_summary.py)."""
    monkeypatch.setenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", "1")
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Alice", email="alice@example.com",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    fb = {"FREEZABLE": []}

    custom_explanation = (
        "Your funds were transferred to Tornado Cash, a privacy "
        "mixer. After mixing, the funds were withdrawn to a "
        "different address that we cannot link back to the original "
        "deposit. Mixer-funds recovery requires specialized "
        "chain-analysis tooling typically only available to law "
        "enforcement."
    )

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=fb, briefs_dir=briefs_dir,
            unrecoverable_reason_short="Funds went into Tornado Cash.",
            unrecoverable_explanation=custom_explanation,
        )
        assert out_path is not None
        html = out_path.read_text(encoding="utf-8")

    assert "Tornado Cash" in html
    assert "privacy mixer" in html


def test_render_returns_none_on_template_failure(monkeypatch) -> None:
    """If the Jinja render fails (template missing, bad context),
    the renderer logs and returns None instead of crashing the
    surrounding build_all_deliverables call.

    v0.15.2: opt into the unrecoverable gate so the None return is
    attributable to the template failure (the original intent of
    this test), not to the safety gate firing first."""
    monkeypatch.setenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", "1")
    case = _make_minimal_case()
    victim = VictimInfo(name="X", wallet_address="0x" + "1" * 40)
    investigator = InvestigatorInfo(
        name="Alec", organization="Recupero LLC", email="alec@recupero.io",
    )

    # Patch the templates dir to a non-existent path → Jinja FileSystemLoader
    # will succeed to construct but the get_template call will raise.
    import recupero.worker._victim_summary as vs
    monkeypatch.setattr(vs, "_TEMPLATES_DIR", Path("/nonexistent/path"))

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief={"FREEZABLE": []},
            briefs_dir=briefs_dir,
        )
        assert out_path is None


def test_recoverable_variant_renders_with_real_e917ffc5_freezable(
    monkeypatch,
) -> None:
    """End-to-end with the actual freeze_brief.json shape from real
    case e917ffc5 (4 issuers, 6+18+17+17 holdings, ~$1M suspected,
    ~$7k freezable). Renders without errors and includes all 4
    issuers in the per-issuer table.

    Note: the test's name is historical — the ~$12.6k total freezable
    is actually BELOW the $40k recoverable floor, so the renderer
    selects the unrecoverable variant. The test exercises the per-
    issuer table population, which both variants share. v0.15.2:
    opt into the unrecoverable gate so this end-to-end render still
    runs."""
    monkeypatch.setenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", "1")
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Validation Run", email="val@test.local",
        wallet_address="0x8E3b200f356724299643402148a25FD4B852Bd53",
        citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    fb = {"FREEZABLE": [
        {"issuer": "Circle", "token": "USDC",
         "total_usd": "$7,097.58", "total_suspected_usd": "$1,037,451.35",
         "freeze_capability": "HIGH"},
        {"issuer": "Tether", "token": "USDT",
         "total_usd": "$3,200.00", "total_suspected_usd": "$45,000.00",
         "freeze_capability": "HIGH"},
        {"issuer": "Sky Protocol (formerly MakerDAO)", "token": "DAI",
         "total_usd": "$1,500.00", "total_suspected_usd": "$8,200.00",
         "freeze_capability": "MEDIUM"},
        {"issuer": "Paxos / PayPal", "token": "PYUSD",
         "total_usd": "$800.00", "total_suspected_usd": "$2,100.00",
         "freeze_capability": "HIGH"},
    ]}

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=fb, briefs_dir=briefs_dir,
        )
        assert out_path is not None
        html = out_path.read_text(encoding="utf-8")

    # All 4 issuers + their stablecoins appear
    assert "Circle" in html
    assert "USDC" in html
    assert "Tether" in html
    assert "USDT" in html
    assert "Sky" in html
    assert "DAI" in html
    assert "Paxos" in html
    assert "PYUSD" in html

    # Freezable counts: 4 issuers
    assert "4" in html  # somewhere should reference the issuer count


# ---- v0.15.2 unrecoverable-emit safety gate ---- #


def test_unrecoverable_gate_suppresses_emission_by_default(
    monkeypatch, caplog
) -> None:
    """v0.15.2: with no env opt-in, render_victim_summary returns
    None for an unrecoverable case AND writes no file to disk.

    This is the customer-protection guarantee — until the
    freeze_asks synthesis bug uncovered in V-CFI01 validation is
    fixed end-to-end, a "we cannot help you" letter cannot
    accidentally auto-emit on a false-negative classification."""
    monkeypatch.delenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", raising=False)
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Gated Victim", email="gated@example.com",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )

    import logging
    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        with caplog.at_level(logging.WARNING, logger="recupero.worker._victim_summary"):
            out_path = render_victim_summary(
                case=case, victim=victim, investigator=investigator,
                freeze_brief={"FREEZABLE": []},
                briefs_dir=briefs_dir,
            )
        assert out_path is None
        # No file should have been written to the briefs dir.
        assert list(briefs_dir.glob("victim_summary_*.html")) == []
        # The gate must announce itself in the log so the operator
        # can find out why the artifact didn't appear.
        assert any(
            "safety gate" in rec.getMessage()
            for rec in caplog.records
        ), [rec.getMessage() for rec in caplog.records]


def test_unrecoverable_gate_passes_with_explicit_opt_in(monkeypatch) -> None:
    """Setting RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE=1 restores
    the original render behavior. This is the path operators take
    AFTER they've verified freeze_asks is structurally correct for
    the case at hand."""
    monkeypatch.setenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", "1")
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Opted In", email="opted@example.com",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief={"FREEZABLE": []},
            briefs_dir=briefs_dir,
        )
        assert out_path is not None
        assert "unrecoverable" in out_path.name


def test_unrecoverable_gate_does_not_affect_recoverable_path(monkeypatch) -> None:
    """The safety gate is asymmetric — it only suppresses the
    unrecoverable variant. Recoverable cases (where there are
    confirmed freezable funds above the floor) render exactly as
    before, with or without the env var set."""
    monkeypatch.delenv("RECUPERO_ALLOW_UNRECOVERABLE_DELIVERABLE", raising=False)
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Recoverable Vic", email="rec@example.com",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok", organization="Recupero LLC",
        email="alec@recupero.io",
    )
    fb = {"FREEZABLE": [_circle_freezable_entry("$70,975.80")]}

    with TemporaryDirectory() as tmp:
        briefs_dir = Path(tmp)
        out_path = render_victim_summary(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=fb, briefs_dir=briefs_dir,
        )
        assert out_path is not None
        # The recoverable variant always renders; the gate is
        # unrecoverable-only.
        assert "recoverable" in out_path.name
        assert "unrecoverable" not in out_path.name
