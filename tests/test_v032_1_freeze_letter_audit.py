"""Tests for v0.32.1 freeze-letter audit closures.

Closes 6 CRITs + 11 HIGHs from
docs/JACOB_FREEZE_LETTER_AUDIT_v032.md:

  CRIT-FR-1 — subject line + salutation
  CRIT-FR-2 — corporate legal entity name
  CRIT-FR-3 — legal-posture disclaimer
  CRIT-FR-4 — freeze_notes surfaced
  CRIT-ST-1 — AUSA-signature-required gate
  CRIT-ST-2 — corporate-entity correctness on CEX targets
  CRIT-EL-1 — recovery-rate disclosure in engagement letter
  HIGH-FR-1 — regulatory framework rendered for non-Midas issuers
  HIGH-FR-2 — Coinbase cbBTC KYC asymmetry
  HIGH-FR-3 — reference number for reply tracking
  HIGH-FR-6 — empty contact_email defensive
  HIGH-ST-1 — § 3486 → FRCrimP 17(c)
  HIGH-ST-2 — tx_hash + chain in subpoena evidence
  HIGH-LE-1 — LE handoff uses corporate legal name (via CRIT-FR-2)
  HIGH-LE-2 — LE handoff issuer jurisdiction populated (via HIGH-FR-1)
  HIGH-EL-2 — freeze-letter-send timestamp tracking
  HIGH-EL-3 — governing-law consumer-fairness language
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.freeze.asks import load_issuer_db
from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.brief import (
    InvestigatorInfo,
    IssuerInfo,
    generate_briefs,
)
from recupero.reports.victim import VictimInfo
from recupero.worker._deliverables import _issuer_info_for
from recupero.worker._engagement_letter import render_engagement_letter

# ---------- CRIT-FR-2 + HIGH-FR-1: issuers.json carries legal entity ---------- #


def test_issuer_db_carries_legal_name_for_tether() -> None:
    """CRIT-FR-2 closure: USDT issuer.legal_name resolves to 'Tether
    Operations Limited' (BVI) — the corporate entity, not the bare
    short tag."""
    db = load_issuer_db()
    usdt = db.get((Chain.ethereum, "0xdac17f958d2ee523a2206206994597c13d831ec7"))
    assert usdt is not None, "USDT ETH must be in seed DB"
    assert usdt.legal_name == "Tether Operations Limited"
    assert usdt.corporate_jurisdiction is not None
    assert "British Virgin Islands" in usdt.corporate_jurisdiction


def test_issuer_db_carries_legal_name_for_circle() -> None:
    """CRIT-FR-2: USDC issuer.legal_name is 'Circle Internet Group,
    Inc.' — the post-IPO renamed entity."""
    db = load_issuer_db()
    usdc = db.get((Chain.ethereum, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"))
    assert usdc is not None
    assert usdc.legal_name == "Circle Internet Group, Inc."


def test_issuer_db_carries_legal_name_for_coinbase_cbbtc() -> None:
    """CRIT-FR-2: cbBTC legal_name is the NYDFS-chartered trust co,
    NOT the operating sub 'Coinbase, Inc.'."""
    db = load_issuer_db()
    cbbtc = db.get((Chain.ethereum, "0xcbb7c0006f23900c38eb856149f799620fcb8a4a"))
    assert cbbtc is not None
    assert cbbtc.legal_name == "Coinbase Custody Trust Company, LLC"


def test_issuer_db_carries_legal_name_for_paxos() -> None:
    """CRIT-FR-2: BUSD / PYUSD / USDP all addressed to the NYDFS trust."""
    db = load_issuer_db()
    busd = db.get((Chain.ethereum, "0x4fabb145d64652a948d72533023f6e7a623c7c53"))
    assert busd is not None
    assert busd.legal_name == "Paxos Trust Company, LLC"


# ---------- _issuer_info_for surfaces the legal entity ---------- #


def test_issuer_info_for_uses_legal_name_when_present() -> None:
    """CRIT-FR-2: _issuer_info_for returns IssuerInfo.name = corporate
    legal entity when freezable_entry carries `legal_name`."""
    entry = {
        "issuer": "Tether",
        "contact_email": "compliance@tether.to",
        "legal_name": "Tether Operations Limited",
        "corporate_jurisdiction": "British Virgin Islands",
        "freeze_notes": "Tether has frozen billions in USDT…",
        "issuer_jurisdiction": "British Virgin Islands",
    }
    info = _issuer_info_for("Tether", entry)
    assert info.name == "Tether Operations Limited"
    assert info.short_name == "Tether"  # prose flow stays readable
    assert info.jurisdiction == "British Virgin Islands"
    assert info.regulatory_framework == "British Virgin Islands"
    # CRIT-FR-4: freeze_notes surfaced
    assert info.freeze_notes is not None
    assert "billions" in info.freeze_notes


def test_issuer_info_for_falls_back_to_short_tag_without_legal_name() -> None:
    """Backward compat: an old freeze_brief.json without legal_name
    falls back to the bare short tag (no crash, no missing data)."""
    entry = {
        "issuer": "SomeNewIssuer",
        "contact_email": "compliance@example.com",
    }
    info = _issuer_info_for("SomeNewIssuer", entry)
    assert info.name == "SomeNewIssuer"
    assert info.jurisdiction is None
    assert info.freeze_notes is None


def test_issuer_info_for_coinbase_kyc_required() -> None:
    """HIGH-FR-2: Coinbase cbBTC sets kyc_required=True so the
    KYC-asymmetry block renders for that issuer (not just Midas)."""
    entry = {
        "issuer": "Coinbase",
        "contact_email": "subpoenas@coinbase.com",
        "legal_name": "Coinbase Custody Trust Company, LLC",
    }
    info = _issuer_info_for("Coinbase", entry)
    assert info.kyc_required is True
    assert info.kyc_minimum is not None


# ---------- Freeze letter template — rendered HTML ---------- #


def _circle_freeze_brief_entry_with_seed() -> dict:
    """v0.32.1: same shape as test_per_issuer_freeze_letter, but
    populated with legal_name + freeze_notes (post-v0.32.1 schema)."""
    return {
        "issuer": "Circle",
        "token": "USDC",
        "total_usd": "$7,097.58",
        "total_suspected_usd": "$1,037,451.35",
        "freeze_capability": "HIGH",
        "holdings": [
            {
                "address": "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A",
                "amount": "6031.31 USDC",
                "usd": "$6,031.31",
                "status": "FREEZABLE",
            },
        ],
        "contact_email": "compliance@circle.com",
        "legal_name": "Circle Internet Group, Inc.",
        "corporate_jurisdiction": "United States (New York; MTL + BitLicense)",
        "freeze_notes": "Circle has demonstrated freeze capability via blacklist on multiple occasions.",
    }


def _make_case() -> Case:
    return Case(
        case_id="test-v032-1",
        seed_address="0x" + "1" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 2, tzinfo=UTC),
        transfers=[Transfer(
            transfer_id="ethereum:0xtheft:0",
            chain=Chain.ethereum,
            tx_hash="0x" + "f" * 64,
            block_number=12345,
            block_time=datetime(2026, 1, 2, tzinfo=UTC),
            from_address="0x" + "1" * 40,
            to_address="0x" + "2" * 40,
            counterparty=Counterparty(
                address="0x" + "2" * 40, label=None, is_contract=False,
            ),
            token=TokenRef(
                chain=Chain.ethereum, contract=None, symbol="ETH",
                decimals=18, coingecko_id="ethereum",
            ),
            amount_raw="1000000000000000000",
            amount_decimal=Decimal("1"),
            usd_value_at_tx=Decimal("3000"),
            hop_depth=0,
            fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=UTC),
            explorer_url="https://etherscan.io/tx/0xtheft",
        )],
        trace_started_at=datetime(2026, 1, 2, tzinfo=UTC),
        software_version="test",
    )


def _victim() -> VictimInfo:
    return VictimInfo(
        name="Jane Doe",
        wallet_address="0x" + "1" * 40,
        citizenship="USA",
    )


def _investigator() -> InvestigatorInfo:
    return InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )


def test_freeze_letter_has_subject_line_and_salutation() -> None:
    """CRIT-FR-1: 'RE:' subject + 'Dear ... Compliance Team,'
    salutation rendered above Section 1."""
    issuer = IssuerInfo(
        name="Circle Internet Group, Inc.",
        short_name="Circle",
        contact_email="compliance@circle.com",
    )
    with TemporaryDirectory() as tmp:
        bundle = generate_briefs(
            primary_case=_make_case(), linked_cases=[],
            victim=_victim(), investigator=_investigator(),
            case_dir=Path(tmp), issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry_with_seed(),
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    # Subject line keyed on the issuer's letter triage routing.
    assert "RE:" in html, "missing 'RE:' subject line"
    assert "URGENT" in html, "subject line should be urgent-flagged"
    assert "Dear Circle Compliance Team," in html, "missing salutation"
    # HIGH-FR-3: reference number for reply tracking.
    assert "Please quote reference" in html
    assert "case" in html.lower()


def test_freeze_letter_has_legal_posture_disclaimer() -> None:
    """CRIT-FR-3: explicit 'not a law firm / not a subpoena' footer
    paragraph above the brand footer."""
    issuer = IssuerInfo(
        name="Circle Internet Group, Inc.",
        short_name="Circle",
        contact_email="compliance@circle.com",
    )
    with TemporaryDirectory() as tmp:
        bundle = generate_briefs(
            primary_case=_make_case(), linked_cases=[],
            victim=_victim(), investigator=_investigator(),
            case_dir=Path(tmp), issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry_with_seed(),
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    assert "investigation service, not a law firm" in html
    assert "voluntary compliance request" in html
    assert "NOT a subpoena" in html


def test_freeze_letter_renders_freeze_notes_when_present() -> None:
    """CRIT-FR-4: issuer.freeze_notes from the seed DB renders as a
    quoted paragraph in Section 6 of the freeze letter."""
    issuer = IssuerInfo(
        name="Circle Internet Group, Inc.",
        short_name="Circle",
        contact_email="compliance@circle.com",
        regulatory_framework="United States",
        freeze_notes="Circle has demonstrated freeze capability via blacklist.",
    )
    with TemporaryDirectory() as tmp:
        bundle = generate_briefs(
            primary_case=_make_case(), linked_cases=[],
            victim=_victim(), investigator=_investigator(),
            case_dir=Path(tmp), issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry_with_seed(),
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    assert "Freeze Posture" in html or "freeze-posture" in html.lower()
    assert "demonstrated freeze capability" in html


def test_freeze_letter_renders_regulatory_framework_for_non_midas() -> None:
    """HIGH-FR-1: Section 6 renders regulatory_framework even when
    issuer.kyc_required is False (pre-v0.32.1 only the Midas letter
    showed this section)."""
    issuer = IssuerInfo(
        name="Tether Operations Limited",
        short_name="Tether",
        contact_email="compliance@tether.to",
        regulatory_framework="British Virgin Islands",
    )
    with TemporaryDirectory() as tmp:
        bundle = generate_briefs(
            primary_case=_make_case(), linked_cases=[],
            victim=_victim(), investigator=_investigator(),
            case_dir=Path(tmp), issuer=issuer,
            issuer_freezable={
                "issuer": "Tether",
                "token": "USDT",
                "total_usd": "$5,000.00",
                "total_suspected_usd": "$0.00",
                "freeze_capability": "HIGH",
                "holdings": [{
                    "address": "0x" + "3" * 40, "amount": "5000 USDT",
                    "usd": "$5,000.00", "status": "FREEZABLE",
                }],
                "contact_email": "compliance@tether.to",
            },
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    assert "British Virgin Islands" in html


def test_freeze_letter_legal_entity_in_addressed_to_block() -> None:
    """CRIT-FR-2: 'Addressed To' cover-meta shows the corporate legal
    entity, not the bare short tag."""
    issuer = IssuerInfo(
        name="Tether Operations Limited",  # corporate legal entity
        short_name="Tether",
        contact_email="compliance@tether.to",
    )
    with TemporaryDirectory() as tmp:
        bundle = generate_briefs(
            primary_case=_make_case(), linked_cases=[],
            victim=_victim(), investigator=_investigator(),
            case_dir=Path(tmp), issuer=issuer,
            issuer_freezable={
                "issuer": "Tether",
                "token": "USDT",
                "total_usd": "$5,000.00",
                "total_suspected_usd": "$0.00",
                "freeze_capability": "HIGH",
                "holdings": [{
                    "address": "0x" + "3" * 40, "amount": "5000 USDT",
                    "usd": "$5,000.00", "status": "FREEZABLE",
                }],
                "contact_email": "compliance@tether.to",
            },
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    assert "Tether Operations Limited" in html


# ---------- Subpoena target template ---------- #


def test_subpoena_target_has_ausa_gate() -> None:
    """CRIT-ST-1: explicit 'DO NOT SERVE WITHOUT AUSA SIGNATURE'
    banner at top + footer of the subpoena_target template."""
    from jinja2 import (
        Environment,
        FileSystemLoader,
        select_autoescape,
    )

    from recupero.reports._jinja_filters import register_safe_filters

    env = Environment(
        loader=FileSystemLoader(
            str(Path(__file__).parent.parent / "src" / "recupero"
                / "reports" / "templates")
        ),
        autoescape=select_autoescape(["html", "j2"]),
    )
    register_safe_filters(env)
    html = env.get_template("subpoena_target.html.j2").render(
        case_id="C-1",
        generated_at="2026-05-28",
        victim={"name": "Jane Doe"},
        investigator={"name": "Alec", "organization": "Recupero LLC",
                      "email": "alec@recupero.io"},
        target={
            "target_id": "subpoena-1",
            "recipient_name": "Binance Holdings Limited",
            "recipient_jurisdiction": "Cayman Islands",
            "recipient_type": "cex",
            "recipient_compliance_email": "leinquiries@binance.com",
            "priority": "high",
            "evidentiary_basis": "off_ramp_deposit",
            "estimated_response_window_days": 21,
            "linked_addresses": [{
                "address": "0x" + "a" * 40,
                "chain": "ethereum",
                "role": "off-ramp deposit (perpetrator-owned)",
                "evidence": [{
                    "amount_usd": "5000.00",
                    "label_source": "label_db",
                    "tx_hashes": ["0x" + "f" * 64],
                    "first_observed_at": "2026-01-02",
                    "last_observed_at": "2026-01-03",
                    "transfer_count": 3,
                }],
            }],
            "expected_records": ["KYC", "IP logs"],
            "follow_up_pivots": [],
            "instrument": "grand_jury_subpoena",
            "depends_on": [],
        },
    )
    assert "DO NOT SERVE WITHOUT AUSA SIGNATURE" in html
    # HIGH-ST-1: Rule 17(c) cite, not § 3486
    assert "Federal Rule of Criminal Procedure 17(c)" in html
    # HIGH-ST-2: tx_hash + transfer_count rendered
    assert "0x" + "f" * 64 in html
    assert "across 3 on-chain transfer" in html


def test_subpoena_targets_legal_entity_resolutions() -> None:
    """CRIT-ST-2: Coinbase / Binance / Gemini resolve to the right
    corporate entities in the CEX compliance map."""
    from recupero.reports.subpoena_targets import _KNOWN_CEX_COMPLIANCE
    assert _KNOWN_CEX_COMPLIANCE["binance"][0] == "Binance Holdings Limited"
    assert _KNOWN_CEX_COMPLIANCE["coinbase"][0] == "Coinbase, Inc."
    assert _KNOWN_CEX_COMPLIANCE["gemini"][0] == "Gemini Trust Company, LLC"


# ---------- Engagement letter CRIT-EL-1 ---------- #


def test_engagement_letter_includes_recovery_disclosure_industry_baseline() -> None:
    """CRIT-EL-1: when the case sample is < 30 (or DSN unset), the
    contract names the Chainalysis 3%/7% industry baseline."""
    case = Case(
        case_id="test-eng-1",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[Transfer(
            transfer_id="ethereum:0x:0",
            chain=Chain.ethereum,
            tx_hash="0x" + "f" * 64,
            block_number=1,
            block_time=datetime(2026, 1, 2, tzinfo=UTC),
            from_address="0x" + "a" * 40,
            to_address="0x" + "b" * 40,
            counterparty=Counterparty(
                address="0x" + "b" * 40, label=None, is_contract=False,
            ),
            token=TokenRef(
                chain=Chain.ethereum, contract=None, symbol="ETH",
                decimals=18, coingecko_id="ethereum",
            ),
            amount_raw="1000000000000000000",
            amount_decimal=Decimal("1"),
            usd_value_at_tx=Decimal("3000"),
            hop_depth=0,
            fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=UTC),
            explorer_url="https://etherscan.io/tx/0x",
        )],
        trace_started_at=datetime(2026, 1, 2, tzinfo=UTC),
        software_version="test",
    )
    victim = VictimInfo(
        name="Jane Doe",
        email="jane@example.com",
        wallet_address="0x" + "a" * 40,
        citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )
    freeze_brief = {"FREEZABLE": [{
        "issuer": "Circle", "token": "USDC",
        "total_usd": "$5,000.00",
        "total_suspected_usd": "$0.00",
        "freeze_capability": "HIGH",
        "holdings": [{
            "address": "0x" + "c" * 40, "amount": "5000 USDC",
            "usd": "$5,000.00", "status": "FREEZABLE",
        }],
    }]}
    with TemporaryDirectory() as tmp:
        # Empty DSN forces industry-baseline path.
        path = render_engagement_letter(
            case=case, victim=victim, investigator=investigator,
            freeze_brief=freeze_brief, briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("5000.00"),
            total_suspected_usd=Decimal("0.00"),
            recovery_stats_dsn="",  # empty → industry baseline
        )
        assert path is not None
        html = path.read_text(encoding="utf-8")

    # CRIT-EL-1: the disclosure language is in the binding contract.
    assert "Recovery-rate disclosure" in html
    assert "3%" in html or "industry baseline" in html.lower()
    # MED-EL-1: investigator attestation block
    assert "Investigator Attestation" in html
    # HIGH-EL-2: letter-send notification commitment
    assert "Letter-send notification" in html or "send-notification" in html
    # HIGH-EL-3: consumer-fairness language
    assert "consumer-protection rights" in html or "opt out" in html
