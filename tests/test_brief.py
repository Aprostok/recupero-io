"""Tests for the brief generator."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from recupero.models import (
    Case, Chain, Counterparty, Label, LabelCategory, TokenRef, Transfer,
)
from recupero.reports.brief import (
    InvestigatorInfo, IssuerInfo, MIDAS_ISSUER, generate_briefs,
    _build_hops, _find_theft_transfer,
)
from recupero.reports.victim import VictimInfo, load_victim, write_victim


VICTIM = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP1 = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
PERP2 = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"
TOKEN_CONTRACT = "0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50"


def _now():
    return datetime(2025, 10, 9, 1, 13, 47, tzinfo=timezone.utc)


def _msyrup() -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum, contract=TOKEN_CONTRACT,
        symbol="msyrupUSDp", decimals=18, coingecko_id="midas-msyrupusdp",
    )


def _label(name: str, cat: LabelCategory, addr: str) -> Label:
    return Label(
        address=addr, name=name, category=cat, source="test",
        confidence="high", added_at=_now(),
    )


def _transfer(
    *, from_addr: str, to_addr: str, amount: Decimal, usd: Decimal | None,
    block: int, tx_hash: str, label: Label | None = None,
) -> Transfer:
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum, tx_hash=tx_hash, block_number=block,
        block_time=datetime.fromtimestamp(1759972427 + block, tz=timezone.utc),
        from_address=from_addr, to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=label, is_contract=False),
        token=_msyrup(),
        amount_raw=str(int(amount * Decimal(10**18))),
        amount_decimal=amount,
        usd_value_at_tx=usd, hop_depth=0,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _victim_case() -> Case:
    """Mimics ZIGHA-VERIFY: theft from victim to perp1."""
    return Case(
        case_id="ZIGHA-VERIFY", seed_address=VICTIM, chain=Chain.ethereum,
        incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
        transfers=[
            _transfer(
                from_addr=VICTIM, to_addr=PERP1,
                amount=Decimal("3109861.71576"), usd=Decimal("3119023.12"),
                block=23537860, tx_hash="0x7a2d99bf",
                label=_label("ZIGHA Perpetrator (primary)", LabelCategory.perpetrator, PERP1),
            ),
        ],
    )


def _perp_case() -> Case:
    """Mimics ZIGHA-PERP-HOP1: perp1 forwards to perp2."""
    return Case(
        case_id="ZIGHA-PERP-HOP1", seed_address=PERP1, chain=Chain.ethereum,
        incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
        transfers=[
            _transfer(
                from_addr=PERP1, to_addr=PERP2,
                amount=Decimal("3109861.71576"), usd=Decimal("3119023.12"),
                block=23538020, tx_hash="0x4197d990",
            ),
            _transfer(
                from_addr=PERP1, to_addr="0xother",
                amount=Decimal("23.5"), usd=Decimal("71278.69"),
                block=23538100, tx_hash="0x7482dcd1",
            ),
        ],
    )


class TestVictim:
    def test_round_trip(self, tmp_path: Path):
        v = VictimInfo(name="Test", wallet_address=VICTIM, email="a@b.c")
        write_victim(tmp_path, v)
        loaded = load_victim(tmp_path)
        assert loaded.name == "Test"
        assert loaded.wallet_address == VICTIM
        assert loaded.email == "a@b.c"


class TestBriefHelpers:
    def test_find_theft_transfer_picks_largest_usd(self):
        case = _perp_case()
        theft = _find_theft_transfer(case)
        assert theft is not None
        assert theft.tx_hash == "0x4197d990"  # the $3.1M, not the $71k

    def test_build_hops_walks_forward(self):
        primary = _victim_case()
        linked = [_perp_case()]
        theft = _find_theft_transfer(primary)
        hops = _build_hops(theft, linked)
        # The theft went to PERP1; PERP1 forwarded to PERP2
        assert len(hops) == 1
        assert hops[0].from_address == PERP1
        assert hops[0].to_address == PERP2

    def test_build_hops_returns_empty_when_no_forward(self):
        primary = _victim_case()
        theft = _find_theft_transfer(primary)
        hops = _build_hops(theft, [])
        assert hops == []


class TestGenerateBriefs:
    def test_renders_both_briefs(self, tmp_path: Path):
        case_dir = tmp_path / "ZIGHA-VERIFY"
        case_dir.mkdir(parents=True)
        victim = VictimInfo(
            name="Ibrahim Zigha", citizenship="France",
            address="32, Rue Godillot, 93400 France",
            email="snowkombat@gmail.com",
            wallet_address=VICTIM,
            incident_summary="Theft on 2025-10-09.",
        )
        bundle = generate_briefs(
            primary_case=_victim_case(),
            linked_cases=[_perp_case()],
            victim=victim,
            investigator=InvestigatorInfo(
                name="Test Investigator", organization="Recupero",
                email="test@recupero.example",
            ),
            case_dir=case_dir,
            outbound_count_of_stolen_asset=0,
        )
        # Both files exist
        assert bundle.maple_path.exists()
        assert bundle.le_path.exists()
        assert bundle.manifest_path.exists()

        # Filename now reflects Midas as issuer, not "maple"
        assert "freeze_request_midas" in bundle.maple_path.name

        # Content sanity — Midas-targeted
        maple = bundle.maple_html
        assert "Ibrahim Zigha" in maple
        assert "snowkombat@gmail.com" in maple
        assert PERP1 in maple
        assert PERP2 in maple   # current holder shown
        assert "msyrupUSDp" in maple
        assert "3,109,861.71576" in maple
        assert "Midas Software GmbH" in maple
        assert "Maple Finance" in maple   # cited as secondary party
        assert "team@midas.app" in maple
        assert "voluntarily" in maple.lower() or "freeze" in maple.lower()
        # KYC asymmetry section should appear because MIDAS_ISSUER.kyc_required=True
        assert "KYC" in maple

        le = bundle.le_html
        assert "Ibrahim Zigha" in le
        assert "France" in le
        assert "Law Enforcement Handoff Package" in le
        assert "Recommended Actions" in le
        assert "Midas" in le
        # France + Germany triggers EU coordination paragraph
        assert "BaFin" in le or "OCLCTIC" in le or "MiCA" in le

    def test_brief_handles_no_linked_cases(self, tmp_path: Path):
        """If only the victim's case exists (no forwarding traced yet), still generate."""
        case_dir = tmp_path / "case"
        case_dir.mkdir(parents=True)
        victim = VictimInfo(name="X", wallet_address=VICTIM)
        bundle = generate_briefs(
            primary_case=_victim_case(),
            linked_cases=[],
            victim=victim,
            investigator=InvestigatorInfo(
                name="X", organization="Y", email="z@a.b",
            ),
            case_dir=case_dir,
        )
        # Current holder defaults to the theft's destination (perp1) when no hops
        assert PERP1 in bundle.maple_html
        # And the LE doc still renders without errors
        assert bundle.le_path.exists()

    def test_custom_issuer_overrides_default(self, tmp_path: Path):
        """A different IssuerInfo should fully override the Midas default."""
        case_dir = tmp_path / "custom"
        case_dir.mkdir(parents=True)
        custom = IssuerInfo(
            name="ExampleProtocol Inc",
            short_name="ExampleProtocol",
            contact_email="legal@example.com",
            jurisdiction="Switzerland",
            kyc_required=False,
        )
        bundle = generate_briefs(
            primary_case=_victim_case(),
            linked_cases=[],
            victim=VictimInfo(name="V", wallet_address=VICTIM),
            investigator=InvestigatorInfo(
                name="X", organization="Y", email="z@a.b",
            ),
            case_dir=case_dir,
            issuer=custom,
        )
        # Filename uses custom slug
        assert "freeze_request_exampleprotocol" in bundle.maple_path.name
        # No KYC section because kyc_required=False
        assert "ExampleProtocol Inc" in bundle.maple_html
        assert "Switzerland" in bundle.maple_html
        # Should NOT mention Midas anywhere
        assert "Midas" not in bundle.maple_html
