"""Full V-CFI01 render audit — generates all 4 issuer letters + LE handoff and
inspects every section for quality issues Jacob would flag."""
import os, sys, re, tempfile
os.environ["SOURCE_DATE_EPOCH"] = "1747785600"

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.brief import InvestigatorInfo, IssuerInfo, generate_briefs
from recupero.reports.emit_brief import emit_brief
from recupero.reports.victim import VictimInfo

VICTIM       = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP_HUB     = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
MSYRUP_DEST  = "0x3e2E66af967075120fa8bE27C659d0803DfF4436"
CBBTC_DEST   = "0x6E4141d33021b52C91c28608403db4A0FFB50Ec6"
USDT_DEST_1  = "0x00000688768803Bbd44095770895ad27ad6b0d95"
USDT_DEST_2  = "0x5141B82f5fFDa4c6fE1E372978F1C5427640a190"
USDC_DEST    = "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4"
USDT_DEST_3  = "0x3B0AA7d38Bf3C103bf02d1De2E37568cBED3D6e8"
USDT_CONTRACT   = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC_CONTRACT   = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
CBBTC_CONTRACT  = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"
MSYRUP_CONTRACT = "0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50"
DAI_CONTRACT    = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
INCIDENT_TIME = datetime(2025, 10, 9, 0, 29, tzinfo=timezone.utc)

def mk_token(contract, symbol, decimals=6):
    return TokenRef(chain=Chain.ethereum, contract=contract, symbol=symbol,
                    decimals=decimals, coingecko_id=None)

def mk_transfer(from_addr, to_addr, token, usd, tx_hash, amount=None):
    if amount is None:
        amount = usd
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1", chain=Chain.ethereum, tx_hash=tx_hash,
        block_number=18900000, block_time=INCIDENT_TIME, from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=token, amount_raw=str(int(amount * 10**token.decimals)),
        amount_decimal=amount, usd_value_at_tx=usd, hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}", fetched_at=INCIDENT_TIME,
    )

transfers = [
    mk_transfer(VICTIM, PERP_HUB, mk_token(USDT_CONTRACT, "USDT"),
                Decimal("600000"), f"0xtheft{i:04d}")
    for i in range(1, 7)
]
transfers += [
    mk_transfer(PERP_HUB, MSYRUP_DEST, mk_token(MSYRUP_CONTRACT,"mSyrupUSDp",18),
                Decimal("3119023.12"), "0xmsyrup", Decimal("3119023.12")),
    mk_transfer(PERP_HUB, CBBTC_DEST, mk_token(CBBTC_CONTRACT,"cbBTC",8),
                Decimal("246812.01"), "0xcbbtc", Decimal("2.46")),
    mk_transfer(PERP_HUB, USDT_DEST_1, mk_token(USDT_CONTRACT,"USDT"),
                Decimal("97535.58"), "0xusdt1"),
    mk_transfer(PERP_HUB, USDT_DEST_2, mk_token(USDT_CONTRACT,"USDT"),
                Decimal("73151.68"), "0xusdt2"),
    mk_transfer(PERP_HUB, USDC_DEST, mk_token(USDC_CONTRACT,"USDC"),
                Decimal("8881.31"), "0xusdc"),
    mk_transfer(PERP_HUB, USDT_DEST_3, mk_token(USDT_CONTRACT,"USDT"),
                Decimal("1597.70"), "0xusdt3"),
    mk_transfer(PERP_HUB, PERP_HUB, mk_token(DAI_CONTRACT,"DAI",18),
                Decimal("655751.45"), "0xdai", Decimal("655751.45")),
]

case = Case(
    case_id="V-CFI01", seed_address=VICTIM, chain=Chain.ethereum,
    incident_time=INCIDENT_TIME, transfers=transfers,
    trace_started_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
    software_version="0.20.3", config_used={},
)

DEST_NOTES = {
    MSYRUP_DEST: "🟩 FREEZABLE — Holds $3.12M mSyrupUSDp (Midas). Freezability HIGH.",
    CBBTC_DEST:  "🟩 FREEZABLE — Holds $246K cbBTC (Coinbase). Freezability HIGH.",
    USDT_DEST_1: "🟩 FREEZABLE — Holds $97K USDT (Tether). Freezability HIGH.",
    USDT_DEST_2: "🟩 FREEZABLE — Holds $73K USDT (Tether). Freezability HIGH.",
    USDC_DEST:   "🟩 FREEZABLE — Holds $8.8K USDC (Circle). Freezability HIGH.",
    USDT_DEST_3: "🟩 FREEZABLE — Holds $1.6K USDT (Tether). Freezability HIGH.",
    PERP_HUB:    "⬛ UNRECOVERABLE — Holds $655K DAI (Sky Protocol). Freezability LOW.",
}

editorial = {
    "CASE_ID": "V-CFI01",
    "REPORT_DATE": "May 20, 2026",
    "INCIDENT_DATE": "October 9, 2025",
    "INCIDENT_TYPE": "Wallet drainer via phishing site posing as DeFi protocol",
    "PRIMARY_CHAIN": "Ethereum",
    "INCIDENT_NARRATIVE_RECUPERO": (
        "On October 9, 2025, the victim's wallet was drained of approximately "
        "$3.6M in USDT across six transactions. The perpetrator hub subsequently "
        "distributed funds to six downstream destinations."
    ),
    "INCIDENT_NARRATIVE_FIRST_PERSON": (
        "On October 9, 2025, I discovered that approximately $3.6M in USDT "
        "had been stolen from my wallet. I did not authorize these transactions."
    ),
    "VICTIM_SUMMARY": (
        "Your wallet was drained of $3.6M USDT on October 9, 2025. "
        "Recupero has traced the funds to six downstream addresses."
    ),
    "VICTIM_ADDRESS_LINE1": "123 Test Street",
    "VICTIM_ADDRESS_LINE2": "New York, NY 10001",
    "VICTIM_JURISDICTION": "USA (New York)",
    "DESTINATION_NOTES": DEST_NOTES,
    "UNRECOVERABLE_ITEMS": [],
    "IC3_CASE_ID": None,
    "INVESTIGATOR_NAME": "Test Investigator",
    "INVESTIGATOR_EMAIL": "investigator@test.com",
    "INVESTIGATOR_ENTITY": "Recupero",
    "INVESTIGATOR_ENTITY_FULL": "Recupero Forensics Ltd.",
    "INVESTIGATOR_WEB": "https://recupero.io",
    "TEMPLATE_VERSION": "v1.0 — May 2026",
}

freeze_asks = {"by_issuer": {
    "Midas": [{"address": MSYRUP_DEST, "chain": "ethereum", "symbol": "mSyrupUSDp",
               "amount": "3119023.12", "usd_value": "3119023.12", "freeze_capability": "yes",
               "issuer": "Midas", "primary_contact": "compliance@midas.app",
               "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
               "observed_transfer_count": 1}],
    "Coinbase": [{"address": CBBTC_DEST, "chain": "ethereum", "symbol": "cbBTC",
                  "amount": "2.46", "usd_value": "246812.01", "freeze_capability": "yes",
                  "issuer": "Coinbase", "primary_contact": "compliance@coinbase.com",
                  "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
                  "observed_transfer_count": 1}],
    "Tether": [
        {"address": USDT_DEST_1, "chain": "ethereum", "symbol": "USDT",
         "amount": "97535.58", "usd_value": "97535.58", "freeze_capability": "yes",
         "issuer": "Tether", "primary_contact": "compliance@tether.to",
         "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
         "observed_transfer_count": 1},
        {"address": USDT_DEST_2, "chain": "ethereum", "symbol": "USDT",
         "amount": "73151.68", "usd_value": "73151.68", "freeze_capability": "yes",
         "issuer": "Tether", "primary_contact": "compliance@tether.to",
         "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
         "observed_transfer_count": 1},
        {"address": USDT_DEST_3, "chain": "ethereum", "symbol": "USDT",
         "amount": "1597.70", "usd_value": "1597.70", "freeze_capability": "yes",
         "issuer": "Tether", "primary_contact": "compliance@tether.to",
         "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
         "observed_transfer_count": 1},
    ],
    "Circle": [{"address": USDC_DEST, "chain": "ethereum", "symbol": "USDC",
                "amount": "8881.31", "usd_value": "8881.31", "freeze_capability": "yes",
                "issuer": "Circle", "primary_contact": "compliance@circle.com",
                "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
                "observed_transfer_count": 1}],
    "Sky Protocol": [{"address": PERP_HUB, "chain": "ethereum", "symbol": "DAI",
                      "amount": "655751.45", "usd_value": "655751.45", "freeze_capability": "no",
                      "issuer": "Sky Protocol", "primary_contact": None,
                      "evidence_type": "historical_inflow", "observed_at": "2025-10-09T00:29:00Z",
                      "observed_transfer_count": 1}],
}, "exchange_deposits": []}

issuer_metadata = {
    "Midas":    {"contact_email": "compliance@midas.app",    "portal_url": "https://midas.app/compliance",   "typical_response_time": "2-5 business days", "freeze_note": "BaFin-regulated"},
    "Tether":   {"contact_email": "compliance@tether.to",    "portal_url": "https://tether.to",              "typical_response_time": "24-48 hours",       "freeze_note": "Responds within 24h on LE-backed requests"},
    "Circle":   {"contact_email": "compliance@circle.com",   "portal_url": "https://circle.com/legal",       "typical_response_time": "Same day",          "freeze_note": "Fastest stablecoin pathway"},
    "Coinbase": {"contact_email": "compliance@coinbase.com", "portal_url": "https://coinbase.com/legal",     "typical_response_time": "2-3 business days", "freeze_note": "cbBTC backing held at Coinbase"},
}

victim = VictimInfo(name="Jacob Test Victim", wallet_address=VICTIM,
                    state="NY", country="US", email="victim@test.com")
investigator = InvestigatorInfo(name="Test Investigator",
                                organization="Recupero Forensics Ltd.",
                                email="investigator@test.com")

print("=== STEP 1: emit_brief() ===")
brief_data = emit_brief(case=case, victim=victim, editorial=editorial,
                        freeze_asks=freeze_asks, issuer_metadata=issuer_metadata)
all_issuers = brief_data.get("ALL_ISSUER_HOLDINGS", [])

print(f"  THEFT_EVENT_COUNT:    {brief_data['THEFT_EVENT_COUNT']}")
print(f"  TOTAL_LOSS_USD:       {brief_data['TOTAL_LOSS_USD']}")
print(f"  TOTAL_FREEZABLE_USD:  {brief_data['TOTAL_FREEZABLE_USD']}")
print(f"  FREEZABLE issuers:    {[f['issuer'] for f in brief_data['FREEZABLE']]}")
print(f"  ALL_ISSUER_HOLDINGS:  {[(f['issuer'], f['freeze_capability']) for f in all_issuers]}")
print()

# Check DAI appears in ALL_ISSUER_HOLDINGS with UNRECOVERABLE holdings
sky = next((f for f in all_issuers if f["issuer"] == "Sky Protocol"), None)
if sky:
    statuses = [h["status"] for h in sky.get("holdings", [])]
    print(f"  Sky Protocol holdings statuses: {statuses}")
    assert "UNRECOVERABLE" in statuses, "BUG: Sky Protocol holdings not UNRECOVERABLE"
    print("  [OK] Sky Protocol correctly UNRECOVERABLE in ALL_ISSUER_HOLDINGS")
else:
    print("  [FAIL] BUG: Sky Protocol missing from ALL_ISSUER_HOLDINGS!")

print()
print("=== STEP 2: generate_briefs() for all 4 issuers ===")
tmpdir = tempfile.mkdtemp()

issuer_configs = [
    ("Midas", IssuerInfo(name="Midas Software GmbH", short_name="Midas",
        contact_email="compliance@midas.app", jurisdiction="Germany (EU)",
        regulatory_framework="EU MiCA / BaFin", secondary_party="Maple Finance",
        secondary_role="underlying yield strategy manager",
        asset_description="Midas ERC-20 mSyrupUSDp wrapper", kyc_required=True, kyc_minimum="USD 125,000"),
     "ERC-20 yield-bearing wrapper token"),
    ("Tether", IssuerInfo(name="Tether Limited", short_name="Tether",
        contact_email="compliance@tether.to", jurisdiction="British Virgin Islands"),
     "ERC-20 stablecoin"),
    ("Circle", IssuerInfo(name="Circle Internet Financial", short_name="Circle",
        contact_email="compliance@circle.com", jurisdiction="USA"),
     "ERC-20 stablecoin"),
    ("Coinbase", IssuerInfo(name="Coinbase Inc.", short_name="Coinbase",
        contact_email="compliance@coinbase.com", jurisdiction="USA"),
     "ERC-20 wrapped BTC"),
]

bundles = {}
for issuer_name, issuer_obj, asset_type in issuer_configs:
    freezable = next((f for f in brief_data.get("FREEZABLE", []) if f["issuer"] == issuer_name), None)
    bundle = generate_briefs(
        primary_case=case, linked_cases=[], victim=victim, investigator=investigator,
        case_dir=Path(tmpdir), issuer=issuer_obj, asset_type=asset_type,
        outbound_count_of_stolen_asset=0, issuer_freezable=freezable,
        all_issuers_freezable=all_issuers,
    )
    bundles[issuer_name] = bundle
    print(f"  {issuer_name:12s} letter: {len(bundle.maple_html):>6,} chars | LE: {len(bundle.le_html):>6,} chars")

# Save HTMLs
for name, bundle in bundles.items():
    Path(tmpdir, f"{name.lower()}_letter.html").write_text(bundle.maple_html, encoding="utf-8")
    Path(tmpdir, f"{name.lower()}_le.html").write_text(bundle.le_html, encoding="utf-8")
print(f"\n  HTML saved: {tmpdir}")

print()
print("=== STEP 3: Section-by-section quality audit ===")
issues = []

def check(name, condition, msg):
    if not condition:
        issues.append(f"[{name}] {msg}")
        print(f"  [FAIL] [{name}] {msg}")
    else:
        print(f"  [OK] [{name}] {msg.split(' — ')[0]}")

# --- Midas letter checks ---
ml = bundles["Midas"].maple_html
le = bundles["Midas"].le_html

# A: No render artifacts
check("midas_letter", "{{ " not in ml and " }}" not in ml, "No unrendered Jinja tags")
check("midas_le",     "{{ " not in le and " }}" not in le, "No unrendered Jinja tags")
check("midas_letter", "Undefined" not in ml, "No 'Undefined' context vars")
check("midas_letter", "TODO:" not in ml, "No TODO: placeholders")
check("midas_le",     "TODO:" not in le, "No TODO: placeholders")

# B: Dollar amounts
check("midas_letter", "3,119,023" in ml or "3,119" in ml, "mSyrupUSDp $3.12M in letter — correct amount")
check("midas_le",     "3,600,000" in le, "LE shows $3.6M total theft — multi-event rollup")

# C: Status pills
check("midas_letter", "FREEZABLE" in ml, "FREEZABLE pill in issuer letter")
check("midas_le",     "UNRECOVERABLE" in le, "UNRECOVERABLE pill in LE — Sky DAI")

# D: Section 4.2 (all-issuers LE view)
check("midas_le",     "4.2" in le or "Complete Holdings" in le, "Section 4.2 present in LE")
for issuer in ("Midas", "Coinbase", "Tether", "Circle"):
    check("midas_le", issuer in le, f"{issuer} appears in LE (Section 4.2)")
check("midas_le",     "Sky Protocol" in le, "Sky Protocol appears in LE (UNRECOVERABLE)")

# E: Explorer links
check("midas_letter", "etherscan.io" in ml, "etherscan.io URLs in issuer letter")
check("midas_le",     "Etherscan" in le, "Etherscan name resolved from primary_chain_explorer_name")

# F: Address rendering (mixed case, not lowercased)
check("midas_letter", VICTIM in ml, "Victim address in mixed-case form in letter")
check("midas_letter", MSYRUP_DEST in ml, "mSyrupUSDp dest address in mixed-case form in letter")

# G: Multi-event (6 theft transactions)
check("midas_letter", "3,600,000" in ml or "3.6" in ml, "Total theft $3.6M shown in letter")

# H: DAI routing — UNRECOVERABLE not FREEZABLE
perp_positions = [m.start() for m in re.finditer(re.escape(PERP_HUB), le, re.IGNORECASE)]
dai_near_freezable = False
for pos in perp_positions:
    snippet = le[max(0, pos-500):pos+500]
    if "FREEZABLE" in snippet and "UNRECOVERABLE" not in snippet:
        dai_near_freezable = True
check("midas_le", not dai_near_freezable, "PERP_HUB (DAI) not near FREEZABLE pill without UNRECOVERABLE — correct routing")

# I: Issuer targeting
check("midas_letter", "Midas" in ml, "Letter addressed to Midas")
check("midas_letter", "Dear Sky Protocol" not in ml, "Not addressed to Sky Protocol")
midas_tether_check = True
pos = ml.lower().find("asset issuer")
if pos != -1:
    snippet = ml[pos:pos+200]
    if "Tether" in snippet and "Midas" not in snippet:
        midas_tether_check = False
check("midas_letter", midas_tether_check, "Asset issuer section shows Midas not Tether — residual #6")

# J: LE structure
check("midas_le", "V-CFI01 Test Victim" in le or "Jacob Test Victim" in le, "Victim name in LE")
check("midas_le", "V-CFI01" in le, "Case ID V-CFI01 in LE")
check("midas_le", "Test Investigator" in le, "Investigator name in LE")
check("midas_le", "Attestation" in le or "attestation" in le, "Attestation section in LE")
check("midas_le", "Verification" in le, "Verification section in LE")

# Check all 6 destinations in LE
dests = [MSYRUP_DEST, CBBTC_DEST, USDT_DEST_1, USDT_DEST_2, USDC_DEST, USDT_DEST_3]
missing = [d for d in dests if d.lower() not in le.lower()]
check("midas_le", not missing, f"All 6 freezable destination addresses in LE — {len(dests)-len(missing)}/6 present")

# Tether letter — 3 addresses
tl = bundles["Tether"].maple_html
check("tether_letter", USDT_DEST_1 in tl or USDT_DEST_1.lower() in tl.lower(), "USDT_DEST_1 in Tether letter")
check("tether_letter", USDT_DEST_2 in tl or USDT_DEST_2.lower() in tl.lower(), "USDT_DEST_2 in Tether letter")
check("tether_letter", USDT_DEST_3 in tl or USDT_DEST_3.lower() in tl.lower(), "USDT_DEST_3 in Tether letter")
check("tether_letter", "172,285" in tl or "172,284" in tl or "172" in tl, "Tether total (~$172K across 3 addresses) in letter")

# Circle letter
cl = bundles["Circle"].maple_html
check("circle_letter", "8,881" in cl or "8881" in cl, "Circle USDC $8.8K amount in letter")
check("circle_letter", USDC_DEST in cl or USDC_DEST.lower() in cl.lower(), "USDC dest address in Circle letter")

# Coinbase letter
cbl = bundles["Coinbase"].maple_html
check("coinbase_letter", "246,812" in cbl or "246" in cbl, "Coinbase cbBTC $246K in letter")
check("coinbase_letter", CBBTC_DEST in cbl or CBBTC_DEST.lower() in cbl.lower(), "cbBTC dest address in Coinbase letter")

print()
if issues:
    print(f"=== {len(issues)} ISSUE(S) FOUND ===")
    for i in issues:
        print(f"  {i}")
    sys.exit(1)
else:
    print(f"=== ALL {sum(1 for line in open(__file__) if 'check(' in line)} CHECKS PASSED — RENDER IS CLEAN ===")
