"""Tests for v0.13.4 multi-destination DESTINATIONS enumeration.

The Jacob V-CFI01 follow-up: pre-v0.13.4, _extract_destinations
filtered to addresses the AI editorial labeled in editorial_notes.
On multi-destination cases (perp hub disperses to 10+ downstream
addresses, each holding $K-$M in freezable tokens), missing AI
labels silently dropped every downstream destination from the
brief — the Triage Report rendered "Freezable: $0" when the trace
had identified $3M+ in freezable downstream holdings.

This file pins the new behavior:
  * Every destination above the dust threshold (default $1,000)
    appears in DESTINATIONS, regardless of editorial coverage.
  * Mechanical fallback notes carry the right emoji prefix (🟩 /
    ⬛ / 🟦 / 🟧) so the JS renderer + freezable totals work.
  * Operator-pre-labeled addresses (via editorial_notes) still get
    the editorial note verbatim — back-compat preserved.
  * Below-threshold dust ($50, $10) is filtered out as noise.
  * The seed address is never in DESTINATIONS.
  * Addresses in freeze_targets_by_addr are ALWAYS included even
    when trace inflow is sub-threshold (a wallet that received
    $1 from THIS victim but holds $3M in USDT-from-other-victims
    should still surface as a freeze candidate).
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, Label, LabelCategory, TokenRef, Transfer
from recupero.reports.emit_brief import _extract_destinations

# ---- Fixtures ---- #


VICTIM = "0x" + "a" * 40
PERP_HUB = "0x" + "b" * 40
MAPLE_DEST = "0x" + "c" * 40   # holds $3.1M mSyrupUSDp
USDT_DEST_1 = "0x" + "d" * 40  # holds $171K USDT
USDT_DEST_2 = "0x" + "e" * 40  # holds $82K USDT
DAI_DEST = "0x" + "f" * 40     # holds $100K DAI (NOT freezable)
DUST_DEST = "0x" + "1" * 40    # only $50 received — below threshold


def _label(addr: str, *, category: LabelCategory, name: str = "Test") -> Label:
    return Label(
        address=addr,
        name=name,
        category=category,
        source="test",
        confidence="high",
        added_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    token_symbol: str = "USDT",
    counterparty_label: Label | None = None,
    tx_hash: str | None = None,
) -> Transfer:
    ts = datetime(2026, 4, 1, tzinfo=UTC)
    tx_hash = tx_hash or "0x" + "1" * 64
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr,
            label=counterparty_label,
            is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol=token_symbol,
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="V-CFI01",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 4, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 4, 1, tzinfo=UTC),
        software_version="v0.13.4",
        config_used={},
    )


def _freeze_targets(*entries: dict) -> dict[str, dict]:
    """Build the freeze_targets_by_addr lookup that emit_brief
    constructs from freeze_asks.json."""
    return {e["address"]: e for e in entries}


# ============ The bug Jacob reported ============ #


def test_v_cfi01_shape_enumerates_all_downstream_destinations() -> None:
    """V-CFI01 shape: victim → perp hub → 4 downstream destinations
    (Maple $3.1M, USDT $171K, USDT $82K, DAI $100K). Pre-v0.13.4 the
    brief showed only 1 destination (the hub). Now it should show 5
    (hub + 4 downstream).

    THIS IS THE ACCEPTANCE CRITERION FROM JACOB'S EMAIL.
    """
    transfers = [
        # Victim → hub (1 transfer carrying the full $3.12M)
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("3120000"), tx_hash="0xhub"),
        # Hub → Maple dest ($3.1M mSyrupUSDp inflow recorded in trace)
        _transfer(from_addr=PERP_HUB, to_addr=MAPLE_DEST,
                  usd=Decimal("3100000"), token_symbol="mSyrupUSDp",
                  tx_hash="0xmaple1"),
        # Hub → USDT dest 1
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_1,
                  usd=Decimal("171000"), token_symbol="USDT",
                  tx_hash="0xusdt1"),
        # Hub → USDT dest 2
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_2,
                  usd=Decimal("82000"), token_symbol="USDT",
                  tx_hash="0xusdt2"),
        # Hub → DAI dest
        _transfer(from_addr=PERP_HUB, to_addr=DAI_DEST,
                  usd=Decimal("100000"), token_symbol="DAI",
                  tx_hash="0xdai"),
    ]
    case = _case(transfers)

    # AI only labeled the hub (the pre-v0.13.4 buggy behavior).
    editorial_notes = {
        PERP_HUB: "🟧 INVESTIGATE — Perpetrator consolidation address...",
    }
    # Freeze asks found the Maple + 2 USDT destinations (DAI is
    # non-freezable so it wouldn't be in freeze_asks).
    freeze_targets = _freeze_targets(
        {"address": MAPLE_DEST, "symbol": "mSyrupUSDp",
         "usd_value": "3100000", "issuer": "Maple Finance",
         "freeze_capability": "limited"},
        {"address": USDT_DEST_1, "symbol": "USDT",
         "usd_value": "171000", "issuer": "Tether",
         "freeze_capability": "yes"},
        {"address": USDT_DEST_2, "symbol": "USDT",
         "usd_value": "82000", "issuer": "Tether",
         "freeze_capability": "yes"},
    )

    destinations = _extract_destinations(case, editorial_notes, freeze_targets)

    # ALL 5 perpetrator-controlled addresses must appear.
    addrs = {d["address"] for d in destinations}
    assert PERP_HUB in addrs
    assert MAPLE_DEST in addrs, "Maple destination must surface in DESTINATIONS"
    assert USDT_DEST_1 in addrs
    assert USDT_DEST_2 in addrs
    assert DAI_DEST in addrs, "DAI destination must surface (UNRECOVERABLE)"

    # And the count is exactly 5 (no extras, no drops).
    assert len(destinations) == 5


def test_v_cfi01_freezable_destinations_get_freezable_emoji() -> None:
    """Mechanical fallback notes for freeze-target addresses carry
    the 🟩 prefix when freeze_capability=yes, ensuring the JS renderer
    counts them in the FREEZABLE total."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_1,
                  usd=Decimal("80000"), token_symbol="USDT",
                  tx_hash="0xusdt1"),
    ]
    case = _case(transfers)
    freeze_targets = _freeze_targets(
        {"address": USDT_DEST_1, "symbol": "USDT",
         "usd_value": "80000", "issuer": "Tether",
         "freeze_capability": "yes"},
    )
    destinations = _extract_destinations(case, {}, freeze_targets)
    usdt_dest = next(d for d in destinations if d["address"] == USDT_DEST_1)
    assert usdt_dest["status"] == "FREEZABLE"
    assert "🟩" in usdt_dest["notes"]
    assert "Tether" in usdt_dest["notes"]
    assert "Freezability HIGH" in usdt_dest["notes"]


def test_dai_destination_classified_unrecoverable_not_freezable() -> None:
    """DAI is in freeze_asks (the dormant detector found it) but
    freeze_capability='no' (Sky Protocol is permissionless). The
    mechanical fallback note must emit ⬛ UNRECOVERABLE, NOT 🟩 —
    otherwise the brief would tell the issuer (Sky) to freeze
    funds they have no authority to freeze."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=DAI_DEST,
                  usd=Decimal("100000"), token_symbol="DAI",
                  tx_hash="0xdai"),
    ]
    case = _case(transfers)
    freeze_targets = _freeze_targets(
        {"address": DAI_DEST, "symbol": "DAI",
         "usd_value": "100000", "issuer": "Sky Protocol",
         "freeze_capability": "no"},
    )
    destinations = _extract_destinations(case, {}, freeze_targets)
    dai_dest = next(d for d in destinations if d["address"] == DAI_DEST)
    assert dai_dest["status"] == "UNRECOVERABLE"
    assert "⬛" in dai_dest["notes"]
    assert "Sky Protocol" in dai_dest["notes"]


def test_dust_below_threshold_filtered_out() -> None:
    """Destinations with USD received below the dust threshold are
    NOT enumerated — keeps the brief readable when the trace has
    100+ MEV-bot pennies."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        # $50 dust — below the $1000 default threshold.
        _transfer(from_addr=PERP_HUB, to_addr=DUST_DEST,
                  usd=Decimal("50"), tx_hash="0xdust"),
    ]
    case = _case(transfers)
    destinations = _extract_destinations(case, {}, {})
    addrs = {d["address"] for d in destinations}
    assert PERP_HUB in addrs
    assert DUST_DEST not in addrs


def test_editorial_pre_labeled_dust_still_included() -> None:
    """If the operator hand-wrote an editorial note for a $50 dust
    address (because it's evidentially relevant — say, the address
    was used for a 0-value test transfer that confirms identity),
    do NOT drop it just because of the threshold."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=DUST_DEST,
                  usd=Decimal("50"), tx_hash="0xdust"),
    ]
    case = _case(transfers)
    editorial_notes = {
        DUST_DEST: "🟧 INVESTIGATE — test-tx address, evidentially relevant",
    }
    destinations = _extract_destinations(case, editorial_notes, {})
    addrs = {d["address"] for d in destinations}
    assert DUST_DEST in addrs


def test_seed_address_never_in_destinations() -> None:
    """A reverse transfer (perp → victim, e.g. dust attack) must not
    add the victim's own seed wallet as a 'destination'."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        # Reverse — perp sends dust back to victim (would happen if
        # the trace's bidirectional walk is on).
        _transfer(from_addr=PERP_HUB, to_addr=VICTIM,
                  usd=Decimal("5000"), tx_hash="0xdust_back"),
    ]
    case = _case(transfers)
    destinations = _extract_destinations(case, {}, {})
    addrs = {d["address"] for d in destinations}
    assert VICTIM not in addrs


def test_freeze_target_with_no_trace_inflow_still_surfaces() -> None:
    """A wallet in freeze_asks (the dormant detector found it
    holding $3M freezable balance) but with trace inflow below
    threshold MUST still appear in DESTINATIONS — the $3M is the
    point, not the $1 attribution share."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100"), tx_hash="0xhub"),
        # Tiny $1 attribution to Maple dest — but the dormant
        # detector sees $3.1M sitting there in mSyrupUSDp from
        # other victims pooled at this address.
        _transfer(from_addr=PERP_HUB, to_addr=MAPLE_DEST,
                  usd=Decimal("1"), tx_hash="0xmaple"),
    ]
    case = _case(transfers)
    freeze_targets = _freeze_targets(
        {"address": MAPLE_DEST, "symbol": "mSyrupUSDp",
         "usd_value": "3100000", "issuer": "Maple Finance",
         "freeze_capability": "limited"},
    )
    destinations = _extract_destinations(case, {}, freeze_targets)
    addrs = {d["address"] for d in destinations}
    assert MAPLE_DEST in addrs
    maple = next(d for d in destinations if d["address"] == MAPLE_DEST)
    # Holding now reflects the $3.1M from the dormant detector,
    # NOT the $1 attribution.
    assert "3,100,000" in maple["usd_holding_now"]


def test_destinations_sorted_by_usd_received_descending() -> None:
    """Largest received first, so the brief leads with the most
    consequential destinations."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("500000"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_1,
                  usd=Decimal("400000"), tx_hash="0xusdt1"),
        _transfer(from_addr=PERP_HUB, to_addr=DAI_DEST,
                  usd=Decimal("50000"), tx_hash="0xdai"),
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_2,
                  usd=Decimal("100000"), tx_hash="0xusdt2"),
    ]
    case = _case(transfers)
    destinations = _extract_destinations(case, {}, {})
    usd_received_order = [d["usd_received_in_trace"] for d in destinations]
    # Should be sorted desc by USD received. The hub got the biggest
    # ($500k) since it received from the victim, then USDT_DEST_1
    # ($400k), USDT_DEST_2 ($100k), DAI_DEST ($50k).
    # (Format strings, but lexically comparable: '$500,000.00' >
    # '$400,000.00' > '$100,000.00' > '$50,000.00')
    parsed = [
        Decimal(s.replace("$", "").replace(",", "")) for s in usd_received_order
    ]
    assert parsed == sorted(parsed, reverse=True)


def test_exchange_label_classified_blue() -> None:
    """A destination labeled as a known exchange should get the 🟦
    EXCHANGE prefix mechanically (no AI editorial needed)."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(
            from_addr=PERP_HUB,
            to_addr=USDT_DEST_1,
            usd=Decimal("50000"),
            counterparty_label=_label(
                USDT_DEST_1,
                category=LabelCategory.exchange_deposit,
                name="Binance Hot Wallet",
            ),
            tx_hash="0xbnb",
        ),
    ]
    case = _case(transfers)
    destinations = _extract_destinations(case, {}, {})
    binance_dest = next(d for d in destinations if d["address"] == USDT_DEST_1)
    assert binance_dest["status"] == "EXCHANGE"
    assert "🟦" in binance_dest["notes"]


def test_mixer_label_classified_unrecoverable() -> None:
    """A destination labeled as a mixer → ⬛ UNRECOVERABLE."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(
            from_addr=PERP_HUB,
            to_addr=USDT_DEST_1,
            usd=Decimal("50000"),
            counterparty_label=_label(
                USDT_DEST_1,
                category=LabelCategory.mixer,
                name="Tornado Cash: 100 ETH",
            ),
            tx_hash="0xmixer",
        ),
    ]
    case = _case(transfers)
    destinations = _extract_destinations(case, {}, {})
    mixer_dest = next(d for d in destinations if d["address"] == USDT_DEST_1)
    assert mixer_dest["status"] == "UNRECOVERABLE"
    assert "⬛" in mixer_dest["notes"]


def test_editorial_notes_still_take_precedence_when_present() -> None:
    """Back-compat: if the operator hand-wrote a DESTINATION_NOTES
    entry for an address, that note appears verbatim — the mechanical
    fallback is suppressed."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100000"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_1,
                  usd=Decimal("80000"), tx_hash="0xusdt1"),
    ]
    case = _case(transfers)
    editorial_notes = {
        USDT_DEST_1: "🟩 OPERATOR-WROTE — special note that wins.",
    }
    freeze_targets = _freeze_targets(
        {"address": USDT_DEST_1, "symbol": "USDT",
         "usd_value": "80000", "issuer": "Tether",
         "freeze_capability": "yes"},
    )
    destinations = _extract_destinations(case, editorial_notes, freeze_targets)
    usdt = next(d for d in destinations if d["address"] == USDT_DEST_1)
    assert "OPERATOR-WROTE" in usdt["notes"]
    assert "Mechanical fallback should not appear when editorial provided it"


def test_custom_dust_threshold_via_arg() -> None:
    """Caller can override the dust threshold per call (used by tests
    + investigations that want finer granularity)."""
    transfers = [
        _transfer(from_addr=VICTIM, to_addr=PERP_HUB,
                  usd=Decimal("100"), tx_hash="0xhub"),
        _transfer(from_addr=PERP_HUB, to_addr=USDT_DEST_1,
                  usd=Decimal("50"), tx_hash="0xusdt1"),
    ]
    case = _case(transfers)
    # With $10 threshold, both should appear.
    destinations = _extract_destinations(
        case, {}, {}, dust_threshold_usd=Decimal("10"),
    )
    addrs = {d["address"] for d in destinations}
    assert PERP_HUB in addrs
    assert USDT_DEST_1 in addrs
    # With $200 threshold, neither.
    destinations = _extract_destinations(
        case, {}, {}, dust_threshold_usd=Decimal("200"),
    )
    addrs = {d["address"] for d in destinations}
    assert PERP_HUB not in addrs
    assert USDT_DEST_1 not in addrs
