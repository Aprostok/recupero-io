"""Tests for v0.14.9 evidence-type propagation through emit_brief.

The freeze-asks pipeline now produces entries with
``evidence_type='historical_inflow'`` (v0.14.8). The brief generator
needs to:

  1. Thread that field into per-holding dicts in FREEZABLE
     entries so the freeze-letter template can read it.
  2. Aggregate per-issuer ``evidence_mode``
     ('current_balance_only' | 'historical_only' | 'mixed') so the
     template can branch the cover-page framing.
  3. Carry the earliest observed_at across the issuer's historical
     holdings (for the letter's "received on or about" line).
"""

from __future__ import annotations

from decimal import Decimal

from recupero.reports.emit_brief import _extract_freezable


def _freeze_asks_with(asks: list[dict]) -> dict:
    """Build a freeze_asks.json-shaped dict with the given asks all
    grouped under a single Tether issuer."""
    return {"by_issuer": {"Tether": asks}}


def _ask(
    *,
    address: str,
    usd: str = "50000",
    evidence_type: str = "current_balance",
    observed_at: str | None = None,
    transfer_count: int = 1,
    capability: str = "yes",
) -> dict:
    return {
        "address": address,
        "chain": "ethereum",
        "symbol": "USDT",
        "amount": "50000",
        "usd_value": usd,
        "primary_contact": "compliance@tether.to",
        "freeze_capability": capability,
        "explorer_url": f"https://etherscan.io/address/{address}",
        "evidence_type": evidence_type,
        "observed_at": observed_at,
        "observed_transfer_count": transfer_count,
    }


# ---- Per-holding evidence_type ---- #


def test_evidence_type_threads_through_per_holding() -> None:
    """Every per-holding dict in FREEZABLE.holdings must carry
    evidence_type / observed_at / observed_transfer_count so the
    letter template can read them per row."""
    freeze_asks = _freeze_asks_with([
        _ask(
            address="0xhistorical",
            evidence_type="historical_inflow",
            observed_at="2025-10-09T00:29:00Z",
            transfer_count=2,
        ),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert len(out) == 1
    tether = out[0]
    h = tether["holdings"][0]
    assert h["evidence_type"] == "historical_inflow"
    assert h["observed_at"] == "2025-10-09T00:29:00Z"
    assert h["observed_transfer_count"] == 2


def test_evidence_type_defaults_to_current_balance() -> None:
    """Back-compat: freeze_asks without evidence_type set default to
    'current_balance' on the holding so old pipelines keep working."""
    # Note: this directly tests the old-shape ask dict (no evidence_type field).
    freeze_asks = _freeze_asks_with([
        {
            "address": "0xlegacy",
            "chain": "ethereum",
            "symbol": "USDT",
            "amount": "50000",
            "usd_value": "50000",
            "freeze_capability": "yes",
            "explorer_url": "",
        },
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    h = out[0]["holdings"][0]
    assert h["evidence_type"] == "current_balance"
    assert h["observed_at"] is None
    assert h["observed_transfer_count"] == 1


# ---- Per-issuer evidence_mode ---- #


def test_evidence_mode_current_balance_only() -> None:
    """All holdings are current_balance → evidence_mode='current_balance_only'."""
    freeze_asks = _freeze_asks_with([
        _ask(address="0xa", evidence_type="current_balance"),
        _ask(address="0xb", evidence_type="current_balance"),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert out[0]["evidence_mode"] == "current_balance_only"
    assert out[0]["historical_count"] == 0
    assert out[0]["current_balance_count"] == 2


def test_evidence_mode_historical_only() -> None:
    """All holdings are historical_inflow → 'historical_only'.
    This is Jacob's V-CFI01 case shape."""
    freeze_asks = _freeze_asks_with([
        _ask(address="0xa", evidence_type="historical_inflow",
             observed_at="2025-10-09T00:29:00Z"),
        _ask(address="0xb", evidence_type="historical_inflow",
             observed_at="2025-10-09T00:30:00Z"),
        _ask(address="0xc", evidence_type="historical_inflow",
             observed_at="2025-10-09T00:31:00Z"),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert out[0]["evidence_mode"] == "historical_only"
    assert out[0]["historical_count"] == 3
    assert out[0]["current_balance_count"] == 0


def test_evidence_mode_mixed() -> None:
    """One current + one historical → 'mixed'."""
    freeze_asks = _freeze_asks_with([
        _ask(address="0xcurrent", evidence_type="current_balance"),
        _ask(address="0xhistorical", evidence_type="historical_inflow",
             observed_at="2025-10-09T00:29:00Z"),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert out[0]["evidence_mode"] == "mixed"
    assert out[0]["historical_count"] == 1
    assert out[0]["current_balance_count"] == 1


# ---- Earliest observation ---- #


def test_earliest_observed_picks_smallest_iso() -> None:
    """The letter template uses earliest_observed for 'received on or
    about [date]'. Verify it's the smallest ISO timestamp across the
    historical holdings."""
    freeze_asks = _freeze_asks_with([
        _ask(address="0xa", evidence_type="historical_inflow",
             observed_at="2025-11-29T00:00:00Z"),
        _ask(address="0xb", evidence_type="historical_inflow",
             observed_at="2025-10-09T00:29:00Z"),  # earliest
        _ask(address="0xc", evidence_type="historical_inflow",
             observed_at="2025-10-13T00:00:00Z"),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert out[0]["earliest_observed"] == "2025-10-09T00:29:00Z"


def test_earliest_observed_none_when_all_current_balance() -> None:
    """Current-balance asks don't carry observed_at; earliest is None."""
    freeze_asks = _freeze_asks_with([
        _ask(address="0xa", evidence_type="current_balance"),
    ])
    out = _extract_freezable(freeze_asks, issuer_metadata={})
    assert out[0]["earliest_observed"] is None


# ---- Jacob's V-CFI01 acceptance shape ---- #


def test_jacobs_v_cfi01_freezable_shape() -> None:
    """The acceptance shape Jacob's email specifies: Tether letter
    bundling 3 USDT addresses, Circle letter with 1 USDC address.
    All historical_inflow evidence.

    v0.16.2 (corrected semantics after rolling back v0.16.1's
    over-correction):

    Historical_inflow at a freezable issuer (cap=yes/limited)
    STAYS as status=FREEZABLE in the brief — because:
      1. The freeze letter IS the recovery mechanism for this case
         shape; the issuer can investigate and freeze if balances
         remain. From a process standpoint these ARE freezable.
      2. The customer letter and freeze letter templates branch on
         evidence_mode (per-issuer) to render the right language
         ("received at" vs "currently held").
      3. Downgrading to INVESTIGATE in v0.16.1 zeroed per-issuer
         total_usd, which routed cases like V-CFI01 to unrecoverable
         via classify_recovery_prospects — the same end-state as
         the original Jacob bug, just for a different reason.

    The contract:
      - per-issuer total_usd      → sums all FREEZABLE-status rows
                                     including historical_inflow at
                                     freezable issuers
      - evidence_mode             → 'historical_only' / 'mixed' /
                                     'current_balance_only'
      - per-holding evidence_type → 'historical_inflow' or
                                     'current_balance'
      - per-holding status        → 'FREEZABLE' (or UNRECOVERABLE
                                     if cap=no/low)

    Templates branch on evidence_mode for language.
    """
    freeze_asks = {
        "by_issuer": {
            "Tether": [
                _ask(address="0x00000688768803Bbd44095770895ad27ad6b0d95",
                     usd="170687.26", evidence_type="historical_inflow",
                     observed_at="2025-10-09T00:29:00Z"),
                _ask(address="0x5141B82f5fFDa4c6fE1E372978F1C5427640a190",
                     usd="82277.60", evidence_type="historical_inflow",
                     observed_at="2025-10-09T00:30:00Z"),
                _ask(address="0x3B0AA7d38Bf3C103bf02d1De2E37568cBED3D6e8",
                     usd="1597.70", evidence_type="historical_inflow",
                     observed_at="2025-10-13T00:00:00Z"),
            ],
            "Circle": [
                _ask(address="0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4",
                     usd="8881.31", evidence_type="historical_inflow",
                     observed_at="2025-10-09T00:31:00Z"),
            ],
        },
    }
    # Editorial notes that the AI editorial would produce — the v0.14.9
    # prompt encourages 🟩 FREEZABLE for historical-inflow at freezable
    # issuers because "the operator will still send a freeze letter."
    # v0.16.1 catches and downgrades the per-issuer aggregate so the
    # letter doesn't make a current-balance claim.
    editorial_notes = {
        "0x00000688768803Bbd44095770895ad27ad6b0d95": "🟩 FREEZABLE — Tether",
        "0x5141B82f5fFDa4c6fE1E372978F1C5427640a190": "🟩 FREEZABLE — Tether",
        "0x3B0AA7d38Bf3C103bf02d1De2E37568cBED3D6e8": "🟩 FREEZABLE — Tether",
        "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4": "🟩 FREEZABLE — Circle",
    }
    out = _extract_freezable(freeze_asks, issuer_metadata={},
                              editorial_notes=editorial_notes)
    by_issuer = {entry["issuer"]: entry for entry in out}

    # Tether: 3 historical holdings, all FREEZABLE status (v0.16.2).
    tether = by_issuer["Tether"]
    assert tether["evidence_mode"] == "historical_only"
    assert tether["historical_count"] == 3
    assert tether["current_balance_count"] == 0
    # v0.16.2: total_usd sums historical_inflow at freezable issuers
    # too — the freeze letter is the recovery mechanism for this
    # case shape. The template branches on evidence_mode to render
    # "received at" instead of "currently held". Routing the case
    # to recoverable depends on this number flowing through.
    expected_tether = (
        Decimal("170687.26") + Decimal("82277.60") + Decimal("1597.70")
    )
    actual_tether = Decimal(
        tether["total_usd"].replace("$", "").replace(",", "")
    )
    assert actual_tether == expected_tether, (
        f"total_usd must sum FREEZABLE-status historical_inflow asks "
        f"at freezable issuers (v0.16.2). Got ${actual_tether}, "
        f"expected ${expected_tether}"
    )
    # Earliest observation Oct 9.
    assert tether["earliest_observed"] == "2025-10-09T00:29:00Z"

    # Circle: 1 historical holding, still FREEZABLE.
    circle = by_issuer["Circle"]
    assert circle["evidence_mode"] == "historical_only"
    assert circle["historical_count"] == 1
    assert circle["current_balance_count"] == 0
    circle_total = Decimal(circle["total_usd"].replace("$", "").replace(",", ""))
    assert circle_total == Decimal("8881.31")

    # Every per-holding entry carries evidence_type. Per-row status
    # is FREEZABLE for historical_inflow at freezable issuers
    # (template uses evidence_type, not status, to render language).
    for entry in out:
        for h in entry["holdings"]:
            assert h["evidence_type"] in ("current_balance", "historical_inflow")
            # All freezable issuer + non-zero historical_inflow rows
            # in this fixture are FREEZABLE-status post v0.16.2.
            assert h["status"] == "FREEZABLE", (
                f"v0.16.2: historical_inflow at freezable issuer must "
                f"keep status FREEZABLE. Got status={h['status']!r}"
            )
