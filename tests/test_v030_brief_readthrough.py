"""v0.30.0 brief read-through regression tests.

Pins the F1–F7 fixes from `docs/BRIEF_READTHROUGH_FINDINGS_v030.md`:

  F1. Footer version pulls from `recupero.__version__` (not hardcoded).
  F2. Issuer freeze letter does NOT leak victim home address / email.
  F3/F4. US victim with `citizenship="USA (Texas)"` and `country=None`
         is correctly routed to IC3 + Texas-state contacts, NOT
         INTERNATIONAL_FALLBACK with an empty Contact column.
  F5. USDT (and other canonical stablecoins) gets a per-token asset
      description, NOT the Midas-specific "yield-bearing wrapper".
  F6. Section 5 unlabeled-wallets list is filtered + capped and burn
      address gets a hard-coded label.
  F7. Operator-name unconfigured → brief auto-stamped with
      `UNSIGNED — DO NOT TRANSMIT` watermark.
"""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

# ──────────────────────────────────────────────────────────────────────
# F3/F4 — jurisdiction parser + US-victim routing
# ──────────────────────────────────────────────────────────────────────


def test_citizenship_parser_pulls_us_state_from_combined_field() -> None:
    from recupero.worker._le_routing import _parse_citizenship_country_state
    assert _parse_citizenship_country_state("USA (Texas)") == ("USA", "Texas")
    assert _parse_citizenship_country_state("United States (CA)") == ("United States", "CA")
    assert _parse_citizenship_country_state("Germany") == ("Germany", None)
    assert _parse_citizenship_country_state("USA") == ("USA", None)
    assert _parse_citizenship_country_state(None) == (None, None)
    assert _parse_citizenship_country_state("") == (None, None)


def test_us_victim_with_combined_citizenship_field_routes_to_ic3() -> None:
    """The actual failure mode the smoke read-through caught: victim has
    `citizenship="USA (Texas)"` and `country=None` / `state=None`.
    Pre-v0.30.0 the LE handoff emitted INTERNATIONAL_FALLBACK with an
    empty Contact column."""
    from recupero.worker._le_routing import recommend_le_routes
    plan = recommend_le_routes(
        state=None, country="USA (Texas)", total_loss_usd=Decimal("21317.94"),
    )
    primary_names = [r.name for r in plan.primary_routes]
    assert any("IC3" in n for n in primary_names), (
        f"Expected IC3 in primary_routes; got {primary_names!r}. "
        f"Pre-v0.30.0 the citizenship-with-state combined field would "
        f"have produced INTERNATIONAL_FALLBACK here."
    )
    # State routes must be present too.
    state_names = [r.name for r in plan.state_routes]
    assert any("Texas" in n for n in state_names), (
        f"Texas-state routing failed. Plan: primary={primary_names!r}, "
        f"state={state_names!r}"
    )


def test_us_victim_with_various_country_spellings_classified_as_us() -> None:
    """Defensive: 'America', 'United States of America', etc."""
    from recupero.worker._le_routing import recommend_le_routes
    for spelling in (
        "USA", "US", "U.S.", "U.S.A.", "United States",
        "United States of America", "America",
    ):
        plan = recommend_le_routes(state=None, country=spelling, total_loss_usd=None)
        names = [r.name for r in plan.primary_routes]
        assert any("IC3" in n for n in names), (
            f"Country spelling {spelling!r} not routed to IC3 — got {names!r}"
        )


def test_non_us_victim_still_gets_international_fallback() -> None:
    """Don't regress the international path."""
    from recupero.worker._le_routing import recommend_le_routes
    plan = recommend_le_routes(state=None, country="Germany", total_loss_usd=None)
    names = [r.name for r in plan.primary_routes]
    assert not any("IC3" in n for n in names)
    assert any("National cybercrime" in n for n in names)


# ──────────────────────────────────────────────────────────────────────
# F5 — per-token asset description
# ──────────────────────────────────────────────────────────────────────


def test_usdt_resolved_to_stablecoin_description() -> None:
    """USDT contract gets a stablecoin description, not the Midas
    yield-bearing default."""
    from recupero.reports.brief import _resolve_asset_description
    desc = _resolve_asset_description(
        token_contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        default_description=None,
        fallback_asset_type="ERC-20 token",
    )
    assert "USD-pegged stablecoin" in desc
    assert "Tether" in desc
    assert "yield-bearing" not in desc


def test_usdc_resolved_to_stablecoin_description() -> None:
    from recupero.reports.brief import _resolve_asset_description
    desc = _resolve_asset_description(
        token_contract="0xA0b86991c6218b36c1D19D4a2e9Eb0cE3606eB48",
        default_description=None,
        fallback_asset_type="ERC-20 token",
    )
    assert "USD-pegged stablecoin" in desc
    assert "Circle" in desc


def test_unknown_token_falls_back_to_asset_type() -> None:
    from recupero.reports.brief import _resolve_asset_description
    desc = _resolve_asset_description(
        token_contract="0xdeadbeef00000000000000000000000000000000",
        default_description=None,
        fallback_asset_type="ERC-20 token",
    )
    assert desc == "ERC-20 token"


def test_issuer_supplied_description_wins() -> None:
    """If the issuer config has a hand-curated description, it
    overrides the per-token map (e.g., Midas's mSyrupUSDp)."""
    from recupero.reports.brief import _resolve_asset_description
    desc = _resolve_asset_description(
        token_contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        default_description="Hand-curated description from issuer config",
        fallback_asset_type="ERC-20 token",
    )
    assert desc == "Hand-curated description from issuer config"


# ──────────────────────────────────────────────────────────────────────
# F7 — operator-identity gate
# ──────────────────────────────────────────────────────────────────────


def test_is_investigator_configured_returns_false_when_env_unset(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_INVESTIGATOR_NAME", raising=False)
    from recupero._common import is_investigator_configured
    assert is_investigator_configured() is False


def test_is_investigator_configured_returns_true_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_INVESTIGATOR_NAME", "Jane Doe")
    from recupero._common import is_investigator_configured
    assert is_investigator_configured() is True


def test_is_investigator_configured_rejects_placeholder_value(monkeypatch) -> None:
    """If someone literally writes the placeholder string into the env
    var, treat it as unconfigured."""
    monkeypatch.setenv(
        "RECUPERO_INVESTIGATOR_NAME", "(operator name not configured)",
    )
    from recupero._common import is_investigator_configured
    assert is_investigator_configured() is False


def test_require_investigator_configured_raises_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_INVESTIGATOR_NAME", raising=False)
    from recupero._common import require_investigator_configured
    with pytest.raises(RuntimeError, match="RECUPERO_INVESTIGATOR_NAME"):
        require_investigator_configured()


def test_require_investigator_configured_passes_when_set(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_INVESTIGATOR_NAME", "Real Name")
    from recupero._common import require_investigator_configured
    require_investigator_configured()  # must not raise


# ──────────────────────────────────────────────────────────────────────
# F6 — Section 5 noise filtering (small unit-level checks; the
# end-to-end shrink-from-407-to-25 is covered by the smoke test).
# ──────────────────────────────────────────────────────────────────────


def test_burn_address_map_is_lowercase_keyed() -> None:
    """The burn address map must be lowercase-keyed so the lookup at
    render time matches regardless of input casing."""
    from recupero.reports.brief import _BURN_ADDRESSES
    for k in _BURN_ADDRESSES:
        assert k == k.lower(), f"Burn-address key {k!r} not lowercase"


def test_section_5_inclusion_floor_is_configurable_constant() -> None:
    """The USD inclusion floor is a named constant the audit cycle can
    bump as needed — not a magic number buried in a function body."""
    from recupero.reports.brief import (
        _SECTION_5_HOP_DEPTH_FLOOR,
        _SECTION_5_UNLABELED_HARD_CAP,
        _SECTION_5_USD_INCLUSION_FLOOR_DEFAULT,
    )
    assert isinstance(_SECTION_5_USD_INCLUSION_FLOOR_DEFAULT, Decimal)
    assert Decimal("0") < _SECTION_5_USD_INCLUSION_FLOOR_DEFAULT
    assert isinstance(_SECTION_5_HOP_DEPTH_FLOOR, int)
    assert isinstance(_SECTION_5_UNLABELED_HARD_CAP, int)
    assert _SECTION_5_UNLABELED_HARD_CAP >= 10


# ──────────────────────────────────────────────────────────────────────
# F2 — Issuer freeze letter PII contract (template-level check)
# ──────────────────────────────────────────────────────────────────────


def test_seed_chain_field_matches_name_chain_hint() -> None:
    """v0.30.0 audit Tier-1 (Tornado-Cash-on-BSC): the v0.29.1 sweep
    mass-stamped chain='ethereum' on every list-shape seed entry,
    including a Tornado Cash row whose name explicitly said
    "(BSC)" — the name carried the truth, the sweep didn't read it.

    This regression pins: any seed entry whose name contains a
    chain hint must have `chain` matching it. Otherwise OFAC
    sanctions intelligence misroutes — BSC funds at the BSC
    Tornado contract would be missed by an Ethereum-only query.
    """
    import json
    seeds = Path("src/recupero/labels/seeds")
    # Chain-hint suffix → required chain value
    name_chain_hints: dict[str, str] = {
        "(bsc)": "bsc",
        "(binance)": "bsc",
        "(arbitrum)": "arbitrum",
        "(optimism)": "optimism",
        "(base)": "base",
        "(polygon)": "polygon",
        "(avalanche)": "avalanche",
        "(fantom)": "fantom",
        "(tron)": "tron",
        "(solana)": "solana",
    }
    offenders: list[str] = []
    for fname in ["bridges.json", "cex_deposits.json", "defi_protocols.json", "mixers.json"]:
        path = seeds / fname
        if not path.exists():
            continue
        for entry in json.loads(path.read_text(encoding="utf-8")):
            if not isinstance(entry, dict) or "address" not in entry:
                continue
            name = str(entry.get("name", "")).lower()
            actual_chain = str(entry.get("chain", "")).lower()
            for hint, expected in name_chain_hints.items():
                if hint in name and actual_chain and actual_chain != expected:
                    offenders.append(
                        f"{fname}: {entry.get('name')!r} has chain={actual_chain!r} "
                        f"but name suggests {expected!r}"
                    )
                    break
    assert not offenders, (
        "Seed entries whose name says one chain but `chain` field says "
        "another. This is the Tornado-Cash-on-BSC class of bug "
        "(v0.30.0 audit Tier-1) — fix the chain field:\n  "
        + "\n  ".join(offenders)
    )


def test_issuer_freeze_template_omits_residential_address_block() -> None:
    """The issuer freeze letter template must NOT contain a
    `victim.address`-rendered home-address field. Compliance teams have
    no need-to-know for victim PII; the LE handoff is where that lives."""
    template = Path(
        "src/recupero/reports/templates/issuer_freeze_request.html.j2"
    ).read_text(encoding="utf-8")
    # The block we want gone: a `victim.address` rendered directly.
    # The previous template emitted exactly:
    #   {% if victim.address %}<dt>Address:</dt><dd>{{ victim.address }}
    # Look for that pattern; absence proves the PII isn't being shown.
    assert "{{ victim.address }}" not in template, (
        "Issuer freeze letter template renders victim.address — "
        "this is a PII leak to issuer compliance teams. Remove the "
        "<dt>Address:</dt><dd>{{ victim.address }}</dd> block."
    )
    assert "{{ victim.email }}" not in template, (
        "Issuer freeze letter template renders victim.email — same "
        "PII concern. Remove the <dt>Email:</dt> block."
    )
    assert "{{ victim.phone }}" not in template, (
        "Issuer freeze letter template renders victim.phone — same "
        "PII concern. Remove the <dt>Phone:</dt> block."
    )
