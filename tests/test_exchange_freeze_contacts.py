"""Freeze-track P0 foundation — exchange FREEZE contact resolution.

Pins the trust/safety contract of the user-fillable override layer:
  * the shipped seed file parses and contains NO falsely-"verified" entry;
  * a verified override wins over the unverified starter contact;
  * a verified override that lacks a channel/source is downgraded (never
    shipped as verified) — so a seed-file typo degrades safely;
  * unknown exchanges resolve to None (we never invent a contact);
  * known starter exchanges resolve UNVERIFIED (operator must confirm).
"""

from __future__ import annotations

import json

from recupero.freeze.exchange_contacts import (
    _OVERRIDES_PATH,
    ExchangeFreezeContact,
    load_exchange_freeze_overrides,
    resolve_exchange_freeze_contact,
)


def test_seed_file_parses_and_has_no_false_verified() -> None:
    """The committed seed file must be valid JSON and must not ship any entry
    that claims verified=true without a real channel + source."""
    raw = json.loads(_OVERRIDES_PATH.read_text(encoding="utf-8-sig"))
    assert isinstance(raw, dict)
    for key, entry in raw.items():
        if key.startswith("_"):
            continue  # documentation keys
        assert isinstance(entry, dict), key
        if entry.get("verified"):
            has_channel = bool(entry.get("compliance_email") or entry.get("le_portal_url"))
            assert has_channel and entry.get("source"), (
                f"seed entry {key!r} is verified=true but lacks a channel/source"
            )


def test_unknown_exchange_resolves_to_none() -> None:
    assert resolve_exchange_freeze_contact("Definitely Not A Real Exchange XYZ") is None
    assert resolve_exchange_freeze_contact("") is None
    assert resolve_exchange_freeze_contact("   ") is None


def test_known_starter_exchange_is_unverified() -> None:
    """An exchange present only in the unverified starter dict resolves to an
    UNVERIFIED contact (so the letter flags 'confirm before sending').

    Uses 'BTC Markets', which is intentionally NOT in the verified override
    seed, so it exercises the starter-dict fallback path. (Binance et al. now
    ship verified overrides — see test_seed_verified_entries_resolve.)"""
    c = resolve_exchange_freeze_contact("BTC Markets")
    assert isinstance(c, ExchangeFreezeContact)
    assert c.verified is False
    assert c.freeze_capability == "unknown"
    # case/space-insensitive
    assert resolve_exchange_freeze_contact("  bTc MaRkEtS ") is not None


def test_seed_verified_entries_resolve() -> None:
    """The shipped seed's high-confidence entries resolve as VERIFIED contacts
    carrying a real channel + a source (so the freeze letter omits the
    UNVERIFIED banner and cites the channel). Locks the v0.39 freeze-contact DB
    — each entry was confirmed against the exchange's own published LE page."""
    for name in ("Binance", "Coinbase", "Kraken", "OKX", "Crypto.com",
                 "KuCoin", "Gate.io", "Bitget", "Bitfinex", "MEXC", "Robinhood"):
        c = resolve_exchange_freeze_contact(name)
        assert isinstance(c, ExchangeFreezeContact), name
        assert c.verified is True, name
        assert c.has_channel, name
        assert c.source, name
        assert c.freeze_capability in ("yes", "limited"), name


def test_seed_medium_confidence_entries_unverified_but_populated() -> None:
    """Gemini/Bitstamp/Bybit are populated from research but kept verified=False
    (confirm-before-send): the letter still shows the UNVERIFIED banner. They
    carry a source so they're a better starting point than the bare starter
    pattern guess, without overclaiming a confirmed channel."""
    for name in ("Gemini", "Bitstamp", "Bybit"):
        c = resolve_exchange_freeze_contact(name)
        assert isinstance(c, ExchangeFreezeContact), name
        assert c.verified is False, name
        assert c.source, name


def test_verified_override_wins() -> None:
    overrides = load_exchange_freeze_overrides()  # baseline (committed, no real entries)
    overrides = dict(overrides)
    overrides["binance"] = {
        "name": "Binance",
        "legal_name": "Binance Holdings Ltd.",
        "compliance_email": "le@binance.example",
        "le_portal_url": "https://le.binance.example",
        "freeze_capability": "yes",
        "freeze_request_channel": "portal",
        "verified": True,
        "source": "test fixture",
        "notes": None,
    }
    c = resolve_exchange_freeze_contact("Binance", overrides=overrides)
    assert c is not None
    assert c.verified is True
    assert c.freeze_capability == "yes"
    assert c.le_portal_url == "https://le.binance.example"
    assert c.has_channel is True


def test_loader_downgrades_verified_without_channel_or_source(tmp_path) -> None:
    """A verified=true entry missing a channel/source must be downgraded to
    unverified by the loader (defense against seed-file mistakes)."""
    p = tmp_path / "ex.json"
    p.write_text(
        json.dumps({
            "_README": "doc key ignored",
            "NoChannel": {
                "legal_name": "No Channel Exchange",
                "compliance_email": None,
                "le_portal_url": None,
                "freeze_capability": "yes",
                "verified": True,
                "source": "someone said so",
            },
            "NoSource": {
                "legal_name": "No Source Exchange",
                "compliance_email": "le@nosource.example",
                "freeze_capability": "yes",
                "verified": True,
                "source": None,
            },
        }),
        encoding="utf-8",
    )
    ov = load_exchange_freeze_overrides(path=p)
    assert ov["nochannel"]["verified"] is False
    assert ov["nosource"]["verified"] is False


def test_missing_file_returns_empty(tmp_path) -> None:
    assert load_exchange_freeze_overrides(path=tmp_path / "does_not_exist.json") == {}
