"""Tests for the Stripe Payment Link URL builder + dispatcher
client_reference_id parsing.

The URL builder is half of the round-trip:
    operator → URL with client_reference_id → customer pays
        → Stripe webhook → dispatcher parses → workflow advances.

The parsing logic on the receive side lives in
recupero.payments.dispatcher; we test the two halves together
in this file so the encoding ↔ decoding contract is locked in
one place.
"""

from __future__ import annotations

import urllib.parse
from uuid import UUID, uuid4

import pytest

from recupero.payments.dispatcher import (
    _merge_metadata_sources,
    _parse_client_reference_id,
)
from recupero.payments.payment_links import (
    PaymentLinkConfigError,
    build_diagnostic_link,
    build_engagement_link,
)


# ---- _parse_client_reference_id ---- #


def test_parse_diagnostic_cri() -> None:
    """The diag: prefix yields a metadata-shaped dict with the
    type, case_id, chain, and seed_address all populated."""
    case_id = uuid4()
    out = _parse_client_reference_id(
        f"diag:{case_id}:ethereum:0xabc123def456",
    )
    assert out == {
        "type": "diagnostic",
        "case_id": str(case_id),
        "chain": "ethereum",
        "seed_address": "0xabc123def456",
    }


def test_parse_engagement_cri() -> None:
    """The eng: prefix yields a metadata-shaped dict with type and
    investigation_id."""
    inv_id = uuid4()
    out = _parse_client_reference_id(f"eng:{inv_id}")
    assert out == {
        "type": "engagement",
        "investigation_id": str(inv_id),
    }


def test_parse_empty_returns_empty() -> None:
    """No client_reference_id → empty dict, not error. The dispatcher
    degrades to audit-only in that case."""
    assert _parse_client_reference_id("") == {}


def test_parse_unknown_prefix_returns_empty() -> None:
    """Prefix isn't 'diag' or 'eng' (e.g., 'subscription:abc') →
    empty. The dispatcher logs an unrecognized payment in audit."""
    assert _parse_client_reference_id("subscription:abc") == {}


def test_parse_truncated_diag_returns_empty() -> None:
    """`diag:` without the rest of the parts → empty. We require
    all 4 fields (type, case_id, chain, seed_address) so we don't
    fabricate partial state."""
    case_id = uuid4()
    assert _parse_client_reference_id(f"diag:{case_id}:ethereum") == {}
    assert _parse_client_reference_id(f"diag:{case_id}") == {}
    assert _parse_client_reference_id("diag:") == {}


def test_parse_truncated_eng_returns_empty() -> None:
    """`eng:` without the UUID → empty."""
    assert _parse_client_reference_id("eng:") == {}


def test_parse_is_case_insensitive_on_prefix() -> None:
    """Stripe might mangle case in some edge paths (it doesn't but
    defensive). We accept Diag: / DIAG: / diag: identically."""
    case_id = uuid4()
    for prefix in ("diag", "Diag", "DIAG"):
        out = _parse_client_reference_id(
            f"{prefix}:{case_id}:ethereum:0xabc",
        )
        assert out["type"] == "diagnostic"


# ---- _merge_metadata_sources ---- #


def test_merge_metadata_wins_over_cri() -> None:
    """When both metadata.* and client_reference_id are set,
    metadata wins. The Dashboard-baked type is more authoritative
    than the URL-parametrized form (which a clever customer could
    have hand-edited)."""
    case_id = uuid4()
    out = _merge_metadata_sources(
        metadata_dict={"type": "engagement", "investigation_id": "xyz"},
        client_reference_id=f"diag:{case_id}:ethereum:0xabc",
    )
    # metadata.type wins
    assert out["type"] == "engagement"
    # metadata.investigation_id wins
    assert out["investigation_id"] == "xyz"
    # client_reference_id-derived fields that AREN'T in metadata
    # still fill in (case_id, chain, seed_address aren't in metadata).
    assert out.get("case_id") == str(case_id)


def test_merge_cri_fills_in_when_metadata_empty() -> None:
    """Payment Link path: metadata is empty, all info comes from
    client_reference_id. The merged dict carries the parsed values."""
    case_id = uuid4()
    out = _merge_metadata_sources(
        metadata_dict={},
        client_reference_id=f"diag:{case_id}:ethereum:0xabc",
    )
    assert out["type"] == "diagnostic"
    assert out["case_id"] == str(case_id)


def test_merge_empty_inputs_yields_empty() -> None:
    """No data anywhere → empty dict. Dispatcher's audit-only path
    takes over."""
    assert _merge_metadata_sources(
        metadata_dict={}, client_reference_id="",
    ) == {}


def test_merge_strips_empty_metadata_values() -> None:
    """metadata.investigation_id = '' shouldn't shadow a populated
    client_reference_id value. The merge skips empty/None values
    in the metadata overlay."""
    case_id = uuid4()
    out = _merge_metadata_sources(
        metadata_dict={"type": "diagnostic", "case_id": ""},
        client_reference_id=f"diag:{case_id}:ethereum:0xabc",
    )
    # metadata.case_id was empty → client_reference_id's value wins
    assert out["case_id"] == str(case_id)


# ---- build_diagnostic_link ---- #


def test_build_diagnostic_link_happy_path(monkeypatch) -> None:
    """Given a configured base URL + valid params → a parameterized
    URL with client_reference_id encoded in our format."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK",
        "https://buy.stripe.com/test_diag",
    )
    case_id = uuid4()
    url = build_diagnostic_link(
        case_id=case_id, chain="ethereum",
        seed_address="0xABCdef1234567890",
        prefilled_email="victim@example.com",
    )
    parsed = urllib.parse.urlsplit(url)
    assert parsed.netloc == "buy.stripe.com"
    assert parsed.path == "/test_diag"
    qs = dict(urllib.parse.parse_qsl(parsed.query))
    assert qs["client_reference_id"] == (
        f"diag:{case_id}:ethereum:0xABCdef1234567890"
    )
    assert qs["prefilled_email"] == "victim@example.com"


def test_build_diagnostic_link_normalizes_chain() -> None:
    """chain is lowercased before encoding so 'Ethereum' and
    'ETHEREUM' produce the same client_reference_id."""
    case_id = uuid4()
    url = build_diagnostic_link(
        case_id=case_id, chain="Ethereum",
        seed_address="0xabc", base_url="https://buy.stripe.com/x",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert qs["client_reference_id"].endswith(":ethereum:0xabc")


def test_build_diagnostic_link_requires_seed_address() -> None:
    """Empty seed_address → ValueError. The CLI catches this and
    surfaces a 'required' error."""
    with pytest.raises(ValueError, match="seed_address"):
        build_diagnostic_link(
            case_id=uuid4(), chain="ethereum", seed_address="",
            base_url="https://buy.stripe.com/x",
        )


def test_build_diagnostic_link_raises_when_unconfigured(monkeypatch) -> None:
    """Neither base_url kwarg nor env var → PaymentLinkConfigError
    with a clear message pointing at the env var to set."""
    monkeypatch.delenv("RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK", raising=False)
    with pytest.raises(PaymentLinkConfigError, match="DIAGNOSTIC"):
        build_diagnostic_link(
            case_id=uuid4(), chain="ethereum", seed_address="0xabc",
        )


def test_build_diagnostic_link_preserves_existing_query_params() -> None:
    """Operator's Stripe Dashboard URL may already carry query params
    (utm_source, locale, etc.). We append ours without dropping theirs."""
    url = build_diagnostic_link(
        case_id=uuid4(), chain="ethereum", seed_address="0xabc",
        base_url="https://buy.stripe.com/x?locale=en&utm=email",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert qs.get("locale") == "en"
    assert qs.get("utm") == "email"
    assert "client_reference_id" in qs


# ---- build_engagement_link ---- #


def test_build_engagement_link_happy_path(monkeypatch) -> None:
    """eng:<inv_id> in client_reference_id, optional email pre-fill."""
    monkeypatch.setenv(
        "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK",
        "https://buy.stripe.com/test_eng",
    )
    inv_id = uuid4()
    url = build_engagement_link(
        investigation_id=inv_id, prefilled_email="victim@example.com",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert qs["client_reference_id"] == f"eng:{inv_id}"
    assert qs["prefilled_email"] == "victim@example.com"


def test_build_engagement_link_raises_when_unconfigured(monkeypatch) -> None:
    """Engagement env var unset → typed error."""
    monkeypatch.delenv("RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK", raising=False)
    with pytest.raises(PaymentLinkConfigError, match="ENGAGEMENT"):
        build_engagement_link(investigation_id=uuid4())


def test_build_engagement_link_email_optional() -> None:
    """prefilled_email is optional. Without it, the URL still has a
    valid client_reference_id; the customer types their email at
    checkout."""
    url = build_engagement_link(
        investigation_id=uuid4(),
        base_url="https://buy.stripe.com/x",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert "client_reference_id" in qs
    assert "prefilled_email" not in qs


# ---- Round-trip ---- #


def test_round_trip_diagnostic() -> None:
    """Build a diagnostic URL → extract client_reference_id from
    the URL → feed it through the dispatcher parser → get back
    the same fields we put in. Locks the encoding ↔ decoding
    contract."""
    case_id = uuid4()
    chain = "arbitrum"
    seed = "0xDeadBeef00000000000000000000000000000000"

    url = build_diagnostic_link(
        case_id=case_id, chain=chain, seed_address=seed,
        base_url="https://buy.stripe.com/x",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    parsed = _parse_client_reference_id(qs["client_reference_id"])
    assert parsed == {
        "type": "diagnostic",
        "case_id": str(case_id),
        "chain": chain,
        "seed_address": seed,
    }


def test_round_trip_engagement() -> None:
    inv_id = uuid4()
    url = build_engagement_link(
        investigation_id=inv_id, base_url="https://buy.stripe.com/x",
    )
    qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    parsed = _parse_client_reference_id(qs["client_reference_id"])
    assert parsed == {
        "type": "engagement",
        "investigation_id": str(inv_id),
    }


def test_round_trip_survives_url_encoding() -> None:
    """The encoded URL goes through email clients that aggressively
    URL-decode and re-encode; the round-trip should survive that.
    Manually URL-encode the client_reference_id and confirm the
    parser still gets the right fields."""
    case_id = uuid4()
    cri = f"diag:{case_id}:ethereum:0xabc"
    # Worst case: %3A-encoded colons (some email clients do this)
    encoded = urllib.parse.quote(cri, safe="")
    decoded = urllib.parse.unquote(encoded)
    assert _parse_client_reference_id(decoded) == {
        "type": "diagnostic",
        "case_id": str(case_id),
        "chain": "ethereum",
        "seed_address": "0xabc",
    }
