"""RIGOR-Jacob Z15: adversarial input hunt on payments/portal/worker plumbing.

Three concrete bugs found by hunting embed-in-format / NaN-propagation /
header-injection shapes through:

  Z15-1  payment_links.build_diagnostic_link silently accepts the format
         separator (':') inside chain / seed_address, producing a CRI
         like "diag:UUID:ethereum:fake:rest" that the dispatcher then
         mis-parses (parts[2]=ethereum, parts[3]=fake, the rest dropped).
         The downstream P-validation would mark the row audit_only, but
         the URL itself is corrupted before the customer ever clicks —
         legitimate seeds containing ':' (Solana ATA paths, future chain
         formats) silently lose data. Defense: refuse ':' at link build.

  Z15-2  payment_links accepts CRLF / NUL bytes in chain / seed_address /
         prefilled_email. URL-encoding hides them on the wire but they
         decode back on Stripe's side and could be reflected in webhook
         payloads. Defense-in-depth: refuse control characters at link
         build.

  Z15-3  _engagement_letter._fmt_usd renders Decimal('NaN') / Infinity
         as the strings '$NaN' / '$Infinity' inline in the customer's
         engagement contract.  A propagated NaN from an upstream
         aggregation lands directly in the legal letter the victim is
         asked to sign — strictly worse than a missing value.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from recupero.payments.payment_links import (
    build_diagnostic_link,
    build_engagement_link,
)
from recupero.worker._engagement_letter import _fmt_usd


# ---- Z15-1: ':' embedding in build_diagnostic_link ---- #


def test_z15_diagnostic_link_rejects_colon_in_seed_address() -> None:
    """A seed_address containing ':' (the CRI separator) silently corrupts
    the parsed dispatcher metadata. Refuse at link build."""
    with pytest.raises(ValueError, match="seed_address"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum",
            seed_address="0xdeadbeef:injected",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_diagnostic_link_rejects_colon_in_chain() -> None:
    """A chain string containing ':' is similarly format-poisoning."""
    with pytest.raises(ValueError, match="chain"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum:evil",
            seed_address="0xdeadbeef",
            base_url="https://buy.stripe.com/test",
        )


# ---- Z15-2: CRLF / NUL hardening on payment links ---- #


def test_z15_diagnostic_link_rejects_crlf_in_seed_address() -> None:
    with pytest.raises(ValueError, match="seed_address"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum",
            seed_address="0xabc\r\nevil",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_diagnostic_link_rejects_nul_in_seed_address() -> None:
    with pytest.raises(ValueError, match="seed_address"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum",
            seed_address="0xabc\x00evil",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_diagnostic_link_rejects_crlf_in_chain() -> None:
    with pytest.raises(ValueError, match="chain"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum\nfoo",
            seed_address="0xabc",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_diagnostic_link_rejects_crlf_in_prefilled_email() -> None:
    """prefilled_email lands in the Stripe Checkout's prefilled state.
    A CRLF in the value is gibberish at best — refuse at build."""
    with pytest.raises(ValueError, match="prefilled_email"):
        build_diagnostic_link(
            case_id=uuid4(),
            chain="ethereum",
            seed_address="0xabc",
            prefilled_email="victim@x.com\r\nBcc: a@b.com",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_engagement_link_rejects_crlf_in_prefilled_email() -> None:
    """Same defense on the engagement link path."""
    with pytest.raises(ValueError, match="prefilled_email"):
        build_engagement_link(
            investigation_id=uuid4(),
            prefilled_email="victim@x.com\nBcc: x@y.com",
            base_url="https://buy.stripe.com/test",
        )


def test_z15_diagnostic_link_happy_path_unchanged() -> None:
    """Sanity: the validation MUST NOT regress the canonical happy
    path — well-formed chain + 0x-style address + plain email."""
    case_id = uuid4()
    url = build_diagnostic_link(
        case_id=case_id,
        chain="ethereum",
        seed_address="0x" + "a" * 40,
        prefilled_email="victim@example.com",
        base_url="https://buy.stripe.com/test_499",
    )
    assert "client_reference_id=" in url
    assert "prefilled_email=victim%40example.com" in url


# ---- Z15-3: NaN/Infinity propagation in engagement letter $ fields ---- #


def test_z15_fmt_usd_rejects_nan() -> None:
    """A NaN propagated into total_freezable_usd / total_suspected_usd
    must NOT render as the literal string '$NaN' in the engagement
    contract. The whole point of fmt_usd_or's `fallback` arg is to
    handle non-finite inputs the same way it handles None — fall back
    to the safe default. Pre-fix this asserted '$NaN'."""
    result = _fmt_usd(Decimal("NaN"))
    assert "NaN" not in result, (
        f"_fmt_usd rendered literal NaN: {result!r} — would land in the "
        f"engagement letter as '$NaN' the customer is asked to sign"
    )


def test_z15_fmt_usd_rejects_infinity() -> None:
    """Same protection for Decimal('Infinity')."""
    result = _fmt_usd(Decimal("Infinity"))
    assert "Infinity" not in result, (
        f"_fmt_usd rendered literal Infinity: {result!r}"
    )


def test_z15_fmt_usd_happy_path_unchanged() -> None:
    """The fix MUST NOT regress finite-Decimal formatting."""
    assert _fmt_usd(Decimal("0")) == "$0.00"
    assert _fmt_usd(Decimal("1234.56")) == "$1,234.56"
    assert _fmt_usd(Decimal("10000")) == "$10,000.00"
