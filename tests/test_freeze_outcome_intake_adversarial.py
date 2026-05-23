"""RIGOR-Jacob E adversarial: lock /v1/freeze-outcomes against
input shapes that bypass FreezeOutcomeIn's validators.

The endpoint accepts money values from external integrators
(exchange compliance APIs, AUSA paralegal webhooks, operator tools).
Pre-hardening the Pydantic model trusted:

  * ``frozen_usd: float | None = Field(default=None, ge=0)``
  * ``returned_usd: float | None = Field(default=None, ge=0)``
  * ``target_address: Field(..., min_length=4, max_length=128)``

That left three concrete attack surfaces:

  1. ``frozen_usd = float('inf')`` passes ``ge=0`` and lands in
     ``Decimal(str(inf)) = Decimal('Infinity')`` which psycopg
     refuses; the row insert crashes → 500 → log spam.
  2. ``frozen_usd = 1e18`` (a quintillion USD) passes; aggregate
     "$ confirmed frozen" rolls up bogus numbers into the LE
     handoff Section 5.5. Realistic cap is the largest seizure ever
     recorded (~$3B in BTC, FBI 2022); 1e12 is a generous ceiling.
  3. ``target_address = "abcd"`` (4 chars) passes; any 4-char
     fake-address fills the DB before the recorder lookup 404s.

Locks the contract: each shape returns 422 (or fails Pydantic at
ingest), NOT a 500 / 201.
"""

from __future__ import annotations

import math

import pytest


def _build_minimal_outcome_payload(**overrides: object) -> dict[str, object]:
    """Valid baseline payload — easy to mutate one field at a time."""
    payload = {
        "case_id": "00000000-0000-0000-0000-000000000000",
        "issuer": "Coinbase",
        "target_address": "0x" + "a" * 40,
        "outcome_type": "acknowledged",
    }
    payload.update(overrides)
    return payload


def test_frozen_usd_infinity_rejected_by_pydantic() -> None:
    """RIGOR-Jacob E: float('inf') must NOT pass the FreezeOutcomeIn
    validator. Pre-fix this passed ``ge=0`` (positive infinity IS
    >= 0) and would crash psycopg on insert."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        frozen_usd=float("inf"),
    )
    try:
        FreezeOutcomeIn(**payload)
    except ValidationError:
        return  # expected
    raise AssertionError(
        "FreezeOutcomeIn accepted frozen_usd=inf — would crash on "
        "Decimal('Infinity') insert."
    )


def test_frozen_usd_nan_rejected_by_pydantic() -> None:
    """NaN is neither >= 0 nor <= 0; some FP libs accept NaN through
    ge=0 checks. Locked-out explicitly."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        frozen_usd=float("nan"),
    )
    try:
        FreezeOutcomeIn(**payload)
    except ValidationError:
        return
    raise AssertionError("FreezeOutcomeIn accepted frozen_usd=nan")


def test_returned_usd_infinity_rejected() -> None:
    """Same hardening on returned_usd."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        outcome_type="returned_to_victim",
        returned_usd=math.inf,
    )
    try:
        FreezeOutcomeIn(**payload)
    except ValidationError:
        return
    raise AssertionError("FreezeOutcomeIn accepted returned_usd=inf")


def test_frozen_usd_extreme_value_rejected() -> None:
    """A quintillion USD is not a realistic seizure. Even if Decimal
    can represent it, downstream aggregates would render absurd
    numbers in LE handoffs ("$1,000,000,000,000,000,000 confirmed
    frozen"). Bound at $1T (1e12) — generous: largest seizure ever
    was ~$3B."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        frozen_usd=1e18,
    )
    try:
        FreezeOutcomeIn(**payload)
    except ValidationError:
        return
    raise AssertionError(
        "FreezeOutcomeIn accepted frozen_usd=1e18 (a quintillion USD)"
    )


def test_frozen_usd_one_trillion_is_accepted() -> None:
    """Sanity: the cap is generous. 1 trillion USD is at the boundary
    and SHOULD be accepted (sets the cap exclusive at 1e15 = a
    quadrillion). Anything realistic is well under."""
    from recupero.api.app import FreezeOutcomeIn

    # 1 trillion should still work (largest historical seizure ~$3B).
    payload = _build_minimal_outcome_payload(frozen_usd=1_000_000_000_000)
    obj = FreezeOutcomeIn(**payload)
    assert obj.frozen_usd == 1_000_000_000_000


def test_target_address_short_string_rejected() -> None:
    """RIGOR-Jacob E: target_address must be at least the length of
    a real chain address. The shortest valid forms:

      * Bitcoin legacy P2PKH: 25 chars (base58)
      * Solana: 32 chars (base58)
      * Tron: 34 chars (base58)
      * EVM: 42 chars (0x + 40 hex)

    A 4-char address is unconditionally garbage. Reject with 422."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    for short_addr in ("a", "abc", "abcd", "0x12"):
        payload = _build_minimal_outcome_payload(target_address=short_addr)
        try:
            FreezeOutcomeIn(**payload)
        except ValidationError:
            continue
        raise AssertionError(
            f"FreezeOutcomeIn accepted target_address={short_addr!r} "
            f"(below any real chain's address length)"
        )


def test_target_address_real_btc_address_accepted() -> None:
    """Sanity: a real 25-char BTC legacy address is accepted."""
    from recupero.api.app import FreezeOutcomeIn

    # Real Bitcoin Genesis-coinbase address (25 chars base58).
    btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    payload = _build_minimal_outcome_payload(target_address=btc)
    obj = FreezeOutcomeIn(**payload)
    assert obj.target_address == btc


def test_target_address_real_evm_address_accepted() -> None:
    """Sanity: a real 42-char EVM address is accepted."""
    from recupero.api.app import FreezeOutcomeIn

    evm = "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # USDT contract
    payload = _build_minimal_outcome_payload(target_address=evm)
    obj = FreezeOutcomeIn(**payload)
    assert obj.target_address == evm


def test_response_text_rejects_null_byte() -> None:
    """RIGOR-Jacob O: response_text flows into a Postgres TEXT column;
    a null byte crashes psycopg INSERT after the API has already
    returned 201 (record_outcome's broad except returns None,
    but the API claims success). Reject null bytes at Pydantic
    parse so the failure is clean."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        response_text="Acknowledged\x00malicious",
    )
    with pytest.raises(ValidationError):
        FreezeOutcomeIn(**payload)


def test_operator_notes_rejects_null_byte() -> None:
    """Same on operator_notes."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    payload = _build_minimal_outcome_payload(
        operator_notes="Note\x00poison",
    )
    with pytest.raises(ValidationError):
        FreezeOutcomeIn(**payload)


def test_response_text_rejects_bidi_override() -> None:
    """Trojan-Source defense. A response_text with bidi override
    chars renders ambiguously in operator triage UIs + LE handoff
    Section 5.5."""
    from pydantic import ValidationError

    from recupero.api.app import FreezeOutcomeIn

    # U+202E (RIGHT-TO-LEFT OVERRIDE)
    payload = _build_minimal_outcome_payload(
        response_text="Frozen ‮1000000 USDT",
    )
    with pytest.raises(ValidationError):
        FreezeOutcomeIn(**payload)


def test_response_text_legitimate_text_accepted() -> None:
    """Sanity: hardening must not block legit response text including
    non-Latin scripts."""
    from recupero.api.app import FreezeOutcomeIn

    for legit in (
        "Acknowledged. Funds frozen pending court order.",
        "已确认。资金已冻结，等待法院命令。",  # Chinese
        "Frozen $1,234.56 USDT.",
    ):
        payload = _build_minimal_outcome_payload(response_text=legit)
        obj = FreezeOutcomeIn(**payload)
        assert obj.response_text == legit
