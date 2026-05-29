"""RIGOR-Jacob Z10: adversarial-input hardening across the freeze
learning recorder + dormant detector + freeze.asks surfaces.

Threat models tested here:

  1. ``record_outcome`` / ``record_outcome_by_target`` are invoked
     from the operator CLI (``recupero-ops record-freeze-outcome``)
     with operator-typed strings — null bytes, BOM, bidi controls
     — that bypass the API-layer ``FreezeOutcomeIn`` validator. The
     CLI passes ``args.note`` straight through. A row containing a
     ``\\x00`` byte hits the DB insert and either crashes psycopg
     mid-transaction (corrupting downstream state) or, on systems
     that silently strip nulls, produces an off-by-one ``operator_notes``
     value the operator can't reproduce. Defense-in-depth: validate
     in the recorder itself so the contract is identical regardless
     of which call site (CLI vs API) triggered the write.

  2. ``record_outcome`` accepts ``Decimal('NaN')`` and
     ``Decimal('Infinity')`` for ``frozen_usd`` / ``returned_usd``.
     The CLI shim does ``Decimal(args.frozen_usd)`` directly — both
     ``"NaN"`` and ``"Infinity"`` are valid ``Decimal`` constructors.
     The API rejects these at the Pydantic layer (``RIGOR-Jacob E``)
     but the recorder is a separate entry point. Aggregations like
     ``compute_priors_from_outcomes`` and the LE handoff Section 5.5
     would otherwise consume the bogus value.

  3. ``dormant.finder._check_one_address`` aggregates ``total_usd``
     across per-token holdings via ``sum(h.usd_value, ...)``. A
     ``Decimal('NaN')`` price (corrupted ``price_now`` cache —
     ``RIGOR-Jacob F`` only hardened the ``price_at`` cache path)
     propagates into the aggregate. ``NaN < min_usd`` is False, so
     the candidate is NOT filtered out; ``DormantCandidate.total_usd``
     becomes NaN, threads into ``FreezeAsk.__post_init__`` which
     raises ``ValueError`` mid-brief generation — a denial-of-service
     on the freeze brief from an attacker-controlled token contract.
     Guard at the dormant-detector boundary.

Each test asserts the post-fix invariant: bad shape is rejected with
a clear ``ValueError``, NOT silently propagated downstream.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

# ---------- Bug 1: record_outcome free-text trojan validation ---------- #


def test_record_outcome_rejects_null_byte_in_operator_notes() -> None:
    """RIGOR-Jacob Z10: a null byte in ``operator_notes`` must be
    rejected at the recorder layer.

    Trigger: operator runs
        recupero-ops record-freeze-outcome --note "bad\\x00note" ...
    The CLI does NOT scrub ``args.note``; it passes the raw string
    straight into ``record_outcome``. Pre-fix this hit psycopg's TEXT
    insert which either errors out (aborting the transaction) or
    silently truncates at the null — both bad outcomes. Post-fix:
    raise ``ValueError`` at the recorder boundary with a clear message,
    so the CLI surfaces it as a user-visible error.
    """
    from recupero.freeze_learning.recorder import record_outcome

    with pytest.raises(ValueError, match="(null|control|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="acknowledged",
            operator_notes="legit prefix\x00trailing-after-null",
            dsn="postgresql://nope",  # never reached
        )


def test_record_outcome_rejects_bidi_in_response_text() -> None:
    """Bidi RLO + LRO chars in ``response_text`` render as Trojan-
    Source spoofs in the operator triage UI and LE handoff Section 5.5.
    The API endpoint already rejects these (FreezeOutcomeIn
    ``_reject_text_trojans``); the recorder must too, since the CLI
    bypasses the Pydantic layer entirely.
    """
    from recupero.freeze_learning.recorder import record_outcome

    bidi_payload = "compliance says: ‮froze 100k‬ — see attached"
    with pytest.raises(ValueError, match="(bidi|spoof|Unicode|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="full_freeze",
            response_text=bidi_payload,
            dsn="postgresql://nope",
        )


def test_record_outcome_rejects_zero_width_invisible_in_notes() -> None:
    """Zero-width joiner / non-joiner / space chars don't print but
    affect ``\\b`` boundaries, search/replace, and downstream LE-handoff
    grep tools. Cf. CVE-2021-42574 (Trojan Source)."""
    from recupero.freeze_learning.recorder import record_outcome

    zwsp = "frozen amount: 100​USDC"  # zero-width space mid-number
    with pytest.raises(ValueError, match="(zero[- ]?width|invisible|spoof|Unicode|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="partial_freeze",
            operator_notes=zwsp,
            dsn="postgresql://nope",
        )


def test_record_outcome_by_target_rejects_null_byte_in_notes() -> None:
    """``record_outcome_by_target`` is the v0.21.0 case-scoped path
    used by both the API endpoint and the CLI's
    ``--case/--issuer/--target-address`` form. Same hardening as
    ``record_outcome`` — the contract is identical regardless of
    which lookup shape the caller uses.
    """
    from recupero.freeze_learning.recorder import record_outcome_by_target

    with pytest.raises(ValueError, match="(null|control|invalid)"):
        record_outcome_by_target(
            case_id=uuid4(),
            issuer="Tether",
            target_address="0x" + "a" * 40,
            outcome_type="acknowledged",
            operator_notes="bad\x00data",
            dsn="postgresql://nope",
        )


# ---------- Bug 2: record_outcome NaN/Infinity USD ---------- #


def test_record_outcome_rejects_decimal_nan_frozen_usd() -> None:
    """RIGOR-Jacob Z10: ``Decimal('NaN')`` for ``frozen_usd`` must be
    rejected at the recorder boundary.

    Trigger: operator CLI runs ``record-freeze-outcome --frozen-usd NaN``.
    The CLI does ``_Decimal(args.frozen_usd)`` directly and
    ``Decimal('NaN')`` is a perfectly valid Decimal. Pre-fix this
    flowed into psycopg's NUMERIC insert (a corrupt row), and into
    ``compute_priors_from_outcomes`` aggregations. The API layer
    has equivalent rejection in ``FreezeOutcomeIn._reject_non_finite_usd``
    — the recorder needs parity for the CLI bypass.
    """
    from recupero.freeze_learning.recorder import record_outcome

    with pytest.raises(ValueError, match="(finite|NaN|Infinity|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="full_freeze",
            frozen_usd=Decimal("NaN"),
            dsn="postgresql://nope",
        )


def test_record_outcome_rejects_decimal_infinity_returned_usd() -> None:
    """``Decimal('Infinity')`` for ``returned_usd`` — same threat as
    NaN; would render as "$Infinity returned to victim" in legal
    documents."""
    from recupero.freeze_learning.recorder import record_outcome

    with pytest.raises(ValueError, match="(finite|NaN|Infinity|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="returned_to_victim",
            returned_usd=Decimal("Infinity"),
            dsn="postgresql://nope",
        )


def test_record_outcome_rejects_negative_decimal_frozen_usd() -> None:
    """Negative ``frozen_usd`` is operator-typo or hostile input.
    "Frozen -$5,000" is a sign error that should fail at the boundary
    rather than land in the LE handoff."""
    from recupero.freeze_learning.recorder import record_outcome

    with pytest.raises(ValueError, match="(negative|>=|invalid)"):
        record_outcome(
            letter_id=uuid4(),
            outcome_type="partial_freeze",
            frozen_usd=Decimal("-5000.00"),
            dsn="postgresql://nope",
        )


def test_record_outcome_by_target_rejects_nan_frozen_usd() -> None:
    """The case-scoped recorder must reject NaN frozen_usd before the
    letter lookup happens — fail fast on the input rather than after a
    DB round-trip."""
    from recupero.freeze_learning.recorder import record_outcome_by_target

    with pytest.raises(ValueError, match="(finite|NaN|Infinity|invalid)"):
        record_outcome_by_target(
            case_id=uuid4(),
            issuer="Circle",
            target_address="0x" + "b" * 40,
            outcome_type="full_freeze",
            frozen_usd=Decimal("NaN"),
            dsn="postgresql://nope",
        )


def test_record_outcome_accepts_legitimate_values() -> None:
    """Sanity guard: the new validators must NOT reject legitimate
    inputs. A normal Decimal + plain notes + ascii response text
    should pass the pre-DB validation and then fail only on the DB
    side (which is the existing behaviour). We assert the DB-side
    failure path is reached by checking that no ValueError is raised
    on the inputs themselves.
    """
    from recupero.freeze_learning.recorder import record_outcome

    # ``dsn="postgresql://nope"`` triggers a DB connection failure
    # inside ``record_outcome``; the function swallows it and returns
    # None. The point of the test: we must hit that DB-failure code
    # path, NOT a ValueError on the inputs.
    result = record_outcome(
        letter_id=uuid4(),
        outcome_type="acknowledged",
        frozen_usd=Decimal("100000.00"),
        returned_usd=None,
        response_text="Standard compliance acknowledgement. Frozen 100k USDC.",
        operator_notes="Received from Tether legal 2026-05-21 — case progressing.",
        dsn="postgresql://nope",
    )
    # DB failure path returned None — that's fine. The point is no
    # ValueError was raised on the input shapes.
    assert result is None or isinstance(result, type(uuid4()))


# ---------- Bug 3: dormant finder NaN/Inf in usd_value ---------- #


def test_check_one_address_drops_holdings_with_nan_usd() -> None:
    """RIGOR-Jacob Z10: a ``Decimal('NaN')`` ``usd_value`` from the
    pricing layer must NOT contaminate the dormant aggregate.

    Trigger: the ``price_now`` cache (used by dormant detection) is
    NOT hardened against ``{"usd": "NaN"}`` corruption — only the
    ``price_at`` cache is (RIGOR-Jacob F). An attacker-controlled
    token contract whose first lookup poisoned the cache, or simple
    disk corruption, returns ``Decimal('NaN')`` from
    ``price_client.price_now(token)``. Pre-fix this propagates
    through ``_fetch_holdings`` → ``_check_one_address.total_usd``
    (NaN), then ``total_usd < min_usd`` is False (NaN comparison),
    so the candidate IS NOT filtered. The NaN threads into
    ``DormantCandidate.total_usd`` and lands in
    ``FreezeAsk.__post_init__`` which raises ``ValueError`` mid-brief.

    Post-fix: ``_check_one_address`` filters non-finite ``usd_value``
    holdings before aggregation. The candidate passes through with
    only the finite holdings counted.
    """
    from recupero.dormant.finder import (
        _check_one_address,
    )
    from recupero.models import Chain, TokenRef

    # Build the minimal token/holdings setup we'll inject.
    nan_token = TokenRef(
        chain=Chain.ethereum,
        contract="0x" + "c" * 40,
        symbol="EVIL",
        decimals=18,
    )
    good_token = TokenRef(
        chain=Chain.ethereum,
        contract="0x" + "d" * 40,
        symbol="USDC",
        decimals=6,
    )

    # Fake adapter that returns raw=1 for both tokens (and 0 native).
    class _FakeClient:
        def get_token_balance(self, contract: str, address: str) -> int:
            return 10**18  # 1 token in raw units (works for both decimals)

        def get_eth_balance(self, address: str) -> int:
            return 0  # no native dust to confuse the test

    class _FakeAdapter:
        client = _FakeClient()

        def explorer_address_url(self, address: str) -> str:
            return f"https://etherscan.io/address/{address}"

    # Price client: NaN for the evil token, finite for USDC.
    from recupero.pricing.coingecko import PriceResult

    class _FakePriceClient:
        def price_now(self, token: TokenRef) -> PriceResult:
            if token.symbol == "EVIL":
                return PriceResult(
                    usd_value=Decimal("NaN"),
                    source="cache_poisoned",
                    error=None,
                )
            # USDC → $1 each, so the holding (1 token at 18 decimals
            # but priced as $1) is large enough to clear the threshold.
            return PriceResult(usd_value=Decimal("1.00"), source="par", error=None)

        def close(self) -> None:
            pass

    # min_usd=Decimal("0.5") so a single $1 holding clears; the NaN
    # holding would have dominated absurdly without the fix.
    cand = _check_one_address(
        address="0x" + "e" * 40,
        tokens=[nan_token, good_token],
        adapter=_FakeAdapter(),
        price_client=_FakePriceClient(),
        chain=Chain.ethereum,
        min_usd=Decimal("0.5"),
        inflow_usd=Decimal("1000"),
        inflow_count=1,
    )

    # Either:
    #   * the candidate is None because the NaN holding was dropped
    #     and the remaining finite total ($1.00 from USDC's "1e18 raw
    #     → 1e12 decimal scaled" — but USDC is 6 decimals so raw=10^18
    #     → decimal_amount=10^12, which clears any sane threshold), OR
    #   * the candidate has total_usd that is finite (NaN was filtered).
    # The hard requirement: if a candidate is returned, total_usd
    # MUST be finite. NaN must never propagate.
    assert cand is None or cand.total_usd.is_finite(), (
        f"dormant candidate carried non-finite total_usd: {cand.total_usd!r}"
    )


def test_check_one_address_drops_holdings_with_infinity_usd() -> None:
    """Same threat shape as NaN, with ``Decimal('Infinity')`` — a
    poisoned cache writing ``{"usd": "Infinity"}`` produces a Decimal
    that passes ``> 0`` checks but renders as ``$Infinity`` in the
    brief. Filter at the dormant-detector boundary."""
    from recupero.dormant.finder import _check_one_address
    from recupero.models import Chain, TokenRef
    from recupero.pricing.coingecko import PriceResult

    bad_token = TokenRef(
        chain=Chain.ethereum,
        contract="0x" + "f" * 40,
        symbol="BADINF",
        decimals=18,
    )

    class _FakeClient:
        def get_token_balance(self, contract: str, address: str) -> int:
            return 10**18

        def get_eth_balance(self, address: str) -> int:
            return 0

    class _FakeAdapter:
        client = _FakeClient()

        def explorer_address_url(self, address: str) -> str:
            return f"https://etherscan.io/address/{address}"

    class _FakePriceClient:
        def price_now(self, token: TokenRef) -> PriceResult:
            return PriceResult(
                usd_value=Decimal("Infinity"),
                source="cache_poisoned",
                error=None,
            )

        def close(self) -> None:
            pass

    cand = _check_one_address(
        address="0x" + "1" * 40,
        tokens=[bad_token],
        adapter=_FakeAdapter(),
        price_client=_FakePriceClient(),
        chain=Chain.ethereum,
        min_usd=Decimal("10000"),
        inflow_usd=Decimal("1000"),
        inflow_count=1,
    )

    # The Infinity holding must be filtered. Either the candidate is
    # None (filtered below min_usd) or its total_usd is finite.
    assert cand is None or cand.total_usd.is_finite(), (
        f"dormant candidate carried non-finite total_usd: {cand.total_usd!r}"
    )
