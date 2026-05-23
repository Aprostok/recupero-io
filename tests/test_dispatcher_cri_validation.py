"""RIGOR-Jacob P: dispatcher CRI (client_reference_id) input validation.

Stripe's ``client_reference_id`` is set by the CUSTOMER when they
load the Checkout page — Stripe forwards it verbatim into the
webhook payload. Our Payment Link URL is operator-generated, but
an attacker who knows the URL (or guesses the product code from
the Stripe Dashboard) can construct a custom Checkout session with
any ``client_reference_id`` value.

The dispatcher's ``_handle_diagnostic`` pulls ``chain`` and
``seed_address`` from the parsed CRI metadata and INSERTs them
into the investigations row WITHOUT validation. Two attack shapes:

  1. ``chain = "javascript_chain"`` (or any other non-supported
     chain name). Worker instantiates ``ChainAdapter.for_chain(...)``
     → NotImplementedError → row stuck in pending state, retried
     by reaper repeatedly, polluting the operations dashboard.

  2. ``seed_address = "<arbitrary>"`` (not validated for shape).
     Garbage in the investigations.seed_address column; downstream
     trace pipeline fails; operator triage UI shows misleading
     data.

Lock the contract: ``_handle_diagnostic`` validates chain against
the supported enum AND seed_address against a per-chain shape
before INSERTing. On validation failure, returns audit_only with a
clear notes message — same shape as the other defensive branches.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4


def _build_cur(case_row: dict | None = None):
    """Construct a MagicMock cursor that fakes the existing-case +
    no-existing-investigation lookups so _handle_diagnostic reaches
    the INSERT branch."""
    cur = MagicMock()
    cur.fetchone.side_effect = [
        case_row or {"id": uuid4(), "case_number": "CASE-001"},
        None,  # no existing investigation
    ]
    return cur


def test_diagnostic_rejects_unsupported_chain() -> None:
    """A chain value not in the supported set must NOT land in the
    investigations row."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    cur = _build_cur()
    obj = {
        "metadata": {
            "chain": "javascript_chain",  # ← bogus
            "seed_address": "0x" + "a" * 40,
        },
        "client_reference_id": "",
    }
    action, inv_id, notes = _handle_diagnostic(cur, case_uuid, 49900, obj)

    assert action == "audit_only", (
        f"Bogus chain accepted into investigations table! Got "
        f"action={action!r}, notes={notes!r}"
    )
    # The investigations INSERT should NOT have been called.
    insert_calls = [
        c for c in cur.execute.call_args_list
        if "INSERT INTO public.investigations" in (c.args[0] if c.args else "")
    ]
    assert not insert_calls, (
        f"Bogus chain triggered an INSERT into investigations: "
        f"{insert_calls!r}"
    )


def test_diagnostic_rejects_malformed_seed_address() -> None:
    """seed_address shape isn't enforced — a non-address string
    pollutes the DB."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    cur = _build_cur()
    obj = {
        "metadata": {
            "chain": "ethereum",
            "seed_address": "<arbitrary-garbage-here>",
        },
        "client_reference_id": "",
    }
    action, inv_id, notes = _handle_diagnostic(cur, case_uuid, 49900, obj)

    assert action == "audit_only", (
        f"Garbage seed_address accepted! action={action!r}, notes={notes!r}"
    )
    insert_calls = [
        c for c in cur.execute.call_args_list
        if "INSERT INTO public.investigations" in (c.args[0] if c.args else "")
    ]
    assert not insert_calls


def test_diagnostic_rejects_seed_address_with_null_byte() -> None:
    """Null bytes in seed_address crash psycopg TEXT inserts at the
    investigations row level. Reject up-front."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    cur = _build_cur()
    obj = {
        "metadata": {
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 38 + "\x00\x00",
        },
        "client_reference_id": "",
    }
    action, inv_id, notes = _handle_diagnostic(cur, case_uuid, 49900, obj)
    assert action == "audit_only"


def test_diagnostic_accepts_valid_inputs() -> None:
    """Sanity: legitimate chain + EVM address still INSERTs."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    case_row = {"id": case_uuid, "case_number": "CASE-001"}
    cur = _build_cur(case_row)
    obj = {
        "metadata": {
            "chain": "ethereum",
            "seed_address": "0x" + "a" * 40,
        },
        "client_reference_id": "",
    }
    action, inv_id, notes = _handle_diagnostic(cur, case_uuid, 49900, obj)

    assert action == "investigation_created"
    insert_calls = [
        c for c in cur.execute.call_args_list
        if "INSERT INTO public.investigations" in (c.args[0] if c.args else "")
    ]
    assert insert_calls, "Valid input should INSERT the investigation row"


def test_diagnostic_accepts_solana_address() -> None:
    """Cross-chain support: Solana base58 address (32-44 chars) for
    a Solana chain."""
    from recupero.payments.dispatcher import _handle_diagnostic

    case_uuid = uuid4()
    case_row = {"id": case_uuid, "case_number": "CASE-002"}
    cur = _build_cur(case_row)
    obj = {
        "metadata": {
            "chain": "solana",
            "seed_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        },
        "client_reference_id": "",
    }
    action, inv_id, notes = _handle_diagnostic(cur, case_uuid, 49900, obj)
    assert action == "investigation_created", (
        f"Legit Solana case rejected: action={action!r}, notes={notes!r}"
    )
