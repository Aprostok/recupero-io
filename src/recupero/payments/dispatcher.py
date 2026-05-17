"""Stripe-event → workflow-state dispatcher.

Given a verified StripeEvent, the dispatcher:

  1. Inserts a row into public.payments (idempotent via the
     UNIQUE constraint on stripe_event_id — re-deliveries return
     "already processed" without re-applying side effects).
  2. Reads metadata.type and metadata.case_id /
     metadata.investigation_id from the Checkout Session payload.
  3. Applies the appropriate workflow transition:

       type=diagnostic   → INSERT pending investigation row for
                           case_id (triggers diagnostic pipeline).
       type=engagement   → UPDATE investigation: set
                           engagement_started_at +
                           engagement_fee_paid_usd.
       type=contingent   → AUDIT-only for now; recovery contingent
                           fees aren't yet automated.
       (anything else)   → AUDIT-only with notes for operator triage.

  4. Records processed_at and any notes on the payments row.

The dispatcher returns a DispatchResult so the HTTP handler can
return an informative 200 or 202 to Stripe (Stripe retries
non-2xx for up to 3 days, so we want to return 2xx unless the
caller actually wants Stripe to retry).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from recupero.payments.webhook import StripeEvent

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DispatchResult:
    """Outcome of processing one webhook event. The HTTP handler
    turns this into the response body so the operator sees the
    same shape in Stripe's webhook dashboard."""
    duplicate: bool          # True if we'd already processed this event_id
    action: str              # 'investigation_created', 'engagement_activated', 'audit_only', etc.
    payment_id: str | None   # PK of the public.payments row, if inserted
    case_id: str | None
    investigation_id: str | None
    notes: str | None


# Default amounts (CENTS) by type. Used as fallbacks if the event
# payload doesn't carry an amount (rare; checkout.session events
# always do, but defensive). Sourced from the centralized pricing
# module so a price change updates this without manual sync.
def _default_amounts_cents() -> dict[str, int]:
    from recupero._pricing import (
        DIAGNOSTIC_FEE_CENTS, ENGAGEMENT_FEE_CENTS,
    )
    return {
        "diagnostic": DIAGNOSTIC_FEE_CENTS,
        "engagement": ENGAGEMENT_FEE_CENTS,
    }


def dispatch(*, event: StripeEvent, dsn: str) -> DispatchResult:
    """Process one verified Stripe event end-to-end.

    Returns a DispatchResult describing what happened. Errors
    propagate as exceptions — the HTTP layer turns those into
    500s so Stripe retries.
    """
    # Most-common shape: checkout.session.completed carries the
    # session object as event.data.object.
    obj = (event.payload.get("data") or {}).get("object") or {}

    # Workflow metadata can come from two places:
    #   * `metadata.*` dict — set by the Stripe Dashboard's Payment
    #     Link config OR by a Checkout Session created via API.
    #   * `client_reference_id` — a free-form string parameterizable
    #     on Payment Link URLs (?client_reference_id=...). This is
    #     the path the CLI uses when generating per-customer URLs.
    #
    # metadata wins when both are set (Dashboard-baked types are the
    # most authoritative); client_reference_id fills in for variables
    # that can't be baked (the specific case_id / investigation_id).
    metadata = _merge_metadata_sources(
        metadata_dict=obj.get("metadata") or {},
        client_reference_id=obj.get("client_reference_id") or "",
    )

    amount_type = (metadata.get("type") or "").strip() or "unknown"
    case_id_raw = (metadata.get("case_id") or "").strip() or None
    inv_id_raw = (metadata.get("investigation_id") or "").strip() or None
    amount_cents = _resolve_amount_cents(obj, amount_type)
    currency = (obj.get("currency") or "usd").lower()
    status = _resolve_payment_status(event.event_type, obj)
    checkout_session_id = obj.get("id") if obj.get("object") == "checkout.session" else None
    payment_intent_id = (
        obj.get("payment_intent") if isinstance(obj.get("payment_intent"), str)
        else obj.get("id") if obj.get("object") == "payment_intent" else None
    )

    case_uuid: UUID | None = None
    inv_uuid: UUID | None = None
    if case_id_raw:
        try:
            case_uuid = UUID(case_id_raw)
        except ValueError:
            log.warning("dispatcher: malformed case_id in metadata: %r", case_id_raw)
    if inv_id_raw:
        try:
            inv_uuid = UUID(inv_id_raw)
        except ValueError:
            log.warning("dispatcher: malformed investigation_id in metadata: %r", inv_id_raw)

    # Idempotency: INSERT ... ON CONFLICT (stripe_event_id) DO NOTHING.
    # If the row already exists, return early without re-running
    # side effects.
    with psycopg.connect(dsn, autocommit=False, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.payments (
                    stripe_event_id, stripe_event_type,
                    stripe_checkout_session_id, stripe_payment_intent_id,
                    case_id, investigation_id,
                    amount_type, amount_cents, currency, status,
                    raw_event
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb
                )
                ON CONFLICT (stripe_event_id) DO NOTHING
                RETURNING id
                """,
                (
                    event.event_id, event.event_type,
                    checkout_session_id, payment_intent_id,
                    str(case_uuid) if case_uuid else None,
                    str(inv_uuid) if inv_uuid else None,
                    amount_type, amount_cents, currency, status,
                    json.dumps(event.payload),
                ),
            )
            row = cur.fetchone()
            if row is None:
                # Duplicate — already processed. Look up the prior
                # payment row so the response is still informative.
                cur.execute(
                    """
                    SELECT id, case_id, investigation_id, amount_type, notes
                      FROM public.payments
                     WHERE stripe_event_id = %s
                    """,
                    (event.event_id,),
                )
                prior = cur.fetchone() or {}
                conn.commit()
                return DispatchResult(
                    duplicate=True,
                    action="duplicate",
                    payment_id=str(prior.get("id")) if prior.get("id") else None,
                    case_id=str(prior.get("case_id")) if prior.get("case_id") else None,
                    investigation_id=(
                        str(prior.get("investigation_id"))
                        if prior.get("investigation_id") else None
                    ),
                    notes=prior.get("notes"),
                )
            payment_id = UUID(str(row["id"]))

            # Side-effect dispatch by amount_type. Each branch may
            # update inv_uuid (engagement creation actually creates
            # the investigation row).
            action, dispatched_inv_uuid, notes = _apply_workflow(
                cur=cur,
                amount_type=amount_type,
                event_type=event.event_type,
                case_uuid=case_uuid,
                inv_uuid=inv_uuid,
                amount_cents=amount_cents,
                obj=obj,
            )

            # Finalize the payments row.
            cur.execute(
                """
                UPDATE public.payments
                   SET processed_at = NOW(),
                       investigation_id = COALESCE(investigation_id, %s),
                       notes = %s
                 WHERE id = %s
                """,
                (
                    str(dispatched_inv_uuid) if dispatched_inv_uuid else None,
                    notes,
                    str(payment_id),
                ),
            )
        conn.commit()

    return DispatchResult(
        duplicate=False,
        action=action,
        payment_id=str(payment_id),
        case_id=str(case_uuid) if case_uuid else None,
        investigation_id=(
            str(dispatched_inv_uuid) if dispatched_inv_uuid else
            str(inv_uuid) if inv_uuid else None
        ),
        notes=notes,
    )


# ----- Helpers ----- #


# Parse convention for ``client_reference_id`` on Stripe Payment Links.
# Two formats today, both colon-separated:
#
#   diag:<case_uuid>:<chain>:<seed_address>
#   eng:<investigation_uuid>
#
# Why this format?
# Payment Link URLs accept ``?client_reference_id=...`` as a single
# free-form string. The metadata dict is NOT URL-parametrizable on
# Payment Links — only on API-created Checkout Sessions. So we encode
# the dynamic parts (case_id, seed_address) into client_reference_id
# and rely on the Stripe Dashboard's Payment Link config to bake in
# the static parts (e.g., the product → amount mapping).
#
# UUIDs, chain names ('ethereum', 'arbitrum', etc.), and 0x-prefixed
# addresses don't contain `:`, so the separator is safe.
_CRI_PREFIX_DIAG = "diag"
_CRI_PREFIX_ENG = "eng"


def _merge_metadata_sources(
    *,
    metadata_dict: dict[str, Any],
    client_reference_id: str,
) -> dict[str, Any]:
    """Build a unified metadata dict from both possible sources.

    Resolution order (`metadata_dict` wins on conflict):
      1. Start with the parsed client_reference_id (Payment Link path).
      2. Overlay any keys from metadata_dict (API-Checkout path or
         Dashboard-baked Payment Link metadata).

    The result is a flat dict the dispatcher's existing code path
    can read without needing to know which source it came from.
    """
    out = _parse_client_reference_id(client_reference_id.strip())
    for k, v in metadata_dict.items():
        if v not in (None, ""):
            out[k] = v
    return out


def _parse_client_reference_id(cri: str) -> dict[str, str]:
    """Parse our Payment Link convention into the same shape as
    metadata.*. Returns an empty dict if unparseable — the
    dispatcher then degrades to audit-only and the operator sees
    a clear note on the payments row.

    Schema:
      ``diag:<case_uuid>:<chain>:<seed_address>``
      ``eng:<investigation_uuid>``
    """
    if not cri:
        return {}
    parts = cri.split(":")
    if not parts:
        return {}
    prefix = parts[0].lower()
    if prefix == _CRI_PREFIX_DIAG and len(parts) >= 4:
        # All four trailing fields must be non-empty — defensive
        # against tokens like 'diag:abc::seed' that would otherwise
        # produce a half-populated metadata dict.
        if all(p.strip() for p in parts[1:4]):
            return {
                "type": "diagnostic",
                "case_id": parts[1],
                "chain": parts[2],
                "seed_address": parts[3],
            }
        return {}
    if prefix == _CRI_PREFIX_ENG and len(parts) >= 2 and parts[1].strip():
        return {
            "type": "engagement",
            "investigation_id": parts[1],
        }
    return {}


def _resolve_amount_cents(obj: dict[str, Any], amount_type: str) -> int:
    """Extract the payment amount from the Stripe object.

    Checkout Session uses ``amount_total``. PaymentIntent uses
    ``amount``. Refund/dispute events have their own shapes —
    handled when we expand beyond the diagnostic + engagement
    types. For unknown shapes, fall back to the typed default
    (so an INSERT with amount_cents>0 succeeds) and rely on the
    notes column to flag the manual triage need.
    """
    for key in ("amount_total", "amount"):
        val = obj.get(key)
        if isinstance(val, int) and val > 0:
            return val
    return _default_amounts_cents().get(amount_type, 0)


def _resolve_payment_status(event_type: str, obj: dict[str, Any]) -> str:
    """Translate Stripe event-type + object state into our 4-value
    payments.status enum ('paid' | 'unpaid' | 'refunded' | 'disputed').

    Conservative defaults: anything we don't recognize maps to
    'paid' for completed-event types and 'unpaid' for everything
    else. The notes field carries the disambiguation.
    """
    if event_type.startswith("charge.refunded"):
        return "refunded"
    if event_type.startswith("charge.dispute"):
        return "disputed"
    if event_type == "checkout.session.completed":
        payment_status = (obj.get("payment_status") or "").lower()
        if payment_status in ("paid", "no_payment_required"):
            return "paid"
        return "unpaid"
    if event_type == "checkout.session.expired":
        return "unpaid"
    return "paid"


def _apply_workflow(
    *,
    cur: Any,
    amount_type: str,
    event_type: str,
    case_uuid: UUID | None,
    inv_uuid: UUID | None,
    amount_cents: int,
    obj: dict[str, Any],
) -> tuple[str, UUID | None, str | None]:
    """Apply the side effects implied by `amount_type`. Returns
    ``(action_name, investigation_uuid, notes)`` so the caller can
    finalize the payments row and produce a DispatchResult.

    Only processes 'paid' events — refunds and disputes log to
    the payments table but don't reverse workflow state (that's
    operator-supervised triage). Future versions can hook a
    refund event into recupero-ops mark-refunded once we have a
    concrete workflow for it.
    """
    status = _resolve_payment_status(event_type, obj)
    if status != "paid":
        return "audit_only", inv_uuid, (
            f"non-paid event ({event_type}, status={status}) — audit only"
        )
    if amount_type == "diagnostic":
        return _handle_diagnostic(cur, case_uuid, amount_cents, obj)
    if amount_type == "engagement":
        return _handle_engagement(cur, inv_uuid, amount_cents)
    if amount_type == "contingent":
        return "audit_only", inv_uuid, (
            "contingent payment received; recovery-fee workflow not "
            "automated yet — operator triage required"
        )
    # 'unknown' / unparseable
    return "audit_only", inv_uuid, (
        f"unrecognized amount_type={amount_type!r} in metadata; "
        "operator triage required"
    )


def _handle_diagnostic(
    cur: Any, case_uuid: UUID | None, amount_cents: int, obj: dict[str, Any],
) -> tuple[str, UUID | None, str | None]:
    """Diagnostic payment → INSERT a pending investigation row
    for the case. The pipeline picks it up on the next claim cycle
    and runs the $499 trace.

    Pre-flight: confirm the case exists. If case_uuid is missing
    or invalid, log to notes and skip the side effect.
    """
    if case_uuid is None:
        return "audit_only", None, (
            "diagnostic payment without metadata.case_id — operator "
            "must create the investigation manually"
        )
    cur.execute(
        "SELECT id, case_number FROM public.cases WHERE id = %s",
        (str(case_uuid),),
    )
    case_row = cur.fetchone()
    if not case_row:
        return "audit_only", None, (
            f"diagnostic payment references unknown case {case_uuid} — "
            "operator triage required"
        )

    # Read seed_address from the merged metadata source. With
    # Payment Links these arrive via client_reference_id; with
    # API-created Checkout Sessions they arrive via metadata.*.
    # The merged dict captures both paths uniformly.
    metadata = _merge_metadata_sources(
        metadata_dict=obj.get("metadata") or {},
        client_reference_id=obj.get("client_reference_id") or "",
    )
    seed_address = (metadata.get("seed_address") or "").strip()
    chain = (metadata.get("chain") or "ethereum").strip().lower()

    if not seed_address:
        return "audit_only", None, (
            f"diagnostic payment for case {case_row['case_number']} "
            "missing metadata.seed_address — operator must populate "
            "before the investigation can run"
        )

    new_inv_id = uuid4()
    cur.execute(
        """
        INSERT INTO public.investigations
            (id, case_id, status, chain, seed_address, triggered_at,
             triggered_by, label)
        VALUES (%s, %s, 'pending', %s, %s, NOW(),
                'stripe-webhook', %s)
        """,
        (
            str(new_inv_id), str(case_uuid), chain, seed_address,
            f"diagnostic-{case_row['case_number']}",
        ),
    )
    return "investigation_created", new_inv_id, (
        f"diagnostic payment for case {case_row['case_number']} "
        f"(${amount_cents/100:.2f}); investigation {new_inv_id} queued"
    )


def _handle_engagement(
    cur: Any, inv_uuid: UUID | None, amount_cents: int,
) -> tuple[str, UUID | None, str | None]:
    """Engagement payment → set engagement_started_at +
    engagement_fee_paid_usd on the investigation.

    Uses COALESCE on engagement_started_at so a customer who
    already e-signed via the portal (which set the timestamp)
    has it preserved. If they pay first and sign later, the
    portal's COALESCE preserves THIS timestamp. Either order
    works.
    """
    if inv_uuid is None:
        return "audit_only", None, (
            "engagement payment without metadata.investigation_id — "
            "operator must manually run mark-engaged"
        )
    cur.execute(
        "SELECT id FROM public.investigations WHERE id = %s",
        (str(inv_uuid),),
    )
    if not cur.fetchone():
        return "audit_only", inv_uuid, (
            f"engagement payment references unknown investigation "
            f"{inv_uuid} — operator triage required"
        )
    amount_usd = round(amount_cents / 100.0, 2)
    cur.execute(
        """
        UPDATE public.investigations
           SET engagement_started_at = COALESCE(engagement_started_at, NOW()),
               engagement_closed_at = NULL,
               engagement_fee_paid_usd = %s,
               last_followup_sent_at = NULL
         WHERE id = %s
        """,
        (amount_usd, str(inv_uuid)),
    )
    return "engagement_activated", inv_uuid, (
        f"engagement fee ${amount_usd:.2f} recorded; follow-up cron "
        "will pick up on next run"
    )


__all__ = ("DispatchResult", "dispatch")
