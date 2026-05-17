"""Payment integration — Stripe webhook handler + dispatcher.

The worker accepts payment events at ``/webhooks/stripe`` and
translates them into workflow state transitions:

  * ``checkout.session.completed`` with ``metadata.type=diagnostic``
    → INSERT into public.investigations (status='pending'),
      kicking off the $499 diagnostic pipeline.
  * ``checkout.session.completed`` with ``metadata.type=engagement``
    → UPDATE public.investigations
        SET engagement_started_at = COALESCE(engagement_started_at, NOW()),
            engagement_fee_paid_usd = <amount>
      WHERE id = <metadata.investigation_id>.

Every event is logged to public.payments (UNIQUE on
stripe_event_id) so re-deliveries are no-ops and the audit trail
captures everything Stripe ever told us about a case.

Modules
-------

  * ``webhook`` — signature verification + handler entrypoint.
  * ``dispatcher`` — event-type routing + workflow side effects.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
