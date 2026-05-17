"""Build parameterized Stripe Payment Link URLs.

A Stripe Payment Link is a static URL (e.g.,
``https://buy.stripe.com/test_abc123``) created in the Stripe
Dashboard for a fixed product + amount. Each customer gets a
**personalized** version of that URL by appending query
parameters — primarily ``client_reference_id``, which arrives
in the webhook event as ``checkout.session.client_reference_id``
and is how we link the payment back to a specific case /
investigation.

This module is the single source of truth on the encoding
convention; the dispatcher's parser in dispatcher.py reads
the same format on the way back in.

Configuration
-------------

Two env vars hold the base Payment Link URLs (set in the Stripe
Dashboard, copied here):

  RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK
      e.g., https://buy.stripe.com/test_499_diag

  RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK
      e.g., https://buy.stripe.com/test_10000_eng

Both should have ``metadata.type`` baked into the Dashboard
config (`diagnostic` / `engagement` respectively) so the
dispatcher's metadata.* path also identifies them correctly —
that way payments still classify properly even if the
client_reference_id gets stripped by an aggressive copy-paste.
"""

from __future__ import annotations

import os
import urllib.parse
from uuid import UUID

# Env var names — exposed as constants so the CLI's error
# messages reference the same string the operator needs to set.
ENV_DIAGNOSTIC_LINK = "RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK"
ENV_ENGAGEMENT_LINK = "RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK"


class PaymentLinkConfigError(RuntimeError):
    """Raised when the Payment Link base URL isn't configured.
    The CLI catches this and turns it into a friendly error
    message pointing at the env var the operator needs to set."""


def build_diagnostic_link(
    *,
    case_id: UUID,
    chain: str,
    seed_address: str,
    prefilled_email: str | None = None,
    base_url: str | None = None,
) -> str:
    """Build the customer-facing $499 diagnostic Payment Link URL.

    ``client_reference_id`` is encoded as
    ``diag:<case_uuid>:<chain>:<seed_address>`` — the dispatcher
    parses this back out when the webhook fires.

    Raises ``PaymentLinkConfigError`` if neither ``base_url`` nor
    ``RECUPERO_STRIPE_DIAGNOSTIC_PAYMENT_LINK`` is set.
    """
    base = (base_url or os.environ.get(ENV_DIAGNOSTIC_LINK, "")).strip()
    if not base:
        raise PaymentLinkConfigError(
            f"{ENV_DIAGNOSTIC_LINK} is not set. Configure it in Railway "
            "with the Payment Link URL from your Stripe Dashboard "
            "(the $499 diagnostic product)."
        )

    seed_clean = seed_address.strip()
    chain_clean = chain.strip().lower()
    if not seed_clean:
        raise ValueError("seed_address is required for a diagnostic link")
    if not chain_clean:
        raise ValueError("chain is required for a diagnostic link")

    cri = f"diag:{case_id}:{chain_clean}:{seed_clean}"
    return _attach_params(base, client_reference_id=cri,
                          prefilled_email=prefilled_email)


def build_engagement_link(
    *,
    investigation_id: UUID,
    prefilled_email: str | None = None,
    base_url: str | None = None,
) -> str:
    """Build the customer-facing $10,000 engagement Payment Link URL.

    ``client_reference_id`` is encoded as
    ``eng:<investigation_uuid>`` — the dispatcher parses this back
    out on the webhook side to find the right investigation row
    to activate.

    Raises ``PaymentLinkConfigError`` if neither ``base_url`` nor
    ``RECUPERO_STRIPE_ENGAGEMENT_PAYMENT_LINK`` is set.
    """
    base = (base_url or os.environ.get(ENV_ENGAGEMENT_LINK, "")).strip()
    if not base:
        raise PaymentLinkConfigError(
            f"{ENV_ENGAGEMENT_LINK} is not set. Configure it in Railway "
            "with the Payment Link URL from your Stripe Dashboard "
            "(the $10,000 engagement product)."
        )
    cri = f"eng:{investigation_id}"
    return _attach_params(base, client_reference_id=cri,
                          prefilled_email=prefilled_email)


def _attach_params(
    base_url: str,
    *,
    client_reference_id: str,
    prefilled_email: str | None,
) -> str:
    """Append client_reference_id (+ optional prefilled_email) to
    the base Payment Link URL, preserving any existing query
    params the operator may have set in the Stripe Dashboard.

    Notes:
      * client_reference_id is URL-encoded so colons survive
        copy-paste through email clients that aggressively
        decode URLs.
      * prefilled_email is honored by Stripe even on Payment
        Links — the checkout page renders with the email pre-
        populated, reducing friction.
    """
    parsed = urllib.parse.urlsplit(base_url)
    # Preserve any existing query, append ours.
    existing_qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = list(existing_qs)
    # Replace any pre-existing client_reference_id (operator
    # shouldn't set one in the Dashboard, but defensive).
    new_qs = [(k, v) for k, v in new_qs if k != "client_reference_id"]
    new_qs.append(("client_reference_id", client_reference_id))
    if prefilled_email:
        new_qs = [(k, v) for k, v in new_qs if k != "prefilled_email"]
        new_qs.append(("prefilled_email", prefilled_email))
    new_query = urllib.parse.urlencode(new_qs, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path,
        new_query, parsed.fragment,
    ))


__all__ = (
    "ENV_DIAGNOSTIC_LINK",
    "ENV_ENGAGEMENT_LINK",
    "PaymentLinkConfigError",
    "build_diagnostic_link",
    "build_engagement_link",
)
