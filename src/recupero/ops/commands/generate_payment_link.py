"""recupero-ops generate-payment-link <case_id> --type diagnostic|engagement

Mints a personalized Stripe Payment Link URL for a specific case.
Two flavors:

  --type diagnostic
    Builds the $499 diagnostic Payment Link with the case_id,
    chain, and seed_address encoded into client_reference_id so
    the webhook dispatcher can correlate the payment with the
    right case and trigger the investigation.

  --type engagement
    Builds the $10,000 engagement Payment Link with the
    investigation_id encoded. The webhook fires
    engagement_started_at when the payment lands.

The operator pastes the resulting URL into the customer email
(or shares via SMS / signal / etc.). On payment, the webhook at
/webhooks/stripe receives the event, the dispatcher reads
client_reference_id, and the workflow advances automatically.

Typical run::

    $ recupero-ops generate-payment-link 5a9c901e-... \\
          --type diagnostic --chain ethereum \\
          --seed-address 0x0cdC...e955

    OK — diagnostic payment link for case V-ZTST01 (Smoke Test):

        https://buy.stripe.com/test_499_diag
            ?client_reference_id=diag:5a9c901e-...:ethereum:0x0cdC...e955
            &prefilled_email=victim@example.com

    Amount: $499
    Send this URL to the customer; the webhook will trigger
    investigation creation on completed payment.
"""

from __future__ import annotations

import logging
from uuid import UUID

from psycopg.rows import dict_row

from recupero._common import db_connect

log = logging.getLogger(__name__)


def run(
    *,
    case_id: UUID,
    link_type: str,
    chain: str | None,
    seed_address: str | None,
    investigation_id: UUID | None,
    prefilled_email: str | None,
    dsn: str,
) -> int:
    """Mint + print a Stripe Payment Link URL. Returns 0 on success."""
    if link_type not in ("diagnostic", "engagement"):
        print(f"ERROR: --type must be 'diagnostic' or 'engagement' (got {link_type!r})")
        return 1

    # Verify the case exists and pull a few fields for the success
    # message. Catches operator-typo case_ids before we mint a URL
    # the webhook would later reject as audit_only.
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT case_number, client_name, client_email "
            "  FROM public.cases WHERE id = %s",
            (str(case_id),),
        )
        case_row = cur.fetchone()
        if not case_row:
            print(f"ERROR: case {case_id} not found")
            return 1

        # For engagement: resolve the latest investigation for
        # this case if one wasn't supplied. Operator usually
        # only knows the case_id; they shouldn't have to look
        # up the investigation_id manually.
        if link_type == "engagement" and investigation_id is None:
            cur.execute(
                "SELECT id FROM public.investigations "
                " WHERE case_id = %s "
                " ORDER BY triggered_at DESC NULLS LAST "
                " LIMIT 1",
                (str(case_id),),
            )
            inv_row = cur.fetchone()
            if not inv_row:
                print(
                    f"ERROR: no investigation found for case "
                    f"{case_row['case_number']}. Run the diagnostic "
                    "first, then generate the engagement link."
                )
                return 1
            investigation_id = UUID(str(inv_row["id"]))

    # Default prefilled_email to the case's contact email if unset.
    effective_email = prefilled_email or case_row.get("client_email") or None

    # Build the URL via the payment_links primitive (raises
    # PaymentLinkConfigError if the base URL env var isn't set).
    from recupero.payments.payment_links import (
        PaymentLinkConfigError,
        build_diagnostic_link,
        build_engagement_link,
    )
    try:
        if link_type == "diagnostic":
            if not seed_address:
                print("ERROR: --seed-address is required for diagnostic links")
                return 1
            url = build_diagnostic_link(
                case_id=case_id, chain=chain or "ethereum",
                seed_address=seed_address, prefilled_email=effective_email,
            )
        else:
            assert investigation_id is not None
            url = build_engagement_link(
                investigation_id=investigation_id,
                prefilled_email=effective_email,
            )
    except PaymentLinkConfigError as exc:
        print(f"ERROR: {exc}")
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    from recupero._pricing import (
        DIAGNOSTIC_FEE_USD,
        ENGAGEMENT_FEE_USD,
        fmt_usd_short,
    )
    amount = (
        fmt_usd_short(DIAGNOSTIC_FEE_USD) if link_type == "diagnostic"
        else fmt_usd_short(ENGAGEMENT_FEE_USD)
    )

    # Detect test/live mode mismatch BEFORE printing the URL.
    # The most expensive operator mistake is "paste a URL into a
    # customer email that will fail webhook verification when the
    # customer pays." Printing the mismatch warning before the
    # URL makes it impossible to miss — the warning shows up
    # immediately above the success line they were going to copy.
    from recupero.payments.stripe_mode import (
        detect_mode_from_env,
        format_mismatch_warning,
    )
    mode_report = detect_mode_from_env()
    if mode_report.mismatch:
        import sys
        print(format_mismatch_warning(mode_report), file=sys.stderr)
        print(file=sys.stderr)  # blank line separator

    print(
        f"OK — {link_type} payment link for case "
        f"{case_row['case_number']} ({case_row['client_name']}):\n\n"
        f"    {url}\n\n"
        f"Amount: {amount}  ({mode_report.consensus} mode)\n"
    )
    if link_type == "diagnostic":
        print(
            "On completed payment, the webhook will:\n"
            "  • INSERT a pending investigation row\n"
            "  • Worker picks it up on next poll cycle\n"
            "  • Diagnostic + victim_summary auto-emailed when done\n"
        )
    else:
        print(
            "On completed payment, the webhook will:\n"
            "  • UPDATE engagement_started_at = NOW() (if not already set)\n"
            "  • Record engagement_fee_paid_usd\n"
            "  • Follow-up cron picks up on next run\n"
        )

    print("Send this URL to the customer.")
    return 0


__all__ = ("run",)
