"""recupero-ops <command> dispatch.

argparse-based subcommand router. Imports each command's
implementation lazily so the operator can run e.g. ``recupero-ops
status <id>`` without paying the import cost of the freeze-letter-
sending modules.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from decimal import Decimal
from uuid import UUID

from dotenv import load_dotenv

from recupero.logging_setup import setup_logging

log = logging.getLogger("recupero.ops")


def _require_dsn() -> str:
    """Resolve SUPABASE_DB_URL or exit non-zero. Every ops command
    needs DB access; if it's missing the operator made a setup
    mistake and we should fail loudly."""
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        print(
            "ERROR: SUPABASE_DB_URL is not set. "
            "Source your .env or export the variable before running ops commands.",
            file=sys.stderr,
        )
        sys.exit(2)
    return dsn


def _parse_uuid(s: str, *, field_name: str = "investigation_id") -> UUID:
    """Parse a UUID arg or exit with a helpful error."""
    try:
        return UUID(s)
    except ValueError:
        print(
            f"ERROR: {field_name!r} must be a UUID (e.g., "
            f"'e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c'). Got: {s!r}",
            file=sys.stderr,
        )
        sys.exit(2)


def _confirm(prompt: str, *, default: bool = False) -> bool:
    """Interactive y/N prompt. Returns True if user confirmed,
    False on N / empty / EOF. Honors --yes flag via the
    RECUPERO_OPS_ASSUME_YES env var for scripted ops use."""
    if os.environ.get("RECUPERO_OPS_ASSUME_YES", "").strip() == "1":
        return True
    default_str = "Y/n" if default else "y/N"
    try:
        ans = input(f"{prompt} [{default_str}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not ans:
        return default
    return ans in ("y", "yes")


def cli() -> None:
    """Entry point for ``recupero-ops``."""
    parser = argparse.ArgumentParser(
        prog="recupero-ops",
        description="Operator CLI for investigation management.",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("RECUPERO_LOG_LEVEL", "INFO"),
        help="Python log level. Default INFO.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ----- status ----- #
    p_status = sub.add_parser(
        "status",
        help="Show full state of an investigation.",
    )
    p_status.add_argument("investigation_id", help="UUID of the investigation")

    # ----- mark-engaged ----- #
    p_engage = sub.add_parser(
        "mark-engaged",
        help="Activate Tier-2 engagement on an investigation.",
    )
    p_engage.add_argument("investigation_id", help="UUID of the investigation")
    p_engage.add_argument(
        "--fee", type=str, default=None,
        help="Engagement fee paid (USD). Defaults to the value in "
             "recupero._pricing (currently $10,000). The first "
             "follow-up email will be sent on the next "
             "--send-followups cron run.",
    )

    # ----- mark-closed ----- #
    p_close = sub.add_parser(
        "mark-closed",
        help="Close an active engagement.",
    )
    p_close.add_argument("investigation_id", help="UUID of the investigation")
    p_close.add_argument(
        "--reason", type=str, default="operator-closed",
        help="Free-form reason recorded in change_summary for audit.",
    )

    # ----- send-freeze-letters ----- #
    p_freeze = sub.add_parser(
        "send-freeze-letters",
        help="Send prepared compliance freeze letters to issuer "
             "compliance teams. Requires confirmation.",
    )
    p_freeze.add_argument("investigation_id", help="UUID of the investigation")
    p_freeze.add_argument(
        "--issuer", type=str, default=None,
        help="If set, send only to the named issuer (e.g., 'Circle'). "
             "Default: send to every issuer in the FREEZABLE list.",
    )

    # ----- send-le-handoff ----- #
    p_le = sub.add_parser(
        "send-le-handoff",
        help="Send the LE handoff package to a specific law-enforcement "
             "officer or attorney.",
    )
    p_le.add_argument("investigation_id", help="UUID of the investigation")
    p_le.add_argument(
        "--to", required=True, dest="to_email",
        help="Recipient email address (the LE officer or attorney).",
    )

    # ----- followup-now ----- #
    p_followup = sub.add_parser(
        "followup-now",
        help="Force-send a follow-up status email immediately, "
             "bypassing the 6-day cadence check.",
    )
    p_followup.add_argument("investigation_id", help="UUID of the investigation")

    # ----- generate-customer-link ----- #
    p_link = sub.add_parser(
        "generate-customer-link",
        help="Mint a token-gated portal URL for a case so the victim "
             "can view status, download artifacts, and e-sign the "
             "engagement letter.",
    )
    p_link.add_argument("case_id", help="UUID of the case (NOT the investigation)")
    p_link.add_argument(
        "--ttl-days", type=int, default=90,
        help="Token TTL in days (default 90). Pass 0 for a never-"
             "expiring token (special-case workflows only).",
    )
    p_link.add_argument(
        "--label", type=str, default=None,
        help="Free-form label shown on the operator status page "
             "(e.g., 'victim', 'attorney', 'family-member').",
    )

    # ----- stripe-mode ----- #
    sub.add_parser(
        "stripe-mode",
        help="Report the current Stripe configuration mode "
             "(test vs live). Exits non-zero on mismatch — "
             "useful in deployment CI checks.",
    )

    # ----- ofac-sync ----- #
    sub.add_parser(
        "ofac-sync",
        help="Download the latest OFAC SDN List from treasury.gov "
             "and update the local crypto-address CSV used by "
             "risk-scoring. Recommended cadence: weekly via cron.",
    )

    # ----- correlation-stats ----- #
    sub.add_parser(
        "correlation-stats",
        help="Report summary stats from the cross-case correlation "
             "index (public.address_observations). Recommended "
             "cadence: monthly review.",
    )

    # ----- list-payments ----- #
    p_lpay = sub.add_parser(
        "list-payments",
        help="List recent Stripe payment events with workflow "
             "correlation. The operator's go-to for 'did the "
             "webhook fire for case V-...?'",
    )
    p_lpay.add_argument(
        "--limit", type=int, default=10,
        help="Max rows (default 10, max 1000).",
    )
    p_lpay.add_argument(
        "--since", type=str, default="7d",
        help="Time window: 24h, 7d, 30d, 90d, or all (default 7d).",
    )
    p_lpay.add_argument(
        "--case-id", dest="case_id_filter", type=str, default=None,
        help="Filter to one specific case_id (UUID).",
    )

    # ----- generate-payment-link ----- #
    p_paylink = sub.add_parser(
        "generate-payment-link",
        help="Mint a Stripe Payment Link URL for the $499 diagnostic "
             "or $10,000 engagement payment, with case-specific "
             "metadata baked into client_reference_id.",
    )
    p_paylink.add_argument("case_id", help="UUID of the case")
    p_paylink.add_argument(
        "--type", required=True, dest="link_type",
        choices=("diagnostic", "engagement"),
        help="Which payment this link is for.",
    )
    p_paylink.add_argument(
        "--chain", default="ethereum",
        help="Chain for diagnostic links (default: ethereum). Ignored "
             "for engagement.",
    )
    p_paylink.add_argument(
        "--seed-address", dest="seed_address", default=None,
        help="The wallet to trace (required for --type diagnostic).",
    )
    p_paylink.add_argument(
        "--investigation-id", dest="investigation_id", default=None,
        help="Investigation UUID for --type engagement. If omitted, "
             "uses the latest investigation for the case.",
    )
    p_paylink.add_argument(
        "--prefilled-email", dest="prefilled_email", default=None,
        help="Override the case's contact email for the Stripe "
             "checkout 'Email' field pre-fill.",
    )

    # ----- promote-freezable ----- #
    p_promote = sub.add_parser(
        "promote-freezable",
        help="Promote an INVESTIGATE watchlist row to FREEZABLE after "
             "issuer compliance confirms KYC. Requires confirmation.",
    )
    p_promote.add_argument("watchlist_id", help="UUID of the watchlist row")
    p_promote.add_argument(
        "--reason", required=True,
        help="Required: free-form reason for the promotion. Include "
             "the issuer ticket number or email thread so the audit "
             "trail can be re-verified later.",
    )
    p_promote.add_argument(
        "--force", action="store_true",
        help="Overwrite kyc_* columns if the row is already FREEZABLE. "
             "Use sparingly — this destroys the original audit trail.",
    )

    args = parser.parse_args()
    load_dotenv()
    setup_logging(args.log_level.upper())

    # Dispatch lazily — only import the command module we need
    if args.command == "status":
        from recupero.ops.commands import status as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            dsn=_require_dsn(),
        ))

    if args.command == "mark-engaged":
        from recupero._pricing import ENGAGEMENT_FEE_USD
        from recupero.ops.commands import mark_engaged as cmd
        if args.fee is None:
            fee = ENGAGEMENT_FEE_USD
        else:
            try:
                fee = Decimal(args.fee)
            except Exception:
                print(
                    f"ERROR: --fee must be a decimal number (got: {args.fee!r})",
                    file=sys.stderr,
                )
                sys.exit(2)
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            fee_usd=fee, dsn=_require_dsn(),
        ))

    if args.command == "mark-closed":
        from recupero.ops.commands import mark_closed as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            reason=args.reason, dsn=_require_dsn(),
        ))

    if args.command == "send-freeze-letters":
        from recupero.ops.commands import send_freeze_letters as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            issuer_filter=args.issuer,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "send-le-handoff":
        from recupero.ops.commands import send_le_handoff as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            to_email=args.to_email,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "followup-now":
        from recupero.ops.commands import followup_now as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "generate-customer-link":
        from recupero.ops.commands import generate_customer_link as cmd
        ttl: int | None = args.ttl_days
        if ttl is not None and ttl <= 0:
            ttl = None  # 0 → never expires
        sys.exit(cmd.run(
            case_id=_parse_uuid(args.case_id, field_name="case_id"),
            ttl_days=ttl,
            label=args.label,
            dsn=_require_dsn(),
        ))

    if args.command == "promote-freezable":
        from recupero.ops.commands import promote_freezable as cmd
        sys.exit(cmd.run(
            watchlist_id=_parse_uuid(args.watchlist_id, field_name="watchlist_id"),
            reason=args.reason,
            force=args.force,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "stripe-mode":
        from recupero.ops.commands import stripe_mode_cmd as cmd
        sys.exit(cmd.run())

    if args.command == "ofac-sync":
        from recupero.ops.commands import ofac_sync_cmd as cmd
        sys.exit(cmd.run())

    if args.command == "correlation-stats":
        from recupero.ops.commands import correlation_stats as cmd
        sys.exit(cmd.run(dsn=_require_dsn()))

    if args.command == "list-payments":
        from recupero.ops.commands import list_payments as cmd
        case_uuid: UUID | None = None
        if args.case_id_filter:
            case_uuid = _parse_uuid(args.case_id_filter, field_name="case_id")
        sys.exit(cmd.run(
            limit=args.limit, since=args.since, case_id=case_uuid,
            dsn=_require_dsn(),
        ))

    if args.command == "generate-payment-link":
        from recupero.ops.commands import generate_payment_link as cmd
        investigation_uuid: UUID | None = None
        if args.investigation_id:
            investigation_uuid = _parse_uuid(
                args.investigation_id, field_name="investigation_id",
            )
        sys.exit(cmd.run(
            case_id=_parse_uuid(args.case_id, field_name="case_id"),
            link_type=args.link_type,
            chain=args.chain,
            seed_address=args.seed_address,
            investigation_id=investigation_uuid,
            prefilled_email=args.prefilled_email,
            dsn=_require_dsn(),
        ))

    print(f"ERROR: unknown command {args.command!r}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    cli()
