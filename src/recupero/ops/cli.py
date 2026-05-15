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
        "--fee", type=str, default="1500",
        help="Engagement fee paid (USD, default 1500). The first "
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
        from recupero.ops.commands import mark_engaged as cmd
        try:
            fee = Decimal(args.fee)
        except Exception:
            print(f"ERROR: --fee must be a decimal number (got: {args.fee!r})",
                  file=sys.stderr)
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

    print(f"ERROR: unknown command {args.command!r}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    cli()
