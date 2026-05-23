"""recupero-ops generate-customer-link <case_id> [--ttl-days 90] [--label ...]

Mints a fresh case_tokens row + prints the customer-facing URL.

Typical workflow:

    $ recupero-ops generate-customer-link 535a5ced-...
    OK — portal link for case V-058868 (Validation Run):

        https://portal.recupero.io/portal/abc...xyz

    Expires: 2026-08-13 (90 days)

    Send this to the customer in your reply. They can use it to
    view case status, download artifacts, and sign the engagement
    letter electronically.

Idempotency: each invocation mints a NEW token — re-running doesn't
return the same token. This is intentional. If the operator needs to
re-send a link, the second invocation invalidates the first
*workflow-wise* (the customer should ignore the old link) but both
remain valid until expiry / revocation. To revoke an old token, the
operator runs a manual UPDATE on case_tokens.revoked_at — most cases
won't need this.
"""

from __future__ import annotations

import logging
import os
from uuid import UUID

from psycopg.rows import dict_row

from recupero._common import db_connect
from recupero.portal.tokens import generate_token, public_portal_url

log = logging.getLogger(__name__)


def run(
    *,
    case_id: UUID,
    ttl_days: int | None,
    label: str | None,
    dsn: str,
) -> int:
    """Mint + print a portal link. Returns 0 on success, 1 on errors."""
    # v0.20.1 (Z14): validate ttl_days + label BEFORE the DB round-trip.
    # Pre-v0.20.1: --ttl-days -7 minted an already-expired token;
    # --ttl-days 100000 minted a 273-year token; --label with NUL bytes
    # silently corrupted the audit row.
    if ttl_days is not None:
        if not isinstance(ttl_days, int) or isinstance(ttl_days, bool):
            print(f"ERROR: --ttl-days must be an integer (got {ttl_days!r})")
            return 1
        if ttl_days <= 0:
            print(
                f"ERROR: --ttl-days must be > 0 (got {ttl_days}). "
                "Negative or zero TTLs mint an already-expired token; "
                "use 90 for the default."
            )
            return 1
        if ttl_days > 730:
            print(
                f"ERROR: --ttl-days must be <= 730 (got {ttl_days}). "
                "Portal tokens are bearer credentials; multi-year TTLs "
                "are almost always operator typos. Re-issue when needed."
            )
            return 1
    if label is not None:
        if not isinstance(label, str) or len(label) > 200:
            print(
                "ERROR: --label must be a string of <= 200 characters."
            )
            return 1
        for ch in label:
            if ord(ch) < 0x20 or ord(ch) == 0x7f:
                print(
                    f"ERROR: --label contains a control character "
                    f"(codepoint U+{ord(ch):04X}). Reject before insert."
                )
                return 1

    # Fetch the case so we can echo back "V-058868 (Validation Run)" in
    # the success line — much easier for the operator to confirm "yes
    # this is the right case" than seeing only the UUID.
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT case_number, client_name FROM public.cases WHERE id = %s",
            (str(case_id),),
        )
        case_row = cur.fetchone()
    if not case_row:
        print(f"ERROR: case {case_id} not found")
        return 1

    try:
        token_id, token, expires_at = generate_token(
            case_id=case_id, dsn=dsn, ttl_days=ttl_days, label=label,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    url = public_portal_url(token=token)
    base_set = bool(os.environ.get("RECUPERO_PORTAL_BASE_URL", "").strip())

    print(
        f"OK — portal link for case {case_row['case_number']} "
        f"({case_row['client_name']}):\n\n"
        f"    {url}\n"
    )
    if expires_at is not None:
        print(f"Expires: {expires_at.strftime('%Y-%m-%d')} "
              f"({ttl_days} days)")
    else:
        print("Expires: never (special-case token — be careful)")
    if label:
        print(f"Label:   {label}")
    print(f"Token ID: {token_id}")

    if not base_set:
        print(
            "\nWARN: RECUPERO_PORTAL_BASE_URL is not set — the URL above "
            "uses a localhost fallback that won't resolve for your "
            "customer. Set the env var to the production portal hostname "
            "(e.g., https://portal.recupero.io) before sending."
        )

    print(
        "\nSend this URL to the customer. They can:\n"
        "  • View case status and engagement state\n"
        "  • Download diagnostic, engagement letter, and flow diagram\n"
        "  • Sign the engagement letter electronically (POST flow)\n"
    )
    return 0


__all__ = ("run",)
