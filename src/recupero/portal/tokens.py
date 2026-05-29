"""Bearer-token generation + verification for the customer portal.

Tokens are 32 bytes of `secrets.token_urlsafe` → ~43 base64url chars.
That's the same entropy floor as Stripe's secret keys; brute-forcing
would take ~10^77 operations, which is enough that we don't need to
rate-limit token-lookup endpoints to defend against guessing.

Lifecycle:

  1. Operator runs `recupero-ops generate-customer-link <case_id>`,
     which calls `generate_token` and prints a URL.
  2. Operator sends that URL to the victim (in the diagnostic email,
     manually, or via the upcoming auto-send on case completion).
  3. Victim hits `/portal/<token>` → the HTTP handler calls
     `verify_token` to look it up + reject expired/revoked tokens.
  4. On successful verification, `last_used_at` is bumped so an
     operator can see "is this token active?"

We deliberately do NOT bump `last_used_at` on every request — the
write-amplification is bad for the pooler and the resolution we
need is "did the victim ever use this?", not "exactly when". The
handler bumps it once per (token, day) at most.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple
from uuid import UUID

import psycopg  # noqa: F401 — re-exported for the test-mock seam: the
# token-verification tests patch ``recupero.portal.tokens.psycopg.connect``
# to exercise the DB path without a live Postgres. verify_token() reaches
# the DB via ``recupero._common.db_connect`` (which calls psycopg.connect),
# so this module-level name must remain importable for that patch target.
from psycopg.rows import dict_row

from recupero._common import db_connect

log = logging.getLogger(__name__)


# Default token TTL. 90 days covers a typical 30-day engagement plus
# a buffer for the victim to re-download artifacts after the
# engagement closes. Overridable per-call via the `ttl_days` kwarg.
_DEFAULT_TTL_DAYS = 90

# Minimum interval between `last_used_at` bumps for the same token.
# Set to 1 hour — we want enough resolution to see "did the victim
# visit today?" without rewriting the row on every page navigation.
_LAST_USED_BUMP_INTERVAL = timedelta(hours=1)

# Token byte length. 32 bytes → ~43 base64url chars. Stripe-equivalent.
_TOKEN_BYTES = 32


# v0.16.12 (round-9 security CRIT): HMAC-of-token lookup, eliminating
# the byte-by-byte timing side-channel in the prior raw-token equality
# compare against an indexed column. See migrations/014_case_token_hmac.sql
# for the migration plan and motivation.
#
# The server pepper lives in RECUPERO_TOKEN_PEPPER. When unset the app
# falls back to LEGACY-MODE (raw-token compare, with a WARNING) so a
# misconfigured deploy doesn't break existing tokens. Production
# deployments MUST set this env var; ops runbook covers rotation.


def _token_pepper() -> bytes | None:
    """Resolve the HMAC pepper from env.

    Accepts hex (64 chars) or base64-url (44 chars). Returns None when
    unset — callers fall back to legacy raw-token comparison with a
    one-time WARNING log. Pepper rotation invalidates every active
    token; operators must re-issue. We refuse to load short peppers
    (<16 bytes raw entropy) so a typo can't silently degrade to
    weak HMAC.
    """
    raw = (os.environ.get("RECUPERO_TOKEN_PEPPER", "") or "").strip()
    if not raw:
        return None
    # Try hex first (64 chars = 32 bytes).
    hex_ok = False
    try:
        decoded = bytes.fromhex(raw)
        hex_ok = True
        if len(decoded) >= 16:
            return decoded
    except ValueError:
        pass
    # Adversarial-input audit (v0.20.2): if the input parsed cleanly as
    # hex but came back too short, do NOT silently fall through to the
    # base64 decoder. Otherwise an operator typo (truncated 32-byte hex
    # pepper) can decode as 16+ "valid" base64 bytes and quietly accept
    # a derivation of the typo as the live pepper. Refusing the hex
    # case here surfaces the misconfiguration via the error log below.
    if hex_ok:
        log.error(
            "RECUPERO_TOKEN_PEPPER parsed as hex but is too short "
            "(need >=32 hex chars / 16 bytes). Falling back to LEGACY "
            "raw-token lookup — fix the env var ASAP."
        )
        return None
    # Try base64-url.
    import base64
    try:
        # Pad to multiple of 4 for forgiving base64-url decode.
        padded = raw + "=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if len(decoded) >= 16:
            return decoded
    except (ValueError, Exception):  # noqa: BLE001
        pass
    log.error(
        "RECUPERO_TOKEN_PEPPER set but unparseable / too short "
        "(need >=16 bytes of hex or base64). Falling back to LEGACY "
        "raw-token lookup — fix the env var ASAP."
    )
    return None


def compute_token_hmac(token: str) -> str | None:
    """Compute the HMAC-SHA256 hex digest of `token` with the server
    pepper. Returns None if the pepper env var is unset (legacy mode).

    The output is 64 hex chars, safe to index + compare without
    side-channel concerns (HMAC outputs are uniformly random over the
    output space regardless of input).
    """
    pepper = _token_pepper()
    if pepper is None:
        return None
    return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()


class VerifiedToken(NamedTuple):
    """A successfully-verified portal token, joined with case state.

    Returned by `verify_token`. The handler uses this to render the
    status page without a second DB roundtrip — every field the
    landing page needs is here.
    """
    token_id: UUID
    case_id: UUID
    case_number: str
    client_name: str
    client_email: str | None
    case_status: str
    case_state: str | None
    estimated_value_usd: Any  # Decimal or None
    quoted_fee_usd: Any       # Decimal or None — pulled from latest investigation
    investigation_id: UUID | None
    engagement_started_at: datetime | None
    engagement_closed_at: datetime | None
    engagement_fee_paid_usd: Any
    expires_at: datetime | None
    label: str | None


def generate_token(
    *,
    case_id: UUID,
    dsn: str,
    ttl_days: int | None = _DEFAULT_TTL_DAYS,
    label: str | None = None,
) -> tuple[UUID, str, datetime | None]:
    """Mint a new portal token for the given case.

    Returns ``(token_id, token_value, expires_at)``. The caller is
    responsible for surfacing the URL to the operator — we don't
    construct URLs here because the public-base-URL configuration
    lives in the CLI's environment, not in the portal module.

    ``ttl_days=None`` mints a never-expiring token; only use this
    for special-case workflows. Otherwise stick with the 90-day
    default — the operator can always issue a new token if the
    victim needs continued access.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    expires_at: datetime | None
    if ttl_days is None:
        expires_at = None
    else:
        expires_at = datetime.now(UTC) + timedelta(days=ttl_days)

    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        # Verify the case exists first so we don't insert orphan
        # token rows on operator typos.
        cur.execute(
            "SELECT id FROM public.cases WHERE id = %s",
            (str(case_id),),
        )
        if not cur.fetchone():
            raise ValueError(f"case {case_id} not found")

        # S-5 close-out: token_hmac is now the canonical column. The
        # raw `token` column has been dropped (migration 016). pepper
        # MUST be configured — without it we cannot persist a usable
        # token, and silently writing a NULL hmac would create a row
        # no future verify_token call can ever match.
        token_hmac_val = compute_token_hmac(token)
        if token_hmac_val is None:
            raise RuntimeError(
                "RECUPERO_TOKEN_PEPPER not configured — cannot mint "
                "portal tokens. Set the env var and restart the worker."
            )
        cur.execute(
            """
                INSERT INTO public.case_tokens
                    (case_id, token_hmac, expires_at, label)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
            (str(case_id), token_hmac_val, expires_at, label),
        )
        row = cur.fetchone()
        token_id = UUID(str(row["id"]))

    log.info("portal: minted token for case %s (id=%s, ttl_days=%s)",
             case_id, token_id, ttl_days)
    return token_id, token, expires_at


def verify_token(*, token: str, dsn: str) -> VerifiedToken | None:
    """Look up a token + join the case + latest-investigation fields
    the status page needs. Returns None if the token is unknown,
    expired, or revoked — the handler renders the same "link expired"
    page in all three cases so we don't leak whether a token ever
    existed.

    Lookup is by HMAC-SHA256(server_pepper, token) on the
    `token_hmac` column — never by raw-token equality. Raw-equality
    compare on an indexed column leaks byte-comparison timing (a side
    channel an attacker with millions of samples could exploit to
    guess token prefixes). HMAC makes the indexed compare uniformly
    random regardless of input.

    S-5 close-out: the legacy raw-token fallback that ran before this
    release has been removed. If RECUPERO_TOKEN_PEPPER is unset, no
    token can verify — by design. Operators MUST configure the pepper
    before this code path is exercised.
    """
    if not token or len(token) < 20:
        # Cheap guard — real tokens are 43+ chars. Reject malformed
        # input early so we don't burn a roundtrip.
        return None
    # v0.16.7 LOW: also reject excessively long tokens.
    if len(token) > 64:
        return None

    now = datetime.now(UTC)
    candidate_hmac = compute_token_hmac(token)
    if candidate_hmac is None:
        # No pepper -> no way to compute the canonical hash -> no
        # lookup. Returning None preserves the "expired/unknown/
        # revoked all look the same" property.
        log.warning(
            "verify_token: RECUPERO_TOKEN_PEPPER not configured; "
            "rejecting all tokens"
        )
        return None
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            """
                SELECT t.id AS token_id, t.case_id, t.expires_at,
                       t.revoked_at, t.label, t.last_used_at,
                       c.case_number, c.client_name, c.client_email,
                       c.status AS case_status, c.case_state,
                       c.estimated_value_usd
                  FROM public.case_tokens t
                  JOIN public.cases c ON c.id = t.case_id
                 WHERE t.token_hmac = %s
                """,
            (candidate_hmac,),
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["revoked_at"] is not None:
            log.info("portal: rejected revoked token %s", row["token_id"])
            return None
        if row["expires_at"] is not None and row["expires_at"] < now:
            log.info("portal: rejected expired token %s", row["token_id"])
            return None

        # Bump last_used_at if it's been >= 1 hour since the
        # previous bump. Reduces write amplification — see the
        # module docstring.
        last_used = row["last_used_at"]
        if last_used is None or (now - last_used) >= _LAST_USED_BUMP_INTERVAL:
            cur.execute(
                "UPDATE public.case_tokens SET last_used_at = NOW() WHERE id = %s",
                (str(row["token_id"]),),
            )

        # Fetch the latest investigation for this case to surface
        # engagement state on the portal landing page. A case with
        # zero investigations is rare-but-possible (intake-only)
        # — handle that without erroring.
        cur.execute(
            """
                SELECT id, engagement_started_at, engagement_closed_at,
                       engagement_fee_paid_usd
                  FROM public.investigations
                 WHERE case_id = %s
                 ORDER BY triggered_at DESC NULLS LAST
                 LIMIT 1
                """,
            (str(row["case_id"]),),
        )
        inv_row = cur.fetchone()

    inv_id: UUID | None = None
    eng_started = eng_closed = None
    eng_fee = None
    if inv_row:
        inv_id = UUID(str(inv_row["id"]))
        eng_started = inv_row["engagement_started_at"]
        eng_closed = inv_row["engagement_closed_at"]
        eng_fee = inv_row["engagement_fee_paid_usd"]

    # Quoted engagement fee: default to the published Tier-2
    # engagement fee (recupero._pricing.ENGAGEMENT_FEE_USD) if the
    # case hasn't already paid one. Surfaced on the sign-engagement
    # form so the victim sees the exact amount they're agreeing to.
    from recupero._pricing import ENGAGEMENT_FEE_USD
    quoted_fee = eng_fee if eng_fee is not None else ENGAGEMENT_FEE_USD

    return VerifiedToken(
        token_id=UUID(str(row["token_id"])),
        case_id=UUID(str(row["case_id"])),
        case_number=row["case_number"] or "",
        client_name=row["client_name"] or "",
        client_email=row["client_email"],
        case_status=row["case_status"] or "",
        case_state=row["case_state"],
        estimated_value_usd=row["estimated_value_usd"],
        quoted_fee_usd=quoted_fee,
        investigation_id=inv_id,
        engagement_started_at=eng_started,
        engagement_closed_at=eng_closed,
        engagement_fee_paid_usd=eng_fee,
        expires_at=row["expires_at"],
        label=row["label"],
    )


def revoke_token(*, token_id: UUID, dsn: str) -> bool:
    """Mark a token as revoked. Idempotent: re-revoking a revoked
    token is a no-op + returns True so scripts can re-run safely.
    Returns False if the token doesn't exist."""
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            """
                UPDATE public.case_tokens
                   SET revoked_at = COALESCE(revoked_at, NOW())
                 WHERE id = %s
                RETURNING id
                """,
            (str(token_id),),
        )
        return cur.fetchone() is not None


def public_portal_url(*, token: str, base_url: str | None = None) -> str:
    """Construct the user-facing portal URL.

    Resolution order:
      1. Explicit ``base_url`` kwarg (tests + ops scripts).
      2. ``RECUPERO_PORTAL_BASE_URL`` env var (preferred — set on
         Railway to the canonical hostname, e.g.
         ``https://portal.recupero.io``).
      3. Railway-assigned hostname from ``RAILWAY_PUBLIC_DOMAIN``
         (auto-populated on every Railway deploy). This makes the
         portal usable end-to-end the moment v0.5.4 ships, even
         before DNS is configured.
      4. Localhost fallback for local dev — the CLI's
         generate-customer-link warns if this path is taken.
    """
    base = (base_url or "").rstrip("/")
    if not base:
        base = os.environ.get("RECUPERO_PORTAL_BASE_URL", "").rstrip("/")
    if not base:
        railway_host = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").rstrip("/")
        if railway_host:
            # RAILWAY_PUBLIC_DOMAIN is a bare hostname (no scheme).
            base = f"https://{railway_host}"
    if not base:
        # Conservative fallback. The CLI wraps this and adds a
        # "WARN: RECUPERO_PORTAL_BASE_URL is not set" notice so the
        # operator sees it.
        base = "http://localhost:8080"
    return f"{base}/portal/{token}"


__all__ = (
    "VerifiedToken",
    "generate_token",
    "verify_token",
    "revoke_token",
    "public_portal_url",
)
