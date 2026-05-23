"""Self-service victim intake (v0.25.0).

The pre-v0.25.0 funnel required Jacob to create every case manually
in the admin UI before any trace could run. That puts the operator
in the critical path of every intake — a real bottleneck for the
$99 diagnostic product where margins don't justify operator-touch
on every customer.

This module is the entry point that removes the operator. The flow
becomes:

  victim → fills public intake form (wallet, name, email)
        → form POST creates a `cases` row with status='intake'
        → form returns the diagnostic Stripe Checkout URL
        → victim pays
        → existing Stripe webhook dispatcher (payments/dispatcher.py)
          parses `client_reference_id=diag:<case>:<chain>:<seed>`
          and INSERTs an investigations row with status='pending'
        → existing worker claim loop picks it up next tick
        → existing trace pipeline → emit_brief → deliverables

The new surface this module owns:

  * ``IntakePayload`` — validated form fields with helpful error
    messages
  * ``validate_intake_payload`` — pure function; raises
    ``IntakeValidationError`` with the specific bad field on
    invalid input
  * ``create_case_from_intake`` — INSERTs the cases row + returns
    the new case_id, then the caller builds the diagnostic
    payment link

Failure mode: any DB error during case creation surfaces as a
typed exception the FastAPI route handler turns into a 5xx, with
a generic detail string so DSN / password info doesn't leak.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

log = logging.getLogger(__name__)


# Chains the intake form accepts. Must match what the trace pipeline
# can actually handle — recupero.models.Chain enum values.
_SUPPORTED_CHAINS = frozenset({
    "ethereum", "arbitrum", "base", "polygon", "bsc",
    "solana", "tron", "bitcoin", "hyperliquid",
})

# Address shape validation per chain. Cheap pre-flight before the
# trace pipeline runs — bad addresses get rejected at the form
# stage rather than burning a Stripe checkout session that resolves
# to a non-existent wallet.
_EVM_CHAINS = frozenset({"ethereum", "arbitrum", "base", "polygon", "bsc", "hyperliquid"})

# Plausible-Ethereum-address regex. The trace pipeline does a
# stricter checksum check downstream; this is a "form-level
# obvious typo" filter.
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Solana base58 — variable length but typically 32-44 chars. Cheap
# shape check; the trace pipeline validates further.
_SOL_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# Tron base58check — addresses begin with 'T' and are 34 chars.
_TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")

# Bitcoin: P2PKH (1...), P2SH (3...), bech32 (bc1...). We accept
# any of these shapes.
_BTC_ADDR_RE = re.compile(r"^(bc1[0-9a-zA-Z]{8,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$")

# Minimal email validation. Not RFC 5321 — just enough to reject
# obvious typos so the operator's inbox doesn't fill up with
# undeliverable confirmation emails.
#
# ReDoS note (regex-audit, v0.20.x): the previous shape
# ``^[^@\s]+@[^@\s]+\.[^@\s]+$`` was polynomial-backtracking on
# inputs of the form ``a@<huge>`` (no final dot) because the two
# right-hand ``[^@\s]+`` quantifiers both admit ``.`` so the engine
# tries every split point for where the literal ``.`` lives.
# Hardened by (a) capping length BEFORE the match (see
# ``_EMAIL_MAX_LEN`` below — enforced in ``validate_intake_payload``)
# and (b) replacing the host-part with a class that excludes ``.``,
# so the ``\.`` separator is unambiguous and matching is linear.
_EMAIL_MAX_LEN = 320  # RFC 5321 ceiling — enforced BEFORE the regex
_EMAIL_RE = re.compile(r"^[^@\s.]+(?:\.[^@\s.]+)*@[^@\s.]+(?:\.[^@\s.]+)+$")


# RIGOR-Jacob E: Unicode-trojan code-point set we reject on every
# user-supplied free-text intake field. Covers:
#   * NUL byte (psycopg-crash on Postgres TEXT insert)
#   * Bidi formatting / overrides / isolates (Trojan-Source spoofs)
#   * Zero-width chars (invisible-payload smuggling)
#   * BOM (display-render inconsistency)
# Standard `str.strip()` only removes ASCII whitespace — these
# code points survive the strip and corrupt downstream displays.
_FORBIDDEN_CHARS: frozenset[str] = frozenset({
    "\x00",  # NUL
    "‪",  # LEFT-TO-RIGHT EMBEDDING
    "‫",  # RIGHT-TO-LEFT EMBEDDING
    "‬",  # POP DIRECTIONAL FORMATTING
    "‭",  # LEFT-TO-RIGHT OVERRIDE
    "‮",  # RIGHT-TO-LEFT OVERRIDE
    "⁦",  # LEFT-TO-RIGHT ISOLATE
    "⁧",  # RIGHT-TO-LEFT ISOLATE
    "⁨",  # FIRST-STRONG ISOLATE
    "⁩",  # POP DIRECTIONAL ISOLATE
    "​",  # ZERO-WIDTH SPACE
    "‌",  # ZERO-WIDTH NON-JOINER
    "‍",  # ZERO-WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "﻿",  # BOM / ZERO-WIDTH NO-BREAK SPACE
})


class IntakeValidationError(ValueError):
    """Raised when an intake form submission has a field-level
    validation error. ``field`` is the form field name; ``detail``
    is a human-readable explanation suitable for the form UI."""

    def __init__(self, field: str, detail: str) -> None:
        super().__init__(f"{field}: {detail}")
        self.field = field
        self.detail = detail


def _reject_unicode_trojans(value: str, *, field: str) -> None:
    """Raise IntakeValidationError when ``value`` contains any
    code point in _FORBIDDEN_CHARS. Pure check; no normalization."""
    for ch in value:
        if ch in _FORBIDDEN_CHARS:
            raise IntakeValidationError(
                field,
                "Contains a hidden / invisible character "
                "(bidi-override, zero-width, or NUL). Please retype "
                "this field directly without copy-pasting from a "
                "rich-text source.",
            )


@dataclass(frozen=True)
class IntakePayload:
    """Validated intake form submission, ready for DB insert."""
    client_name: str
    client_email: str
    seed_address: str
    chain: str
    incident_date_iso: str   # ISO date (YYYY-MM-DD) — when the theft happened
    description: str         # free-text victim story (truncated to 2000 chars)
    country: str | None = None   # ISO country code or full name; optional


def validate_intake_payload(form: dict[str, Any]) -> IntakePayload:
    """Validate raw form input. Raises ``IntakeValidationError`` on the
    first failing field with a UI-suitable message.

    Pure function — no DB access. Callers should run this BEFORE
    opening any DB transaction so a bad form doesn't burn a
    cases row.
    """
    name = (form.get("client_name") or "").strip()
    if not name:
        raise IntakeValidationError(
            "client_name",
            "Please enter your full legal name as it appears on your ID.",
        )
    if len(name) > 200:
        raise IntakeValidationError(
            "client_name",
            "Name is too long (200 character limit).",
        )
    # RIGOR-Jacob E: bidi-override / zero-width / NUL rejection.
    _reject_unicode_trojans(name, field="client_name")

    email = (form.get("client_email") or "").strip().lower()
    if not email:
        raise IntakeValidationError(
            "client_email",
            "Please enter the email address where you'd like updates sent.",
        )
    # ReDoS hardening: length cap BEFORE regex so a multi-MB
    # attacker-supplied "email" can never reach _EMAIL_RE at all.
    # (Even though _EMAIL_RE is now linear, defense in depth.)
    if len(email) > _EMAIL_MAX_LEN:
        raise IntakeValidationError(
            "client_email",
            "Email is too long.",
        )
    if not _EMAIL_RE.match(email):
        raise IntakeValidationError(
            "client_email",
            "That doesn't look like a valid email address.",
        )

    chain = (form.get("chain") or "").strip().lower()
    if not chain:
        raise IntakeValidationError(
            "chain",
            "Please select which blockchain the stolen funds were on.",
        )
    if chain not in _SUPPORTED_CHAINS:
        raise IntakeValidationError(
            "chain",
            f"We don't yet support {chain!r}. Supported chains: "
            f"{', '.join(sorted(_SUPPORTED_CHAINS))}.",
        )

    seed_address = (form.get("seed_address") or "").strip()
    if not seed_address:
        raise IntakeValidationError(
            "seed_address",
            "Please enter your wallet address — the one that was drained.",
        )
    if not _validate_address_shape(seed_address, chain):
        raise IntakeValidationError(
            "seed_address",
            f"That doesn't look like a valid {chain} wallet address. "
            "Please double-check and paste the full address.",
        )

    # v0.25.0: incident_date is required for the LE filing later (the
    # theft timestamp is the anchor for the 30-day freeze-window
    # response timeline). We accept any ISO-shaped date.
    incident_date = (form.get("incident_date") or "").strip()
    if not incident_date:
        raise IntakeValidationError(
            "incident_date",
            "Please enter the date the theft happened, even if "
            "approximate.",
        )
    if not _is_valid_iso_date(incident_date):
        raise IntakeValidationError(
            "incident_date",
            "Please enter the date in YYYY-MM-DD format. The date "
            "must be in the past 10 years and not in the future.",
        )

    # Description is required for the operator to triage; rejecting
    # empty descriptions is the cheapest filter against spam intake.
    description = (form.get("description") or "").strip()
    if not description:
        raise IntakeValidationError(
            "description",
            "Please describe what happened — even one sentence helps "
            "us understand the case.",
        )
    # v0.25.1 (A-3): never silently truncate the narrative — that
    # risks chopping off a critical sentence ("...I sent to 0xabc...")
    # without warning the victim. Make the user trim instead so we
    # get a clean, complete story for triage.
    if len(description) > 2000:
        raise IntakeValidationError(
            "description",
            "Description is too long (2000 character limit). Please trim.",
        )
    # RIGOR-Jacob E: bidi-override / zero-width / NUL rejection on
    # the free-text description (highest-impact display-spoof field).
    _reject_unicode_trojans(description, field="description")

    country = (form.get("country") or "").strip() or None
    if country and len(country) > 100:
        country = country[:100]

    return IntakePayload(
        client_name=name,
        client_email=email,
        seed_address=seed_address,
        chain=chain,
        incident_date_iso=incident_date,
        description=description,
        country=country,
    )


def _validate_address_shape(address: str, chain: str) -> bool:
    """Cheap shape check per chain. False on obvious typos; True
    when the address could plausibly be valid (the trace pipeline
    runs the strict check downstream).
    """
    if chain in _EVM_CHAINS:
        return bool(_EVM_ADDR_RE.match(address))
    if chain == "solana":
        return bool(_SOL_ADDR_RE.match(address))
    if chain == "tron":
        return bool(_TRON_ADDR_RE.match(address))
    if chain == "bitcoin":
        return bool(_BTC_ADDR_RE.match(address))
    # Unknown chain — let the chain validator above catch it; if
    # somehow we get here, be permissive.
    return True


def _is_valid_iso_date(s: str) -> bool:
    """ISO YYYY-MM-DD validator. Accepts trailing 'Z' / time-of-day
    (e.g. '2026-04-19T12:00:00Z') but only validates the date part.

    v0.25.1 (A-1): bound the parsed date to ``[today - 10 years, today]``.
    Without bounds the field accepts implausible values (1900-01-01,
    9999-12-31, future dates) that downstream poison the freeze-window
    timeline computations in worker/_followup.py (72h/7d/14d offsets
    from incident_date), permanently mis-classifying the case.
    """
    from datetime import date, timedelta
    try:
        # Take the first 10 chars and parse as YYYY-MM-DD
        parsed = date.fromisoformat(s[:10])
    except (ValueError, TypeError):
        return False
    today = date.today()
    # Reject future dates and anything older than 10 years.
    if parsed > today:
        return False
    if parsed < today - timedelta(days=10 * 365):
        return False
    return True


def create_case_from_intake(
    payload: IntakePayload,
    *,
    dsn: str,
) -> UUID:
    """Insert a ``cases`` row from the validated intake payload.
    Returns the new case_id (UUID) the caller uses to build the
    diagnostic Payment Link.

    Raises:
        RuntimeError: any DB error. The caller should turn this
            into a 5xx with a generic detail (don't leak DSN).
    """
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        raise RuntimeError("psycopg not installed") from None

    from recupero._common import db_connect

    sql = """
        INSERT INTO public.cases (
            id, case_number, client_name, client_email, country,
            description, incident_date, chain, seed_address,
            created_at, status
        ) VALUES (
            %(id)s, %(case_number)s, %(name)s, %(email)s, %(country)s,
            %(description)s, %(incident)s, %(chain)s, %(seed)s,
            NOW(), 'intake'
        )
        RETURNING id
    """

    # v0.25.1 (A-2): the previous build used a fixed 8-char UUID
    # prefix which hits the birthday-paradox boundary near 80k cases
    # (~1% collision at 10k). At scale a UniqueViolation on
    # `cases.case_number` would surface as a generic 503 the victim
    # cannot recover from. We now retry with a fresh UUID up to 3
    # times. The case_number includes the current year for human-
    # readable grouping ("RCP-INTAKE-2026-<8 hex>"); year+8 chars
    # ≈ 4B per-year combinations, well past any realistic load.
    from datetime import date as _date

    from psycopg import errors as _pg_errors  # type: ignore[import-not-found]

    year = _date.today().year
    last_exc: Exception | None = None
    for _attempt in range(3):
        new_case_id = uuid4()
        case_number = f"RCP-INTAKE-{year}-{str(new_case_id)[:8]}"
        try:
            with db_connect(dsn) as conn, conn.cursor() as cur:
                cur.execute(sql, {
                    "id": str(new_case_id),
                    "case_number": case_number,
                    "name": payload.client_name,
                    "email": payload.client_email,
                    "country": payload.country,
                    "description": payload.description,
                    "incident": payload.incident_date_iso[:10],
                    "chain": payload.chain,
                    "seed": payload.seed_address,
                })
                row = cur.fetchone()
                if not row:
                    raise RuntimeError("INSERT returned no row")
                return row[0] if isinstance(row[0], UUID) else UUID(str(row[0]))
        except _pg_errors.UniqueViolation as exc:
            # Collision on case_number — retry with a fresh UUID. Log
            # at INFO since this is a rare-but-expected branch.
            log.info(
                "create_case_from_intake: case_number collision on %r; "
                "retrying with fresh UUID (attempt %d/3)",
                case_number, _attempt + 1,
            )
            last_exc = exc
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "create_case_from_intake failed (email=%s, chain=%s): %s",
                payload.client_email, payload.chain, exc,
            )
            raise RuntimeError("case creation failed") from None

    # All 3 retries hit collisions — vanishingly unlikely with full UUID.
    log.warning(
        "create_case_from_intake: 3 consecutive case_number collisions "
        "(email=%s); last error: %s",
        payload.client_email, last_exc,
    )
    raise RuntimeError("case creation failed") from None


__all__ = (
    "IntakePayload",
    "IntakeValidationError",
    "validate_intake_payload",
    "create_case_from_intake",
)
