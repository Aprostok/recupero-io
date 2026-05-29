"""Email-sending primitive (Resend REST API).

The worker generates customer-facing artifacts (victim summary,
engagement letter, compliance freeze letters, LE handoffs) but
until this module landed, sending them was manual operator work
— attach to email, type recipient address, hit send. For a
service company scaling past the first few cases, that's a real
drag.

This module is the lowest-level send primitive: it calls Resend's
REST API with optional file attachments and logs every attempt
(success or failure) to ``public.emails_sent`` for audit + idempotency.

Higher-level "auto-send victim summary on case completion" /
"operator-triggered freeze-letter send" wrappers live in
``worker/_deliverables.py`` and a future CLI helper. Keeping this
module narrow makes it easy to swap providers (SendGrid, Postmark)
later without rewriting the dispatch logic.

Configuration
-------------

Required env vars:
  * RESEND_API_KEY        — API key from https://resend.com
  * SUPABASE_DB_URL       — for the audit log (same DB the worker uses)

Optional env vars:
  * RECUPERO_EMAIL_FROM       — From: address. Default falls back to
                                ``RECUPERO_INVESTIGATOR_EMAIL`` and
                                ultimately to ``compliance@recupero.io``
                                when neither is set.
  * RECUPERO_EMAIL_FROM_NAME  — From: display name (default "Recupero Investigation Services")
  * RECUPERO_DISABLE_EMAIL    — If "1", skip sending entirely + log only.
                                For local development / testing.

Idempotency
-----------

The auto-send wrappers check the ``emails_sent`` audit log before
sending:

    SELECT 1 FROM emails_sent
     WHERE investigation_id = $1
       AND email_type = $2
       AND error_message IS NULL
     LIMIT 1

If a row matches (a previous successful send), the wrapper skips
re-sending. Failed sends DO NOT count toward idempotency — the
worker can re-attempt them on the next claim/resume cycle.
"""

from __future__ import annotations

import base64
import json
import logging
import mimetypes
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


_RESEND_API_BASE = "https://api.resend.com"


# v0.20.2 (logging-content audit): mask the local-part of recipient
# email addresses before they land in any log line. The audit DB row
# still carries the FULL address (op-data), but stdout / Railway /
# trace.log get the masked form so a leaked log archive can't reveal
# the victim's actual inbox.
#
# Format: "f***@gmail.com". 1-char prefix is enough for an operator
# debugging delivery patterns; the rest is replaced with ``***``. A
# string without an "@" is fully masked since it's either malformed or
# already a non-email value.
def _mask_email_for_log(addr: object) -> str:
    """Return a log-safe rendering of an email address. Never echoes
    the full local-part. Accepts any object (stringifies first) so
    callsites don't need null-guards."""
    if addr is None:
        return "<none>"
    s = str(addr)
    if "@" not in s:
        return "***"
    local, _, domain = s.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"

# v0.19.0: From-address default now resolves at call-time via the
# canonical investigator-identity helper so an unconfigured deploy
# can't ship the dev's email on every outbound message. Pre-v0.19.0
# `_DEFAULT_FROM_ADDR = "alec@recupero.io"` was baked in as a module
# constant; rotating RECUPERO_INVESTIGATOR_EMAIL had no effect on
# already-imported workers.
_DEFAULT_FROM_NAME = "Recupero Investigation Services"

# Hard cap on a single header line. RFC 5322 §2.1.1 caps lines at 998
# octets excluding CRLF; we cap raw header values short of that so even
# after encoding/folding the wire bytes stay under the limit. A
# 10KB subject line has crashed real MTAs in the past — bound the
# blast radius here at the entry point rather than trusting Resend
# to do it for us.
_EMAIL_HEADER_MAX_LEN = 800

# Characters that have no legitimate place in any RFC 5322 header
# value and that an attacker can leverage to inject new headers
# (\r\n) or bypass header parsing entirely (NUL). Bidi controls
# (U+202A..U+202E, U+2066..U+2069) can hide the real sender display
# name from the recipient — Gmail / Outlook render them as-is.
# Assembled from explicit codepoints so the source is unambiguous
# at code-review time and grep-friendly.
_HEADER_FORBIDDEN_CHARS = (
    "\r\n\x00\x0b\x0c"
    + "".join(chr(c) for c in range(0x202A, 0x202E + 1))  # LRE..RLO
    + "".join(chr(c) for c in range(0x2066, 0x2069 + 1))  # LRI..PDI
)
_HEADER_STRIP_RE = re.compile(
    "[" + re.escape(_HEADER_FORBIDDEN_CHARS) + "]"
)
_UNUSED_BIDI_SCRATCHPAD = (  # noqa: E501
    # Vestigial: superseded by _HEADER_FORBIDDEN_CHARS above. Left
    # as a string-typed sink so a clean replace-all doesn't have to
    # touch lines containing non-printable bidi characters.
    "‪-‮"  # bidi formatting (LRE..RLO)
    "⁦-⁩"  # bidi isolates (LRI..PDI)
    "]" + "" + "[also strip:  ‪-‮⁦-⁩]"
)

# Strict-ish RFC 5322 address regex. Not a full grammar — we
# intentionally REJECT the obscure-but-legal forms (quoted local
# parts with @ inside, IP-literal hosts, comments) because they
# never show up in legitimate victim / law-firm / issuer addresses
# and they're the exact shapes an attacker uses to smuggle data
# past naïve parsers.
_EMAIL_ADDR_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@"            # local-part (no quoted form)
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"  # labels
    r"[A-Za-z]{2,63}$"                       # TLD
)


def _sanitize_email_header(value: str | None, *, max_length: int = _EMAIL_HEADER_MAX_LEN) -> str:
    """Strip CRLF / NUL / bidi controls from any string that's about
    to land in an RFC 5322 header (Subject, From display name, cc/bcc,
    To, etc.), and cap length to keep MTAs from choking on a 10KB
    subject line.

    Returns the sanitized string. Never raises — header injection is
    silently neutralized at the boundary so an attacker who poisons
    a label or display-name field can't crash the worker either.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    # RIGOR-Wave6 hardening: TRUNCATE at the first forbidden char
    # rather than `re.sub("", ...)` which would silently concatenate
    # the post-CRLF segment ("Bcc: leak@evil.com") onto the legitimate
    # subject ("Freeze"). With truncation, the attacker's injected
    # header fragment is fully discarded — only the prefix preceding
    # any CRLF / NUL / bidi / etc. survives.
    m = _HEADER_STRIP_RE.search(value)
    cleaned = value[:m.start()] if m is not None else value
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def _validate_email_address(addr: str | None) -> bool:
    """Return True iff ``addr`` is a plain RFC-5322-ish ``local@host``
    address that passes a strict regex. Rejects:
        * empty / None
        * any CR / LF / NUL / bidi / whitespace inside
        * quoted local parts (``"a@b"@c.com``)
        * IP-literal hosts (``a@[1.2.3.4]``)
        * multiple @ signs
        * trailing dots / TLD < 2 chars
        * length > 254 (RFC 3696 §3 ceiling)

    The downstream Resend API does its own validation but by the time
    a malformed address reaches Resend we've already minted a portal
    token / advanced a freeze-letter stage / written an audit row —
    fail FAST at the dispatcher so we don't leave half-written state.
    """
    if not addr or not isinstance(addr, str):
        return False
    if len(addr) > 254:
        return False
    if _HEADER_STRIP_RE.search(addr) is not None:
        return False
    # The regex is anchored; whitespace + control chars fail it.
    return _EMAIL_ADDR_RE.match(addr) is not None


def _default_from_addr() -> str:
    """Resolve the canonical From: fallback address at call time."""
    from recupero._common import investigator_defaults
    return investigator_defaults()["INVESTIGATOR_EMAIL"]

# Retry sequence (seconds) for transient Resend failures. Mirrors
# the ai_editorial retry budget so worker logs read consistently
# across email + AI transients. 4 total attempts (initial + 3
# retries) with 5s / 15s / 30s waits; tighter than the AI retry
# because we don't expect Resend to need a full minute to recover
# from a brief 5xx (their SLOs are tighter than the Anthropic
# capacity-overload events the AI retry was designed for).
_RESEND_RETRY_WAITS_SEC = (5, 15, 30)


# v0.19.1 (round-12 arch-HIGH-3): delegate to the canonical env_truthy
# helper so a single source defines what "true" means across the worker.
# Pre-v0.19.1 this module kept its own `_is_truthy` while followup /
# deliverables / ops-commands checked `== "1"` — an operator setting
# `RECUPERO_DISABLE_EMAIL=true` got email skipped on the trace pipeline
# but emails still went out from the followup cron + send_le_handoff.
# Partial mode is the hardest debug shape.
# RIGOR-2: tests patch `recupero.worker._email.psycopg.connect` via
# unittest.mock.patch (see tests/test_email_sender.py + test_round13_*).
# psycopg MUST be a top-level module attribute even though we don't
# reference it by name; the module attribute IS the test-mock seam.
# Ruff F401 wants to remove it (no in-file reference); that breaks
# every DB-mock test in the suite.
import psycopg  # noqa: F401, E402

from recupero._common import db_connect  # noqa: E402
from recupero._common import env_truthy as _is_truthy_env


def _resend_send_with_retry(req: urllib.request.Request) -> dict[str, Any]:
    """Send a Resend API request with retry-on-transient logic.

    Retriable: 5xx HTTP responses, urllib URLError (DNS/connect/
    timeout), socket timeout, 429 rate-limit. Non-retriable: other 4xx
    (caller bug: bad address, invalid template, auth) — re-raised
    immediately so the audit log captures the real error message
    instead of burning 50s on retries that will all fail the same way.

    Backoff: per-attempt waits from _RESEND_RETRY_WAITS_SEC with
    jitter (+/- 25%). 429 responses honor the `Retry-After` header
    when present (Resend sends it on rate-limit), capped to the
    largest configured wait to bound worst-case latency.

    v0.16.8 (round-9 worker-resilience HIGH):
      * Honor Retry-After on 429.
      * Add per-attempt jitter so concurrent senders don't thundering-
        herd against Resend after a brief outage.

    Returns the parsed JSON response on success. Raises the LAST
    exception on exhaustion (HTTPError or URLError) so the existing
    handler in send_email can format it for the audit row without
    changes.
    """
    import random as _random
    last_exc: BaseException | None = None
    retry_after_override: float | None = None
    total_attempts = len(_RESEND_RETRY_WAITS_SEC) + 1
    for attempt_idx in range(total_attempts):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Other 4xx → caller bug. Don't retry.
            if 400 <= exc.code < 500 and exc.code != 429:
                raise
            last_exc = exc
            # Resend (and most APIs) include Retry-After on 429.
            # Use it in place of our fixed backoff for the NEXT
            # retry — bounded so a misbehaving header doesn't hang
            # the worker.
            if exc.code == 429 and exc.headers is not None:
                ra = exc.headers.get("Retry-After")
                if ra:
                    try:
                        retry_after_override = min(
                            float(ra), float(max(_RESEND_RETRY_WAITS_SEC)) * 2,
                        )
                    except (TypeError, ValueError):
                        retry_after_override = None
        except (urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
        if attempt_idx >= len(_RESEND_RETRY_WAITS_SEC):
            break
        base_wait = _RESEND_RETRY_WAITS_SEC[attempt_idx]
        if retry_after_override is not None:
            base_wait = max(base_wait, retry_after_override)
            retry_after_override = None
        # Jitter ±25% so concurrent senders desynchronize after a
        # shared transient. Without jitter, 20 workers all retry on
        # the exact same wall-clock offset and re-hit Resend at the
        # same instant.
        jitter = _random.uniform(-0.25, 0.25) * base_wait
        wait_sec = max(0.1, base_wait + jitter)
        log.warning(
            "resend transient failure on attempt %d/%d — retrying in %.1fs: %s",
            attempt_idx + 1, total_attempts, wait_sec, last_exc,
        )
        time.sleep(wait_sec)
    # v0.17.3 (round-10 audit HIGH): replaced `assert last_exc is not None`
    # because asserts are STRIPPED under `python -O`, then `raise None`
    # raises `TypeError: exceptions must derive from BaseException`
    # masking the original retry-exhaustion error.
    if last_exc is None:
        raise RuntimeError(
            "resend retry loop exited without exception — unreachable"
        )
    raise last_exc


@dataclass(frozen=True)
class EmailResult:
    """Outcome of a single send attempt. Always logged regardless
    of success/failure; the audit row's error_message disambiguates."""
    success: bool
    message_id: str | None
    error: str | None
    skipped: bool = False  # True when RECUPERO_DISABLE_EMAIL=1 was set


def send_email(
    *,
    to: str,
    subject: str,
    html: str,
    investigation_id: UUID | str | None = None,
    email_type: str,
    attachments: list[Path] | None = None,
    from_addr: str | None = None,
    from_name: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    preview_text: str | None = None,
    sent_by: str = "worker:auto",
    dsn: str | None = None,
    # v0.32 — Tier-0 gap #1 mandatory human-review gate inputs.
    # Pass a case_id + the on-disk artifact path that this email is
    # delivering and the LAST-GATE check refuses to send unless an
    # approved (or audited-override) brief_reviews row exists for the
    # artifact's exact SHA-256. None/None skips the gate so internal
    # ops emails (digest summaries, audit notifications) that don't
    # carry a case artifact still flow. Local-dev without a DSN also
    # skips the gate (the gate logs WARN and returns).
    review_case_id: UUID | str | None = None,
    review_artifact_kind: str | None = None,
    review_artifact_path: Path | None = None,
) -> EmailResult:
    """Send one email via Resend. Logs the attempt to emails_sent
    regardless of outcome.

    ``email_type`` is one of: 'victim_summary', 'engagement_letter',
    'freeze_letter', 'le_handoff'. Drives the audit-log
    categorization + the idempotency check.

    ``attachments`` is a list of paths to local files; each is
    base64-encoded and attached. Resend's REST API caps total
    message size around 40MB — caller should filter to the
    intended attachments before calling.

    Tier-0 review gate (v0.32): when ``review_case_id``,
    ``review_artifact_kind``, AND ``review_artifact_path`` are all
    supplied, the LAST gate before send is a call to
    ``recupero.dispatcher.require_review_approved``. If no approved
    review row matches the artifact's SHA-256, the send is REFUSED
    and ``BriefNotReviewedError`` propagates (the EmailResult never
    materializes — the caller gets the exception).  Local dev
    without ``SUPABASE_DB_URL`` skips the gate with a WARN log so
    test runs aren't blocked.
    """
    # Adversarial-input guard. Run BEFORE the disable switch /
    # API-key check so the caller gets a consistent rejection
    # regardless of deploy mode, and so we never advance pipeline
    # state (mint portal token, claim freeze-letter stage, write
    # emails_sent row with message_id=None) on a poisoned address.
    #
    # 1. Reject malformed recipient — strict regex, no quoted/IP
    #    literal forms. Defense against `victim@bank.com\r\nBcc:
    #    leak@evil.com` and `"a@b"@c.com` smuggle shapes.
    # 2. Strip CRLF / NUL / bidi controls from the subject. A
    #    poisoned counterparty_label flowing into the freeze-letter
    #    or freeze-followup subject line would otherwise inject
    #    additional headers via Resend's JSON-to-MIME translation.
    # 3. Same validation on each cc / bcc entry. Anything bad gets
    #    DROPPED (not just sanitized) — better to silently lose a
    #    cc than to leak the body to an injected recipient.
    if not _validate_email_address(to):
        # NB: ``err`` echoes the raw ``to`` for the audit-DB row but
        # the LOG line uses only the email_type so a malformed
        # attacker-supplied address can't write itself into stdout.
        err = f"invalid recipient address rejected: {to!r}"
        log.warning("send_email: invalid recipient (type=%s)", email_type)
        _log_to_audit(
            dsn=dsn, investigation_id=investigation_id,
            to_address=str(to)[:200], subject=str(subject)[:200],
            email_type=email_type,
            message_id=None, error_message=err,
            sent_by=sent_by, preview_text=preview_text,
            attachment_names=[p.name for p in (attachments or [])],
        )
        return EmailResult(success=False, message_id=None, error=err)
    subject = _sanitize_email_header(subject)
    if cc is not None:
        cc = [a for a in cc if _validate_email_address(a)]
    if bcc is not None:
        bcc = [a for a in bcc if _validate_email_address(a)]

    # v0.32 Tier-0 gap #1 — MANDATORY HUMAN REVIEW GATE.
    #
    # This is the LAST gate before the artifact leaves the system.
    # By contract the dispatcher refuses the send unless an approved
    # (or audited-override) brief_reviews row exists for the artifact's
    # exact SHA-256. The gate raises BriefNotReviewedError on refusal,
    # which propagates up to the caller — DO NOT catch it here.
    # Internal-ops emails (digest summary etc.) without a case
    # artifact pass review_artifact_path=None and bypass the gate.
    # Local dev without a DSN also short-circuits inside the gate.
    if (
        review_case_id is not None
        and review_artifact_kind is not None
        and review_artifact_path is not None
    ):
        from recupero.dispatcher import require_review_approved
        require_review_approved(
            case_id=review_case_id,
            artifact_kind=review_artifact_kind,
            artifact_path=review_artifact_path,
            dsn=dsn,
        )

    # Honor the disable switch for local dev / testing.
    # v0.16.10 (round-9 worker LOW): accept any truthy variant
    # ("1", "true", "yes", "on", case-insensitive). Pre-v0.16.10 only
    # the literal "1" worked, so operators who set "true" expected
    # disabled email but got real sends.
    if _is_truthy_env("RECUPERO_DISABLE_EMAIL"):
        log.info(
            "RECUPERO_DISABLE_EMAIL set — skipping send to %s "
            "(would have sent: type=%s, attachments=%d)",
            _mask_email_for_log(to), email_type,
            len(attachments) if attachments else 0,
        )
        return EmailResult(
            success=False, message_id=None,
            error="skipped: RECUPERO_DISABLE_EMAIL",
            skipped=True,
        )

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        err = "RESEND_API_KEY not configured"
        log.warning(
            "send_email: %s; cannot send to %s",
            err, _mask_email_for_log(to),
        )
        _log_to_audit(
            dsn=dsn, investigation_id=investigation_id,
            to_address=to, subject=subject, email_type=email_type,
            message_id=None, error_message=err,
            sent_by=sent_by, preview_text=preview_text,
            attachment_names=[p.name for p in (attachments or [])],
        )
        return EmailResult(success=False, message_id=None, error=err)

    from_full = _format_from_header(from_addr, from_name)

    body: dict[str, Any] = {
        "from": from_full,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if cc:
        body["cc"] = cc
    if bcc:
        body["bcc"] = bcc

    # Encode attachments — Resend expects {filename, content (base64)}
    if attachments:
        encoded = []
        for ap in attachments:
            try:
                content = ap.read_bytes()
                encoded.append({
                    "filename": ap.name,
                    "content": base64.b64encode(content).decode("ascii"),
                    "content_type": (
                        mimetypes.guess_type(ap.name)[0]
                        or "application/octet-stream"
                    ),
                })
            except Exception as e:  # noqa: BLE001
                log.warning("email attachment %s read failed: %s", ap, e)
                continue
        if encoded:
            body["attachments"] = encoded

    req = urllib.request.Request(
        f"{_RESEND_API_BASE}/emails",
        data=json.dumps(body, allow_nan=False, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    message_id = None
    error_message = None
    try:
        resp_body = _resend_send_with_retry(req)
        message_id = resp_body.get("id")
        log.info(
            "sent email to=%s type=%s subject=%r message_id=%s",
            _mask_email_for_log(to), email_type, subject[:50], message_id,
        )
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8")
        except Exception:  # noqa: BLE001
            err_body = ""
        # ``err_body`` is preserved on the audit row (error_message) but
        # NOT echoed to the log line: the Resend HTTP error body
        # routinely contains the recipient address and a fragment of
        # the rejected payload (subject, sometimes preview text). The
        # status code is enough for an operator to triage; the audit
        # row carries the full body for forensic review.
        error_message = f"HTTP {exc.code}: {err_body[:500]}"
        log.warning(
            "send_email failed to=%s type=%s status=%d",
            _mask_email_for_log(to), email_type, exc.code,
        )
    except urllib.error.URLError as exc:
        error_message = f"URLError: {exc.reason}"
        log.warning(
            "send_email URLError to=%s type=%s reason=%s",
            _mask_email_for_log(to), email_type, exc.reason,
        )
    except Exception as exc:  # noqa: BLE001
        error_message = f"{type(exc).__name__}: {exc}"
        log.warning(
            "send_email unexpected error to=%s type=%s err=%s",
            _mask_email_for_log(to), email_type, exc,
        )

    # Always log to audit (success or failure)
    _log_to_audit(
        dsn=dsn, investigation_id=investigation_id,
        to_address=to, subject=subject, email_type=email_type,
        message_id=message_id, error_message=error_message,
        sent_by=sent_by, preview_text=preview_text,
        attachment_names=[p.name for p in (attachments or [])],
    )

    return EmailResult(
        success=(error_message is None),
        message_id=message_id,
        error=error_message,
    )


def has_been_sent(
    *,
    investigation_id: UUID | str,
    email_type: str,
    dsn: str | None = None,
) -> bool:
    """Idempotency check: has the worker already successfully sent
    an email of this type for this investigation?

    Returns True if at least one emails_sent row exists with
    error_message IS NULL for the given (investigation_id, email_type).
    Failed sends don't count — the worker is allowed to retry them.
    """
    dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.warning("has_been_sent: no DSN; cannot check audit log")
        return False

    try:
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                    SELECT 1 FROM public.emails_sent
                     WHERE investigation_id = %s
                       AND email_type = %s
                       AND error_message IS NULL
                     LIMIT 1
                    """,
                (str(investigation_id), email_type),
            )
            return cur.fetchone() is not None
    except Exception as exc:  # noqa: BLE001
        # v0.19.2 (round-13 pipeline-HIGH-1): fail-CLOSED on audit-query
        # failure. Pre-v0.19.2 a transient pooler blip caused the
        # idempotency check to return False (= "not yet sent"), and the
        # caller would then send the victim summary again — but the
        # victim-summary path mints a NEW portal token + a fresh Stripe
        # payment link. Customer who already paid the engagement fee
        # could click the new link and pay it twice; the dispatcher
        # COALESCEs `engagement_started_at` so state doesn't reset but
        # both payments land as separate Stripe charges. Treating "DB
        # unreachable" as "already sent" trades a delayed legitimate
        # send for an impossible duplicate charge. Operators can force
        # a send via the ops CLI once the DB recovers.
        log.warning(
            "has_been_sent: audit query failed — failing closed to "
            "prevent duplicate send: %s", exc,
        )
        return True


# ----- internals ----- #


def _format_from_header(
    from_addr: str | None, from_name: str | None,
) -> str:
    """Build the From: header. Resend accepts ``Name <email@host>``.

    v0.18.4 (round-11 worker-CRIT-004 + worker-HIGH-008):
    * detect the case where the operator pasted the WHOLE header
      into RECUPERO_EMAIL_FROM (e.g. `Recupero <alec@recupero.io>`).
      Pre-v0.18.4 we double-wrapped it into
      `Recupero Investigation Services <Recupero <alec@recupero.io>>`
      which Resend rejects as malformed RFC 5322.
    * reject any From containing `\r`, `\n`, `\0`, `<`, `>` in the
      NAME portion — CRLF in the env var would have allowed header
      injection (Bcc: attacker@…) through Resend's JSON encoding.
    """
    addr_raw = (from_addr
            or os.environ.get("RECUPERO_EMAIL_FROM", "").strip()
            or _default_from_addr())
    name_raw = (from_name
            or os.environ.get("RECUPERO_EMAIL_FROM_NAME", "").strip()
            or _DEFAULT_FROM_NAME)

    # If operator pasted the whole header `Name <addr>` into FROM,
    # use it verbatim and skip name-wrapping.
    if "<" in addr_raw and ">" in addr_raw:
        # Sanitize control chars (CRLF/NUL/bidi) and cap length.
        return _sanitize_email_header(addr_raw)

    # Sanitize name: strip CRLF / NUL / bidi + cap length, then
    # remove angle brackets (which would break the wrap below).
    name = _sanitize_email_header(name_raw).replace("<", "").replace(">", "")
    # Sanitize addr the same way.
    addr = _sanitize_email_header(addr_raw).replace("<", "").replace(">", "")
    # Defense against From-spoofing: if the display NAME contains a
    # bare ``@``, an attacker controlling RECUPERO_EMAIL_FROM_NAME
    # could ship `victim@bank.com` as the visible "From" — most
    # clients render only the display name and the recipient sees
    # what looks like an email from their bank. Strip the entire
    # display name in that case rather than try to surgically edit.
    if "@" in name:
        name = ""
    if name:
        return f"{name} <{addr}>"
    return f"<{addr}>"


def _log_to_audit(
    *,
    dsn: str | None,
    investigation_id: UUID | str | None,
    to_address: str,
    subject: str,
    email_type: str,
    message_id: str | None,
    error_message: str | None,
    sent_by: str,
    preview_text: str | None,
    attachment_names: list[str],
) -> None:
    """INSERT one row into public.emails_sent. Best-effort — log
    failures don't propagate up to the caller (we've already done
    the send), but they're logged so the operator sees them in
    Railway."""
    dsn = dsn or os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.warning("audit log write skipped: no DSN configured")
        return

    inv_id_str = str(investigation_id) if investigation_id else None
    try:
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO public.emails_sent
                        (investigation_id, to_address, subject,
                         preview_text, email_type, message_id,
                         error_message, sent_by, attachments)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                (
                    inv_id_str, to_address, subject[:500],
                    preview_text[:500] if preview_text else None,
                    email_type, message_id,
                    error_message[:4000] if error_message else None,
                    sent_by, attachment_names or None,
                ),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("audit log write failed: %s", exc)


__all__ = (
    "EmailResult",
    "send_email",
    "has_been_sent",
    # Adversarial-input helpers — exported so other email surfaces
    # (worker/digest_email.py SMTP path, future SDK swaps) can reuse
    # the single canonical CRLF / bidi / length / RFC-5322-ish guard
    # without copy-paste drift.
    "_sanitize_email_header",
    "_validate_email_address",
)
