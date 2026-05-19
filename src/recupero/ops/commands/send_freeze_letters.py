"""recupero-ops send-freeze-letters <inv_id> — send to issuer compliance.

The most operator-sensitive ops command. Sends prepared freeze
letters to each issuer's compliance contact, with an interactive
confirmation step that lists every recipient before sending.

Eligibility:
  * Investigation must exist
  * Investigation must have freeze_brief.json with FREEZABLE entries
  * Each FREEZABLE entry's issuer must have a contact_email
  * Per-issuer idempotency: skips issuers we've already sent for
    (uses emails_sent audit log)

The confirmation step shows:
  * Each issuer name
  * Each issuer's contact email
  * The freeze-letter filename being attached
  * Total recoverable USD per issuer

The operator types ``y`` to confirm OR ``n`` to abort the whole
batch. There's no per-issuer y/n — running this in interactive
batch-confirm mode keeps the operator in the loop without making
each send a 30-second decision.
"""

from __future__ import annotations

from recupero._common import db_connect

import json
import logging
import os
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger(__name__)


def run(
    *,
    investigation_id: UUID,
    issuer_filter: str | None,
    dsn: str,
    confirm: Callable[[str], bool],
) -> int:
    """Send freeze letters to issuer compliance teams. Returns 0
    on success, 1 on errors."""
    # 1. Load investigation + freeze_brief
    inv = _fetch_investigation(investigation_id=investigation_id, dsn=dsn)
    if not inv:
        print(f"ERROR: investigation {investigation_id} not found")
        return 1
    if not inv["case_id"]:
        # Fixed in v0.16.6: the prior message was a truncated sentence
        # ("Use --skip-freeze-briefs investigations have no...") that
        # crashed two operators mid-investigation last quarter because
        # they couldn't tell what corrective action to take. The actual
        # answer is simply "this investigation isn't a theft case and
        # therefore has no freeze letters to dispatch" — there is no
        # --skip-freeze-briefs flag to invoke at send time; the flag
        # lives at investigation-creation time.
        print(
            f"ERROR: investigation {investigation_id} is a wallet trace "
            f"(no case_id, no FREEZABLE list to send). Wallet-trace "
            f"investigations are created with --skip-freeze-briefs and "
            f"have no freeze letters to dispatch."
        )
        return 1

    freeze_brief = _fetch_freeze_brief_from_bucket(investigation_id=investigation_id)
    if not freeze_brief:
        print(f"ERROR: could not load freeze_brief.json from bucket for "
              f"investigation {investigation_id}")
        return 1
    # v0.16.3 (audit round-4 fix #B): check schema version. Stale briefs
    # without evidence_mode fields cause the freeze-letter templates to
    # fall through to "currently held" language even for historical-
    # receipt cases. Operator dispatch is the LAST chance to catch this
    # before the letter goes out.
    from recupero.reports.brief import check_brief_schema_version
    schema_warning = check_brief_schema_version(freeze_brief)
    if schema_warning:
        print(f"WARNING: freeze_brief is stale — {schema_warning}")
        print(
            "Recommend re-emitting the brief with "
            "`recupero emit-brief <case_id>` before dispatching letters."
        )
    freezable = freeze_brief.get("FREEZABLE") or []
    if not freezable:
        print(f"NOTE: freeze_brief has no FREEZABLE entries for "
              f"investigation {investigation_id}. No letters to send.")
        return 0

    # 2. Filter by issuer if requested
    if issuer_filter:
        freezable = [
            e for e in freezable
            if (e.get("issuer") or "").lower() == issuer_filter.lower()
        ]
        if not freezable:
            print(f"ERROR: no FREEZABLE entry for issuer={issuer_filter!r}. "
                  f"Available issuers: "
                  f"{[e.get('issuer') for e in (freeze_brief.get('FREEZABLE') or [])]}")
            return 1

    # 3. Build a per-issuer dispatch plan, skipping already-sent
    plan = _build_dispatch_plan(
        investigation_id=investigation_id,
        freezable=freezable,
        dsn=dsn,
    )
    if not plan:
        print("Nothing to do — every issuer's freeze letter has already been sent.")
        return 0

    # 4. Show the plan + ask confirmation
    print("=" * 72)
    print(f"FREEZE LETTER DISPATCH — Investigation {investigation_id}")
    print("=" * 72)
    print()
    for entry in plan:
        print(f"  {entry['issuer']:30s} -> {entry['contact_email']}")
        print(f"    Stablecoin: {entry['token']}")
        print(f"    Freezable:  {entry['total_usd']}")
        print(f"    File:       {entry['letter_filename']}")
        print()
    print(f"Total: {len(plan)} freeze letter(s) to send.")
    print()

    if not confirm("Proceed with sending all letters?", default=False):
        print("Cancelled.")
        return 1

    # 5. Send each
    sent = 0
    failed = 0
    from recupero.worker._email import send_email
    for entry in plan:
        # Download the letter HTML from bucket
        html = _fetch_letter_html(
            investigation_id=investigation_id,
            filename=entry["letter_filename"],
        )
        if html is None:
            print(f"  FAIL  {entry['issuer']}: could not load letter HTML")
            failed += 1
            continue

        # Download the PDF for attachment (optional)
        pdf_path = _download_pdf(
            investigation_id=investigation_id,
            filename=entry["letter_filename"].replace(".html", ".pdf"),
        )
        attachments = [pdf_path] if pdf_path else []

        subject = (
            f"Compliance Freeze Request — Case "
            f"{str(investigation_id)[:8]}: "
            f"{entry['token']} at {entry['total_usd']} recoverable"
        )

        result = send_email(
            to=entry["contact_email"],
            subject=subject,
            html=html,
            investigation_id=investigation_id,
            email_type="freeze_letter",
            attachments=attachments,
            preview_text=(
                f"Recupero is requesting a precautionary freeze of "
                f"{entry['total_usd']} {entry['token']} associated "
                f"with case {str(investigation_id)[:8]}."
            ),
            sent_by="recupero-ops:operator",
        )

        # Clean up the temp PDF
        if pdf_path:
            try:
                pdf_path.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass

        if result.success:
            # v0.16.8 (round-9 worker-resilience HIGH): record the send
            # in freeze_letters_sent so the recovery-learning loop
            # (refresh_priors, record_outcome) has data to update
            # issuer priors against. Pre-v0.16.8 the table existed
            # but was never written to — the entire learned-prior
            # pipeline ingested zero rows.
            _record_freeze_letter_sent(
                dsn=dsn,
                investigation_id=investigation_id,
                case_id=inv.get("case_id"),
                entry=entry,
                subject=subject,
                html_excerpt=html[:1000] if html else "",
            )
            print(f"  OK    {entry['issuer']}: message_id={result.message_id}")
            sent += 1
        elif result.skipped:
            # RECUPERO_DISABLE_EMAIL=1 path — not a failure, just a
            # configured no-op. Distinguish in the output so the
            # operator doesn't see "FAIL" on every line during a
            # disabled-email dry-run.
            print(f"  SKIP  {entry['issuer']}: email disabled (RECUPERO_DISABLE_EMAIL=1)")
        else:
            print(f"  FAIL  {entry['issuer']}: {result.error}")
            failed += 1

    print()
    print(f"Done: {sent} sent, {failed} failed.")
    return 0 if failed == 0 else 1


# ----- helpers ----- #


def _record_freeze_letter_sent(
    *,
    dsn: str,
    investigation_id: UUID,
    case_id: Any,
    entry: dict,
    subject: str,
    html_excerpt: str,
) -> None:
    """Insert a row into public.freeze_letters_sent.

    Idempotent via the UNIQUE (case_id, issuer, target_address,
    asset_symbol) constraint — a re-send with the same target is a
    no-op INSERT (ON CONFLICT DO NOTHING) rather than a duplicate row.
    Failures are logged but do NOT propagate: a send-recorded-but-
    audit-failed is preferable to a send-rolled-back-because-audit-
    failed (the email is already out the door at this point).

    v0.16.8 (round-9 worker-resilience HIGH): this function did not
    exist pre-v0.16.8 — every successful send was emitted to the
    issuer but no record appeared in the audit table, so freeze_outcomes
    + the learned-prior refresh pipeline never had inputs.
    """
    operator = (
        os.environ.get("RECUPERO_OPS_OPERATOR", "").strip()
        or "recupero-ops:operator"
    )
    # The brief carries either total_usd or usd_value; pick whichever is
    # populated. Strip "$" and "," for the numeric column.
    raw_usd = str(entry.get("total_usd") or entry.get("usd_value") or "0")
    cleaned = raw_usd.replace("$", "").replace(",", "").strip()
    try:
        requested_usd = float(cleaned) if cleaned else 0.0
    except (TypeError, ValueError):
        requested_usd = 0.0
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            # v0.16.12 (round-9 worker MED): two ON CONFLICT clauses
            # can't be combined in one INSERT, so we try the
            # case-driven UNIQUE first; on a NULL case_id (wallet-
            # trace row) we fall through to the investigation-keyed
            # partial unique from migration 016. Catching UniqueViolation
            # on the second branch lets the no-op be idempotent
            # either way.
            cur.execute(
                """
                INSERT INTO public.freeze_letters_sent (
                    case_id, investigation_id, issuer, target_address,
                    chain, asset_symbol, requested_freeze_usd,
                    letter_subject, letter_body_excerpt, contact_email,
                    operator
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (case_id, issuer, target_address, asset_symbol)
                DO NOTHING
                """,
                (
                    str(case_id) if case_id else None,
                    str(investigation_id),
                    entry.get("issuer") or "(unknown)",
                    entry.get("target_address") or entry.get("address") or "",
                    entry.get("chain") or "ethereum",
                    entry.get("token") or entry.get("symbol") or "?",
                    requested_usd,
                    subject[:500],
                    html_excerpt[:1000],
                    entry.get("contact_email") or "",
                    operator,
                ),
            )
    except psycopg.errors.UniqueViolation:
        # v0.16.12: the partial-unique on (investigation_id, issuer,
        # target_address, asset_symbol) WHERE case_id IS NULL caught
        # a wallet-trace duplicate that the case_id-keyed ON CONFLICT
        # couldn't see (NULL != NULL in UNIQUE semantics). Treat as
        # no-op — the prior send already lives in the audit trail.
        log.info(
            "freeze_letters_sent: duplicate detected by partial unique "
            "(wallet-trace row) for issuer=%s addr=%s — skipping",
            entry.get("issuer"), entry.get("target_address"),
        )
    except Exception as exc:  # noqa: BLE001
        # Best-effort: the email is already sent. Log and continue.
        log.warning(
            "freeze_letters_sent INSERT failed for issuer=%s addr=%s: %s",
            entry.get("issuer"), entry.get("target_address"), exc,
        )


def _fetch_investigation(*, investigation_id: UUID, dsn: str) -> dict | None:
    with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, case_id, status FROM public.investigations WHERE id = %s",
            (str(investigation_id),),
        )
        return cur.fetchone()


def _fetch_freeze_brief_from_bucket(*, investigation_id: UUID) -> dict | None:
    """Pull freeze_brief.json from the case's bucket prefix."""
    sb = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not sb or not key:
        log.warning("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing")
        return None
    url = (
        f"{sb}/storage/v1/object/investigation-files/"
        f"investigations/{investigation_id}/freeze_brief.json"
    )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {key}", "apikey": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        log.warning("freeze_brief download failed: %s", e)
        return None


def _build_dispatch_plan(
    *,
    investigation_id: UUID,
    freezable: list[dict],
    dsn: str,
) -> list[dict[str, Any]]:
    """Decide what to send for each issuer.

    Per-issuer idempotency: skip issuers where the audit log shows
    a successful freeze_letter send to the issuer's contact_email
    for this investigation."""

    # Find the latest brief filename per issuer in the bucket
    bucket_files = _list_bucket_briefs(investigation_id=investigation_id)
    plan: list[dict[str, Any]] = []
    skip_count = 0

    for entry in freezable:
        issuer = entry.get("issuer")
        contact = entry.get("contact_email")
        token = entry.get("token", "?")
        total = entry.get("total_usd", "$0")
        if not issuer or not contact:
            print(f"  SKIP  {issuer or '(no issuer)'}: missing contact_email "
                  "(was not in the freeze_brief)")
            continue

        # Per-issuer-per-investigation-per-recipient idempotency check
        if _already_sent_to(
            investigation_id=investigation_id,
            email_type="freeze_letter",
            to_address=contact,
            dsn=dsn,
        ):
            print(f"  SKIP  {issuer}: freeze letter already sent to {contact}")
            skip_count += 1
            continue

        # Find the latest brief for this issuer
        issuer_slug = (issuer.split()[0].split("/")[0]).lower()
        latest = _find_latest_brief(bucket_files, slug=issuer_slug)
        if not latest:
            print(f"  SKIP  {issuer}: no freeze_request_{issuer_slug}_*.html "
                  "in bucket (was the case run before per-issuer letters landed?)")
            continue

        plan.append({
            "issuer": issuer,
            "token": token,
            "total_usd": total,
            "contact_email": contact,
            "letter_filename": latest,
        })

    if skip_count:
        print(f"({skip_count} issuer(s) skipped — already sent)")
    return plan


def _list_bucket_briefs(*, investigation_id: UUID) -> list[dict[str, Any]]:
    """List the bucket's briefs/ subdir contents."""
    sb = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    url = f"{sb}/storage/v1/object/list/investigation-files"
    req = urllib.request.Request(
        url,
        data=json.dumps({
            "prefix": f"investigations/{investigation_id}/briefs/",
            "limit": 200,
            "offset": 0,
        }).encode(),
        headers={
            "Authorization": f"Bearer {key}", "apikey": key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        log.warning("briefs/ list failed: %s", e)
        return []


def _find_latest_brief(files: list[dict], *, slug: str) -> str | None:
    """Find the latest (by BRIEF-<timestamp>) freeze_request HTML
    for the given issuer slug."""
    import re
    candidates = [
        f["name"] for f in files
        if f.get("name", "").startswith(f"freeze_request_{slug}_BRIEF-")
        and f.get("name", "").endswith(".html")
    ]
    if not candidates:
        return None
    # Sort by embedded timestamp descending
    def _ts(name: str) -> str:
        m = re.search(r"BRIEF-(\d{8}T\d{6})", name)
        return m.group(1) if m else ""
    return max(candidates, key=_ts)


def _fetch_letter_html(*, investigation_id: UUID, filename: str) -> str | None:
    """Download a letter HTML from the bucket."""
    sb = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    url = (
        f"{sb}/storage/v1/object/investigation-files/"
        f"investigations/{investigation_id}/briefs/{filename}"
    )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {key}", "apikey": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode("utf-8")
    except Exception as e:  # noqa: BLE001
        log.warning("letter HTML download failed for %s: %s", filename, e)
        return None


def _download_pdf(*, investigation_id: UUID, filename: str) -> Path | None:
    """Download a letter PDF to a temp file. Returns path or None
    on failure. Caller is expected to delete the file when done."""
    import tempfile
    sb = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    url = (
        f"{sb}/storage/v1/object/investigation-files/"
        f"investigations/{investigation_id}/briefs/{filename}"
    )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {key}", "apikey": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read()
        # Write to temp file
        tmp = Path(tempfile.mkstemp(suffix=".pdf", prefix="recupero-attach-")[1])
        tmp.write_bytes(body)
        return tmp
    except Exception as e:  # noqa: BLE001
        log.debug("PDF attachment download failed for %s: %s", filename, e)
        return None


def _already_sent_to(
    *,
    investigation_id: UUID,
    email_type: str,
    to_address: str,
    dsn: str,
) -> bool:
    """Per-recipient idempotency: have we sent this email_type to
    this address for this investigation already?"""
    try:
        with db_connect(dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM public.emails_sent
                     WHERE investigation_id = %s
                       AND email_type = %s
                       AND to_address = %s
                       AND error_message IS NULL
                     LIMIT 1
                    """,
                    (str(investigation_id), email_type, to_address),
                )
                return cur.fetchone() is not None
    except Exception as e:  # noqa: BLE001
        log.warning("per-recipient idempotency check failed: %s", e)
        return False


__all__ = ("run",)
