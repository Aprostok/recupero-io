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

import json
import logging
import os
import urllib.request
from pathlib import Path
from typing import Any, Callable
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
        print(f"ERROR: investigation {investigation_id} is a wallet trace "
              "(no case_id, no FREEZABLE list to send). Use --skip-freeze-briefs "
              "investigations have no freeze letters to send.")
        return 1

    freeze_brief = _fetch_freeze_brief_from_bucket(investigation_id=investigation_id)
    if not freeze_brief:
        print(f"ERROR: could not load freeze_brief.json from bucket for "
              f"investigation {investigation_id}")
        return 1
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
            print(f"  OK    {entry['issuer']}: message_id={result.message_id}")
            sent += 1
        else:
            print(f"  FAIL  {entry['issuer']}: {result.error}")
            failed += 1

    print()
    print(f"Done: {sent} sent, {failed} failed.")
    return 0 if failed == 0 else 1


# ----- helpers ----- #


def _fetch_investigation(*, investigation_id: UUID, dsn: str) -> dict | None:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
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
    from recupero.worker._email import has_been_sent

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
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
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
