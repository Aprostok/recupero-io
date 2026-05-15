"""recupero-ops send-le-handoff <inv_id> --to EMAIL — to LE officer.

Sends the LE handoff package to a specific law-enforcement
officer or attorney. The recipient address is operator-supplied
(no auto-routing) because the right recipient depends on which
agency the operator + victim selected from the recommended
routes table in the LE handoff itself.

Attaches:
  * The LE handoff PDF (this is the primary artifact LE needs)
  * The fund-flow diagram PDF
  * The trace report PDF (full forensic detail)

Per-recipient idempotency via the audit log — sending the same
LE handoff twice to the same officer is a no-op.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
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
    to_email: str,
    dsn: str,
    confirm: Callable[[str], bool],
) -> int:
    """Send the LE handoff to a specific recipient. Returns 0 on
    success, 1 on errors."""
    inv = _fetch_investigation(investigation_id=investigation_id, dsn=dsn)
    if not inv:
        print(f"ERROR: investigation {investigation_id} not found")
        return 1

    # Find the latest LE handoff in the bucket
    bucket_files = _list_bucket_briefs(investigation_id=investigation_id)
    le_html_name = _find_latest_le_handoff(bucket_files)
    if not le_html_name:
        print(f"ERROR: no le_handoff_*.html found for investigation "
              f"{investigation_id}. Has the case been completed by the worker?")
        return 1

    # Idempotency check
    if _already_sent_to(
        investigation_id=investigation_id,
        email_type="le_handoff",
        to_address=to_email,
        dsn=dsn,
    ):
        print(f"NOTE: LE handoff already sent to {to_email} for this "
              "investigation. No re-send.")
        return 0

    # Confirmation
    print("=" * 72)
    print(f"LE HANDOFF DISPATCH — Investigation {investigation_id}")
    print("=" * 72)
    print(f"  Recipient:     {to_email}")
    print(f"  LE handoff:    {le_html_name}")
    print(f"  Will attach:   LE handoff PDF, trace_report PDF, flow PDF")
    print()
    if not confirm(f"Send LE handoff to {to_email}?", default=False):
        print("Cancelled.")
        return 1

    # Download HTML body
    html = _fetch_letter_html(
        investigation_id=investigation_id, filename=le_html_name,
    )
    if html is None:
        print("ERROR: could not download LE handoff HTML from bucket")
        return 1

    # Download attachment PDFs
    pdf_candidates = [
        le_html_name.replace(".html", ".pdf"),  # the LE handoff itself
    ]
    # Find trace_report + flow PDFs in the bucket
    for f in bucket_files:
        name = f.get("name", "")
        if name.startswith("trace_report_") and name.endswith(".pdf"):
            pdf_candidates.append(name)
        elif name.startswith("flow_") and name.endswith(".pdf"):
            pdf_candidates.append(name)
    attachments: list[Path] = []
    for pdf_name in pdf_candidates:
        p = _download_pdf(
            investigation_id=investigation_id, filename=pdf_name,
        )
        if p:
            attachments.append(p)

    subject = (
        f"Law Enforcement Handoff — Recupero Case "
        f"{str(investigation_id)[:8]}"
    )
    preview = (
        "Forensic-trace evidence package for a cryptocurrency theft "
        f"investigation. Includes addresses, transactions, and "
        f"recommended filing routes."
    )

    from recupero.worker._email import send_email
    result = send_email(
        to=to_email,
        subject=subject,
        html=html,
        investigation_id=investigation_id,
        email_type="le_handoff",
        attachments=attachments,
        preview_text=preview,
        sent_by="recupero-ops:operator",
    )

    # Clean up temp PDFs
    for p in attachments:
        try:
            p.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass

    if result.success:
        print(f"OK — LE handoff sent to {to_email}")
        print(f"     message_id: {result.message_id}")
        print(f"     attached: {len(attachments)} PDF(s)")
        return 0
    if result.skipped:
        # RECUPERO_DISABLE_EMAIL=1: configured no-op, not a failure.
        # Exit 0 so dry-run scripts can chain commands without
        # tripping `set -e`.
        print(f"SKIP — email disabled (RECUPERO_DISABLE_EMAIL=1). Would have "
              f"sent LE handoff to {to_email} with {len(attachments)} PDF(s).")
        return 0
    print(f"FAIL — {result.error}")
    return 1


# ----- helpers (shared with send_freeze_letters) ----- #


def _fetch_investigation(*, investigation_id: UUID, dsn: str) -> dict | None:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row,
                         connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, case_id, status FROM public.investigations WHERE id = %s",
                (str(investigation_id),),
            )
            return cur.fetchone()


def _list_bucket_briefs(*, investigation_id: UUID) -> list[dict[str, Any]]:
    sb = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    url = f"{sb}/storage/v1/object/list/investigation-files"
    req = urllib.request.Request(
        url,
        data=json.dumps({
            "prefix": f"investigations/{investigation_id}/briefs/",
            "limit": 200, "offset": 0,
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


def _find_latest_le_handoff(files: list[dict]) -> str | None:
    """Find the latest le_handoff_*.html in the bucket."""
    import re
    candidates = [
        f["name"] for f in files
        if f.get("name", "").startswith("le_handoff_")
        and f.get("name", "").endswith(".html")
    ]
    if not candidates:
        return None
    def _ts(name: str) -> str:
        m = re.search(r"BRIEF-(\d{8}T\d{6})", name)
        return m.group(1) if m else ""
    return max(candidates, key=_ts)


def _fetch_letter_html(*, investigation_id: UUID, filename: str) -> str | None:
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
        log.warning("letter HTML download failed: %s", e)
        return None


def _download_pdf(*, investigation_id: UUID, filename: str) -> Path | None:
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
        tmp = Path(tempfile.mkstemp(suffix=".pdf", prefix="recupero-attach-")[1])
        tmp.write_bytes(body)
        return tmp
    except Exception as e:  # noqa: BLE001
        log.debug("PDF download failed for %s: %s", filename, e)
        return None


def _already_sent_to(
    *,
    investigation_id: UUID,
    email_type: str,
    to_address: str,
    dsn: str,
) -> bool:
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
