"""Mirror a local CaseStore case directory up to Supabase Storage.

Why this exists: Phase 2 deliberately keeps the trace/freeze/editorial/emit
pipeline functions untouched (Phase 4 owns that migration). Those functions
read and write a local ``case_dir`` via ``CaseStore``. The worker's job is
to run them on a per-investigation tempdir, then sync the produced artifacts
to the long-term storage location (the bucket).

Translations applied during sync:

* ``tx_evidence/<hash>.json``  →  ``evidence/<hash>.json``
  (Local pipeline uses ``tx_evidence``; the bucket contract uses ``evidence``.
  The translation is via ``store.write_evidence(tx_hash, payload)``.)
* ``logs/`` is skipped — log retention is Railway's job, not the bucket's.
* ``prices_cache/`` (if it ever leaks under a case dir) is also skipped.

The sync is "upload everything, idempotent, never delete from the bucket."
Re-running sync after a stage produces a superset of artifacts, never less.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from recupero.storage.supabase_case_store import SupabaseCaseStore

log = logging.getLogger(__name__)


_SKIP_DIRS: frozenset[str] = frozenset({"logs", "prices_cache"})


def upload_case_dir(case_dir: Path, store: SupabaseCaseStore) -> int:
    """Walk ``case_dir`` and upload every file to ``store``.

    Returns the count of files uploaded. Idempotent — every upload uses
    upsert mode in the underlying store.
    """
    if not case_dir.exists():
        raise FileNotFoundError(f"case_dir does not exist: {case_dir}")

    uploaded = 0
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file():
            continue

        rel = path.relative_to(case_dir)
        parts = rel.parts
        if not parts or parts[0] in _SKIP_DIRS:
            continue

        # Per-tx evidence: tx_evidence/<hash>.json → evidence/<hash>.json
        if len(parts) == 2 and parts[0] == "tx_evidence" and parts[1].endswith(".json"):
            tx_hash = parts[1][:-5]
            payload = json.loads(_read_text(path))
            store.write_evidence(tx_hash, payload)
            uploaded += 1
            log.debug("uploaded %s as evidence/%s.json", rel, tx_hash)
            continue

        # building_package deliverables: case_dir/briefs/*.html etc.
        # Mirror the directory verbatim under the bucket prefix.
        if parts[0] == "briefs":
            bucket_path = "/".join(parts)  # e.g. briefs/freeze_request_circle_BRIEF-...html
            content_type = _content_type_for(path.suffix.lower())
            _upload_to_subpath(store, bucket_path, _read_text(path).encode("utf-8"),
                               content_type)
            uploaded += 1
            log.debug("uploaded %s", rel)
            continue

        # Top-level files: write_json for *.json, write_text for the rest.
        if len(parts) != 1:
            log.warning("skipping nested non-evidence file: %s", rel)
            continue

        filename = parts[0]
        if filename.endswith(".json"):
            data = json.loads(_read_text(path))
            store.write_json(filename, data)
        elif filename.endswith(".csv"):
            store.write_text(filename, _read_text(path), "text/csv; charset=utf-8")
        else:
            store.write_text(filename, _read_text(path))
        uploaded += 1
        log.debug("uploaded %s", rel)

    log.info("synced %d file(s) from %s to bucket prefix %s",
             uploaded, case_dir, store.storage_prefix)
    return uploaded


def download_editorial(store: SupabaseCaseStore, case_dir: Path) -> None:
    """Refresh ``brief_editorial.json`` in ``case_dir`` from the bucket.

    The admin UI is allowed to rewrite this file during the review checkpoint.
    The worker MUST re-read it from the bucket before the emit stage; the
    in-memory or local-disk copy may be stale.
    """
    data = store.read_json("brief_editorial.json")
    dest = case_dir / "brief_editorial.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    log.debug("refreshed brief_editorial.json from bucket → %s", dest)


def _read_text(path: Path) -> str:
    """Read a text file, stripping a leading UTF-8 BOM if present.

    Mirrors the BOM-tolerant read used elsewhere in the codebase
    (PowerShell's ``Set-Content -Encoding UTF8`` writes a BOM).
    """
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8")


def _content_type_for(suffix: str) -> str:
    """Map a file extension to a Content-Type for bucket upload."""
    return {
        ".json": "application/json",
        ".csv": "text/csv; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".htm": "text/html; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
    }.get(suffix, "application/octet-stream")


def _upload_to_subpath(
    store: SupabaseCaseStore,
    bucket_relative_path: str,
    body: bytes,
    content_type: str,
) -> None:
    """Upload to <storage_prefix>/<bucket_relative_path>.

    SupabaseCaseStore's public surface only exposes flat (single-segment)
    writes via write_text/write_json/write_evidence; nested-subdirectory
    writes need to go through the same upload primitive directly. We hit
    the underlying _upload helper since the storage_prefix already carries
    the investigations/<id>/ part.
    """
    full = store.storage_prefix + bucket_relative_path
    store._upload(full, body, content_type)  # noqa: SLF001
