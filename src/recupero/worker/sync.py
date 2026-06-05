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

from recupero.storage.supabase_case_store import (
    PayloadTooLargeError,
    SupabaseCaseStore,
    _validate_relpath,
)

log = logging.getLogger(__name__)


_SKIP_DIRS: frozenset[str] = frozenset({"logs", "prices_cache"})

# Per-file pre-upload size cap. The bucket / edge layer enforces its
# own limit and returns 413, but ``path.read_bytes()`` slurps the
# entire file into memory FIRST — a 10 GB file planted in case_dir
# would OOM the worker before the 413 ever arrives. 256 MB mirrors
# ``_DOWNLOAD_HARD_CAP_BYTES`` in the store; any single artifact
# above this is either corruption or hostile, and oversize evidence
# is already gracefully handled downstream as PayloadTooLargeError.
_UPLOAD_HARD_CAP_BYTES = 256 * 1024 * 1024


def upload_case_dir(case_dir: Path, store: SupabaseCaseStore) -> int:
    """Walk ``case_dir`` and upload every file to ``store``.

    Returns the count of files uploaded. Idempotent — every upload uses
    upsert mode in the underlying store.

    Per-tx evidence files are best-effort: if a single evidence file is
    too large for the bucket / edge layer, log it and continue. Evidence
    is supplementary audit material, not the deliverable itself; losing
    one (and surfacing the loss in logs) is preferable to failing the
    whole investigation. Top-level files (case.json, freeze_brief.json,
    briefs/*.html) still hard-fail on upload errors — those are the
    actual deliverables.
    """
    if not case_dir.exists():
        raise FileNotFoundError(f"case_dir does not exist: {case_dir}")

    # Resolve once for the containment guard below.
    case_root = case_dir.resolve()
    uploaded = 0
    skipped_oversize = 0
    for path in sorted(case_dir.rglob("*")):
        if not path.is_file():
            continue
        # Adversarial-input audit: skip symlinks. ``rglob`` does not
        # recurse into symlinked directories on 3.13+, but a symlink
        # pointing at a regular FILE outside ``case_dir`` is still
        # enumerated and ``is_file()`` returns True. ``read_bytes()``
        # follows the link and would upload the target's contents
        # (e.g. /etc/passwd, a host-mounted secret) under the bucket
        # prefix. The case_dir contract is "files this worker wrote"
        # — symlinks have no legitimate use.
        # v0.31.3 — use is_link_like so Windows NTFS junctions are also
        # skipped (Path.is_symlink returns False for junctions).
        from recupero._common import is_link_like
        if is_link_like(path):
            log.warning("skipping symlink in case_dir: %s", path)
            continue
        # Containment guard (v0.36): a file reached THROUGH a junctioned /
        # symlinked PARENT dir is itself a regular file (is_link_like misses
        # it), but its real path escapes case_dir. Pre-v0.36 the blanket
        # "skip nested non-briefs" branch happened to block this; now that we
        # mirror every nested subdir, refuse anything whose resolved path is
        # not inside case_dir so a planted junction can't exfiltrate host
        # files under the bucket prefix.
        try:
            path.resolve().relative_to(case_root)
        except (OSError, ValueError):
            log.warning("skipping path resolving outside case_dir: %s", path)
            continue
        # Per-file size cap — refuse oversized files BEFORE
        # read_bytes() / _read_text() pulls them into RAM. Without
        # this, a planted 10 GB file in briefs/ would OOM the worker
        # before the bucket's 413 response ever arrives.
        try:
            size = path.stat().st_size
        except OSError as e:
            log.warning("cannot stat %s, skipping: %s", path, e)
            continue
        if size > _UPLOAD_HARD_CAP_BYTES:
            log.warning(
                "skipping oversized file %s (%d bytes > %d cap); "
                "investigation continues without it",
                path, size, _UPLOAD_HARD_CAP_BYTES,
            )
            skipped_oversize += 1
            continue

        rel = path.relative_to(case_dir)
        parts = rel.parts
        if not parts or parts[0] in _SKIP_DIRS:
            continue

        # Per-tx evidence: tx_evidence/<hash>.json → evidence/<hash>.json
        if len(parts) == 2 and parts[0] == "tx_evidence" and parts[1].endswith(".json"):
            tx_hash = parts[1][:-5]
            try:
                payload = json.loads(_read_text(path))
                store.write_evidence(tx_hash, payload)
                uploaded += 1
                log.debug("uploaded %s as evidence/%s.json", rel, tx_hash)
            except PayloadTooLargeError as e:
                skipped_oversize += 1
                log.warning(
                    "skipping oversized evidence file %s (%d bytes); "
                    "investigation continues without it",
                    rel, e.size,
                )
            continue

        # Any nested deliverable subdir — briefs/, legal_requests/,
        # regulatory_filing/, exhibit_pack/, custody/, … — is mirrored
        # VERBATIM under the bucket prefix so the FULL deliverable tree
        # reaches the operator console, not just briefs/. (tx_evidence/ is
        # handled above; logs/ + prices_cache/ are in _SKIP_DIRS.)
        #
        # v0.36: pre-fix this branch only matched ``briefs`` and a blanket
        # ``if len(parts) != 1: skip`` dropped every other subdir, so the
        # exchange-freeze letters / time-sensitivity advisory / SAR draft /
        # exhibit pack never synced to the console from a CLI run.
        #
        # IMPORTANT: read_bytes() rather than _read_text() — these dirs hold
        # PDF (WeasyPrint) + SVG (Graphviz) binaries; UTF-8 decoding chokes
        # on the binary stream. HTML/JSON written utf-8 round-trip fine
        # through read_bytes, so binary is the safe default. Each path
        # segment is validated inside _upload_to_subpath.
        if len(parts) >= 2:
            bucket_path = "/".join(parts)
            content_type = _content_type_for(path.suffix.lower())
            _upload_to_subpath(store, bucket_path, path.read_bytes(),
                               content_type)
            uploaded += 1
            log.debug("uploaded %s", rel)
            continue

        # Top-level files: write_json for *.json, write_text for the rest.
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

    if skipped_oversize:
        log.warning(
            "synced %d file(s) from %s to bucket prefix %s "
            "(skipped %d oversized evidence file(s); see warnings above)",
            uploaded, case_dir, store.storage_prefix, skipped_oversize,
        )
    else:
        log.info("synced %d file(s) from %s to bucket prefix %s",
                 uploaded, case_dir, store.storage_prefix)
    return uploaded


def download_editorial(store: SupabaseCaseStore, case_dir: Path) -> None:
    """Refresh ``brief_editorial.json`` in ``case_dir`` from the bucket.

    The admin UI is allowed to rewrite this file during the review checkpoint.
    The worker MUST re-read it from the bucket before the emit stage; the
    in-memory or local-disk copy may be stale.

    v0.17.4 (round-10 audit HIGH): write is now atomic. A worker crash
    mid-`write_text` could leave an empty brief_editorial.json that the
    next stage misread as REVIEW_REQUIRED=False, emitting a broken brief.
    """
    from recupero._common import atomic_write_text
    data = store.read_json("brief_editorial.json")
    dest = case_dir / "brief_editorial.json"
    atomic_write_text(dest, json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False))
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
        # building_package deliverables — PDFs from WeasyPrint, SVGs
        # from Graphviz. Browsers and compliance teams need the right
        # content-type to open these inline rather than downloading as
        # opaque bytes.
        ".pdf": "application/pdf",
        ".svg": "image/svg+xml",
        ".png": "image/png",
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
    # Adversarial-input audit: SupabaseCaseStore.write_text/write_json
    # call _validate_relpath, but _upload_to_subpath goes straight
    # through the underlying _upload primitive — the validator was
    # bypassed. Validate each path segment so a hostile filename
    # (e.g. "briefs/../escape.html", NUL byte, backslash) cannot
    # break out of the investigation prefix.
    _validate_relpath(bucket_relative_path, kind="bucket_relative_path")
    for seg in bucket_relative_path.split("/"):
        if seg:
            _validate_relpath(seg, kind="bucket_relative_path segment")

    full = store.storage_prefix + bucket_relative_path
    store._upload(full, body, content_type)  # noqa: SLF001
