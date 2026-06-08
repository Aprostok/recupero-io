"""Supabase Storage adapter for case files.

Mirrors CaseStore but writes to Supabase Storage via raw HTTPS instead of the
local filesystem. Used by the worker that runs on Railway alongside the Next.js
admin UI; the admin UI reads/writes the same bucket.

Why no SDK: ``pip install supabase`` pulls in ``pyiceberg``, which lacks Python
3.14 wheels and would force Visual C++ Build Tools at install time. We only need
a handful of Storage REST endpoints — ``httpx`` (already a dep) is enough.

Bucket layout (locked by the contract with the admin UI)::

    investigation-files/
    └── investigations/<uuid>/
        ├── case.json
        ├── manifest.json
        ├── transfers.csv
        ├── freeze_asks.json
        ├── brief_editorial.json   # shared write — UI may overwrite
        ├── freeze_brief.json
        └── evidence/
            └── <tx_hash>.json

``investigation_id`` is the UUID primary key of ``public.investigations``.
It is NOT the same as ``Case.case_id`` on the Pydantic model.
"""

from __future__ import annotations

import csv
import io
import logging
import re
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import orjson
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from recupero import __version__
from recupero.config import RecuperoConfig
from recupero.models import Case

log = logging.getLogger(__name__)

_BOM = b"\xef\xbb\xbf"

# RIGOR-Jacob Z19-2: hard cap on a single download response body.
# Anyone with bucket write access (admin UI, sibling worker, a future
# tenant) can plant a multi-GB case.json — the next worker that
# resumes the case would OOM. 256 MB is generous (a real case.json
# is a few MB at most); any single artifact larger than this is
# either corruption or hostile.
_DOWNLOAD_HARD_CAP_BYTES = 256 * 1024 * 1024

# RIGOR-Jacob Z19-3: hard cap on _list pagination. A buggy or
# hostile Supabase endpoint that returns ``limit`` rows forever
# would pin the worker. 200 pages × 1000 = 200 000 files is far
# beyond any real investigation.
_LIST_MAX_PAGES = 200

# RIGOR-Jacob Z19-4: max recursion depth for _walk_all_files.
# Real bucket nesting is 2 levels (investigations/<uuid>/evidence/);
# 16 leaves ample slack and prevents stack-exhaustion DoS.
_WALK_MAX_DEPTH = 16

# RIGOR-Jacob Z19-5: substrings forbidden in filenames / tx_hashes.
# The storage URL is built by string-concat, so any of these would
# break out of the investigation prefix.
_FILENAME_FORBIDDEN_SUBSTRINGS = ("..", "\x00", "\n", "\r", "\\", "//")


def _validate_relpath(value: str, *, kind: str) -> None:
    """RIGOR-Jacob Z19-5: reject filename / tx_hash values that would
    break out of the investigation's storage prefix when string-
    concatenated into the bucket URL."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {kind}: must be a non-empty string")
    if value.startswith("/"):
        raise ValueError(
            f"invalid {kind} {value!r}: must not start with '/' "
            f"(would break out of investigation prefix)"
        )
    for bad in _FILENAME_FORBIDDEN_SUBSTRINGS:
        if bad in value:
            raise ValueError(
                f"invalid {kind} {value!r}: contains forbidden "
                f"substring {bad!r} (path traversal / control char)"
            )


class _StorageTransient(RuntimeError):
    """Marker exception raised internally to signal a retriable
    transport-or-5xx failure. The retry decorator catches this;
    callers continue to see RuntimeError for terminal errors.

    Keeps the existing public exception contract (RuntimeError on
    non-200) intact while allowing tenacity to discriminate.
    """


def _is_storage_transient(exc: BaseException) -> bool:
    """Retriable iff httpx transport failure (DNS / connect /
    read timeout) or our internal 5xx marker.

    Deliberately NOT retried:
      - FileNotFoundError (4xx-equivalent for downloads)
      - PayloadTooLargeError (413: no amount of waiting fixes it)
      - RuntimeError for 4xx (caller bug)
    """
    return isinstance(exc, (httpx.TransportError, _StorageTransient))


# Retry policy for transient Storage failures (5xx, transport
# timeouts, connection resets). Mirrors the other clients in the
# codebase: 4 attempts, 2s/4s/8s exponential waits capped at 30s.
# The Supabase Storage edge is generally reliable; this exists
# for the once-a-week brief blip rather than for sustained
# capacity events.
_storage_retry = retry(
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=2, max=30),
    retry=retry_if_exception(_is_storage_transient),
    reraise=True,
)


class PayloadTooLargeError(RuntimeError):
    """Raised when an upload body exceeds the bucket / edge size limit.

    Callers (e.g. ``upload_case_dir`` for evidence files) can catch this
    specifically to skip-and-log instead of failing the whole stage.
    """

    def __init__(self, path: str, size: int, status_code: int) -> None:
        super().__init__(
            f"upload to {path} rejected as too large "
            f"({size} bytes, HTTP {status_code})"
        )
        self.path = path
        self.size = size
        self.status_code = status_code


# building_package writes per-issuer deliverables tagged with a shared
# generation stamp ``BRIEF-<YYYYMMDDTHHMMSS>`` (the per-issuer short hash
# follows). Grouping briefs by that stamp lets us keep the latest generation
# and prune older ones. The timestamp is fixed-width + zero-padded, so a
# lexicographic max is chronological.
_BRIEF_GEN_RE = re.compile(r"BRIEF-(\d{8}T\d{6})")


def latest_brief_generation(names: list[str]) -> str | None:
    """The newest ``BRIEF-<YYYYMMDDTHHMMSS>`` stamp among ``names``, or None."""
    stamps = {m.group(1) for n in names if (m := _BRIEF_GEN_RE.search(n))}
    return max(stamps) if stamps else None


def stale_brief_generation_files(names: list[str]) -> list[str]:
    """Given briefs/ filenames, return those belonging to a NON-latest
    ``BRIEF-<timestamp>`` generation (i.e. safe to prune).

    Files with no ``BRIEF-<timestamp>`` token (flow diagrams, investigator
    findings, trace report, recovery snapshot, the case-level manifest) are
    NEVER returned — they aren't generation-scoped. Returns [] when 0 or 1
    generation is present (nothing to prune)."""
    gens: dict[str, list[str]] = {}
    for n in names:
        m = _BRIEF_GEN_RE.search(n)
        if m:
            gens.setdefault(m.group(1), []).append(n)
    if len(gens) <= 1:
        return []
    latest = max(gens)
    return sorted(f for ts, fs in gens.items() if ts != latest for f in fs)


class SupabaseCaseStore:
    """Storage adapter that writes case files to Supabase Storage via raw HTTPS.

    One instance per investigation. The investigation_id is the UUID primary
    key of the public.investigations row, used as the storage path prefix.

    Uses httpx directly (no supabase-py SDK) to avoid the pyiceberg/storage3
    transitive dependency chain. The Storage REST API is small and stable.
    """

    def __init__(
        self,
        config: RecuperoConfig,
        supabase_url: str,
        service_role_key: str,
        investigation_id: str,
        bucket: str = "investigation-files",
        timeout: float = 30.0,
    ) -> None:
        if not supabase_url:
            raise ValueError("supabase_url is required")
        if not service_role_key:
            raise ValueError("service_role_key is required")
        if not investigation_id:
            raise ValueError("investigation_id is required")
        # RIGOR-Jacob V: validate investigation_id is a UUID — the
        # documented contract. Without this, a value like
        # ``"../../bucket/admin"`` lands in storage_prefix as
        # ``investigations/../../bucket/admin/`` — even if Supabase
        # normalizes the URL, the documented contract is violated
        # and the surface is confusing 4xx errors. UUID validation
        # closes the path-traversal + garbage-input class for this
        # external-data-sink boundary.
        from uuid import UUID as _UUID
        try:
            _UUID(str(investigation_id))
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"investigation_id {investigation_id!r} is not a "
                f"valid UUID"
            ) from e
        if not bucket:
            raise ValueError("bucket is required")

        self._config = config
        self._pretty = config.storage.pretty_json
        self._supabase_url = supabase_url.rstrip("/")
        self._service_role_key = service_role_key
        self._investigation_id = investigation_id
        self._bucket = bucket

        # New-style sb_secret_* keys require BOTH headers; sending only
        # Authorization yields a confusing 401.
        self._storage_root = f"{self._supabase_url}/storage/v1"
        self._client = httpx.Client(
            headers={
                "apikey": service_role_key,
                "Authorization": f"Bearer {service_role_key}",
            },
            timeout=timeout,
        )

    # ----- properties ----- #

    @property
    def storage_prefix(self) -> str:
        return f"investigations/{self._investigation_id}/"

    # ----- High-level Case I/O ----- #

    def write_case(self, case: Case) -> str:
        """Upload case bundle to Supabase Storage.

        v0.19.1 (round-12 resilience-HIGH-1): write order inverted so
        ``case.json`` lands LAST. Pre-v0.19.1 the order was case.json →
        manifest.json → transfers.csv; a worker crash (OOM, SIGKILL on
        Railway redeploy, transient 5xx on the second upload) between
        steps left case.json present but the companion artifacts
        missing. The pipeline's resume probe checks for case.json as
        the "this stage completed" sentinel, so on the next claim it
        skipped the trace stage but downstream deliverables choked on
        the absent manifest/transfers — empty PDFs shipped to victims.
        Now: companions first, case.json last → resume sentinel only
        flips after every artifact is durably stored.
        """
        log.info("writing case to supabase storage prefix %s", self.storage_prefix)

        opts = orjson.OPT_INDENT_2 if self._pretty else 0
        case_payload = case.model_dump(mode="json")
        case_bytes = orjson.dumps(case_payload, option=opts)
        case_path = self.storage_prefix + "case.json"

        # Manifest fields mirror CaseStore.write_case exactly.
        manifest = {
            "case_id": case.case_id,
            "schema_version": case.schema_version,
            "software_version": __version__,
            "chain": case.chain.value,
            "seed_address": case.seed_address,
            "incident_time": case.incident_time.isoformat(),
            "trace_started_at": case.trace_started_at.isoformat(),
            "trace_completed_at": (
                case.trace_completed_at.isoformat() if case.trace_completed_at else None
            ),
            "transfer_count": len(case.transfers),
            "exchange_endpoint_count": len(case.exchange_endpoints),
            "total_usd_out": str(case.total_usd_out) if case.total_usd_out is not None else None,
            "config_used": case.config_used,
            "written_at": datetime.now(UTC).isoformat(),
        }
        manifest_bytes = orjson.dumps(manifest, option=orjson.OPT_INDENT_2)
        csv_bytes = self._render_transfers_csv(case)

        # Companions FIRST so case.json is the sentinel that flips
        # only when the bundle is durable end-to-end.
        self._upload(self.storage_prefix + "transfers.csv", csv_bytes, "text/csv; charset=utf-8")
        self._upload(self.storage_prefix + "manifest.json", manifest_bytes, "application/json")
        self._upload(case_path, case_bytes, "application/json")

        return case_path

    def read_case(self) -> Case:
        log.info("reading case from supabase storage prefix %s", self.storage_prefix)
        raw = self._download(self.storage_prefix + "case.json")
        if raw.startswith(_BOM):
            raw = raw[3:]
        return Case.model_validate(orjson.loads(raw))

    # ----- Generic helpers ----- #

    def write_text(
        self,
        filename: str,
        content: str,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        _validate_relpath(filename, kind="filename")
        self._upload(self.storage_prefix + filename, content.encode("utf-8"), content_type)

    def read_text(self, filename: str) -> str:
        _validate_relpath(filename, kind="filename")
        raw = self._download(self.storage_prefix + filename)
        if raw.startswith(_BOM):
            raw = raw[3:]
        return raw.decode("utf-8")

    def write_json(self, filename: str, data: dict | list) -> None:
        _validate_relpath(filename, kind="filename")
        opts = orjson.OPT_INDENT_2 if self._pretty else 0
        body = orjson.dumps(data, option=opts)
        self._upload(self.storage_prefix + filename, body, "application/json")

    def read_json(self, filename: str) -> dict | list:
        _validate_relpath(filename, kind="filename")
        raw = self._download(self.storage_prefix + filename)
        if raw.startswith(_BOM):
            raw = raw[3:]
        return orjson.loads(raw)

    def exists(self, filename: str) -> bool:
        _validate_relpath(filename, kind="filename")
        url = f"{self._storage_root}/object/{self._bucket}/{self.storage_prefix}{filename}"
        resp = self._client.head(url)
        if resp.status_code == 200:
            return True
        if resp.status_code in (400, 404):
            return False
        raise RuntimeError(
            f"HEAD {filename} failed: {resp.status_code} {resp.text[:200]}"
        )

    # ----- Evidence subpath ----- #

    def write_evidence(self, tx_hash: str, payload: dict) -> None:
        # RIGOR-Jacob Z19-5: tx_hash is concatenated into the storage
        # URL; a regressed chain adapter producing ``"../../leak"``
        # would write outside the investigation prefix. Reject early.
        _validate_relpath(tx_hash, kind="tx_hash")
        opts = orjson.OPT_INDENT_2 if self._pretty else 0
        body = orjson.dumps(payload, option=opts)
        path = self.storage_prefix + f"evidence/{tx_hash}.json"
        self._upload(path, body, "application/json")

    def list_evidence(self) -> list[str]:
        names = self.list_files("evidence")
        return [n[:-5] for n in names if n.endswith(".json")]

    # ----- Generic listing ----- #

    def list_files(self, subpath: str | None = None) -> list[str]:
        prefix = self.storage_prefix
        if subpath:
            prefix = prefix + subpath.strip("/") + "/"
        items = self._list(prefix)
        return [item["name"] for item in items if item.get("id") is not None]

    # ----- Browse (operator console) ----- #

    def list_artifacts(self) -> list[tuple[str, int]]:
        """Every file under this investigation's prefix as
        ``(relpath, size_bytes)`` pairs (relpath is prefix-relative, POSIX).

        Powers the Case-Index per-case artifact browser when the console is
        backed by Supabase. Sizes come from the Storage list ``metadata.size``;
        a missing/garbage size degrades to 0 rather than raising."""
        out: list[tuple[str, int]] = []
        for full, size in self._walk_with_meta(self.storage_prefix):
            rel = full[len(self.storage_prefix):] if full.startswith(self.storage_prefix) else full
            out.append((rel, size))
        return out

    def list_top_level_names(self) -> list[str]:
        """Names directly under this investigation's prefix (files AND folders),
        in one non-recursive list call. The console index uses this to derive
        deliverable-presence flags cheaply (case.json / freeze_brief.json /
        ai_triage.json / graph_ui.html / the exhibit_pack folder)."""
        return [
            str(i["name"]).rstrip("/")
            for i in self._list(self.storage_prefix)
            if i.get("name")
        ]

    def read_artifact(self, relpath: str) -> bytes:
        """Download one prefix-relative artifact (e.g. ``briefs/le_handoff.html``).
        Path-traversal-guarded via ``_validate_relpath`` (rejects ``..`` / ``//``
        / leading-slash / control chars), then size-capped by ``_download``."""
        _validate_relpath(relpath, kind="artifact path")
        return self._download(self.storage_prefix + relpath)

    def _walk_with_meta(
        self, prefix: str, _depth: int = 0,
    ) -> list[tuple[str, int]]:
        """Like ``_walk_all_files`` but also returns each file's size from the
        list ``metadata``. Same depth bound (``_WALK_MAX_DEPTH``)."""
        if _depth >= _WALK_MAX_DEPTH:
            log.warning(
                "supabase _walk_with_meta hit max recursion depth %d at "
                "prefix %r — skipping deeper traversal", _WALK_MAX_DEPTH, prefix,
            )
            return []
        out: list[tuple[str, int]] = []
        for item in self._list(prefix):
            name = item.get("name")
            if not name:
                continue
            full = prefix + name
            if item.get("id") is None:
                out.extend(self._walk_with_meta(full + "/", _depth=_depth + 1))
            else:
                meta = item.get("metadata") or {}
                try:
                    size = int(meta.get("size") or 0)
                except (TypeError, ValueError):
                    size = 0
                out.append((full, max(0, size)))
        return out

    # ----- Cleanup ----- #

    def delete_all(self) -> int:
        return self._delete_under_prefix(self.storage_prefix)

    def delete_under(self, subpath: str) -> int:
        """Delete every file under ``storage_prefix + subpath``.

        Intended for "fresh start" stages that re-generate all their
        outputs and want to remove stale artifacts from prior runs.
        The canonical use case is ``building_package``: each run
        produces fresh per-issuer briefs with a new BRIEF-<timestamp>
        ID, so prior runs' briefs accumulate in the bucket without
        cleanup. Calling ``delete_under("briefs")`` before upload
        keeps the bucket bounded.

        Idempotent — returns 0 if the prefix is already empty.
        Returns the number of files deleted so callers can log.
        """
        if not subpath:
            raise ValueError(
                "delete_under requires a non-empty subpath; use delete_all() "
                "to wipe the entire investigation's bucket prefix"
            )
        full_prefix = self.storage_prefix + subpath.strip("/") + "/"
        return self._delete_under_prefix(full_prefix)

    def _delete_under_prefix(self, prefix: str) -> int:
        """Batch-delete every file under ``prefix``. Shared
        implementation between delete_all and delete_under so the
        batching + error-handling stays in one place."""
        return self._delete_object_paths(self._walk_all_files(prefix))

    def _delete_object_paths(self, paths: list[str]) -> int:
        """Batch-delete an explicit list of full object paths (200/req).
        Shared by prefix-deletes and the brief-generation dedupe."""
        if not paths:
            return 0
        deleted = 0
        for i in range(0, len(paths), 200):
            batch = paths[i : i + 200]
            url = f"{self._storage_root}/object/{self._bucket}"
            resp = self._client.request(
                "DELETE",
                url,
                json={"prefixes": batch},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code not in (200, 204):
                raise RuntimeError(
                    f"DELETE batch failed: {resp.status_code} {resp.text[:200]}"
                )
            try:
                deleted += len(resp.json())
            except Exception:  # noqa: BLE001
                deleted += len(batch)
        return deleted

    def dedupe_brief_generations(self, *, dry_run: bool = True) -> dict[str, Any]:
        """Keep only the LATEST ``BRIEF-<timestamp>`` generation under briefs/;
        remove older generations' files.

        Each building_package re-run writes a fresh ``BRIEF-<YYYYMMDDTHHMMSS>``
        generation of every per-issuer deliverable (le_handoff / freeze_request
        / manifest). Pre-cleanup-era cases accumulated multiple generations in
        one folder; the output_integrity validator then sees N disagreeing
        generations and fires cross-document-consistency criticals. This
        collapses the case to one clean generation.

        Default ``dry_run=True`` returns what WOULD be removed without touching
        the bucket. Returns ``{latest, removed, kept, dry_run, deleted}``.
        No-op (removed=[]) when 0 or 1 generation is present.
        """
        names = self.list_files("briefs")
        stale = stale_brief_generation_files(names)
        latest = latest_brief_generation(names)
        removed = [f"briefs/{n}" for n in stale]
        deleted = 0
        if removed and not dry_run:
            deleted = self._delete_object_paths(
                [self.storage_prefix + r for r in removed]
            )
        return {
            "latest": latest,
            "removed": removed,
            "kept": len(names) - len(stale),
            "dry_run": dry_run,
            "deleted": deleted,
        }

    # ----- Lifecycle ----- #

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SupabaseCaseStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # =====================================================================
    # internals
    # =====================================================================

    def _upload(self, path: str, body: bytes, content_type: str) -> None:
        """Upsert ``body`` at ``path``.

        Uses PUT, not POST: Supabase Storage's POST endpoint creates
        new objects only and returns 400 if the file already exists,
        even with ``x-upsert: true`` (the header is reliably honored
        on PUT but flaky on POST). Resumed worker stages re-upload
        the same case_dir, so every upload must be idempotent.

        On 413, or 400 with an HTML body and a >10 MB payload (typical
        Cloudflare/edge size-limit response shape, before the request
        even reaches Supabase), raise ``PayloadTooLargeError`` so the
        caller can skip non-critical files instead of failing the
        whole stage.
        """
        url = f"{self._storage_root}/object/{self._bucket}/{path}"
        return self._upload_with_retry(url, body, content_type, path)

    @_storage_retry
    def _upload_with_retry(
        self, url: str, body: bytes, content_type: str, path: str
    ) -> None:
        """Inner retry-wrapped PUT. 5xx + transport errors retry on
        the 2s/4s/8s schedule; 4xx (incl. 413/oversize) bubbles up
        immediately."""
        resp = self._client.put(
            url,
            content=body,
            headers={"Content-Type": content_type, "x-upsert": "true"},
        )
        if resp.status_code in (200, 201):
            return
        is_oversize = resp.status_code == 413 or (
            resp.status_code == 400
            and "text/html" in resp.headers.get("content-type", "").lower()
            and len(body) > 10 * 1024 * 1024
        )
        if is_oversize:
            raise PayloadTooLargeError(path, len(body), resp.status_code)
        if 500 <= resp.status_code < 600:
            raise _StorageTransient(
                f"upload to {path} failed (5xx, will retry): "
                f"{resp.status_code} {resp.text[:200]}"
            )
        raise RuntimeError(
            f"upload to {path} failed: {resp.status_code} {resp.text[:200]}"
        )

    @_storage_retry
    def _download(self, path: str) -> bytes:
        url = f"{self._storage_root}/object/{self._bucket}/{path}"
        resp = self._client.get(url)
        if resp.status_code in (400, 404):
            raise FileNotFoundError(f"Not found in Supabase Storage: {path}")
        if 500 <= resp.status_code < 600:
            raise _StorageTransient(
                f"download {path} failed (5xx, will retry): "
                f"{resp.status_code} {resp.text[:200]}"
            )
        if resp.status_code != 200:
            raise RuntimeError(
                f"download {path} failed: {resp.status_code} {resp.text[:200]}"
            )
        # RIGOR-Jacob Z19-2: cap response body. Anyone with bucket
        # write access (admin UI, sibling worker, a hostile tenant)
        # can plant a multi-GB case.json — the next worker resuming
        # the case would OOM loading it via resp.content.
        try:
            content_length_header = resp.headers.get("content-length")
        except Exception:  # noqa: BLE001
            content_length_header = None
        try:
            content_length = (
                int(content_length_header) if content_length_header else None
            )
        except (TypeError, ValueError):
            content_length = None
        if content_length is not None and content_length > _DOWNLOAD_HARD_CAP_BYTES:
            raise PayloadTooLargeError(path, content_length, resp.status_code)
        body = resp.content
        if len(body) > _DOWNLOAD_HARD_CAP_BYTES:
            # Server lied about / omitted Content-Length; the body
            # is already in memory but we still refuse to hand it
            # back to the caller so downstream parsers can't choke
            # on a hostile payload.
            raise PayloadTooLargeError(path, len(body), resp.status_code)
        return body

    def _list(self, prefix: str, limit: int = 1000) -> list[dict[str, Any]]:
        url = f"{self._storage_root}/object/list/{self._bucket}"
        offset = 0
        out: list[dict[str, Any]] = []
        # RIGOR-Jacob Z19-3: bounded pagination. A hostile / buggy
        # endpoint that keeps returning `limit` rows would otherwise
        # spin the worker forever with unbounded memory growth.
        for _ in range(_LIST_MAX_PAGES):
            page = self._list_page(url, prefix, limit, offset)
            if not page:
                break
            out.extend(page)
            if len(page) < limit:
                break
            offset += limit
        else:
            log.warning(
                "supabase _list pagination hit cap of %d pages for "
                "prefix %r — returning truncated result; check for "
                "pathological bucket state",
                _LIST_MAX_PAGES, prefix,
            )
        return out

    @_storage_retry
    def _list_page(
        self, url: str, prefix: str, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        """One paginated list call, retry-wrapped at the page level
        so a transient mid-pagination failure only redoes the
        offending page, not the whole walk."""
        resp = self._client.post(
            url,
            json={
                "prefix": prefix,
                "limit": limit,
                "offset": offset,
                "sortBy": {"column": "name", "order": "asc"},
            },
            headers={"Content-Type": "application/json"},
        )
        if 500 <= resp.status_code < 600:
            raise _StorageTransient(
                f"list {prefix} failed (5xx, will retry): "
                f"{resp.status_code} {resp.text[:200]}"
            )
        if resp.status_code != 200:
            raise RuntimeError(
                f"list {prefix} failed: {resp.status_code} {resp.text[:200]}"
            )
        # RIGOR-Jacob Z19-6: validate response shape. A CDN error
        # page parsed as JSON, an upstream schema change, or a hostile
        # MITM could return a string / dict / null instead of a list.
        # Without this guard the caller crashes with a confusing
        # ``str.get`` AttributeError deep in a list comprehension.
        try:
            payload = resp.json()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"list {prefix} returned non-JSON response: {e}"
            ) from e
        if not isinstance(payload, list):
            raise RuntimeError(
                f"list {prefix} returned invalid response shape: "
                f"expected list of dicts, got {type(payload).__name__}"
            )
        return payload

    def _walk_all_files(self, prefix: str, _depth: int = 0) -> list[str]:
        """Recursively collect every file path under ``prefix``.

        RIGOR-Jacob Z19-4: ``_depth`` is bounded by ``_WALK_MAX_DEPTH``
        so a hostile bucket layout (or a Supabase server that reports
        the same directory as its own child) cannot blow Python's
        recursion limit. Production nesting is 2 levels
        (``investigations/<uuid>/evidence/``); 16 leaves ample slack.
        """
        if _depth >= _WALK_MAX_DEPTH:
            log.warning(
                "supabase _walk_all_files hit max recursion depth %d "
                "at prefix %r — skipping deeper traversal (suggests "
                "pathological bucket state or buggy server)",
                _WALK_MAX_DEPTH, prefix,
            )
            return []
        out: list[str] = []
        items = self._list(prefix)
        for item in items:
            name = item.get("name")
            if not name:
                continue
            full = prefix + name
            if item.get("id") is None:
                out.extend(self._walk_all_files(full + "/", _depth=_depth + 1))
            else:
                out.append(full)
        return out

    @staticmethod
    def _render_transfers_csv(case: Case) -> bytes:
        fields = [
            "transfer_id",
            "tx_hash",
            "block_number",
            "block_time_utc",
            "from_address",
            "to_address",
            "to_label",
            "to_label_category",
            "to_exchange",
            "is_contract",
            "token_symbol",
            "token_contract",
            "amount_decimal",
            "amount_raw",
            "usd_value_at_tx",
            "pricing_source",
            "pricing_error",
            "hop_depth",
            "explorer_url",
        ]
        buf = io.StringIO(newline="")
        w = csv.DictWriter(buf, fieldnames=fields)
        w.writeheader()
        for t in case.transfers:
            cp_label = t.counterparty.label
            w.writerow({
                "transfer_id": t.transfer_id,
                "tx_hash": t.tx_hash,
                "block_number": t.block_number,
                "block_time_utc": t.block_time.isoformat(),
                "from_address": t.from_address,
                "to_address": t.to_address,
                "to_label": cp_label.name if cp_label else "",
                "to_label_category": cp_label.category.value if cp_label else "unknown",
                "to_exchange": (cp_label.exchange if cp_label else "") or "",
                "is_contract": "yes" if t.counterparty.is_contract else "no",
                "token_symbol": t.token.symbol,
                "token_contract": t.token.contract or "",
                "amount_decimal": _fmt_decimal(t.amount_decimal),
                "amount_raw": t.amount_raw,
                "usd_value_at_tx": _fmt_decimal(t.usd_value_at_tx) if t.usd_value_at_tx else "",
                "pricing_source": t.pricing_source or "",
                "pricing_error": t.pricing_error or "",
                "hop_depth": t.hop_depth,
                "explorer_url": t.explorer_url,
            })
        return buf.getvalue().encode("utf-8")


def _fmt_decimal(d: Decimal | None) -> str:
    if d is None:
        return ""
    return format(d, "f")


# Nil UUID used purely to satisfy the per-investigation constructor when we
# only need the bucket-level list client; its prefix is never read or written.
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


def list_investigation_ids(
    config: RecuperoConfig,
    supabase_url: str,
    service_role_key: str,
    bucket: str = "investigation-files",
    timeout: float = 30.0,
) -> list[str]:
    """List the investigation_id folders under ``investigations/`` in the
    bucket — the bucket-level enumeration the operator Case-Index console needs
    to show every Supabase-backed case (the per-investigation store can't do
    this, it's scoped to one id).

    Reuses the store's hardened, retrying, bounded ``_list`` (built with a nil
    UUID purely for the client; the nil prefix is never touched). Returns the
    folder UUIDs in listing order. Closes the throwaway client before
    returning.
    """
    store = SupabaseCaseStore(
        config, supabase_url=supabase_url, service_role_key=service_role_key,
        investigation_id=_NIL_UUID, bucket=bucket, timeout=timeout,
    )
    try:
        items = store._list("investigations/")  # noqa: SLF001 — same module
        # Folders have id == None; their `name` is the investigation_id.
        return [
            str(item["name"]).rstrip("/")
            for item in items
            if item.get("id") is None and item.get("name")
        ]
    finally:
        store.close()
