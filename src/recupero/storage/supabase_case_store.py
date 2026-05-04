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
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import httpx
import orjson

from recupero import __version__
from recupero.config import RecuperoConfig
from recupero.models import Case

log = logging.getLogger(__name__)

_BOM = b"\xef\xbb\xbf"


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
        log.info("writing case to supabase storage prefix %s", self.storage_prefix)

        opts = orjson.OPT_INDENT_2 if self._pretty else 0
        case_payload = case.model_dump(mode="json")
        case_bytes = orjson.dumps(case_payload, option=opts)
        case_path = self.storage_prefix + "case.json"
        self._upload(case_path, case_bytes, "application/json")

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
            "written_at": datetime.now(timezone.utc).isoformat(),
        }
        manifest_bytes = orjson.dumps(manifest, option=orjson.OPT_INDENT_2)
        self._upload(self.storage_prefix + "manifest.json", manifest_bytes, "application/json")

        csv_bytes = self._render_transfers_csv(case)
        self._upload(self.storage_prefix + "transfers.csv", csv_bytes, "text/csv; charset=utf-8")

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
        self._upload(self.storage_prefix + filename, content.encode("utf-8"), content_type)

    def read_text(self, filename: str) -> str:
        raw = self._download(self.storage_prefix + filename)
        if raw.startswith(_BOM):
            raw = raw[3:]
        return raw.decode("utf-8")

    def write_json(self, filename: str, data: dict | list) -> None:
        opts = orjson.OPT_INDENT_2 if self._pretty else 0
        body = orjson.dumps(data, option=opts)
        self._upload(self.storage_prefix + filename, body, "application/json")

    def read_json(self, filename: str) -> dict | list:
        raw = self._download(self.storage_prefix + filename)
        if raw.startswith(_BOM):
            raw = raw[3:]
        return orjson.loads(raw)

    def exists(self, filename: str) -> bool:
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

    # ----- Cleanup ----- #

    def delete_all(self) -> int:
        paths = self._walk_all_files(self.storage_prefix)
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
            except Exception:
                deleted += len(batch)
        return deleted

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
        raise RuntimeError(
            f"upload to {path} failed: {resp.status_code} {resp.text[:200]}"
        )

    def _download(self, path: str) -> bytes:
        url = f"{self._storage_root}/object/{self._bucket}/{path}"
        resp = self._client.get(url)
        if resp.status_code in (400, 404):
            raise FileNotFoundError(f"Not found in Supabase Storage: {path}")
        if resp.status_code != 200:
            raise RuntimeError(
                f"download {path} failed: {resp.status_code} {resp.text[:200]}"
            )
        return resp.content

    def _list(self, prefix: str, limit: int = 1000) -> list[dict[str, Any]]:
        url = f"{self._storage_root}/object/list/{self._bucket}"
        offset = 0
        out: list[dict[str, Any]] = []
        while True:
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
            if resp.status_code != 200:
                raise RuntimeError(
                    f"list {prefix} failed: {resp.status_code} {resp.text[:200]}"
                )
            page = resp.json()
            if not page:
                break
            out.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return out

    def _walk_all_files(self, prefix: str) -> list[str]:
        """Recursively collect every file path under ``prefix``."""
        out: list[str] = []
        items = self._list(prefix)
        for item in items:
            name = item.get("name")
            if not name:
                continue
            full = prefix + name
            if item.get("id") is None:
                out.extend(self._walk_all_files(full + "/"))
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
