#!/usr/bin/env python3
"""Snapshot the investigations + cases tables to a local JSON archive.

Recupero's source-of-truth metadata lives in two Postgres tables:
``public.investigations`` (queue + worker outputs) and ``public.cases``
(victim/incident narrative). Losing either one means losing the audit
trail for every brief we've produced. Supabase's own backups cover us
for total-loss disaster, but a self-managed weekly snapshot gives:

  * point-in-time recovery from a bad UI deploy or an accidental DELETE
    that Supabase's PITR window has already aged out of (free tier is
    7 days);
  * an offline copy we control;
  * a portable export if we ever migrate off Supabase.

The bucket files (briefs, evidence, fund-flow SVGs) are deliverables —
deterministic outputs of the row data plus the on-chain trace. Losing
them is annoying but recoverable by re-running the worker. They are
NOT backed up by default; pass ``--include-bucket`` if you want a full
snapshot including artifacts.

Output layout::

    <out-dir>/
        investigations.json   # full table dump
        cases.json            # full table dump
        manifest.json         # row counts + checksums + timestamp
        bucket/               # only with --include-bucket
            <inv_uuid>/
                case.json
                ...etc

Usage:
    python scripts/backup_investigations.py
    python scripts/backup_investigations.py --out-dir backups/2026-05-08
    python scripts/backup_investigations.py --include-bucket

Schedule weekly via cron / GitHub Actions; see docs/RAILWAY_DEPLOY.md
§"Weekly backup".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import httpx  # noqa: E402
import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

log = logging.getLogger("backup")

_BUCKET = "investigation-files"
_BUCKET_PREFIX = "investigations/"


def _json_default(obj):
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    raise TypeError(f"not JSON-serializable: {type(obj).__name__}")


def _dump_table(conn: psycopg.Connection, table: str, dest: Path) -> tuple[int, str]:
    """Dump all rows of ``table`` to ``dest`` as a JSON array. Returns (row_count, sha256)."""
    sql = f"SELECT * FROM {table};"
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    payload = json.dumps(rows, default=_json_default, indent=2, sort_keys=True).encode("utf-8")
    dest.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    return len(rows), digest


def _list_bucket_prefix(client: httpx.Client, storage_root: str, prefix: str) -> list[str]:
    """Walk a bucket prefix recursively, return a flat list of object paths."""
    url = f"{storage_root}/object/list/{_BUCKET}"
    out: list[str] = []
    queue = [prefix]
    while queue:
        cur_prefix = queue.pop(0)
        offset = 0
        while True:
            resp = client.post(
                url,
                json={
                    "prefix": cur_prefix,
                    "limit": 1000,
                    "offset": offset,
                    "sortBy": {"column": "name", "order": "asc"},
                },
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"list {cur_prefix} failed: {resp.status_code} {resp.text[:200]}"
                )
            items = resp.json()
            if not items:
                break
            for item in items:
                name = item.get("name")
                if not name:
                    continue
                full = f"{cur_prefix}{name}"
                if item.get("id") is None:
                    queue.append(full + "/")
                else:
                    out.append(full)
            if len(items) < 1000:
                break
            offset += 1000
    return out


def _backup_bucket(out_dir: Path) -> dict[str, int]:
    supabase_url = os.environ["SUPABASE_URL"].rstrip("/")
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    storage_root = f"{supabase_url}/storage/v1"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
    }

    bucket_dir = out_dir / "bucket"
    bucket_dir.mkdir(parents=True, exist_ok=True)

    files = 0
    bytes_total = 0
    with httpx.Client(headers=headers, timeout=60.0) as client:
        paths = _list_bucket_prefix(client, storage_root, _BUCKET_PREFIX)
        for path in paths:
            url = f"{storage_root}/object/{_BUCKET}/{path}"
            resp = client.get(url)
            if resp.status_code != 200:
                log.warning("skip %s (HTTP %s)", path, resp.status_code)
                continue
            relative = path[len(_BUCKET_PREFIX):] if path.startswith(_BUCKET_PREFIX) else path
            local = bucket_dir / relative
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(resp.content)
            files += 1
            bytes_total += len(resp.content)

    return {"files": files, "bytes": bytes_total}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Where to write the snapshot (default: backups/<UTC timestamp>).",
    )
    parser.add_argument(
        "--include-bucket",
        action="store_true",
        help="Also download every file from the investigation-files bucket. "
             "Slower and larger; off by default.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()

    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2
    if args.include_bucket:
        if not (os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY")):
            print(
                "ERROR: --include-bucket needs SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY.",
                file=sys.stderr,
            )
            return 2

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    out_dir = args.out_dir or Path("backups") / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info("writing snapshot → %s", out_dir)

    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            inv_count, inv_sha = _dump_table(conn, "public.investigations", out_dir / "investigations.json")
            log.info("investigations: %d rows, sha256=%s", inv_count, inv_sha[:12])
            case_count, case_sha = _dump_table(conn, "public.cases", out_dir / "cases.json")
            log.info("cases:          %d rows, sha256=%s", case_count, case_sha[:12])
    except psycopg.Error as exc:
        print(f"ERROR: database dump failed: {exc}", file=sys.stderr)
        return 2

    bucket_summary: dict[str, int] | None = None
    if args.include_bucket:
        log.info("downloading bucket contents — this may take a while")
        try:
            bucket_summary = _backup_bucket(out_dir)
            log.info(
                "bucket: %d files, %.1f MB",
                bucket_summary["files"],
                bucket_summary["bytes"] / (1024 * 1024),
            )
        except Exception as exc:
            print(f"ERROR: bucket sync failed: {exc}", file=sys.stderr)
            return 2

    manifest = {
        "snapshot_at": datetime.now(timezone.utc).isoformat(),
        "tables": {
            "public.investigations": {"rows": inv_count, "sha256": inv_sha},
            "public.cases": {"rows": case_count, "sha256": case_sha},
        },
        "bucket": bucket_summary,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.info("done. manifest at %s", out_dir / "manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
