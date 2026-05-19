"""Read and write case folders.

Layout (mirrored in docs/PHASE1_SPEC.md):

    data/cases/<case_id>/
    ├── case.json
    ├── manifest.json
    ├── transfers.csv
    ├── tx_evidence/
    │   └── <tx_hash>.json
    └── logs/
        └── trace.log
"""

from __future__ import annotations

import csv
import hashlib
import logging
import os
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import orjson

from recupero import __version__
from recupero.config import RecuperoConfig
from recupero.models import Case

log = logging.getLogger(__name__)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomic file write — tempfile + os.replace. Used for case.json
    and manifest.json so a worker crash mid-write can't leave a
    truncated file that fails parsing.

    Atomic on POSIX and Windows (Python 3.3+'s os.replace is atomic
    on both). Matches the atomic_write_text helper in recupero._common
    but stays bytes-based here since orjson emits bytes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        raise


class CaseStore:
    def __init__(self, config: RecuperoConfig) -> None:
        self.cases_root = Path(config.storage.data_dir) / "cases"
        self.cases_root.mkdir(parents=True, exist_ok=True)
        self.pretty = config.storage.pretty_json

    def case_dir(self, case_id: str) -> Path:
        d = self.cases_root / case_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "tx_evidence").mkdir(exist_ok=True)
        (d / "logs").mkdir(exist_ok=True)
        return d

    def write_case(self, case: Case) -> Path:
        # All three writes (case.json, manifest.json, transfers.csv)
        # are atomic via tempfile+rename. A worker crash mid-write
        # used to leave truncated case.json that crashed downstream
        # parsers; now either the previous version is intact or the
        # new version is fully written.
        d = self.case_dir(case.case_id)
        case_path = d / "case.json"
        payload = case.model_dump(mode="json")
        opts = orjson.OPT_INDENT_2 if self.pretty else 0
        case_bytes = orjson.dumps(payload, option=opts)
        _atomic_write_bytes(case_path, case_bytes)
        log.info("wrote case file %s", case_path)

        # CSV mirror — flat view for spreadsheet review and LE.
        # Write BEFORE the manifest so we can hash the on-disk CSV
        # for the manifest's chain-of-custody record.
        csv_path = d / "transfers.csv"
        self._write_transfers_csv(case, csv_path)

        # v0.17.7 (round-10 forensic HIGH): manifest now embeds SHA256
        # of the two produced artifacts. Compliance teams + LE expect
        # a chain-of-custody record they can independently verify;
        # pre-v0.17.7 the manifest only carried counts (transfer_count,
        # exchange_endpoint_count) which couldn't detect tampering.
        # Hashes are computed from the bytes we actually wrote, not
        # re-read from disk, so a concurrent-write race can't alter
        # the recorded value.
        case_sha256 = hashlib.sha256(case_bytes).hexdigest()
        try:
            csv_sha256 = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        except OSError:
            csv_sha256 = None

        # Manifest — small subset of metadata, easy to read
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
            # v0.17.7: chain-of-custody artifact hashes.
            "artifact_sha256": {
                "case.json": case_sha256,
                "transfers.csv": csv_sha256,
            },
        }
        manifest_path = d / "manifest.json"
        _atomic_write_bytes(
            manifest_path,
            orjson.dumps(manifest, option=orjson.OPT_INDENT_2),
        )

        return case_path

    def read_case(self, case_id: str) -> Case:
        path = self.cases_root / case_id / "case.json"
        with path.open("rb") as f:
            raw = f.read()
        # Strip UTF-8 BOM if present (PowerShell's `Set-Content -Encoding UTF8`
        # writes a BOM that orjson/json reject).
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        data = orjson.loads(raw)
        return Case.model_validate(data)

    # ----- internals -----

    @staticmethod
    def _write_transfers_csv(case: Case, path: Path) -> None:
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
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
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


def _fmt_decimal(d: Decimal | None) -> str:
    if d is None:
        return ""
    # Avoid scientific notation in CSV
    return format(d, "f")
