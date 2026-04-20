"""On-disk cache for historical price lookups.

Cache key is (token_id_or_contract, date_yyyymmdd). One JSON file per key.
The cache is append-only — we never invalidate. Historical prices don't change.
"""

from __future__ import annotations

import json
import logging
from decimal import Decimal
from pathlib import Path

log = logging.getLogger(__name__)


class PriceCache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str) -> dict | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            with path.open() as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("price cache miss (corrupted) %s: %s", path, e)
            return None

    def put(self, key: str, value: dict) -> None:
        path = self._path_for(key)
        # Convert Decimals to strings for JSON safety
        value = self._json_safe(value)
        try:
            with path.open("w") as f:
                json.dump(value, f, indent=2)
        except OSError as e:
            log.warning("failed to write price cache %s: %s", path, e)

    def _path_for(self, key: str) -> Path:
        # Replace path-unsafe chars
        safe = key.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe}.json"

    @staticmethod
    def _json_safe(value: dict) -> dict:
        out = {}
        for k, v in value.items():
            if isinstance(v, Decimal):
                out[k] = str(v)
            else:
                out[k] = v
        return out
