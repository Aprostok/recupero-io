"""Victim PII model and loader.

Personally-identifiable info about the victim is stored in
`data/cases/<case_id>/victim.json` — NEVER in case.json. Two reasons:
  (1) case.json is structured chain data, safe to share or anonymize.
      victim.json is sensitive and must be access-controlled.
  (2) The same victim can have multiple cases over time; keeping PII per-case
      lets us redact a single case without losing PII from related cases.

All `data/cases/` is gitignored, so PII is never accidentally committed.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class VictimInfo(BaseModel):
    """PII about the victim. Loaded only when generating briefs."""
    model_config = ConfigDict(extra="forbid")

    name: str
    citizenship: str | None = None
    address: str | None = None       # postal address
    email: str | None = None
    phone: str | None = None
    wallet_address: str               # the victim's wallet (matches case.seed_address)

    # Free-form narrative the brief author wants embedded
    incident_summary: str | None = None

    # Optional: legal representation
    legal_counsel: str | None = None
    legal_counsel_email: str | None = None


def load_victim(case_dir: Path) -> VictimInfo:
    """Load victim.json from a case directory. Raises FileNotFoundError if missing."""
    path = case_dir / "victim.json"
    if not path.exists():
        raise FileNotFoundError(
            f"victim.json not found in {case_dir}. "
            "Create one with the schema in src/recupero/reports/victim.py."
        )
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return VictimInfo.model_validate(data)


def write_victim(case_dir: Path, victim: VictimInfo) -> Path:
    """Write a VictimInfo to victim.json."""
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_dir / "victim.json"
    path.write_text(victim.model_dump_json(indent=2), encoding="utf-8")
    return path


def example_victim() -> VictimInfo:
    """Sample for documentation / tests."""
    return VictimInfo(
        name="Jane Doe",
        citizenship="USA",
        address="1234 Example St, Springfield, IL 62701",
        email="jane@example.com",
        wallet_address="0x0000000000000000000000000000000000000001",
        incident_summary="Wallet drain on 2025-01-01.",
    )
