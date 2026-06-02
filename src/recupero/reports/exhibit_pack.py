"""Court-admissible exhibit pack (v0.35.11 — roadmap H1).

Assembles a single reviewable exhibit pack for expert-testimony / litigation use:

  1. **Exhibit index** — every case artifact (brief, transfers CSV, findings,
     rendered deliverables) listed as Exhibit A, B, C… with its SHA-256 hash and
     byte size. The hash lets a court / opposing expert confirm the file
     introduced into evidence is byte-identical to what was produced.
  2. **Methodology appendix** — a factual, reproducible description of the
     tracing method (value-directed BFS, cryptographic bridge-pairing oracle,
     label provenance + confidence tiers, evidence-receipt chain of custody,
     deterministic software version + config). This is the Daubert "the method
     is reliable and reproducible" section.
  3. **Declaration template** — a 28 U.S.C. § 1746 unsworn-declaration skeleton
     the testifying investigator completes and signs (qualifications, the
     exhibits relied upon, the penalty-of-perjury clause).

Posture: the hashes + artifact list are REAL (computed from the files on disk);
the methodology describes the ACTUAL pipeline; the declaration is a TEMPLATE for
the declarant to complete. Nothing is fabricated. Recupero does not attest —
the testifying expert does, on their own signature.

Output: ``exhibit_pack/exhibit_pack.html`` next to the case deliverables.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero._common import atomic_write_text, resolve_render_time

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Evidentiary file extensions included in the exhibit index. Deterministic,
# top-level-only scan (no recursion) so the index is stable + reviewable.
_EXHIBIT_EXTENSIONS = frozenset({".json", ".csv", ".html", ".pdf", ".txt", ".md"})

# Files the exhibit pack must never list (its own output, transient/lock files).
_EXCLUDE_NAMES = frozenset({"exhibit_pack.html"})

# Read the file in chunks so a large transfers.csv doesn't load fully into RAM.
_HASH_CHUNK_BYTES = 1024 * 1024

# Human-readable purpose hints per known artifact filename (for the index).
_ARTIFACT_PURPOSE: dict[str, str] = {
    "freeze_brief.json": "Structured freeze brief (machine-readable findings).",
    "case.json": "Raw traced case: every fetched transfer + provenance.",
    "transfers.csv": "Tabular transfer ledger (one row per on-chain transfer).",
    "investigator_findings.csv": "Per-finding analyst worksheet (LE-ingestible).",
    "investigator_findings.json": "Per-finding analyst data (structured).",
    "victim.json": "Victim intake record.",
    "freeze_asks.json": "Per-issuer / per-exchange freeze-target worksheet.",
    "graph_ui.html": "Interactive fund-flow graph (self-contained).",
    "ai_triage.json": "AI triage summary (review-required; probabilistic leads).",
}


@dataclass(frozen=True)
class ExhibitEntry:
    """One artifact in the exhibit index."""
    exhibit_label: str        # "Exhibit A", "Exhibit B", …
    filename: str
    sha256: str
    size_bytes: int
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "exhibit_label": self.exhibit_label,
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "size_human": _human_size(self.size_bytes),
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class ExhibitManifest:
    """The full exhibit index for a case."""
    case_id: str
    entries: tuple[ExhibitEntry, ...]
    software_version: str
    config_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "software_version": self.software_version,
            "config_summary": self.config_summary,
            "entries": [e.to_dict() for e in self.entries],
            "exhibit_count": len(self.entries),
        }


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _exhibit_letter(index: int) -> str:
    """0→A, 25→Z, 26→AA, 27→AB … (spreadsheet-column style)."""
    letters = ""
    n = index
    while True:
        letters = chr(ord("A") + (n % 26)) + letters
        n = n // 26 - 1
        if n < 0:
            break
    return letters


def _load_case_meta(case_dir: Path) -> tuple[str, str, str]:
    """Best-effort (case_id, software_version, config_summary) from the
    brief or case.json. Never raises — falls back to placeholders."""
    case_id = case_dir.name
    software_version = "(version not recorded)"
    config_summary = "(configuration not recorded)"
    for name in ("freeze_brief.json", "case.json"):
        p = case_dir / name
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        case_id = str(data.get("CASE_ID") or data.get("case_id") or case_id)
        sv = data.get("SOFTWARE_VERSION") or data.get("software_version")
        if sv:
            software_version = str(sv)
        cfg = data.get("config_used") or data.get("CONFIG_USED")
        if isinstance(cfg, dict) and cfg:
            # Compact, deterministic one-line summary (sorted keys).
            items = sorted(f"{k}={v}" for k, v in cfg.items())
            config_summary = "; ".join(items)[:500]
        break
    return case_id, software_version, config_summary


def build_exhibit_manifest(case_dir: Path) -> ExhibitManifest:
    """Scan ``case_dir`` (top level only) for evidentiary artifacts, hash each,
    and build a deterministic, alphabetically-ordered exhibit index.

    Pure w.r.t. inputs (filesystem read only); deterministic ordering so two
    runs over the same directory produce identical exhibit labels.
    """
    case_id, software_version, config_summary = _load_case_meta(case_dir)

    candidates = sorted(
        p for p in case_dir.iterdir()
        if p.is_file()
        and p.suffix.lower() in _EXHIBIT_EXTENSIONS
        and p.name not in _EXCLUDE_NAMES
    )

    entries: list[ExhibitEntry] = []
    for i, p in enumerate(candidates):
        try:
            digest = _sha256_file(p)
            size = p.stat().st_size
        except OSError as exc:
            log.warning("exhibit-pack: cannot hash %s: %s — skipping", p, exc)
            continue
        entries.append(ExhibitEntry(
            exhibit_label=f"Exhibit {_exhibit_letter(i)}",
            filename=p.name,
            sha256=digest,
            size_bytes=size,
            purpose=_ARTIFACT_PURPOSE.get(p.name, "Case artifact."),
        ))

    return ExhibitManifest(
        case_id=case_id,
        entries=tuple(entries),
        software_version=software_version,
        config_summary=config_summary,
    )


def render_exhibit_pack(
    case_dir: Path, *, output_dir: Path | None = None,
) -> Path:
    """Build the manifest + render the exhibit pack HTML.

    Returns the written path (``exhibit_pack/exhibit_pack.html`` by default).
    """
    manifest = build_exhibit_manifest(case_dir)
    out_dir = output_dir or (case_dir / "exhibit_pack")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template("exhibit_pack.html.j2")
    html = template.render(
        manifest=manifest.to_dict(),
        generated_at=resolve_render_time().isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    out_path = out_dir / "exhibit_pack.html"
    atomic_write_text(out_path, html)
    log.info(
        "rendered exhibit pack: %s (%d exhibits, %d bytes)",
        out_path, manifest.to_dict()["exhibit_count"], out_path.stat().st_size,
    )
    return out_path


__all__ = (
    "ExhibitEntry",
    "ExhibitManifest",
    "build_exhibit_manifest",
    "render_exhibit_pack",
)
