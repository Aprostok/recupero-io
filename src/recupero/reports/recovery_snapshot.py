"""Recovery Snapshot renderer (v0.22.0).

Renders ``recovery_snapshot.html.j2`` — a 1-page pre-engagement
deliverable that summarises the recovery estimate for the victim
and their counsel BEFORE the engagement fee is paid.

The audience for this artifact is non-technical (the victim
themselves, the victim's lawyer, sometimes an insurer). It
deliberately leads with:

  * The recommendation (recommend / caveat / discourage / reject)
  * The headline net-to-victim dollar figure with a 95% CI
  * A per-issuer table with effective freeze probability
  * Recovery drivers explaining what's helping / hurting

The full forensic record (trace report, freeze requests, LE
handoff) remains separate. The snapshot is a single shareable
document, not a forensic worksheet.

Distinct from the freeze-letter and LE-handoff deliverables —
those are post-engagement artifacts addressed to issuers or law
enforcement. The snapshot is pre-engagement and addressed to the
victim's side of the conversation.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import atomic_write_text

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_recovery_snapshot(
    *,
    case_id: str,
    recovery_estimate: dict[str, Any],
    briefs_dir: Path,
) -> Path | None:
    """Render the Recovery Snapshot HTML for ``case_id`` into
    ``briefs_dir`` and return the path.

    Returns None on render failure — the caller decides whether
    to log + continue (default) or surface as a hard error.

    Filename convention: ``recovery_snapshot_<case_id>.html`` —
    follows the same one-per-case shape as the trace report.
    """
    if not recovery_estimate:
        log.info("recovery_snapshot: no recovery estimate provided; skipping")
        return None

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        # StrictUndefined: missing template variables raise instead of
        # silently rendering as empty strings that look like missing data.
        undefined=StrictUndefined,
    )

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.22.x"

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    try:
        html = env.get_template("recovery_snapshot.html.j2").render(
            case_id=case_id,
            recovery_estimate=recovery_estimate,
            generated_at=generated_at,
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("recovery_snapshot render failed: %s", exc)
        return None

    briefs_dir.mkdir(parents=True, exist_ok=True)
    safe_case_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in case_id)
    out_path = briefs_dir / f"recovery_snapshot_{safe_case_id}.html"
    atomic_write_text(out_path, html)
    return out_path


__all__ = ("render_recovery_snapshot",)
