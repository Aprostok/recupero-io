"""Render the SUBPOENA_TARGETS artifact family (v0.28.0).

Produces, per case:
  * One subpoena_target_<recipient_slug>_<brief_id>.html per
    SUBPOENA_TARGETS entry.
  * One subpoena_playbook_<case_id>.html showing the dependency
    graph + recommended sequencing.

Both files are operator-internal legal-process workplans —
NOT auto-sent (chain-of-custody + judicial-authority prerequisites
require manual delivery for the foreseeable future, per the v0.28
design doc).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Filename-character sanitizer: keep alphanumerics + dash + underscore.
_FILENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]")

# v0.28.1 hardening: cap filename component length so we never write
# a path that exceeds platform limits (Windows MAX_PATH = 260 bytes
# including the full path; macOS HFS+ = 255 bytes per component;
# Linux ext4 = 255 bytes per component). 64 chars per component
# leaves headroom for the surrounding case_dir + suffix + .tmp +
# the OS's own overhead. Truncation includes a 16-char hash suffix
# so two long names that share a prefix don't collide silently.
_FILENAME_COMPONENT_MAX = 64


def _safe_filename_component(s: object) -> str:
    """Make `s` filename-safe with platform length cap.

    Empty / non-string → 'unknown'. Long strings (>64 chars after
    sanitization) get truncated with a stable hash suffix so two
    different inputs sharing a prefix don't collide.
    """
    if not isinstance(s, str) or not s.strip():
        return "unknown"
    out = _FILENAME_SANITIZE_RE.sub("-", s.strip())
    out = re.sub(r"-+", "-", out).strip("-_.")
    if not out:
        return "unknown"
    if len(out) > _FILENAME_COMPONENT_MAX:
        # Truncate with a hash suffix for collision resistance.
        # 47-char prefix + "-" + 16-char hex hash = 64 chars total.
        import hashlib
        digest = hashlib.sha256(out.encode("utf-8")).hexdigest()[:16]
        out = f"{out[:47]}-{digest}"
    return out


def _make_brief_id(case: Any) -> str:
    """Derive a stable brief-id from the case. Falls back to the
    case_id directly, sanitized."""
    case_id_raw = getattr(case, "case_id", None) or "case"
    return _safe_filename_component(f"BRIEF-{case_id_raw}")


def render_subpoena_artifacts(
    *,
    case: Any,
    victim: Any | None,
    investigator: Any | None,
    freeze_brief: dict[str, Any],
    case_dir: Path,
) -> list[Path]:
    """Render every subpoena_target_*.html + the playbook, return
    the list of written paths. Empty list when no SUBPOENA_TARGETS
    entries exist (most freezable-only cases).

    Args:
      case:         a Case-like object with .case_id and .chain
      victim:       VictimInfo-like dict / dataclass / None
      investigator: InvestigatorInfo-like / None
      freeze_brief: the freeze_brief.json content (must have
                    SUBPOENA_TARGETS list to produce output)
      case_dir:     the case directory (briefs/ subdir gets the files)

    Returns:
      Sorted list of Path objects pointing at the new HTML files.
    """
    targets = freeze_brief.get("SUBPOENA_TARGETS") or []
    if not isinstance(targets, list):
        log.warning(
            "SUBPOENA_TARGETS is not a list (got %s); skipping render",
            type(targets).__name__,
        )
        return []

    briefs_dir = case_dir / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)

    # Build common Jinja context.
    case_id = str(getattr(case, "case_id", "") or "case")
    brief_id = _make_brief_id(case)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    victim_ctx = _normalize_victim(victim)
    investigator_ctx = _normalize_investigator(investigator)

    written: list[Path] = []

    if not targets:
        # No qualifying targets → no per-target files. Skip the
        # playbook too — an empty playbook would just confuse
        # operators ("why is this here if it has nothing?").
        log.info("no SUBPOENA_TARGETS for case=%s; skipping render", case_id)
        return written

    # Load Jinja env. Reuse the existing project env to inherit any
    # filters / safe_url / autoescape settings the freeze-letter
    # templates rely on.
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        log.error("jinja2 not available; cannot render subpoena artifacts")
        return []

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
        keep_trailing_newline=True,
    )
    # safe_url filter — reuse the same canonical implementation as
    # the freeze-letter templates. Defensive: if the helper isn't
    # available, fall back to a pass-through.
    try:
        from recupero.reports._jinja_filters import safe_url
        env.filters["safe_url"] = safe_url
    except Exception:  # noqa: BLE001
        env.filters["safe_url"] = lambda u: u

    # ── Per-target rendering ──
    try:
        target_template = env.get_template("subpoena_target.html.j2")
    except Exception as exc:  # noqa: BLE001
        log.error("subpoena_target template missing: %s", exc)
        return written

    for t in targets:
        if not isinstance(t, dict):
            log.warning("skipping non-dict SUBPOENA_TARGETS entry: %r", t)
            continue
        recipient_slug = _safe_filename_component(
            t.get("recipient_slug") or t.get("recipient_name") or "unknown"
        )
        filename = f"subpoena_target_{recipient_slug}_{brief_id}.html"
        out_path = briefs_dir / filename
        try:
            html = target_template.render(
                target=t,
                case_id=case_id,
                brief_id=brief_id,
                victim=victim_ctx,
                investigator=investigator_ctx,
                generated_at=generated_at,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "subpoena_target render failed for %s: %s",
                t.get("target_id"), exc,
            )
            continue
        _atomic_write(out_path, html)
        written.append(out_path)
        log.info(
            "wrote subpoena target file=%s target_id=%s recipient=%s",
            filename, t.get("target_id"),
            t.get("recipient_name") or "(unknown)",
        )

    # ── Playbook (one per case) ──
    try:
        playbook_template = env.get_template("subpoena_playbook.html.j2")
    except Exception as exc:  # noqa: BLE001
        log.error("subpoena_playbook template missing: %s", exc)
        return written

    playbook_filename = (
        f"subpoena_playbook_{_safe_filename_component(case_id)}.html"
    )
    playbook_path = briefs_dir / playbook_filename
    try:
        playbook_html = playbook_template.render(
            targets=targets,
            case_id=case_id,
            brief_id=brief_id,
            victim=victim_ctx,
            investigator=investigator_ctx,
            generated_at=generated_at,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("subpoena_playbook render failed: %s", exc)
        return written
    _atomic_write(playbook_path, playbook_html)
    written.append(playbook_path)
    log.info("wrote subpoena playbook file=%s targets=%d",
             playbook_filename, len(targets))

    return sorted(written)


def _atomic_write(path: Path, content: str) -> None:
    """LF-only atomic write so manifest SHAs match disk on Windows."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    tmp.replace(path)


def _normalize_victim(victim: Any) -> dict[str, Any] | None:
    """Convert a VictimInfo dataclass / dict / None into a dict the
    Jinja template can consume safely. None passes through."""
    if victim is None:
        return None
    if isinstance(victim, dict):
        return victim
    # Dataclass / pydantic / generic object — pluck common attrs.
    return {
        "name": getattr(victim, "name", None),
        "wallet_address": getattr(victim, "wallet_address", None),
        "citizenship": getattr(victim, "citizenship", None),
        "email": getattr(victim, "email", None),
    }


def _normalize_investigator(inv: Any) -> dict[str, Any] | None:
    if inv is None:
        return None
    if isinstance(inv, dict):
        return inv
    return {
        "name": getattr(inv, "name", None),
        "email": getattr(inv, "email", None),
        "organization": getattr(inv, "organization", None),
    }


__all__ = (
    "render_subpoena_artifacts",
)
