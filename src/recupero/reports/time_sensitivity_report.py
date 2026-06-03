"""Render the case time-sensitivity / statute-of-limitations advisory.

A standalone HTML deliverable that surfaces (a) the practical freeze-window
clocks we know cold from on-chain timestamps and (b) the jurisdiction's
limitation references with real citations — explicitly framed as legal
INFORMATION to confirm with counsel, never legal advice. Built on
:mod:`recupero.legal.time_sensitivity`.

This renderer is callable on its own (and is unit-tested as such); wiring it
into the auto-pipeline is a separate, deliberate step.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from recupero._common import atomic_write_text, resolve_render_time
from recupero.legal.time_sensitivity import build_time_sensitivity

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_time_sensitivity(
    brief: dict,
    *,
    output_dir: Path,
    as_of: date | None = None,
) -> Path:
    """Render ``legal_time_sensitivity.html`` for the brief into ``output_dir``.

    ``as_of`` pins "now" for deterministic output (defaults to today). Returns
    the path written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = build_time_sensitivity(brief, as_of=as_of)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)
    template = env.get_template("legal_time_sensitivity.html.j2")

    html = template.render(
        ts=ts,
        case_id=ts.case_id,
        generated_at=resolve_render_time().strftime("%Y-%m-%d %H:%M"),
    )
    out_path = output_dir / "legal_time_sensitivity.html"
    atomic_write_text(out_path, html)
    return out_path


__all__ = ("render_time_sensitivity",)
