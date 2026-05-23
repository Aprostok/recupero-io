"""Aggregated cluster handoff renderer (v0.23.0).

Renders ``cluster_handoff.html.j2`` — one document covering EVERY
victim in a multi-victim cluster. Generated on demand via
``recupero-ops render-cluster <public_id>``.

This is the law-firm-market unlock: when a single perpetrator hits
N victims and a coordinating attorney has all N cases, the
aggregated handoff is the document they hand to the AUSA / DOJ
section chief that says "you have one filing decision to make, not
N".

Inputs:
  * public_id   — the cluster's CL-XXXXXX identifier
  * dsn         — Supabase DSN; the renderer reads case_clusters +
                  case_cluster_members directly

Outputs:
  * cluster_handoff_<public_id>.html written to the provided
    output_dir (operator-supplied, defaults to ``cluster-handoffs/``
    next to the case dir)

Failure mode: returns None when the cluster doesn't exist OR the
template render fails. Never raises so the ops CLI can produce a
clean error message.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from recupero._common import atomic_write_text

log = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_cluster_handoff(
    public_id: str,
    *,
    output_dir: Path,
    dsn: str | None,
) -> Path | None:
    """Render the aggregated cluster handoff for ``public_id`` into
    ``output_dir`` and return the path.

    Returns None when:
      * dsn is unset
      * the cluster doesn't exist
      * the render fails

    Operator-facing CLI surface: ``recupero-ops render-cluster``.
    """
    if not dsn:
        log.warning("render_cluster_handoff: no DSN configured")
        return None

    from recupero.monitoring.cluster_builder import fetch_cluster_summary
    cluster = fetch_cluster_summary(public_id, dsn=dsn)
    if not cluster:
        log.warning(
            "render_cluster_handoff: cluster %s not found", public_id,
        )
        return None

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        # StrictUndefined: a missing template variable is loud at
        # render time, not silently rendered as empty.
        undefined=StrictUndefined,
    )
    # XSS defense-in-depth (safe_url / safe_text on href interpolations).
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)

    # Computed display fields the template expects.
    # Z7: non-finite (NaN / Infinity) total_loss_usd from an upstream
    # aggregator glitch must NOT render as ``$NaN`` / ``$Infinity`` in
    # the LE-facing aggregated handoff. Clamp to $0.00 with the same
    # contract as ``_pricing.fmt_usd``.
    total_loss = cluster.get("total_loss_usd") or 0
    from decimal import Decimal
    try:
        d = Decimal(str(total_loss))
    except Exception:  # noqa: BLE001
        d = Decimal(0)
    if not d.is_finite():
        d = Decimal(0)
    cluster["total_loss_usd"] = d
    cluster["total_loss_usd_human"] = f"${d:,.2f}"

    try:
        from recupero import __version__ as software_version
    except Exception:  # noqa: BLE001
        software_version = "0.23.x"

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    try:
        html = env.get_template("cluster_handoff.html.j2").render(
            cluster=cluster,
            generated_at=generated_at,
            software_version=software_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_cluster_handoff: render failed for %s: %s",
            public_id, exc,
        )
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in public_id)
    out_path = output_dir / f"cluster_handoff_{safe_id}.html"
    atomic_write_text(out_path, html)
    return out_path


__all__ = ("render_cluster_handoff",)
