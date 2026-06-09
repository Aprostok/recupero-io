"""Alert → auto-draft → human-gate freeze loop (roadmap-to-#1 v3 item #3).

``recovery_alerts`` raises a ``freezable_inflow`` / ``freezable_outflow`` alert
when freezable funds arrive at / leave a known address — but historically that
was an advisory *text* line; nothing turned it into a ready-to-approve freeze
request. For stablecoin theft (minutes-to-cash-out) the time-to-freeze gap is
the difference between recovery and loss.

This module converts a freeze-actionable :class:`RecoveryAlert` into a
``FreezeDraft`` (the pre-filled content a human approves) and enqueues it into
the EXISTING human-review queue (``brief_reviews`` via
``dispatcher.review_gate.create_review_row``) in status ``awaiting_review``.

INVARIANT (never auto-send): a draft is ONLY ever queued for human approval —
it is never dispatched automatically. The dispatcher's review gate already
blocks send until a human approves; this just pre-stages the artifact so the
approve-to-send step is one click instead of a from-scratch draft.

The converter + renderer are pure (unit-tested without a DB); the enqueue is
best-effort and DSN/None-safe.
"""

from __future__ import annotations

import html
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Only these alert kinds are freeze-actionable (a known/freezable address with
# funds in motion). Others (tracked_outflow, dormant_reactivation) are re-trace
# prompts, not freeze asks.
_FREEZE_ACTIONABLE_KINDS = frozenset({"freezable_inflow", "freezable_outflow"})

_DRAFT_STATUS = "awaiting_review"


@dataclass(frozen=True)
class FreezeDraft:
    """A pre-filled, human-approval-pending freeze request derived from a
    recovery alert. ``status`` is always ``awaiting_review`` — never sent
    without a human approving it in the review gate."""
    investigation_id: str
    address: str
    chain: str
    kind: str
    delta_usd: str
    role: str
    label_name: str | None
    body: str
    status: str = _DRAFT_STATUS


def draft_freeze_from_alert(alert: Any) -> FreezeDraft | None:
    """Convert a freeze-actionable alert into a :class:`FreezeDraft`, or
    ``None`` when the alert isn't freeze-actionable or has no originating case
    (we can't queue a review row without a case to attach it to). Pure."""
    kind = getattr(alert, "kind", "") or ""
    if kind not in _FREEZE_ACTIONABLE_KINDS:
        return None
    inv = getattr(alert, "investigation_id", None)
    if not inv:
        return None
    address = str(getattr(alert, "address", "") or "")
    chain = str(getattr(alert, "chain", "") or "")
    delta_usd = str(getattr(alert, "delta_usd", "") or "")
    role = str(getattr(alert, "role", "") or "")
    label_name = getattr(alert, "label_name", None)
    body = render_freeze_draft_body(
        investigation_id=str(inv), address=address, chain=chain,
        kind=kind, delta_usd=delta_usd, role=role, label_name=label_name,
    )
    return FreezeDraft(
        investigation_id=str(inv), address=address, chain=chain, kind=kind,
        delta_usd=delta_usd, role=role, label_name=label_name, body=body,
    )


def render_freeze_draft_body(
    *,
    investigation_id: str,
    address: str,
    chain: str,
    kind: str,
    delta_usd: str,
    role: str,
    label_name: str | None,
) -> str:
    """Render the draft as a self-contained HTML fragment. Every interpolated
    value is HTML-escaped (an on-chain address/label is attacker-influenced)."""
    e = html.escape
    direction = (
        "arrived at (freeze opportunity)" if kind == "freezable_inflow"
        else "is LEAVING (freeze before it moves on)"
    )
    lbl = f" ({e(label_name)})" if label_name else ""
    return (
        "<section class=\"freeze-draft\">"
        "<h2>DRAFT freeze request — AWAITING HUMAN APPROVAL</h2>"
        "<p><strong>This is an auto-generated DRAFT. It is NOT sent until a "
        "human reviews and approves it in the review gate.</strong></p>"
        f"<dl>"
        f"<dt>Case</dt><dd>{e(investigation_id)}</dd>"
        f"<dt>Address</dt><dd>{e(address)}{lbl}</dd>"
        f"<dt>Chain</dt><dd>{e(chain)}</dd>"
        f"<dt>Trigger</dt><dd>Freezable funds {direction} — {e(delta_usd)} "
        f"(watch role: {e(role)})</dd>"
        f"</dl>"
        "<p>Recommended action: confirm the on-chain movement, then approve "
        "this draft to file a freeze request with the relevant issuer / "
        "exchange via the verified freeze-contact channel.</p>"
        "</section>"
    )


def _safe_addr_segment(address: str) -> str:
    """A short, filesystem-safe slug of the address for the artifact name."""
    keep = "".join(c for c in (address or "") if c.isalnum())
    return (keep[:16] or "addr").lower()


def enqueue_freeze_drafts(
    alerts: Iterable[Any],
    *,
    out_dir: Path,
    dsn: str | None = None,
) -> list[Path]:
    """For each freeze-actionable alert, write a draft artifact under
    ``out_dir`` (named ``freeze_request_draft_*.html`` so it routes to the
    ``freeze_request`` review kind) and best-effort enqueue a ``brief_reviews``
    row in ``awaiting_review`` for the alert's case.

    Returns the list of artifact paths written. Best-effort throughout: a draft
    is written even if the DB enqueue is skipped (no DSN) or fails — the file is
    the artifact a human reviews. Never raises into the caller (the watch tick).
    """
    written: list[Path] = []
    try:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("freeze-draft: could not create out_dir %s: %s", out_dir, exc)
        return written

    for alert in alerts or []:
        draft = draft_freeze_from_alert(alert)
        if draft is None:
            continue
        fname = f"freeze_request_draft_{_safe_addr_segment(draft.address)}_{draft.kind}.html"
        path = out_dir / fname
        try:
            path.write_text(draft.body, encoding="utf-8")
        except OSError as exc:
            log.warning("freeze-draft: write failed for %s: %s", path, exc)
            continue
        written.append(path)
        # Best-effort enqueue into the human-review queue (never auto-send).
        try:
            from recupero.dispatcher.review_gate import create_review_row
            create_review_row(
                case_id=draft.investigation_id,
                artifact_kind="freeze_request",
                artifact_path=path,
                dsn=dsn,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "freeze-draft: review-row enqueue skipped for case=%s: %s",
                draft.investigation_id, exc,
            )
    if written:
        log.info("freeze-draft: drafted %d freeze request(s) for human review", len(written))
    return written


__all__ = (
    "FreezeDraft",
    "draft_freeze_from_alert",
    "render_freeze_draft_body",
    "enqueue_freeze_drafts",
)
