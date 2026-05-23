"""Wave-7 adversarial audit: ``recupero.worker.mini_freeze``.

The mini-freeze digest is the dormant-balance/watch-tick deliverable
that ships to operators through the ``watchlist-digest/<date>/`` bucket
prefix. Inputs (``MaterialChange.label_name``, ``MaterialChange.reason``,
``MaterialChange.asset_symbol``, ``MaterialChange.new_usd`` / ``delta_usd``)
flow in from Etherscan tag scrapes, operator notes, and the pricing
layer — all attacker-influenced surfaces.

Threat models exercised:

  1. NaN / Infinity in any of the USD Decimals (``new_usd``,
     ``prior_usd``, ``delta_usd``) reaches ``_fmt_signed_usd`` which
     formats them literally as ``"+NaN"`` or ``"-Infinity"`` into the
     rendered HTML. The digest then ships to operators showing
     nonsensical accounting figures. Defense: reject before render
     (or fall back to ``"—"``).

  2. Bidi-override / NUL / CR / LF bytes in ``label_name`` /
     ``reason`` / ``issuer`` / ``asset_symbol`` reach the template
     un-scrubbed. Jinja autoescape neutralizes ``<script>`` but does
     NOT strip ``U+202E`` — a Trojan-Source-style spoof renders in
     the PDF the operator forwards to compliance. ``safe_text``
     exists for exactly this; it just isn't wired up at the digest
     ``_change_to_ctx`` boundary.

  3. ``digest_id`` is the filesystem stem for both the HTML and the
     summary JSON. It's currently built from ``report.started_at``
     (a datetime) + a uuid4 hex slice. A subclassed / spoofed
     ``started_at`` whose ``strftime`` returns ``"../evil"`` would
     escape the output_dir. Defense-in-depth: normalize the stem
     against a strict ``[A-Z0-9_-]`` allowlist before path-joining.

  4. Empty material-change list — confirm the renderer doesn't
     crash and produces a non-empty HTML body. (Template HAS an
     ``{% if material_count == 0 %}`` branch; this guards against
     a future regression that removes it.)

  5. Jinja Environment must declare ``autoescape`` covering the
     template's actual extension (``.html.j2``). Defense-in-depth
     check on the renderer call site, not the template.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

from recupero.worker.mini_freeze import (
    _change_to_ctx,
    _fmt_signed_usd,
    generate_daily_digest,
)
from recupero.worker.watch_tick import MaterialChange, WatchTickReport


# ---------- helpers ---------- #


def _mk_change(**overrides) -> MaterialChange:
    """Build a minimal MaterialChange; overrides patch any field."""
    base = dict(
        watchlist_id=uuid4(),
        address="0x" + "ab" * 20,
        chain="ethereum",
        role="perpetrator",
        label_name="Honest Label",
        is_freezeable=True,
        issuer="Tether",
        asset_symbol="USDT",
        prior_taken_at=datetime(2026, 5, 20, 12, 0, tzinfo=UTC),
        prior_usd=Decimal("1000.00"),
        prior_tx_count=10,
        new_taken_at=datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
        new_usd=Decimal("500.00"),
        new_tx_count=12,
        delta_usd=Decimal("-500.00"),
        tx_count_delta=2,
        reason="balance dropped 50%",
    )
    base.update(overrides)
    return MaterialChange(**base)


def _mk_report(changes: list[MaterialChange]) -> WatchTickReport:
    return WatchTickReport(
        started_at=datetime(2026, 5, 21, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 21, 0, 1, tzinfo=UTC),
        candidates=len(changes),
        snapshotted=len(changes),
        skipped_cooldown=0,
        skipped_unsupported_chain=0,
        errors=[],
        material_changes=changes,
    )


# ---------- Bug 1: NaN/Inf in USD fields ---------- #


def test_fmt_signed_usd_rejects_nan() -> None:
    """``_fmt_signed_usd(Decimal('NaN'))`` must NOT render the literal
    string ``"NaN"`` (with or without a sign prefix). It should fall
    back to the same em-dash placeholder ``None`` produces.

    Pre-fix: ``f"{abs(Decimal('NaN')):,.2f}"`` → ``"NaN"`` and the
    digest renders ``"-$NaN"`` in the delta column.
    """
    out = _fmt_signed_usd(Decimal("NaN"))
    assert "NaN" not in out, f"NaN leaked into rendered USD: {out!r}"
    assert out == "—"


def test_fmt_signed_usd_rejects_infinity() -> None:
    """Same as above for ``Decimal('Infinity')`` — must collapse to
    the em-dash fallback rather than rendering ``"+Infinity"``."""
    out = _fmt_signed_usd(Decimal("Infinity"))
    assert "Infinity" not in out
    assert "Inf" not in out
    assert out == "—"


# ---------- Bug 2: Bidi / NUL / CRLF in attacker-controlled text ---------- #


def test_change_to_ctx_scrubs_bidi_in_label_name() -> None:
    """Etherscan-scraped tag set is attacker-controllable. A
    ``U+202E`` (RIGHT-TO-LEFT OVERRIDE) in ``label_name`` flips the
    rendered identifier in the operator PDF.

    Post-fix: ``_change_to_ctx`` must run the labels through
    ``safe_text`` (or equivalent stripping) so the resulting context
    dict carries no bidi-override codepoints.
    """
    poisoned = "alice‮gnp.exe"
    ctx = _change_to_ctx(_mk_change(label_name=poisoned))
    assert "‮" not in ctx["label_name"], (
        f"bidi-override leaked into label_name: {ctx['label_name']!r}"
    )


def test_change_to_ctx_scrubs_nul_and_crlf_in_reason() -> None:
    """``reason`` comes from the watch_tick layer's free-form
    materiality message — a future change could thread an
    attacker-controlled token name into it. NUL / CR / LF bytes
    must be stripped before render."""
    poisoned = "balance drop\x00\r\nInjected-Header: yes"
    ctx = _change_to_ctx(_mk_change(reason=poisoned))
    assert "\x00" not in ctx["reason"]
    assert "\r" not in ctx["reason"]
    assert "\n" not in ctx["reason"]


# ---------- Bug 3: digest_id path-traversal hardening ---------- #


def test_generate_daily_digest_writes_under_output_dir(tmp_path: Path) -> None:
    """Defense-in-depth: the HTML and summary paths must live under
    ``output_dir`` — no traversal escape even if some upstream
    component were to plant a ``"../"`` in ``digest_id``.

    The current implementation builds ``digest_id`` from
    ``report.started_at.strftime`` and ``uuid4``; this test asserts
    the invariant that any future change to that construction must
    preserve.
    """
    bundle = generate_daily_digest(
        _mk_report([_mk_change()]),
        output_dir=tmp_path,
        total_watched=10,
    )
    assert tmp_path in bundle.html_path.parents
    assert tmp_path in bundle.summary_path.parents
    # No path separators inside the stem.
    assert "/" not in bundle.digest_id
    assert "\\" not in bundle.digest_id
    assert ".." not in bundle.digest_id


# ---------- Bug 4: empty-digest render does not crash ---------- #


def test_generate_daily_digest_empty_changes(tmp_path: Path) -> None:
    """Zero material changes — common all-clear path. Must produce
    a valid HTML file with non-trivial body content (the template's
    ``material_count == 0`` branch)."""
    bundle = generate_daily_digest(
        _mk_report([]),
        output_dir=tmp_path,
        total_watched=42,
    )
    assert bundle.html_path.exists()
    body = bundle.html_path.read_text(encoding="utf-8")
    assert len(body) > 500, "all-clear digest should still render full letterhead"
    # No accidental "NaN" / "Infinity" / Python repr leakage.
    assert "NaN" not in body
    assert "Infinity" not in body


# ---------- Bug 5: autoescape declaration covers .html.j2 ---------- #


def test_generate_daily_digest_html_autoescapes_xss_in_label(tmp_path: Path) -> None:
    """Defense-in-depth: even with ``safe_text`` scrubbing, the
    Jinja Environment in ``generate_daily_digest`` must declare
    autoescape such that an HTML-meaningful character in
    ``label_name`` is escaped, not literally embedded.
    """
    bundle = generate_daily_digest(
        _mk_report([_mk_change(label_name="<script>alert(1)</script>")]),
        output_dir=tmp_path,
        total_watched=1,
    )
    body = bundle.html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body, (
        "Jinja autoescape is NOT active on this template — XSS payload "
        "rendered verbatim into the digest HTML."
    )
    # Confirm the entity-escaped form IS present.
    assert "&lt;script&gt;" in body or "&amp;lt;script" in body
