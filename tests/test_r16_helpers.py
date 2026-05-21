"""Unit tests for helpers added/fixed in Round-16 audit (v0.20.12).

Coverage:
  * _svg_to_pdf()                 — atomic tmp+rename+cleanup contract
  * _ai_destination_dust_threshold() — honours RECUPERO_DESTINATION_DUST_USD env var
"""

from __future__ import annotations

import os
import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

# ─────────────────────────────────────────────────────────────────────────────
# _svg_to_pdf — atomic rename + cleanup contract  (R16-C MEDIUM)
# ─────────────────────────────────────────────────────────────────────────────

_MINIMAL_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    "<rect width='100' height='100' fill='#ccc'/>"
    "</svg>"
)


def test_svg_to_pdf_success_writes_final_pdf():
    """_svg_to_pdf must write the final PDF and not leave a .tmp sibling.

    The function renders to a .pdf.tmp path via _render_pdf_in_subprocess,
    then os.replace() renames it to the final path. On success the .tmp
    file must be gone and the final PDF must exist.
    """
    from recupero.worker._deliverables import _svg_to_pdf

    with tempfile.TemporaryDirectory(prefix="svg_pdf_test_") as tmpdir:
        svg_path = Path(tmpdir) / "flow.svg"
        svg_path.write_text(_MINIMAL_SVG, encoding="utf-8")
        pdf_path = Path(tmpdir) / "flow.pdf"
        tmp_pdf_path = pdf_path.with_suffix(pdf_path.suffix + ".tmp")

        def _fake_render(*, script: str, args: list[str], label: str) -> None:
            # Simulate a successful render: write a fake PDF to the tmp path.
            Path(args[1]).write_bytes(b"%PDF-1.4 (fake)")

        with patch(
            "recupero.worker._deliverables._render_pdf_in_subprocess",
            side_effect=_fake_render,
        ):
            _svg_to_pdf(svg_path, pdf_path)

        assert pdf_path.exists(), "Final PDF not written after successful _render_pdf_in_subprocess"
        assert not tmp_pdf_path.exists(), (
            ".pdf.tmp sibling was NOT cleaned up after os.replace() — "
            "atomic rename contract broken"
        )


def test_svg_to_pdf_failure_cleans_up_tmp():
    """_svg_to_pdf must remove the .pdf.tmp file even when _render_pdf_in_subprocess raises.

    The finally block must always clean up the tmp file so a crashed render
    cannot leave a truncated / half-written artifact on disk that looks like
    a valid PDF to subsequent file-glob operations.
    """
    from recupero.worker._deliverables import _svg_to_pdf

    with tempfile.TemporaryDirectory(prefix="svg_pdf_fail_") as tmpdir:
        svg_path = Path(tmpdir) / "flow.svg"
        svg_path.write_text(_MINIMAL_SVG, encoding="utf-8")
        pdf_path = Path(tmpdir) / "flow.pdf"
        tmp_pdf_path = pdf_path.with_suffix(pdf_path.suffix + ".tmp")

        def _failing_render(*, script: str, args: list[str], label: str) -> None:
            # Simulate a partial render: write some bytes then raise.
            Path(args[1]).write_bytes(b"%PDF (truncated)")
            raise RuntimeError("Simulated render crash")

        with patch(
            "recupero.worker._deliverables._render_pdf_in_subprocess",
            side_effect=_failing_render,
        ):
            try:
                _svg_to_pdf(svg_path, pdf_path)
            except RuntimeError:
                pass  # expected

        assert not tmp_pdf_path.exists(), (
            ".pdf.tmp was NOT cleaned up after _render_pdf_in_subprocess raised — "
            "truncated artifact left on disk"
        )
        assert not pdf_path.exists(), (
            "Final PDF must NOT exist when the render failed"
        )


def test_svg_to_pdf_cleans_html_shell():
    """_svg_to_pdf must always delete its temporary HTML shell file.

    The shell is written before the subprocess call and must be cleaned
    up in the finally block even when the subprocess fails.
    """
    import glob

    from recupero.worker._deliverables import _svg_to_pdf

    with tempfile.TemporaryDirectory(prefix="svg_pdf_shell_") as tmpdir:
        svg_path = Path(tmpdir) / "flow.svg"
        svg_path.write_text(_MINIMAL_SVG, encoding="utf-8")
        pdf_path = Path(tmpdir) / "flow.pdf"

        def _fake_render(*, script: str, args: list[str], label: str) -> None:
            Path(args[1]).write_bytes(b"%PDF-1.4 (fake)")

        with patch(
            "recupero.worker._deliverables._render_pdf_in_subprocess",
            side_effect=_fake_render,
        ):
            _svg_to_pdf(svg_path, pdf_path)

        # No .html tmp file should remain in the directory
        leftover_html = glob.glob(str(Path(tmpdir) / "*.html"))
        assert not leftover_html, (
            f"HTML shell file(s) not cleaned up: {leftover_html}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# _ai_destination_dust_threshold — env-var contract  (R16-C MEDIUM)
# ─────────────────────────────────────────────────────────────────────────────

def test_ai_dust_threshold_honours_env_var():
    """_ai_destination_dust_threshold must return the env-var value when set.

    R16-C MEDIUM: if the function ignores the env var (e.g. a hardcoded
    constant left over from the pre-v0.20.11 code), the AI editorial stage
    would use a different threshold than the rest of the pipeline, causing
    destinations visible in the trace report to be absent from the AI
    narrative and vice versa.
    """
    from recupero.reports.ai_editorial import _ai_destination_dust_threshold

    with patch.dict(os.environ, {"RECUPERO_DESTINATION_DUST_USD": "500"}):
        threshold = _ai_destination_dust_threshold()

    assert threshold == Decimal("500"), (
        f"Expected Decimal('500') when env var is '500', got {threshold!r}. "
        "ai_editorial._ai_destination_dust_threshold may be using a hardcoded value."
    )


def test_ai_dust_threshold_default_when_unset():
    """_ai_destination_dust_threshold must return a positive default when env var absent.

    The exact default is $1,000 but the important contract is that it's
    a positive finite Decimal — not zero, not None, not a string.
    """
    from recupero.reports.ai_editorial import _ai_destination_dust_threshold

    env_without_dust = {k: v for k, v in os.environ.items()
                        if k != "RECUPERO_DESTINATION_DUST_USD"}
    with patch.dict(os.environ, env_without_dust, clear=True):
        threshold = _ai_destination_dust_threshold()

    assert isinstance(threshold, Decimal), (
        f"Expected Decimal, got {type(threshold).__name__}"
    )
    assert threshold > 0, f"Default dust threshold must be positive, got {threshold!r}"
    assert threshold.is_finite(), f"Default dust threshold must be finite, got {threshold!r}"


def test_ai_dust_threshold_matches_emit_brief_threshold():
    """Both pipelines must use the same dust threshold for the same env var.

    _ai_destination_dust_threshold() delegates to _parse_dust_threshold()
    from emit_brief. They must agree or destination lists diverge between
    the trace report and the AI narrative.
    """
    from recupero.reports.ai_editorial import _ai_destination_dust_threshold
    from recupero.reports.emit_brief import _parse_dust_threshold

    with patch.dict(os.environ, {"RECUPERO_DESTINATION_DUST_USD": "750"}):
        ai_threshold = _ai_destination_dust_threshold()
        emit_threshold = _parse_dust_threshold()

    assert ai_threshold == emit_threshold, (
        f"ai_editorial threshold ({ai_threshold!r}) != emit_brief threshold "
        f"({emit_threshold!r}) for RECUPERO_DESTINATION_DUST_USD=750. "
        "The two pipelines have diverged."
    )
