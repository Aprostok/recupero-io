"""RIGOR-7 — Production-shape end-to-end test with zero warnings.

Closes pending task #125. Exercises the full production pipeline against
a synthetic V-CFI01-shape case (no real network, no real DB) and asserts:

  1. Zero WARNING-level logs across the entire flow (other than known-
     skipped paths like WeasyPrint).
  2. Zero stderr output (except the same known-skipped paths).
  3. Deliverables land in the expected paths under case_dir/briefs/:
     brief.html (== freeze_request_*.html), freeze_letters (issuer
     letters), evidence (investigator_findings.{csv,json}),
     trace_report.html, recovery_snapshot.html.
  4. Manifest is well-formed and the structural validator passes
     with zero high/critical violations.
  5. Idempotent: running emit_brief + build_all_deliverables twice
     with SOURCE_DATE_EPOCH pinned produces byte-identical output
     for the deterministic artifacts (HTML/JSON/CSV/SVG).
  6. PDF generation is opt-out (RECUPERO_DISABLE_PDF_RENDER=1) and
     the pipeline still ships HTML deliverables.
  7. No NaN / Infinity strings anywhere in any rendered output file.

Marked ``@pytest.mark.slow`` so the gate is opt-in via ``-m slow``.
The full pipeline run is ~3–10s on a developer laptop; budget allows
for re-running twice for the byte-identical idempotency check.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from io import StringIO
from pathlib import Path

import pytest

from recupero.reports.brief import InvestigatorInfo
from recupero.reports.emit_brief import emit_brief
from recupero.reports.victim import VictimInfo
from recupero.validators.output_integrity import validate_case_output
from recupero.worker._deliverables import build_all_deliverables
from tests.test_v_cfi01_full_render import (
    VICTIM,
    _build_editorial,
    _build_freeze_asks_dict,
    _build_issuer_metadata,
    _build_v_cfi01_case,
)

pytestmark = pytest.mark.slow


# ─────────────────────────────────────────────────────────────────────────────
# Known stderr / warning lines that are NOT real findings.
#
# WeasyPrint emits noisy import-time messages on dev machines that lack the
# system libraries (libgobject, libpangocairo). The pipeline already routes
# around them; RECUPERO_DISABLE_PDF_RENDER=1 bypasses the import entirely
# but a stray sub-process can still print. Filter these to keep the test
# robust across developer environments.
# ─────────────────────────────────────────────────────────────────────────────
_ALLOWED_STDERR_PATTERNS = (
    "WeasyPrint",
    "libgobject",
    "libpangocairo",
    "libcairo",
    "cairocffi",
    "DeprecationWarning",  # third-party deprecations not in our control
)

_ALLOWED_WARNING_SUBSTRINGS = (
    "WeasyPrint",
    "libgobject",
    "PDF render skipped",  # info-only, but defensive
)


def _filter_stderr(text: str) -> str:
    """Strip lines that match the allow-list. The remainder is the
    test's effective stderr surface."""
    if not text:
        return ""
    kept: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if any(pat in line for pat in _ALLOWED_STDERR_PATTERNS):
            continue
        kept.append(line)
    return "\n".join(kept)


def _filter_warnings(records: list[logging.LogRecord]) -> list[str]:
    """Return human-readable WARNING/ERROR messages, minus the known
    no-op paths (WeasyPrint, PDF render disable)."""
    out: list[str] = []
    for rec in records:
        if rec.levelno < logging.WARNING:
            continue
        msg = rec.getMessage()
        if any(s in msg for s in _ALLOWED_WARNING_SUBSTRINGS):
            continue
        out.append(f"{rec.name}/{rec.levelname}: {msg}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline driver — runs emit_brief + build_all_deliverables once.
# Returns (case_dir, captured_warnings, captured_stderr).
# ─────────────────────────────────────────────────────────────────────────────


def _run_pipeline_once(
    *,
    tmp_root: Path,
    source_date_epoch: str = "1747785600",  # 2026-05-21 00:00 UTC
) -> tuple[Path, list[str], str]:
    """Build a V-CFI01-shape case dir from synthetic fixtures and run
    the production deliverables pipeline. PDF render is opt-out via
    RECUPERO_DISABLE_PDF_RENDER=1 (assertion #6).

    All env mutation is local: the caller's environment is restored
    on return so pytest's process state stays clean.
    """
    # Snapshot env so we can restore on exit
    prev_env = {
        k: os.environ.get(k)
        for k in (
            "SOURCE_DATE_EPOCH",
            "RECUPERO_DISABLE_PDF_RENDER",
            "RECUPERO_DISABLE_EMAIL",
            "SUPABASE_DB_URL",
        )
    }
    os.environ["SOURCE_DATE_EPOCH"] = source_date_epoch
    os.environ["RECUPERO_DISABLE_PDF_RENDER"] = "1"  # assertion #6
    os.environ["RECUPERO_DISABLE_EMAIL"] = "1"  # no network
    # Remove SUPABASE_DB_URL so the live-status / cooperation lookups
    # short-circuit cleanly without trying to dial a DB.
    os.environ.pop("SUPABASE_DB_URL", None)

    # Capture stderr at the file-descriptor-aware level: we use a
    # StringIO redirector because the worker logging uses logging.*
    # which writes to a stream handler. (capsys is per-test fixture;
    # this internal helper builds its own.)
    captured_stderr = StringIO()
    prev_stderr = sys.stderr
    sys.stderr = captured_stderr

    # Capture warnings on the `recupero` root logger (every worker
    # module logs under recupero.*) so we don't miss any nested module.
    captured_records: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured_records.append(record)

    handler = _ListHandler(level=logging.WARNING)
    recupero_logger = logging.getLogger("recupero")
    recupero_logger.addHandler(handler)
    prev_level = recupero_logger.level
    recupero_logger.setLevel(logging.DEBUG)

    try:
        case = _build_v_cfi01_case()
        editorial = _build_editorial()
        freeze_asks = _build_freeze_asks_dict()
        issuer_metadata = _build_issuer_metadata()

        victim = VictimInfo(
            name="RIGOR-7 E2E Victim",
            wallet_address=VICTIM,
            state="NY",
            country="US",
            email="rigor7@example.com",
        )
        investigator = InvestigatorInfo(
            name="RIGOR-7 Investigator",
            organization="Recupero Forensics Ltd.",
            email="rigor7-investigator@example.com",
        )

        brief = emit_brief(
            case=case,
            victim=victim,
            editorial=editorial,
            freeze_asks=freeze_asks,
            issuer_metadata=issuer_metadata,
        )

        case_dir = Path(tempfile.mkdtemp(prefix="rigor7_e2e_", dir=tmp_root))
        # Persist freeze_brief / freeze_asks so the validator can find them.
        (case_dir / "freeze_brief.json").write_text(
            json.dumps(brief, default=str, sort_keys=True, allow_nan=False),
            encoding="utf-8",
        )
        (case_dir / "freeze_asks.json").write_text(
            json.dumps(freeze_asks, default=str, sort_keys=True, allow_nan=False),
            encoding="utf-8",
        )

        build_all_deliverables(
            case=case,
            victim=victim,
            freeze_brief=brief,
            case_dir=case_dir,
            investigator=investigator,
            skip_freeze_briefs=False,
        )
    finally:
        recupero_logger.removeHandler(handler)
        recupero_logger.setLevel(prev_level)
        sys.stderr = prev_stderr
        # Restore env
        for k, v in prev_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    warnings_text = _filter_warnings(captured_records)
    stderr_text = _filter_stderr(captured_stderr.getvalue())
    return case_dir, warnings_text, stderr_text


# ─────────────────────────────────────────────────────────────────────────────
# Module-scoped fixture: run pipeline TWICE so every assertion shares the
# same expensive runs. The slow marker gates this whole module.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def two_runs(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the production pipeline twice with identical inputs +
    SOURCE_DATE_EPOCH pinned. Returns dict with both case_dirs and
    the merged warnings/stderr from both runs."""
    tmp_root = tmp_path_factory.mktemp("rigor7_e2e_root")
    case_a, warn_a, err_a = _run_pipeline_once(tmp_root=tmp_root)
    case_b, warn_b, err_b = _run_pipeline_once(tmp_root=tmp_root)
    return {
        "case_a": case_a,
        "case_b": case_b,
        "warnings": warn_a + warn_b,
        "stderr": (err_a + "\n" + err_b).strip(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Assertions — one test function per acceptance criterion.
# ─────────────────────────────────────────────────────────────────────────────


def test_e2e_zero_warning_logs(two_runs):
    """#1 — Zero WARNING/ERROR-level logs across the full pipeline,
    minus the known WeasyPrint allow-list. A warning here means a
    silent failure was swallowed (e.g., a generate_briefs crash)."""
    warnings = two_runs["warnings"]
    assert not warnings, (
        f"Pipeline produced {len(warnings)} WARNING/ERROR log(s) — "
        "a stage silently degraded:\n  " + "\n  ".join(warnings)
    )


def test_e2e_zero_stderr_output(two_runs):
    """#2 — Zero stderr output, minus the WeasyPrint allow-list.
    Anything else is a leaked print() or unexpected library warning."""
    stderr = two_runs["stderr"]
    assert not stderr, (
        f"Pipeline produced unexpected stderr output:\n{stderr}"
    )


def test_e2e_expected_deliverables_present(two_runs):
    """#3 — Every expected artifact lands at the expected path.

    The production layout writes everything under ``case_dir/briefs/``:
      * trace_report_<hash>.html        (always)
      * freeze_request_<issuer>_<id>.html  (per freezable issuer — "freeze_letters")
      * le_handoff_<issuer>_<id>.html   (per freezable issuer)
      * victim_summary_<variant>_<hash>.html
      * recovery_snapshot_<hash>.html   (when RECOVERY_ESTIMATE present)
      * investigator_findings.csv + .json  (== "evidence")
      * manifest_<id>.json
      * flow_<hash>.svg
    """
    case_dir = two_runs["case_a"]
    briefs = case_dir / "briefs"
    assert briefs.is_dir(), f"briefs/ subdir missing under {case_dir}"

    # Brief HTMLs (one per freezable issuer — these are the "brief.html" +
    # "freeze_letters" artifacts in the task description)
    freeze_letters = sorted(briefs.glob("freeze_request_*.html"))
    assert len(freeze_letters) == 4, (
        f"Expected 4 freeze request letters (Midas, Coinbase, Tether, "
        f"Circle), got {len(freeze_letters)}: "
        f"{[p.name for p in freeze_letters]}"
    )

    # LE handoffs (one per issuer)
    le_handoffs = sorted(briefs.glob("le_handoff_*.html"))
    assert len(le_handoffs) == 4, (
        f"Expected 4 LE handoff HTMLs, got {len(le_handoffs)}: "
        f"{[p.name for p in le_handoffs]}"
    )

    # Trace report (always)
    trace_reports = sorted(briefs.glob("trace_report_*.html"))
    assert trace_reports, "trace_report_*.html missing"

    # Recovery snapshot (V-CFI01 has RECOVERY_ESTIMATE populated)
    snapshots = sorted(briefs.glob("recovery_snapshot_*.html"))
    assert snapshots, (
        "recovery_snapshot_*.html missing — V-CFI01 carries a "
        "RECOVERY_ESTIMATE so the pre-engagement snapshot must ship."
    )

    # Evidence (investigator exports)
    csv_path = briefs / "investigator_findings.csv"
    json_path = briefs / "investigator_findings.json"
    assert csv_path.is_file(), "investigator_findings.csv missing"
    assert json_path.is_file(), "investigator_findings.json missing"

    # Manifest
    manifests = sorted(briefs.glob("manifest_*.json"))
    assert manifests, "manifest_*.json missing"


def test_e2e_validator_zero_violations(two_runs):
    """#4 — Manifest well-formed + structural validator passes with
    zero critical/high violations.

    Runs the production output-integrity validator (27 invariants per
    Jacob's Part 5 audit) over the synthetic case_dir. Any violation
    here indicates a production-shape regression."""
    case_dir = two_runs["case_a"]
    result = validate_case_output(case_dir)
    hard_violations = [
        v for v in result.violations
        if v.severity in ("critical", "high")
    ]
    assert not hard_violations, (
        f"Structural validator failed with {len(hard_violations)} "
        f"critical/high violation(s):\n{result.summary_text()}"
    )


def _hash_text_file(path: Path) -> str:
    """SHA-256 over file bytes — used for byte-identical comparison."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalize_brief_filename(name: str) -> str:
    """Brief-id suffix changes between runs ONLY when content differs.
    Two runs of the same case with SOURCE_DATE_EPOCH pinned MUST emit
    the same brief-id, so we don't normalize this — we use raw name
    equality. The normalizer exists to surface failures more clearly:
    if filenames differ at all, that's itself a determinism failure."""
    return name


def test_e2e_idempotent_byte_identical(two_runs):
    """#5 — Two pipeline runs with SOURCE_DATE_EPOCH pinned produce
    byte-identical HTML/JSON/CSV/SVG output.

    PDFs are excluded by design — they are disabled (#6) so the test
    is comparing only deterministic-by-construction text artifacts.
    The freeze_letters carry both timestamp and brief-id, but
    SOURCE_DATE_EPOCH pins the timestamp, and the brief-id is a
    content hash that must be identical when content matches."""
    case_a = two_runs["case_a"]
    case_b = two_runs["case_b"]

    def _enumerate(d: Path) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for p in sorted((d / "briefs").rglob("*")):
            if not p.is_file():
                continue
            # Skip PDFs (already opt-out) and any .log scratch files.
            if p.suffix in (".pdf", ".log"):
                continue
            out[p.name] = p
        return out

    files_a = _enumerate(case_a)
    files_b = _enumerate(case_b)

    # Same set of filenames means same brief-id hashes — itself an
    # idempotency assertion (content-addressable naming round-trips).
    missing_in_b = set(files_a) - set(files_b)
    missing_in_a = set(files_b) - set(files_a)
    assert not missing_in_b, (
        f"Run A produced files run B did not: {sorted(missing_in_b)}"
    )
    assert not missing_in_a, (
        f"Run B produced files run A did not: {sorted(missing_in_a)}"
    )

    # Byte-identical content check
    divergent: list[str] = []
    for name in sorted(files_a):
        if _hash_text_file(files_a[name]) != _hash_text_file(files_b[name]):
            divergent.append(name)

    assert not divergent, (
        "SOURCE_DATE_EPOCH is pinned but these files diverge across "
        f"two runs ({len(divergent)} file(s)): {divergent[:8]}. "
        "There is a non-deterministic write path — usually an unsorted "
        "dict iteration, a UUID4 in a filename, or an unpinned now() call."
    )


def test_e2e_pdf_optout_still_ships_html(two_runs):
    """#6 — With RECUPERO_DISABLE_PDF_RENDER=1, no PDFs are written
    but every HTML deliverable is still present.

    The pipeline runs with RECUPERO_DISABLE_PDF_RENDER=1 in
    _run_pipeline_once; the HTML coverage is already asserted by
    test_e2e_expected_deliverables_present. This test additionally
    confirms the opt-out is honored — zero .pdf files on disk."""
    case_dir = two_runs["case_a"]
    pdfs = list((case_dir / "briefs").rglob("*.pdf"))
    assert not pdfs, (
        f"RECUPERO_DISABLE_PDF_RENDER=1 but found {len(pdfs)} PDF(s): "
        f"{[p.name for p in pdfs]}"
    )

    # And HTML deliverables ARE present (sanity — should never trip
    # if test_e2e_expected_deliverables_present passes, but kept as
    # an explicit assertion for the #6 contract).
    htmls = list((case_dir / "briefs").rglob("*.html"))
    assert htmls, "PDF opt-out should not affect HTML emission"


# Regex matches NaN / Infinity as JSON-illegal numeric literals or as
# stringified Python repr. We anchor with word boundaries so legitimate
# text like "Infinitesimal" or "manhattan" isn't a false positive.
_NAN_INF_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:NaN|nan|Infinity|infinity|-Infinity|-infinity)(?![A-Za-z])"
)


def test_e2e_no_nan_infinity_in_output(two_runs):
    """#7 — No NaN / Infinity strings anywhere in any rendered output
    file. JSON does not support these literals; their presence almost
    always indicates an unguarded Decimal('NaN') / float('inf')
    leaking from a price-feed cache or a 0/0 computation."""
    case_dir = two_runs["case_a"]
    offenders: list[tuple[str, str]] = []
    text_exts = (".html", ".json", ".csv", ".svg")
    for p in sorted((case_dir / "briefs").rglob("*")):
        if not p.is_file() or p.suffix not in text_exts:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for m in _NAN_INF_PATTERN.finditer(text):
            # Capture a small window for actionable error messages
            lo = max(0, m.start() - 30)
            hi = min(len(text), m.end() + 30)
            offenders.append((p.name, text[lo:hi]))
            break  # one offender per file is sufficient

    # Also assert freeze_brief.json + freeze_asks.json at the case root
    for fname in ("freeze_brief.json", "freeze_asks.json"):
        fpath = case_dir / fname
        if fpath.is_file():
            text = fpath.read_text(encoding="utf-8")
            for m in _NAN_INF_PATTERN.finditer(text):
                lo = max(0, m.start() - 30)
                hi = min(len(text), m.end() + 30)
                offenders.append((fname, text[lo:hi]))
                break

    assert not offenders, (
        f"NaN/Infinity leaked into {len(offenders)} output file(s):\n"
        + "\n".join(f"  {fname}: ...{ctx}..." for fname, ctx in offenders[:6])
    )
