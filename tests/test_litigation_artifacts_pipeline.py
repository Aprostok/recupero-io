"""TRACK 3 P0a — litigation-grade artifacts wired into the deliverables pipeline.

Before this change the court-exhibit pack (`render_exhibit_pack`) and the signed
Ed25519 chain-of-custody (`custody.create_attestation` + `append_to_chain`)
existed ONLY as manual `recupero-ops` commands — so a real case never shipped
them unless an operator ran them by hand (the pipeline wrote only an UNSIGNED
SHA-256 manifest). `build_all_deliverables` now emits both. As of v0.39
(Activation Sprint #7) the litigation pack is DEFAULT-ON; opt OUT with
`RECUPERO_AUTO_LITIGATION_ARTIFACTS=0` (fixture / golden / byte-identical
determinism runs). The signed chain is produced only when a custody key is
configured.

These tests pin:
  * ON by default — exhibit_pack/ + SAR draft appear with no knob set.
  * OFF when explicitly opted out (=0) — no litigation dirs appear.
  * ON + key configured — exhibit pack HTML renders AND a signed custody chain
    is appended that VERIFIES (zero critical findings).
  * ON + no key — exhibit pack still renders, custody signing is skipped
    cleanly (no crash, no custody/ dir).

Runs in a tempdir; no DB, no network. PDF render disabled for speed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from recupero.custody import chain as custody
from recupero.models import Case, Chain
from recupero.reports.victim import VictimInfo
from recupero.worker._deliverables import build_all_deliverables

_FREEZE_BRIEF: dict = {"FREEZABLE": [], "DESTINATIONS": []}


def _make_case() -> Case:
    return Case(
        case_id="LITIG-TEST-01",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2024, 1, 1, tzinfo=UTC),
        transfers=[],
        exchange_endpoints=[],
        unlabeled_counterparties=[],
        software_version="test",
        trace_started_at=datetime(2024, 1, 1, tzinfo=UTC),
        trace_completed_at=datetime(2024, 1, 1, tzinfo=UTC),
    )


def _victim() -> VictimInfo:
    return VictimInfo(name="Litigation test", wallet_address="0x" + "a" * 40)


def _run(case_dir: Path) -> list[Path]:
    return build_all_deliverables(
        case=_make_case(),
        victim=_victim(),
        freeze_brief=_FREEZE_BRIEF,
        case_dir=case_dir,
        skip_freeze_briefs=True,
        investigation_id="litig-inv-1",
    )


def test_litigation_artifacts_on_by_default(tmp_path, monkeypatch) -> None:
    """v0.39 (#7): no knob → litigation pack ships by DEFAULT (exhibit pack +
    SAR draft present). The signed custody chain still needs a key, so absent a
    configured key there is no custody/ dir — but the document artifacts render."""
    monkeypatch.delenv("RECUPERO_AUTO_LITIGATION_ARTIFACTS", raising=False)
    # Pin the custody key to a non-existent path so we never pick up a real
    # ~/.recupero/custody_key on the dev box (custody signing then skips).
    monkeypatch.setenv("RECUPERO_CUSTODY_KEY_PATH", str(tmp_path / "no_such_key"))
    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    written = _run(case_dir)

    assert written, "pipeline should emit its primary deliverables"
    assert (case_dir / "exhibit_pack" / "exhibit_pack.html").exists(), (
        "exhibit pack must ship by default as of v0.39 #7"
    )
    assert (case_dir / "regulatory_filing" / "us_fincen_sar.html").exists(), (
        "SAR/STR draft must ship by default as of v0.39 #7"
    )
    # No custody key configured → signing skipped cleanly (no custody/ dir).
    assert not (case_dir / "custody").exists(), (
        "custody chain needs a configured signing key; absent one it skips"
    )


def test_litigation_artifacts_opt_out_with_zero(tmp_path, monkeypatch) -> None:
    """Explicit opt-out (=0) → pipeline behavior is minimal: no litigation dirs.
    This is the fixture/golden/determinism escape hatch."""
    monkeypatch.setenv("RECUPERO_AUTO_LITIGATION_ARTIFACTS", "0")
    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    written = _run(case_dir)

    assert written, "pipeline should still emit its primary deliverables"
    assert not (case_dir / "exhibit_pack").exists(), (
        "exhibit pack must NOT be produced when opted out (=0)"
    )
    assert not (case_dir / "custody").exists(), (
        "custody chain must NOT be produced when opted out (=0)"
    )
    assert not (case_dir / "regulatory_filing").exists(), (
        "SAR/STR draft must NOT be produced when opted out (=0)"
    )
    assert not (case_dir / "legal_requests").exists(), (
        "MLAT/314b drafts must NOT be produced when opted out (=0)"
    )


def test_litigation_artifacts_emitted_and_chain_verifies(tmp_path, monkeypatch) -> None:
    """Knob ON + custody key configured → exhibit pack rendered AND a signed
    chain-of-custody appended that passes verification."""
    key_path = tmp_path / "custody_key"
    custody.generate_keypair(output_path=key_path)
    monkeypatch.setenv("RECUPERO_CUSTODY_KEY_PATH", str(key_path))
    monkeypatch.setenv("RECUPERO_AUTO_LITIGATION_ARTIFACTS", "1")
    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    written = _run(case_dir)

    # (1) Exhibit pack rendered (renders gracefully even on a sparse case dir).
    pack = case_dir / "exhibit_pack" / "exhibit_pack.html"
    assert pack.exists(), f"exhibit pack not produced; written={[p.name for p in written]}"
    assert pack.stat().st_size > 0
    assert pack in written

    # (1b) SAR/STR draft rendered (US FinCEN baseline; renders even on a
    # sparse brief). MLAT/314b produce no files here (no exchanges in brief).
    sar = case_dir / "regulatory_filing" / "us_fincen_sar.html"
    assert sar.exists(), f"SAR/STR draft not produced; written={[p.name for p in written]}"
    assert sar.stat().st_size > 0
    assert sar in written

    # (2) Signed chain-of-custody appended.
    chain_file = case_dir / "custody" / "chain.jsonl"
    assert chain_file.exists(), "custody chain.jsonl not written"
    entries = custody.load_chain(case_dir)
    assert len(entries) == 1, f"expected exactly one attestation entry, got {len(entries)}"
    assert entries[0].stage == "deliverables_built"
    assert entries[0].artifacts, "attestation must cover at least one artifact"
    attested = {a.relative_path for a in entries[0].artifacts}
    assert "regulatory_filing/us_fincen_sar.html" in attested, (
        f"the SAR draft must be covered by the custody chain; "
        f"attested={sorted(attested)}"
    )

    # (3) The chain verifies end-to-end (signature + prev-hash + artifact hashes).
    report = custody.verify_chain(case_dir)
    assert report.ok, f"custody chain failed verification: {[f.message for f in report.findings]}"
    assert report.entries_checked == 1


def test_litigation_no_key_renders_pack_but_skips_custody(tmp_path, monkeypatch) -> None:
    """Knob ON but NO custody key → exhibit pack still renders; custody signing
    is skipped cleanly (no crash, no custody/ dir). Points the key path at a
    non-existent file so we never fall back to a real ~/.recupero key."""
    monkeypatch.setenv("RECUPERO_CUSTODY_KEY_PATH", str(tmp_path / "absent_key"))
    monkeypatch.setenv("RECUPERO_AUTO_LITIGATION_ARTIFACTS", "1")
    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    case_dir.mkdir()

    written = _run(case_dir)  # must not raise

    assert (case_dir / "exhibit_pack" / "exhibit_pack.html").exists(), (
        "exhibit pack needs no key and must still render"
    )
    assert (case_dir / "regulatory_filing" / "us_fincen_sar.html").exists(), (
        "SAR/STR draft needs no key and must still render"
    )
    assert not (case_dir / "custody").exists(), (
        "custody signing must be skipped when no key is configured"
    )
    assert written
