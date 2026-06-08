"""Bucket brief-generation dedupe (fleet Jacob-sweep remediation).

Re-running building_package writes a fresh BRIEF-<timestamp> generation of every
per-issuer deliverable; pre-cleanup cases accumulated multiple generations in
one bucket folder, which makes the output_integrity validator fire
cross-document-consistency criticals on the disagreeing union. These pin the
pure generation-selection logic + the store dedupe (dry-run by default).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from recupero.storage.supabase_case_store import (
    SupabaseCaseStore,
    latest_brief_generation,
    stale_brief_generation_files,
)

_GEN_A = "BRIEF-20260509T010806"
_GEN_B = "BRIEF-20260510T193125"

_DUAL = [
    f"le_handoff_circle_{_GEN_A}-85947b.html",
    f"le_handoff_circle_{_GEN_B}-34abbc.html",
    f"freeze_request_paxos_{_GEN_A}-dfc920.html",
    f"freeze_request_paxos_{_GEN_B}-db11fd.html",
    f"manifest_{_GEN_A}-1c13c0.json",
    f"manifest_{_GEN_B}-e8eef4.json",
    "trace_report_0daf3b1e.html",   # no BRIEF token → always kept
    "flow_b712aab3.svg",            # no BRIEF token → always kept
    "recovery_snapshot_RCP-X.html",  # no BRIEF token → always kept
]


def test_latest_generation_is_chronological_max() -> None:
    assert latest_brief_generation(_DUAL) == "20260510T193125"
    assert latest_brief_generation([]) is None
    assert latest_brief_generation(["trace_report_x.html"]) is None


def test_stale_files_are_only_older_generation() -> None:
    stale = stale_brief_generation_files(_DUAL)
    # Exactly the three GEN_A files; never the GEN_B (latest) or the
    # non-generation files (trace_report / flow / recovery_snapshot).
    assert stale == sorted([
        f"le_handoff_circle_{_GEN_A}-85947b.html",
        f"freeze_request_paxos_{_GEN_A}-dfc920.html",
        f"manifest_{_GEN_A}-1c13c0.json",
    ])
    assert all(_GEN_B not in s for s in stale)
    assert not any(s.startswith(("trace_report", "flow_", "recovery_snapshot")) for s in stale)


def test_single_generation_is_noop() -> None:
    single = [
        f"le_handoff_circle_{_GEN_B}-34abbc.html",
        f"freeze_request_paxos_{_GEN_B}-db11fd.html",
        "trace_report_x.html",
    ]
    assert stale_brief_generation_files(single) == []
    assert stale_brief_generation_files(["case.json", "flow_a.svg"]) == []
    assert stale_brief_generation_files([]) == []


def _stub_store() -> SupabaseCaseStore:
    s = SupabaseCaseStore.__new__(SupabaseCaseStore)
    s._storage_root = "https://t.supabase.co/storage/v1"
    s._bucket = "investigation-files"
    s._investigation_id = "11111111-1111-1111-1111-111111111111"
    s._client = MagicMock()
    return s


def test_dedupe_dry_run_reports_without_deleting(monkeypatch) -> None:
    store = _stub_store()
    monkeypatch.setattr(store, "list_files", lambda subpath=None: list(_DUAL))
    store._delete_object_paths = MagicMock(return_value=0)
    out = store.dedupe_brief_generations(dry_run=True)
    assert out["latest"] == "20260510T193125"
    assert out["dry_run"] is True
    assert out["deleted"] == 0
    assert len(out["removed"]) == 3
    assert all(r.startswith("briefs/") and _GEN_A in r for r in out["removed"])
    store._delete_object_paths.assert_not_called()  # dry-run never deletes


def test_dedupe_execute_deletes_stale_full_paths(monkeypatch) -> None:
    store = _stub_store()
    monkeypatch.setattr(store, "list_files", lambda subpath=None: list(_DUAL))
    store._delete_object_paths = MagicMock(return_value=3)
    out = store.dedupe_brief_generations(dry_run=False)
    assert out["dry_run"] is False
    assert out["deleted"] == 3
    store._delete_object_paths.assert_called_once()
    passed = store._delete_object_paths.call_args.args[0]
    # Full bucket paths, only the older generation, under this investigation.
    assert len(passed) == 3
    assert all(p.startswith(store.storage_prefix + "briefs/") for p in passed)
    assert all(_GEN_A in p for p in passed)
