"""v0.39 — the freeze follow-up + refresh-priors loop must run from the MANAGED
cron scheduler, not depend on an external `recupero-worker --freeze-followups`
cron being configured (a silent single-point-of-failure for the recovery loop).

Pins: both jobs are registered in the default job set; both skip cleanly when no
DSN is configured (best-effort, never raise into the HA wrapper); and the wrapper
delegates to the real cron entrypoints when a DSN is present.
"""

from __future__ import annotations

from recupero.worker import cron_scheduler as cs


def test_freeze_followup_and_priors_are_registered() -> None:
    names = {j.name for j in cs._build_default_jobs()}
    assert "freeze_followup" in names
    assert "refresh_priors" in names
    # every job still has a callable schedule_fn + run_fn (HA-wrapper contract)
    for j in cs._build_default_jobs():
        assert callable(j.schedule_fn) and callable(j.run_fn)


def test_jobs_skip_cleanly_without_dsn(monkeypatch) -> None:
    monkeypatch.setattr(cs, "_supabase_dsn", lambda: "")
    # Neither may raise — a DSN-less env must not crash the scheduler tick.
    cs._job_freeze_followup()
    cs._job_refresh_priors()


def test_freeze_followup_delegates_when_dsn_present(monkeypatch) -> None:
    monkeypatch.setattr(cs, "_supabase_dsn", lambda: "postgresql://u:p@h/db")
    from recupero.worker import _freeze_followup as ff

    seen = {}

    def _fake_cron(dsn: str):
        seen["dsn"] = dsn
        return ff.FreezeFollowupResult(candidates_found=3, sent_ok=2)

    monkeypatch.setattr(ff, "run_freeze_followup_cron", _fake_cron)
    cs._job_freeze_followup()
    assert seen["dsn"] == "postgresql://u:p@h/db"


def test_refresh_priors_delegates_when_dsn_present(monkeypatch) -> None:
    monkeypatch.setattr(cs, "_supabase_dsn", lambda: "postgresql://u:p@h/db")
    from recupero.freeze_learning import recorder

    seen = {}

    def _fake_refresh(dsn: str) -> int:
        seen["dsn"] = dsn
        return 9

    monkeypatch.setattr(recorder, "refresh_priors", _fake_refresh)
    cs._job_refresh_priors()
    assert seen["dsn"] == "postgresql://u:p@h/db"
