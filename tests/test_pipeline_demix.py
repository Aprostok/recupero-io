"""Worker-pipeline wiring of the demix runner (Activation Sprint #4b).

Pins ``_maybe_write_demix_leads``:
  * gated OFF (default) → zero-cost no-op: ChainAdapter.for_chain is NEVER
    called and no demix_leads.json is written;
  * gated ON → demix_leads.json written into the case dir from the live trace,
    leads always confidence "low", and the adapter is always closed;
  * ON but no mixer deposit → no file (nothing to demix);
  * ON but the adapter fetch blows up → non-fatal (no file, no raise).

The chain adapter is monkeypatched at ChainAdapter.for_chain so the test needs
no network. Mirrors the deposit/withdrawal fixtures in test_demix_runner.py.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

from recupero.models import Chain
from recupero.worker.pipeline import _maybe_write_demix_leads

_POOL_100ETH = "0xa160cdab225685da1d56aa342ad8841c3b53f291"  # Tornado 100 ETH (eth)
_DEPOSITOR = "0x" + "ab" * 20
_OTHER = "0x" + "cd" * 20
_TORNADO_W_TOPIC0 = (
    "0xe9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931"
)


def _tx(to: str, frm: str, *, chain: str = "ethereum", txh: str = "0xdep"):
    return SimpleNamespace(
        to_address=to, from_address=frm,
        chain=SimpleNamespace(value=chain),
        block_time=datetime(2022, 1, 1, tzinfo=UTC), tx_hash=txh,
    )


def _case(transfers):
    # Duck-typed Case: the helper only touches .chain / .transfers / .case_id.
    return SimpleNamespace(
        chain=Chain.ethereum, transfers=transfers, case_id="DEMIX-PIPE-1",
    )


def _withdrawal_log(recipient: str) -> dict:
    word0 = recipient.removeprefix("0x").rjust(64, "0")          # to
    return {
        "data": "0x" + word0 + "ff" * 32 + format(10**17, "064x"),
        "topics": [_TORNADO_W_TOPIC0, "0x" + "11" * 32],          # relayer topic
        "transactionHash": "0xwtx",
        "timeStamp": str(int(datetime(2022, 2, 1, tzinfo=UTC).timestamp())),
    }


class _MockAdapter:
    def __init__(self, logs: list[dict]):
        self._logs = logs
        self.closed = False

    def block_at_or_before(self, _ts):
        return 1000

    def fetch_logs(self, _addr, _topic0, *, from_block, to_block, topics=None):
        return self._logs

    def close(self):
        self.closed = True


def _patch_for_chain(monkeypatch, factory):
    from recupero.chains import base as base_mod
    monkeypatch.setattr(
        base_mod.ChainAdapter, "for_chain", classmethod(factory),
    )


def test_demix_off_by_default_is_noop(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_DEMIX_LEADS", raising=False)
    calls = {"n": 0}

    def _factory(cls, *a, **k):  # pragma: no cover - must not run
        calls["n"] += 1
        raise AssertionError("for_chain must NOT be called when demix is off")

    _patch_for_chain(monkeypatch, _factory)
    _maybe_write_demix_leads(_case([_tx(_POOL_100ETH, _DEPOSITOR)]),
                             tmp_path, config=None, env=None)
    assert not (tmp_path / "demix_leads.json").exists()
    assert calls["n"] == 0  # zero cost: no adapter constructed


def test_demix_on_writes_artifact_low_confidence(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DEMIX_LEADS", "1")
    # Withdrawal back to the SAME address that deposited → address_reuse lead.
    adapter = _MockAdapter([_withdrawal_log(_DEPOSITOR)])
    _patch_for_chain(monkeypatch, lambda cls, *a, **k: adapter)

    _maybe_write_demix_leads(_case([_tx(_POOL_100ETH, _DEPOSITOR)]),
                             tmp_path, config=None, env=None)

    out = tmp_path / "demix_leads.json"
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["kind"] == "recupero_demix_leads"
    assert doc["deposits"], "expected at least one pool/deposit group"
    assert doc["deposits"][0]["leads"][0]["confidence"] == "low"  # never escalated
    assert adapter.closed is True  # adapter always closed


def test_demix_on_no_mixer_deposit_writes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DEMIX_LEADS", "1")
    adapter = _MockAdapter([])
    _patch_for_chain(monkeypatch, lambda cls, *a, **k: adapter)
    # transfer to a non-mixer address → no deposit to demix
    _maybe_write_demix_leads(_case([_tx(_OTHER, _DEPOSITOR)]),
                             tmp_path, config=None, env=None)
    assert not (tmp_path / "demix_leads.json").exists()


def test_demix_adapter_failure_is_nonfatal(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_DEMIX_LEADS", "1")

    def _boom(cls, *a, **k):
        raise RuntimeError("rpc down")

    _patch_for_chain(monkeypatch, _boom)
    # must NOT raise — a demixing nicety never blocks the trace pipeline
    _maybe_write_demix_leads(_case([_tx(_POOL_100ETH, _DEPOSITOR)]),
                             tmp_path, config=None, env=None)
    assert not (tmp_path / "demix_leads.json").exists()


# -----------------------------------------------------------------------------
# #4b surfacing: trace-report renders a Mixer-Demixing Leads section when (and
# only when) demix_leads.json is present in the case dir.
# -----------------------------------------------------------------------------


def _real_case():
    from recupero.models import Case
    return Case(
        case_id="DEMIX-TR-1",
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


_DEMIX_DOC = {
    "kind": "recupero_demix_leads",
    "disclaimer": "Probabilistic demixing LEADS — never proof.",
    "deposits": [
        {
            "key": "0xa160cdab225685da1d56aa342ad8841c3b53f291@0xdep",
            "leads": [
                {
                    "withdrawal_address": "0x" + "cd" * 20,
                    "withdrawal_tx": "0xw",
                    "pool": "Tornado Cash 100 ETH",
                    "score": 0.5,
                    "signals": ["address_reuse"],
                    "basis": "withdrawal recipient == deposit sender",
                    "confidence": "low",
                }
            ],
        }
    ],
}


def test_trace_report_renders_demix_section_when_present(tmp_path, monkeypatch) -> None:
    from recupero.worker._trace_report import render_trace_report

    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    (case_dir / "demix_leads.json").write_text(
        json.dumps(_DEMIX_DOC), encoding="utf-8")

    path = render_trace_report(
        case=_real_case(),
        freeze_brief={"FREEZABLE": [], "DESTINATIONS": []},
        briefs_dir=briefs,
        investigation_id="inv-1",
    )
    assert path is not None
    html = path.read_text(encoding="utf-8")
    assert "Mixer-Demixing Leads" in html
    assert "address_reuse" in html
    assert "0x" + "cd" * 20 in html
    assert "never proof" in html.lower()  # forensic disclaimer present


def test_trace_report_no_demix_section_without_artifact(tmp_path, monkeypatch) -> None:
    from recupero.worker._trace_report import render_trace_report

    monkeypatch.setenv("RECUPERO_DISABLE_PDF_RENDER", "1")
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)
    # no demix_leads.json → section must be absent (default behavior unchanged)

    path = render_trace_report(
        case=_real_case(),
        freeze_brief={"FREEZABLE": [], "DESTINATIONS": []},
        briefs_dir=briefs,
        investigation_id="inv-1",
    )
    assert path is not None
    html = path.read_text(encoding="utf-8")
    assert "Mixer-Demixing Leads" not in html
