"""#5 — direct (1-hop) high-risk counterparty exposure probe (instant KYT)."""

from __future__ import annotations

from datetime import UTC, datetime

from recupero.screen.exposure_probe import probe_counterparty_exposure
from recupero.trace.risk_scoring import HighRiskEntry

SELF = "0x" + "a" * 40
MIXER = "0x" + "b" * 40
SANCTIONED = "0x" + "c" * 40
CLEAN = "0x" + "d" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _db() -> dict[str, HighRiskEntry]:
    return {
        MIXER.lower(): HighRiskEntry(
            address=MIXER.lower(), name="Tornado Cash",
            risk_category="mixer_high_risk", severity=3),
        SANCTIONED.lower(): HighRiskEntry(
            address=SANCTIONED.lower(), name="Lazarus Group",
            risk_category="ofac_sanctioned", severity=4),
    }


def _row(*, frm: str, to: str, txh: str) -> dict:
    return {
        "chain": "ethereum", "tx_hash": txh, "block_number": 1,
        "from": frm, "to": to, "amount_raw": 1,
        "explorer_url": f"https://etherscan.io/tx/{txh}",
    }


class _FakeAdapter:
    """Minimal ChainAdapter stand-in. Native = TRX-style single list;
    erc20 carries the rest. Inflows/outflows split by direction."""

    def __init__(self, *, outflows=None, inflows=None) -> None:
        self._out = outflows or []
        self._in = inflows or []

    def block_at_or_before(self, ts):  # noqa: ANN001
        return 100

    def fetch_native_outflows(self, addr, start_block):  # noqa: ANN001
        return self._out

    def fetch_erc20_outflows(self, addr, start_block):  # noqa: ANN001
        return []

    def fetch_native_inflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return self._in

    def fetch_erc20_inflows(self, addr, start_block, *, max_results=None):  # noqa: ANN001
        return []


def test_no_high_risk_db_returns_none() -> None:
    adapter = _FakeAdapter(outflows=[_row(frm=SELF, to=MIXER, txh="0x1")])
    assert probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db={}, now=NOW,
    ) is None


def test_clean_counterparties_return_none() -> None:
    adapter = _FakeAdapter(
        outflows=[_row(frm=SELF, to=CLEAN, txh="0x1")],
        inflows=[_row(frm=CLEAN, to=SELF, txh="0x2")],
    )
    assert probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    ) is None


def test_outbound_mixer_exposure_detected() -> None:
    adapter = _FakeAdapter(outflows=[
        _row(frm=SELF, to=MIXER, txh="0x1"),
        _row(frm=SELF, to=MIXER, txh="0x2"),
        _row(frm=SELF, to=CLEAN, txh="0x3"),
    ])
    out = probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    )
    assert out is not None
    cps = out["direct_high_risk_counterparties"]
    assert len(cps) == 1
    assert cps[0]["counterparty"] == MIXER
    assert cps[0]["direction"] == "outbound"
    assert cps[0]["category"] == "mixer_high_risk"
    assert cps[0]["transfer_count"] == 2
    assert cps[0]["sample_tx_hashes"] == ["0x1", "0x2"]
    assert "sent funds to" in out["headline"]


def test_inbound_sanctioned_exposure_detected() -> None:
    adapter = _FakeAdapter(inflows=[_row(frm=SANCTIONED, to=SELF, txh="0xab")])
    out = probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    )
    assert out is not None
    top = out["direct_high_risk_counterparties"][0]
    assert top["direction"] == "inbound"
    assert top["category"] == "ofac_sanctioned"
    assert "received funds from" in out["headline"]


def test_sanctioned_outranks_mixer_in_headline() -> None:
    """OFAC-sanctioned (sev 4) ranks above mixer (sev 3) even with fewer txs."""
    adapter = _FakeAdapter(
        outflows=[_row(frm=SELF, to=MIXER, txh=f"0x{i}") for i in range(5)],
        inflows=[_row(frm=SANCTIONED, to=SELF, txh="0xff")],
    )
    out = probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    )
    assert out["direct_high_risk_counterparties"][0]["category"] == "ofac_sanctioned"
    assert out["by_category"][0]["category"] == "ofac_sanctioned"
    # both categories present in rollup
    cats = {c["category"] for c in out["by_category"]}
    assert cats == {"ofac_sanctioned", "mixer_high_risk"}


def test_sample_tx_hashes_capped_at_five() -> None:
    adapter = _FakeAdapter(outflows=[
        _row(frm=SELF, to=MIXER, txh=f"0x{i}") for i in range(9)
    ])
    out = probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    )
    cp = out["direct_high_risk_counterparties"][0]
    assert cp["transfer_count"] == 9
    assert len(cp["sample_tx_hashes"]) == 5  # capped


def test_failing_fetcher_does_not_void_probe() -> None:
    """If one fetcher raises, the others still produce results."""
    class _PartlyBroken(_FakeAdapter):
        def fetch_erc20_outflows(self, addr, start_block):  # noqa: ANN001
            raise RuntimeError("rpc down")

    adapter = _PartlyBroken(outflows=[_row(frm=SELF, to=MIXER, txh="0x1")])
    out = probe_counterparty_exposure(
        SELF, chain="ethereum", adapter=adapter, high_risk_db=_db(), now=NOW,
    )
    assert out is not None
    assert out["direct_high_risk_counterparties"][0]["counterparty"] == MIXER
