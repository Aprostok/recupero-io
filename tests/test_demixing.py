"""v0.35.5 mixer demixing LEADS — probabilistic, never proof.

Pins the forensic doctrine: leads are ALWAYS low confidence, never fabricated
(empty in ⇒ empty out), require a real signal (not just same-pool membership),
and the strongest signal (address reuse) ranks first. Window is dormancy-aware.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from recupero.trace.demixing import (
    MixerEvent,
    demix_candidates,
    demix_to_provenance,
)

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _dep(addr="0xdeadbeef", pool="100 ETH", gas=None, relayer=None):
    return MixerEvent(address=addr, when=T0, pool=pool, tx_hash="0xdep",
                      gas_price=gas, relayer=relayer)


def _wd(addr, mins=10, pool="100 ETH", tx=None, gas=None, relayer=None):
    return MixerEvent(
        address=addr, when=T0 + timedelta(minutes=mins), pool=pool,
        tx_hash=tx or f"0xw{mins}", gas_price=gas, relayer=relayer,
    )


def test_empty_in_empty_out():
    assert demix_candidates(_dep(), []) == []


def test_address_reuse_is_strongest_lead():
    dep = _dep(addr="0xVICTIM")
    wds = [
        _wd("0xunrelated1", mins=5),
        _wd("0xVICTIM", mins=30),          # reuse — the classic mistake
        _wd("0xunrelated2", mins=8),
    ]
    leads = demix_candidates(dep, wds)
    assert leads, "address-reuse withdrawal must surface as a lead"
    top = leads[0]
    assert top.withdrawal_address == "0xVICTIM"
    assert "address_reuse" in top.signals
    assert top.confidence == "low"          # NEVER higher


def test_relayer_and_gas_fingerprints():
    dep = _dep(gas=30_000_000_000, relayer="0xRELAYER")
    wds = [
        _wd("0xa", mins=20, gas=30_000_000_000),         # gas match
        _wd("0xb", mins=25, relayer="0xRELAYER"),        # relayer match
        _wd("0xc", mins=99),                             # no signal (not FIFO)
    ]
    leads = demix_candidates(dep, wds)
    addrs = {le.withdrawal_address for le in leads}
    assert "0xa" in addrs and "0xb" in addrs
    assert "0xc" not in addrs               # same-pool but no signal → not a lead
    assert all(le.confidence == "low" for le in leads)


def test_same_pool_no_signal_only_fifo_lead():
    dep = _dep()
    # Three signal-less same-pool withdrawals; only the FIFO-nearest is a (weak) lead.
    wds = [_wd("0xa", mins=40), _wd("0xb", mins=10), _wd("0xc", mins=70)]
    leads = demix_candidates(dep, wds)
    assert len(leads) == 1
    assert leads[0].withdrawal_address == "0xb"   # earliest after deposit
    assert leads[0].signals == ("fifo_timing",)


def test_wrong_pool_excluded():
    dep = _dep(pool="100 ETH")
    wds = [_wd("0xdeadbeef", mins=10, pool="10 ETH")]  # reuse but wrong pool
    assert demix_candidates(dep, wds) == []


def test_pre_deposit_withdrawal_excluded():
    dep = _dep(addr="0xX")
    wds = [MixerEvent(address="0xX", when=T0 - timedelta(minutes=5),
                      pool="100 ETH", tx_hash="0xpre")]
    assert demix_candidates(dep, wds) == []


def test_dormant_withdrawal_window():
    dep = _dep(addr="0xX")
    wd = _wd("0xX", mins=0)  # placeholder; override time below
    wd = MixerEvent(address="0xX", when=T0 + timedelta(hours=800), pool="100 ETH",
                    tx_hash="0xlate")
    assert demix_candidates(dep, [wd], window_hours=72) == []        # too late
    leads = demix_candidates(dep, [wd], window_hours=0)              # unbounded
    assert leads and leads[0].withdrawal_address == "0xX"


def test_provenance_shape_flags_probabilistic():
    dep = _dep(addr="0xX")
    leads = demix_candidates(dep, [_wd("0xX", mins=10)])
    prov = demix_to_provenance(dep, leads)
    assert prov["pool"] == "100 ETH"
    assert prov["leads"][0]["confidence"] == "low"
    assert "not proof" in prov["note"].lower()
