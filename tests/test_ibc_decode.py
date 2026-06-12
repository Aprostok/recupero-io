"""Roadmap-v4 Tier-2 #8: IBC (ICS-20) continuation-out decoder + runner.

The fixture is a REAL Osmosis LCD send_packet captured live (2026-06):
src_channel-750 -> dst_channel-1, seq 1222175, carrying
``transfer/channel-750/uusdc`` from osmo1... to noble1... — a real
Circle-freezable USDC exit.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from recupero.trace.ibc_decode import (
    IBC_CHANNEL_REGISTRY,
    parse_ibc_sends,
    strip_ibc_denom,
)
from recupero.trace.ibc_runner import (
    ibc_leads_enabled,
    leads_to_json,
    run_ibc_leads,
)

_OSMO = "osmo1nra90utxlzgtdwft5w2d7pczlhl5gljdkx0a3d"
_NOBLE = "noble1nra90utxlzgtdwft5w2d7pczlhl5gljdk7f9l3"


def _send_packet_event(*, sender, receiver, denom, amount,
                       src_channel="channel-750", dst_channel="channel-1",
                       seq="1222175", src_port="transfer"):
    return {
        "type": "send_packet",
        "attributes": [
            {"key": "packet_data", "value": json.dumps({
                "amount": amount, "denom": denom,
                "receiver": receiver, "sender": sender})},
            {"key": "packet_src_port", "value": src_port},
            {"key": "packet_src_channel", "value": src_channel},
            {"key": "packet_dst_port", "value": "transfer"},
            {"key": "packet_dst_channel", "value": dst_channel},
            {"key": "packet_sequence", "value": seq},
        ],
    }


def _tx(events, txhash="0xABC"):
    return {"txhash": txhash, "events": events}


# REAL outbound USDC exit (live-captured 2026-06).
_REAL_TX = _tx([_send_packet_event(
    sender=_OSMO, receiver=_NOBLE,
    denom="transfer/channel-750/uusdc", amount="5679798")])


def test_strip_ibc_denom() -> None:
    assert strip_ibc_denom("transfer/channel-750/uusdc") == "uusdc"
    assert strip_ibc_denom("transfer/channel-0/transfer/channel-750/uusdc") == "uusdc"
    assert strip_ibc_denom("uosmo") == "uosmo"   # native, no path
    assert strip_ibc_denom("") == ""


def test_parse_real_osmosis_noble_usdc_exit() -> None:
    sends = parse_ibc_sends(_REAL_TX, src_zone="osmosis")
    assert len(sends) == 1
    s = sends[0]
    assert s.sender == _OSMO
    assert s.receiver == _NOBLE
    assert s.denom == "transfer/channel-750/uusdc"
    assert s.base_denom == "uusdc"
    assert s.amount_raw == "5679798"
    assert s.src_channel == "channel-750"
    assert s.dst_channel == "channel-1"
    assert s.sequence == "1222175"
    assert s.dest_chain == "noble"            # registry-resolved
    assert s.is_circle_usdc is True           # Circle-freezable
    assert s.pair_id == ("channel-750", "channel-1", "1222175")


def test_registry_has_verified_routes() -> None:
    assert IBC_CHANNEL_REGISTRY[("osmosis", "channel-750")] == "noble"
    assert IBC_CHANNEL_REGISTRY[("osmosis", "channel-0")] == "cosmoshub"


def test_unknown_channel_surfaces_hop_with_no_dest_chain() -> None:
    tx = _tx([_send_packet_event(
        sender=_OSMO, receiver="cosmos1xyz", denom="uosmo", amount="100",
        src_channel="channel-99999")])
    sends = parse_ibc_sends(tx, src_zone="osmosis")
    assert len(sends) == 1
    assert sends[0].dest_chain is None        # unknown channel → never guessed
    assert sends[0].is_circle_usdc is False


def test_parse_skips_non_transfer_and_malformed() -> None:
    # non-ICS-20 port skipped
    ica = _send_packet_event(sender=_OSMO, receiver=_NOBLE, denom="uusdc",
                             amount="1", src_port="icahost")
    # malformed packet_data
    bad = {"type": "send_packet", "attributes": [
        {"key": "packet_data", "value": "{not json"},
        {"key": "packet_src_port", "value": "transfer"}]}
    # zero amount
    zero = _send_packet_event(sender=_OSMO, receiver=_NOBLE, denom="uusdc", amount="0")
    sends = parse_ibc_sends(_tx([ica, bad, zero]), src_zone="osmosis")
    assert sends == []


# ---- runner ---- #


def _transfer(frm):
    return SimpleNamespace(from_address=frm, to_address="osmo1other")


class _StubClient:
    def __init__(self, by_sender):
        self.by_sender = by_sender
        self.calls: list[str] = []

    def fetch_all_txs_by_sender(self, address):
        self.calls.append(address)
        return self.by_sender.get(address, [])


def test_runner_gate_default_off(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_IBC_LEADS", raising=False)
    assert ibc_leads_enabled() is False
    assert run_ibc_leads(transfers=[_transfer(_OSMO)], client=None) == []
    monkeypatch.setenv("RECUPERO_IBC_LEADS", "1")
    assert ibc_leads_enabled() is True


def test_runner_emits_usdc_freeze_lead() -> None:
    client = _StubClient({_OSMO: {"tx_responses": [_REAL_TX]}})
    leads = run_ibc_leads(transfers=[_transfer(_OSMO)], client=client, force=True)
    assert len(leads) == 1
    ld = leads[0]
    assert ld["dest_chain"] == "noble"
    assert ld["receiver"] == _NOBLE
    assert ld["is_circle_usdc"] is True
    assert ld["freezable_issuer"] == "Circle (USDC)"
    assert ld["confidence"] == "high"
    assert ld["pair_id"] == ["channel-750", "channel-1", "1222175"]
    assert client.calls == [_OSMO]


def test_runner_skips_non_cosmos_wallet() -> None:
    client = _StubClient({})
    leads = run_ibc_leads(
        transfers=[_transfer("0x" + "ab" * 20)], client=client, force=True)
    assert leads == []
    assert client.calls == []   # EVM addr → not a zone → no fetch


def test_runner_drops_foreign_sender() -> None:
    # A send_packet whose sender isn't the queried wallet must not become a lead.
    other_tx = _tx([_send_packet_event(
        sender="osmo1someoneelse", receiver=_NOBLE,
        denom="transfer/channel-750/uusdc", amount="5")])
    client = _StubClient({_OSMO: {"tx_responses": [other_tx]}})
    leads = run_ibc_leads(transfers=[_transfer(_OSMO)], client=client, force=True)
    assert leads == []


def test_leads_to_json_artifact_shape() -> None:
    doc = leads_to_json([{"x": 1}])
    assert doc["kind"] == "recupero_ibc_leads"
    assert doc["lead_count"] == 1
    assert "never a followed destination" in doc["disclaimer"]
    assert "recv_packet" in doc["disclaimer"]
