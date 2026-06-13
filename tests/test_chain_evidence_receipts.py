"""Hardened evidence receipts for the Sui + Aptos adapters.

Both adapters previously returned an epoch-0 placeholder ``block_time`` (and Sui a
0 ``block_number``). These tests lock in the hardening: the receipt now carries
the REAL on-chain time + block id when the source can supply it, and falls back
to the unknown-time sentinel (epoch 0) WITHOUT raising on a transport failure or
an un-indexed/unknown tx — a transient RPC blip must never break evidence
writing, and a time we can't fetch is never fabricated.

No network: fake clients return canned shapes that mirror what was verified live
(Sui ``sui_getTransactionBlock`` → timestampMs/checkpoint/transaction/effects;
Aptos indexer by-version → transaction_timestamp).
"""
from __future__ import annotations

from datetime import UTC, datetime

from recupero.chains.aptos.adapter import AptosAdapter
from recupero.chains.aptos.client import AptosIndexerError
from recupero.chains.sui.adapter import SuiAdapter
from recupero.chains.sui.client import SuiRPCError
from recupero.models import Chain, EvidenceReceipt

_EPOCH0 = datetime.fromtimestamp(0, tz=UTC)


# --------------------------------------------------------------------------- #
# Sui
# --------------------------------------------------------------------------- #
class _FakeSuiClient:
    base_url = "https://fullnode.mainnet.sui.io"

    def __init__(self, *, block=None, error=False):
        self._block = block
        self._error = error
        self.asked = None

    def get_transaction_block(self, digest):
        self.asked = digest
        if self._error:
            raise SuiRPCError("boom")
        return self._block

    def close(self):
        pass


def test_sui_receipt_anchors_real_time_and_checkpoint():
    block = {
        "digest": "DIG", "timestampMs": "1781311239440", "checkpoint": "286332028",
        "transaction": {"data": {"sender": "0xabc"}},
        "effects": {"status": {"status": "success"}},
    }
    ad = SuiAdapter(client=_FakeSuiClient(block=block))
    rec = ad.fetch_evidence_receipt("DIG")
    assert isinstance(rec, EvidenceReceipt)
    assert rec.chain == Chain.sui
    assert rec.block_number == 286332028
    assert rec.block_time == datetime.fromtimestamp(1781311239440 / 1000, tz=UTC)
    assert rec.block_time > _EPOCH0
    assert rec.raw_transaction == block["transaction"]
    assert rec.raw_receipt == block["effects"]
    assert rec.explorer_url.endswith("/tx/DIG")


def test_sui_receipt_falls_back_on_rpc_error_without_raising():
    ad = SuiAdapter(client=_FakeSuiClient(error=True))
    rec = ad.fetch_evidence_receipt("DIG")          # must NOT raise
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 0
    assert rec.raw_transaction == {} and rec.raw_receipt == {}


def test_sui_receipt_falls_back_on_missing_block():
    ad = SuiAdapter(client=_FakeSuiClient(block=None))
    rec = ad.fetch_evidence_receipt("DIG")
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 0


def test_sui_receipt_ignores_zero_timestamp():
    # a malformed/zero timestampMs must not become a "real" epoch-0 claim
    block = {"timestampMs": "0", "checkpoint": "5"}
    ad = SuiAdapter(client=_FakeSuiClient(block=block))
    rec = ad.fetch_evidence_receipt("DIG")
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 5            # checkpoint still captured


# --------------------------------------------------------------------------- #
# Aptos
# --------------------------------------------------------------------------- #
class _FakeAptosClient:
    base_url = "https://api.mainnet.aptoslabs.com/v1/graphql"

    def __init__(self, *, meta=None, error=False):
        self._meta = meta
        self._error = error
        self.asked = None

    def transaction_meta(self, version):
        self.asked = version
        if self._error:
            raise AptosIndexerError("boom")
        return self._meta

    def close(self):
        pass


def test_aptos_receipt_anchors_real_time_from_indexer():
    meta = {"transaction_version": 5707533647,
            "transaction_timestamp": "2026-06-13T00:40:12"}
    ad = AptosAdapter(client=_FakeAptosClient(meta=meta))
    rec = ad.fetch_evidence_receipt("5707533647")
    assert rec.chain == Chain.aptos
    assert rec.block_number == 5707533647
    assert rec.block_time > _EPOCH0
    assert rec.block_time.year == 2026 and rec.block_time.tzinfo is not None
    assert rec.raw_transaction == meta


def test_aptos_receipt_falls_back_on_indexer_error_keeps_version():
    ad = AptosAdapter(client=_FakeAptosClient(error=True))
    rec = ad.fetch_evidence_receipt("5707533647")   # must NOT raise
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 5707533647           # version still from tx_hash
    assert rec.raw_transaction == {}


def test_aptos_receipt_falls_back_on_unindexed_version():
    ad = AptosAdapter(client=_FakeAptosClient(meta=None))
    rec = ad.fetch_evidence_receipt("5707533647")
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 5707533647


def test_aptos_receipt_non_numeric_tx_hash_makes_no_call():
    fake = _FakeAptosClient(meta={"transaction_timestamp": "2026-06-13T00:40:12"})
    ad = AptosAdapter(client=fake)
    rec = ad.fetch_evidence_receipt("not-a-version")
    assert rec.block_time == _EPOCH0
    assert rec.block_number == 0
    assert fake.asked is None                        # never queried the indexer
