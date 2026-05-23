"""Adversarial tests for the address inspector.

The inspector promises "never raise on chain errors". Its inputs are:
  1. The address argument (user CLI input — may be junk).
  2. The transactions list returned by Etherscan (external API).

Both can carry adversarial payloads:
  * Extreme ``timeStamp`` values (OverflowError on
    datetime.fromtimestamp) — pre-fix the code catches KeyError,
    ValueError, TypeError but NOT OverflowError / OSError.
  * Invalid ``blockNumber`` or ``timeStamp`` types.
  * Malformed addresses in ``from`` / ``to`` (existing catch covers
    ValueError but verify it).
  * The inspect_address(address=...) input itself: junk strings,
    non-strings, CRLF, or path-traversal-shaped values shouldn't
    crash the function.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from recupero.chains.base import ChainAdapter
from recupero.config import RecuperoConfig, RecuperoEnv, StorageParams
from recupero.inspect.inspector import inspect_address
from recupero.labels.store import LabelStore
from recupero.models import Chain, EvidenceReceipt


SEED = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"


class FakeEtherscanClient:
    """Same minimal shape as the inspector test FakeEtherscanClient."""

    def __init__(self, normal_txs=None, contract_meta=None, balance=0):
        self._normal_txs = normal_txs or []
        self._contract_meta = contract_meta or {}
        self._balance = balance

    def get_normal_transactions(self, address, start_block=0, page=1, offset=1000):
        return list(self._normal_txs)

    def get_contract_source(self, address):
        return dict(self._contract_meta)

    def get_eth_balance(self, address, tag="latest"):
        return self._balance


class FakeAdapter(ChainAdapter):
    chain = Chain.ethereum

    def __init__(self, *, is_contract: bool, etherscan: FakeEtherscanClient):
        self._is_contract = is_contract
        self.client = etherscan

    def block_at_or_before(self, ts):
        return 0

    def is_contract(self, address):
        return self._is_contract

    def fetch_native_outflows(self, from_address, start_block):
        return []

    def fetch_erc20_outflows(self, from_address, start_block):
        return []

    def fetch_evidence_receipt(self, tx_hash):
        return EvidenceReceipt(
            chain=Chain.ethereum, tx_hash=tx_hash, block_number=0,
            block_time=datetime.now(UTC),
            raw_transaction={}, raw_receipt={}, raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from="fake", explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash):
        return f"https://etherscan.io/tx/{tx_hash}"

    def explorer_address_url(self, address):
        return f"https://etherscan.io/address/{address}"


@pytest.fixture
def cfg(tmp_path):
    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    env = RecuperoEnv(ETHERSCAN_API_KEY="TEST")
    return cfg, env


def _tx(from_addr, to_addr, block=19000000, ts=1736942400):
    return {
        "blockNumber": str(block),
        "timeStamp": str(ts),
        "from": from_addr,
        "to": to_addr,
        "hash": f"0x{block:064x}",
        "value": "0",
        "isError": "0",
    }


def _install_adapter(monkeypatch, adapter):
    monkeypatch.setattr(
        ChainAdapter, "for_chain",
        classmethod(lambda cls, chain, bundle: adapter),
    )


# ---- Extreme timestamp / blockNumber values ---- #


def test_extreme_timestamp_does_not_crash(cfg, monkeypatch) -> None:
    """An Etherscan response carrying a timeStamp string like
    99999999999999999 must not raise OverflowError out of
    inspect_address. The existing try/except catches KeyError,
    ValueError, TypeError — but datetime.fromtimestamp(very_large)
    raises OverflowError / OSError, which the current code does NOT
    catch."""
    config, env = cfg
    bad_tx = _tx(SEED, PERP, ts=99_999_999_999_999_999)
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[bad_tx]),
    )
    _install_adapter(monkeypatch, fake)
    try:
        profile = inspect_address(
            address=SEED, chain=Chain.ethereum, config=config, env=env,
        )
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"inspect_address raised {type(e).__name__} on extreme "
            f"Etherscan timeStamp: {e}. Inspector is documented as "
            "best-effort and must never raise on chain errors."
        ) from e
    # Got a profile. first_seen_at is either None (skipped due to
    # overflow) or a sane datetime (year <= 9999).
    if profile.first_seen_at is not None:
        assert profile.first_seen_at.year <= 9999


def test_negative_extreme_timestamp_does_not_crash(cfg, monkeypatch) -> None:
    config, env = cfg
    bad_tx = _tx(SEED, PERP, ts=-99_999_999_999_999)
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[bad_tx]),
    )
    _install_adapter(monkeypatch, fake)
    try:
        profile = inspect_address(
            address=SEED, chain=Chain.ethereum, config=config, env=env,
        )
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"inspect_address raised {type(e).__name__} on negative "
            f"extreme Etherscan timeStamp: {e}"
        ) from e
    assert profile.observed_tx_count == 1


def test_non_numeric_timestamp_does_not_crash(cfg, monkeypatch) -> None:
    """Existing try/except already covers this — keep a regression
    lock so the catch list doesn't shrink."""
    config, env = cfg
    bad_tx = _tx(SEED, PERP)
    bad_tx["timeStamp"] = "definitely-not-a-number"
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[bad_tx]),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    # Got a profile with first_seen_at=None.
    assert profile.first_seen_at is None
    assert profile.observed_tx_count == 1  # the tx still counted


def test_missing_timestamp_does_not_crash(cfg, monkeypatch) -> None:
    config, env = cfg
    bad_tx = _tx(SEED, PERP)
    del bad_tx["timeStamp"]
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[bad_tx]),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    assert profile.first_seen_at is None


# ---- Garbage 'from' / 'to' addresses ---- #


def test_invalid_counterparty_address_skipped(cfg, monkeypatch) -> None:
    """Malformed `from` / `to` in a tx must be skipped (existing
    try/except). Regression lock."""
    config, env = cfg
    txs = [
        # Valid tx.
        _tx(SEED, PERP, block=100, ts=1700000000),
        # Garbage `to`.
        {**_tx(SEED, PERP, block=200, ts=1700000100), "to": "not-an-address"},
        # Garbage `from`.
        {**_tx(SEED, PERP, block=300, ts=1700000200), "from": "0x" + "Z" * 40},
    ]
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=txs),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    # Counterparty aggregation should only include the valid tx's PERP.
    cps = {cp.address for cp in profile.top_counterparties}
    assert PERP in cps
    # observed_tx_count counts raw response length, not parseable txs.
    assert profile.observed_tx_count == 3


def test_to_is_none_contract_creation_skipped(cfg, monkeypatch) -> None:
    """Contract-creation txs have `to=None`. Regression lock."""
    config, env = cfg
    tx = _tx(SEED, PERP, block=100, ts=1700000000)
    tx["to"] = ""    # Etherscan sometimes returns empty string
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[tx]),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    # No counterparty extracted.
    assert profile.top_counterparties == []


# ---- Invalid address input to inspect_address itself ---- #


def test_invalid_address_argument_does_not_silently_succeed(cfg, monkeypatch) -> None:
    """Junk address like 'not-an-address' currently raises out of
    to_checksum_address. That's an acceptable failure mode (CLI
    can catch it) — but the failure must be a clear, named
    exception, not an internal crash deep in the heuristic."""
    config, env = cfg
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[]),
    )
    _install_adapter(monkeypatch, fake)
    # Acceptable: ValueError / TypeError from to_checksum_address.
    # NOT acceptable: AttributeError, OverflowError, KeyError.
    with pytest.raises((ValueError, TypeError)):
        inspect_address(
            address="definitely-not-an-eth-address",
            chain=Chain.ethereum, config=config, env=env,
        )


# ---- Self-tx + extreme volume guards ---- #


def test_self_tx_excluded_from_counterparty_aggregation(cfg, monkeypatch) -> None:
    """A tx where from == to (self-loop) must not count as a
    counterparty. Regression lock — the existing code has an
    explicit `if other.lower() == addr.lower(): continue`."""
    config, env = cfg
    txs = [
        _tx(SEED, SEED, block=100, ts=1700000000),
        _tx(SEED, PERP, block=200, ts=1700000100),
    ]
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=txs),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    # Only PERP shows up; SEED filtered as self-tx.
    cps = [cp.address for cp in profile.top_counterparties]
    assert PERP in cps
    assert SEED not in cps


# ---- get_contract_source returns non-dict ---- #


def test_contract_source_returns_non_dict_handled(cfg, monkeypatch) -> None:
    """A misbehaving Etherscan / proxy returning a list instead of
    a dict for contract_source must not crash the inspector. The
    existing isinstance(meta, dict) guard handles this; regression lock."""
    config, env = cfg

    class WeirdShapeClient(FakeEtherscanClient):
        def get_contract_source(self, address):
            return ["unexpected", "shape"]    # not a dict

    fake = FakeAdapter(
        is_contract=True,
        etherscan=WeirdShapeClient(normal_txs=[_tx(SEED, PERP)]),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    assert profile.is_contract is True
    assert profile.contract_name is None  # silently dropped


def test_negative_eth_balance_handled(cfg, monkeypatch) -> None:
    """A misbehaving client returns -1 for balance. Decimal accepts
    negative ints; the question is whether downstream display will
    bork. The inspector currently passes negative balance through;
    verify it does so without crashing."""
    config, env = cfg
    fake = FakeAdapter(
        is_contract=False,
        etherscan=FakeEtherscanClient(normal_txs=[], balance=-1),
    )
    _install_adapter(monkeypatch, fake)
    profile = inspect_address(
        address=SEED, chain=Chain.ethereum, config=config, env=env,
    )
    # Negative balance should be coerced to 0 or None (a wallet can't
    # owe ETH). This is a defense-in-depth ask — pre-fix the inspector
    # propagates the negative value silently.
    if profile.eth_balance is not None:
        assert profile.eth_balance >= 0, (
            f"Negative ETH balance propagated: {profile.eth_balance}. "
            "Real wallets can't have negative balances; a -1 from the "
            "client is a bug we should mask, not propagate."
        )
