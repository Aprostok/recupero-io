"""Aptos mainnet chain adapter (roadmap-v4: Aptos live transfer coverage).

Closes the gap where ``ChainAdapter.for_chain(Chain.aptos)`` raised
NotImplementedError, so a trace that bridged INTO Aptos dead-ended. Aptos-native
Circle USDC is issuer-freezable, so reaching it is directly actionable.

Aptos has two asset standards — the legacy Coin standard and the Fungible Asset
(FA) standard — and FA transfer events fire on a fungible-store OBJECT whose owner
must be resolved (the correctness trap). Rather than parse raw events, this
adapter reads the public, keyless Aptos Indexer ``fungible_asset_activities``
feed, which has ALREADY done both hard parts: it resolves each store object back
to its OWNER address and unifies legacy-coin (``token_standard "v1"``) with FA
(``"v2"``) into one owner-keyed activity row (owner_address / amount / asset_type
/ type / is_gas_fee / transaction_version / transaction_timestamp).

A transfer A->B of asset X at version V appears as two rows: a Withdraw owned by
A and a Deposit owned by B. The adapter reconstructs from->to edges by pairing,
PER (version, asset_type): the focus's Withdraw with the OTHER owners' Deposits.

Forensic guards:
  * Single-withdrawer rule: an edge is emitted only when the focus is the SOLE
    withdrawer of that asset at that version. A multi-sender aggregation (≥2
    distinct withdrawers) is SKIPPED, not attributed — under-emit beats
    mis-attributing A->B when the sender was really C.
  * A swap whose only same-asset Deposit is back to the focus (round-trip) emits
    no edge (it's a swap, not a transfer out).
  * Gas (``is_gas_fee``) and failed txs are excluded server-side.
  * amount_raw = the recipient's Deposit amount (the value that actually arrived;
    fee-clean from the recipient's side).
  * Decimals come from LIVE-VERIFIED pinned canonical assets (APT coin + FA @0xa,
    USDC) or a real ``fungible_asset_metadata`` lookup keyed by the asset_type
    itself (contract identity — NEVER by symbol, since the metadata table is
    riddled with symbol-spoofing "USDT"/"APT" fakes). An asset whose metadata
    can't be resolved is SKIPPED, never assigned guessed decimals.

Addresses are canonicalised via the verified Move-VM codec. The Indexer has no
per-event receipt block; ``fetch_evidence_receipt`` returns the version +
explorer pointer (raw_* empty) rather than inventing block data.
"""

from __future__ import annotations

import contextlib
import logging
import os
from datetime import UTC, datetime
from typing import Any

from recupero.chains.aptos.client import AptosIndexerClient, AptosIndexerError
from recupero.chains.base import ChainAdapter
from recupero.chains.move_address import is_valid_aptos_address, normalize_aptos_address
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)

APT_COIN_TYPE = "0x1::aptos_coin::AptosCoin"
# Canonical APT Fungible Asset metadata object (verified live: symbol APT, 8 dec).
APT_FA_TYPE = "0x" + "0" * 63 + "a"
APT_SYMBOL = "APT"
APT_DECIMALS = 8
APT_COINGECKO_ID = "aptos"

# Both representations are native APT.
_APT_ASSET_TYPES = frozenset({APT_COIN_TYPE, APT_FA_TYPE})

_EXPLORER_TX = "https://explorer.aptoslabs.com/txn/"
_EXPLORER_ADDR = "https://explorer.aptoslabs.com/account/"
_EXPLORER_NET = "?network=mainnet"

# Per-address activity budget. The Indexer hard-caps a single query at 100 rows,
# but the client now PAGINATES (compound version+event_index cursor), so the only
# remaining bound is this budget — mirroring the project standard
# (config.trace.max_transfers_per_address = 50_000, env-overridable) so Aptos
# isn't a silent outlier. A fetch that actually hits the budget is WARNED (real
# truncation), never silent.
_DEFAULT_MAX_TRANSFERS_PER_ADDRESS = 50_000
_HARD_ROW_CEILING = 250_000  # runaway backstop for a "disabled"/garbage budget.


def _resolve_budget() -> int:
    """RECUPERO_MAX_TRANSFERS_PER_ADDRESS as a row budget (default 50_000).
    ``<= 0`` (disabled/unbounded) → the hard ceiling; clamped to it otherwise."""
    raw = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
    budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if raw is not None:
        try:
            budget = int(raw)
        except (TypeError, ValueError):
            budget = _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
    if budget <= 0:
        return _HARD_ROW_CEILING
    return min(budget, _HARD_ROW_CEILING)

# LIVE-VERIFIED canonical assets: asset_type -> (symbol, decimals, coingecko_id).
# Pinned by ADDRESS (not symbol) — the metadata table has many symbol-spoof fakes.
_PINNED_ASSETS: dict[str, tuple[str, int, str | None]] = {
    APT_COIN_TYPE: (APT_SYMBOL, APT_DECIMALS, APT_COINGECKO_ID),
    APT_FA_TYPE: (APT_SYMBOL, APT_DECIMALS, APT_COINGECKO_ID),
    # Circle native USDC on Aptos (verified: symbol USDC, 6 dec, ~160M supply).
    "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b":
        ("USDC", 6, "usd-coin"),
}


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.fromtimestamp(0, tz=UTC)


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _is_withdraw(type_str: Any) -> bool:
    return isinstance(type_str, str) and "withdraw" in type_str.lower()


def _is_deposit(type_str: Any) -> bool:
    return isinstance(type_str, str) and "deposit" in type_str.lower()


class AptosAdapter(ChainAdapter):
    """Aptos mainnet adapter (native APT + coin/FA transfers via the Indexer)."""

    chain = Chain.aptos

    def __init__(self, *, client: AptosIndexerClient | None = None,
                 max_legs: int | None = None) -> None:
        self.client = client or AptosIndexerClient()
        # max_legs=None (default) → the project transfer budget
        # (RECUPERO_MAX_TRANSFERS_PER_ADDRESS, default 50_000). The client now
        # paginates, so this is a real total-row budget, not the 100-row cap.
        if max_legs is None:
            max_legs = _resolve_budget()
        self._max_legs = max(1, max_legs)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()

    # ----- block / time -----

    def block_at_or_before(self, ts: datetime) -> int:
        """Aptos has no ts->version endpoint here; the fetch filters client-side
        on each activity's transaction_timestamp. Return a unix-ts cutoff."""
        return int(ts.timestamp())

    def is_contract(self, address: Address) -> bool:  # noqa: ARG002
        """A traced owner address is an account; resource/object addresses are
        not trace continuation targets. Conservatively False."""
        return False

    # ----- token resolution -----

    def _resolve_tokens(self, asset_types: set[str]) -> dict[str, TokenRef]:
        """Map each asset_type to a TokenRef. Pinned canonical assets first; the
        rest via live metadata (decimals from the asset_type's OWN metadata, not
        symbol). Assets with no resolvable decimals are omitted (skipped — never
        guessed)."""
        out: dict[str, TokenRef] = {}
        need: list[str] = []
        for a in asset_types:
            pinned = _PINNED_ASSETS.get(a)
            if pinned is not None:
                sym, dec, cg = pinned
                out[a] = TokenRef(chain=Chain.aptos, contract=a, symbol=sym,
                                  decimals=dec, coingecko_id=cg)
            else:
                need.append(a)
        if need:
            meta = self.client.asset_metadata(need)
            for a, m in meta.items():
                dec = _to_int(m.get("decimals"))
                if dec is None or dec < 0 or dec > 255:
                    continue  # unresolvable decimals -> skip this asset
                sym = str(m.get("symbol") or a.rsplit("::", 1)[-1])[:32]
                out[a] = TokenRef(chain=Chain.aptos, contract=a, symbol=sym,
                                  decimals=dec, coingecko_id=None)
        return out

    # ----- edge reconstruction -----

    def _build_edges(
        self, address: Address, start_block: int, *, outflow: bool, native: bool,
    ) -> list[dict[str, Any]]:
        if not is_valid_aptos_address(address):
            return []
        focus = normalize_aptos_address(address)
        try:
            legs_raw = (
                self.client.withdraw_activities(focus, limit=self._max_legs)
                if outflow else
                self.client.deposit_activities(focus, limit=self._max_legs)
            )
        except AptosIndexerError as exc:
            log.warning("aptos: activity fetch failed for %s: %s", focus, exc)
            return []

        if len(legs_raw) >= self._max_legs:
            log.warning(
                "aptos: %s activity fetch for %s hit the %d-row budget — older "
                "activity NOT seen, trace may be INCOMPLETE; raise "
                "RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                "outflow" if outflow else "inflow", focus, self._max_legs,
            )

        # focus's own legs of interest: {(version, asset): (amount, block_time)}
        focus_legs: dict[tuple[int, str], tuple[int, datetime]] = {}
        for r in legs_raw:
            v = _to_int(r.get("transaction_version"))
            asset = r.get("asset_type")
            amt = _to_int(r.get("amount"))
            if v is None or not isinstance(asset, str) or amt is None or amt <= 0:
                continue
            if native != (asset in _APT_ASSET_TYPES):
                continue
            bt = _parse_ts(r.get("transaction_timestamp"))
            if int(bt.timestamp()) < start_block:
                continue
            focus_legs[(v, asset)] = (amt, bt)
        if not focus_legs:
            return []

        versions = sorted({v for (v, _a) in focus_legs})
        try:
            # Counterparties can outnumber the focus's own legs (several parties
            # per version) — give the (chunked, paginated) fetch room up to the
            # same per-address budget so they aren't truncated below it.
            all_rows = self.client.activities_at_versions(
                versions, limit=self._max_legs,
            )
        except AptosIndexerError as exc:
            log.warning("aptos: counterparty fetch failed for %s: %s", focus, exc)
            return []
        if len(all_rows) >= self._max_legs:
            log.warning(
                "aptos: counterparty fetch for %s hit the %d-row budget across "
                "%d version(s) — some counterparties NOT seen, edges may be "
                "INCOMPLETE; raise RECUPERO_MAX_TRANSFERS_PER_ADDRESS.",
                focus, self._max_legs, len(versions),
            )

        # group counterparty activities by (version, asset)
        groups: dict[tuple[int, str], dict[str, list[tuple[str, int]]]] = {}
        for r in all_rows:
            v = _to_int(r.get("transaction_version"))
            asset = r.get("asset_type")
            amt = _to_int(r.get("amount"))
            owner = r.get("owner_address")
            if (v is None or not isinstance(asset, str) or amt is None
                    or not isinstance(owner, str) or not is_valid_aptos_address(owner)):
                continue
            g = groups.setdefault((v, asset), {"withdraws": [], "deposits": []})
            norm_owner = normalize_aptos_address(owner)
            if _is_withdraw(r.get("type")):
                g["withdraws"].append((norm_owner, amt))
            elif _is_deposit(r.get("type")):
                g["deposits"].append((norm_owner, amt))

        tokens = self._resolve_tokens({a for (_v, a) in focus_legs})

        edges: list[dict[str, Any]] = []
        for (v, asset), (focus_amt, bt) in focus_legs.items():
            token = tokens.get(asset)
            if token is None:
                continue
            grp = groups.get((v, asset))
            if grp is None:
                continue
            withdrawers = {o for o, _a in grp["withdraws"]}
            if outflow:
                # focus must be the SOLE withdrawer (else ambiguous attribution).
                if focus not in withdrawers or len(withdrawers) != 1:
                    continue
                for owner, amt in grp["deposits"]:
                    if owner == focus or amt <= 0:
                        continue
                    edges.append(self._edge(v, bt, focus, owner, token, amt))
            else:
                # inbound: a single non-focus withdrawer is the unambiguous source.
                other_withdrawers = withdrawers - {focus}
                if len(other_withdrawers) != 1:
                    continue
                from_owner = next(iter(other_withdrawers))
                edges.append(self._edge(v, bt, from_owner, focus, token, focus_amt))
        return edges

    def _edge(
        self, version: int, block_time: datetime, frm: str, to: str,
        token: TokenRef, amount_raw: int,
    ) -> dict[str, Any]:
        return {
            "chain": Chain.aptos,
            "tx_hash": str(version),  # Aptos txs are addressed by ledger version
            "block_number": version,  # transaction_version IS the ledger ordinal
            "block_time": block_time,
            "log_index": None,
            "from": frm,
            "to": to,
            "token": token,
            "amount_raw": int(amount_raw),
            "explorer_url": self.explorer_tx_url(str(version)),
            "_native_source": "aptos_fa_activity",
        }

    # ----- transfer fetching -----

    def fetch_native_outflows(
        self, from_address: Address, start_block: int = 0,
    ) -> list[dict[str, Any]]:
        return self._build_edges(from_address, start_block, outflow=True, native=True)

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int = 0,
    ) -> list[dict[str, Any]]:
        return self._build_edges(from_address, start_block, outflow=True, native=False)

    def fetch_native_inflows(
        self, to_address: Address, start_block: int = 0,
        *, max_results: int | None = None,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return self._build_edges(to_address, start_block, outflow=False, native=True)

    def fetch_erc20_inflows(
        self, to_address: Address, start_block: int = 0,
        *, max_results: int | None = None,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return self._build_edges(to_address, start_block, outflow=False, native=False)

    # ----- evidence + explorer -----

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Anchor the receipt to the REAL block time. The Indexer carries
        ``transaction_timestamp`` per ledger version, so the chain-of-custody
        record gets a true block time instead of a placeholder. Best-effort: a
        transport/GraphQL failure (or an un-indexed version) falls back to the
        unknown-time sentinel (epoch 0, raw_* empty) rather than raising — a
        transient blip never breaks evidence writing, and we never fabricate a
        time we couldn't fetch. ``tx_hash`` is the ledger version (Aptos txs are
        addressed by version)."""
        version = _to_int(tx_hash)
        block_time = datetime.fromtimestamp(0, tz=UTC)
        raw: dict[str, Any] = {}
        if version is not None:
            try:
                meta = self.client.transaction_meta(version)
            except AptosIndexerError as exc:
                log.warning("aptos: evidence ts fetch failed for v%s: %s", version, exc)
                meta = None
            if isinstance(meta, dict):
                bt = _parse_ts(meta.get("transaction_timestamp"))
                if int(bt.timestamp()) > 0:  # real time fetched (not epoch-0 fallback)
                    block_time = bt
                raw = meta
        return EvidenceReceipt(
            chain=Chain.aptos,
            tx_hash=tx_hash,
            block_number=version or 0,
            block_time=block_time,
            raw_transaction=raw,
            raw_receipt={},
            raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from=self.client.base_url,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_EXPLORER_TX}{tx_hash}{_EXPLORER_NET}"

    def explorer_address_url(self, address: Address) -> str:
        return f"{_EXPLORER_ADDR}{address}{_EXPLORER_NET}"


__all__ = (
    "AptosAdapter",
    "APT_COIN_TYPE",
    "APT_FA_TYPE",
    "APT_SYMBOL",
    "APT_DECIMALS",
    "APT_COINGECKO_ID",
)
