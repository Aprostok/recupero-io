"""MistTrack (SlowMist) keyed attribution provider.

MistTrack's open API is the highest-relevance paid source for this tool's case
profile — best-in-class on Tron / USDT-TRC20, Asian exchanges, and
scam / pig-butchering attribution. It is query-BY-ADDRESS:

    GET https://openapi.misttrack.io/v1/address_labels?coin=<COIN>&address=<ADDR>&api_key=<KEY>
    GET https://openapi.misttrack.io/v1/risk_score?coin=<COIN>&address=<ADDR>&api_key=<KEY>

Activated by setting ``MISTTRACK_API_KEY``. With no key this module is inert
(``resolve_attribution`` returns ``None``, makes no network call) so the deploy
behaves exactly as before. Output is a LOW-confidence ``CandidateLabel`` for the
review→promote pipeline — never auto-trusted.

Shapes confirmed from MistTrack's published docs (docs.misttrack.io): the
auth param is ``api_key``; a successful ``address_labels`` response is
``{"success": true, "data": {"label_list": [<entity-name + tags>],
"label_type": "exchange"|"defi"|"mixer"|"nft"|""}}``; the auth-error envelope
``{"success": false, "msg": "InvalidApiKey"}`` was verified live. The parser is
still deliberately defensive (unrecognized shape → ``None``) so any drift yields
no label rather than a wrong one — confirm exact fields on the first keyed call.
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Any

import httpx

log = logging.getLogger(__name__)

_MISTTRACK_HOST = "openapi.misttrack.io"
_MISTTRACK_BASE = f"https://{_MISTTRACK_HOST}/v1"
_API_KEY_ENV = "MISTTRACK_API_KEY"

# Chain → MistTrack coin code. MistTrack keys queries by coin; an unmapped
# chain → we skip rather than guess a code.
_CHAIN_TO_COIN: dict[str, str] = {
    "ethereum": "ETH",
    "tron": "TRX",
    "bitcoin": "BTC",
    "bsc": "BSC",
    "polygon": "MATIC",
    "arbitrum": "Arbitrum",
    "solana": "SOL",
}

# Label tokens (lower-cased, substring match) that mark a centralized exchange.
_EXCHANGE_TOKENS = (
    "binance", "coinbase", "kraken", "kucoin", "okx", "okex", "bybit",
    "bitfinex", "huobi", "htx", "gate", "bitget", "mexc", "gemini",
    "bitstamp", "poloniex", "upbit", "bithumb", "exchange",
)
# Label tokens that mark a malicious / scam / drainer address.
_MALICIOUS_TOKENS = (
    "phish", "scam", "hack", "theft", "stolen", "drainer", "fake",
    "malicious", "fraud", "ponzi", "rug",
)


def misttrack_enabled() -> bool:
    """True when a MistTrack API key is configured."""
    return bool((os.environ.get(_API_KEY_ENV, "") or "").strip())


def _get(path: str, params: dict[str, Any], *, http_client: httpx.Client | None) -> dict | None:
    """Host-pinned GET. The api_token is in the query string (MistTrack's
    scheme) but is NEVER logged. Returns parsed JSON dict or None on any
    failure."""
    client = http_client or httpx.Client(timeout=httpx.Timeout(connect=8.0, read=15.0,
                                                               write=15.0, pool=15.0))
    owns = http_client is None
    try:
        url = f"{_MISTTRACK_BASE}{path}"
        # SSRF belt: only ever talk to the pinned MistTrack host.
        if httpx.URL(url).host != _MISTTRACK_HOST:
            return None
        resp = client.get(url, params=params, follow_redirects=False)
        if resp.status_code != 200:
            log.debug("misttrack %s → HTTP %d", path, resp.status_code)
            return None
        body = resp.json()
        return body if isinstance(body, dict) else None
    except Exception as exc:  # noqa: BLE001
        log.debug("misttrack %s failed: %s", path, exc)
        return None
    finally:
        if owns:
            with contextlib.suppress(Exception):
                client.close()


def _labels_from_data(data: Any) -> list[str]:
    """Defensively pull label strings out of MistTrack's ``data`` (list of str,
    list of dict with name/label, or a dict). Unknown → []."""
    labels: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                labels.append(item)
            elif isinstance(item, dict):
                v = item.get("label") or item.get("name") or item.get("type")
                if isinstance(v, str):
                    labels.append(v)
    elif isinstance(data, dict):
        for k in ("label_list", "labels", "label"):
            v = data.get(k)
            if isinstance(v, list):
                labels.extend(x for x in v if isinstance(x, str))
            elif isinstance(v, str):
                labels.append(v)
    return labels


def _categorize(labels: list[str], label_type: str | None) -> tuple[str, str] | None:
    """Map MistTrack labels → (category, representative_name) for the candidate
    pipeline, or None when no pipeline-supported category applies.

    ``label_type`` is MistTrack's structured class (exchange/defi/mixer/nft);
    ``labels`` are the entity-name + tag strings. Malicious tags (rare in
    address_labels — risk_score is the dedicated risk endpoint) → scam_drainer;
    an ``exchange`` type or an exchange-name tag → exchange_hot_wallet."""
    lt = (label_type or "").strip().lower()
    name = labels[0] if labels else (lt or "MistTrack entity")
    for lab in labels:
        if any(tok in lab.lower() for tok in _MALICIOUS_TOKENS):
            return "scam_drainer", lab
    if lt == "exchange":
        return "exchange_hot_wallet", name
    for lab in labels:
        if any(tok in lab.lower() for tok in _EXCHANGE_TOKENS):
            return "exchange_hot_wallet", lab
    return None


def resolve_attribution(
    address: str,
    *,
    chain: str = "ethereum",
    api_key: str | None = None,
    http_client: httpx.Client | None = None,
) -> Any | None:
    """Resolve ``address`` to a LOW-confidence ``CandidateLabel`` via MistTrack,
    or ``None`` (no key / unmapped chain / no usable label / any failure).

    Returns a ``labels.auto_ingest.CandidateLabel`` so it drops straight into
    ``persist_candidates`` for operator review. Never raises; never fabricates.
    """
    key = (api_key or os.environ.get(_API_KEY_ENV, "") or "").strip()
    if not key or not address:
        return None
    coin = _CHAIN_TO_COIN.get(chain.lower())
    if coin is None:
        return None

    body = _get(
        "/address_labels",
        {"coin": coin, "address": address, "api_key": key},
        http_client=http_client,
    )
    if not body or body.get("success") is not True:
        return None
    data = body.get("data")
    labels = _labels_from_data(data)
    label_type = data.get("label_type") if isinstance(data, dict) else None
    cat = _categorize(labels, label_type)
    if cat is None:
        return None
    category, name = cat

    from recupero.labels.auto_ingest import CandidateLabel
    try:
        return CandidateLabel(
            address=address.lower() if address.startswith("0x") else address,
            chain=chain.lower(),
            proposed_category=category,
            proposed_name=f"MistTrack: {name}"[:200],
            source="misttrack",
            source_url="https://misttrack.io/",
            raw_metadata={"misttrack_labels": labels},
        )
    except ValueError as exc:
        log.debug("misttrack: CandidateLabel rejected for %s: %s", address, exc)
        return None


def enrich_addresses(
    addresses: list[str], *, chain: str = "ethereum",
) -> list[Any]:
    """Resolve a batch of addresses (e.g. the attribution-coverage labeling
    targets) into CandidateLabels. Inert + empty when no key is set."""
    if not misttrack_enabled():
        return []
    out: list[Any] = []
    seen: set[str] = set()
    for addr in addresses:
        if not isinstance(addr, str) or addr in seen:
            continue
        seen.add(addr)
        c = resolve_attribution(addr, chain=chain)
        if c is not None:
            out.append(c)
    return out
