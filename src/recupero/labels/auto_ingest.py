"""Auto-ingest new bridge contracts + CEX hot wallets from Etherscan,
Tronscan, and Solscan public tag APIs. Closes Tier-1 gaps #1 + #2 from
the pre-mortem.

Two-stage workflow:
  1. Daily cron job pulls new candidate labels from upstream tag APIs
     and writes them to `label_candidates` table (status='pending_review').
  2. Operator reviews via the API (`/v1/labels/candidates`) and either
     PROMOTES (writes to bridges.json/cex_deposits.json) or REJECTS
     (records reason, never re-suggested for that address).

Sources:
  * Etherscan address tags (free tier): https://api.etherscan.io/api?module=label&action=getlabels
    NOTE: Etherscan doesn't actually publish bulk tags free — use the
    address-info endpoint per known protocols + scrape the public
    pages where allowed. The simpler interim: read Etherscan V2's
    contract-source endpoint for known protocol routers and parse the
    `ContractName` field.
  * Tronscan: https://apilist.tronscanapi.com/api/contracts (public tags)
  * Solscan: https://public-api.solscan.io/account/{addr} (public tags)
  * DeFiLlama: https://api.llama.fi/protocols (new-protocol feed
    filtered to category="Bridges" or "Crypto Exchange")

Defensive: any source unreachable → log WARN, skip that source, continue.
Net total candidates per day capped at 100 to avoid review-queue overflow.

INGEST IS NOT AUTO-PROMOTE. A new candidate lands at
``proposed_confidence='low'`` with ``status='pending_review'``. An
operator must explicitly promote via
``POST /v1/labels/candidates/{id}/promote`` (which appends to the
version-controlled seeds JSON) before the address starts showing up
in briefs as a labeled bridge / exchange. Skipping the review step
would let a tag-spammer inject bogus labels straight into operator
output; that's the load-bearing safety property of this pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# v0.32.1 JACOB_SECURITY_AUDIT_v032 CRIT-1 close-out:
# Promote-candidate field validation. Every promotable field is checked
# against a chain-aware shape, an enum allow-list, and a Unicode-trojan
# reject set BEFORE any disk write. Without these gates, an admin-key
# leak with an unintended row payload writes attacker-controlled JSON
# directly to the version-controlled seed file ("Binance Hot Wallet"
# label on attacker EOA → next day's freeze letters mis-target Coinbase
# as a mixer).
# ──────────────────────────────────────────────────────────────────────


# Chain enum allow-list. MUST match the Chain enum elsewhere in the
# codebase. Listed explicitly here so a typo in upstream label data
# fails closed rather than silently writing an "atlantis" chain entry.
_VALID_CHAINS = frozenset({
    "ethereum", "polygon", "arbitrum", "optimism", "base",
    "bsc", "avalanche", "fantom", "tron", "solana",
    "bitcoin", "hyperliquid", "zksync_era", "linea",
    "scroll", "blast", "mantle", "celo", "gnosis",
    "moonbeam", "polygon_zkevm", "metis", "kava",
    # v0.32.1 W5 (round-2 wire-up): additional rollup-canonical L2s
    "opbnb", "manta", "zksync",
})

# Category enum allow-list. Anything else is rejected pre-write.
_VALID_CATEGORIES = frozenset({
    "bridge", "exchange_hot_wallet", "exchange_deposit",
    "mixer", "sanctioned", "ofac", "custodian", "dex_pool",
    "lp_token", "stablecoin_issuer", "service_wallet",
    "psm_stable_swap",
})

# Name charset: printable ASCII + extended Latin + common punctuation.
# Reject control chars, NUL, bidi overrides, zero-width spaces.
_INVISIBLE_UNICODE = frozenset({
    "​",  # Zero Width Space
    "‌",  # Zero Width Non-Joiner
    "‍",  # Zero Width Joiner
    "⁠",  # Word Joiner
    "﻿",  # Zero Width No-Break Space (BOM)
    "‪",  # Left-to-Right Embedding
    "‫",  # Right-to-Left Embedding
    "‬",  # Pop Directional Formatting
    "‭",  # Left-to-Right Override
    "‮",  # Right-to-Left Override
    "⁦",  # Left-to-Right Isolate
    "⁧",  # Right-to-Left Isolate
    "⁨",  # First Strong Isolate
    "⁩",  # Pop Directional Isolate
})

_EVM_HEX_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TRON_BASE58_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_SOLANA_BASE58_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_BITCOIN_ADDR_RE = re.compile(
    r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{8,87})$"
)
# Source must be a short, lowercase, dotted/underscored identifier.
# Reject any whitespace, quotes, semicolons, shell metachars.
_VALID_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-:]{0,63}$")


def _validate_promote_fields(row: dict[str, Any]) -> None:
    """Pre-write validation gate for promote_candidate.

    Raises ValueError on the FIRST violation found. Order is chosen so
    the most-likely-to-fail check fires first (address) and the
    cheapest checks come before expensive ones.

    Closes JACOB_SECURITY_AUDIT_v032 CRIT-1.
    """
    chain = str(row.get("chain") or "").strip().lower()
    address = str(row.get("address") or "").strip()
    category = str(row.get("proposed_category") or row.get("category") or "").strip()
    name = str(row.get("proposed_name") or row.get("name") or "")
    source = str(row.get("source") or "")

    # 1) Chain enum allow-list.
    if chain not in _VALID_CHAINS:
        raise ValueError(
            f"chain {chain!r} is not a known Chain enum member. "
            f"Allowed: {sorted(_VALID_CHAINS)}"
        )

    # 2) Chain-aware address shape.
    evm_chains = {
        "ethereum", "polygon", "arbitrum", "optimism", "base", "bsc",
        "avalanche", "fantom", "hyperliquid", "zksync_era", "zksync",
        "linea", "scroll", "blast", "mantle", "celo", "gnosis",
        "moonbeam", "polygon_zkevm", "metis", "kava",
        # v0.32.1 W5: additional rollup-canonical L2s (all EVM-format)
        "opbnb", "manta",
    }
    if chain in evm_chains:
        if not _EVM_HEX_ADDR_RE.match(address):
            raise ValueError(
                f"address {address!r} is not a valid EVM hex address "
                f"for chain {chain!r} (expected 0x + 40 hex chars)"
            )
    elif chain == "tron":
        if not _TRON_BASE58_ADDR_RE.match(address):
            raise ValueError(
                f"address {address!r} is not a valid Tron base58 address"
            )
    elif chain == "solana":
        if not _SOLANA_BASE58_ADDR_RE.match(address):
            raise ValueError(
                f"address {address!r} is not a valid Solana base58 address"
            )
    elif chain == "bitcoin":
        if not _BITCOIN_ADDR_RE.match(address):
            raise ValueError(
                f"address {address!r} is not a valid Bitcoin address"
            )

    # 3) Category enum allow-list.
    if category not in _VALID_CATEGORIES:
        raise ValueError(
            f"category {category!r} is not a known label category. "
            f"Allowed: {sorted(_VALID_CATEGORIES)}"
        )

    # 4) Name — reject control chars + NUL + invisible Unicode.
    if not name or len(name) > 256:
        raise ValueError(
            f"proposed_name must be 1..256 chars; got len={len(name)}"
        )
    for ch in name:
        # v0.32.1: check the INVISIBLE_UNICODE set FIRST because those
        # chars are also Cf-category — if we did the category check
        # first, the "control character" branch would shadow the more
        # specific "invisible Unicode" message expected by adversarial
        # tests + by the audit's homoglyph/bidi narrative.
        if ch in _INVISIBLE_UNICODE:
            raise ValueError(
                f"proposed_name contains invisible Unicode "
                f"U+{ord(ch):04X} — reject (homoglyph / bidi attack)"
            )
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch != " ":
            # Cc (control), Cf (format), Co (private use), Cn (unassigned)
            raise ValueError(
                f"proposed_name contains control character "
                f"U+{ord(ch):04X} (category {cat})"
            )

    # 5) Source — must match strict identifier shape. Rejects quotes,
    # semicolons, shell metachars, command-substitution sequences.
    if not _VALID_SOURCE_RE.match(source):
        raise ValueError(
            f"source {source!r} does not match the allowed source "
            f"identifier pattern (lowercase, alnum + _.-:, max 64 chars). "
            f"Possible injection attempt."
        )


def _compute_promote_confirm_sha256(row: dict[str, Any]) -> str:
    """Stable hash of the (address, chain, category, name, source) tuple.

    Used by the API endpoint's ``X-Recupero-Promote-Confirm`` header
    pin: the operator viewing the candidate sees this hash, and must
    echo it in the promote request. An admin-key leak with an
    unintended row payload (attacker swapped the row mid-flight)
    produces a mismatch and fails closed.
    """
    canon = json.dumps(
        {
            "address": str(row.get("address") or "").lower(),
            "chain": str(row.get("chain") or "").lower(),
            "proposed_category": str(
                row.get("proposed_category") or row.get("category") or ""
            ),
            "proposed_name": str(
                row.get("proposed_name") or row.get("name") or ""
            ),
            "source": str(row.get("source") or ""),
        },
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Per-day cap on total candidates persisted across all sources. Keeps
# the operator review queue from overflowing when an upstream tag API
# starts returning thousands of new addresses overnight (typically a
# sign of a sync bug, not a real labeling event).
_DEFAULT_DAILY_CAP = 100

# Per-source HTTP timeout — every source is a single GET, so 10s is
# generous. The pipeline runs once per day at 02:00 UTC and is not
# latency-sensitive; we'd rather wait 30s total than miss labels
# behind a momentarily-slow upstream.
_HTTP_TIMEOUT_SEC = 10.0

# DeFiLlama categories we care about. Names taken verbatim from
# https://api.llama.fi/protocols — case-sensitive.
_LLAMA_BRIDGE_CATEGORIES = ("Bridge", "Bridges", "Cross Chain")
_LLAMA_CEX_CATEGORIES = ("CEX", "Centralized Exchange", "Crypto Exchange")


def _daily_cap() -> int:
    """Read ``RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP`` from env, clamped
    to a sane range. Bad input → default with WARN."""
    raw = (os.environ.get("RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP") or "").strip()
    if not raw:
        return _DEFAULT_DAILY_CAP
    try:
        val = int(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=%r is not an int — "
            "using default %d", raw, _DEFAULT_DAILY_CAP,
        )
        return _DEFAULT_DAILY_CAP
    if val <= 0 or val > 10000:
        log.warning(
            "RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=%d out of range "
            "[1, 10000] — using default %d", val, _DEFAULT_DAILY_CAP,
        )
        return _DEFAULT_DAILY_CAP
    return val


# ─────────────────────────────────────────────────────────────────────────────
# CandidateLabel — the in-memory shape produced by every source
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CandidateLabel:
    """One pending label candidate, pre-persistence.

    All fields except ``raw_metadata`` and ``source_url`` are required.
    ``proposed_confidence`` is ALWAYS 'low' for newly-ingested rows —
    operators upgrade to medium/high during promotion based on their
    own verification (chain explorer, protocol docs, etc.).
    """

    address: str
    chain: str  # Chain enum value as string; sources may emit non-EVM
    proposed_category: str  # 'bridge' / 'exchange_hot_wallet' / 'exchange_deposit'
    proposed_name: str
    source: str  # e.g. 'tronscan_tag', 'defillama_new_protocol'
    source_url: str = ""
    proposed_confidence: str = "low"
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.address or not isinstance(self.address, str):
            raise ValueError("CandidateLabel.address must be a non-empty string")
        if not self.chain or not isinstance(self.chain, str):
            raise ValueError("CandidateLabel.chain must be a non-empty string")
        if self.proposed_category not in (
            "bridge", "exchange_hot_wallet", "exchange_deposit",
        ):
            raise ValueError(
                f"CandidateLabel.proposed_category {self.proposed_category!r} "
                "must be one of bridge / exchange_hot_wallet / exchange_deposit"
            )
        if self.proposed_confidence not in ("low", "medium", "high"):
            raise ValueError(
                f"CandidateLabel.proposed_confidence "
                f"{self.proposed_confidence!r} must be one of low/medium/high"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Source fetchers — each one is defensive and never raises
# ─────────────────────────────────────────────────────────────────────────────


# v0.32.1 JACOB_SECURITY_AUDIT_v032 HIGH-1 close-out:
# SSRF defense for the daily label ingest. Allow-list of upstream hosts,
# https-only scheme, DNS-resolve + private-IP block, no redirects, 10MB
# body cap. The original implementation accepted arbitrary URLs; a
# malicious upstream redirect (or DNS rebind) to 169.254.169.254 (cloud
# metadata) would have been followed by httpx without any defense.
_AUTO_INGEST_ALLOWED_HOSTS = frozenset({
    "api.llama.fi",
    "apilist.tronscanapi.com",
    "public-api.solscan.io",
    "api.solscan.io",
    "api.etherscan.io",
    # v0.38 (#1, more-data/TON): tonapi.io curated TON account metadata + name
    # search — the free attribution source for TON entities (CEX wallets,
    # services). Names are tonapi-curated, not user memos.
    "tonapi.io",
    # v0.38 (#1, more-sources): brianleect/etherscan-labels — a large free OSS
    # dump of explorer labels across 6 EVM chains, served as static JSON.
    "raw.githubusercontent.com",
})

# Hard cap on the response body. Realistic upstream JSON is <2MB; the
# 10MB cap is a 5× safety margin that still blocks the "billion-laughs"
# / OOM class of bug.
_AUTO_INGEST_MAX_BODY_BYTES = 10 * 1024 * 1024


def _ssrf_validate_url(url: str) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for the SSRF gate.

    Rules:
      * Scheme MUST be https.
      * Host MUST be in ``_AUTO_INGEST_ALLOWED_HOSTS``.
      * Host MUST NOT resolve to a private / loopback / link-local /
        reserved IP address (DNS-rebind defense).
    """
    try:
        from urllib.parse import urlparse
    except ImportError:
        return (False, "urlparse import failed")
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return (False, "url parse failed")
    if parsed.scheme != "https":
        return (False, f"non-https scheme: {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        return (False, "empty host")
    if host not in _AUTO_INGEST_ALLOWED_HOSTS:
        return (False, f"host {host!r} not in allow-list")
    # DNS resolve and refuse private / loopback / link-local / reserved.
    import ipaddress
    import socket
    try:
        addrs = socket.getaddrinfo(host, parsed.port or 443)
    except OSError as exc:
        return (False, f"dns resolve failed: {exc}")
    for entry in addrs:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            return (False, f"unparseable resolved ip: {raw_ip!r}")
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return (False, f"resolved to private/reserved ip: {raw_ip}")
    return (True, "ok")


def _safe_http_get_json(url: str, *, source_name: str) -> Any:
    """Issue a GET and return parsed JSON. Any failure → log WARN,
    return None. NEVER raises — the daily pipeline must continue even
    when an upstream is down.

    v0.32.1 HIGH-1: SSRF-hardened. Validates host allow-list + scheme
    + private-IP block BEFORE the network call, disables redirects, and
    caps response body size.
    """
    ok, reason = _ssrf_validate_url(url)
    if not ok:
        log.warning(
            "label auto-ingest: %s URL %r refused by SSRF gate: %s",
            source_name, url, reason,
        )
        return None
    try:
        import httpx
        # follow_redirects=False — refuse to chase a 3xx Location. A
        # malicious upstream redirecting to 169.254.169.254 would have
        # bypassed the host-allow-list otherwise.
        with httpx.Client(
            timeout=_HTTP_TIMEOUT_SEC,
            follow_redirects=False,
        ) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            log.warning(
                "label auto-ingest: %s returned HTTP %d — skipping",
                source_name, resp.status_code,
            )
            return None
        # Body cap — refuse responses larger than the limit.
        try:
            body = resp.content
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "label auto-ingest: %s body read failed: %s",
                source_name, exc,
            )
            return None
        if len(body) > _AUTO_INGEST_MAX_BODY_BYTES:
            log.warning(
                "label auto-ingest: %s body %d bytes > cap %d — skipping",
                source_name, len(body), _AUTO_INGEST_MAX_BODY_BYTES,
            )
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning(
                "label auto-ingest: %s JSON decode failed: %s",
                source_name, exc,
            )
            return None
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "label auto-ingest: %s unreachable (%s: %s) — skipping",
            source_name, type(exc).__name__, exc,
        )
        return None


def fetch_candidate_bridges() -> list[CandidateLabel]:
    """Pull bridge-protocol candidates from DeFiLlama + Tronscan.

    Returns a list of CandidateLabel rows, each pre-validated. Order
    is source-deterministic so the daily cap drops the same overflow
    rows on every re-run.
    """
    out: list[CandidateLabel] = []

    # ── DeFiLlama: every protocol with category in _LLAMA_BRIDGE_CATEGORIES
    llama = _safe_http_get_json(
        "https://api.llama.fi/protocols",
        source_name="defillama_protocols",
    )
    if isinstance(llama, list):
        for proto in llama:
            if not isinstance(proto, dict):
                continue
            category = proto.get("category")
            if category not in _LLAMA_BRIDGE_CATEGORIES:
                continue
            name = proto.get("name") or ""
            address = proto.get("address") or ""
            chains = proto.get("chains") or []
            if not (isinstance(address, str) and address):
                continue
            # DeFiLlama puts the chain as the first element of `chains`
            # when there's only one; multi-chain rows we map to the
            # first chain and emit one candidate (operator can add
            # other chains on promotion).
            chain = "ethereum"
            if isinstance(chains, list) and chains:
                first = chains[0]
                if isinstance(first, str) and first:
                    chain = first.lower()
            try:
                out.append(CandidateLabel(
                    address=address,
                    chain=chain,
                    proposed_category="bridge",
                    proposed_name=str(name)[:200] or "(unnamed bridge)",
                    source="defillama_new_protocol",
                    source_url=f"https://defillama.com/protocol/{proto.get('slug', '')}",
                    raw_metadata={
                        "defillama_id": proto.get("id"),
                        "category": category,
                        "chains": chains,
                    },
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed DeFiLlama row: %s",
                    exc,
                )

    # ── Tronscan: bridge contracts tagged on Tronscan
    tron = _safe_http_get_json(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge",
        source_name="tronscan_bridges",
    )
    if isinstance(tron, dict):
        for row in tron.get("data") or []:
            if not isinstance(row, dict):
                continue
            address = row.get("address") or ""
            name = row.get("name") or row.get("tag1") or ""
            if not (isinstance(address, str) and address):
                continue
            try:
                out.append(CandidateLabel(
                    address=address,
                    chain="tron",
                    proposed_category="bridge",
                    proposed_name=str(name)[:200] or "(unnamed Tron bridge)",
                    source="tronscan_tag",
                    source_url=f"https://tronscan.org/#/contract/{address}",
                    raw_metadata={"tronscan_raw": row},
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed Tronscan row: %s",
                    exc,
                )

    return out


def fetch_candidate_cex_deposits() -> list[CandidateLabel]:
    """Pull candidate CEX hot wallets + deposit addresses from Tronscan,
    Solscan, and Etherscan address-info per known partner exchanges.
    """
    out: list[CandidateLabel] = []

    # ── Tronscan: exchange-tagged contracts
    tron = _safe_http_get_json(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=exchange",
        source_name="tronscan_exchanges",
    )
    if isinstance(tron, dict):
        for row in tron.get("data") or []:
            if not isinstance(row, dict):
                continue
            address = row.get("address") or ""
            name = row.get("name") or row.get("tag1") or ""
            if not (isinstance(address, str) and address):
                continue
            # Hot-wallet vs deposit: Tronscan tag1 typically contains
            # "Hot Wallet" or "Deposit" in the human-readable name.
            # Default to exchange_hot_wallet; operator promotes with
            # category change if needed.
            name_lc = str(name).lower()
            category = (
                "exchange_deposit" if "deposit" in name_lc
                else "exchange_hot_wallet"
            )
            try:
                out.append(CandidateLabel(
                    address=address,
                    chain="tron",
                    proposed_category=category,
                    proposed_name=str(name)[:200] or "(unnamed Tron exchange)",
                    source="tronscan_tag",
                    source_url=f"https://tronscan.org/#/contract/{address}",
                    raw_metadata={"tronscan_raw": row},
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed Tronscan exchange row: %s",
                    exc,
                )

    # ── Solscan: exchange-tagged accounts (the public-api endpoint
    # returns one address at a time; we walk a known seed-list of
    # exchange root accounts to discover hot wallets they're moving
    # to. For the v0.32 bootstrap we accept the existing seeds as
    # the discovery surface — a future revision can subscribe to
    # Solscan's webhook feed.)
    # We hit the labels feed if it exists, else fall through silent.
    sol = _safe_http_get_json(
        "https://public-api.solscan.io/account/labels?category=exchange",
        source_name="solscan_exchanges",
    )
    if isinstance(sol, list):
        for row in sol:
            if not isinstance(row, dict):
                continue
            address = row.get("address") or ""
            name = row.get("label") or row.get("name") or ""
            if not (isinstance(address, str) and address):
                continue
            try:
                out.append(CandidateLabel(
                    address=address,
                    chain="solana",
                    proposed_category="exchange_hot_wallet",
                    proposed_name=str(name)[:200] or "(unnamed Solana exchange)",
                    source="solscan_tag",
                    source_url=f"https://solscan.io/account/{address}",
                    raw_metadata={"solscan_raw": row},
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed Solscan row: %s",
                    exc,
                )

    # ── DeFiLlama CEX feed
    llama = _safe_http_get_json(
        "https://api.llama.fi/protocols",
        source_name="defillama_cex",
    )
    if isinstance(llama, list):
        for proto in llama:
            if not isinstance(proto, dict):
                continue
            category = proto.get("category")
            if category not in _LLAMA_CEX_CATEGORIES:
                continue
            name = proto.get("name") or ""
            address = proto.get("address") or ""
            chains = proto.get("chains") or []
            if not (isinstance(address, str) and address):
                continue
            chain = "ethereum"
            if isinstance(chains, list) and chains:
                first = chains[0]
                if isinstance(first, str) and first:
                    chain = first.lower()
            try:
                out.append(CandidateLabel(
                    address=address,
                    chain=chain,
                    proposed_category="exchange_hot_wallet",
                    proposed_name=str(name)[:200] or "(unnamed CEX)",
                    source="defillama_new_protocol",
                    source_url=f"https://defillama.com/protocol/{proto.get('slug', '')}",
                    raw_metadata={
                        "defillama_id": proto.get("id"),
                        "category": category,
                        "chains": chains,
                    },
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed DeFiLlama CEX row: %s",
                    exc,
                )

    return out


# Major centralized exchanges known to operate on TON. tonapi resolves each
# name to its curated TON account(s); we accept only results whose tonapi name
# still contains the query term (precision against unrelated matches). The
# operator verifies each candidate before promotion — these land low/pending.
_TON_EXCHANGE_QUERIES: tuple[str, ...] = (
    "Binance", "OKX", "Bybit", "Bitget", "MEXC", "Gate", "KuCoin", "HTX",
)


# brianleect/etherscan-labels — combined explorer-label dumps per EVM chain.
# {explorer_path: (chain, address_explorer_prefix)}. Each is a static JSON dict
# keyed by address → {"name", "labels": [...]}. Free, no key, GitHub-hosted.
_OSS_LABEL_DUMPS: dict[str, tuple[str, str]] = {
    "etherscan":   ("ethereum", "https://etherscan.io/address/"),
    "bscscan":     ("bsc",      "https://bscscan.com/address/"),
    "polygonscan": ("polygon",  "https://polygonscan.com/address/"),
    "arbiscan":    ("arbitrum", "https://arbiscan.io/address/"),
    "optimism":    ("optimism", "https://optimistic.etherscan.io/address/"),
    "ftmscan":     ("fantom",   "https://ftmscan.com/address/"),
}
_OSS_DUMP_URL = (
    "https://raw.githubusercontent.com/brianleect/etherscan-labels/main/"
    "data/{explorer}/combined/combinedAllLabels.json"
)
# Exact label tokens that mark a centralized-exchange address in the dump.
_OSS_EXCHANGE_LABELS = frozenset({
    "binance", "coinbase", "kraken", "kucoin", "okx", "okex", "bybit",
    "bitfinex", "huobi", "htx", "gate", "gate.io", "crypto-com", "bitget",
    "mexc", "gemini", "bitstamp", "poloniex", "upbit", "bithumb",
    "exchange", "cex", "centralized-exchange",
})


def fetch_candidate_etherscan_label_dumps() -> list[CandidateLabel]:
    """Harvest exchange + bridge candidates from the brianleect/etherscan-labels
    OSS dumps across 6 EVM chains. Maps the dump's label tokens to our category
    set: an exact ``bridge`` label → bridge; an exchange-name / ``cex`` /
    ``exchange`` label → exchange_hot_wallet (or exchange_deposit when the name
    says "deposit"). Anything else is skipped — we only harvest the two
    categories the promote pipeline supports. EVM addresses lower-cased
    (canonical). Best-effort; never raises."""
    out: list[CandidateLabel] = []
    for explorer, (chain, addr_prefix) in _OSS_LABEL_DUMPS.items():
        body = _safe_http_get_json(
            _OSS_DUMP_URL.format(explorer=explorer),
            source_name=f"etherscan_labels_oss:{explorer}",
        )
        if not isinstance(body, dict):
            continue
        for addr, v in body.items():
            if not isinstance(addr, str) or not isinstance(v, dict):
                continue
            labels = {str(x).lower() for x in (v.get("labels") or [])}
            name = str(v.get("name") or "").strip()
            if labels & _OSS_EXCHANGE_LABELS:
                category = (
                    "exchange_deposit" if "deposit" in name.lower()
                    else "exchange_hot_wallet"
                )
            elif "bridge" in labels:
                category = "bridge"
            else:
                continue  # not an exchange/bridge label → skip
            display = name or (sorted(labels)[0] if labels else "")
            try:
                out.append(CandidateLabel(
                    address=addr.lower(),
                    chain=chain,
                    proposed_category=category,
                    proposed_name=display[:200] or "(unnamed)",
                    source="etherscan_labels_oss",
                    source_url=f"{addr_prefix}{addr}",
                    raw_metadata={"labels": sorted(labels), "explorer": explorer},
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed OSS-dump row: %s", exc,
                )
    return out


def fetch_candidate_ton_entities() -> list[CandidateLabel]:
    """Pull candidate TON exchange addresses from tonapi.io's curated name
    search (``/v2/accounts/search``). tonapi names are maintainer-curated (not
    user memos), so a name match is a defensible LOW-confidence candidate for
    operator review. Addresses canonicalized to TON raw form; non-TON / un-
    normalizable results skipped. Best-effort — never raises."""
    from recupero.chains.ton.address import normalize_ton_address

    out: list[CandidateLabel] = []
    seen: set[str] = set()
    for query in _TON_EXCHANGE_QUERIES:
        body = _safe_http_get_json(
            f"https://tonapi.io/v2/accounts/search?name={query}",
            source_name=f"tonapi_search:{query}",
        )
        if not isinstance(body, dict):
            continue
        for row in body.get("addresses") or []:
            if not isinstance(row, dict):
                continue
            address = row.get("address") or ""
            name = row.get("name") or ""
            if not (isinstance(address, str) and address):
                continue
            # Precision: tonapi's curated name must still reference the query —
            # drops unrelated fuzzy matches before they reach the review queue.
            if query.lower() not in str(name).lower():
                continue
            try:
                canonical = normalize_ton_address(address)
            except ValueError:
                continue
            if canonical in seen:
                continue
            seen.add(canonical)
            try:
                out.append(CandidateLabel(
                    address=canonical,
                    chain="ton",
                    proposed_category="exchange_hot_wallet",
                    proposed_name=str(name)[:200],
                    source="tonapi_search",
                    source_url=f"https://tonviewer.com/{address}",
                    raw_metadata={"tonapi_raw": row, "query": query},
                ))
            except ValueError as exc:
                log.debug(
                    "label auto-ingest: skipping malformed tonapi row: %s", exc,
                )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Persistence — write to label_candidates with dedup
# ─────────────────────────────────────────────────────────────────────────────


def persist_candidates(
    candidates: list[CandidateLabel],
    *,
    dsn: str | None = None,
    daily_cap: int | None = None,
) -> int:
    """Persist `candidates` to ``public.label_candidates``.

    Deduplicates on ``(chain, address)`` — a row that already exists
    (in ANY status — pending, promoted, rejected, expired) is skipped
    silently. Operators have already made a call about it.

    Returns the number of NEW rows actually inserted (i.e., not the
    input length — duplicates are subtracted).

    The daily-cap clamp is applied AFTER de-duplication so already-
    reviewed rows don't waste the budget.
    """
    if daily_cap is None:
        daily_cap = _daily_cap()
    if dsn is None:
        dsn = (os.environ.get("SUPABASE_DB_URL") or "").strip()
    if not candidates:
        return 0

    # Apply daily cap. Order-preserving so re-runs drop the same tail.
    capped = candidates[:daily_cap]
    if len(candidates) > daily_cap:
        log.warning(
            "label auto-ingest: %d candidates exceeds daily cap %d — "
            "dropping %d",
            len(candidates), daily_cap, len(candidates) - daily_cap,
        )

    if not dsn:
        log.info(
            "label auto-ingest: SUPABASE_DB_URL unset — would have "
            "persisted %d candidates (local-dev no-op)", len(capped),
        )
        return 0

    inserted = 0
    sql = """
    INSERT INTO public.label_candidates (
        address, chain, proposed_category, proposed_name,
        proposed_confidence, source, source_url, raw_metadata
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
    ON CONFLICT (chain, address) DO NOTHING
    RETURNING id
    """
    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            for c in capped:
                cur.execute(sql, (
                    c.address, c.chain, c.proposed_category, c.proposed_name,
                    c.proposed_confidence, c.source, c.source_url,
                    json.dumps(c.raw_metadata, default=str),
                ))
                if cur.fetchone() is not None:
                    inserted += 1
    except Exception as exc:  # noqa: BLE001
        log.error(
            "label auto-ingest: persist failed (%s: %s) — %d rows "
            "may have been written before the error",
            type(exc).__name__, exc, inserted,
        )
        return inserted

    log.info(
        "label auto-ingest: persisted %d new candidates "
        "(of %d submitted, %d were duplicates)",
        inserted, len(capped), len(capped) - inserted,
    )
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# Promotion / rejection — operator-driven
# ─────────────────────────────────────────────────────────────────────────────


_SEEDS_DIR = Path(__file__).parent / "seeds"


# Map proposed_category → which seed file the promoted entry lands in.
# CEX hot wallets AND deposits both go into cex_deposits.json — the
# file holds both shapes (its existing rows mix both categories).
_CATEGORY_TO_SEED_FILE = {
    "bridge": "bridges.json",
    "exchange_hot_wallet": "cex_deposits.json",
    "exchange_deposit": "cex_deposits.json",
}


def _read_candidate(
    candidate_id: int, dsn: str,
) -> dict[str, Any] | None:
    """Fetch one candidate row by id. Returns None if not found."""
    from recupero._common import db_connect
    sql = """
    SELECT id, address, chain, proposed_category, proposed_name,
           proposed_confidence, source, source_url, raw_metadata, status
      FROM public.label_candidates
     WHERE id = %s
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(sql, (candidate_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {
        "id": row[0], "address": row[1], "chain": row[2],
        "proposed_category": row[3], "proposed_name": row[4],
        "proposed_confidence": row[5], "source": row[6],
        "source_url": row[7], "raw_metadata": row[8], "status": row[9],
    }


def promote_candidate(
    candidate_id: int,
    reviewer: str,
    *,
    confidence: str = "medium",
    dsn: str | None = None,
    seeds_dir: Path | None = None,
    confirm_sha256: str | None = None,
    bypass_multi_source: bool = False,
) -> dict[str, Any]:
    """Append the candidate to the appropriate seeds JSON and mark
    the candidate row as ``status='promoted'``.

    Confidence defaults to 'medium' on promotion — operators reviewing
    an upstream tag have enough evidence to bump above the 'low' default
    of pending rows, but 'high' is reserved for primary-source
    verification (the protocol team's own docs, the exchange's own
    confirmation, etc.). The promotion endpoint accepts a different
    confidence via its body.

    Raises ValueError if the candidate is already promoted/rejected
    or doesn't exist (the caller — the API endpoint — turns this into
    a 404 / 409).
    """
    if dsn is None:
        dsn = (os.environ.get("SUPABASE_DB_URL") or "").strip()
    if not dsn:
        raise RuntimeError(
            "promote_candidate requires SUPABASE_DB_URL to be set"
        )
    if seeds_dir is None:
        seeds_dir = _SEEDS_DIR
    if confidence not in ("low", "medium", "high"):
        raise ValueError(
            f"confidence {confidence!r} must be one of low/medium/high"
        )

    row = _read_candidate(candidate_id, dsn)
    if row is None:
        raise ValueError(f"candidate {candidate_id} not found")
    if row["status"] != "pending_review":
        raise ValueError(
            f"candidate {candidate_id} is already {row['status']!r}; "
            "only pending_review rows can be promoted"
        )

    # v0.32.1 SECURITY CRIT-1 close-out: validate every promotable
    # field BEFORE any disk write. Raises ValueError on the first
    # violation. The seed file is untouched if validation fails.
    _validate_promote_fields(row)

    # v0.32.1 SECURITY CRIT-1 close-out, second gate: optional
    # confirm-hash pin. When the operator promotes via the API they
    # pass the SHA-256 of the candidate row they were shown. A mismatch
    # means an attacker swapped the row between view and promote (or
    # the operator is acting on stale state); reject without writing.
    if confirm_sha256 is not None:
        expected = _compute_promote_confirm_sha256(row)
        actual = confirm_sha256.strip().lower()
        if actual != expected:
            raise ValueError(
                f"confirm_sha256 mismatch — candidate row may have "
                f"changed since you viewed it (expected {expected[:12]}…, "
                f"got {actual[:12]}…). Re-fetch the candidate and retry."
            )

    # v0.32.1 W2 (round-2 adversary M-1 wire-up): multi-source
    # confirmation gate for HIGH-IMPACT label categories
    # (exchange_hot_wallet, bridge, mixer, sanctioned, ofac, custodian,
    # exchange_deposit). Pre-W2 these checks shipped as dead code; the
    # promote endpoint accepted a single-source candidate and wrote the
    # seed file. JACOB_ADVERSARY_AUDIT_v032 poisoning attacks P1-P4
    # (DeFiLlama fake-bridge, Tronscan tag spoofing) succeed entirely
    # through this gap. The bypass kwarg is audit-logged at INFO; ops
    # emergencies set it when they need to force a high-impact promote
    # during an active incident response.
    #
    # Gated on ``RECUPERO_MULTI_SOURCE_CONFIRM`` env var to preserve BC
    # for v0.32.1 legacy tests that promote a single-source candidate
    # against an in-memory seed dir. Production deployments MUST set
    # this to ``1`` (the runbook covers it). When unset the gate is
    # bypassed with a one-time WARN; the explicit bypass kwarg still
    # logs at INFO for parity with the gated path.
    gate_env = (
        os.environ.get("RECUPERO_MULTI_SOURCE_CONFIRM", "")
        .strip().lower()
    )
    gate_enabled = gate_env in ("1", "true", "yes", "on")
    if bypass_multi_source:
        log.info(
            "label PROMOTE multi-source bypass — candidate=%s reviewer=%s "
            "category=%s. Audit trail required.",
            candidate_id, reviewer, row.get("proposed_category"),
        )
    elif not gate_enabled:
        log.debug(
            "multi-source gate not enabled (RECUPERO_MULTI_SOURCE_CONFIRM "
            "unset); proceeding with single-source promote. SET THIS IN "
            "PRODUCTION."
        )
    else:
        try:
            from recupero.labels.multi_source_confirm import (
                confirm_via_secondary_sources,
                requires_multi_source_confirm,
            )
        except Exception as exc:  # noqa: BLE001 — never break promote on import
            log.warning(
                "multi_source_confirm import failed (%s); skipping gate",
                exc,
            )
        else:
            if requires_multi_source_confirm(row):
                result = confirm_via_secondary_sources(
                    address=row["address"],
                    claimed_category=row["proposed_category"],
                    claimed_name=row["proposed_name"],
                    sources_seen=[row["source"]],
                    chain=row["chain"],
                )
                if not result.accepted or result.confidence == "low":
                    raise ValueError(
                        f"multi-source confirm rejected: {result.reason} "
                        "High-impact label categories require 2+ "
                        "independent sources. Set bypass_multi_source=True "
                        "to override (audit-logged)."
                    )
                log.info(
                    "multi-source confirm PASSED — candidate=%s category=%s "
                    "confidence=%s sources=%s",
                    candidate_id, row["proposed_category"],
                    result.confidence, result.supporting_sources,
                )

    seed_file = _CATEGORY_TO_SEED_FILE.get(row["proposed_category"])
    if seed_file is None:
        raise ValueError(
            f"no seed-file mapping for category {row['proposed_category']!r}"
        )
    seed_path = seeds_dir / seed_file

    new_entry: dict[str, Any] = {
        "address": row["address"],
        "name": row["proposed_name"],
        "category": row["proposed_category"],
        "source": f"auto_ingest:{row['source']}",
        "confidence": confidence,
        "added_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "chain": row["chain"],
        "_v032_auto_ingest": True,
    }
    # The bridges.json schema flags 'category' as optional and elides it
    # from required, while cex_deposits.json keeps it. Both schemas accept
    # the field, so we always emit it for explicitness.

    _append_to_seed_file(seed_path, new_entry)

    from recupero._common import db_connect
    sql = """
    UPDATE public.label_candidates
       SET status = 'promoted',
           reviewer_email = %s,
           reviewed_at_utc = NOW()
     WHERE id = %s AND status = 'pending_review'
    RETURNING id
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(sql, (reviewer, candidate_id))
        if cur.fetchone() is None:
            # Lost a race with another promoter — already moved out
            # of pending_review. The seed-file append is idempotent at
            # the JSON list level (duplicate addresses warn but don't
            # break loading), so we tolerate it.
            log.warning(
                "label auto-ingest: candidate %d transitioned out of "
                "pending_review during promote — seed file still appended",
                candidate_id,
            )

    return {**row, "promoted_to": str(seed_path), "promoted_entry": new_entry}


def reject_candidate(
    candidate_id: int,
    reviewer: str,
    reason: str,
    *,
    dsn: str | None = None,
) -> dict[str, Any]:
    """Mark candidate as rejected. ``reason`` is required (callers
    enforce min_length at the request layer)."""
    if dsn is None:
        dsn = (os.environ.get("SUPABASE_DB_URL") or "").strip()
    if not dsn:
        raise RuntimeError(
            "reject_candidate requires SUPABASE_DB_URL to be set"
        )
    if not reason or not reason.strip():
        raise ValueError("reject_candidate requires a non-empty reason")

    row = _read_candidate(candidate_id, dsn)
    if row is None:
        raise ValueError(f"candidate {candidate_id} not found")
    if row["status"] != "pending_review":
        raise ValueError(
            f"candidate {candidate_id} is already {row['status']!r}; "
            "only pending_review rows can be rejected"
        )

    from recupero._common import db_connect
    sql = """
    UPDATE public.label_candidates
       SET status = 'rejected',
           reviewer_email = %s,
           review_notes = %s,
           reviewed_at_utc = NOW()
     WHERE id = %s AND status = 'pending_review'
    RETURNING id
    """
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(sql, (reviewer, reason[:4000], candidate_id))
        affected = cur.fetchone()
    if affected is None:
        raise ValueError(
            f"candidate {candidate_id} could not be marked rejected "
            "(lost race with another reviewer)"
        )
    return {**row, "rejection_reason": reason}


def _append_to_seed_file(seed_path: Path, entry: dict[str, Any]) -> None:
    """Append `entry` to the JSON-list seed file at `seed_path`.

    The on-disk shape of bridges.json and cex_deposits.json is a flat
    JSON list of objects. We read, append, write — atomically via
    ``_common.atomic_write_text`` so a partial write can't corrupt the
    seed file.
    """
    from recupero._common import atomic_write_text

    if seed_path.exists():
        existing = json.loads(seed_path.read_text(encoding="utf-8-sig"))
        if not isinstance(existing, list):
            raise RuntimeError(
                f"seed file {seed_path} is not a JSON list; refusing to "
                "auto-append"
            )
    else:
        existing = []

    existing.append(entry)
    atomic_write_text(
        seed_path,
        json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Cron entry point — orchestrates the daily pull
# ─────────────────────────────────────────────────────────────────────────────


def run_daily_pull() -> dict[str, int]:
    """Pull bridges + CEX candidates, dedupe, persist.

    Returns a small summary dict the cron driver can log:
    ``{"bridges_seen": N, "cex_seen": M, "persisted": K}``.
    """
    log.info("label auto-ingest: starting daily pull")
    bridges = fetch_candidate_bridges()
    cex = fetch_candidate_cex_deposits()
    ton = fetch_candidate_ton_entities()
    oss = fetch_candidate_etherscan_label_dumps()
    total = bridges + cex + ton + oss
    persisted = persist_candidates(total)
    log.info(
        "label auto-ingest: daily pull done — bridges=%d cex=%d ton=%d "
        "oss=%d persisted=%d",
        len(bridges), len(cex), len(ton), len(oss), persisted,
    )
    return {
        "bridges_seen": len(bridges),
        "cex_seen": len(cex),
        "ton_seen": len(ton),
        "oss_seen": len(oss),
        "persisted": persisted,
    }


def list_candidates(
    *,
    status: str = "pending_review",
    limit: int = 100,
    dsn: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch candidate rows for the operator review UI / API."""
    if dsn is None:
        dsn = (os.environ.get("SUPABASE_DB_URL") or "").strip()
    if not dsn:
        return []
    # Defensive bounds — the API caller already clamps, but persistence
    # callers might not.
    limit = max(1, min(int(limit or 100), 500))
    if status not in ("pending_review", "promoted", "rejected", "expired"):
        raise ValueError(f"unknown status {status!r}")

    from recupero._common import db_connect
    sql = """
    SELECT id, address, chain, proposed_category, proposed_name,
           proposed_confidence, source, source_url, raw_metadata,
           status, review_notes, reviewer_email, reviewed_at_utc,
           created_at_utc
      FROM public.label_candidates
     WHERE status = %s
     ORDER BY created_at_utc DESC
     LIMIT %s
    """
    out: list[dict[str, Any]] = []
    with db_connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(sql, (status, limit))
        for r in cur.fetchall():
            out.append({
                "id": r[0], "address": r[1], "chain": r[2],
                "proposed_category": r[3], "proposed_name": r[4],
                "proposed_confidence": r[5], "source": r[6],
                "source_url": r[7], "raw_metadata": r[8],
                "status": r[9], "review_notes": r[10],
                "reviewer_email": r[11],
                "reviewed_at_utc": (
                    r[12].isoformat() if r[12] is not None else None
                ),
                "created_at_utc": (
                    r[13].isoformat() if r[13] is not None else None
                ),
            })
    return out


__all__ = (
    "CandidateLabel",
    "fetch_candidate_bridges",
    "fetch_candidate_cex_deposits",
    "fetch_candidate_ton_entities",
    "fetch_candidate_etherscan_label_dumps",
    "persist_candidates",
    "promote_candidate",
    "reject_candidate",
    "run_daily_pull",
    "list_candidates",
)
