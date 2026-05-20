"""X (Twitter) hack-watcher feed.

Reads the public X accounts of the four canonical crypto-security
research firms via the official X API v2:

  * @PeckShieldAlert — autopost on detected exploits, usually within
    minutes of an attack landing on-chain.
  * @CertiK — postmortem-style reporting + Hack3D leaderboard updates.
  * @SlowMist_Team — DPRK / Lazarus attribution work; OFAC-adjacent
    reporting.
  * @beosin — Asia-focused exploit reporting; often first on Asian-DEX
    incidents.
  * @BlockSecTeam — protocol-side exploit forensics.

Authentication
--------------

The X API v2 requires a Bearer Token. Set ``RECUPERO_X_BEARER_TOKEN``
in the operator's .env. Without it, the scraper returns an empty
list and logs an INFO line — no auth = no fetch is the safest default
for a feature-flagged module.

The Bearer Token can be generated at
https://developer.x.com/en/portal/projects-and-apps (free tier supports
500K reads/month, well within the daily-digest budget).

Offline / fixture mode
----------------------

When ``RECUPERO_HACK_TRACKER_OFFLINE=1`` (or the ``offline=True``
parameter is passed), returns a small fixture set so we can iterate
on the daily digest format without burning API budget.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import UTC, datetime, timedelta

from recupero.hack_tracker.models import (
    HackEvent,
    HackEventSeverity,
    HackEventSource,
)

log = logging.getLogger(__name__)


# X handle → HackEventSource mapping.
# Adding a new researcher: bump models.HackEventSource + add a row.
_X_HANDLES: dict[str, HackEventSource] = {
    "PeckShieldAlert": HackEventSource.x_peckshield,
    "CertiK":          HackEventSource.x_certik,
    "SlowMist_Team":   HackEventSource.x_slowmist,
    "beosinAlert":     HackEventSource.x_beosin,
    "BlockSecTeam":    HackEventSource.x_blocksec,
}

# X API v2 base. Pinned to /2/ to match the docs the bearer token
# was issued against (X has historically changed the v1.1 endpoints
# without warning; v2 has been stable since 2021).
_X_API_BASE = "https://api.x.com/2"


def fetch(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch X posts from the canonical hack-watcher accounts since
    ``since`` (UTC).

    Returns a (possibly empty) list of normalized HackEvent. NEVER
    raises — transient errors are logged + an empty slice returned.
    """
    if offline or _is_offline():
        log.info("hack_tracker.x_feed: offline mode — returning fixture")
        return _offline_fixture(since=since)

    token = (os.environ.get("RECUPERO_X_BEARER_TOKEN") or "").strip()
    if not token:
        log.info(
            "hack_tracker.x_feed: RECUPERO_X_BEARER_TOKEN unset — "
            "skipping X feed fetch (returning empty)"
        )
        return []

    out: list[HackEvent] = []
    for handle, source in _X_HANDLES.items():
        try:
            posts = _fetch_user_tweets(
                handle=handle, since=since, bearer_token=token,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "hack_tracker.x_feed: fetch for @%s failed: %s",
                handle, exc,
            )
            continue
        for p in posts:
            ev = _post_to_event(post=p, handle=handle, source=source)
            if ev is not None:
                out.append(ev)

    log.info("hack_tracker.x_feed: %d events across %d handles",
             len(out), len(_X_HANDLES))
    return out


# ---- internals ---- #


def _is_offline() -> bool:
    from recupero._common import env_truthy
    return env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")


def _fetch_user_tweets(
    *, handle: str, since: datetime, bearer_token: str,
) -> list[dict]:
    """Fetch recent tweets for one user since ``since``. Returns the
    raw X-API tweet list (each entry contains id, text, created_at,
    public_metrics).

    NB: feature-flagged path — operator must set
    RECUPERO_HACK_TRACKER_ENABLED=1 + RECUPERO_X_BEARER_TOKEN to
    activate. Implementation is intentionally a stub for v0.20.0; the
    real X-API integration ships in the next phase once we've
    validated the digest format against the fixture data.
    """
    log.debug(
        "x_feed._fetch_user_tweets stub: @%s since=%s — returns empty "
        "until X-API integration lands in v0.20.1",
        handle, since,
    )
    return []


def _post_to_event(
    *, post: dict, handle: str, source: HackEventSource,
) -> HackEvent | None:
    """Normalize an X-API tweet dict into a HackEvent. Returns None
    if the post is filtered out (retweet, off-topic, etc.)."""
    text = (post.get("text") or "").strip()
    if not text or len(text) < 20:
        return None
    tweet_id = post.get("id", "")
    if not tweet_id:
        return None
    created_at_raw = post.get("created_at", "")
    try:
        created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        created_at = datetime.now(UTC)
    severity = _infer_severity(text)
    addrs = _extract_addresses(text)
    txs = _extract_tx_hashes(text)
    chains = _extract_chains_mentioned(text)
    actor = _infer_actor(text)
    return HackEvent(
        content_hash=_content_hash(source.value, text[:200], addrs),
        source=source,
        source_url=f"https://x.com/{handle}/status/{tweet_id}",
        observed_at=datetime.now(UTC),
        incident_time=created_at,
        title=text[:120],
        summary=text[:1500],
        severity=severity,
        chains_mentioned=chains,
        addresses=addrs,
        tx_hashes=txs,
        attributed_actor=actor,
        tags=_infer_tags(text),
    )


def _content_hash(source: str, title: str, addrs: list[str]) -> str:
    """Stable dedup key — sha256(source|title|sorted(addrs))."""
    blob = f"{source}|{title}|{'|'.join(sorted(addrs))}".encode()
    return hashlib.sha256(blob).hexdigest()


def _infer_severity(text: str) -> HackEventSeverity:
    """Rough severity inference from numeric strings in the post."""
    lower = text.lower()
    if "$" in text:
        # Crude — pull numbers next to the $; refined version lives in
        # the v0.20.1 enhancement.
        import re
        amounts = re.findall(r"\$([\d.,]+)\s*(m|million|b|billion|k)?", lower)
        for raw, unit in amounts:
            try:
                value = float(raw.replace(",", ""))
            except ValueError:
                continue
            if unit in ("b", "billion"):
                value *= 1e9
            elif unit in ("m", "million"):
                value *= 1e6
            elif unit == "k":
                value *= 1e3
            if value >= 10_000_000:
                return HackEventSeverity.critical
            if value >= 1_000_000:
                return HackEventSeverity.high
            if value >= 100_000:
                return HackEventSeverity.medium
    if any(kw in lower for kw in ("ofac", "lazarus", "dprk")):
        return HackEventSeverity.critical
    return HackEventSeverity.medium


def _extract_addresses(text: str) -> list[str]:
    """Pull EVM 0x-addresses out of free-form text."""
    import re
    return re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)


def _extract_tx_hashes(text: str) -> list[str]:
    """Pull EVM tx hashes (0x + 64 hex) out of free-form text."""
    import re
    return re.findall(r"\b0x[a-fA-F0-9]{64}\b", text)


def _extract_chains_mentioned(text: str) -> list[str]:
    """Heuristic chain mention extraction from post text."""
    lower = text.lower()
    chain_keywords = {
        "ethereum":  ["ethereum", "eth", "mainnet"],
        "arbitrum":  ["arbitrum", "arb"],
        "optimism":  ["optimism", "op stack"],
        "base":      ["base"],
        "bsc":       ["bsc", "binance smart chain", "bnb chain"],
        "polygon":   ["polygon", "matic"],
        "solana":    ["solana", "sol"],
        "tron":      ["tron", "trx"],
        "bitcoin":   ["bitcoin", "btc"],
        "avalanche": ["avalanche", "avax"],
        "ton":       ["ton chain", "telegram open"],
    }
    found = []
    for chain, keywords in chain_keywords.items():
        if any(kw in lower for kw in keywords):
            found.append(chain)
    return found


def _infer_actor(text: str) -> str | None:
    """Heuristic attribution — look for known threat-actor names."""
    lower = text.lower()
    actors = [
        ("Lazarus / DPRK",     ["lazarus", "dprk", "north korea"]),
        ("Pink Drainer",       ["pink drainer", "pinkdrainer"]),
        ("Inferno Drainer",    ["inferno drainer", "infernodrainer"]),
        ("Angel Drainer",      ["angel drainer", "angeldrainer"]),
    ]
    for name, keywords in actors:
        if any(kw in lower for kw in keywords):
            return name
    return None


def _infer_tags(text: str) -> list[str]:
    """Free-form tag inference for ranking + digest filtering."""
    lower = text.lower()
    tags = []
    candidates = {
        "phishing":       ["phishing", "fake site", "scam"],
        "bridge_exploit": ["bridge", "cross-chain hack"],
        "rugpull":        ["rugpull", "rug pull", "rug-pulled"],
        "drainer":        ["drainer", "wallet drainer"],
        "flash_loan":     ["flash loan", "flashloan"],
        "ofac":           ["ofac", "sanctioned"],
        "exchange_hack":  ["exchange hack", "cex hack"],
        "dex_exploit":    ["dex exploit", "dex hack"],
    }
    for tag, kws in candidates.items():
        if any(kw in lower for kw in kws):
            tags.append(tag)
    return tags


# ---- offline fixture ---- #


def _offline_fixture(*, since: datetime) -> list[HackEvent]:
    """Return synthetic events for dev / digest-format iteration.

    Three illustrative shapes:
      1. A CRIT-severity bridge hack (drainer + OFAC tag)
      2. A HIGH pig-butchering campaign reveal
      3. A MED rugpull
    """
    now = datetime.now(UTC)
    return [
        HackEvent(
            content_hash=_content_hash("fixture", "bridge hack 50M", []),
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/PeckShieldAlert/status/1100000000000000001",
            observed_at=now,
            incident_time=now - timedelta(hours=2),
            title="[FIXTURE] @PeckShieldAlert: $50M exploit on a cross-chain bridge",
            summary=(
                "Fixture data — replace with a real X feed once "
                "RECUPERO_X_BEARER_TOKEN is set. Bridge X lost ~$50M "
                "via a signature-replay vulnerability; funds routed to "
                "0x" + "a" * 40 + " then through Tornado Cash."
            ),
            severity=HackEventSeverity.critical,
            chains_mentioned=["ethereum", "arbitrum"],
            addresses=["0x" + "a" * 40],
            estimated_loss_usd=None,
            attributed_actor=None,
            tags=["bridge_exploit", "flash_loan"],
            has_identifiable_victim=False,
        ),
        HackEvent(
            content_hash=_content_hash("fixture", "pig butchering ring", []),
            source=HackEventSource.x_slowmist,
            source_url="https://x.com/SlowMist_Team/status/1100000000000000002",
            observed_at=now,
            incident_time=now - timedelta(hours=8),
            title="[FIXTURE] @SlowMist_Team: pig-butchering ring identified",
            summary=(
                "Fixture data. Coordinated pig-butchering network "
                "extracting ~$3M / week, terminal addresses all on Tron. "
                "Recommended watchlist entries: T" + "x" * 32 + " "
                "(USDT-TRC20 hot wallet)."
            ),
            severity=HackEventSeverity.high,
            chains_mentioned=["tron"],
            tags=["phishing", "drainer"],
            has_identifiable_victim=True,
            victim_hint="Multiple retail victims via dating-app social engineering",
        ),
        HackEvent(
            content_hash=_content_hash("fixture", "rugpull memecoin", []),
            source=HackEventSource.rekt,
            source_url="https://rekt.news/article/fixture-rugpull-001/",
            observed_at=now,
            incident_time=now - timedelta(days=1),
            title="[FIXTURE] rekt.news: memecoin RUGPULL — $250K vanished",
            summary=(
                "Fixture data. Anonymous deployer minted token, drove "
                "liquidity to $250K, then pulled LP + transferred treasury "
                "to a fresh address. Standard rug shape; surface only "
                "if operator wants to track outflow."
            ),
            severity=HackEventSeverity.medium,
            chains_mentioned=["base"],
            tags=["rugpull"],
            has_identifiable_victim=False,
        ),
    ]
