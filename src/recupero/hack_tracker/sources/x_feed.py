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
import math
import os
import re
import threading
import time
from datetime import UTC, datetime, timedelta

from recupero.hack_tracker.models import (
    HackEvent,
    HackEventSeverity,
    HackEventSource,
    _scrub_hostile_chars,
)

log = logging.getLogger(__name__)


# Defense-in-depth caps. Adversarial X posts can be megabyte-scale
# even though the public API caps per-tweet content; the upstream
# payload contains multi-tweet threads concatenated by the X API.
# These caps bound CPU + memory before we even hand text to regex
# / Pydantic.
_MAX_TWEET_TEXT_CHARS = 20_000   # generous, ~10x normal tweet
_MAX_EXTRACTED_ADDRS = 5_000     # one tweet can mention many addrs but not millions
_TWEET_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


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

_HTTP_TIMEOUT_S = 20

# Cost defaults, deliberately conservative. X bills new developers PER POST READ
# (pay-per-use replaced the flat Basic/Pro tiers for new signups in Feb 2026 and
# there is no free read tier), so the product of
# handles x tweets-per-handle x fetches-per-day IS the invoice:
#
#   5 handles x 10 tweets x  1 fetch/day  ~=   1.5k reads/month
#   5 handles x 10 tweets x  4 fetch/day  ~=     6k reads/month
#   5 handles x 10 tweets x 96 fetch/day  ~=   288k reads/month
#
# The feed endpoint caches for 15 minutes, so an unguarded fetch would land in
# that last row. Raise these only with the arithmetic in front of you.
_DEFAULT_MAX_TWEETS = 10             # per handle per fetch
_DEFAULT_MIN_INTERVAL_S = 6 * 3600   # at most 4 fetches/day
_DEFAULT_MAX_READS_PER_DAY = 250     # hard ceiling on billable posts read

_budget_lock = threading.Lock()
_budget: dict[str, object] = {
    "last_fetch_monotonic": None,
    "day": None,
    "reads_today": 0,
}


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

    # Money gate. Checked BEFORE any request, because X reads are billed per
    # post and the caller (a cached HTTP endpoint) has no idea it is spending.
    if not _x_budget_allows():
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
    """Fetch recent tweets for one user since ``since``.

    Returns the raw X-API v2 tweet list (each entry has id, text, created_at,
    public_metrics). Never raises: on any error it logs and returns [].

    COST WARNING -- read this before changing the caller's cadence. X moved new
    developers to pay-per-use in Feb 2026: reads are billed PER POST
    (~$0.005each at time of writing), the flat Basic/Pro tiers are closed to new
    signups, and there is no free read tier. Cost is therefore a direct function
    of how often this runs times ``_max_tweets_per_handle()``:

        5 handles x 10 tweets, once daily  ~= 1.5k reads/mo
        5 handles x 10 tweets, every 15min ~= 288k reads/mo

    The endpoint that surfaces this feed has a 15-minute cache, so without a
    floor on fetch frequency a few console visitors would poll X ~96x/day.
    ``_x_budget_allows()`` enforces that floor plus a daily read ceiling. Do not
    remove it to "make the feed fresher" without doing the arithmetic.
    """
    user_id = _resolve_user_id(handle=handle, bearer_token=bearer_token)
    if not user_id:
        return []

    max_results = _max_tweets_per_handle()
    params = {
        "max_results": str(max_results),
        "tweet.fields": "created_at,public_metrics",
        "exclude": "retweets,replies",
        "start_time": since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload = _x_get(
        f"{_X_API_BASE}/users/{user_id}/tweets",
        params=params, bearer_token=bearer_token, label=f"tweets @{handle}",
    )
    if payload is None:
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        # No posts in the window is a normal, non-error response.
        return []
    _record_reads(len(data))
    return [d for d in data if isinstance(d, dict)]


# Resolved handle -> numeric id. Handle-to-id mappings never change, so caching
# them for the process lifetime removes a billable lookup per handle per run.
_user_id_cache: dict[str, str] = {}


def _resolve_user_id(*, handle: str, bearer_token: str) -> str | None:
    cached = _user_id_cache.get(handle)
    if cached:
        return cached
    payload = _x_get(
        f"{_X_API_BASE}/users/by/username/{handle}",
        params={}, bearer_token=bearer_token, label=f"lookup @{handle}",
    )
    if payload is None:
        return None
    data = payload.get("data")
    uid = data.get("id") if isinstance(data, dict) else None
    if not isinstance(uid, str) or not uid.isdigit():
        log.warning("x_feed: unexpected user-lookup payload for @%s", handle)
        return None
    _user_id_cache[handle] = uid
    return uid


def _x_get(
    url: str, *, params: dict, bearer_token: str, label: str,
) -> dict | None:
    """One authenticated GET against the X API. None on any failure."""
    try:
        import httpx
    except ImportError:  # pragma: no cover
        log.warning("x_feed: httpx unavailable")
        return None
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_S, follow_redirects=False) as c:
            resp = c.get(
                url, params=params,
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "User-Agent": "recupero-hack-tracker/1.0",
                },
            )
    except Exception as exc:  # noqa: BLE001 — transport errors
        log.warning("x_feed: %s failed: %s", label, exc)
        return None

    if resp.status_code == 429:
        log.warning(
            "x_feed: %s rate-limited (429). Reset: %s",
            label, resp.headers.get("x-rate-limit-reset", "unknown"),
        )
        return None
    if resp.status_code in (401, 403):
        # Distinguish a bad token from an under-entitled one: both are operator
        # config problems, not transient, so say so loudly once per run.
        log.error(
            "x_feed: %s returned HTTP %s — the bearer token is invalid or the "
            "account lacks read entitlement (X has no free read tier).",
            label, resp.status_code,
        )
        return None
    if resp.status_code != 200:
        log.warning("x_feed: %s returned HTTP %s", label, resp.status_code)
        return None
    try:
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        log.warning("x_feed: %s returned unparseable JSON: %s", label, exc)
        return None
    return payload if isinstance(payload, dict) else None


# ---- cost guardrails ---- #


def _max_tweets_per_handle() -> int:
    """Posts requested per handle per fetch. 5..100 (X API's own bounds)."""
    raw = (os.environ.get("RECUPERO_X_MAX_TWEETS_PER_HANDLE") or "").strip()
    try:
        n = int(raw) if raw else _DEFAULT_MAX_TWEETS
    except ValueError:
        n = _DEFAULT_MAX_TWEETS
    return max(5, min(100, n))


def _min_fetch_interval_s() -> int:
    raw = (os.environ.get("RECUPERO_X_MIN_FETCH_INTERVAL_S") or "").strip()
    try:
        return max(0, int(raw)) if raw else _DEFAULT_MIN_INTERVAL_S
    except ValueError:
        return _DEFAULT_MIN_INTERVAL_S


def _max_reads_per_day() -> int:
    raw = (os.environ.get("RECUPERO_X_MAX_READS_PER_DAY") or "").strip()
    try:
        return max(0, int(raw)) if raw else _DEFAULT_MAX_READS_PER_DAY
    except ValueError:
        return _DEFAULT_MAX_READS_PER_DAY


def _x_budget_allows() -> bool:
    """True if we may spend money on X reads right now.

    Two independent brakes, because X reads cost real money per post:
      * a floor on how often any fetch may happen at all, so a busy console
        (15-minute cache) cannot turn into 96 polls/day; and
      * a rolling daily ceiling on posts actually read.

    In-process state, so a restart resets it. That is deliberate -- the
    alternative is a shared datastore this module has no business depending on
    -- but it means the ceiling is per-process. Keep the defaults conservative.
    """
    now = time.monotonic()
    with _budget_lock:
        interval = _min_fetch_interval_s()
        last = _budget["last_fetch_monotonic"]
        if last is not None and (now - last) < interval:
            log.info(
                "x_feed: skipping fetch — last was %.0fs ago, minimum interval "
                "is %ds (RECUPERO_X_MIN_FETCH_INTERVAL_S). This brake exists "
                "because X bills per post read.",
                now - last, interval,
            )
            return False
        # Roll the daily window.
        day = int(time.time() // 86400)
        if _budget["day"] != day:
            _budget["day"] = day
            _budget["reads_today"] = 0
        cap = _max_reads_per_day()
        if _budget["reads_today"] >= cap:
            log.warning(
                "x_feed: daily read cap reached (%d/%d, "
                "RECUPERO_X_MAX_READS_PER_DAY) — not fetching",
                _budget["reads_today"], cap,
            )
            return False
        _budget["last_fetch_monotonic"] = now
        return True


def _record_reads(n: int) -> None:
    if n <= 0:
        return
    with _budget_lock:
        _budget["reads_today"] = int(_budget["reads_today"]) + n


def _post_to_event(
    *, post: dict, handle: str, source: HackEventSource,
) -> HackEvent | None:
    """Normalize an X-API tweet dict into a HackEvent. Returns None
    if the post is filtered out (retweet, off-topic, etc.) or hostile.

    Adversarial-input hardening (v0.20.1):
      * tweet_id is validated against a strict allowlist
        (alphanumeric + ``-_``) — anything else (``..``, ``@``,
        ``/``, control chars, non-string types) would let an attacker
        rewrite the constructed source_url to an arbitrary URL.
      * Tweet text is scrubbed of NUL / bidi / zero-width / control
        chars BEFORE every downstream use (regex extractors, severity
        inference, hashing, model construction). Without this an
        attacker could smuggle invisible content into the operator's
        digest.
      * Text is capped at ``_MAX_TWEET_TEXT_CHARS`` before regex
        extraction to bound CPU/memory.
      * datetime parsing catches every exception type
        (ValueError, TypeError, OverflowError, AttributeError) — the
        X API has historically returned malformed timestamps for
        archived tweets.
    """
    # --- text validation + scrub ---
    raw_text = post.get("text")
    if not isinstance(raw_text, str):
        return None
    # Cap BEFORE the scrub loop so a megabyte-scale hostile post can't
    # waste CPU on the per-char iteration.
    if len(raw_text) > _MAX_TWEET_TEXT_CHARS:
        raw_text = raw_text[:_MAX_TWEET_TEXT_CHARS]
    text = _scrub_hostile_chars(raw_text).strip()
    if not text or len(text) < 20:
        return None

    # --- tweet_id validation (SSRF guard for source_url) ---
    tweet_id_raw = post.get("id")
    if not isinstance(tweet_id_raw, str):
        return None
    tweet_id = tweet_id_raw.strip()
    if not tweet_id or not _TWEET_ID_RE.match(tweet_id):
        return None

    # --- created_at parsing ---
    created_at_raw = post.get("created_at", "")
    created_at = datetime.now(UTC)
    if isinstance(created_at_raw, str) and created_at_raw:
        try:
            cleaned = _scrub_hostile_chars(created_at_raw).strip()
            cleaned = cleaned.replace("Z", "+00:00")
            created_at = datetime.fromisoformat(cleaned)
        except (ValueError, TypeError, OverflowError, AttributeError):
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
    """Rough severity inference from numeric strings in the post.

    Adversarial-input hardening:
      * ``float()`` can raise ``OverflowError`` for ``"1e400"``-style
        inputs (not a ValueError) — both are caught.
      * After parsing + unit multiplication, the value is gated through
        ``math.isfinite()``. An attacker post claiming ``$1e400 million``
        would otherwise produce ``inf`` and trivially rank ``critical``.
      * NaN parses to ``nan``; ``math.isfinite()`` rejects it.
    """
    lower = text.lower()
    if "$" in text:
        # Crude — pull numbers next to the $; refined version lives in
        # the v0.20.1 enhancement.
        amounts = re.findall(r"\$([\d.,eE+-]+)\s*(m|million|b|billion|k)?", lower)
        for raw, unit in amounts:
            try:
                value = float(raw.replace(",", ""))
            except (ValueError, OverflowError):
                continue
            if not math.isfinite(value):
                continue
            if unit in ("b", "billion"):
                value *= 1e9
            elif unit in ("m", "million"):
                value *= 1e6
            elif unit == "k":
                value *= 1e3
            # Re-check finiteness after the multiplication — `1e308 * 1e9`
            # overflows to inf in IEEE-754 even though both operands
            # are finite.
            if not math.isfinite(value) or value < 0:
                continue
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
    """Pull EVM 0x-addresses out of free-form text.

    Returns canonical lowercased, deduped form. Caps total returned at
    ``_MAX_EXTRACTED_ADDRS`` so an attacker can't OOM the digest with
    a tweet containing megabytes of repeated 0x patterns.
    """
    # Cap input length defensively — the caller in _post_to_event
    # already caps, but _extract_addresses is also called from tests.
    if len(text) > _MAX_TWEET_TEXT_CHARS:
        text = text[:_MAX_TWEET_TEXT_CHARS]
    raw = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
    out: list[str] = []
    seen: set[str] = set()
    for r in raw:
        canon = r.lower()
        if canon in seen:
            continue
        seen.add(canon)
        out.append(canon)
        if len(out) >= _MAX_EXTRACTED_ADDRS:
            break
    return out


def _extract_tx_hashes(text: str) -> list[str]:
    """Pull EVM tx hashes (0x + 64 hex) out of free-form text.

    Same defensive caps + dedup as ``_extract_addresses``.
    """
    if len(text) > _MAX_TWEET_TEXT_CHARS:
        text = text[:_MAX_TWEET_TEXT_CHARS]
    raw = re.findall(r"\b0x[a-fA-F0-9]{64}\b", text)
    out: list[str] = []
    seen: set[str] = set()
    for r in raw:
        canon = r.lower()
        if canon in seen:
            continue
        seen.add(canon)
        out.append(canon)
        if len(out) >= _MAX_EXTRACTED_ADDRS:
            break
    return out


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
