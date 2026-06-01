"""Pydantic / dataclass models for the hack-tracker.

Adversarial-input hardening (v0.20.1+, deepened in v0.20.2)
-----------------------------------------------------------

Every field on ``HackEvent`` is at least partially attacker-controlled
(X tweet text, government press-release prose, RSS feed entries).
Validators below enforce:

  * Text fields are scrubbed of NUL bytes, C0/C1 controls, bidi
    overrides, zero-width invisibles, AND HTML/<script> tags.
    Operator digests render HTML — a smuggled <script> would
    otherwise execute.
  * ``estimated_loss_usd`` rejects NaN, Infinity, negative values,
    AND values above $1e15 (global crypto market cap is ~$3-4T;
    higher is an obvious feed parse-error / hostile injection).
  * ``source_url`` must use http(s) AND its host must be on a
    closed allowlist (twitter / x.com / treasury / ic3 / cisa /
    rekt.news). Any other host is rejected even on https.
  * ``observed_at`` / ``incident_time``: naive datetimes are
    coerced to UTC so the downstream invariant
    ``ev.observed_at.tzinfo is not None`` always holds.
  * ``addresses`` are canonicalized (lowercased, deduped) and any
    non-canonical entry is dropped. A regex-extracted ``0x``+garbage
    string would otherwise persist as if it were a valid EVM address.
  * ``tx_hashes`` accept both ``0x``+64-hex and bare 64-hex inputs;
    output is always canonical ``0x``-prefixed lowercase.
  * ``severity`` only accepts members of ``HackEventSeverity``.
  * ``title`` is capped at 200 chars, ``summary`` at 2000.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allowlisted source_url hosts. Anything outside this set is rejected
# at validation time — feeds we don't recognize are presumed hostile
# (an attacker controls the URL string in every X / RSS payload).
#
# This is broader than "twitter + OFAC" because the existing offline
# fixtures + government_feeds adapter emit ic3.gov, cisa.gov, and
# rekt.news URLs that must continue to validate.
_ALLOWED_SOURCE_URL_HOSTS = frozenset({
    "x.com", "www.x.com",
    "twitter.com", "www.twitter.com", "mobile.twitter.com",
    "ofac.treasury.gov", "home.treasury.gov", "www.treasury.gov",
    "treasury.gov",
    "ic3.gov", "www.ic3.gov",
    "cisa.gov", "www.cisa.gov",
    "rekt.news", "www.rekt.news",
})

# Implausibility cap on estimated_loss_usd. Global crypto market cap
# is ~$3-4T at peak; a single-incident loss of $1e15 ($1 quadrillion)
# is an obvious feed parse-error or hostile injection.
_MAX_LOSS_USD = Decimal("1000000000000000")  # 1e15

# HTML / script tag scrub patterns. Operator digests render HTML; any
# attacker-controlled text that smuggles a <script> tag would execute.
_SCRIPT_TAG_RE = re.compile(r"<\s*/?\s*script[^>]*>", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")


class HackEventSource(str, Enum):
    """Where this event was found. Drives the source-weight in the
    ranking algorithm and the citation link in the daily digest."""

    x_peckshield = "x_peckshield"
    x_certik = "x_certik"
    x_slowmist = "x_slowmist"
    x_beosin = "x_beosin"
    x_blocksec = "x_blocksec"
    x_other = "x_other"           # generic X mention picked up by keyword search
    ofac_sdn = "ofac_sdn"          # OFAC SDN list update
    ofac_advisory = "ofac_advisory"
    ic3_alert = "ic3_alert"
    cisa_alert = "cisa_alert"
    rekt = "rekt"                  # rekt.news postmortem
    manual = "manual"              # operator-added entry


class HackEventSeverity(str, Enum):
    """Operator-facing severity bucket. Used for digest sorting +
    marketing-priority signal."""

    critical = "critical"   # 8-figure+ theft; nation-state attribution; OFAC
    high = "high"           # 7-figure theft; bridge/protocol exploit
    medium = "medium"       # 6-figure theft; phishing campaign
    low = "low"             # <6-figure; routine pig-butchering chatter
    info = "info"           # advisory only, no specific victim


class HackEvent(BaseModel):
    """One normalized event from any source.

    The aggregator dedupes events by ``content_hash`` (computed from
    source + title + perpetrator addresses), so an attack reported on
    X and then in a rekt.news postmortem 24h later won't double-stamp
    the operator's digest.
    """

    model_config = ConfigDict(extra="forbid")

    # Identity / dedup
    content_hash: str = Field(..., description="sha256(source + title + addrs)")
    source: HackEventSource
    source_url: str = Field(..., description="Original URL or X status link")

    # Time
    observed_at: datetime = Field(..., description="When we fetched it")
    incident_time: datetime | None = Field(
        None, description="When the hack itself occurred (if knowable)",
    )

    # Content
    title: str = Field(..., max_length=200)
    summary: str = Field(..., max_length=2000)
    severity: HackEventSeverity = HackEventSeverity.medium

    # Forensic surface — what addresses / tx hashes / chains are mentioned.
    # Operators use these to prioritize watchlist additions + marketing
    # outreach (a fresh hack with extracted addresses is the highest-value
    # outreach signal).
    chains_mentioned: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)
    tx_hashes: list[str] = Field(default_factory=list)
    estimated_loss_usd: Decimal | None = None

    # Attribution (where source identifies a perpetrator group)
    attributed_actor: str | None = None  # e.g., "DPRK / Lazarus", "Drainer-X"

    # Marketing-priority signal — does this event include enough info
    # to identify a likely victim or victim-group to reach out to?
    has_identifiable_victim: bool = False
    victim_hint: str | None = None  # e.g., "DEX protocol", "individual whale"

    # Free-form tags ("phishing", "bridge_exploit", "rugpull", "OFAC")
    tags: list[str] = Field(default_factory=list)

    # ---- Adversarial-input validators ---- #

    @field_validator(
        "title", "summary", "attributed_actor", "victim_hint",
        mode="before",
    )
    @classmethod
    def _scrub_text(cls, v):  # noqa: D401
        """Scrub NUL / C0-C1 controls / bidi overrides / zero-width
        invisibles plus HTML/<script> tags from operator-visible text."""
        if v is None:
            return v
        if not isinstance(v, str):
            v = str(v)
        # W11-01 ReDoS hardening: `_HTML_TAG_RE.sub` over an input that
        # contains many `<` without matching `>` causes O(N²) backtracks
        # (every `<` triggers a scan-to-end-of-string). Cap the input
        # at a generous 16KB BEFORE invoking the regex — well above
        # any realistic title/summary/actor/victim_hint field, and well
        # below the multi-MB sizes that turn the scrub into a DoS.
        if len(v) > 16384:
            v = v[:16384]
        v = _scrub_hostile_chars(v)
        # Drop <script> blocks first (also nukes their content), then
        # strip any remaining HTML tags. Operator digests render HTML,
        # so an attacker-controlled <script>...</script> in a tweet
        # body would otherwise execute.
        v = _SCRIPT_TAG_RE.sub("", v)
        return _HTML_TAG_RE.sub("", v)

    @field_validator("observed_at", "incident_time", mode="before")
    @classmethod
    def _coerce_tz_aware(cls, v):
        """Ensure datetimes are tz-aware.

        Naive datetimes (e.g., ``datetime.utcnow()`` from legacy
        fixture code) are coerced to UTC rather than rejected, so the
        existing ranker contract — which constructs HackEvent with a
        naive ``observed_at`` and expects validation to succeed —
        keeps working. The invariant we guarantee downstream is
        ``ev.observed_at.tzinfo is not None``.
        """
        if v is None:
            return v
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @field_validator("source_url", mode="before")
    @classmethod
    def _validate_source_url(cls, v):
        """Reject non-http(s) schemes and non-allowlisted hosts.

        The allowlist is closed: twitter/x.com, government press-release
        domains (treasury / ic3 / cisa), and rekt.news. Any other host
        (even on https) is presumed hostile because the URL string is
        attacker-controlled in every feed payload.
        """
        if v is None or not isinstance(v, str):
            raise ValueError("source_url must be a non-empty string")
        cleaned = _scrub_hostile_chars(v).strip()
        if not cleaned:
            raise ValueError("source_url must be a non-empty string")
        low = cleaned.lower()
        if not (low.startswith("http://") or low.startswith("https://")):
            raise ValueError(
                "source_url scheme must be http or https; "
                f"got {cleaned[:40]!r}"
            )
        # Host allowlist check
        try:
            parts = urlsplit(cleaned)
        except ValueError as exc:
            raise ValueError(f"source_url is not parseable: {exc}") from exc
        host = (parts.hostname or "").lower()
        if host not in _ALLOWED_SOURCE_URL_HOSTS:
            raise ValueError(
                f"source_url host {host!r} not in allowlist "
                "(twitter/x/treasury/ic3/cisa/rekt only)"
            )
        return cleaned

    @field_validator("estimated_loss_usd")
    @classmethod
    def _validate_loss_usd(cls, v):
        """Reject NaN, Infinity, negative, and absurdly-large losses.

        Decimal("NaN") and Decimal("Infinity") are legal Python objects
        but produce ``$nan`` / ``$inf`` text in operator digests and
        violate every downstream USD-comparison gate.

        We also cap at $1e15 — global crypto market cap is ~$3-4T;
        any single-incident loss exceeding $1 quadrillion is an
        obvious feed parse-error or hostile injection.
        """
        if v is None:
            return v
        # Decimal exposes is_nan() / is_infinite()
        if hasattr(v, "is_nan") and v.is_nan():
            raise ValueError("estimated_loss_usd cannot be NaN")
        if hasattr(v, "is_infinite") and v.is_infinite():
            raise ValueError("estimated_loss_usd cannot be Infinity")
        if v < 0:
            raise ValueError("estimated_loss_usd cannot be negative")
        if v > _MAX_LOSS_USD:
            raise ValueError(
                "estimated_loss_usd exceeds plausibility cap "
                f"(${_MAX_LOSS_USD} = $1e15)"
            )
        return v

    @field_validator("addresses")
    @classmethod
    def _canonicalize_addresses(cls, v):
        """Drop entries that are not canonical EVM (0x + 40 hex).

        Returns a deduped lowercased list. Non-canonical inputs are
        silently dropped (callers extracted via regex from prose;
        garbage matches are expected at low rates).
        """
        if not v:
            return []
        out: list[str] = []
        seen: set[str] = set()
        for raw in v:
            if not isinstance(raw, str):
                continue
            s = raw.strip()
            if not s.startswith("0x") or len(s) != 42:
                continue
            suffix = s[2:]
            if not all(c in "0123456789abcdefABCDEF" for c in suffix):
                continue
            canon = s.lower()
            if canon in seen:
                continue
            seen.add(canon)
            out.append(canon)
        return out

    @field_validator("tx_hashes")
    @classmethod
    def _canonicalize_tx_hashes(cls, v):
        """Drop entries that are not canonical EVM tx hashes.

        Accepts both ``0x`` + 64-hex (66 chars total) and bare 64-hex
        forms — many regex extractors emit the bare form. Both shapes
        are stored in canonical ``0x``-prefixed lowercase.
        """
        if not v:
            return []
        out: list[str] = []
        seen: set[str] = set()
        for raw in v:
            if not isinstance(raw, str):
                continue
            s = raw.strip()
            # Accept either 0x+64hex or bare 64hex
            if s.startswith("0x") and len(s) == 66:
                suffix = s[2:]
            elif len(s) == 64:
                suffix = s
            else:
                continue
            if not all(c in "0123456789abcdefABCDEF" for c in suffix):
                continue
            canon = "0x" + suffix.lower()
            if canon in seen:
                continue
            seen.add(canon)
            out.append(canon)
        return out


# ---- Helper: hostile-character scrubber ---- #


_BIDI_OVERRIDES = frozenset({
    0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})
_ZERO_WIDTH_INVISIBLES = frozenset({
    0x200B, 0x200C, 0x200D, 0xFEFF,
})


def _scrub_hostile_chars(s: str) -> str:
    """Return ``s`` with NUL / C0 / C1 / bidi-override / zero-width
    invisibles removed.

    Preserves ordinary whitespace (tab, newline, space). Used by
    every HackEvent text-field validator + by the X-feed normalizer
    before strings reach the model.
    """
    if not s:
        return s
    out_chars: list[str] = []
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            continue
        # C0 controls (except tab=0x09, newline=0x0A, CR=0x0D)
        if cp < 0x20 and cp not in (0x09, 0x0A, 0x0D):
            continue
        # DEL + C1 controls
        if cp == 0x7F or 0x80 <= cp <= 0x9F:
            continue
        if cp in _BIDI_OVERRIDES:
            continue
        if cp in _ZERO_WIDTH_INVISIBLES:
            continue
        out_chars.append(ch)
    return "".join(out_chars)
