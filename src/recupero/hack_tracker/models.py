"""Pydantic / dataclass models for the hack-tracker."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


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
    title: str = Field(..., max_length=400)
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
