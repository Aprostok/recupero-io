"""recupero-ops <command> dispatch.

argparse-based subcommand router. Imports each command's
implementation lazily so the operator can run e.g. ``recupero-ops
status <id>`` without paying the import cost of the freeze-letter-
sending modules.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from decimal import Decimal
from uuid import UUID

from dotenv import load_dotenv

from recupero.logging_setup import setup_logging

log = logging.getLogger("recupero.ops")


def _require_dsn() -> str:
    """Resolve SUPABASE_DB_URL or exit non-zero. Every ops command
    needs DB access; if it's missing the operator made a setup
    mistake and we should fail loudly."""
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        print(
            "ERROR: SUPABASE_DB_URL is not set. "
            "Source your .env or export the variable before running ops commands.",
            file=sys.stderr,
        )
        sys.exit(2)
    return dsn


def _parse_uuid(s: str, *, field_name: str = "investigation_id") -> UUID:
    """Parse a UUID arg or exit with a helpful error."""
    try:
        return UUID(s)
    except ValueError:
        print(
            f"ERROR: {field_name!r} must be a UUID (e.g., "
            f"'e917ffc5-36ec-40e0-a0b3-cc5a6b03f31c'). Got: {s!r}",
            file=sys.stderr,
        )
        sys.exit(2)


def _confirm(prompt: str, *, default: bool = False) -> bool:
    """Interactive y/N prompt. Returns True if user confirmed,
    False on N / empty / EOF. Honors the ``RECUPERO_OPS_ASSUME_YES``
    env var (any canonical truthy value: ``1`` / ``true`` / ``yes`` /
    ``on``) for scripted ops use.

    v0.19.2 (round-13 CLI-HIGH-7): the env-var check now flows through
    `recupero._common.env_truthy` so it matches the project-wide
    truthy parsing. Pre-v0.19.2 we accepted only the literal "1", but
    `RECUPERO_DISABLE_EMAIL` accepted full truthy variants — operators
    who copy-pasted `RECUPERO_DISABLE_EMAIL=true` style into their cron
    and wrote `RECUPERO_OPS_ASSUME_YES=true` got the interactive prompt
    blocking the cron mid-run.
    """
    from recupero._common import env_truthy
    if env_truthy("RECUPERO_OPS_ASSUME_YES"):
        return True
    default_str = "Y/n" if default else "y/N"
    try:
        ans = input(f"{prompt} [{default_str}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not ans:
        return default
    return ans in ("y", "yes")


def cli() -> None:
    """Entry point for ``recupero-ops``."""
    # v0.19.2 (round-13 CLI-HIGH-9): pull deployed version for --version.
    try:
        from importlib.metadata import version as _v
        _recupero_version = _v("recupero")
    except Exception:  # noqa: BLE001
        _recupero_version = "unknown"

    parser = argparse.ArgumentParser(
        prog="recupero-ops",
        description="Operator CLI for investigation management.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"recupero-ops (recupero {_recupero_version})",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("RECUPERO_LOG_LEVEL", "INFO"),
        help="Python log level. Default INFO.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ----- status ----- #
    p_status = sub.add_parser(
        "status",
        help="Show full state of an investigation.",
    )
    p_status.add_argument("investigation_id", help="UUID of the investigation")

    # ----- mark-engaged ----- #
    p_engage = sub.add_parser(
        "mark-engaged",
        help="Activate Tier-2 engagement on an investigation.",
    )
    p_engage.add_argument("investigation_id", help="UUID of the investigation")
    p_engage.add_argument(
        "--fee", type=str, default=None,
        help="Engagement fee paid (USD). Defaults to the value in "
             "recupero._pricing (currently $10,000). The first "
             "follow-up email will be sent on the next "
             "--send-followups cron run.",
    )

    # ----- mark-closed ----- #
    p_close = sub.add_parser(
        "mark-closed",
        help="Close an active engagement.",
    )
    p_close.add_argument("investigation_id", help="UUID of the investigation")
    p_close.add_argument(
        "--reason", type=str, default="operator-closed",
        help="Free-form reason recorded in change_summary for audit.",
    )

    # ----- close-case (v0.32 Tier-0 gap #2) ----- #
    # Gated case-close: cases CANNOT transition to status='closed'
    # without a documented outcome. The outcome is what drives the
    # recovery-rate disclosure on /v1/intake, so silent informal closes
    # would corrupt the published rate. See
    # recupero.ops.commands.close_case for the gate logic.
    p_close_case = sub.add_parser(
        "close-case",
        help="Close a case with a documented outcome. REQUIRED before "
             "the case can be marked status='closed'; without an outcome "
             "row the recovery-rate disclosure on /v1/intake undercounts "
             "the denominator.",
    )
    p_close_case.add_argument(
        "--case", dest="case_id", required=True,
        help="UUID of the case to close.",
    )
    p_close_case.add_argument(
        "--outcome", required=True,
        choices=("full_recovery", "partial_recovery", "no_recovery", "dropped"),
        help="Outcome category. full_recovery requires --recovered-usd.",
    )
    p_close_case.add_argument(
        "--recovered-usd", dest="recovered_usd", default=None,
        help="Dollar amount returned to the victim. REQUIRED for "
             "--outcome full_recovery; optional otherwise.",
    )
    p_close_case.add_argument(
        "--note", default=None,
        help="Free-form operator note attached to the synthetic "
             "freeze_outcomes audit row.",
    )

    # ----- send-freeze-letters ----- #
    p_freeze = sub.add_parser(
        "send-freeze-letters",
        help="Send prepared compliance freeze letters to issuer "
             "compliance teams. Requires confirmation.",
    )
    p_freeze.add_argument("investigation_id", help="UUID of the investigation")
    p_freeze.add_argument(
        "--issuer", type=str, default=None,
        help="If set, send only to the named issuer (e.g., 'Circle'). "
             "Default: send to every issuer in the FREEZABLE list.",
    )

    # ----- send-le-handoff ----- #
    p_le = sub.add_parser(
        "send-le-handoff",
        help="Send the LE handoff package to a specific law-enforcement "
             "officer or attorney.",
    )
    p_le.add_argument("investigation_id", help="UUID of the investigation")
    p_le.add_argument(
        "--to", required=True, dest="to_email",
        help="Recipient email address (the LE officer or attorney).",
    )

    # ----- followup-now ----- #
    p_followup = sub.add_parser(
        "followup-now",
        help="Force-send a follow-up status email immediately, "
             "bypassing the 6-day cadence check.",
    )
    p_followup.add_argument("investigation_id", help="UUID of the investigation")

    # ----- generate-customer-link ----- #
    p_link = sub.add_parser(
        "generate-customer-link",
        help="Mint a token-gated portal URL for a case so the victim "
             "can view status, download artifacts, and e-sign the "
             "engagement letter.",
    )
    p_link.add_argument("case_id", help="UUID of the case (NOT the investigation)")
    p_link.add_argument(
        "--ttl-days", type=int, default=90,
        help="Token TTL in days (default 90). Pass 0 for a never-"
             "expiring token (special-case workflows only).",
    )
    p_link.add_argument(
        "--label", type=str, default=None,
        help="Free-form label shown on the operator status page "
             "(e.g., 'victim', 'attorney', 'family-member').",
    )

    # ----- revoke-token ----- #
    # v0.18.9 (round-11 ops-HIGH-010): CLI wrapper around
    # portal.tokens.revoke_token. Pre-v0.18.9 the function existed
    # in `__all__` but no CLI surface — operators responding to a
    # leaked-link incident had to run raw SQL.
    p_revoke = sub.add_parser(
        "revoke-token",
        help="Revoke a portal bearer token so the URL stops working. "
             "Use when a victim accidentally forwarded the link, or "
             "when ops sees suspicious portal-access patterns.",
    )
    p_revoke.add_argument(
        "token_id",
        help="UUID of the case_tokens row (printed by generate-customer-link).",
    )

    # ----- stripe-mode ----- #
    sub.add_parser(
        "stripe-mode",
        help="Report the current Stripe configuration mode "
             "(test vs live). Exits non-zero on mismatch — "
             "useful in deployment CI checks.",
    )

    # ----- ofac-sync ----- #
    sub.add_parser(
        "ofac-sync",
        help="Download the latest OFAC SDN List from treasury.gov "
             "and update the local crypto-address CSV used by "
             "risk-scoring. Recommended cadence: weekly via cron.",
    )

    # ----- import-sanctions (v0.35.6 / E5) ----- #
    p_intl = sub.add_parser(
        "import-sanctions",
        help="Import multi-regime sanctioned crypto wallets (EU / UK "
             "HMT-OFSI / UN / Israel / Japan / …) from an OpenSanctions "
             "CryptoWallet bulk file (FtM JSON/NDJSON) into the local "
             "intl-sanctions CSV used by risk-scoring, alongside OFAC.",
    )
    p_intl.add_argument(
        "--file", dest="sanctions_file", required=True,
        help="Path to the OpenSanctions crypto bulk export "
             "(entities .json array or .ndjson).",
    )

    # ----- import-attribution (v0.35.9 / B1-B2) ----- #
    p_attr = sub.add_parser(
        "import-attribution",
        help="Harvest a free open-source attribution feed (CSV or "
             "JSON/NDJSON of address/chain/category/name) into the label "
             "candidate review queue. Bridge + exchange categories only; "
             "rows land pending_review (NOT auto-promoted).",
    )
    p_attr.add_argument(
        "--file", dest="attribution_file", required=True,
        help="Path to the attribution feed (.csv, .json array, or .ndjson).",
    )
    p_attr.add_argument(
        "--source", dest="attribution_source", default="attribution_feed",
        help="Default source identifier for rows that don't carry one "
             "(default: attribution_feed).",
    )

    # ----- harvest-blacklist (v0.39) ----- #
    p_bl = sub.add_parser(
        "harvest-blacklist",
        help="Harvest the internal known-bad blacklist from the case corpus "
             "(Supabase bucket). Every wallet across all investigations, "
             "deduped with provenance; only REAL illicit-role addresses "
             "(perpetrator/mixer/current-holder) are ARMED to alert — never "
             "test fixtures, victims, or legitimate services. Writes a JSON "
             "the screener + tracer consult so a future case routing through a "
             "listed wallet fires a high-risk verdict.",
    )
    p_bl.add_argument(
        "--out", dest="blacklist_out", default=None,
        help="Output path (default: RECUPERO_INTERNAL_BLACKLIST_PATH env or "
             "{data_dir}/intel/internal_blacklist.json).",
    )
    p_bl.add_argument(
        "--limit", dest="blacklist_limit", type=int, default=None,
        help="Cap the number of investigations scanned (debugging).",
    )

    # ----- blacklist-arm / blacklist-disarm (v0.39, operator-curated) ----- #
    p_arm = sub.add_parser(
        "blacklist-arm",
        help="Manually arm a known-bad wallet (e.g. an exploiter seed or a "
             "Tornado deposit you've attributed). Survives re-harvest. The "
             "screener + tracer then fire a high-risk verdict on a hit.",
    )
    p_arm.add_argument("--address", required=True, help="Wallet address.")
    p_arm.add_argument("--chain", default="ethereum", help="Chain (default: ethereum).")
    p_arm.add_argument("--reason", default=None, help="Why it's known-bad (shown in the alert).")
    p_arm.add_argument("--label", dest="arm_label", default=None, help="Short display label.")

    p_disarm = sub.add_parser(
        "blacklist-disarm",
        help="Remove a manually-armed wallet from the internal blacklist.",
    )
    p_disarm.add_argument("--address", required=True, help="Wallet address.")
    p_disarm.add_argument("--chain", default="ethereum", help="Chain (default: ethereum).")

    # ----- benchmark (v0.35.12 / J1) ----- #
    p_bench = sub.add_parser(
        "benchmark",
        help="Score a finished trace against an independently-verified "
             "ground-truth endpoint set: recall (did we reach the known "
             "endpoints?), endpoint precision, F1, and the missed/spurious "
             "lists. Ground truth is supplied as JSON.",
    )
    p_bench.add_argument(
        "--case", dest="benchmark_case", required=True,
        help="Path to the case directory (containing case.json + "
             "freeze_brief.json).",
    )
    p_bench.add_argument(
        "--truth", dest="benchmark_truth", required=True,
        help="Path to the ground-truth JSON "
             "({case_id, endpoints[], by_category{}, notes}).",
    )

    # ----- graph-analyze (v0.35.16 / C6) ----- #
    p_graph = sub.add_parser(
        "graph-analyze",
        help="Structural analysis of a traced case's fund-flow graph: "
             "consolidation hubs (where split funds re-merge — the actor's "
             "hub) + value cycles (wash/loop obfuscation) + depth/metrics.",
    )
    p_graph.add_argument(
        "--case", dest="graph_case", required=True,
        help="Path to the case directory (containing case.json).",
    )
    p_graph.add_argument(
        "--min-sources", dest="graph_min_sources", type=int, default=3,
        help="Min distinct upstream sources for a consolidation hub (default 3).",
    )

    # ----- label-freshness (v0.35.15 / J3) ----- #
    sub.add_parser(
        "label-freshness",
        help="Report the freshness of every label source (OFAC feed, "
             "intl-sanctions, bridges, CEX deposits, mixers, …) against its "
             "per-class SLA. Flags stale/critical sources; OFAC feed age is "
             "the headline alarm. Recommended cadence: daily via cron.",
    )

    # ----- bridge-sync (v0.29.1 Recommendation #5) ----- #
    p_bridge_sync = sub.add_parser(
        "bridge-sync",
        help="Audit the local bridges.json against L2Beat + DefiLlama "
             "and write bridges_diff.json listing (protocol, chain) "
             "pairs we don't yet cover. REPORT-ONLY — operator triages "
             "and adds verified addresses in a follow-up commit. "
             "Recommended cadence: weekly via cron.",
    )
    p_bridge_sync.add_argument(
        "--output", default=None,
        help="Output path for bridges_diff.json (default ./bridges_diff.json).",
    )
    p_bridge_sync.add_argument(
        "--bridges", default=None,
        help="Override path to bridges.json (default ships-with-package).",
    )
    p_bridge_sync.add_argument(
        "--offline", action="store_true",
        help="Skip live HTTP and use bundled snapshots (CI-safe).",
    )

    # ----- retrace-scan (v0.31.2 Gap #14) ----- #
    p_retrace_scan = sub.add_parser(
        "retrace-scan",
        help="Scan every case for re-trace candidates: cases whose "
             "trace_completed_at predates a newer bridge / mixer / "
             "exchange_deposit / exchange_hot_wallet / perpetrator "
             "label that now matches a counterparty in the case. "
             "REPORT-ONLY — writes data/retrace_candidates.json; "
             "operator picks which cases to re-trace. Recommended "
             "cadence: weekly cron after label-DB updates land.",
    )
    p_retrace_scan.add_argument(
        "--out", default=None,
        help="Output path for retrace_candidates.json (default "
             "data/retrace_candidates.json).",
    )

    # ----- hack-tracker ----- #
    # v0.20.0 (Phase D): daily hack-feed aggregator. Feature-flagged
    # OFF in production — operator must opt in via
    # RECUPERO_HACK_TRACKER_ENABLED=1 OR _OFFLINE=1.
    p_tracker = sub.add_parser(
        "hack-tracker",
        help="Aggregate daily hack reports from X (Twitter) + OFAC + "
             "IC3 + CISA + rekt.news into a ranked operator digest. "
             "Feature-flagged OFF until v0.20.x; "
             "RECUPERO_HACK_TRACKER_OFFLINE=1 exercises fixture data.",
    )
    tracker_sub = p_tracker.add_subparsers(dest="tracker_command", required=True)
    p_tracker_daily = tracker_sub.add_parser(
        "daily",
        help="Print today's digest to stdout (text or JSON).",
    )
    p_tracker_daily.add_argument(
        "--hours", type=int, default=24,
        help="Lookback window in hours (default 24).",
    )
    p_tracker_daily.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format. Default text; use json for piping.",
    )

    # ----- correlation-stats ----- #
    sub.add_parser(
        "correlation-stats",
        help="Report summary stats from the cross-case correlation "
             "index (public.address_observations). Recommended "
             "cadence: monthly review.",
    )

    # ----- custody-keygen ----- #
    p_keygen = sub.add_parser(
        "custody-keygen",
        help="Generate a new Ed25519 keypair for court-admissible "
             "chain-of-custody signing. One-time setup per operator.",
    )
    p_keygen.add_argument(
        "--output-path", type=str, default=None,
        help="Path to write the private key (default "
             "~/.recupero/custody_key, overridable via "
             "RECUPERO_CUSTODY_KEY_PATH env var).",
    )

    # ----- custody-verify ----- #
    p_verify = sub.add_parser(
        "custody-verify",
        help="Verify a case's chain-of-custody chain. Walks every "
             "signed attestation, checks hash links, re-hashes "
             "attested artifacts, and reports tampering.",
    )
    p_verify.add_argument(
        "case_dir", help="Path to the case directory.",
    )
    p_verify.add_argument(
        "--public-key", type=str, default=None,
        help="Base64-encoded Ed25519 public key. If omitted, read "
             "from case_dir/custody/public_key.txt. For court use, "
             "ALWAYS supply this from an independently-trusted source.",
    )

    # ----- v0.14.5 cleanup: previously-orphaned commands ----- #

    # ----- refresh-freeze-priors (v0.14.2) ----- #
    sub.add_parser(
        "refresh-freeze-priors",
        help="Recompute per-issuer freeze-success priors from the "
             "freeze_outcomes table. Recommended cadence: nightly cron.",
    )

    # ----- cooperation-dashboard (v0.24.0) ----- #
    p_coop = sub.add_parser(
        "cooperation-dashboard",
        help="Render the cross-case issuer cooperation dashboard — "
             "operator-facing HTML aggregating every issuer's "
             "freeze-letter response history + recommended legal "
             "instrument for the next case. Refresh after batches "
             "of new outcomes land.",
    )
    p_coop.add_argument(
        "--output-dir", type=str, default="cooperation-dashboard",
        help="Directory to write the rendered HTML (created if "
             "missing). Default: ./cooperation-dashboard/",
    )

    # ----- law-firm-dashboard (v0.26.0) ----- #
    p_firm = sub.add_parser(
        "law-firm-dashboard",
        help="Render a partner law firm's portfolio dashboard — "
             "aggregate state of all cases the firm has referred. "
             "Pass --firm <slug-or-uuid> for one firm, or --all to "
             "render every active firm.",
    )
    p_firm.add_argument(
        "--firm", dest="firm_key", default=None,
        help="law_firms.slug or law_firms.id of the firm to render. "
             "Required unless --all is set.",
    )
    p_firm.add_argument(
        "--all", dest="all_firms", action="store_true",
        help="Render dashboards for every active firm. Mutually "
             "exclusive with --firm.",
    )
    p_firm.add_argument(
        "--output-dir", type=str, default="law-firm-dashboards",
        help="Directory to write the rendered HTML (created if "
             "missing). Default: ./law-firm-dashboards/",
    )

    # ----- watchlist-dashboard (v0.35.0) ----- #
    p_watch_dash = sub.add_parser(
        "watchlist-dashboard",
        help="Render the Watchlist / Watcher dashboard — every address "
             "under monitoring, where it sits, and whether it has MOVED "
             "since the last re-check. Run watchlist-run first to refresh "
             "the on-chain snapshots.",
    )
    p_watch_dash.add_argument(
        "--output-dir", type=str, default="watchlist-dashboard",
        help="Directory to write the rendered HTML (created if missing). "
             "Default: ./watchlist-dashboard/",
    )
    p_watch_dash.add_argument(
        "--investigation-id", dest="investigation_id", default=None,
        help="Scope to one investigation UUID. Omit for the global view.",
    )
    p_watch_dash.add_argument(
        "--stale-after-hours", dest="stale_after_hours", type=int, default=24,
        help="Flag a watched address as DUE for re-check when its last "
             "snapshot is older than this. Default: 24 (daily). Use 720 "
             "for a monthly cadence.",
    )

    # ----- watchlist-run (v0.35.0) ----- #
    p_watch_run = sub.add_parser(
        "watchlist-run",
        help="Trigger a watchlist re-check tick: snapshot the on-chain "
             "balance / tx-count of every eligible watched address and "
             "record movement. The daily/monthly job; safe to run on "
             "demand (per-row cooldowns prevent redundant work).",
    )
    p_watch_run.add_argument(
        "--parallelism", type=int, default=None,
        help="Concurrent snapshot workers (default: env / 4).",
    )
    p_watch_run.add_argument(
        "--limit", type=int, default=None,
        help="Max rows to snapshot this tick (default: all eligible).",
    )

    # ----- validate-output (v0.28.0 / JACOB-3) ----- #
    p_val = sub.add_parser(
        "validate-output",
        help="Run the output-integrity validator against a case "
             "directory. Checks 12 structural invariants (filename / "
             "content consistency, manifest SHA, freezable-issuer "
             "letter coverage, etc.) per Jacob's v0.20.15 review "
             "Part 4 spec. Exits 0 on PASS, 1 on FAIL with the "
             "violation list on stdout.",
    )
    p_val.add_argument(
        "case_dir",
        help="Path to the case output directory (e.g. cases/V-CFI01/).",
    )
    p_val.add_argument(
        "--json", action="store_true",
        help="Emit the full digest as JSON (for CI piping).",
    )

    # ----- nightly-audit (v0.28.0) ----- #
    p_nightly = sub.add_parser(
        "nightly-audit",
        help="Run the daily codebase health audit. Aggregates pytest "
             "/ ruff / mypy / git / TODO / lazy-import / file-growth "
             "/ test-coverage / migration checks into a single JSON "
             "digest + human-readable summary. Designed for a Railway "
             "cron schedule.",
    )
    p_nightly.add_argument(
        "--out-json", default="nightly_audit.json",
        help="JSON digest output path. Default: ./nightly_audit.json",
    )
    p_nightly.add_argument(
        "--baseline", default=None,
        help="Previous digest file for delta computation.",
    )
    p_nightly.add_argument(
        "--skip", default="",
        help="Comma-separated check names to skip.",
    )
    p_nightly.add_argument(
        "--llm-review", action="store_true",
        help="Append an LLM narrative review (requires "
             "ANTHROPIC_API_KEY).",
    )

    # ----- api-key-mint (v0.27.0) ----- #
    p_mint = sub.add_parser(
        "api-key-mint",
        help="Generate a random API-key secret + emit a "
             "RECUPERO_API_KEYS-compatible snippet the operator pastes "
             "into the Railway env. v0.27.0 — used to onboard exchange / "
             "compliance team partners.",
    )
    p_mint.add_argument(
        "name",
        help="Partner key name (e.g. 'exchange-acme'). Goes in the "
             "RECUPERO_API_KEYS env as the part before the colon.",
    )
    p_mint.add_argument(
        "--bytes", type=int, default=32, dest="key_bytes",
        help="Random-secret length in bytes (default 32 → 64 hex "
             "chars). Larger = stronger; smaller is rejected if < 16.",
    )

    # ----- render-cluster (v0.23.0) ----- #
    p_cluster = sub.add_parser(
        "render-cluster",
        help="Render an aggregated multi-victim cluster handoff (one "
             "document covering ALL victims sharing a perpetrator). "
             "Produced for a cluster identifier (CL-XXXXXX) returned "
             "by emit_brief when cross-case overlap is detected.",
    )
    p_cluster.add_argument(
        "public_id",
        help="Cluster public id (e.g. CL-AB12CD).",
    )
    p_cluster.add_argument(
        "--output-dir", type=str, default="cluster-handoffs",
        help="Directory to write the rendered handoff (created if "
             "missing). Default: ./cluster-handoffs/",
    )

    # ----- record-freeze-outcome (v0.14.2) ----- #
    p_outcome = sub.add_parser(
        "record-freeze-outcome",
        help="Record an outcome event for a previously-sent freeze "
             "letter (the operator's view of what happened: "
             "acknowledged, declined, full_freeze, returned, silence).",
    )
    # v0.14.2: positional letter_id form (kept for back-compat with
    # existing scripts / ops runbooks).
    # v0.21.0: alternative case-scoped form via --case + --issuer +
    # --target-address — easier for operators who have the case
    # context in hand and don't want to look up the letter UUID first.
    p_outcome.add_argument(
        "letter_id", nargs="?", default=None,
        help="UUID of the freeze_letters_sent row (v0.14.2 form). "
             "Mutually exclusive with --case / --issuer / --target-address.",
    )
    p_outcome.add_argument(
        "--case", dest="case", default=None,
        help="Case UUID (v0.21.0 lookup form). Used with --issuer "
             "and --target-address to resolve the letter id.",
    )
    p_outcome.add_argument(
        "--issuer", default=None,
        help="Issuer name (with --case / --target-address).",
    )
    p_outcome.add_argument(
        "--target-address", default=None,
        help="Target wallet address (with --case / --issuer).",
    )
    p_outcome.add_argument(
        "--asset-symbol", default=None,
        help="Asset symbol (optional disambiguator when more than one "
             "asset has been frozen at the same address by the same issuer).",
    )
    p_outcome.add_argument(
        "--outcome", required=True,
        choices=("acknowledged", "request_more_info", "declined",
                 "partial_freeze", "full_freeze", "released",
                 "returned_to_victim", "silence_14d",
                 "silence_30d", "silence_90d"),
    )
    p_outcome.add_argument(
        "--frozen-usd", type=str, default=None,
        help="USD amount frozen (for partial_freeze / full_freeze).",
    )
    p_outcome.add_argument(
        "--returned-usd", type=str, default=None,
        help="USD amount returned to victim (for returned_to_victim).",
    )
    p_outcome.add_argument(
        "--note", type=str, default=None,
        help="Free-form operator note for audit.",
    )

    # ----- validate-labels (v0.14.4) ----- #
    sub.add_parser(
        "validate-labels",
        help="Validate the address-label seed files (high_risk.json, "
             "mixers.json, etc.) against the schema spec. CI gate for "
             "PRs that touch label data.",
    )

    # ----- diagnose-case (v0.14.10) ----- #
    p_diag = sub.add_parser(
        "diagnose-case",
        help="Pre-flight diagnostic for a case. Walks the existing "
             "artifacts on disk, identifies why the brief looks the "
             "way it does, and recommends the next command to run. "
             "Useful when freeze_asks is empty / brief has no "
             "FREEZABLE entries / freeze letters aren't being generated.",
    )
    p_diag.add_argument(
        "case_id",
        help="Case ID (folder name under data/cases/).",
    )
    p_diag.add_argument(
        "--case-dir", type=str, default=None,
        help="Override the case directory path. Default: "
             "data/cases/<case_id>/ relative to repo root.",
    )

    # ----- list-payments ----- #
    p_lpay = sub.add_parser(
        "list-payments",
        help="List recent Stripe payment events with workflow "
             "correlation. The operator's go-to for 'did the "
             "webhook fire for case V-...?'",
    )
    p_lpay.add_argument(
        "--limit", type=int, default=10,
        help="Max rows (default 10, max 1000).",
    )
    p_lpay.add_argument(
        "--since", type=str, default="7d",
        help="Time window: 24h, 7d, 30d, 90d, or all (default 7d).",
    )
    p_lpay.add_argument(
        "--case-id", dest="case_id_filter", type=str, default=None,
        help="Filter to one specific case_id (UUID).",
    )

    # ----- generate-payment-link ----- #
    p_paylink = sub.add_parser(
        "generate-payment-link",
        help="Mint a Stripe Payment Link URL for the $499 diagnostic "
             "or $10,000 engagement payment, with case-specific "
             "metadata baked into client_reference_id.",
    )
    p_paylink.add_argument("case_id", help="UUID of the case")
    p_paylink.add_argument(
        "--type", required=True, dest="link_type",
        choices=("diagnostic", "engagement"),
        help="Which payment this link is for.",
    )
    p_paylink.add_argument(
        "--chain", default="ethereum",
        help="Chain for diagnostic links (default: ethereum). Ignored "
             "for engagement.",
    )
    p_paylink.add_argument(
        "--seed-address", dest="seed_address", default=None,
        help="The wallet to trace (required for --type diagnostic).",
    )
    p_paylink.add_argument(
        "--investigation-id", dest="investigation_id", default=None,
        help="Investigation UUID for --type engagement. If omitted, "
             "uses the latest investigation for the case.",
    )
    p_paylink.add_argument(
        "--prefilled-email", dest="prefilled_email", default=None,
        help="Override the case's contact email for the Stripe "
             "checkout 'Email' field pre-fill.",
    )

    # ----- envvars (v0.31.4) ----- #
    # Print the canonical RECUPERO_* env-var reference to stdout so
    # operators can `recupero-ops envvars` and see the full list
    # without leaving the terminal. The source of truth is
    # docs/ENV_VARS.md; this command resolves it relative to the
    # installed package OR the repo working tree, falling back
    # gracefully when neither is available (e.g. in a stripped
    # production wheel that excluded the doc tree).
    p_envvars = sub.add_parser(
        "envvars",
        help="Print the canonical RECUPERO_* env-var reference "
             "(docs/ENV_VARS.md). Use --index for the tabular index "
             "only.",
    )
    p_envvars.add_argument(
        "--index", action="store_true",
        help="Print only the tabular index (name | default | type | "
             "range | introduced | purpose) without the per-variable "
             "long-form sections. Useful for piping to grep.",
    )

    # ----- promote-freezable ----- #
    p_promote = sub.add_parser(
        "promote-freezable",
        help="Promote an INVESTIGATE watchlist row to FREEZABLE after "
             "issuer compliance confirms KYC. Requires confirmation.",
    )
    p_promote.add_argument("watchlist_id", help="UUID of the watchlist row")
    p_promote.add_argument(
        "--reason", required=True,
        help="Required: free-form reason for the promotion. Include "
             "the issuer ticket number or email thread so the audit "
             "trail can be re-verified later.",
    )
    p_promote.add_argument(
        "--force", action="store_true",
        help="Overwrite kyc_* columns if the row is already FREEZABLE. "
             "Use sparingly — this destroys the original audit trail.",
    )

    args = parser.parse_args()
    load_dotenv()
    setup_logging(args.log_level.upper())

    # Dispatch lazily — only import the command module we need
    if args.command == "status":
        from recupero.ops.commands import status as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            dsn=_require_dsn(),
        ))

    if args.command == "mark-engaged":
        from recupero._pricing import ENGAGEMENT_FEE_USD
        from recupero.ops.commands import mark_engaged as cmd
        if args.fee is None:
            fee = ENGAGEMENT_FEE_USD
        else:
            try:
                fee = Decimal(args.fee)
            except Exception:
                print(
                    f"ERROR: --fee must be a decimal number (got: {args.fee!r})",
                    file=sys.stderr,
                )
                sys.exit(2)
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            fee_usd=fee, dsn=_require_dsn(),
        ))

    if args.command == "mark-closed":
        from recupero.ops.commands import mark_closed as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            reason=args.reason, dsn=_require_dsn(),
        ))

    if args.command == "close-case":
        from recupero.ops.commands import close_case as cmd
        sys.exit(cmd.run(
            case_id=_parse_uuid(args.case_id, field_name="case_id"),
            outcome=args.outcome,
            recovered_usd_raw=args.recovered_usd,
            note=args.note,
            dsn=_require_dsn(),
        ))

    if args.command == "send-freeze-letters":
        from recupero.ops.commands import send_freeze_letters as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            issuer_filter=args.issuer,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "send-le-handoff":
        from recupero.ops.commands import send_le_handoff as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            to_email=args.to_email,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "followup-now":
        from recupero.ops.commands import followup_now as cmd
        sys.exit(cmd.run(
            investigation_id=_parse_uuid(args.investigation_id),
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "generate-customer-link":
        from recupero.ops.commands import generate_customer_link as cmd
        ttl: int | None = args.ttl_days
        if ttl is not None and ttl <= 0:
            ttl = None  # 0 → never expires
        sys.exit(cmd.run(
            case_id=_parse_uuid(args.case_id, field_name="case_id"),
            ttl_days=ttl,
            label=args.label,
            dsn=_require_dsn(),
        ))

    if args.command == "revoke-token":
        # v0.18.9 (round-11 ops-HIGH-010): inline revoke. No
        # confirmation prompt — revoking an active token is the
        # right thing under any "operator panic" workflow (forwarded
        # link, suspicious access).
        from recupero.portal.tokens import revoke_token
        token_id = _parse_uuid(args.token_id, field_name="token_id")
        ok = revoke_token(token_id=token_id, dsn=_require_dsn())
        if ok:
            print(f"OK — revoked portal token {token_id}")
            sys.exit(0)
        else:
            print(f"ERROR: no active token found with id={token_id}")
            sys.exit(1)

    if args.command == "envvars":
        # v0.31.4: print docs/ENV_VARS.md so operators can see the
        # canonical RECUPERO_* env-var list without browsing GitHub.
        # Doc resolution: walk up from this file looking for
        # `docs/ENV_VARS.md` (works in editable install + repo checkout);
        # if not found, try the importlib-resources path next to the
        # installed `recupero` package (works in a non-editable wheel
        # if the doc was shipped via package_data).
        from pathlib import Path as _Path
        doc_path: _Path | None = None
        # 1. Repo working tree: src/recupero/ops/cli.py → parents[3] = repo root.
        try:
            here = _Path(__file__).resolve()
            candidate = here.parents[3] / "docs" / "ENV_VARS.md"
            if candidate.is_file():
                doc_path = candidate
        except (IndexError, OSError):
            pass
        # 2. Installed wheel sibling (less common, but supports a
        #    future shipped-with-package doc).
        if doc_path is None:
            try:
                pkg_root = _Path(__file__).resolve().parents[1]
                candidate = pkg_root / "docs" / "ENV_VARS.md"
                if candidate.is_file():
                    doc_path = candidate
            except (IndexError, OSError):
                pass
        if doc_path is None:
            print(
                "ERROR: docs/ENV_VARS.md not found relative to the "
                "installed package or the repo checkout. This means "
                "the build dropped the doc tree — re-run from a repo "
                "clone or open the doc on GitHub.",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            text = doc_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: failed to read {doc_path}: {exc}", file=sys.stderr)
            sys.exit(2)
        if args.index:
            # Print only the lines between "## Index" and the next
            # top-level section ("## Per-variable detail" or "## "
            # generally). Markdown tables are still readable in a
            # terminal; the index is small enough to scan visually.
            lines = text.splitlines()
            start = None
            end = None
            for i, line in enumerate(lines):
                stripped = line.strip()
                if start is None and stripped == "## Index":
                    start = i
                    continue
                if start is not None and i > start and stripped.startswith("## "):
                    end = i
                    break
            if start is None:
                # Doc shape changed — fall back to printing the
                # whole file rather than silently emitting nothing.
                print(text)
            else:
                # Skip the "## Index" line itself + any blank trailer
                # lines before the next section.
                snippet = "\n".join(lines[start:end]) if end else "\n".join(lines[start:])
                print(snippet)
            sys.exit(0)
        print(text)
        sys.exit(0)

    if args.command == "promote-freezable":
        from recupero.ops.commands import promote_freezable as cmd
        sys.exit(cmd.run(
            watchlist_id=_parse_uuid(args.watchlist_id, field_name="watchlist_id"),
            reason=args.reason,
            force=args.force,
            dsn=_require_dsn(),
            confirm=_confirm,
        ))

    if args.command == "stripe-mode":
        from recupero.ops.commands import stripe_mode_cmd as cmd
        sys.exit(cmd.run())

    if args.command == "ofac-sync":
        from recupero.ops.commands import ofac_sync_cmd as cmd
        sys.exit(cmd.run())

    if args.command == "import-sanctions":
        from pathlib import Path as _Path

        from recupero.labels.sanctions_intl import import_opensanctions_file
        src = _Path(args.sanctions_file)
        if not src.exists():
            print(f"ERROR: file not found: {src}", file=sys.stderr)
            sys.exit(2)
        n = import_opensanctions_file(src)
        print(f"Imported {n} intl-sanctioned crypto wallet(s) → risk-scoring CSV.")
        sys.exit(0)

    if args.command == "import-attribution":
        from pathlib import Path as _Path

        from recupero.labels.attribution_feed import import_attribution_file
        src = _Path(args.attribution_file)
        if not src.exists():
            print(f"ERROR: file not found: {src}", file=sys.stderr)
            sys.exit(2)
        result = import_attribution_file(
            src, default_source=args.attribution_source,
        )
        print(
            f"Attribution feed: parsed {result.parsed}, skipped "
            f"{result.skipped}, persisted {result.persisted} candidate(s) "
            "→ pending_review. Promote via the labels API after review."
        )
        if result.skipped_reasons:
            print(f"  skipped breakdown: {result.skipped_reasons}")
        sys.exit(0)

    if args.command == "harvest-blacklist":
        from pathlib import Path as _Path

        from recupero.intel_harvest import harvest_from_supabase
        from recupero.labels.internal_blacklist import (
            default_blacklist_path,
            save_blacklist,
        )
        try:
            entries, stats = harvest_from_supabase(limit=args.blacklist_limit)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(2)
        out_path = (
            _Path(args.blacklist_out) if args.blacklist_out
            else default_blacklist_path()
        )
        save_blacklist(entries, out_path)
        armed = [e for e in entries if e.alert_enabled]
        print(
            f"Harvested {len(entries)} address(es) from {stats['cases_parsed']} "
            f"case(s) ({stats['real_cases']} real, {stats['test_cases']} test) "
            f"-> {out_path}"
        )
        print(f"  ARMED (alert-triggering): {len(armed)}")
        for e in armed[:15]:
            print(
                f"    [{e.confidence}] {e.address} ({e.role}) "
                f"- {e.real_case_count} real case(s)"
            )
        sys.exit(0)

    if args.command in ("blacklist-arm", "blacklist-disarm"):
        from recupero.labels.internal_blacklist import (
            add_manual_arm,
            default_manual_arm_path,
            remove_manual_arm,
        )
        mpath = default_manual_arm_path()
        if args.command == "blacklist-arm":
            try:
                added = add_manual_arm(
                    mpath, args.address, args.chain,
                    reason=args.reason, label_name=args.arm_label,
                )
            except ValueError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                sys.exit(2)
            verb = "Armed" if added else "Updated"
            print(f"{verb} {args.address} ({args.chain}) on the internal "
                  f"blacklist -> {mpath}. Screener + tracer now fire on a hit.")
            sys.exit(0)
        removed = remove_manual_arm(mpath, args.address, args.chain)
        print(f"{'Disarmed' if removed else 'No manual entry for'} "
              f"{args.address} ({args.chain}).")
        sys.exit(0 if removed else 1)

    if args.command == "benchmark":
        import json as _json
        from pathlib import Path as _Path

        from recupero.trace.benchmark import load_ground_truth, score_case_dir
        case_dir = _Path(args.benchmark_case)
        truth_path = _Path(args.benchmark_truth)
        if not case_dir.exists():
            print(f"ERROR: case dir not found: {case_dir}", file=sys.stderr)
            sys.exit(2)
        if not truth_path.exists():
            print(f"ERROR: ground-truth not found: {truth_path}", file=sys.stderr)
            sys.exit(2)
        try:
            truth = load_ground_truth(truth_path)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(2)
        score = score_case_dir(case_dir, truth)
        print(_json.dumps(score.to_dict(), indent=2))
        sys.exit(0)

    if args.command == "graph-analyze":
        import json as _json
        from pathlib import Path as _Path

        from recupero.trace.graph_analysis import analyze_case_graph
        case_dir = _Path(args.graph_case)
        case_json = case_dir / "case.json"
        if not case_json.exists():
            print(f"ERROR: case.json not found in {case_dir}", file=sys.stderr)
            sys.exit(2)
        try:
            data = _json.loads(case_json.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: case.json unreadable: {exc}", file=sys.stderr)
            sys.exit(2)
        analysis = analyze_case_graph(
            data, min_distinct_sources=max(2, int(args.graph_min_sources or 3)),
        )
        print(_json.dumps(analysis.to_dict(), indent=2))
        sys.exit(0)

    if args.command == "label-freshness":
        import json as _json
        from datetime import UTC as _UTC
        from datetime import datetime as _dt

        from recupero.labels.freshness import build_freshness_report
        report = build_freshness_report(now=_dt.now(_UTC))
        print(_json.dumps(report, indent=2))
        # Non-zero exit when OFAC is critical, so a cron wrapper can alert.
        sys.exit(1 if report["summary"]["ofac_status"] == "critical" else 0)

    if args.command == "bridge-sync":
        from pathlib import Path as _Path

        from recupero.ops.commands import bridge_sync_cmd as bs
        sys.exit(bs.run(
            bridges_path=_Path(args.bridges) if args.bridges else None,
            output_path=_Path(args.output) if args.output else None,
            offline=bool(args.offline),
        ))

    if args.command == "retrace-scan":
        # v0.31.2 (Gap #14): observability cron. The same logic is also
        # exposed as ``python scripts/retrace_backfill_scan.py`` and as
        # ``python -m recupero.worker.retrace_backfill`` — this is the
        # ops-CLI entry so operators get the command via the same
        # surface they use for every other periodic task.
        from pathlib import Path as _Path

        from recupero.config import load_config
        from recupero.worker.retrace_backfill import (
            DEFAULT_OUT_RELATIVE,
            run_backfill_scan,
        )
        cfg, _env = load_config()
        out_path = (
            _Path(args.out) if args.out else _Path(DEFAULT_OUT_RELATIVE)
        )
        n = run_backfill_scan(config=cfg, out_path=out_path)
        print(f"retrace-scan: {n} candidate(s) → {out_path}")
        sys.exit(0)

    if args.command == "hack-tracker":
        # v0.20.0 (Phase D): feature-flagged hack-feed aggregator.
        # Currently only the `daily` subcommand is wired; future
        # subcommands (e.g., `mark-read`, `export-csv`) will land
        # without changing the top-level CLI surface.
        from recupero.hack_tracker.digest_cli import run as _tracker_run
        if args.tracker_command == "daily":
            sys.exit(_tracker_run(
                hours=args.hours,
                output_format=args.format,
            ))
        print(f"unknown hack-tracker subcommand: {args.tracker_command!r}")
        sys.exit(2)

    if args.command == "correlation-stats":
        from recupero.ops.commands import correlation_stats as cmd
        sys.exit(cmd.run(dsn=_require_dsn()))

    if args.command == "custody-keygen":
        from pathlib import Path as _Path

        from recupero.ops.commands import custody_cmd as cmd
        out = _Path(args.output_path) if args.output_path else None
        sys.exit(cmd.run_keygen(output_path=out))

    if args.command == "custody-verify":
        from pathlib import Path as _Path

        from recupero.ops.commands import custody_cmd as cmd
        sys.exit(cmd.run_verify(
            case_dir=_Path(args.case_dir),
            public_key_b64=args.public_key,
        ))

    if args.command == "refresh-freeze-priors":
        from recupero.freeze_learning.recorder import refresh_priors
        n = refresh_priors(_require_dsn())
        print(f"Refreshed {n} per-issuer prior(s) in issuer_freeze_priors.")
        sys.exit(0)

    if args.command == "cooperation-dashboard":
        from pathlib import Path as _Path

        from recupero.reports.cooperation_dashboard import (
            render_cooperation_dashboard,
        )
        out_dir = _Path(args.output_dir)
        out_path = render_cooperation_dashboard(
            output_dir=out_dir,
            dsn=_require_dsn(),
        )
        if out_path is None:
            print(
                "ERROR: cooperation dashboard render failed — no issuers "
                "with freeze-letter history on file yet, or DB unreachable.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"Rendered cooperation dashboard to {out_path}")
        sys.exit(0)

    if args.command == "law-firm-dashboard":
        from pathlib import Path as _Path

        from recupero.reports.law_firm_dashboard import (
            render_all_law_firm_dashboards,
            render_law_firm_dashboard,
        )
        out_dir = _Path(args.output_dir)
        # --firm and --all are mutually exclusive at the argparse layer
        # (we enforce here rather than via add_mutually_exclusive_group
        # to keep --all opt-in not required).
        if args.all_firms and args.firm_key:
            print(
                "ERROR: --firm and --all are mutually exclusive.",
                file=sys.stderr,
            )
            sys.exit(2)
        if not args.all_firms and not args.firm_key:
            print(
                "ERROR: pass --firm <slug-or-uuid> for one firm, or "
                "--all to render every active firm.",
                file=sys.stderr,
            )
            sys.exit(2)

        if args.all_firms:
            paths = render_all_law_firm_dashboards(
                output_dir=out_dir, dsn=_require_dsn(),
            )
            if not paths:
                print(
                    "ERROR: no firms rendered — none are active, or DB "
                    "unreachable.",
                    file=sys.stderr,
                )
                sys.exit(2)
            for p in paths:
                print(f"Rendered {p}")
            sys.exit(0)

        out_path = render_law_firm_dashboard(
            args.firm_key, output_dir=out_dir, dsn=_require_dsn(),
        )
        if out_path is None:
            print(
                f"ERROR: dashboard render failed for firm "
                f"{args.firm_key!r} — firm not found, or DB unreachable.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"Rendered law-firm dashboard to {out_path}")
        sys.exit(0)

    if args.command == "watchlist-dashboard":
        from pathlib import Path as _Path

        from recupero.reports.watchlist_dashboard import (
            render_watchlist_dashboard,
        )
        out_path = render_watchlist_dashboard(
            output_dir=_Path(args.output_dir),
            dsn=_require_dsn(),
            investigation_id=args.investigation_id,
            stale_after_hours=args.stale_after_hours,
        )
        if out_path is None:
            print(
                "ERROR: watchlist dashboard render failed — DB unreachable.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"Rendered watchlist dashboard to {out_path}")
        sys.exit(0)

    if args.command == "watchlist-run":
        from recupero.config import load_config
        from recupero.worker.watch_tick import run_watch_tick
        cfg, env = load_config()
        report = run_watch_tick(
            dsn=_require_dsn(), config=cfg, env=env,
            parallelism=args.parallelism, limit=args.limit,
        )
        print(
            f"watchlist-run: snapshotted {report.snapshotted}/"
            f"{report.candidates} eligible · "
            f"{len(report.material_changes)} moved · "
            f"{report.skipped_cooldown} on cooldown · "
            f"{len(report.errors)} errors"
        )
        for mc in report.material_changes:
            print(f"  MOVED: {mc}")
        sys.exit(0)

    if args.command == "validate-output":
        from pathlib import Path as _Path

        from recupero.validators.output_integrity import validate_case_output
        case_dir = _Path(args.case_dir)
        result = validate_case_output(case_dir)
        if args.json:
            import json as _json
            print(_json.dumps({
                "ok": result.ok,
                "critical_count": result.critical_count,
                "high_count": result.high_count,
                "checks_run": result.checks_run,
                "violations": [
                    {
                        "check": v.check, "severity": v.severity,
                        "detail": v.detail, "file": v.file,
                    }
                    for v in result.violations
                ],
            }, indent=2))
        else:
            print(result.summary_text())
        sys.exit(0 if result.ok else 1)

    if args.command == "nightly-audit":
        # Delegate to scripts/nightly_audit.py — keep the orchestrator
        # in a single place so the cron-driven path and the ops-CLI
        # path produce identical digests.
        from pathlib import Path as _Path
        script = (
            _Path(__file__).resolve().parents[3] / "scripts" / "nightly_audit.py"
        )
        if not script.exists():
            print(
                f"ERROR: nightly_audit.py not found at {script}",
                file=sys.stderr,
            )
            sys.exit(2)
        forward = [
            sys.executable, str(script),
            "--out-json", args.out_json,
        ]
        if args.baseline:
            forward += ["--baseline", args.baseline]
        if args.skip:
            forward += ["--skip", args.skip]
        if args.llm_review:
            forward.append("--llm-review")
        import subprocess as _sp
        rc = _sp.call(forward)
        sys.exit(rc)

    if args.command == "api-key-mint":
        import re as _re
        import secrets as _secrets
        # Validate the name shape — it goes into RECUPERO_API_KEYS
        # which uses ',' as pair separator and ':' as name/secret
        # separator. A name containing those breaks the parser.
        if not _re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$", args.name):
            print(
                "ERROR: name must be 2-64 chars, ASCII alphanumeric / "
                "underscore / dash, starting with alphanumeric.",
                file=sys.stderr,
            )
            sys.exit(2)
        if args.key_bytes < 16:
            print(
                "ERROR: --bytes must be >= 16 (a 16-byte secret = "
                "128-bit entropy; smaller is brute-forceable).",
                file=sys.stderr,
            )
            sys.exit(2)
        secret = _secrets.token_hex(args.key_bytes)
        # v0.27.1 (HIGH-3): emit the SECRET to stderr (not stdout)
        # with a clear banner so operators piping `... | tee` or
        # capturing CI logs don't accidentally persist the key.
        # Stdout receives only the non-secret snippet with the
        # secret REDACTED, so logs are safe.
        print("=" * 64, file=sys.stderr)
        print(
            "DO NOT COPY THIS TO LOGS - STDERR ONLY",
            file=sys.stderr,
        )
        print(f"  Name:   {args.name}", file=sys.stderr)
        print(f"  Secret: {secret}", file=sys.stderr)
        print(
            "  Append to RECUPERO_API_KEYS env "
            "(comma-separated pairs):",
            file=sys.stderr,
        )
        print(f"  {args.name}:{secret}", file=sys.stderr)
        print("=" * 64, file=sys.stderr)
        # Stdout — safe to capture / log.
        print(f"# Generated API key for partner: {args.name}")
        print(f"# Secret printed to STDERR (length={len(secret)} hex chars).")
        print("# Append to RECUPERO_API_KEYS env (REDACTED form shown):")
        print(f"{args.name}:***")
        print()
        print("# Partner integration snippet (substitute real secret):")
        print("#   curl -H 'X-Recupero-API-Key: <SECRET>' \\")
        print("#        https://api.recupero.io/v1/health")
        sys.exit(0)

    if args.command == "render-cluster":
        from pathlib import Path as _Path

        from recupero.reports.cluster_handoff import render_cluster_handoff
        out_dir = _Path(args.output_dir)
        out_path = render_cluster_handoff(
            args.public_id,
            output_dir=out_dir,
            dsn=_require_dsn(),
        )
        if out_path is None:
            print(
                f"ERROR: cluster {args.public_id!r} not found or render failed "
                "(see logs).",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"Rendered cluster handoff to {out_path}")
        sys.exit(0)

    if args.command == "record-freeze-outcome":
        from decimal import Decimal as _Decimal

        # Two forms — positional letter_id OR case-scoped triple.
        # Mutually exclusive: surface a clear error if the operator
        # mixes them.
        has_letter_id = bool(args.letter_id)
        has_triple = bool(args.case and args.issuer and args.target_address)
        if has_letter_id and has_triple:
            print("ERROR: pass either positional letter_id OR --case/--issuer/"
                  "--target-address, not both.", file=sys.stderr)
            sys.exit(2)
        if not has_letter_id and not has_triple:
            print("ERROR: must provide either letter_id (positional) "
                  "or --case + --issuer + --target-address.",
                  file=sys.stderr)
            sys.exit(2)

        # Z13-4: wrap Decimal parsing so a malformed --frozen-usd /
        # --returned-usd argument produces a clean ERROR + exit 2
        # rather than a ``decimal.InvalidOperation`` traceback.
        try:
            frozen = _Decimal(args.frozen_usd) if args.frozen_usd else None
            returned = _Decimal(args.returned_usd) if args.returned_usd else None
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: invalid --frozen-usd/--returned-usd: {e}",
                  file=sys.stderr)
            sys.exit(2)

        if has_letter_id:
            # Legacy form: record_outcome by letter_id.
            from recupero.freeze_learning.recorder import record_outcome
            # Z13-4: wrap record_outcome() — the recorder raises
            # ValueError for non-finite frozen_usd; without this try
            # the operator sees a traceback instead of ``ERROR: ...``.
            try:
                out_id = record_outcome(
                    letter_id=_parse_uuid(args.letter_id, field_name="letter_id"),
                    outcome_type=args.outcome,
                    frozen_usd=frozen,
                    returned_usd=returned,
                    operator_notes=args.note,
                    dsn=_require_dsn(),
                )
            except ValueError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                sys.exit(2)
            if out_id is None:
                print("ERROR: failed to record outcome (see logs).")
                sys.exit(1)
            print(f"Recorded outcome {out_id} for letter {args.letter_id}.")
            sys.exit(0)

        # v0.21.0 case-scoped form
        from recupero.freeze_learning.recorder import (
            LetterNotFoundError,
            record_outcome_by_target,
        )
        try:
            out_id = record_outcome_by_target(
                case_id=_parse_uuid(args.case, field_name="--case"),
                issuer=args.issuer,
                target_address=args.target_address,
                asset_symbol=args.asset_symbol,
                outcome_type=args.outcome,
                frozen_usd=frozen,
                returned_usd=returned,
                operator_notes=args.note,
                dsn=_require_dsn(),
            )
        except LetterNotFoundError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)
        except (ValueError, RuntimeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        print(
            f"Recorded outcome {out_id} for case {args.case} / "
            f"issuer {args.issuer} / address {args.target_address}."
        )
        sys.exit(0)

    if args.command == "validate-labels":
        from recupero.labels.validator import main as _validator_main
        sys.exit(_validator_main())

    if args.command == "diagnose-case":
        from pathlib import Path as _Path

        from recupero.config import load_config
        from recupero.ops.commands import diagnose_case as cmd
        if args.case_dir:
            case_dir = _Path(args.case_dir)
        else:
            # v0.16.3 (audit fix #B5): use raw Path resolution, not
            # CaseStore.case_dir(), because the latter MUTATES the
            # filesystem (mkdir + tx_evidence/logs subdirs). For a
            # READ-ONLY diagnostic this is wrong — running
            # `diagnose-case V-DOESNT-EXIST` would create a stub dir
            # then misleadingly report "EXISTS / case.json MISSING".
            cfg, _env = load_config()
            case_dir = _Path(cfg.storage.data_dir) / "cases" / args.case_id
        sys.exit(cmd.run(case_id=args.case_id, case_dir=case_dir))

    if args.command == "list-payments":
        from recupero.ops.commands import list_payments as cmd
        case_uuid: UUID | None = None
        if args.case_id_filter:
            case_uuid = _parse_uuid(args.case_id_filter, field_name="case_id")
        sys.exit(cmd.run(
            limit=args.limit, since=args.since, case_id=case_uuid,
            dsn=_require_dsn(),
        ))

    if args.command == "generate-payment-link":
        from recupero.ops.commands import generate_payment_link as cmd
        investigation_uuid: UUID | None = None
        if args.investigation_id:
            investigation_uuid = _parse_uuid(
                args.investigation_id, field_name="investigation_id",
            )
        sys.exit(cmd.run(
            case_id=_parse_uuid(args.case_id, field_name="case_id"),
            link_type=args.link_type,
            chain=args.chain,
            seed_address=args.seed_address,
            investigation_id=investigation_uuid,
            prefilled_email=args.prefilled_email,
            dsn=_require_dsn(),
        ))

    print(f"ERROR: unknown command {args.command!r}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    cli()
