"""Recupero CLI.

Run via `recupero` (after `pip install -e .`) or `python -m recupero.cli`.

Phase 1 commands:
    recupero trace      Run a trace and write a case folder
    recupero show       Print a brief summary of an existing case
    recupero inspect    Quick on-chain profile of a single address
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from recupero.config import load_config
from recupero.inspect.inspector import DEEP_WINDOW, DEFAULT_WINDOW, inspect_address
from recupero.labels.store import LabelStore
from recupero.logging_setup import setup_logging
from recupero.models import Chain, LabelCategory
from recupero.reports.aggregate import aggregate_stolen, format_aggregate_markdown, write_aggregate_json
from recupero.reports.brief import InvestigatorInfo, IssuerInfo, MIDAS_ISSUER, generate_briefs
from recupero.reports.victim import VictimInfo, load_victim, write_victim
from recupero.storage.case_store import CaseStore
from recupero.trace.tracer import run_trace

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Recupero — crypto theft tracing.")
console = Console()
log = logging.getLogger(__name__)


@app.command("trace")
def trace_cmd(
    chain: str = typer.Option("ethereum", help="Chain to trace: ethereum, arbitrum, bsc, or solana."),
    address: str = typer.Option(..., help="Seed (victim) address."),
    incident_time: str = typer.Option(..., help="ISO-8601 UTC timestamp of the incident."),
    case_id: str = typer.Option(..., help="Identifier for this case. Becomes folder name."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config override."),
    max_depth: int | None = typer.Option(None, help="Override trace depth. 1=single hop (default), 2-5=recursive BFS trace."),
    dust_threshold_usd: float | None = typer.Option(None, help="Skip transfers below this USD value. Default 50."),
    follow_contracts: bool = typer.Option(
        False, "--follow-contracts",
        help="By default the tracer stops at contract destinations (DeFi routers, pools). "
             "Use this flag to follow them (produces much larger traces).",
    ),
    follow_bridges: bool = typer.Option(
        False, "--follow-bridges",
        help="By default the tracer stops at labeled bridges (cross-chain flows can't "
             "be followed with a single-chain adapter). Use this to record bridge-side "
             "transfers on the current chain even if labeled as bridge.",
    ),
) -> None:
    cfg, env = load_config(config_path)
    if max_depth is not None:
        cfg.trace.max_depth = max_depth
    if dust_threshold_usd is not None:
        cfg.trace.dust_threshold_usd = dust_threshold_usd
    # Thread through to the trace policy via the config. TraceParams will accept
    # these fields (added in v13); if they're not there yet we just set them on
    # the object so getattr-style access still finds them.
    if follow_contracts:
        cfg.trace.stop_at_contract = False
    if follow_bridges:
        cfg.trace.stop_at_bridge = False

    try:
        chain_enum_early = Chain(chain)
    except ValueError:
        console.print(f"[bold red]Unknown chain:[/] {chain}")
        raise typer.Exit(code=2)

    # API key requirements vary by chain
    if chain_enum_early == Chain.solana:
        if not env.HELIUS_API_KEY:
            console.print("[bold red]Missing HELIUS_API_KEY in .env (required for Solana tracing)[/]")
            raise typer.Exit(code=2)
    elif not env.ETHERSCAN_API_KEY:
        console.print("[bold red]Missing ETHERSCAN_API_KEY in .env[/]")
        raise typer.Exit(code=2)

    store = CaseStore(cfg)
    case_dir = store.case_dir(case_id)
    setup_logging(cfg.logging.level, case_dir)

    chain_enum = chain_enum_early

    # Advisory: BSC is not on Etherscan V2's free tier. Fail fast with guidance
    # instead of making the user wade through a stack trace.
    if chain_enum == Chain.bsc:
        console.print(
            "[bold yellow]Warning:[/] BSC is not supported on Etherscan V2's free tier. "
            "The API will reject the request.\n"
            "Options: (1) upgrade your Etherscan plan at https://etherscan.io/apis, "
            "(2) wait for a future patch adding an alternative BSC data source "
            "(bscscan.com free tier, Alchemy, or a public RPC)."
        )
        # Allow the user to proceed anyway in case they've upgraded their key

    try:
        when = datetime.fromisoformat(incident_time.replace("Z", "+00:00"))
    except ValueError:
        console.print(f"[bold red]Bad incident_time (need ISO-8601): {incident_time}[/]")
        raise typer.Exit(code=2) from None

    try:
        case = run_trace(
            chain=chain_enum,
            seed_address=address,
            incident_time=when,
            case_id=case_id,
            config=cfg,
            env=env,
            case_dir=case_dir,
        )
    except Exception as e:  # noqa: BLE001
        # Surface common API errors cleanly instead of dumping a stack trace.
        err_msg = str(e).lower()
        if "free api access is not supported" in err_msg or "upgrade your api plan" in err_msg:
            console.print(
                f"\n[bold red]API tier limit:[/] the free Etherscan V2 tier does not "
                f"support {chain_enum.value}. Upgrade at https://etherscan.io/apis "
                f"or use a different data source."
            )
            raise typer.Exit(code=3) from None
        if "invalid api key" in err_msg or "http 401" in err_msg:
            console.print(
                f"\n[bold red]API key rejected:[/] check ETHERSCAN_API_KEY / "
                f"HELIUS_API_KEY in .env."
            )
            raise typer.Exit(code=3) from None
        # Anything else: let the original exception propagate so we can see it
        raise

    case_path = store.write_case(case)

    _print_summary(case)
    console.print(f"\n[bold green]Wrote[/] {case_path}")
    console.print(f"[bold green]Wrote[/] {case_dir / 'transfers.csv'}")


@app.command("show")
def show_cmd(case_id: str = typer.Argument(..., help="Case ID to summarize.")) -> None:
    cfg, _ = load_config()
    store = CaseStore(cfg)
    try:
        case = store.read_case(case_id)
    except FileNotFoundError:
        console.print(f"[bold red]No case found:[/] {case_id}")
        raise typer.Exit(code=1) from None
    _print_summary(case)


def _print_summary(case) -> None:
    console.print(f"\n[bold]Case:[/] {case.case_id}")
    console.print(f"[bold]Seed:[/] {case.seed_address} ({case.chain.value})")
    console.print(f"[bold]Incident:[/] {case.incident_time.isoformat()}")
    console.print(f"[bold]Transfers:[/] {len(case.transfers)}")
    console.print(f"[bold]Total USD out:[/] {case.total_usd_out}")
    console.print(f"[bold]Unlabeled counterparties:[/] {len(case.unlabeled_counterparties)}")

    if case.exchange_endpoints:
        t = Table(title="Exchange endpoints (FREEZE TARGETS)", show_lines=False)
        t.add_column("Exchange", style="bold cyan")
        t.add_column("Address")
        t.add_column("USD received", justify="right", style="bold yellow")
        t.add_column("Deposits", justify="right")
        t.add_column("First / Last")
        for ep in case.exchange_endpoints:
            t.add_row(
                ep.exchange,
                ep.address,
                str(ep.total_received_usd) if ep.total_received_usd else "?",
                str(len(ep.transfer_ids)),
                f"{ep.first_deposit_at.date()} → {ep.last_deposit_at.date()}",
            )
        console.print(t)
    else:
        console.print("[yellow]No exchange endpoints detected.[/]")


@app.command("inspect")
def inspect_cmd(
    address: str = typer.Argument(..., help="Address to inspect."),
    chain: str = typer.Option("ethereum", help="Chain. Phase 1 supports only 'ethereum'."),
    deep: bool = typer.Option(False, "--deep", help=f"Pull up to {DEEP_WINDOW} txs (slower) instead of {DEFAULT_WINDOW}."),
    save_label: str | None = typer.Option(
        None, "--save-label",
        help=(
            "If set, persist the inspection's likely identity as a label using the given category. "
            f"Choices: {', '.join(c.value for c in LabelCategory)}"
        ),
    ),
    save_label_name: str | None = typer.Option(
        None, "--save-label-name",
        help="Override the saved label's display name (defaults to the inspector's likely_identity).",
    ),
    save_label_exchange: str | None = typer.Option(
        None, "--save-label-exchange",
        help="Set the exchange field on the saved label (only relevant for exchange_* categories).",
    ),
    save_label_file: str = typer.Option(
        "inspector", "--save-label-file",
        help="Save into data/labels/local_<file>.json. Default 'inspector'.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Print the profile as JSON instead of a formatted table."),
) -> None:
    cfg, env = load_config()
    if not env.ETHERSCAN_API_KEY:
        console.print("[bold red]Missing ETHERSCAN_API_KEY in .env[/]")
        raise typer.Exit(code=2)

    # Inspector logs are quiet (no per-case file handler — this is interactive)
    setup_logging(cfg.logging.level)

    try:
        chain_enum = Chain(chain)
    except ValueError:
        console.print(f"[bold red]Unsupported chain: {chain}[/]")
        raise typer.Exit(code=2) from None

    label_store = LabelStore.load(cfg)
    profile = inspect_address(
        address=address,
        chain=chain_enum,
        config=cfg,
        env=env,
        label_store=label_store,
        window=DEEP_WINDOW if deep else DEFAULT_WINDOW,
    )

    if json_out:
        console.print_json(profile.model_dump_json(indent=2))
    else:
        _print_profile(profile)

    if save_label:
        try:
            cat = LabelCategory(save_label)
        except ValueError:
            console.print(
                f"[bold red]Bad --save-label category. Choose from:[/] {', '.join(c.value for c in LabelCategory)}"
            )
            raise typer.Exit(code=2) from None
        out_dir = Path(cfg.storage.data_dir) / "labels"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"local_{save_label_file}.json"
        existing = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else []
        new_entry = {
            "address": profile.address,
            "name": save_label_name or profile.likely_identity or "Inspector-saved label",
            "category": cat.value,
            "exchange": save_label_exchange,
            "source": f"inspector:{datetime.now(timezone.utc).date().isoformat()}",
            "confidence": "medium",
            "notes": profile.likely_identity_reason or "Saved from `recupero inspect`",
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        existing.append(new_entry)
        out_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        console.print(f"\n[green]Saved label to {out_path}[/]")


def _print_profile(p) -> None:
    console.print()
    console.print(f"[bold]Inspecting[/] {p.address} on {p.chain.value}")
    console.print(f"[dim]{p.explorer_url}[/]\n")

    typ = "Contract" if p.is_contract else "EOA"
    if p.is_contract and p.contract_name:
        typ += f" (verified: [cyan]{p.contract_name}[/])"
        if p.contract_proxy:
            typ += " [proxy]"
    elif p.is_contract:
        typ += " (unverified bytecode)"
    console.print(f"  [bold]Type:[/]               {typ}")

    if p.existing_label:
        lbl = p.existing_label
        console.print(
            f"  [bold]Known label:[/]        [yellow]{lbl.name}[/] "
            f"({lbl.category.value}, source: {lbl.source})"
        )
    else:
        console.print("  [bold]Known label:[/]        [dim]none[/]")

    if p.first_seen_at:
        console.print(f"  [bold]First seen:[/]         {p.first_seen_at.date()} (block {p.first_seen_block})")
    if p.last_seen_at:
        console.print(f"  [bold]Last seen:[/]          {p.last_seen_at.date()} (block {p.last_seen_block})")
    cap_marker = "+" if p.observed_tx_count_capped else ""
    console.print(f"  [bold]Tx count (window):[/]  {p.observed_tx_count}{cap_marker}")
    if p.eth_balance is not None:
        console.print(f"  [bold]ETH balance:[/]        {p.eth_balance:.6f} ETH")

    if p.top_counterparties:
        console.print()
        t = Table(title="Top counterparties (by tx count in window)", show_lines=False)
        t.add_column("Address")
        t.add_column("Txs", justify="right")
        t.add_column("Known label")
        for cp in p.top_counterparties:
            label_str = f"{cp.label.name} ({cp.label.category.value})" if cp.label else "—"
            t.add_row(cp.address, str(cp.tx_count), label_str)
        console.print(t)

    if p.likely_identity:
        console.print(f"\n  [bold]Likely identity:[/]    [bold cyan]{p.likely_identity}[/]")
        if p.likely_identity_reason:
            console.print(f"  [dim]{p.likely_identity_reason}[/]")
    console.print()


@app.command("aggregate")
def aggregate_cmd(
    cases: str = typer.Option(..., "--cases", help="Comma-separated list of case IDs to aggregate."),
    perpetrators: str = typer.Option(..., "--perpetrators", help="Comma-separated list of perpetrator addresses."),
    out_json: str | None = typer.Option(
        None, "--out-json",
        help="Optional path to write the full aggregate JSON. Default: data/cases/aggregate_<timestamp>.json",
    ),
) -> None:
    """Sum perpetrator-bound transfers across many cases. Outputs markdown + JSON."""
    cfg, _ = load_config()
    setup_logging(cfg.logging.level)
    store = CaseStore(cfg)

    case_ids = [c.strip() for c in cases.split(",") if c.strip()]
    perp_addrs = [p.strip() for p in perpetrators.split(",") if p.strip()]
    if not case_ids:
        console.print("[bold red]No cases specified[/]")
        raise typer.Exit(code=2)
    if not perp_addrs:
        console.print("[bold red]No perpetrators specified[/]")
        raise typer.Exit(code=2)

    cases_loaded = []
    for cid in case_ids:
        try:
            cases_loaded.append(store.read_case(cid))
        except FileNotFoundError:
            console.print(f"[yellow]Case not found, skipping:[/] {cid}")

    result = aggregate_stolen(cases=cases_loaded, perpetrator_addresses=perp_addrs)

    md = format_aggregate_markdown(result)
    console.print()
    console.print(md)

    out_path = Path(out_json) if out_json else (
        Path(cfg.storage.data_dir) / "cases" / f"aggregate_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_aggregate_json(result, out_path)
    console.print()
    console.print(f"[green]Wrote full aggregate to[/] [cyan]{out_path}[/]")


@app.command("hyperliquid-scrape")
def hyperliquid_scrape_cmd(
    address: str = typer.Option(..., help="Wallet address to scrape (Hyperliquid uses Ethereum-format addresses)."),
    incident_time: str = typer.Option(..., help="ISO-8601 UTC timestamp of the incident."),
    case_id: str = typer.Option(..., help="Case ID (becomes folder name under data/cases/)."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config override."),
) -> None:
    """Fetch Hyperliquid non-funding ledger events (deposits, withdrawals, transfers)
    and write them as a case file. No API key required."""
    from decimal import Decimal
    from recupero.chains.hyperliquid.scraper import scrape_hyperliquid_case

    cfg, env = load_config(config_path)
    store = CaseStore(cfg)
    case_dir = store.case_dir(case_id)
    setup_logging(cfg.logging.level, case_dir)

    try:
        when = datetime.fromisoformat(incident_time.replace("Z", "+00:00"))
    except ValueError:
        console.print(f"[bold red]Bad incident_time (need ISO-8601): {incident_time}[/]")
        raise typer.Exit(code=2) from None

    case = scrape_hyperliquid_case(
        user_address=address,
        case_id=case_id,
        incident_time=when,
        config=cfg,
        env=env,
    )
    case_path = store.write_case(case)

    usd_total = sum(
        (t.usd_value_at_tx for t in case.transfers if t.usd_value_at_tx is not None),
        start=Decimal("0"),
    )
    outflows = [t for t in case.transfers if t.from_address.lower() == address.lower()]
    inflows = [t for t in case.transfers if t.to_address.lower() == address.lower()]

    console.print()
    console.print(f"[bold]Hyperliquid scrape:[/] {address}")
    console.print(f"  Case: {case.case_id}")
    console.print(f"  Events: {len(case.transfers)} ({len(outflows)} outflows, {len(inflows)} inflows)")
    console.print(f"  Total USDC movement: ${usd_total:,.2f}")
    console.print(f"  Wrote {case_path}")


@app.command("find-dormant")
def find_dormant_cmd(
    case_id: str = typer.Argument(..., help="Case ID to analyze."),
    min_usd: float = typer.Option(10000.0, help="Only report addresses with >= this USD value (default $10K)."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config override."),
) -> None:
    """Find addresses from a case that still hold meaningful USD value.

    These are your potential freeze targets — addresses where stolen money
    landed and hasn't moved since. The output is sorted by current USD held,
    descending. Currently Ethereum-only (Solana/Arbitrum/BSC support pending).
    """
    from decimal import Decimal as _D
    from recupero.dormant import find_dormant_in_case, write_dormant_report

    cfg, env = load_config(config_path)
    if not env.ETHERSCAN_API_KEY:
        console.print("[bold red]Missing ETHERSCAN_API_KEY in .env[/]")
        raise typer.Exit(code=2)

    store = CaseStore(cfg)
    try:
        case = store.read_case(case_id)
    except FileNotFoundError:
        console.print(f"[bold red]No case found:[/] {case_id}")
        raise typer.Exit(code=1) from None

    setup_logging(cfg.logging.level, store.case_dir(case_id))

    console.print(f"\n[bold]Scanning case {case_id} for dormant freeze targets[/]")
    console.print(f"  Chain: {case.chain.value}")
    console.print(f"  Transfers in case: {len(case.transfers)}")
    console.print(f"  Min USD threshold: ${min_usd:,.2f}\n")

    candidates = find_dormant_in_case(
        case=case, config=cfg, env=env, min_usd=_D(str(min_usd)),
    )

    if not candidates:
        console.print("[yellow]No addresses found holding ≥ threshold.[/]")
        console.print(
            "  This might mean: (a) all stolen funds have been moved through, "
            "(b) the case isn't deep enough — try re-tracing with --max-depth 3+, "
            "(c) the threshold is too high — try --min-usd 1000."
        )
        return

    # Pretty-print top candidates
    console.print(f"[bold green]Found {len(candidates)} dormant target(s):[/]\n")
    for i, c in enumerate(candidates, start=1):
        console.print(f"  {i}. [bold]{c.address}[/]  →  [bold green]${c.total_usd:,.2f}[/]")
        console.print(f"     Holdings: {c.top_holding_summary()}")
        console.print(
            f"     Received during case: ${c.inflow_usd_during_case:,.2f} "
            f"across {c.inflow_count} transfer(s)"
        )
        console.print(f"     Explorer: {c.explorer_url}\n")

    out_path = write_dormant_report(store.case_dir(case_id), candidates)
    console.print(f"[bold]Wrote[/] {out_path}")


@app.command("list-freeze-targets")
def list_freeze_targets_cmd(
    case_id: str = typer.Argument(..., help="Case ID to analyze."),
    min_usd: float = typer.Option(10000.0, help="Min USD per dormant address (default $10K)."),
    min_holding_usd: float = typer.Option(1000.0, help="Min USD per individual holding (default $1K)."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config override."),
) -> None:
    """End-to-end freeze-target identification: find dormant wallets, match to
    issuers, and print a ranked action list of who to email and what to ask for.

    This is the closest thing to a one-command answer for "what do I do with
    this case." For each freezable holding, you get the issuer's contact info,
    their freeze capability rating, and a short summary line.
    """
    from decimal import Decimal as _D
    from recupero.dormant import find_dormant_in_case
    from recupero.freeze import group_by_issuer, match_freeze_asks

    cfg, env = load_config(config_path)
    if not env.ETHERSCAN_API_KEY:
        console.print("[bold red]Missing ETHERSCAN_API_KEY in .env[/]")
        raise typer.Exit(code=2)

    store = CaseStore(cfg)
    try:
        case = store.read_case(case_id)
    except FileNotFoundError:
        console.print(f"[bold red]No case found:[/] {case_id}")
        raise typer.Exit(code=1) from None

    setup_logging(cfg.logging.level, store.case_dir(case_id))

    console.print(f"\n[bold]Step 1/2:[/] Finding dormant addresses in {case_id}...")
    candidates = find_dormant_in_case(
        case=case, config=cfg, env=env, min_usd=_D(str(min_usd)),
    )
    if not candidates:
        console.print("[yellow]No dormant addresses found at the given threshold.[/]")
        return

    console.print(f"  Found {len(candidates)} dormant candidate(s).\n")
    console.print(f"[bold]Step 2/2:[/] Matching token holdings to known issuers...\n")

    matched, unmatched = match_freeze_asks(
        candidates, min_holding_usd=_D(str(min_holding_usd)),
    )

    if not matched:
        console.print(
            "[yellow]No matched freeze asks found.[/] The dormant wallets hold "
            "tokens we don't have issuer info for. Add them to "
            "src/recupero/labels/seeds/issuers.json if they're worth chasing."
        )
        if unmatched:
            console.print(f"\n[dim]Unmatched holdings worth investigating:[/]")
            for h in unmatched[:10]:
                usd = f"${h.usd_value:,.2f}" if h.usd_value else "?"
                console.print(f"  - {h.decimal_amount:,.2f} {h.token.symbol} ({usd}) — contract: {h.token.contract}")
        return

    console.print(f"[bold green]Found {len(matched)} actionable freeze ask(s):[/]\n")

    grouped = group_by_issuer(matched)
    for issuer_name, asks in grouped.items():
        total = sum((a.holding_usd_value or _D("0") for a in asks), start=_D("0"))
        first = asks[0]  # all asks for one issuer share the same IssuerEntry contact info
        cap_color = {"yes": "green", "limited": "yellow", "no": "red"}.get(
            first.issuer.freeze_capability, "white"
        )
        console.print(f"[bold cyan]→ {issuer_name}[/]  ([{cap_color}]freeze: {first.issuer.freeze_capability}[/])")
        console.print(f"  Contact:      {first.issuer.primary_contact or '(none — see notes)'}")
        if first.issuer.secondary_contact:
            console.print(f"  Secondary:    {first.issuer.secondary_contact}")
        console.print(f"  Jurisdiction: {first.issuer.jurisdiction}")
        console.print(f"  Total ask:    [bold green]${total:,.2f}[/] across {len(asks)} holding(s)")
        console.print(f"  Notes:        {first.issuer.freeze_notes}")
        for ask in asks:
            console.print(f"    • {ask.short_summary()}")
        console.print()

    if unmatched:
        console.print(
            f"[dim]({len(unmatched)} holding(s) skipped — no issuer info. "
            f"Run with --min-holding-usd 0 to see them.)[/]"
        )

    # Persist as JSON for downstream tooling
    out_path = store.case_dir(case_id) / "freeze_asks.json"
    import json
    out_path.write_text(
        json.dumps({
            "case_id": case_id,
            "total_asks": len(matched),
            "by_issuer": {
                issuer: [
                    {
                        "address": a.candidate_address,
                        "chain": a.chain.value,
                        "symbol": a.holding_symbol,
                        "amount": str(a.holding_decimal_amount),
                        "usd_value": str(a.holding_usd_value) if a.holding_usd_value else None,
                        "primary_contact": a.issuer.primary_contact,
                        "freeze_capability": a.issuer.freeze_capability,
                        "explorer_url": a.explorer_url,
                    }
                    for a in asks
                ]
                for issuer, asks in grouped.items()
            },
        }, indent=2),
        encoding="utf-8",
    )
    console.print(f"[bold]Wrote[/] {out_path}")


def main() -> None:  # pragma: no cover
    app()


@app.command("brief")
def brief_cmd(
    primary_case: str = typer.Option(..., "--case", help="Primary case ID (the victim's case)."),
    linked_cases: str = typer.Option(
        "", "--linked",
        help="Comma-separated list of follow-up case IDs (depth-N forwarding hops).",
    ),
    investigator_name: str = typer.Option(..., "--investigator-name"),
    investigator_org: str = typer.Option("Recupero", "--investigator-org"),
    investigator_email: str = typer.Option(..., "--investigator-email"),
    investigator_phone: str | None = typer.Option(None, "--investigator-phone"),
    issuer_name: str | None = typer.Option(
        None, "--issuer-name",
        help="Override default issuer name (default: Midas Software GmbH).",
    ),
    issuer_short: str | None = typer.Option(
        None, "--issuer-short",
        help="Short form of issuer name used in filenames and prose (default: Midas).",
    ),
    issuer_email: str | None = typer.Option(
        None, "--issuer-email",
        help="Issuer's contact email (default: team@midas.app).",
    ),
    issuer_jurisdiction: str | None = typer.Option(
        None, "--issuer-jurisdiction",
        help="Issuer's regulatory jurisdiction.",
    ),
    asset_type: str = typer.Option(
        "ERC-20 yield-bearing wrapper token", "--asset-type",
    ),
    asset_usd_current: str | None = typer.Option(
        None, "--asset-usd-current",
        help="Current USD value of the position (manual input from current Etherscan/CoinGecko).",
    ),
    outbound_count: int = typer.Option(
        0, "--outbound-count",
        help="Number of outbound transfers of the stolen asset observed from the current holder. 0 means funds still parked.",
    ),
) -> None:
    """Generate issuer freeze request + LE handoff briefs from one or more cases.

    Defaults are tuned for Midas-issued wrappers (e.g. msyrupUSDp). Override via
    --issuer-* flags for other issuers.
    """
    cfg, _env = load_config()
    setup_logging(cfg.logging.level)
    store = CaseStore(cfg)

    # Load primary case + victim PII
    try:
        primary = store.read_case(primary_case)
    except FileNotFoundError:
        console.print(f"[bold red]Primary case not found:[/] {primary_case}")
        raise typer.Exit(code=2) from None
    primary_dir = store.case_dir(primary_case)
    try:
        victim = load_victim(primary_dir)
    except FileNotFoundError as e:
        console.print(f"[bold red]{e}[/]")
        console.print("Hint: write data/cases/<case>/victim.json or use `recupero victim set`.")
        raise typer.Exit(code=2) from None

    # Load linked cases
    linked = []
    if linked_cases.strip():
        for cid in [c.strip() for c in linked_cases.split(",") if c.strip()]:
            try:
                linked.append(store.read_case(cid))
            except FileNotFoundError:
                console.print(f"[yellow]Linked case not found, skipping:[/] {cid}")

    # Build issuer: start from Midas defaults, override fields if provided
    issuer = IssuerInfo(
        name=issuer_name or MIDAS_ISSUER.name,
        short_name=issuer_short or MIDAS_ISSUER.short_name,
        contact_email=issuer_email or MIDAS_ISSUER.contact_email,
        jurisdiction=issuer_jurisdiction or MIDAS_ISSUER.jurisdiction,
        regulatory_framework=MIDAS_ISSUER.regulatory_framework,
        secondary_party=MIDAS_ISSUER.secondary_party,
        secondary_role=MIDAS_ISSUER.secondary_role,
        asset_description=MIDAS_ISSUER.asset_description,
        kyc_required=MIDAS_ISSUER.kyc_required,
        kyc_minimum=MIDAS_ISSUER.kyc_minimum,
    )

    bundle = generate_briefs(
        primary_case=primary,
        linked_cases=linked,
        victim=victim,
        investigator=InvestigatorInfo(
            name=investigator_name,
            organization=investigator_org,
            email=investigator_email,
            phone=investigator_phone,
        ),
        case_dir=primary_dir,
        issuer=issuer,
        asset_type=asset_type,
        asset_usd_value_current=asset_usd_current,
        outbound_count_of_stolen_asset=outbound_count,
    )

    console.print()
    console.print(f"[bold green]Brief generated:[/] {bundle.brief_id}")
    console.print(f"  Issuer freeze request:    [cyan]{bundle.maple_path}[/]")
    console.print(f"  LE handoff package:       [cyan]{bundle.le_path}[/]")
    console.print(f"  Manifest:                 [dim]{bundle.manifest_path}[/]")
    console.print()
    console.print("Next: open both HTML files in a browser, review, then print to PDF for sending.")


@app.command("victim")
def victim_cmd(
    case_id: str = typer.Option(..., "--case"),
    name: str = typer.Option(..., help="Victim full name."),
    wallet: str = typer.Option(..., help="Victim wallet address."),
    citizenship: str | None = typer.Option(None),
    address: str | None = typer.Option(None, help="Postal address."),
    email: str | None = typer.Option(None),
    phone: str | None = typer.Option(None),
    incident_summary: str | None = typer.Option(None, "--summary"),
    legal_counsel: str | None = typer.Option(None),
    legal_counsel_email: str | None = typer.Option(None),
) -> None:
    """Write or update the victim.json for a case."""
    cfg, _ = load_config()
    store = CaseStore(cfg)
    case_dir = store.case_dir(case_id)
    victim = VictimInfo(
        name=name,
        wallet_address=wallet,
        citizenship=citizenship,
        address=address,
        email=email,
        phone=phone,
        incident_summary=incident_summary,
        legal_counsel=legal_counsel,
        legal_counsel_email=legal_counsel_email,
    )
    path = write_victim(case_dir, victim)
    console.print(f"[green]Wrote[/] {path}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
