#!/usr/bin/env python3
"""Seed-list utilities.

Phase 1 ships static seed JSON files in src/recupero/labels/seeds/. This script
is for: (a) inspecting what's loaded, (b) adding a new label entry interactively
into a local override file at data/labels/local_<name>.json.

Usage:
    python scripts/seed_labels.py list
    python scripts/seed_labels.py add --address 0x... --name "Foo" --category exchange_deposit --exchange Foo
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import typer  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from recupero.config import load_config  # noqa: E402
from recupero.labels.store import LabelStore  # noqa: E402
from recupero.models import LabelCategory  # noqa: E402

app = typer.Typer(add_completion=False, help="Inspect and manage Recupero labels.")
console = Console()


@app.command("list")
def list_cmd() -> None:
    cfg, _ = load_config()
    store = LabelStore.load(cfg)
    table = Table(title=f"Loaded labels ({len(store._by_addr_lower)})")
    table.add_column("Address", style="dim")
    table.add_column("Name")
    table.add_column("Category", style="cyan")
    table.add_column("Exchange")
    table.add_column("Source")
    for label in sorted(store._by_addr_lower.values(), key=lambda l: (l.category.value, l.name)):
        table.add_row(
            label.address,
            label.name,
            label.category.value,
            label.exchange or "",
            label.source,
        )
    console.print(table)


@app.command("add")
def add_cmd(
    address: str = typer.Option(..., help="Address to label."),
    name: str = typer.Option(..., help="Human-readable name."),
    category: str = typer.Option(..., help="One of: " + ", ".join(c.value for c in LabelCategory)),
    exchange: str | None = typer.Option(None, help="Exchange name if applicable."),
    source: str = typer.Option("user:manual", help="Provenance string."),
    confidence: str = typer.Option("medium", help="high|medium|low"),
    notes: str | None = typer.Option(None, help="Free-text note."),
    file: str = typer.Option("manual", help="Goes into data/labels/local_<file>.json"),
) -> None:
    try:
        cat = LabelCategory(category)
    except ValueError:
        console.print(f"[bold red]Bad category. Choose from:[/] {', '.join(c.value for c in LabelCategory)}")
        raise typer.Exit(2)

    cfg, _ = load_config()
    out_dir = Path(cfg.storage.data_dir) / "labels"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"local_{file}.json"
    existing = json.loads(out_path.read_text()) if out_path.exists() else []
    existing.append({
        "address": address,
        "name": name,
        "category": cat.value,
        "exchange": exchange,
        "source": source,
        "confidence": confidence,
        "notes": notes,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    out_path.write_text(json.dumps(existing, indent=2))
    console.print(f"[green]Added label, total in {out_path}: {len(existing)}[/]")


if __name__ == "__main__":
    app()
