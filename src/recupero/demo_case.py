"""Labeled DEMO/SAMPLE case seeding for the operator console.

So a freshly-deployed ``recupero-api`` (whose local case store is empty) shows a
fully-populated, clickable case in the Case Index immediately — without anyone
running a real investigation. Everything here is an OBVIOUS, clearly-banner'd
SAMPLE: placeholder addresses, no real victim, ``"_demo": true`` markers. It is
NEVER presented as a real forensic result.

Safety / behavior:
  * Seeds ONLY into an EMPTY case store (never overwrites or sits beside real
    cases), and only from ``recupero-api``'s ``main()`` startup (NOT a FastAPI
    startup event — that would pollute tests). The seeder fn itself is pure +
    unit-tested.
  * Gated by ``RECUPERO_SEED_DEMO_CASE``: unset/empty -> seed when the store is
    empty (so prod "just shows something"); ``=0/false/no/off`` -> never seed.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DEMO_CASE_ID = "DEMO-SAMPLE-0001"

# Obvious placeholders — valid-shaped but unmistakably fake, and labeled.
_VICTIM = "Jane Demo (SAMPLE victim — not real)"
_SEED = "0x1111111111111111111111111111111111111111"
_PERP = "0x2222222222222222222222222222222222222222"
_CEX_DEP = "0x3333333333333333333333333333333333333333"

_BANNER = (
    '<div style="background:#7c2d12;color:#fff;padding:.7rem 1rem;border-radius:8px;'
    'font-family:system-ui,sans-serif;margin:0 0 1rem;font-weight:600">'
    '⚠ SAMPLE / DEMONSTRATION — this is a synthetic demo case with placeholder '
    'addresses. Not a real victim, not a real forensic result.</div>'
)


def _doc(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>DEMO — {title}</title>"
        "<style>body{font-family:Georgia,'Times New Roman',serif;max-width:50rem;"
        "margin:1.5rem auto;padding:0 1.25rem;color:#1a1a1a;line-height:1.5}"
        "h1{font-size:1.3rem}h2{font-size:1rem;margin-top:1.4rem}"
        "code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em}"
        "table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.6rem 0}"
        "td,th{border:1px solid #ddd;padding:.35rem .5rem;text-align:left}</style>"
        f"</head><body>{_BANNER}<h1>{title}</h1>{body}"
        "<hr><p style=\"color:#888;font-size:.8rem\">Recupero — SAMPLE deliverable. "
        "Generated for UI demonstration only.</p></body></html>"
    )


def _files() -> dict[str, str]:
    """case-relative path -> text content for the demo case."""
    freeze_brief = {
        "_demo": True,
        "CASE_ID": DEMO_CASE_ID,
        "VICTIM_NAME": _VICTIM,
        "VICTIM_JURISDICTION": "US",
        "TOTAL_LOSS_USD": "250000.00",
        "SEED_ADDRESS": _SEED,
        "FREEZABLE": [
            {"issuer": "Circle (USDC)", "address": _PERP, "chain": "ethereum",
             "amount_usd": "180000.00", "freeze_capability": "yes"},
        ],
        "DESTINATIONS": [
            {"address": _CEX_DEP, "chain": "ethereum", "label": "Binance (deposit)",
             "amount_usd": "70000.00", "kind": "exchange_deposit"},
        ],
        "EXCHANGES": ["Binance"],
    }
    ai_triage = {
        "_demo": True,
        "case_summary_plain": (
            "SAMPLE: ~$250k in USDC was moved from the victim wallet through one "
            "hop to a Circle-issuable address (freezable) and a Binance deposit "
            "address (subpoena/freeze target). Demonstration data only."
        ),
        "recommended_next_steps": [
            "DEMO step — file a freeze request with Circle for the USDC at the perp address.",
            "DEMO step — subpoena Binance for KYC on the deposit address.",
            "DEMO step — add both addresses to the monitoring watchlist.",
        ],
        "_DISCLAIMER": "SAMPLE demo output. Not proof, not legal advice.",
    }
    transfers = (
        "tx_hash,from,to,asset,amount,usd,chain\n"
        f"0xdemo0001,{_SEED},{_PERP},USDC,180000,180000.00,ethereum\n"
        f"0xdemo0002,{_SEED},{_CEX_DEP},USDC,70000,70000.00,ethereum\n"
    )
    le_body = (
        f"<h2>Subject</h2><p>Victim: {_VICTIM}</p>"
        f"<p>Seed address: <code>{_SEED}</code></p>"
        "<h2>Freezable holdings</h2><table><tr><th>Issuer</th><th>Address</th>"
        "<th>USD</th></tr>"
        f"<tr><td>Circle (USDC)</td><td><code>{_PERP}</code></td><td>$180,000</td></tr></table>"
        "<h2>Exchange deposit (subpoena/freeze target)</h2>"
        f"<p>Binance deposit <code>{_CEX_DEP}</code> — $70,000 (DEMO)</p>"
    )
    freeze_body = (
        "<h2>Freeze request (SAMPLE)</h2><p>To: Circle compliance.</p>"
        f"<p>Please freeze USDC held at <code>{_PERP}</code> traced from the "
        "documented theft of $250,000 (demo).</p>"
    )
    victim_body = (
        "<h2>Victim summary (SAMPLE)</h2>"
        "<p>This is a demonstration of the plain-English summary a victim receives. "
        "~$250,000 in USDC was traced one hop to a freezable issuer address and a "
        "Binance deposit. Demo data only.</p>"
    )
    sar_body = (
        "<h2>SAR/STR draft (SAMPLE — US FinCEN)</h2>"
        "<p>Suspicious activity: misappropriation of ~$250,000 in digital assets "
        "(demonstration). Drafts only — Recupero is not a filer.</p>"
    )
    trace_body = (
        "<h2>Trace report (SAMPLE)</h2><table><tr><th>tx</th><th>from</th>"
        "<th>to</th><th>USD</th></tr>"
        f"<tr><td><code>0xdemo0001</code></td><td><code>{_SEED[:10]}…</code></td>"
        f"<td><code>{_PERP[:10]}…</code></td><td>$180,000</td></tr>"
        f"<tr><td><code>0xdemo0002</code></td><td><code>{_SEED[:10]}…</code></td>"
        f"<td><code>{_CEX_DEP[:10]}…</code></td><td>$70,000</td></tr></table>"
    )
    exhibit_body = (
        "<h2>Exhibit pack index (SAMPLE)</h2><p>Exhibit A — trace_report_demo.html<br>"
        "Exhibit B — freeze_brief.json</p><p>SHA-256 hashes + Daubert appendix + "
        "28 U.S.C. §1746 declaration appear here for a real case (demo placeholder).</p>"
    )
    graph_body = (
        "<h2>Investigation graph (SAMPLE)</h2>"
        f"<p>victim <code>{_SEED[:10]}…</code> → perp <code>{_PERP[:10]}…</code> "
        f"→ Binance <code>{_CEX_DEP[:10]}…</code></p>"
        "<p>The real graph console renders an interactive D3 node-link diagram.</p>"
    )
    return {
        "case.json": json.dumps(
            {"_demo": True, "case_id": DEMO_CASE_ID, "victim": _VICTIM,
             "software_version": "demo", "note": "SAMPLE demo case"},
            indent=2),
        "freeze_brief.json": json.dumps(freeze_brief, indent=2),
        "ai_triage.json": json.dumps(ai_triage, indent=2),
        "transfers.csv": transfers,
        "graph_ui.html": _doc("Investigation Graph", graph_body),
        "trace_report_demo.html": _doc("Trace Report", trace_body),
        "briefs/le_handoff_demo.html": _doc("Law-Enforcement Handoff", le_body),
        "briefs/freeze_request_circle_demo.html": _doc("Freeze Request — Circle", freeze_body),
        "briefs/victim_summary_demo.html": _doc("Victim Summary", victim_body),
        "regulatory_filing/us_fincen_sar_demo.html": _doc("US FinCEN SAR Draft", sar_body),
        "exhibit_pack/exhibit_pack.html": _doc("Exhibit Pack", exhibit_body),
    }


def seed_demo_case(cases_root: Path) -> bool:
    """Write the demo case under ``cases_root/DEMO-SAMPLE-0001`` if not already
    present. Returns True if it wrote the case, False if it already existed.
    Pure w.r.t. env/config — caller decides whether to invoke."""
    dest = cases_root / DEMO_CASE_ID
    if (dest / "case.json").is_file():
        return False
    for rel, content in _files().items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    log.info("seeded DEMO/SAMPLE case at %s", dest)
    return True


def _seeding_enabled() -> bool:
    raw = (os.environ.get("RECUPERO_SEED_DEMO_CASE", "") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def maybe_seed_demo_case() -> bool:
    """Startup hook (called from the recupero-api entrypoint): seed the demo
    case when the store is EMPTY and seeding isn't disabled. Best-effort —
    never raises into bootstrap."""
    try:
        if not _seeding_enabled():
            return False
        from recupero.config import load_config
        cfg, _ = load_config()
        cases_root = Path(cfg.storage.data_dir) / "cases"
        cases_root.mkdir(parents=True, exist_ok=True)
        # "Empty" = no real case dirs (a case dir has a case.json). The demo's
        # own dir doesn't count for re-seeding (seed_demo_case is idempotent).
        for child in cases_root.iterdir():
            if child.is_dir() and child.name != DEMO_CASE_ID and (child / "case.json").is_file():
                return False  # real cases present — do not seed
        return seed_demo_case(cases_root)
    except Exception as exc:  # noqa: BLE001
        log.warning("demo-case seed skipped (non-fatal): %s", exc)
        return False


__all__ = ("DEMO_CASE_ID", "seed_demo_case", "maybe_seed_demo_case")
