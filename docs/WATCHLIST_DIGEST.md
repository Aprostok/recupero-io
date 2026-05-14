# Watchlist Digest — Daily "Mini Freeze" Operations Runbook

The worker emits a **Daily Movement Digest** for every active wallet
in `public.watchlist`. It snapshots balances + tx counts, detects
material changes against the previous snapshot, and renders a
2–4 page letter (HTML + PDF) summarizing what moved.

## How it runs

A single CLI command does the whole pass:

```bash
recupero-worker --watch-tick
```

That command:

1. Pulls every active watchlist row where `last_snapshot_at` is older
   than the cooldown window (default 12 hours).
2. For each row, fetches:
   - native gas-token balance (`eth_getBalance`)
   - lifetime transaction count (`eth_getTransactionCount` via proxy)
   - one ERC-20 balance for the row's `asset_contract` if set
3. Prices the holdings via the persistent CoinGecko cache (zero
   network when yesterday's coins are already cached).
4. Inserts a row into `public.watchlist_snapshots` and updates the
   denormalized `last_*` fields on `public.watchlist`.
5. Computes `delta_usd` vs the most recent prior snapshot. Flags
   the row as a **material change** when:
   - `|delta_usd| ≥ $100` (default; configurable via env), OR
   - tx count strictly increased (any new outbound observed)
6. Renders the digest HTML using `mini_freeze_digest.html.j2`.
7. Renders matching PDF via WeasyPrint (apt-installed in the Docker
   image — same dependency that produces the full freeze letters).
8. Uploads HTML + PDF to the Supabase bucket at
   `watchlist-digest/<YYYY-MM-DD>/<digest_id>.{html,pdf}`.

## Materiality, cooldown, and limits

All three tuning knobs are env-overridable — set them on the Railway
cron service to adjust behavior without a code push.

| Env var | Default | What it controls |
|---|---|---|
| `RECUPERO_WATCH_DELTA_USD_THRESHOLD` | `100` | USD delta below which a balance change is ignored. Set to `0` to flag any non-zero balance change (noisy). |
| `RECUPERO_WATCH_MIN_INTERVAL_SEC` | `43200` (12h) | Cooldown — same wallet not re-snapshotted within this window. Set to `0` for hourly polling on a high-priority case. |
| `RECUPERO_WATCH_PARALLELISM` | `4` | Concurrent snapshot workers per chain. Etherscan free tier caps at 5 rps so >5 is wasted. |

Bad values (unparseable Decimal / int) log a warning and fall back to
the default — typos don't silently change behavior.

The CLI also supports `--watch-tick-limit N` to cap the pass size
(useful for first-run validation; budget per wallet is ~3 Etherscan
calls + 0 CoinGecko calls if cached).

## Multi-chain coverage

| Chain | Snapshot path | Status |
|---|---|---|
| `ethereum` | Etherscan v2 (`chain_id=1`) | ✅ supported |
| `arbitrum` | Etherscan v2 (`chain_id=42161`) | ✅ supported |
| `base` | Etherscan v2 (`chain_id=8453`) | ✅ supported |
| `polygon` | Etherscan v2 (`chain_id=137`) | ✅ supported |
| `bsc` | Etherscan v2 (`chain_id=56`) | ✅ supported |
| `solana` | Helius RPC (`getBalance` + `getSignaturesForAddress`) | ✅ supported (needs `HELIUS_API_KEY`) |
| `hyperliquid` | — | ⛔ not implemented (existing scraper has no balance endpoint) |

Solana SPL token balances are deferred — currently only the native
SOL balance contributes to the snapshot's `usd_value`. Adding SPL
support means routing through `getTokenAccountsByOwner` per mint
when the watchlist row's `asset_contract` is set (matches the
EVM-side `asset_contract` semantics).

Hyperliquid rows on the watchlist are skipped with a per-row error
("hyperliquid snapshot not implemented") logged in the report. The
rows remain `active` for the next tick once balance fetching lands.

## Cost shape

Per tick of N watched wallets:

- **Etherscan v2 free tier (5 rps):** ~3 calls per wallet. 1227
  active wallets → ~3,700 calls → ~14 min wallclock. Well within the
  100k/day free-tier budget.
- **CoinGecko:** cache-only (persistent in Postgres, shared across
  ticks). New tokens trigger one historical-price lookup at 0.5 rps.
- **Anthropic:** zero — no LLM use in this stage.
- **Supabase Storage:** ~30KB HTML + ~50KB PDF per day = 80KB/day,
  trivial.

## Railway cron setup

Railway supports cron via a **separate service** in the same
project. Recommended setup:

1. In the Railway dashboard, open the `recupero-io` project.
2. Click **+ New** → **GitHub Repo** → pick the same repo + branch
   as the main worker service.
3. Give the new service a name like `recupero-watch-tick`.
4. Under **Settings** → **Deploy**:
   - **Builder**: Dockerfile (uses the same image as the worker)
   - **Start command**: `recupero-worker --watch-tick`
   - **Cron Schedule**: `0 3 * * *` (03:00 UTC daily — 23:00 EST)
   - **Restart Policy**: never (cron jobs shouldn't restart on exit)
5. Under **Variables**, attach the same env reference as the main
   worker service (`SUPABASE_DB_URL`, `SUPABASE_URL`,
   `SUPABASE_SERVICE_ROLE_KEY`, `ETHERSCAN_API_KEY`, optionally
   `COINGECKO_API_KEY`).

A 03:00 UTC tick takes ~14 min on the current watchlist (1,227 rows)
— well under the next tick's 24-hour window, and Railway only bills
for the seconds the cron container is actually running (no idle
charge between ticks).

## Email delivery (optional)

When configured, the cron sends the digest by email after the bucket
upload. Plain-text body + HTML alternative (the rendered digest
itself, inlined for HTML mail clients) + PDF attachment.

Env vars (all required for sending):

| Env var | Required? | Notes |
|---|---|---|
| `RECUPERO_DIGEST_RECIPIENTS` | yes (to enable) | Comma-separated email list. Absent = no email sent. |
| `RECUPERO_SMTP_HOST` | yes | e.g. `smtp.sendgrid.net`, `smtp.postmarkapp.com`. |
| `RECUPERO_SMTP_USER` | yes | SMTP username. For SendGrid use `apikey`. |
| `RECUPERO_SMTP_PASSWORD` | yes | SMTP password or API key. |
| `RECUPERO_SMTP_PORT` | optional | Default `587` (STARTTLS). |
| `RECUPERO_DIGEST_FROM` | optional | `"Name <addr@host>"`. Default `"Recupero Digest <digest@recupero.io>"`. |
| `RECUPERO_DIGEST_ALWAYS_SEND` | optional | `1` to send even on all-clear ticks. Default off (no inbox noise on quiet days). |

Subject line lead with the actionable signal:

- `[Recupero] 2 FREEZABLE wallets moved · 2026-05-14`
- `[Recupero] 3 watched wallets moved · 2026-05-14`
- `[Recupero] Daily Digest 2026-05-14 — all clear` (only when `ALWAYS_SEND=1`)

Failures are best-effort: a delivery error logs a WARNING but
doesn't fail the cron. The digest is always uploaded to the bucket
first, so a failed email can be retrieved manually.

## Inspecting the output

Per-tick digest files land in the bucket at:

```
watchlist-digest/2026-05-14/DIGEST-20260514T030042-a1b2c3.html
watchlist-digest/2026-05-14/DIGEST-20260514T030042-a1b2c3.pdf
watchlist-digest/2026-05-14/DIGEST-20260514T030042-a1b2c3.summary.json
```

The `.summary.json` is a compact (~500B – 5KB) listing the admin UI's
**Digest Archive** view can consume without downloading the full
HTML/PDF. Schema fields (stable — coordinate before renaming):

```json
{
  "digest_id":            "DIGEST-...",
  "generated_at":         "2026-05-14T03:00:42+00:00",
  "tick_started_at":      "2026-05-14T03:00:00+00:00",
  "tick_finished_at":     "2026-05-14T03:14:21+00:00",
  "tick_duration_seconds": 861.3,
  "total_watched":        1227,
  "snapshotted":          245,
  "skipped_cooldown":     982,
  "skipped_unsupported_chain": 0,
  "material_count":       3,
  "freezeable_count":     1,
  "error_count":          0,
  "total_outflow_usd":    "12300.45",
  "html_filename":        "DIGEST-...html",
  "pdf_filename":         "DIGEST-...pdf",
  "material_changes": [
    {
      "address":         "0xabc...",
      "chain":           "ethereum",
      "role":            "perpetrator",
      "label_name":      null,
      "is_freezeable":   true,
      "issuer":          "Circle",
      "asset_symbol":    "USDC",
      "delta_usd":       "-8400.20",
      "tx_count_delta":  3,
      "reason":          "balance -$8,400.20 USD · 3 new outbound tx(s)"
    }
  ]
}
```

Admin UI flow: list `watchlist-digest/<date>/*.summary.json` from the
bucket, render an archive table, link each row's `html_filename` /
`pdf_filename` to a signed-URL for in-browser opening. Each entry in
the PDF links its address to the appropriate chain explorer.

The raw `watchlist_snapshots` history is retained indefinitely for
audit — query examples:

```sql
-- Wallets that moved most USD in the past week
SELECT w.address, w.role, w.issuer,
       MIN(s.usd_value) AS low_usd, MAX(s.usd_value) AS high_usd
  FROM public.watchlist w
  JOIN public.watchlist_snapshots s ON s.watchlist_id = w.id
 WHERE s.taken_at > NOW() - INTERVAL '7 days'
   AND w.status = 'active'
 GROUP BY w.id, w.address, w.role, w.issuer
 ORDER BY (MAX(s.usd_value) - MIN(s.usd_value)) DESC NULLS LAST
 LIMIT 25;

-- All snapshots for one address in chronological order
SELECT s.taken_at, s.native_balance, s.tx_count, s.usd_value, s.delta_usd
  FROM public.watchlist_snapshots s
  JOIN public.watchlist w ON w.id = s.watchlist_id
 WHERE w.address = '0xabc...'
 ORDER BY s.taken_at ASC;
```

## Failure modes

The cron is intentionally fault-tolerant — partial failures emit a
WARNING but the cron exits 0 so Railway doesn't escalate. Per-row
errors are captured in the digest's "Errors" cover stat.

- **One wallet fails to fetch**: error recorded in
  `WatchTickReport.errors`; that row is NOT snapshotted, retried
  next tick. The other 1,226 wallets still get their snapshot.
- **CoinGecko price miss**: USD value is `NULL` for that snapshot
  but the snapshot row still writes. Materiality detection skips
  rows with null USD on either side of the diff.
- **WeasyPrint not importable**: digest ships as HTML only; PDF
  generation logs a warning. (Should never happen on Railway since
  the Docker image has all the apt deps.)
- **Bucket upload fails**: digest is written to local tempdir and
  logged. The cron container exits after the temp dir is reaped, so
  manual recovery means re-running the tick (snapshots are
  idempotent under the cooldown guard).

## Manual operations

Run a one-off tick interactively from a dev box:

```bash
# Process at most 10 wallets — fast smoke
python -m recupero.worker.main --watch-tick --watch-tick-limit 10

# Full pass (~14 min on current watchlist)
python -m recupero.worker.main --watch-tick

# Verify env / DB / bucket connectivity first
python -m recupero.worker.main --health-check
```

Pause monitoring on a specific wallet (already on the watchlist):

```bash
python scripts/recupero_watch.py set --address 0xabc... --chain ethereum \
    --status cleared --reason "exchange determined was internal wallet"
```

Manual addition of a tipoff wallet:

```bash
python scripts/recupero_watch.py add 0xabc... --chain ethereum \
    --reason "tipoff from victim" --issuer Tether --asset USDT
```

The next nightly tick picks up the new entry automatically.
