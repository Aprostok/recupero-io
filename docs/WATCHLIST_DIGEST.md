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

These are env-overridable in `_run_watch_tick_once`:

| Env var (suggested) | Default | What it controls |
|---|---|---|
| (none) — code default | `100 USD` | `delta_usd_threshold` |
| (none) — code default | `12h` | `min_interval_sec` cooldown |
| (none) — code default | `4` | `parallelism` (Etherscan-bound) |

The CLI also supports `--watch-tick-limit N` to cap the pass size
(useful for first-run validation; the budget per wallet is ~3
Etherscan calls + 0 CoinGecko calls if cached).

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

## Inspecting the output

Per-tick digest files land in the bucket at:

```
watchlist-digest/2026-05-14/DIGEST-20260514T030042-a1b2c3.html
watchlist-digest/2026-05-14/DIGEST-20260514T030042-a1b2c3.pdf
```

Open the PDF directly from the Supabase dashboard, or via the admin
UI's "Digest Archive" view (Jacob's UI work). Each entry in the PDF
links its address to the appropriate chain explorer.

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
