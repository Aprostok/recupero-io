# Deploying the recupero worker to Railway

The worker (`src/recupero/worker/`) is meant to run as a long-lived process
on Railway. It polls `public.investigations` for queued work, runs the
trace → freeze → editorial → emit pipeline, mirrors artifacts to the
Supabase `investigation-files` bucket, and updates the row's status as it
goes.

The worker exposes two HTTP endpoints purely for Railway's healthcheck:

- `GET /healthz` — instant liveness probe. Returns 200 if the process is up.
  This is what Railway polls (`healthcheckPath: /healthz` in `railway.json`).
- `GET /health` — full readiness probe. Runs env-var, DB connectivity,
  bucket-reachability, and package-integrity checks. Slower (~2-5s on
  cold start due to DB + bucket round-trips). Used by ops manually
  (`recupero-worker --health-check` runs the same checks via CLI).

If the worker exits, Railway restarts it per the on-failure policy in
[railway.json](../railway.json) (10 retries before giving up).

## Prerequisites

- A Railway account (https://railway.app)
- Push access to `Aprostok/recupero-io` (so Railway can pull the code)
- The Supabase project's URL, service-role key, and database password
- `ANTHROPIC_API_KEY` for the AI editorial stage
- `ETHERSCAN_API_KEY` for the trace stage

## One-time setup

### 1. Create a new Railway service

- Railway dashboard → **New Project** → **Deploy from GitHub repo**
- Select `Aprostok/recupero-io`
- Railway auto-detects Python via Nixpacks (`pyproject.toml`); the
  `railway.json` at repo root tells it to run `recupero-worker` as the
  start command.

### 2. Configure environment variables

In the service's **Variables** tab, add the following. Mirror the names
in [.env.example](../.env.example).

| Variable                          | Notes |
|-----------------------------------|-------|
| `SUPABASE_URL`                    | `https://<project_ref>.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY`       | From Supabase → Settings → API → service_role |
| `SUPABASE_DB_URL`                 | Direct connection string. URL-encode special chars in the password (`%` → `%25`, `#` → `%23`, `^` → `%5E`). Format: `postgresql://postgres:<encoded_pw>@db.<ref>.supabase.co:5432/postgres?sslmode=require` |
| `ANTHROPIC_API_KEY`               | https://console.anthropic.com/settings/keys |
| `ETHERSCAN_API_KEY`               | https://etherscan.io/myapikey |
| `COINGECKO_API_KEY`               | https://www.coingecko.com/en/api (demo tier OK) |
| `RECUPERO_LOG_LEVEL`              | `INFO` (default) or `DEBUG` |

Optional tunables (defaults are sensible):

| Variable                          | Default | Meaning |
|-----------------------------------|---------|---------|
| `RECUPERO_HEARTBEAT_INTERVAL_SEC` | 30      | How often the worker pings `last_heartbeat_at` while a row is in flight. |
| `RECUPERO_STALE_AFTER_SEC`        | 300     | A row whose heartbeat is older than this is eligible for re-claim by another worker. |
| `RECUPERO_POLL_IDLE_SEC`          | 2       | Initial backoff between empty polls. Doubles up to `RECUPERO_POLL_MAX_SEC`. |
| `RECUPERO_POLL_MAX_SEC`           | 30      | Cap on idle backoff. |

### 3. Deploy

Railway redeploys automatically on every push to `main`. First deploy
runs `pip install .` from `pyproject.toml`, then starts `recupero-worker`.

Watch the **Deployments** tab → the build log should end with the
`recupero-worker starting id=...` log line.

### 4. Verify

In a separate terminal locally:

```bash
python test_worker.py
```

This inserts a synthetic investigations row, then watches the row's
status transitions. If Railway's worker is running, it'll claim the row
within a few seconds. The test cleans up after itself.

To prove it's the *Railway* worker doing the work (not your local one),
make sure no local worker is running and watch Railway's log stream
for the `claimed inv id=<uuid>` line.

## Operations

### Logs

Railway's **Deployments → View Logs** shows stdout/stderr. The worker
logs every claim, transition, and failure with the investigation ID.
Filter by `id=<uuid>` to follow one investigation end-to-end.

### Stopping the worker

- **Pause** (keeps env vars; instant restart): Service → ⋯ → Pause
- **Delete** (full teardown): Service → Settings → Delete

A paused or deleted worker means queued investigations stay queued —
no harm, no rollback. The next worker that comes up claims them.

### Multiple workers / horizontal scaling

The claim SQL uses `FOR UPDATE SKIP LOCKED`, so multiple Railway
instances can run concurrently without fighting. Each instance claims
the next available row; the others skip past locked rows.

To scale up, either:
- Increase the service's instance count in Railway (Settings → Replicas), OR
- Deploy the same repo as a second Railway service (e.g. for staging vs prod)

The `worker_id` column captures `<hostname>-<pid>` so you can correlate
Railway log streams to claimed rows.

### Troubleshooting

| Symptom                                                        | Likely cause |
|----------------------------------------------------------------|--------------|
| Worker logs `missing required env vars`                        | One of `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_URL` isn't set in Railway Variables |
| `FATAL: Tenant or user not found` on claim                     | Wrong DB connection string format. Use direct connection (`db.<ref>.supabase.co:5432`), not the pooler. |
| `connection refused` from Postgres                             | Supabase project paused. Free-tier projects pause after a week of inactivity — log into the dashboard to resume. |
| Worker starts then crashes with `chain not in CHECK constraint`| Investigation row has a chain value the worker doesn't support. Valid values are listed in `worker/db.py` and Jacob's [investigation-integration.md](https://github.com/thingssneakers/recupero/blob/main/docs/investigation-integration.md) §investigations table |
| Worker claims a row, runs trace, then fails on `editorial_drafting` | Missing or invalid `ANTHROPIC_API_KEY` |
| Worker fails on `tracing` with rate-limit error                | Etherscan free tier exhausted; either upgrade plan or wait until next 24h reset |

## Operational monitoring

The worker is meant to run unattended for weeks at a time. Three
out-of-band checks make sure nothing rots silently:

### Uptime monitoring (UptimeRobot on `/healthz`)

Railway will restart the worker on crash, but it won't tell you if the
service has been crash-looping for hours, or if Railway itself has paged
your project. An external HTTP probe catches that.

1. Sign up at [uptimerobot.com](https://uptimerobot.com) (the free tier
   covers 50 monitors at 5-minute resolution — fine for one service).
2. **Add New Monitor** → Type: `HTTP(s)`.
3. **URL**: paste the public URL of the Railway service +`/healthz`,
   e.g. `https://recupero-worker-production.up.railway.app/healthz`.
   Find the URL in the Railway service → **Settings → Networking →
   Public Networking**. Generate a domain if none exists.
4. **Monitoring Interval**: 5 minutes.
5. **Alert Contacts**: at minimum the on-call email; ideally a Slack
   webhook so the alert lands in a channel everyone can see.
6. Save. UptimeRobot starts probing immediately; the first datapoint
   shows up within a minute.

`/healthz` returns 200 the moment the process is up — no DB or bucket
round-trips — so it can't false-positive on transient Supabase
flakiness. If you ever need a deeper probe, point a second monitor at
`/health` with a longer timeout (it does the full readiness check).

### Stale-review alert (`scripts/check_stale_reviews.py`)

The worker pauses every investigation at `awaiting_review` so a human
can sign off on the AI editorial. There is intentionally no automated
escalation in the pipeline — the brief might genuinely need a rewrite —
so a row can sit in `awaiting_review` forever if nobody clicks. Run
this query daily; exit code 1 means there's at least one stale row.

```bash
python scripts/check_stale_reviews.py                    # default 24h
python scripts/check_stale_reviews.py --threshold-hours 48
python scripts/check_stale_reviews.py --json | jq .      # for tooling
```

Schedule via cron / GitHub Actions. Minimal GitHub Actions example
(put `SUPABASE_DB_URL` in repo secrets, alert wiring up to you):

```yaml
# .github/workflows/stale-review-alert.yml
name: stale-review-alert
on:
  schedule:
    - cron: '0 14 * * *'   # 14:00 UTC = 09:00 ET daily
  workflow_dispatch:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install psycopg[binary] python-dotenv
      - env:
          SUPABASE_DB_URL: ${{ secrets.SUPABASE_DB_URL }}
        run: python scripts/check_stale_reviews.py
```

When the action fails, GitHub emails the repo admins. Wire the
`--json` output into a Slack notify step if you want richer alerts.

### Weekly snapshot (`scripts/backup_investigations.py`)

Supabase's own backups cover total-loss disaster, but a self-managed
snapshot also protects against a bad UI deploy or an accidental DELETE
that ages out of the (free-tier) 7-day PITR window. The script dumps
`public.investigations` and `public.cases` to JSON; the bucket files
are deterministic outputs of those rows + the on-chain trace, so
they're not backed up by default.

```bash
python scripts/backup_investigations.py
python scripts/backup_investigations.py --out-dir /mnt/backups/recupero/2026-05-08
python scripts/backup_investigations.py --include-bucket  # full snapshot
```

Each run writes `investigations.json`, `cases.json`, and a
`manifest.json` with row counts + sha256 digests. Schedule weekly via
cron or GitHub Actions; ship the directory to S3 / a NAS / wherever
you keep operational backups. Restore is `psql \copy` per table — the
JSON shape matches the column set 1:1.

## Watchlist (LE-handoff blacklist + nightly balance monitor)

The worker auto-populates `public.watchlist` after every successful
trace. **Every** non-victim wallet on the trace path lands there: the
perpetrator, every hop, current holders, exchange deposits, mixers,
bridges. The `is_freezeable` flag (set true only for current holders
of asset-issuer-freezable positions and known exchange deposits) is
what the nightly monitor filters on.

Schema lives in [migrations/001_watchlist.sql](../migrations/001_watchlist.sql).
Apply with `python scripts/apply_migration.py migrations/001_watchlist.sql`
(idempotent).

### Daily monitoring

A scheduled task (`recupero-watchlist-monitor`, 03:03 ET daily) runs:

```bash
python scripts/monitor_watchlist.py --json-only
```

Filter contract: monitors only `status='active' AND is_freezeable=true`
rows where either `last_balance_usd > 0` or `last_snapshot_at IS NULL`.
Mixers and bridges have `is_freezeable=false` and are skipped; dust
wallets that snapshot at $0 are skipped from the second run onwards.

Exit code 1 means at least one wallet moved (native balance changed or
`tx_count` advanced). The scheduled task surfaces movement back here.

### Manual entries

For ad-hoc additions, lifecycle changes, or LE-driven flagging:

```bash
python scripts/recupero_watch.py add 0xabc... --chain ethereum \
    --reason "tipoff from victim" --issuer Tether --asset USDT
python scripts/recupero_watch.py list --freezeable-only
python scripts/recupero_watch.py set --address 0xabc... --chain ethereum \
    --status frozen --note "Tether confirmed freeze on 2026-05-08"
python scripts/recupero_watch.py clear --address 0xabc... --chain ethereum \
    --reason "exchange determined was their internal wallet"
```

### Law-enforcement export

```bash
python scripts/export_watchlist.py --format csv --out le_handoff.csv
python scripts/export_watchlist.py --format json --freezeable-only
python scripts/export_watchlist.py --case-id <uuid>
```

Default scope is `status='active'` rows; pass `--include-cleared` for a
full audit dump.

### Limitations (v1)

- Solana / Hyperliquid wallets are inserted into the table but the
  monitor skips them with a warning until chain dispatch is extended.
- Per-token balances (USDC / USDT positions) are not snapshotted — the
  monitor only tracks native balance + `tx_count`. A change in
  `tx_count` is a reliable proxy for token movement; per-token USD
  values are deferred pending a richer snapshot schema.

## What the worker writes to the bucket

Each completed investigation lands the following under
`investigation-files/investigations/<investigation_id>/`:

```
case.json                # structured trace data + endpoints
manifest.json            # run metadata
transfers.csv            # flat CSV mirror of all transfers
freeze_asks.json         # candidate freeze targets per issuer + per exchange
brief_editorial.json     # AI-drafted editorial, post-review
freeze_brief.json        # final customer-facing brief JSON
evidence/<tx_hash>.json  # one per traced transfer (EVM chains only)
briefs/
  freeze_request_<issuer>_<brief_id>.html   # one per matched issuer
  le_handoff_<issuer>_<brief_id>.html       # LE handoff per issuer
  manifest_<brief_id>.json                  # output manifest
  flow_<id>.svg                             # standalone fund-flow diagram
```

The HTML briefs embed the same SVG inline so they render self-contained.
The standalone `flow_*.svg` is provided so operators can drop the
diagram into separate decks or PDFs without re-rendering.

## System dependencies in the image

The Dockerfile installs:

- **`graphviz`** + **`fonts-dejavu-core`** (apt) — `dot` binary used to
  render the fund-flow SVGs. ~30 MB image overhead. Without these the
  worker still runs; the deliverables stage emits a placeholder SVG and
  logs a warning.
- **All Python deps** ship as pre-built wheels for cp312-manylinux —
  no compiler needed in the image.

## What this deploy does NOT do

- **JS-side .docx / .pdf rendering** — the worker emits HTML briefs that
  print to PDF cleanly via Chrome / wkhtmltopdf. Native `.docx` export
  is deferred. Productionize when needed by either (a) bundling Node +
  the JS builders into the same image or (b) running a second Railway
  service that watches for `complete` rows.
- **Native cross-chain bridge following** — when the trace hits a
  labeled bridge, it stops on the source chain and records "bridged
  out" as a finding. Following the funds onto the destination chain
  requires bridge decoders (DeBridge, Wormhole, Stargate, Across)
  tracked in `docs/BACKLOG.md` Phase 4.
