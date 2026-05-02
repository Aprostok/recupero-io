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
