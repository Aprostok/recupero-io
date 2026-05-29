# Developer Onboarding

This is the 30-minute path from a fresh clone to running a real trace
end-to-end. If you're following along and any step takes more than its
allotted time, stop and ask — it usually means an env var is missing
or the version pin slipped.

Target audience: a new contributor with senior Python experience but
no prior Recupero context. Total wall-clock: ~30 minutes.

---

## 1. Clone the repo (1 minute)

```bash
git clone https://github.com/recupero-io/recupero-io.git
cd recupero-io
git checkout pdf-deliverables   # active-development branch
```

`main` is the production-deploy branch — Railway auto-deploys on push.
Do not commit directly to `main`. Feature work happens on
`pdf-deliverables` (or a worktree off it).

---

## 2. Python and venv (3 minutes)

The project pins `requires-python = ">=3.11"` in `pyproject.toml`.
Python 3.11 is the canonical target — 3.12 also works, 3.10 is
unsupported.

```bash
# macOS / Linux
python3.11 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1

# Verify
python --version       # Python 3.11.x
which python           # …/.venv/bin/python   (POSIX)
Get-Command python     # …\.venv\Scripts\python.exe   (Windows)
```

---

## 3. Editable install (3 minutes)

```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

The `[dev]` extras pull pytest, pytest-asyncio, pytest-httpx, respx,
ruff, mypy, and the test-time types stubs. The editable install
registers the five console scripts (`recupero`, `recupero-ops`,
`recupero-worker`, `recupero-api`, `recupero-cron`).

Verify:

```bash
recupero --help
recupero-ops --help
```

Both should print the typer command tree.

On Windows you also need Graphviz for the flow-diagram renderer
(`reports/dotgraph.py`). Install from https://graphviz.org/download/
and ensure `dot.exe` is on PATH. On Linux/macOS the Dockerfile
installs Graphviz via apt; for local dev `brew install graphviz` or
`apt install graphviz` is enough.

---

## 4. Env vars (5 minutes)

Copy the template and fill in the required values:

```bash
cp .env.example .env
```

Then edit `.env`. The required-for-any-flow set:

| Var | Source | What breaks without it |
|---|---|---|
| `SUPABASE_DB_URL` | Supabase → Settings → Database → URI. URL-encode special characters in the password. | Worker, portal, dispatcher, anything that touches the queue. |
| `ETHERSCAN_API_KEY` | https://etherscan.io/myapikey (free tier is fine for dev). | All EVM-chain traces. Set to a stub for offline tests (the suite mocks Etherscan). |
| `RECUPERO_TOKEN_PEPPER` | Generate: `python -c "import secrets; print(secrets.token_hex(32))"` | Portal token mint raises RuntimeError. Even local-dev portal flows need this. |
| `RECUPERO_RANDOMIZATION_SECRET` | Generate: `python -c "import secrets; print(secrets.token_hex(32))"` | Per-case randomized fanout thresholds collapse to a fixed value (predictable to an adversary reading the source). v0.32.1 hard-requires this for any worker boot. |
| `COINGECKO_API_KEY` | Optional. https://www.coingecko.com/en/api. Free demo tier works locally. | Historical USD valuations fail; the trace still runs but produces $0 figures. |

The full env-var reference is `docs/ENV_VARS.md`. The
`tests/test_v031_4_env_vars_doc.py` test mechanically enforces that
every `RECUPERO_*` env var in `config.py` is documented there.

For development you can use stub values for the rate-limited / paid
API keys — the offline test suite mocks the HTTP boundary entirely.
For an end-to-end live trace you need at least `ETHERSCAN_API_KEY`,
`COINGECKO_API_KEY`, and (for Solana) `HELIUS_API_KEY` to be real.

---

## 5. Run the test suite (5 minutes)

The fast offline suite is the day-one signal that the install
succeeded:

```bash
pytest -q
```

Expected at v0.32.1: ~4600 passed, ~10 skipped, 0 failed. Wall clock
should be under 2 minutes on a modern laptop. The
`addopts = "-m 'not slow'"` in `pyproject.toml` excludes the
performance-regression locks by default; opt in with `pytest -m slow`
when you need them.

If a test fails on a fresh clone, the most common causes are:

1. A missing required env var (see step 4) — pytest prints the
   `RuntimeError: token mint requires RECUPERO_TOKEN_PEPPER` clearly.
2. A stale pyc / `__pycache__` from a previous Python version. Run
   `find . -name __pycache__ -exec rm -rf {} +` and retry.
3. The Graphviz `dot` binary missing from PATH on Windows.

---

## 6. Run the mutation harness (3 minutes)

```bash
python scripts/mutation_smoke.py
```

Expected: `43/43 mutations detected` (the exact count grows over
time; the success line is the last printed line). This is the smoke
test that validates the test suite actually catches the mutations the
suite was written to catch. Any failure here is a real signal — do
not merge through it.

If you are adding a new module, you should also add a mutation entry
to `scripts/mutation_smoke.py` that exercises the failure mode you
care about. The pattern is well-documented in the script itself.

---

## 7. Run a single case end-to-end (8 minutes)

```bash
recupero trace \
    --chain ethereum \
    --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
    --incident-time "2025-10-09T00:00:00Z" \
    --case-id DEMO-001
```

This is the Zigha victim address — a well-understood Ethereum theft
case used as the golden integration target. Wall clock for the trace
is 1-3 minutes against the free Etherscan tier.

Output lands in `data/cases/DEMO-001/`:

- `case.json` — the structured trace result (Pydantic-serialized).
- `transfers.csv` — flat CSV of every transfer the BFS visited.
- `evidence/*.json` — per-tx evidence receipt (one file per
  transfer).
- `case.log` — the full trace log at the level set by
  `RECUPERO_LOG_LEVEL`.
- `manifest.json` — chain-of-custody manifest with the Ed25519
  signature (if `RECUPERO_INVESTIGATOR_*` is configured).

Inspect the result:

```bash
recupero show --case-id DEMO-001
recupero inspect --case-id DEMO-001 --kind transfers
```

You can also drive the full pipeline (intake → trace → brief →
review → dispatch) by starting the worker against a Postgres instance:

```bash
# In one terminal: the worker
recupero-worker

# In a second terminal: post an intake via the API
recupero-api &
curl -X POST http://localhost:8000/v1/intake \
  -H "Content-Type: application/json" \
  -d '{...intake payload...}'
```

The full intake payload schema is in
`src/recupero/portal/intake.py`. For local dev the easiest path is to
open `http://localhost:8000/intake` in a browser and submit the form
manually.

---

## 8. Where to read next (3 minutes)

In order:

1. **`docs/ARCHITECTURE.md`** — the day-one document. ~5000 words,
   maps every pipeline stage to the modules and tables that implement
   it. Read this before writing any code.
2. **`docs/JACOB_v032_TRIAGE.md`** — the rolling audit-driven
   backlog. Tells you what is shipping in v0.32.1, what is deferred,
   and what the round-2 audit reviewers care about. If you are
   picking up a v0.32.x ticket, this is your context.
3. **`docs/ENV_VARS.md`** — the canonical env-var index.
4. **`docs/RIGOR.md`** — the testing/mutation/invariant philosophy.
5. **`docs/WHY_RECUPERO_WOULD_FAIL.md`** — the pre-mortem. Read this
   before claiming a fix "closes the case" — it has a long list of
   ways the system can still be wrong that the test suite does not
   cover yet.

---

## 9. Branch and PR workflow

- `main` is the Railway auto-deploy branch. Treat it as read-only
  unless you are explicitly cutting a release.
- `pdf-deliverables` is the active-development branch. Feature work
  branches off `pdf-deliverables`; the v0.32.x audit cycle merges back
  here before the merge to `main`.
- Worktrees: feature work commonly happens in a worktree under
  `.claude/worktrees/<feature-slug>/`. Use
  `git worktree add ../<name> pdf-deliverables` to create one.
- PRs target `pdf-deliverables`. The merge to `main` is a separate,
  audit-gated step (see `docs/DEPLOY_v0_32_0_RUNBOOK.md`).

---

## 10. Common pitfalls

- **`pip install -e .` without `[dev]`.** The console scripts install
  but you lose pytest / mypy / ruff. Always use `pip install -e
  ".[dev]"` for dev.
- **Editing src and not seeing the change.** You're not in the venv,
  or you installed without `-e`. Confirm with `pip show recupero` —
  the `Location` should be your source tree, not `site-packages`.
- **Etherscan free-tier rate-limit.** 5 req/sec, 100k req/day. The
  Zigha integration burns ~3k requests. You'll see `429` errors on a
  busy day; wait or upgrade.
- **`RuntimeError: token mint requires RECUPERO_TOKEN_PEPPER`.** Set
  the env var (step 4). Even tests that don't exercise the portal
  import the pepper module.
- **WeasyPrint native deps on Windows.** WeasyPrint needs Pango +
  Cairo. On Windows the simplest path is the GTK+ runtime bundle —
  see https://weasyprint.readthedocs.io/en/stable/install.html#windows.
  On Linux/macOS the Dockerfile / brew formula already covers it.
- **Forgetting to apply migrations.** A clean `SUPABASE_DB_URL`
  database has no Recupero schema. Run `python scripts/apply_migration.py
  migrations/001_*.sql` through `030_*.sql` in numeric order before
  starting the worker.

---

You should now be productive on the codebase. Pair with someone on
your first real PR — the audit cycle is rigorous and the INVARIANT
framework is unforgiving of "looks right" code that hasn't been
verified end-to-end.
