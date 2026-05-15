# Investigations API — admin UI contract

The worker exposes two HTTP endpoints that back the admin UI's
wallet-trace and case-driven investigation views. Both run inside
the existing health-server pod (same process as the `/healthz` and
`/dashboard.json` endpoints), so they share Railway's healthcheck
routing and never require an extra deploy target.

**Base URL:** `https://recupero-worker-production.up.railway.app`
(Railway public domain for the `recupero-worker` service)

**Auth:** none — the endpoints read from the same connection-pooled
DB the worker uses and emit signed Supabase URLs that carry their
own short-lived tokens. The admin UI fronts a separate auth layer;
that layer is the boundary for ACL'ing which operators see which
investigations.

**Response format:** always JSON. `Content-Type: application/json`.
Decimals are returned as strings to preserve precision; datetimes
are ISO-8601 with explicit UTC offsets; UUIDs are unhyphenated-form
canonical strings. `null` is used for genuinely-absent values
(missing column, no end time yet, no error).

---

## `GET /investigations`

Paginated list of investigations matching the given filters. Backs
the admin UI's investigation-index pages (wallet-trace tab,
case-driven tab, etc.).

### Query parameters

| Param           | Type    | Default | Notes |
|-----------------|---------|---------|-------|
| `status`        | string  | (any)   | Match the raw DB column. One of `pending`, `claimed`, `tracing`, `listing_freeze_targets`, `editorial_drafting`, `awaiting_review`, `emitting`, `building_package`, `complete`, `failed`. |
| `chain`         | string  | (any)   | `ethereum`, `arbitrum`, `polygon`, `base`, `bsc`, `solana`, `hyperliquid`. |
| `type`          | string  | (any)   | `wallet_trace` (case_id IS NULL) or `case_driven` (case_id IS NOT NULL). |
| `label_prefix`  | string  | (any)   | Case-insensitive prefix match on `label`. Useful for finding canaries, batch tags. |
| `limit`         | int     | 25      | Max 100. |
| `offset`        | int     | 0       | For paging. |

### Response shape

```jsonc
{
  "items": [
    {
      "id":               "849062ab-6a82-4af2-bfd9-d7092a2701c5",
      "case_id":          null,                                       // null for wallet traces
      "status":           "complete",
      "chain":            "ethereum",
      "seed_address":     "0x8E3b200f356724299643402148a25FD4B852Bd53",
      "label":            "real-case validation: ...",                // operator-set, may be null
      "triggered_by":     "alec@recupero.io",
      "triggered_at":     "2026-05-15T16:54:32.513593+00:00",
      "completed_at":     "2026-05-15T16:55:13.472589+00:00",         // null if not yet complete
      "failed_at":        null,                                        // set if status='failed'
      "max_depth":        1,
      "skip_editorial":   true,
      "skip_freeze_briefs": true,
      "total_loss_usd":   "0.00",                                      // see note below
      "max_recoverable_usd": "0.00",
      "freezable_issuers": null,                                       // array of strings when populated
      "is_wallet_trace":  true                                         // computed: case_id IS NULL
    },
    /* ...more items... */
  ],
  "total":  3,        // matching filters, BEFORE limit/offset
  "limit":  25,
  "offset": 0
}
```

> **Note on `total_loss_usd`**: this column carries the FREEZABLE-only
> total (sum of USD value held by labeled issuers). On wallet-trace
> rows (`skip_freeze_briefs=true`) it's always `"0.00"` because we
> don't compute freezable targets — the real "money that moved
> through this wallet" is in `summary.total_usd_out` on the detail
> endpoint, sourced from `case.json:total_usd_out`. The list endpoint
> intentionally doesn't include this to keep the per-row JSON small;
> fetch the detail when surfacing a flow total in the UI.

### Errors

| Code | Meaning |
|------|---------|
| 200  | Normal response. `total: 0, items: []` is valid for a filter that matches nothing. |
| 400  | Bad query — non-integer `limit` / `offset`, or non-UUID where one was expected. Body: `{"error": "<reason>"}`. |
| 500  | Server-side failure (DB unreachable, etc.). Body: `{"error": "<message>"}`. |

### Example

```bash
curl 'https://recupero-worker-production.up.railway.app/investigations?type=wallet_trace&status=complete&limit=10'
```

---

## `GET /investigations/<uuid>`

Full row + bucket artifact metadata + signed URLs + summary card for
one investigation. Backs the per-investigation detail page (the one
that renders `trace_report.html` in an iframe + surfaces flow-diagram
and raw-case downloads).

### Path parameter

| Param  | Type | Notes |
|--------|------|-------|
| `<uuid>` | UUID | Canonical hyphenated form (e.g. `849062ab-6a82-4af2-bfd9-d7092a2701c5`). |

### Query parameters

| Param           | Type    | Default | Notes |
|-----------------|---------|---------|-------|
| `latest_only`   | bool    | `true`  | When multiple brief sets exist per issuer (from pre-cleanup re-runs), return only the most-recent set per issuer. Set to `false` to get the full historical list — useful for an audit-trail view. Going forward (post commit `a507f12`), each `building_package` cleans the bucket before upload, so investigations should only ever have one set anyway. The filter is the UI-side safety net for historical rows. |

### Response shape

```jsonc
{
  // ----- DB row, projected -----
  "id":                "849062ab-6a82-4af2-bfd9-d7092a2701c5",
  "case_id":           null,
  "status":            "complete",
  "chain":             "ethereum",
  "seed_address":      "0x8E3b200f356724299643402148a25FD4B852Bd53",
  "label":             "real-case validation: ...",
  "max_depth":         1,
  "dust_threshold_usd": "1.0",
  "incident_time":     "2026-01-02T00:00:00+00:00",   // null on full-history wallet traces
  "skip_editorial":    true,
  "skip_freeze_briefs": true,

  "triggered_by":      "alec@recupero.io",
  "triggered_at":      "2026-05-15T16:54:32.513593+00:00",
  "worker_id":         "b6b3522eb9ba-1",
  "claimed_at":        "2026-05-15T16:54:34.439264+00:00",
  "last_heartbeat_at": "2026-05-15T16:55:13.472589+00:00",
  "started_at":        "2026-05-15T16:54:35.772082+00:00",
  "completed_at":      "2026-05-15T16:55:13.472589+00:00",
  "failed_at":         null,
  "error_stage":       null,                          // set if status='failed'
  "error_message":     null,
  "review_required_at": null,
  "reviewed_at":       null,
  "reviewed_by":       null,
  "review_notes":      null,

  "total_loss_usd":    "0.00",
  "max_recoverable_usd": "0.00",
  "api_costs_usd":     null,
  "freezable_issuers": null,
  "supabase_storage_path": "investigations/849062ab-.../",

  "is_followup_run":   false,
  "prior_investigation_id": null,
  "material_change_detected": false,
  "change_summary":    null,

  // ----- Computed for UI convenience -----
  "is_wallet_trace":   true,
  "duration_seconds":  39.03,                         // claimed_at → completed_at|failed_at

  // ----- Bucket artifacts + signed URLs -----
  "artifacts": {
    "trace_report": {
      "html": {
        "name":        "trace_report_22ea9c3f.html",
        "size_bytes":  26005,
        "mimetype":    "text/html; charset=utf-8",
        "signed_url":  "https://...supabase.co/storage/v1/object/sign/...?token=..."
      },
      "pdf": {
        "name":        "trace_report_22ea9c3f.pdf",
        "size_bytes":  47281,
        "mimetype":    "application/pdf",
        "signed_url":  "https://...supabase.co/storage/v1/object/sign/...?token=..."
      }
    },
    "flow_diagram": {
      "svg": { "name": "flow_79766891.svg", "size_bytes": 6947,  "mimetype": "image/svg+xml",  "signed_url": "..." },
      "pdf": { "name": "flow_79766891.pdf", "size_bytes": 17244, "mimetype": "application/pdf", "signed_url": "..." }
    },
    "raw": {
      "case_json":     { "name": "case.json",         "size_bytes": 5962, "mimetype": "application/json", "signed_url": "..." },
      "manifest_json": { "name": "manifest.json",     "size_bytes": 2029, "mimetype": "application/json", "signed_url": "..." },
      "freeze_asks":   { "name": "freeze_asks.json",  "size_bytes": 120,  "mimetype": "application/json", "signed_url": "..." },
      "freeze_brief":  { "name": "freeze_brief.json", "size_bytes": 177,  "mimetype": "application/json", "signed_url": "..." },
      "transfers_csv": { "name": "transfers.csv",     "size_bytes": 1670, "mimetype": "text/csv",         "signed_url": "..." }
      // optional: victim_json, editorial_json (case-driven runs only)
    },
    "freeze_letters": [
      // empty array on wallet traces (skip_freeze_briefs=true).
      // Case-driven runs populate one entry per freezable issuer:
      // {
      //   "issuer_slug": "Circle",
      //   "html":            { "name": "freeze_request_circle_abcd1234.html", ... },
      //   "pdf":             { "name": "freeze_request_circle_abcd1234.pdf",  ... },
      //   "le_handoff_html": { "name": "le_handoff_circle_abcd1234.html",     ... },
      //   "le_handoff_pdf":  { "name": "le_handoff_circle_abcd1234.pdf",      ... }
      // }
    ]
  },

  // ----- Summary card (parsed from case.json) -----
  "summary": {
    "transfers":              3,         // count
    "addresses_traced":       4,         // unique addresses across all transfers (incl. seed)
    "total_usd_out":          "21647.81",// total USD value moved through seed
    "exchange_endpoints":     0,         // labeled exchange destinations the trace stopped at
    "unlabeled_counterparties": 3
  }
}
```

### Signed URLs

- TTL is **60 minutes** from generation. Re-fetch the detail
  endpoint if a cached URL is close to expiry — the URLs are stable
  except for the token, so the UI can cache the rest of the response
  longer.
- Anonymously fetchable — no auth header needed when fetching the
  URL itself. Verified: pasting the trace_report.html URL into a
  fresh tab renders the HTML directly. The admin UI can drop the
  URL straight into `<iframe src="...">` or `<a download>`.
- If the bucket-listing call fails (e.g., transient Supabase Storage
  outage), the `artifacts` block returns its empty shape — `{html:
  null, pdf: null}` for the trace_report, `[]` for freeze_letters,
  etc. The row metadata is still rendered so the UI can show
  partial state with a "couldn't load artifacts, try refresh"
  banner.

### Errors

| Code | Meaning |
|------|---------|
| 200  | Normal response. |
| 400  | `<uuid>` failed UUID parsing. Body: `{"error": "id must be a UUID"}`. |
| 404  | No row with that ID. Body: `{"error": "investigation not found"}`. |
| 500  | Server-side failure. |

### Example

```bash
curl 'https://recupero-worker-production.up.railway.app/investigations/849062ab-6a82-4af2-bfd9-d7092a2701c5'
```

---

## Live canary rows for prototyping

These three investigations are intentionally preserved for the
admin-UI build. All are wallet traces (case_id NULL) and they
exhibit the three states the UI most needs to render correctly.

| ID | Label | Use for |
|----|-------|---------|
| `849062ab-6a82-4af2-bfd9-d7092a2701c5` | real-case validation | **Primary**: 3 real transfers, $21,647.81 flow, all artifacts present (trace_report HTML+PDF, flow SVG+PDF, raw bundle). Best for the "happy path" detail view. |
| `fa34bb56-4319-423c-9eed-c55d3b134948` | canary: wallet-trace fix verification | 0-transfer "found nothing" case. Useful for testing how the UI renders an empty trace_report — the artifact still ships, transfers is `0` but the row is `complete`. |
| `c78b2865-73c1-42cd-aa75-4ab168486512` | pre-fix canary: 0 transfers due to block-clamp bug | Historical / for context. Don't build UI around this one. |

---

## Coming soon

Not yet implemented but on the roadmap if the admin UI needs them:

- `POST /investigations` — trigger a new wallet trace from the
  admin UI. Currently the admin UI inserts rows directly via the
  Supabase client; this would centralize input validation.
- `PATCH /investigations/<id>` — update label, re-run flag, etc.
  Same rationale as above.
- `GET /investigations/<id>/transfers` — paginated transfers if
  `summary.transfers` gets large enough that returning the full
  case.json over signed URL is impractical (>1MB).

File a GitHub issue if you hit a friction point — the API is meant
to be a thin slice over what's needed; we'll widen it as the UI
evolves.
