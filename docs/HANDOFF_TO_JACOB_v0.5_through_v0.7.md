# Handoff to Jacob — worker v0.5.0 through v0.7.3

> Catches you up on what landed on the worker side after the
> v0.5.0/.1/.2 reply (`docs/REPLY_TO_JACOB_2026-05-17.md`).
> Nine tagged releases, three new DB tables, two new HTTP
> surfaces, one big commercial change. Order of priority for
> your build queue is in §6.

---

## 1. TL;DR — what shipped

| Tag | One-line summary | UI impact |
|---|---|---|
| v0.5.3 | Closed retry-with-backoff gaps (Helius, Resend, Storage) | None |
| v0.5.4 | Portal-link auto-delivery in `victim_summary` email | Low |
| v0.6.0 | **Stripe webhook + dispatcher + `public.payments` table** | High |
| v0.6.1 | `recupero-ops generate-payment-link` CLI + dispatcher reads `client_reference_id` | Medium |
| v0.6.2 | Pay-Now button auto-injected in `victim_summary` email | Low |
| **v0.7.0** | **$10,000 decoupled engagement fee + centralized pricing** | **HIGH** |
| v0.7.1 | `list-payments` CLI + `payments` section on `/dashboard.json` | High |
| v0.7.2 | Refund + dispute → operator alert email; `recent_refunds`/`recent_disputes` on dashboard | Medium |
| v0.7.3 | `stripe-mode` CLI + test/live mismatch warnings | None (ops only) |

**Test suite:** 715 passing, 0 regressions.
**Migrations applied to prod:** 007, 008, 009, 010 (see §3).

---

## 2. The big one — pricing changed to $10,000

The engagement fee went from $1,500 to **$10,000**, and the
diagnostic ($499) and engagement are now **decoupled** — the
$499 is NOT credited against the engagement anymore. Both are
separate, non-refundable-once-work-begins charges.

**Customer-facing copy now reads:**
- "$499 diagnostic" (one-time, separate)
- "$10,000 engagement fee" (one-time, separate)
- 15% contingency on recovered funds (unchanged)
- Recoverable floor: $40,000 (4× engagement). Below this we auto-route the case as "unrecoverable" rather than pitching engagement.

**Things in your UI that need updating:**

| Where | What to change |
|---|---|
| Mark Engaged button → fee input default | $1,500 → $10,000 |
| Inline fee editor placeholder | $1,500 → $10,000 |
| Any "Tier 2 — $1,500" or "$1,500 engagement" copy | $10,000 |
| Pricing card / tier table | $499 + $10,000 + 15% contingency |

**Pricing is now a single source of truth on the worker side:**
`recupero._pricing` exports `DIAGNOSTIC_FEE_USD`,
`ENGAGEMENT_FEE_USD`, `CONTINGENCY_PCT`,
`RECOVERABLE_FLOOR_USD`. If you'd find a `/api/pricing` endpoint
useful (so your UI doesn't hardcode the same numbers and drift
again on the next price change), say the word — it'd be a
~10-line addition to the health server.

**Past investigations** with `engagement_fee_paid_usd=$1,500`
remain at $1,500 in the DB unchanged. The change is "what new
investigations record / what new emails say," not a retroactive
rewrite. Your case detail page displaying the value as-stored is
the right behavior.

---

## 3. New DB tables (migrations applied to prod)

### `public.payments` — Stripe audit log + idempotency

One row per Stripe webhook event we've received. UNIQUE on
`stripe_event_id` so re-deliveries are no-ops.

```sql
CREATE TABLE public.payments (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_event_id          text NOT NULL UNIQUE,
    stripe_event_type        text NOT NULL,
    stripe_checkout_session_id text,
    stripe_payment_intent_id text,

    case_id                  uuid REFERENCES public.cases(id),
    investigation_id         uuid REFERENCES public.investigations(id),

    -- 'diagnostic' | 'engagement' | 'contingent' | 'unknown'
    amount_type              text NOT NULL DEFAULT 'unknown',
    amount_cents             integer NOT NULL,
    currency                 text NOT NULL DEFAULT 'usd',
    amount_usd               numeric(20, 2) GENERATED ALWAYS AS (...) STORED,

    -- 'paid' | 'unpaid' | 'refunded' | 'disputed'
    status                   text NOT NULL,
    raw_event                jsonb NOT NULL,

    received_at              timestamptz NOT NULL DEFAULT NOW(),
    processed_at             timestamptz,
    notes                    text
);
```

**Suggested UI:** mirror your existing "Email activity" section.
On case detail, add a "Payment activity" section listing the
rows for that case_id — type, amount, status, received_at,
notes (when status is `refunded`/`disputed` or notes mention
"audit_only", surface as red/amber chips).

### `public.engagement_signatures` — portal e-sign audit trail

One row per electronic signature captured at
`/portal/<token>/sign`. The portal flow also writes
`engagement_started_at` on the investigation row, so the admin
UI's existing Mark-Engaged display "just works" — but the
signature row is the evidence of agreement.

```sql
CREATE TABLE public.engagement_signatures (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id           uuid NOT NULL,
    investigation_id  uuid,
    case_token_id     uuid,
    signature_name    text NOT NULL,    -- customer's typed full name
    agreement_text    text NOT NULL,    -- snapshot of what they agreed to
    fee_usd           numeric(20, 2) NOT NULL,
    signed_at         timestamptz NOT NULL DEFAULT NOW(),
    ip_address        text,
    user_agent        text
);
```

**Suggested UI:** on case detail, indicator next to "Engaged" —
"signed via portal" if there's a row in
`engagement_signatures` for this investigation, "signed
manually" otherwise. Operator sees who consented to the
engagement (portal e-sign vs operator-typed-into-DB).

### `public.case_tokens` — portal access tokens

Token-gated `/portal/<token>` access. Each case can have
multiple tokens (operator regenerates on customer request).

```sql
CREATE TABLE public.case_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id     uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    token       text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    expires_at  timestamptz,
    revoked_at  timestamptz,
    label       text,                  -- 'victim' | 'attorney' | 'family' | ...
    last_used_at timestamptz
);
```

**Suggested UI:** on case detail, "Customer portal access"
section — list active tokens (those without `revoked_at`,
not past `expires_at`), with a "Revoke" button (UPDATE
revoked_at) and a "Generate new link" button (calls
`recupero-ops generate-customer-link` or a similar API).
`last_used_at` lets you show "Customer last visited
2 days ago" indicator.

### `public.watchlist` — new columns from migration 009

The watchlist row now carries three columns from the
INVESTIGATE → FREEZABLE promotion workflow:

```sql
ALTER TABLE public.watchlist ADD COLUMN
    kyc_confirmed_at        timestamptz,
    kyc_confirmed_by_operator text,
    kyc_confirmation_note   text;
```

**Suggested UI:** wherever you display watchlist rows, show
"FREEZABLE via Circle confirmation 2026-05-15 (alec@recupero)"
when `kyc_confirmed_at` is set, vs "INVESTIGATE" otherwise.
The note text is operator-curated and may include a Stripe-style
audit string ("Circle ticket #1234, email thread 2026-05-15").

---

## 4. New API surfaces on the worker

### `/dashboard.json` — new sections

The shape grew. Existing keys (`cases`, `investigations`,
`watchlist`, `snapshots`, `digest`, `stale_review`) are unchanged.
**Three new top-level keys** as of v0.7.3:

```jsonc
{
  // ... existing keys ...

  "stale_engagements": {
    "count":          0,
    "threshold_days": 30,
    "rows": [
      {
        "investigation_id":      "...",
        "case_id":               "...",
        "case_number":           "V-...",
        "client_name":           "...",
        "engagement_started_at": "2026-04-10T12:00:00+00:00",
        "last_followup_sent_at": "2026-05-04T03:00:00+00:00",
        "days_since_start":      35,
        "days_overdue":          5
      }
    ]
  },

  "payments": {
    // Rollup counters
    "count_24h":              N,
    "paid_count_24h":         N,
    "amount_paid_cents_24h":  N_cents,    // divide by 100 for USD
    "refunded_count_24h":     N,
    "disputed_count_24h":     N,
    "count_7d":               N,
    "paid_count_7d":          N,
    "amount_paid_cents_7d":   N_cents,

    // Triage queue — paid events where the dispatcher
    // couldn't fully map them to a workflow row. Surface as
    // "N events need linking" on the homepage.
    "needs_triage_count":     N,

    // Recent items (5 each) for the homepage's attention widget.
    // Each entry: payment_id, received_at, amount_cents,
    // amount_type, case_id, case_number, client_name,
    // investigation_id, notes.
    "recent_refunds":         [...],
    "recent_disputes":        [...]
  }
}
```

**Suggested UI:**
- A "Payments — last 24h / 7d" tile on the homepage with the
  rollup counts + total volume.
- A "Needs attention" widget grouping `stale_review` +
  `stale_engagements` + `needs_triage_count` + recent
  refunds/disputes into one prominent area at the top.

### `/portal/<token>` — token-gated customer surface

The worker hosts a customer-facing HTML portal at
`/portal/<token>`. Three routes:

- `GET /portal/<token>` — case status, artifact downloads,
  engagement state.
- `GET /portal/<token>/sign` — engagement-letter e-sign form.
- `POST /portal/<token>/sign` — captures signature, activates
  engagement.
- `GET /portal/<token>/artifact/<key>` — signed-URL redirect
  to the artifact PDF (5-min TTL).

**Suggested UI:** add a "Customer view" link on case detail
that opens `/portal/<token>` in a new tab using whichever
active token exists for the case. Useful for "what does the
customer see right now?" debugging.

### `/webhooks/stripe` — Stripe webhook receiver

POST endpoint at
`https://recupero-io-production.up.railway.app/webhooks/stripe`.
Verifies HMAC signature with `STRIPE_WEBHOOK_SECRET`, parses
the event, dispatches to the right workflow handler.

Not a UI surface, but: if your UI ever displays "last webhook
received" or has a "Test Stripe webhook" button for ops, this
is the endpoint to point at.

---

## 5. Reminders + open coordination items

### Capability mapping — confirmed

From the prior reply: `yes / limited / no / unknown` →
`HIGH / MEDIUM / NOT FREEZABLE / LOW`. The fourth bucket is
explicitly `"unknown"`, not a default catch-all. Lock the
comment in your code as "definitive" rather than "provisional".

### Engagement-state idempotency

Two paths now write to `investigations.engagement_started_at`:
- Admin UI Mark Engaged button (operator-initiated).
- Portal `/sign` flow (customer-initiated).

The portal uses `COALESCE(engagement_started_at, NOW())` so an
operator who marked Engaged first has their timestamp
preserved. **Recommend your Mark Engaged also use `COALESCE`**
(or its TypeScript equivalent — "if already set, leave it") so
the earlier of the two wins consistently.

### Refund / dispute workflow

`charge.refunded` / `charge.dispute.created` events now
trigger an operator alert email (to
`RECUPERO_OPS_ALERT_EMAIL`, falling back to
`RECUPERO_EMAIL_FROM`) and write a row to `public.payments`
with status='refunded' / 'disputed'. **Neither auto-reverses
engagement state** — the operator decides whether the
refund/dispute means the engagement should end. We don't have
an automated "auto-close on refund" path.

If you'd find an admin UI dispute-response workflow helpful
(file the dispute, attach evidence from the case's
engagement_letter / freeze_letter PDFs, submit to Stripe),
that's a real piece of work worth scoping. Disputes are
time-sensitive (Stripe gives a limited evidence window),
so making the response one-click would be valuable.

### Stage-checkpointing design (Ask #3)

`docs/STAGE_CHECKPOINTING_DESIGN.md` is still queued for your
review when you have bandwidth. Sizing is **1 day** of focused
work on the worker side (not the original 4-5d — the pipeline
already does artifact-existence resume). Four open questions
in the doc are blocking the build.

### Portal hostname

`RECUPERO_PORTAL_BASE_URL` is still unset on Railway. The
worker falls back to `RAILWAY_PUBLIC_DOMAIN` (which currently
resolves to `recupero-io-production.up.railway.app`), so the
portal is usable end-to-end today. Pointing a real
`portal.recupero.io` subdomain at the Railway service is
a 10-minute DNS change whenever you want.

### Stripe test/live mode awareness

New `recupero-ops stripe-mode` command reports which mode the
worker is configured for. Exits non-zero on mismatch — useful
in deployment CI gates. If your deploy pipeline ever does
"run a smoke check after `git push main`," consider invoking
`recupero-ops stripe-mode` as part of it.

---

## 6. Suggested UI builds, in priority order

| # | Build | Why now |
|---|---|---|
| 1 | **Update all $1,500 → $10,000 copy + fee defaults** | Without this, your UI undersells the engagement to the operator. Quickest, highest-impact. |
| 2 | **Payment activity section on case detail** | Mirror the existing emails_sent surface. Stripe payments are the missing piece of the case lifecycle. |
| 3 | **Refund/dispute prominence on dashboard** | Disputes are time-critical; surfacing recent_disputes from `/dashboard.json` payments section means operator sees them within seconds of the alert email. |
| 4 | **Portal token management on case detail** | "View as customer" / "Regenerate link" / "Revoke" buttons. Operator workflow today is `recupero-ops generate-customer-link <case_id>`; admin UI replaces that. |
| 5 | **Engagement signature indicator** | "Signed via portal" vs "Marked manually" — small UI element, helps operator audit who agreed to what. |
| 6 | **promote-freezable workflow** | Currently CLI-only (`recupero-ops promote-freezable <wid> --reason "..."`). Surface as button on watchlist row with a "Reason" prompt. |
| 7 | **stale_engagements widget on homepage** | Mirrors your existing stale_review widget. The data section is already on `/dashboard.json`. |

Item 1 is the customer-impacting one. 2 + 3 are operator-productivity. 4 + 5 + 6 + 7 are workflow polish.

---

## 7. Stripe end-to-end test plan (for confirming the wire is live)

When you point the webhook + Payment Links in Stripe Dashboard
to production, here's the validation sequence:

```bash
# 1. Confirm env vars are coherent
recupero-ops stripe-mode
# Should print: "Consensus: test mode (all configured signals agree)."

# 2. Mint a test diagnostic link for a real case
recupero-ops generate-payment-link 5a9c901e-... \
    --type diagnostic --chain ethereum \
    --seed-address 0x0cdC...e955

# 3. Pay through the printed URL with test card 4242 4242 4242 4242
#    (any future expiry, any 3-digit CVC)

# 4. Confirm the webhook landed
recupero-ops list-payments --since 24h
# Should show a row: type=diagnostic, $499, paid, V-...
```

If anything fails at step 4 — most likely `whsec_test_*` vs
`buy.stripe.com/test_*` mismatch — `stripe-mode` would have
caught it at step 1. The mismatch warning shows up loud in
the CLI output.

---

Holler if anything's unclear, or if you want me to expand on
specific UI pieces above. Happy to write API-shape mocks for
the suggested builds.

— Alec
