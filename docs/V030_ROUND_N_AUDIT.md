# v0.28 – v0.30.0 Round-N Audit (Tier-1 security + correctness)

Read-only audit of post-v0.27.2 surfaces NOT covered by
`docs/V029_AUDIT_FINDINGS.md` (which only inspected the v0.28–v0.29.1
bridge / label / decoder corridor) and NOT already captured by
`docs/BRIEF_READTHROUGH_FINDINGS_v030.md` (which catalogues F1–F17 of
the lawyer read-through). Focus: v0.30.0 brief.py / `_le_routing` /
`_common`, subpoena family (v0.28.1), cluster handoff (v0.23.0),
cooperation intel + law-firm dashboard, intake portal + freeze-outcome
+ monitoring API (v0.27.0), and the freeze-letter / LE templates as
modified in v0.30.0.

## TIER-1 CRITICAL — silent bad output / PII leak / authz bypass

**T1-A. `_enrich_via_label_store` lazy-cache races on multi-thread workers.**
`src/recupero/reports/brief.py:1314-1320` — the function caches the
`LabelStore` on its own `__func__` attribute under a *lock-free* `if
not hasattr(...)` / `setattr` sequence. With two threads concurrently
rendering different briefs, both can pass the `hasattr` check, both
call `LabelStore.load(...)`, and the second `setattr` wins — but the
first thread's local read of `_enrich_via_label_store._store` may
return the half-initialised None set on the `except` branch
(`= None` at line 1319) for the OTHER thread's failed load. Worker
today is single-threaded but emit_brief is also called from
`scripts/render_only.py`, from ops CLI, and (per v0.27.0) from the
FastAPI process; the same module-load shared. A single misroute of a
freeze letter (load returned None temporarily → unlabeled fallback →
section-5 filter drops the bridge contract) is silent and
unrecoverable. **Fix:** wrap the load in a `threading.Lock` guard, or
move the cache to `functools.lru_cache(maxsize=1)` on a wrapper
function (lru_cache is thread-safe).

**T1-B. `is_investigator_configured` / `require_investigator_configured` not exported.**
`src/recupero/_common.py:501-544`, `__all__` at `:659-677` — both
predicates omitted from `__all__`. A consumer that does `from
recupero._common import *` (the AI-editorial path historically did
this) won't see them, will fall back to checking the placeholder
string by hand, and will skip the deploy gate. The whole point of
v0.30.0 F7 is a single canonical predicate so a typo can't bypass —
not exporting it defeats the design. **Fix:** add both names to
`__all__`.

**T1-C. Issuer freeze letter still emits victim citizenship.**
`src/recupero/reports/templates/issuer_freeze_request.html.j2:219` —
v0.30.0 F2 removed home address + personal email + phone (lines
205-217 comment block), but the immediately following line still
renders `victim.name ({{ victim.citizenship }})`. For a US victim
this surfaces "Citizen of USA (Texas)" to Circle / Tether compliance.
Citizenship is PII; an issuer compliance team has no need-to-know.
The same line also leaks the parenthesized state portion when
citizenship is "USA (Texas)" — exactly the field the LE-routing parse
helper exists to extract from. **Fix:** drop `victim.citizenship`
from line 219; the affected-wallet + perpetrator-wallet + token
contract triple is sufficient for the issuer's freeze decision per
the v0.30.0 design comment. Also strip parenthesized state from any
remaining victim-jurisdiction renderings in `exchange_subpoena_request.html.j2:92`.

**T1-D. `INTERNATIONAL_FALLBACK` note text uses unparsed `country`.**
`src/recupero/worker/_le_routing.py:347-351` — after
`_parse_citizenship_country_state` splits `"Germany (Berlin)"` into
`("Germany", "Berlin")`, the int'l-fallback note still does
`f"...({country})..."` — interpolating the RAW string with the state
suffix still attached. A German victim's LE handoff therefore reads
"Victim located outside the US (Germany (Berlin))" — minor render
bug, but worse: if `country` was a structured `None` and
`citizenship` was the carrier, the helper-extracted country flows to
`country_norm` but NOT to the note → the note reads "outside the US
(None)". **Fix:** use `effective_country or country or "unknown"` in
the f-string.

## TIER-2 HIGH — degrades output quality / security posture

**T2-A. Burn-address lookup keys are EVM-form only; chain-agnostic mislabel risk.**
`brief.py:1273-1281` + `:1426-1428` — `_BURN_ADDRESSES` contains only
the EVM `0x000…000` and `0x…dEaD` constants, and the lookup is
`addr_lower = t.to_address.lower()`. A Tron-case (TRC-20) burn
address (`TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy` — Tron official burn)
or Solana incinerator (`1nc1nerator11111111111111111111111111111111`)
is silently labeled "Unlabeled (under investigation)" with a
case-pollution risk on cross-chain Tron/Solana briefs. The v0.30.0 F6
fix only closes the gap on Ethereum. **Fix:** key the map by
`(chain, addr_canonical)` and include the canonical Tron / Solana /
BSC burn destinations.

**T2-B. Section 5 USD floor uses additive aggregation across token types.**
`brief.py:1474-1481` — `agg["usd_in"] += Decimal(t.usd_value_at_tx)`
sums USD across every transfer at the same destination address
without checking that the per-token oracle was finite at the time.
The `_enrich_via_label_store` codepath has no `is_finite()` check on
`t.usd_value_at_tx` (unlike `_pricing.fmt_usd` and the v0.21/.22
hardening elsewhere) — a single NaN in the trace transfers (rare but
possible from a pricing-cache miss the trace did not refresh) makes
`agg["usd_in"]` permanently NaN, which then sorts as the highest USD
in `sorted_unlabeled` (line 1525-1529) and crowds out every
legitimate row from the hard-cap. **Fix:** add an
`if not Decimal(...).is_finite(): continue` before the in-place add.

**T2-C. Subpoena renderer reads victim.email but never strips it.**
`subpoena_renderer.py:267-272` — `_normalize_victim` pulls
`getattr(victim, "email", None)` and passes it to the template
context for `subpoena_target.html.j2` and `subpoena_playbook.html.j2`.
The current templates DON'T render `victim.email` (greps clean), but
the field IS exposed in the context, and a future template edit
({{ victim.email }} anywhere) would silently leak the victim's email
to a grand-jury-subpoena recipient (a CEX compliance team that has
no need-to-know — same blast radius as v0.30.0 F2 / T1-C). **Fix:**
drop `email` from the normalize-dict; let the LE handoff be the
single template family with victim PII.

**T2-D. Subpoena `_resolve_cex_recipient` substring match is greedy.**
`subpoena_targets.py:189-199` — after the exact-key miss, iterates
`compliance_map` and routes on first `if k in exchange:` hit.
Iteration order is dict-insertion order in CPython 3.7+ but the order
in `_KNOWN_CEX_COMPLIANCE` (lines 74-89) lists `"mexc"` first. A
label string like `"MEXC Coinbase trust"` (operator typo, or an
adversarial perpetrator exchange label) would route to MEXC's
compliance email — the subpoena lands at the wrong CEX. Also
`"binance"` is a substring of `"binance.us"` (a separate legal
entity); the BinanceUS subpoena would mis-route to leinquiries@binance.com.
**Fix:** longest-match-wins; sort `compliance_map.items()` by `len(k)
DESC` before the substring loop.

**T2-E. Cluster handoff lacks investigator-configured gate.**
`cluster_handoff.py:44-125` — renders without checking
`is_investigator_configured()`. The cluster handoff is the LAW-FIRM
unlock document (one filing decision across N victims) and inherits
no DRAFT-banner stamping path. v0.30.0 F7 gated the per-case brief
but missed this cousin file. An unconfigured Railway deploy can ship
a cluster handoff to an AUSA with no operator name attached. **Fix:**
call `is_investigator_configured()` and either refuse or stamp a
DRAFT class; mirror the per-case brief logic.

## TIER-3 MEDIUM — hardening + polish

**T3-A. `_TOKEN_ASSET_DESCRIPTIONS` is Ethereum-mainnet-only.**
`brief.py:250-267` — keys are bare lowercased addresses, no chain
tag. USDC's BSC contract (`0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d`)
isn't in the map and falls back to the generic ERC-20 string, but
the address-only keying also means a token at the SAME byte-form
address on another chain (Polygon WETH ≠ Ethereum WETH at the same
hex string — these collide) would resolve to the wrong description.
Today's map happens to be EVM stablecoins, so the cross-chain
collision shape is hypothetical, but the design is fragile. **Fix:**
key by `(chain, lower_address)` tuple and pass `t.chain` into
`_resolve_asset_description`.

**T3-B. `_safe_filename_component` truncation hash-suffix collision window.**
`subpoena_renderer.py:38-57` — the 16-char SHA256 prefix is 64 bits;
birthday-paradox collision probability for N inputs sharing the same
47-char prefix is ~1e-10 at N=1000. Negligible for one case but the
v0.28.3 collision-handling code at line 156-177 already exists for
recipient_name dedup — the same logic should track the
post-truncation hash too. **Fix:** include the hash output in
`used_filenames`.

**T3-C. Subpoena USD threshold sanitized only on entry path.**
`subpoena_targets.py:209-224` — `_sanitize_usd` properly handles
NaN/Inf/negative for `_parse_usd_from_str`, but the
`existing["_total_usd"] += amt` aggregation at line 358 doesn't
re-sanitize. If a future caller passes a raw Decimal directly into
the map's `_total_usd` (e.g. via the `cex_targets_by_recipient`
dict reuse pattern in step 1), Inf survives. **Fix:** wrap the +=
in `_sanitize_usd` defensively.

**T3-D. Portal token last_used_at write is not under the same txn as verify.**
`portal/tokens.py:289-294` — the SELECT runs in one statement; the
UPDATE in another; both inside a single `db_connect` with
`autocommit=True` (the `_common.db_connect` default). Between the
two statements, a concurrent /sign POST + a token-revocation by an
operator can interleave such that the UPDATE writes
`last_used_at = NOW()` on a row whose `revoked_at` was just set —
non-fatal but operator-confusing. **Fix:** ` cur.execute(UPDATE ...
WHERE revoked_at IS NULL AND ...)` to make the update self-guarded.

**T3-E. Stripe webhook payload stored as raw JSONB in payments table.**
`payments/dispatcher.py:151` — `json.dumps(event.payload)` is dumped
unredacted into `public.payments.notes_jsonb` (or similar). Stripe
checkout-session payloads carry `customer_details.email`,
`customer_details.name`, IP, billing-address. An operator running
`SELECT notes FROM public.payments` from psql sees raw customer PII
mixed with payment-state. Not a leak per se (operators are trusted),
but it removes the PII-handling boundary the LE-handoff design tries
to maintain. **Fix:** strip Stripe's `customer_details` /
`payment_method_details` sub-objects before persisting; keep only
the fields the dispatcher actually reads back (event_id, type,
amount, currency, metadata).

## TIER-4 LOW — nice-to-have

**T4-A. `_BLOCKED_HOSTNAMES` set missing CGN-NAT (100.64.0.0/10) IP literal.**
`monitoring_api.py:66-75` — the IP set covers cloud metadata services
but `_is_blocked_ip` relies on `ipaddress.IPv4Address.is_private`
which DOES treat 100.64/10 as reserved → effectively covered. Not a
gap; flagging as a confirmed negative since the CGN-NAT vector is a
known SSRF bypass and the comment doesn't explain why it's
"covered for free".

**T4-B. `_intake_rl_state` dict cleanup loop is O(N) in the request path.**
`api/app.py:1276-1281` — when the dict exceeds 1024 entries every
admit walks the full state to evict stale entries. Under a scan
attack with rotating IPs, this turns a constant-time RL admit into a
1024-step loop per request — degrades the API but does not lock it
up. **Fix:** evict from a heap keyed on `(window_start, ip)` so the
trim is O(log N), or trim every Nth admit instead of every admit
once the threshold is crossed.

**T4-C. Cooperation profile fetch lacks per-issuer cache invalidation marker.**
`monitoring/cooperation_intelligence.py` (whole module) — issues
queries every time `build_cooperation_profile` runs; the
law-firm-dashboard renderer in `reports/law_firm_dashboard.py:212-265`
calls this per top-issuer, so a firm with 20 issuers makes 20 DB
round-trips per dashboard render. The v0.26.1 comment claims the
N×N regression was fixed (it was — for `build_all_firm_portfolios`
calling `render_law_firm_dashboard` twice each), but per-firm the
per-issuer fan-out remains. Not a security finding, but a P95 latency
ceiling once the firm count grows. **Fix:** add a single-query
`build_all_cooperation_profiles_in(issuers=[...])` and let the
dashboard reuse it.

## Surfaces examined with NO findings

- `src/recupero/api/auth.py` — multi-tenant authorization (S-1 +
  RECUPERO_API_KEY_CASES) is sound: deny-by-default, constant-time
  match, prod-marker auth-bypass refusal, 404 response shape parity
  between "unauthorized" and "not found" so no enumeration oracle.
- `src/recupero/api/monitoring_api.py` SSRF guard — strict
  `ipaddress.ip_address` PLUS `socket.inet_aton` fallback closes the
  decimal / octal / hex / short-form IPv4 bypass; hostname-suffix
  block list catches `*.internal` / `*.local`; HTTPS-only + min
  16-char secret + DNS-rebinding check at dispatch time. Round-9
  attack model fully defended.
- `src/recupero/portal/server.py` — Origin-check CSRF defense on
  POST /sign, token rotation after sign, closed-engagement replay
  block, bucket-filename whitelist on artifact resolve, no-referrer
  + no-store on artifact 302. Multi-tenant boundary (token →
  case → investigation) is monotonic.
- `src/recupero/reports/law_firm_dashboard.py` — slug sanitizer
  rejects path traversal, control chars, bidi/zero-width; finite-
  Decimal coercion on every USD cell; firm-portfolio audience
  contract is documented and enforced (top-of-file).
- `src/recupero/reports/subpoena_renderer.py` filename hardening
  (length cap + hash-suffix dedup + per-target collision suffix) is
  appropriate for Windows MAX_PATH and Linux 255-byte component
  limits.
- `src/recupero/portal/intake.py` `create_case_from_intake` —
  UniqueViolation retry loop on `case_number` is correct;
  `case_number` prefix `RCP-INTAKE-YYYY-` is 8 hex per year,
  birthday-paradox safe to ~100k cases/year.
