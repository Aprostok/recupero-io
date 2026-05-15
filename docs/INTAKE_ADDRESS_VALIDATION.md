# Intake address validation spec

Spec for the client-side address validator that the intake form
should run before submission. Mirrors the worker-side fail-fast
guard introduced in commit `5069666` (`_is_obvious_placeholder_address`
in `src/recupero/worker/pipeline.py`).

## Why

The Hekla case (real intake submission, May 2026) was triggered with
seed_address `0x1234567890123456789012345678901234567890` — the user
filled in sequential digits to advance the form past the "wallet
address" field. The submission:

- Burned ~$0.15 of Anthropic budget
- Produced an empty case stuck in `REVIEW_REQUIRED` for 6+ days
- Required manual operator triage

The worker now catches this pattern at claim time and fails fast,
but blocking it client-side is the better UX: no round-trip to the
backend, no investigation row created, no operator notification at
all.

## Validation rules

These should run in addition to your existing format validation
(0x prefix, 40 hex chars, valid base58 for Solana, etc.). All
matches mean the form should **reject submission** with a clear
inline error: "This looks like a placeholder address — please paste
the actual on-chain wallet you want to trace."

For EVM (Ethereum, Arbitrum, Polygon, Base, BSC):

1. **All-same-character** — body is one repeating hex digit.
   Examples: `0x0...0`, `0xf...f`, `0x1...1`, `0xa...a`.

2. **Cycling-digit pattern** — body is a short pattern repeated to
   fill 40 chars. Cycle lengths to check: 2, 4, 5, 8, 10, 20.
   Examples:
   - `0x0101...0101` (2-char cycle, 20 reps)
   - `0xabcd...abcd` (4-char cycle, 10 reps)
   - `0x12345678...12345678` (8-char cycle, 5 reps)
   - `0x1234567890...1234567890` (10-char cycle, 4 reps — Hekla's
     case)

3. **Known test sentinels** — explicit hex strings operators
   sometimes paste from test fixtures:
   - `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
   - `0xcafebabecafebabecafebabecafebabecafebabe`

For Solana: out of scope for now — base58 addresses don't have the
same pattern profile and we haven't seen a placeholder Solana
submission yet. Add if/when we do.

## Reference implementation (TypeScript)

```typescript
/**
 * Returns true if the address looks like an intake-form placeholder
 * (repeating digits, cycling pattern, or known sentinel).
 *
 * Mirrors src/recupero/worker/pipeline.py:_is_obvious_placeholder_address.
 * If you change one, change the other — the worker has a fail-fast guard
 * that produces a clearer error message, but blocking client-side avoids
 * the round-trip + investigation row creation entirely.
 *
 * Only flags addresses whose ENTIRE body matches a placeholder pattern.
 * Addresses that contain "1234" or "dead" as a substring are NOT flagged
 * — real addresses frequently contain these by chance.
 */
export function isObviousPlaceholderAddress(addr: string): boolean {
  if (!addr || !addr.startsWith("0x")) return false;
  const body = addr.slice(2).toLowerCase();
  if (body.length !== 40) return false;

  // All-same-character (0x000...000, 0xfff...fff, etc.)
  if (new Set(body).size === 1) return true;

  // Cycling-digit pattern
  for (const cycleLen of [2, 4, 5, 8, 10, 20]) {
    if (body.length % cycleLen !== 0) continue;
    const first = body.slice(0, cycleLen);
    const reps = body.length / cycleLen;
    if (body === first.repeat(reps)) return true;
  }

  // Known test sentinels
  const sentinels = new Set([
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabecafebabe",
  ]);
  if (sentinels.has(body)) return true;

  return false;
}
```

### Validator integration example

```typescript
// In your form schema (zod / yup / vanilla)
const seedAddressSchema = z.string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "Must be a 0x-prefixed 40-character hex address")
  .refine(
    addr => !isObviousPlaceholderAddress(addr),
    {
      message: "This looks like a placeholder address — please paste the actual wallet you want to trace.",
    }
  );
```

## Test fixtures

The worker has 16 unit tests covering these patterns. Mirror them
client-side to keep the two implementations in sync:

```typescript
// Should reject (return true from isObviousPlaceholderAddress):
const PLACEHOLDERS = [
  "0x1234567890123456789012345678901234567890",  // Hekla (10-char cycle)
  "0x0000000000000000000000000000000000000000",  // zero address
  "0xffffffffffffffffffffffffffffffffffffffff",  // max address
  "0x1111111111111111111111111111111111111111",  // single-digit fill
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // letter fill
  "0x0101010101010101010101010101010101010101",  // 2-char cycle
  "0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",  // 4-char cycle
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  // sentinel
  "0xcafebabecafebabecafebabecafebabecafebabe",  // sentinel
];

// Should accept (return false):
const REAL_ADDRESSES = [
  "0x8E3b200f356724299643402148a25FD4B852Bd53",  // Test wallet
  "0x28C6c06298d514Db089934071355E5743bf21d60",  // Binance 14 hot wallet
  "0x2b22d1A731175a04142fE1bC3c5bbb2B2d813D2F",  // arbitrary real
];

// Edge cases that should NOT be flagged (defensive):
const NOT_FLAGGED = [
  "0xDeAd0fbCe1234567A89B2Cdef5678901234567890",  // contains "Dead" + "1234567890" as substrings but not full-body pattern
];
```

## Server-side worker behavior

If a placeholder somehow slips past the form, the worker still
catches it. The investigation gets marked `failed` immediately with
`error_stage='setup'` and an error_message of the form:

```
seed_address '0x1234...7890' looks like an intake placeholder
(sequential-digit pattern). Verify the address with the client
and re-trigger the investigation with the real wallet.
```

The admin UI's detail endpoint will surface this via the standard
`error_stage` / `error_message` fields — no special-case handling
needed.

## When to update both implementations

If you add a new placeholder pattern client-side, update the worker
side too (and vice versa). Keep the test fixtures in sync. The worker
unit tests live in `tests/test_placeholder_address_guard.py`.
