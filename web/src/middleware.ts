import { NextRequest, NextResponse } from "next/server";

/**
 * OPTIONAL site-wide preview gate.
 *
 * Set `PREVIEW_PASSWORD` (server-side env var, NOT `NEXT_PUBLIC_*`) to put the
 * whole site behind HTTP Basic auth, so a link can be shared for review without
 * being public. Leave it UNSET — the default — and the site is open.
 *
 * Why this changed: the password was the hardcoded literal `"preview"` with the
 * gate ALWAYS on. That is a launch blocker — every real customer (and the Stripe
 * checkout return hop) got a 401 prompt — and the "secret" was public in the
 * repo. Behaviour now: no env var → no gate.
 */
const PREVIEW_PASSWORD = process.env.PREVIEW_PASSWORD ?? "";

/** Length-then-constant-time compare so the gate leaks no timing signal. */
function passwordMatches(candidate: string, expected: string): boolean {
  if (candidate.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i += 1) {
    diff |= candidate.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

export function middleware(req: NextRequest) {
  // Gate disabled (no password configured) → serve everything.
  if (!PREVIEW_PASSWORD) return NextResponse.next();

  const header = req.headers.get("authorization") ?? "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice("Basic ".length));
      const sep = decoded.indexOf(":");
      const password = sep === -1 ? decoded : decoded.slice(sep + 1);
      if (passwordMatches(password, PREVIEW_PASSWORD)) {
        return NextResponse.next();
      }
    } catch {
      // fall through to 401
    }
  }
  return new NextResponse("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Recupero preview", charset="UTF-8"',
    },
  });
}

// Gate every route except Next's static asset pipeline (which the browser
// re-requests with the cached credentials anyway once the user is in).
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
