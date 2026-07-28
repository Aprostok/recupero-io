import { NextRequest, NextResponse } from "next/server";

// Site-wide preview gate. When PREVIEW_PASSWORD is set at build time, every
// route (landing, academy, dashboard) requires HTTP Basic credentials whose
// password matches it; the username is ignored. This lets a link be shared for
// review without the site being fully public.
//
// The password MUST come from the environment, never a literal in this file —
// this repository is public, so a committed password protects nothing.
//
// Next inlines `process.env` for edge middleware at BUILD time, so this has to
// be set in the build environment (same constraint as NEXT_PUBLIC_API_BASE_URL),
// not flipped afterwards in a dashboard.
//
// To lift the gate at launch: build with PREVIEW_PASSWORD unset.
const PREVIEW_PASSWORD = process.env.PREVIEW_PASSWORD ?? "";

export function middleware(req: NextRequest) {
  // No password configured => gate disabled. This is the launch configuration.
  if (!PREVIEW_PASSWORD) {
    return NextResponse.next();
  }
  const header = req.headers.get("authorization") ?? "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice("Basic ".length));
      const sep = decoded.indexOf(":");
      const password = sep === -1 ? decoded : decoded.slice(sep + 1);
      if (password === PREVIEW_PASSWORD) {
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
