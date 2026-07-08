import { NextRequest, NextResponse } from "next/server";

// Site-wide preview gate. Any visitor must present HTTP Basic credentials
// whose password is `preview` (username is ignored). This protects the whole
// site — landing, academy, and dashboard — behind one shared password so a
// link can be shared for review without being fully public. Remove this file
// (and rebuild) to lift the gate.
const PREVIEW_PASSWORD = "preview";

export function middleware(req: NextRequest) {
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
