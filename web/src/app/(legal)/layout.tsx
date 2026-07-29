import Link from "next/link";
import { Brand } from "@/components/Brand";

/**
 * Shared public chrome for the standalone content pages (privacy, terms,
 * contact). A route group, so the URLs stay flat: /privacy, /terms, /contact.
 */
export default function LegalLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="marketing">
      <div className="aurora" aria-hidden>
        <span className="a1" />
        <span className="a2" />
        <span className="a3" />
      </div>
      <div className="grid-bg" aria-hidden />

      <nav className="landing-nav">
        <Brand />
        <span className="spacer" />
        <div className="nav-links">
          <Link href="/">Home</Link>
          <Link href="/academy">Academy</Link>
          <Link href="/login">Sign in</Link>
        </div>
        <Link href="/signup" className="cta primary" style={{ padding: "9px 18px", fontSize: 14 }}>
          Get started
        </Link>
      </nav>

      <article className="section" style={{ maxWidth: 760 }}>
        {children}
      </article>

      <footer className="site-footer">
        <div className="footer-bottom">
          <Link href="/privacy">Privacy</Link> · <Link href="/terms">Terms</Link> ·{" "}
          <Link href="/contact">Contact</Link> · © 2026 Recupero. All rights reserved.
        </div>
      </footer>
    </main>
  );
}
