import Link from "next/link";
import { Brand } from "@/components/Brand";

/** Public marketing chrome for the Academy (nav + aurora background + footer). */
export default function AcademyLayout({ children }: { children: React.ReactNode }) {
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

      {children}

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="col">
            <Brand style={{ marginBottom: 14 }} />
            <p>Crypto asset tracing &amp; recovery for investigators, law firms, and exchanges.</p>
          </div>
          <div className="col">
            <h4>Academy</h4>
            <Link href="/academy">All articles</Link>
            <Link href="/">Platform</Link>
          </div>
          <div className="col">
            <h4>Company</h4>
            <a href="mailto:hello@recupero.io">Contact</a>
            <Link href="/signup">Get started</Link>
          </div>
        </div>
        <div className="footer-bottom">© {new Date().getFullYear()} Recupero. All rights reserved.</div>
      </footer>
    </main>
  );
}
