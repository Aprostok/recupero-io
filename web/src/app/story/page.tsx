import type { ReactNode } from "react";
import Link from "next/link";
import { Brand } from "@/components/Brand";

export const metadata = {
  title: "Our Story — Recupero",
  description:
    "Recupero didn't start as a product. It started as one of the worst days of our lives — and the long climb out of it.",
};

type Chapter = { step: string; title: string; body: ReactNode; pull?: string };

const CHAPTERS: Chapter[] = [
  {
    step: "The day it happened",
    title: "One moment there — the next, gone",
    body: (
      <>
        A few years ago, Recupero was hit. Not a scare, not a near-miss — a real hack that
        drained <strong>millions of dollars</strong> out of our accounts before we fully
        understood what was happening. One moment the funds were there. The next, they were
        moving through wallets we&rsquo;d never seen, splitting and scattering across chains.
      </>
    ),
  },
  {
    step: "The worst part",
    title: "Everyone said it was gone",
    body: (
      <>
        We did what anyone does. We asked for help. And nearly everyone told us the same thing:{" "}
        <strong>crypto theft is final.</strong> Once it&rsquo;s moved, it&rsquo;s gone. Chalk it
        up to a hard lesson and move on.
      </>
    ),
    pull:
      "We genuinely believed we'd never see any of it again. That feeling — that helplessness — is the reason Recupero exists.",
  },
  {
    step: "We refused",
    title: "So we started tracing it ourselves",
    body: (
      <>
        We couldn&rsquo;t accept it. We followed the money by hand — hop by hop, through the
        splits and the mixers and the bridges — building the picture of where our funds had
        actually gone. It was slow, exhausting work. But the trail was <strong>there</strong>,
        if you were willing to follow it far enough.
      </>
    ),
  },
  {
    step: "The turning point",
    title: "We brought it to the authorities",
    body: (
      <>
        Evidence in hand, we worked with <strong>U.S. authorities</strong> to act on it.
        Together we got the funds <strong>frozen</strong> before they could disappear for good —
        and then, against everything we&rsquo;d been told, we got them <strong>back</strong>.
      </>
    ),
  },
  {
    step: "What we learned",
    title: "“Unrecoverable” usually just means “no one traced it”",
    body: (
      <>
        Recovery was possible the whole time. What stood in the way wasn&rsquo;t the blockchain —
        it was the tracing, the evidence, and knowing how to work with the people who can freeze
        and return funds. We&rsquo;d done it the hardest way imaginable. We decided no one else
        should have to.
      </>
    ),
  },
];

const NODE = {
  position: "absolute" as const,
  left: 3,
  top: 6,
  width: 13,
  height: 13,
  borderRadius: "50%",
  background: "var(--bg)",
  border: "2px solid var(--accent)",
  boxShadow: "0 0 0 4px var(--accent-soft)",
};

export default function StoryPage() {
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
          <Link href="/#platform">Platform</Link>
          <Link href="/#how">How it works</Link>
          <Link href="/academy">Academy</Link>
          <Link href="/login">Sign in</Link>
        </div>
        <Link href="/signup" className="cta primary" style={{ padding: "9px 18px", fontSize: 14 }}>
          Get started
        </Link>
      </nav>

      <article style={{ maxWidth: 820, margin: "0 auto", padding: "0 24px" }}>
        <header style={{ padding: "48px 0 8px", textAlign: "center" }}>
          <span className="eyebrow">
            <span className="dot" />
            Our Story
          </span>
          <h1
            style={{
              fontSize: "clamp(2.2rem, 6vw, 3.6rem)",
              fontWeight: 800,
              letterSpacing: "-0.035em",
              lineHeight: 1.05,
              margin: "18px 0 18px",
            }}
          >
            <span className="grad">Millions gone in seconds.</span>
            <br />
            Then we found the way back.
          </h1>
          <p
            style={{
              fontSize: "1.16rem",
              lineHeight: 1.6,
              color: "var(--muted)",
              maxWidth: "62ch",
              margin: "0 auto",
            }}
          >
            Recupero didn&rsquo;t start as a product. It started as one of the worst days of our
            lives — and the long climb out of it. This is why we do what we do.
          </p>
        </header>

        <section style={{ position: "relative", padding: "40px 0 8px", marginLeft: 8 }}>
          <span
            aria-hidden
            style={{
              position: "absolute",
              left: 9,
              top: 46,
              bottom: 40,
              width: 2,
              background: "linear-gradient(180deg, var(--accent), var(--border-strong) 85%)",
            }}
          />
          {CHAPTERS.map((c) => (
            <div key={c.title} style={{ position: "relative", paddingLeft: 40, paddingBottom: 36 }}>
              <span aria-hidden style={NODE} />
              <div
                className="kicker"
                style={{ color: "var(--muted)", marginBottom: 6, fontSize: 11 }}
              >
                {c.step}
              </div>
              <h2
                style={{
                  fontSize: "1.42rem",
                  fontWeight: 700,
                  letterSpacing: "-0.02em",
                  margin: "0 0 12px",
                }}
              >
                {c.title}
              </h2>
              <p style={{ color: "var(--muted)", lineHeight: 1.72, margin: 0, fontSize: "1.02rem" }}>
                {c.body}
              </p>
              {c.pull && (
                <blockquote
                  className="glass"
                  style={{
                    margin: "18px 0 4px",
                    padding: "18px 20px",
                    borderRadius: "var(--r-lg)",
                    fontSize: "1.14rem",
                    lineHeight: 1.5,
                    color: "var(--text)",
                    fontWeight: 500,
                  }}
                >
                  &ldquo;{c.pull}&rdquo;
                </blockquote>
              )}
            </div>
          ))}
        </section>

        <section className="cta-band glass" style={{ margin: "24px 0 64px" }}>
          <h2 style={{ fontSize: "clamp(1.6rem, 3.4vw, 2.2rem)" }}>Why we&rsquo;re here</h2>
          <p>
            We built Recupero to be the help we didn&rsquo;t have — to trace, freeze, and recover
            stolen funds, and to stand with people on what may be one of the worst days of their
            lives. If it happened to you, it isn&rsquo;t necessarily over. Let us help you find
            your way back too.
          </p>
          <div className="cta-row">
            <Link href="/signup" className="cta primary">
              Start an investigation
            </Link>
            <Link href="/academy" className="cta secondary">
              Read the Academy
            </Link>
          </div>
        </section>
      </article>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="col">
            <Brand style={{ marginBottom: 14 }} />
            <p>Crypto asset tracing &amp; recovery for investigators, law firms, and exchanges.</p>
          </div>
          <div className="col">
            <h4>Platform</h4>
            <Link href="/#platform">Tracing</Link>
            <Link href="/#platform">Screening</Link>
            <Link href="/#platform">Recovery artifacts</Link>
          </div>
          <div className="col">
            <h4>Resources</h4>
            <Link href="/academy">Academy</Link>
            <Link href="/login">Sign in</Link>
            <Link href="/signup">Get started</Link>
          </div>
          <div className="col">
            <h4>Company</h4>
            <Link href="/story">Our Story</Link>
            <Link href="/#how">How it works</Link>
            <a href="mailto:hello@recupero.io">Contact</a>
          </div>
        </div>
        <div className="footer-bottom">© {new Date().getFullYear()} Recupero. All rights reserved.</div>
      </footer>
    </main>
  );
}
