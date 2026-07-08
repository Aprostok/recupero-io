"use client";

import { useEffect, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Brand } from "@/components/Brand";

/** Public marketing landing page. Signed-in users are sent to the dashboard. */
export default function Home() {
  const { token, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && token) router.replace("/dashboard");
  }, [ready, token, router]);

  return (
    <main className="marketing">
      <nav className="landing-nav">
        <Brand />
        <span className="spacer" />
        <div className="nav-links">
          <a href="#platform">Platform</a>
          <a href="#how">How it works</a>
          <a href="#insights">Insights</a>
          <Link href="/login">Sign in</Link>
        </div>
        <Link
          href="/signup"
          className="cta primary"
          style={{ padding: "9px 16px", fontSize: 14 }}
        >
          Get started
        </Link>
      </nav>

      <header className="hero">
        <div className="hero-copy">
          <span className="eyebrow">
            <span className="dot" />
            Multi-chain forensic tracing &amp; recovery
          </span>
          <h1>
            Follow the money.
            <br />
            <span className="grad">Freeze it. Recover it.</span>
          </h1>
          <p className="lead">
            Recupero traces stolen crypto across every major chain, screens
            counterparties against live sanctions data, and produces the freeze
            requests and litigation artifacts recovery teams need —
            evidence-grade, from seed address to cash-out.
          </p>
          <div className="cta-row">
            <Link href="/signup" className="cta primary">
              Start tracing
            </Link>
            <Link href="/login" className="cta secondary">
              Sign in
            </Link>
          </div>
        </div>
        <div className="hero-visual">
          <div className="glass">
            <TraceGraphMock />
          </div>
        </div>
      </header>

      <section className="trust-strip">
        <div className="label">Built for the people who recover stolen funds</div>
        <div className="trust-logos">
          <span className="tl">
            <DotMark /> Investigators
          </span>
          <span className="tl">
            <DotMark /> Law firms
          </span>
          <span className="tl">
            <DotMark /> Exchanges
          </span>
          <span className="tl">
            <DotMark /> Insurers
          </span>
          <span className="tl">
            <DotMark /> Law enforcement
          </span>
        </div>
      </section>

      <section className="section" id="platform">
        <div className="section-head">
          <span className="kicker">The platform</span>
          <h2>Everything an asset-recovery investigation needs</h2>
          <p>
            One workspace for tracing, attribution, screening, and the paperwork
            that turns a trace into a recovery.
          </p>
        </div>
        <div className="feature-grid">
          {FEATURES.map((f) => (
            <article className="feature-card" key={f.title}>
              <div className="icon">{f.icon}</div>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section" id="how">
        <div className="section-head">
          <span className="kicker">How it works</span>
          <h2>From seed address to freeze packet</h2>
          <p>Four steps, fully documented and evidence-grade at every hop.</p>
        </div>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div className="step" key={s.title}>
              <div className="n">{i + 1}</div>
              <h4>{s.title}</h4>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="stats-band">
        <div className="stats-inner">
          <div className="stat">
            <div className="metric">10+</div>
            <div className="label">Chains traced end-to-end</div>
          </div>
          <div className="stat">
            <div className="metric">Live</div>
            <div className="label">OFAC &amp; sanctions screening</div>
          </div>
          <div className="stat">
            <div className="metric">Court-ready</div>
            <div className="label">Signed custody &amp; exhibits</div>
          </div>
          <div className="stat">
            <div className="metric">Zero</div>
            <div className="label">Fabricated attributions</div>
          </div>
        </div>
      </section>

      <section className="section" id="insights">
        <div className="section-head">
          <span className="kicker">Insights</span>
          <h2>Field notes from the recovery frontline</h2>
          <p>How illicit funds move — and how investigators catch up.</p>
        </div>
        <div className="insight-grid">
          {INSIGHTS.map((p, i) => (
            <a className="insight-card" key={p.title} href="#insights">
              <div className={`thumb ${["", "b", "c"][i]}`} />
              <div className="body">
                <div className="meta">{p.meta}</div>
                <h4>{p.title}</h4>
              </div>
            </a>
          ))}
        </div>
      </section>

      <section className="cta-band">
        <h2>Turn a stolen-funds trail into a recovery</h2>
        <p>Submit a seed address and get a full trace, risk profile, and freeze packet.</p>
        <div className="cta-row">
          <Link href="/signup" className="cta primary">
            Create an account
          </Link>
          <Link href="/login" className="cta secondary">
            Sign in
          </Link>
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="col">
            <Brand style={{ marginBottom: 14 }} />
            <p>
              Crypto asset tracing &amp; recovery for investigators, law firms,
              and exchanges.
            </p>
          </div>
          <div className="col">
            <h4>Platform</h4>
            <a href="#platform">Tracing</a>
            <a href="#platform">Screening</a>
            <a href="#platform">Recovery artifacts</a>
          </div>
          <div className="col">
            <h4>Resources</h4>
            <a href="#insights">Insights</a>
            <Link href="/login">Sign in</Link>
            <Link href="/signup">Get started</Link>
          </div>
          <div className="col">
            <h4>Company</h4>
            <a href="#how">How it works</a>
            <a href="mailto:hello@recupero.io">Contact</a>
          </div>
        </div>
        <div className="footer-bottom">
          © {new Date().getFullYear()} Recupero. All rights reserved.
        </div>
      </footer>
    </main>
  );
}

/* ─────────────────────────── content ─────────────────────────── */

type Feature = { title: string; body: string; icon: ReactNode };

const FEATURES: Feature[] = [
  {
    title: "Multi-chain tracing",
    body: "Follow stolen funds across Ethereum, L2s, Bitcoin, Solana, Tron, TON, Cosmos, Sui, Aptos and more — through swaps, bridges, and peels.",
    icon: <IconRoute />,
  },
  {
    title: "Sanctions & risk screening",
    body: "Screen any address against live OFAC and OpenSanctions data plus known mixers, exchanges, and bad-actor labels — in real time.",
    icon: <IconShield />,
  },
  {
    title: "Address-poisoning detection",
    body: "Automatically flags spoofed look-alike addresses and airdrop-spam so a trace never follows a poisoned decoy.",
    icon: <IconTarget />,
  },
  {
    title: "Freeze & litigation artifacts",
    body: "Generate exchange freeze requests, SAR/STR drafts, MLAT and 314(b) packets, and signed-custody exhibit packs.",
    icon: <IconDoc />,
  },
  {
    title: "Counterparty & exposure analysis",
    body: "See who an address transacts with, direct exposure to sanctioned entities, and where the funds ultimately cash out.",
    icon: <IconNetwork />,
  },
  {
    title: "Mixer demixing leads",
    body: "Surface candidate withdrawal leads from mixer deposits — always low-confidence, never fabricated, ready for investigator review.",
    icon: <IconShuffle />,
  },
];

const STEPS: { title: string; body: string }[] = [
  { title: "Seed the case", body: "Paste a victim or theft address. Recupero pulls transfers across every supported chain." },
  { title: "Trace & cluster", body: "Follow the largest flows through swaps, bridges and peels; cluster addresses by behavior." },
  { title: "Screen & attribute", body: "Score every hop against live sanctions data, mixers, and known entities." },
  { title: "Package for recovery", body: "Export freeze letters, SAR/STR drafts, and a signed, court-ready exhibit pack." },
];

const INSIGHTS: { title: string; meta: string }[] = [
  { title: "How peel chains launder large thefts — and how to follow them", meta: "Tracing · 6 min read" },
  { title: "Reading a mixer: what withdrawal timing tells you", meta: "Demixing · 5 min read" },
  { title: "Sibling and shadow addresses in address-poisoning scams", meta: "Screening · 4 min read" },
];

/* ─────────────────────────── graphics ─────────────────────────── */

/** Abstract product visual: a mini fund-trace graph with risk coloring. */
function TraceGraphMock() {
  return (
    <svg viewBox="0 0 560 360" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Fund trace preview">
      <rect width="560" height="360" rx="12" fill="#0b1120" />
      {/* header bar */}
      <rect x="0" y="0" width="560" height="42" rx="12" fill="#0e1526" />
      <circle cx="22" cy="21" r="4" fill="#ff5d6c" />
      <circle cx="38" cy="21" r="4" fill="#ffbe4d" />
      <circle cx="54" cy="21" r="4" fill="#35d29a" />
      <rect x="80" y="15" width="150" height="12" rx="6" fill="#1b2438" />
      <rect x="440" y="13" width="96" height="16" rx="8" fill="rgba(255,93,108,.16)" stroke="rgba(255,93,108,.5)" />
      <text x="488" y="25" textAnchor="middle" fill="#ff8f99" fontFamily="Inter, sans-serif" fontSize="10" fontWeight="600">HIGH RISK</text>
      {/* edges */}
      <g stroke="#3d7bff" strokeWidth="2.5" fill="none" opacity="0.85">
        <path d="M96 150 C 170 150, 170 110, 236 110" />
        <path d="M96 150 C 170 150, 170 210, 236 210" />
        <path d="M296 110 C 360 110, 360 150, 424 150" />
        <path d="M296 210 C 360 210, 360 160, 424 150" />
      </g>
      {/* nodes */}
      <g fontFamily="Inter, sans-serif" fontSize="11" fontWeight="600">
        <circle cx="80" cy="150" r="20" fill="#132038" stroke="#3d7bff" strokeWidth="2" />
        <text x="80" y="185" textAnchor="middle" fill="#9aa6be" fontSize="10">Seed</text>
        <circle cx="266" cy="110" r="18" fill="#132038" stroke="#588fff" strokeWidth="2" />
        <circle cx="266" cy="210" r="18" fill="#132038" stroke="#588fff" strokeWidth="2" />
        <circle cx="440" cy="150" r="22" fill="rgba(255,93,108,.14)" stroke="#ff5d6c" strokeWidth="2.5" />
        <text x="440" y="188" textAnchor="middle" fill="#ff8f99" fontSize="10">Mixer</text>
      </g>
      {/* value chips */}
      <g fontFamily="Inter, sans-serif" fontSize="10" fontWeight="600">
        <rect x="150" y="86" width="60" height="18" rx="9" fill="#0e1526" stroke="#1b2438" />
        <text x="180" y="99" textAnchor="middle" fill="#c7d0e0">412 ETH</text>
        <rect x="150" y="196" width="60" height="18" rx="9" fill="#0e1526" stroke="#1b2438" />
        <text x="180" y="209" textAnchor="middle" fill="#c7d0e0">188 ETH</text>
      </g>
      {/* footer legend */}
      <rect x="16" y="300" width="528" height="44" rx="10" fill="#0e1526" />
      <circle cx="40" cy="322" r="5" fill="#3d7bff" />
      <text x="54" y="326" fill="#9aa6be" fontFamily="Inter, sans-serif" fontSize="11">Traced flow</text>
      <circle cx="170" cy="322" r="5" fill="#ff5d6c" />
      <text x="184" y="326" fill="#9aa6be" fontFamily="Inter, sans-serif" fontSize="11">Sanctioned / mixer</text>
      <text x="528" y="326" textAnchor="end" fill="#64708a" fontFamily="Inter, sans-serif" fontSize="11">6 hops · 3 chains</text>
    </svg>
  );
}

function DotMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden>
      <rect width="16" height="16" rx="5" fill="currentColor" opacity="0.18" />
      <circle cx="8" cy="8" r="3" fill="currentColor" />
    </svg>
  );
}

/* ── Inline monochrome line icons (currentColor) ── */
const svgProps = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function IconRoute() {
  return (
    <svg {...svgProps}>
      <circle cx="6" cy="19" r="2.5" />
      <circle cx="18" cy="5" r="2.5" />
      <path d="M8.5 19H15a4 4 0 0 0 0-8H9a4 4 0 0 1 0-8h6.5" />
    </svg>
  );
}
function IconShield() {
  return (
    <svg {...svgProps}>
      <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}
function IconTarget() {
  return (
    <svg {...svgProps}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="12" cy="12" r="0.5" />
    </svg>
  );
}
function IconDoc() {
  return (
    <svg {...svgProps}>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </svg>
  );
}
function IconNetwork() {
  return (
    <svg {...svgProps}>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="18" r="2.5" />
      <circle cx="19" cy="18" r="2.5" />
      <path d="M10.5 7L6.5 16M13.5 7l4 9M7.5 18h9" />
    </svg>
  );
}
function IconShuffle() {
  return (
    <svg {...svgProps}>
      <path d="M4 7h3l10 10h3M4 17h3l3-3M14 10l3-3h3M18 4l3 3-3 3M18 14l3 3-3 3" />
    </svg>
  );
}
