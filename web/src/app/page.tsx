"use client";

import { useEffect, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Brand } from "@/components/Brand";
import { ARTICLES } from "@/content/academy";

/** Public marketing landing page. Signed-in users are sent to the dashboard. */
export default function Home() {
  const { token, ready } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && token) router.replace("/dashboard");
  }, [ready, token, router]);

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
          <a href="#platform">Platform</a>
          <a href="#how">How it works</a>
          <Link href="/story">Our Story</Link>
          <Link href="/academy">Academy</Link>
          <Link href="/login">Sign in</Link>
        </div>
        <Link href="/signup" className="cta primary" style={{ padding: "9px 18px", fontSize: 14 }}>
          Get started
        </Link>
      </nav>

      <header className="hero">
        <span className="eyebrow">
          <span className="dot" />
          AI-assisted crypto asset recovery
        </span>
        <h1>
          Trace stolen crypto.
          <br />
          <span className="grad">Freeze it. Recover it.</span>
        </h1>
        <p className="lead">
          Recupero follows illicit funds across every major chain, screens each hop
          against live sanctions data, and turns the trail into court-ready freeze
          requests — one workspace, from seed address to cash-out.
        </p>
        <div className="cta-row">
          <Link href="/signup" className="cta primary">
            Start tracing
          </Link>
          <Link href="/login" className="cta secondary">
            Sign in
          </Link>
        </div>
        <div className="cta-note">No card required · 10+ chains · evidence-grade output</div>
      </header>

      {/* Product bento panel */}
      <div className="hero-panel glass">
        <div className="hero-bento">
          <div className="mini span2">
            <div className="cap">Live trace</div>
            <MiniTrace />
          </div>
          <div className="mini">
            <div className="cap">Recoverable</div>
            <MiniDonut pct={68} />
          </div>
          <div className="mini">
            <div className="cap">Risk verdict</div>
            <span className="chip risk">● High</span>
            <div style={{ marginTop: 10 }}>
              <MiniBars />
            </div>
          </div>
          <div className="mini wide">
            <div className="cap">Screen API</div>
            <div className="code">
              <span className="c"># POST /v2/screen</span>
              {"\n"}
              <span className="k">curl</span> -s api.recupero.io/v2/screen \{"\n"}
              {"  "}-d <span className="s">{'{"address":"0x9f2…a1"}'}</span>
              {"\n"}
              <span className="c"># → verdict: sanctioned · mixer exposure</span>
            </div>
          </div>
        </div>
      </div>

      {/* Marquee */}
      <div className="marquee">
        <div className="mlabel">Trusted across the recovery workflow</div>
        <div className="marquee-track">
          {[...TRUST, ...TRUST].map((t, i) => (
            <span className="mq-item" key={i}>
              <DotMark />
              {t}
            </span>
          ))}
        </div>
      </div>

      {/* Bento features */}
      <section className="section" id="platform">
        <div className="section-head">
          <span className="kicker">The platform</span>
          <h2>An entire investigation, in one workspace</h2>
          <p>Tracing, attribution, screening, and the paperwork that turns a trace into a recovery.</p>
        </div>
        <div className="bento">
          <article className="b glass wide">
            <div className="icon"><IconRoute /></div>
            <h3>Multi-chain tracing</h3>
            <p>
              Follow funds across Ethereum, L2s, Bitcoin, Solana, Tron, TON, Cosmos,
              Sui and Aptos — through swaps, bridges, and peel chains.
            </p>
            <div className="mock"><MiniTrace flat /></div>
          </article>

          <article className="b glass wide">
            <div className="icon"><IconShield /></div>
            <h3>Sanctions &amp; risk screening</h3>
            <p>
              Score every address against live OFAC and OpenSanctions data plus known
              mixers, exchanges, and bad-actor labels — in real time.
            </p>
            <div className="mock"><MiniBars wide /></div>
          </article>

          <article className="b glass">
            <div className="icon"><IconTarget /></div>
            <h3>Address-poisoning detection</h3>
            <p>Flags spoofed look-alike addresses and airdrop-spam so a trace never follows a decoy.</p>
            <div className="mock"><MiniPoison /></div>
          </article>

          <article className="b glass">
            <div className="icon"><IconDoc /></div>
            <h3>Freeze &amp; litigation artifacts</h3>
            <p>Exchange freeze requests, SAR/STR drafts, MLAT &amp; 314(b) packets, signed exhibit packs.</p>
            <div className="mock"><MiniArtifacts /></div>
          </article>

          <article className="b glass">
            <div className="icon"><IconNetwork /></div>
            <h3>Counterparty &amp; exposure</h3>
            <p>See who an address transacts with, sanctioned exposure, and where funds cash out.</p>
            <div className="mock"><MiniArea /></div>
          </article>

          <article className="b glass wide">
            <div className="icon"><IconShuffle /></div>
            <h3>Mixer demixing leads</h3>
            <p>
              Surface candidate withdrawal leads from mixer deposits — always
              low-confidence, never fabricated, ready for investigator review.
            </p>
            <div className="mock"><MiniMatch /></div>
          </article>

          <article className="b glass wide" style={{ justifyContent: "center", alignItems: "flex-start" }}>
            <h3 style={{ fontSize: "1.4rem" }}>See it on your own case</h3>
            <p style={{ marginBottom: 16 }}>Paste a seed address and get a full trace in minutes.</p>
            <Link href="/signup" className="cta primary">Start tracing</Link>
          </article>
        </div>
      </section>

      {/* Stats */}
      <section className="stats-band">
        <div className="stats-inner glass">
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

      {/* How it works */}
      <section className="section" id="how">
        <div className="section-head">
          <span className="kicker">How it works</span>
          <h2>From seed address to freeze packet</h2>
          <p>Four steps, documented and evidence-grade at every hop.</p>
        </div>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div className="step glass" key={s.title}>
              <div className="n">{i + 1}</div>
              <h4>{s.title}</h4>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Insights / Academy */}
      <section className="section" id="insights">
        <div className="section-head">
          <span className="kicker">Academy</span>
          <h2>Field notes from the recovery frontline</h2>
          <p>How illicit funds move — and how investigators, and everyday users, catch up.</p>
        </div>
        <div className="insight-grid">
          {ARTICLES.slice(0, 3).map((a, i) => (
            <Link className="insight-card glass" key={a.slug} href={`/academy/${a.slug}`}>
              <div className={`thumb ${["", "b", "c"][i]}`} />
              <div className="body">
                <div className="meta">{a.meta}</div>
                <h4>{a.title}</h4>
              </div>
            </Link>
          ))}
        </div>
        <div style={{ textAlign: "center", marginTop: 24 }}>
          <Link href="/academy" className="cta secondary">
            Browse the Academy
          </Link>
        </div>
      </section>

      {/* CTA */}
      <section className="section" style={{ paddingTop: 0 }}>
        <div className="cta-band glass">
          <h2>Turn a stolen-funds trail into a recovery</h2>
          <p>Submit a seed address and get a full trace, risk profile, and freeze packet.</p>
          <div className="cta-row">
            <Link href="/signup" className="cta primary">Create an account</Link>
            <Link href="/login" className="cta secondary">Sign in</Link>
          </div>
        </div>
      </section>

      <footer className="site-footer">
        <div className="footer-inner">
          <div className="col">
            <Brand style={{ marginBottom: 14 }} />
            <p>Crypto asset tracing &amp; recovery for investigators, law firms, and exchanges.</p>
          </div>
          <div className="col">
            <h4>Platform</h4>
            <a href="#platform">Tracing</a>
            <a href="#platform">Screening</a>
            <a href="#platform">Recovery artifacts</a>
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
            <a href="#how">How it works</a>
            <a href="mailto:hello@recupero.io">Contact</a>
          </div>
        </div>
        <div className="footer-bottom">© {new Date().getFullYear()} Recupero. All rights reserved.</div>
      </footer>
    </main>
  );
}

/* ─────────────────────────── content ─────────────────────────── */

const TRUST = ["Investigators", "Law firms", "Exchanges", "Insurers", "Law enforcement", "Recovery agents"];

const STEPS: { title: string; body: string }[] = [
  { title: "Seed the case", body: "Paste a victim or theft address. Recupero pulls transfers across every supported chain." },
  { title: "Trace & cluster", body: "Follow the largest flows through swaps, bridges and peels; cluster addresses by behavior." },
  { title: "Screen & attribute", body: "Score every hop against live sanctions data, mixers, and known entities." },
  { title: "Package for recovery", body: "Export freeze letters, SAR/STR drafts, and a signed, court-ready exhibit pack." },
];

/* ─────────────────────────── mini mockups ─────────────────────────── */

/* Arterial flow paths (also drawn as the visible wires) so the animated
   packets ride exactly along the edges. */
const FLOW_A = "M26 110 C 55 100, 60 60, 92 58 C 130 56, 145 52, 172 52 C 245 50, 275 46, 312 46";
const FLOW_B = "M26 110 C 55 110, 62 110, 92 112 C 130 113, 145 116, 172 118 C 220 120, 255 118, 286 118";
const FLOW_C = "M26 110 C 55 132, 62 168, 92 168 C 130 168, 150 172, 172 172 L232 176 L272 180 L312 182";

function Packet({ path, color, dur, begin }: { path: string; color: string; dur: number; begin: number }) {
  return (
    <circle r="3" fill={color} style={{ filter: `drop-shadow(0 0 4px ${color})` }}>
      <animateMotion dur={`${dur}s`} begin={`${begin}s`} repeatCount="indefinite" calcMode="linear">
        <mpath href={path} />
      </animateMotion>
      <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur={`${dur}s`} begin={`${begin}s`} repeatCount="indefinite" />
    </circle>
  );
}

function MiniTrace({ flat = false }: { flat?: boolean }) {
  const F = "Inter, sans-serif";
  return (
    <svg
      viewBox="0 0 420 220"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Live fund-flow trace with entity clustering: a victim seed address fanning through hops and a peel chain into a reachable exchange cluster, a bridge cluster, and a sanctioned mixer cluster, with value flowing along the edges"
      style={{ marginTop: flat ? 0 : 2 }}
    >
      <defs>
        <path id="rc-fa" d={FLOW_A} />
        <path id="rc-fb" d={FLOW_B} />
        <path id="rc-fc" d={FLOW_C} />
      </defs>

      {/* cluster hulls */}
      <ellipse cx="337" cy="50" rx="46" ry="34" fill="rgba(53,210,154,.06)" stroke="rgba(53,210,154,.3)" strokeWidth="1" strokeDasharray="3 3" />
      <ellipse cx="303" cy="124" rx="40" ry="27" fill="rgba(61,123,255,.06)" stroke="rgba(61,123,255,.32)" strokeWidth="1" strokeDasharray="3 3" />
      <ellipse cx="335" cy="185" rx="44" ry="28" fill="rgba(255,93,108,.06)" stroke="rgba(255,93,108,.38)" strokeWidth="1" strokeDasharray="3 3" />

      {/* arterial wires (visible) */}
      <g fill="none">
        <use href="#rc-fa" stroke="#3d7bff" strokeWidth="3" opacity="0.85" />
        <use href="#rc-fb" stroke="#3d7bff" strokeWidth="3.2" opacity="0.85" />
        <use href="#rc-fc" stroke="#ffbe4d" strokeWidth="2.4" opacity="0.85" />
      </g>
      {/* secondary + bridge cross-links */}
      <g fill="none" opacity="0.7">
        <path d="M172 52 C 240 50, 275 66, 312 68" stroke="#35d29a" strokeWidth="1.6" />
        <path d="M322 110 L332 72" stroke="#588fff" strokeWidth="1.4" />
        <path d="M305 140 L318 178" stroke="#ff5d6c" strokeWidth="2" />
      </g>
      {/* intra-cluster edges (thin) */}
      <g fill="none" opacity="0.5">
        <path d="M312 46 L350 34M312 46 L335 70M350 34 L372 56" stroke="#35d29a" strokeWidth="1" />
        <path d="M286 118 L322 110M286 118 L305 140" stroke="#588fff" strokeWidth="1" />
        <path d="M312 180 L352 172M312 180 L335 202" stroke="#ff5d6c" strokeWidth="1" />
      </g>

      {/* exchange cluster (reachable) */}
      <g fill="#0e2a22" stroke="#35d29a" strokeWidth="1.8">
        <circle cx="312" cy="46" r="8" />
        <circle cx="350" cy="34" r="6" />
        <circle cx="335" cy="70" r="6" />
        <circle cx="372" cy="56" r="5" />
      </g>
      {/* bridge cluster */}
      <g fill="#0f1b33" stroke="#588fff" strokeWidth="1.8">
        <circle cx="286" cy="118" r="8" />
        <circle cx="322" cy="110" r="6" />
        <circle cx="305" cy="140" r="6" />
      </g>
      {/* mixer cluster (sanctioned) */}
      <g fill="rgba(255,93,108,.16)" stroke="#ff5d6c" strokeWidth="2">
        <circle cx="312" cy="180" r="9" />
        <circle cx="352" cy="172" r="6" />
        <circle cx="335" cy="202" r="6" />
      </g>
      {/* pulsing ring on the sanctioned hub */}
      <circle cx="312" cy="180" r="9" fill="none" stroke="#ff5d6c" strokeWidth="2">
        <animate attributeName="r" values="9;22" dur="2.4s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.6;0" dur="2.4s" repeatCount="indefinite" />
      </circle>
      {/* peel-chain nodes (in transit) */}
      <g fill="#2a2410" stroke="#ffbe4d" strokeWidth="1.8">
        <circle cx="172" cy="172" r="6" />
        <circle cx="232" cy="176" r="6" />
        <circle cx="272" cy="180" r="6" />
      </g>
      {/* intermediaries + hops */}
      <g fill="#132038" stroke="#588fff" strokeWidth="2">
        <circle cx="92" cy="58" r="7" />
        <circle cx="92" cy="112" r="7" />
        <circle cx="92" cy="168" r="7" />
        <circle cx="172" cy="52" r="6" />
        <circle cx="172" cy="118" r="6" />
      </g>
      {/* seed */}
      <circle cx="26" cy="110" r="13" fill="#132038" stroke="#3d7bff" strokeWidth="2.4" />
      <circle cx="26" cy="110" r="3.4" fill="#7fa8ff" />

      {/* animated packets riding the arterials */}
      <Packet path="#rc-fa" color="#7fa8ff" dur={3.0} begin={0} />
      <Packet path="#rc-fa" color="#7fa8ff" dur={3.0} begin={1.5} />
      <Packet path="#rc-fb" color="#b39bff" dur={3.6} begin={0.6} />
      <Packet path="#rc-fc" color="#ff8f99" dur={3.2} begin={0} />
      <Packet path="#rc-fc" color="#ff8f99" dur={3.2} begin={1.6} />

      {/* value chip */}
      <g>
        <rect x="42" y="74" width="46" height="15" rx="7.5" fill="#0e1526" stroke="#1b2438" />
        <text x="65" y="84.5" textAnchor="middle" fill="#c7d0e0" fontFamily={F} fontSize="8.5" fontWeight="600">412 ETH</text>
      </g>

      {/* labels */}
      <text x="26" y="136" textAnchor="middle" fill="#8b97ad" fontFamily={F} fontSize="8.5">victim seed</text>
      <text x="337" y="12" textAnchor="middle" fill="#7fe0c0" fontFamily={F} fontSize="9" fontWeight="600">Exchange · reachable</text>
      <text x="303" y="160" textAnchor="middle" fill="#8fb0ff" fontFamily={F} fontSize="8.5" fontWeight="600">Bridge</text>
      <text x="335" y="218" textAnchor="middle" fill="#ff8f99" fontFamily={F} fontSize="9" fontWeight="600">Mixer · sanctioned</text>
    </svg>
  );
}

const FONT = "Inter, sans-serif";
const MONO = "ui-monospace, Menlo, Consolas, monospace";

/* Animated recoverability donut gauge */
function MiniDonut({ pct }: { pct: number }) {
  const R = 46;
  const C = 2 * Math.PI * R;
  const off = C * (1 - pct / 100);
  return (
    <svg viewBox="0 0 120 120" role="img" aria-label={`${pct}% of funds recoverable`} style={{ width: 92, height: 92, margin: "2px auto 0", display: "block" }}>
      <defs>
        <linearGradient id="rc-donut" x1="0" y1="0" x2="120" y2="120" gradientUnits="userSpaceOnUse">
          <stop stopColor="#3d7bff" />
          <stop offset="1" stopColor="#2fd6a0" />
        </linearGradient>
      </defs>
      <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="10" />
      <circle cx="60" cy="60" r={R} fill="none" stroke="url(#rc-donut)" strokeWidth="10" strokeLinecap="round" strokeDasharray={C} strokeDashoffset={off} transform="rotate(-90 60 60)">
        <animate attributeName="stroke-dashoffset" from={C} to={off} dur="1.2s" fill="freeze" calcMode="spline" keySplines="0.32 0.72 0 1" keyTimes="0;1" />
      </circle>
      <text x="60" y="68" textAnchor="middle" fill="#f4f7fd" fontFamily={FONT} fontSize="27" fontWeight="800">{pct}%</text>
    </svg>
  );
}

/* Address-poisoning scanner: a legit row + a flagged look-alike, with a sweep */
function MiniPoison() {
  return (
    <svg viewBox="0 0 260 78" role="img" aria-label="Address-poisoning scanner flagging a spoofed look-alike address" style={{ marginTop: 2 }}>
      <defs>
        <linearGradient id="rc-scan" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="rgba(125,168,255,0)" />
          <stop offset="0.5" stopColor="rgba(125,168,255,.28)" />
          <stop offset="1" stopColor="rgba(125,168,255,0)" />
        </linearGradient>
      </defs>
      <rect x="0" y="8" width="260" height="26" rx="7" fill="rgba(53,210,154,.07)" stroke="rgba(53,210,154,.28)" />
      <rect x="0" y="44" width="260" height="26" rx="7" fill="rgba(255,93,108,.09)" stroke="rgba(255,93,108,.4)" />
      <text x="12" y="25" fill="#c7d0e0" fontFamily={MONO} fontSize="12">0x9f2c··e7d4··8a1c3</text>
      <text x="12" y="61" fill="#c7d0e0" fontFamily={MONO} fontSize="12">
        0x9f2c··<tspan fill="#ff8f99" fontWeight="700">a4b1</tspan>··8a1c3
      </text>
      <circle cx="240" cy="21" r="7" fill="none" stroke="#35d29a" strokeWidth="1.6" />
      <path d="M236.5 21 l2.5 2.5 4-5" fill="none" stroke="#35d29a" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      <text x="248" y="60" textAnchor="end" fill="#ff8f99" fontFamily={FONT} fontSize="8.5" fontWeight="700">SPOOF</text>
      <rect x="-28" y="4" width="24" height="70" fill="url(#rc-scan)">
        <animate attributeName="x" from="-28" to="288" dur="2.6s" repeatCount="indefinite" />
      </rect>
    </svg>
  );
}

/* Litigation-artifact checklist that fills in */
function MiniArtifacts() {
  const items = ["Freeze letter", "SAR / STR draft", "Exhibit pack · SHA-256", "MLAT / 314(b) packet"];
  return (
    <svg viewBox="0 0 260 98" role="img" aria-label="Litigation artifacts generated for the case" style={{ marginTop: 2 }}>
      {items.map((t, i) => {
        const y = 8 + i * 23;
        return (
          <g key={t}>
            <rect x="0" y={y} width="260" height="18" rx="5" fill="rgba(255,255,255,.03)" stroke="rgba(255,255,255,.06)" />
            <circle cx="13" cy={y + 9} r="6.5" fill="rgba(53,210,154,.14)" stroke="#35d29a" strokeWidth="1.5" opacity="0">
              <animate attributeName="opacity" values="0;1" dur="0.35s" begin={`${0.2 + i * 0.4}s`} fill="freeze" />
            </circle>
            <path d={`M9.5 ${y + 9} l2.5 2.5 4.5-5`} fill="none" stroke="#35d29a" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" opacity="0">
              <animate attributeName="opacity" values="0;1" dur="0.3s" begin={`${0.35 + i * 0.4}s`} fill="freeze" />
            </path>
            <text x="28" y={y + 13} fill="#c7d0e0" fontFamily={FONT} fontSize="11">{t}</text>
          </g>
        );
      })}
    </svg>
  );
}

/* Sanctioned-exposure area chart with a draw-on line + travelling head */
function MiniArea() {
  const line = "M0 66 L40 58 L80 60 L120 40 L160 30 L200 34 L240 18";
  const area = `${line} L240 88 L0 88 Z`;
  return (
    <svg viewBox="0 0 240 92" role="img" aria-label="Sanctioned exposure rising across hops" style={{ marginTop: 2 }}>
      <defs>
        <linearGradient id="rc-area" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="rgba(61,123,255,.5)" />
          <stop offset="1" stopColor="rgba(61,123,255,0)" />
        </linearGradient>
      </defs>
      <line x1="0" y1="88" x2="240" y2="88" stroke="rgba(255,255,255,.08)" />
      <path d={area} fill="url(#rc-area)" opacity="0">
        <animate attributeName="opacity" values="0;1" dur="0.9s" begin="0.4s" fill="freeze" />
      </path>
      <path id="rc-aline" d={line} fill="none" stroke="#588fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" pathLength={1} strokeDasharray="1" strokeDashoffset="1">
        <animate attributeName="stroke-dashoffset" from="1" to="0" dur="1.1s" fill="freeze" calcMode="spline" keySplines="0.4 0 0.2 1" keyTimes="0;1" />
      </path>
      <circle r="3.4" fill="#7fa8ff" style={{ filter: "drop-shadow(0 0 4px #7fa8ff)" }}>
        <animateMotion dur="1.1s" fill="freeze" calcMode="linear">
          <mpath href="#rc-aline" />
        </animateMotion>
      </circle>
      <circle cx="240" cy="18" r="3.4" fill="#7fa8ff" opacity="0" style={{ filter: "drop-shadow(0 0 4px #7fa8ff)" }}>
        <animate attributeName="opacity" values="0;1" begin="1.1s" dur="0.2s" fill="freeze" />
        <animate attributeName="r" values="3.4;5.5;3.4" begin="1.1s" dur="1.8s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

/* Demixing: candidate deposit→withdrawal matches, two leads highlighted */
function MiniMatch() {
  const dep = [24, 48, 72, 96];
  const wit = [16, 38, 60, 82, 104];
  const faint = [[0, 1], [1, 0], [1, 3], [2, 4], [3, 4], [2, 2]] as const;
  const leads = [[1, 2], [3, 4]] as const;
  const lx = 46;
  const rx = 314;
  return (
    <svg viewBox="0 0 360 120" role="img" aria-label="Demixing leads linking mixer deposits to candidate withdrawals" style={{ marginTop: 2 }}>
      <text x={lx} y="10" textAnchor="middle" fill="#ffbe4d" fontFamily={FONT} fontSize="9" fontWeight="600" opacity="0.85">deposits</text>
      <text x={rx} y="10" textAnchor="middle" fill="#7fa8ff" fontFamily={FONT} fontSize="9" fontWeight="600" opacity="0.85">withdrawals</text>
      <g stroke="rgba(255,255,255,.14)" strokeWidth="1" fill="none">
        {faint.map(([a, b], i) => <path key={i} d={`M${lx} ${dep[a]} C 170 ${dep[a]}, 190 ${wit[b]}, ${rx} ${wit[b]}`} />)}
      </g>
      <g fill="none">
        {leads.map(([a, b], i) => {
          const d = `M${lx} ${dep[a]} C 170 ${dep[a]}, 190 ${wit[b]}, ${rx} ${wit[b]}`;
          return (
            <g key={i}>
              <path id={`rc-lead-${i}`} d={d} stroke="#3d7bff" strokeWidth="2" opacity="0.9" />
              <circle r="3" fill="#7fa8ff" style={{ filter: "drop-shadow(0 0 3px #7fa8ff)" }}>
                <animateMotion dur="2.2s" begin={`${i * 1.1}s`} repeatCount="indefinite" calcMode="linear">
                  <mpath href={`#rc-lead-${i}`} />
                </animateMotion>
              </circle>
            </g>
          );
        })}
      </g>
      <g fill="#2a2410" stroke="#ffbe4d" strokeWidth="1.8">
        {dep.map((y) => <circle key={y} cx={lx} cy={y} r="5" />)}
      </g>
      <g fill="#0f1b33" stroke="#588fff" strokeWidth="1.8">
        {wit.map((y) => <circle key={y} cx={rx} cy={y} r="5" />)}
      </g>
    </svg>
  );
}

function MiniBars({ wide = false }: { wide?: boolean }) {
  const rows = [
    { l: "Sanctioned", v: 92, c: "#ff5d6c" },
    { l: "Mixer", v: 74, c: "#ffbe4d" },
    { l: "Exchange", v: 40, c: "#3d7bff" },
    { l: "Clean", v: 18, c: "#35d29a" },
  ];
  return (
    <div style={{ display: "grid", gap: 6, marginTop: wide ? 4 : 0 }}>
      {rows.map((r) => (
        <div key={r.l} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 10, color: "#9aa6be", width: 62, flex: "none" }}>{r.l}</span>
          <span style={{ flex: 1, height: 5, borderRadius: 999, background: "rgba(255,255,255,.08)", overflow: "hidden" }}>
            <span style={{ display: "block", width: `${r.v}%`, height: "100%", background: r.c }} />
          </span>
        </div>
      ))}
    </div>
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

/* ── Inline monochrome line icons ── */
const svgProps = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};
function IconRoute() {
  return (<svg {...svgProps}><circle cx="6" cy="19" r="2.5" /><circle cx="18" cy="5" r="2.5" /><path d="M8.5 19H15a4 4 0 0 0 0-8H9a4 4 0 0 1 0-8h6.5" /></svg>);
}
function IconShield() {
  return (<svg {...svgProps}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>);
}
function IconTarget() {
  return (<svg {...svgProps}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="0.5" /></svg>);
}
function IconDoc() {
  return (<svg {...svgProps}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></svg>);
}
function IconNetwork() {
  return (<svg {...svgProps}><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="18" r="2.5" /><circle cx="19" cy="18" r="2.5" /><path d="M10.5 7L6.5 16M13.5 7l4 9M7.5 18h9" /></svg>);
}
function IconShuffle() {
  return (<svg {...svgProps}><path d="M4 7h3l10 10h3M4 17h3l3-3M14 10l3-3h3M18 4l3 3-3 3M18 14l3 3-3 3" /></svg>);
}
