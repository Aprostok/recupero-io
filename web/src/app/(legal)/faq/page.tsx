import Link from "next/link";

export const metadata = {
  title: "FAQ — Recupero",
  description:
    "Straight answers about tracing stolen crypto: what we can and can't recover, what we need from you, which chains we cover, and what it costs.",
};

// Contingency rate charged on funds actually recovered. Keep in sync with the
// engagement letter template (reports/templates/engagement_letter.html.j2 renders
// `contingency_pct`) and with /terms.
const FEE_RANGE = "10–15%";

type QA = { q: string; a: React.ReactNode };
type Group = { cat: string; items: QA[] };

const GROUPS: Group[] = [
  {
    cat: "The honest answers first",
    items: [
      {
        q: "Can you actually get my crypto back?",
        a: (
          <>
            <p>
              Sometimes. Often not. We won&rsquo;t pretend otherwise —{" "}
              <strong>most stolen crypto is never recovered</strong>, and anyone who
              guarantees recovery before looking at your case is not being straight with
              you.
            </p>
            <p>
              What determines the outcome is mostly <em>where the funds went</em>. If they
              landed at an exchange, there is a real, well-trodden path: identify the
              deposit, get a freeze request and subpoena in front of that exchange&rsquo;s
              compliance team fast. If they went through a mixer, or were swapped and
              scattered across chains, the realistic outcome is often intelligence for law
              enforcement rather than money back. A trace tells you which situation
              you&rsquo;re in — usually within minutes.
            </p>
          </>
        ),
      },
      {
        q: "Do you ever ask for my seed phrase or private keys?",
        a: (
          <>
            <p>
              <strong>Never. Not once, not for any reason.</strong> Tracing only reads
              public blockchain data. Nobody who legitimately needs to trace your funds
              needs access to your wallet.
            </p>
            <p>
              If anyone — including someone claiming to be from Recupero — asks for your
              seed phrase, recovery phrase or private key, it is a scam. Recovery scams
              specifically target people who have just been hacked, because they know
              you&rsquo;re desperate. Please be careful.
            </p>
          </>
        ),
      },
      {
        q: "How do you charge?",
        a: (
          <>
            <p>
              Three parts. The <strong>first run is a flat diagnostic fee</strong> — the
              same price for everyone, no matter the size of the theft — which buys the
              investigation and an honest assessment of what is realistically recoverable.
              If you decide to proceed, the <strong>engagement is priced per case</strong>,
              because the work varies enormously with how the funds were moved and which
              venues are involved. Finally, a <strong>contingency fee of {FEE_RANGE}</strong>{" "}
              of any funds actually recovered through the engagement.
            </p>
            <p>
              &ldquo;Recovered&rdquo; means funds returned to you, or to a court-appointed
              custodian on your behalf. The contingency fee is invoiced within 14 days of a
              recovery event and due within 30 days. Recoveries more than 12 months after
              the engagement date aren&rsquo;t subject to it.
            </p>
            <p>
              We tell you the realistic recoverable figure <em>before</em> you commit to an
              engagement — the diagnostic exists precisely so you aren&rsquo;t paying to
              chase money that a trace shows is gone. Exact fee amounts are set out in your
              engagement letter. <span className="tbd">confirm the flat diagnostic fee amount</span>
            </p>
            <p>
              <strong>We never take custody of your assets.</strong> Recovered funds go to
              you or your custodian; we invoice afterwards.
            </p>
          </>
        ),
      },
    ],
  },
  {
    cat: "Getting started",
    items: [
      {
        q: "What do you need from me to start?",
        a: (
          <p>
            Three things: the <strong>address that was drained</strong>, the{" "}
            <strong>chain</strong> it was on (we auto-detect this from the address shape),
            and roughly <strong>when it happened</strong>. That&rsquo;s it — paste the
            address and the trace starts.
          </p>
        ),
      },
      {
        q: "How long does a trace take?",
        a: (
          <p>
            Usually minutes. A large or heavily-laundered case with thousands of hops takes
            longer, and the page updates live as it runs. If a trace can&rsquo;t finish
            within its budget it tells you so and reports what it <em>did</em> reach —
            it will never quietly present a partial trace as complete.
          </p>
        ),
      },
      {
        q: "Which blockchains do you cover?",
        a: (
          <p>
            Ethereum and the major EVM L2s (Arbitrum, Optimism, Base, Polygon, BSC,
            Avalanche), plus Bitcoin, Solana, Tron, TON, Stellar, Cosmos/IBC, Hyperliquid,
            Sui and Aptos. We follow funds <em>across</em> chains through bridges, not just
            within one.
          </p>
        ),
      },
      {
        q: "My theft was years ago. Is it too late?",
        a: (
          <p>
            No — the blockchain doesn&rsquo;t forget, and old cases trace fine. Recovery
            odds do drop over time, because funds have usually reached their final
            destination and exchange records age. But an old trace is still worth running:
            dormant stolen funds sitting untouched at an identified address are a genuinely
            good scenario.
          </p>
        ),
      },
    ],
  },
  {
    cat: "What the results mean",
    items: [
      {
        q: "The funds went into a mixer like Tornado Cash. Now what?",
        a: (
          <p>
            We stop at the mixer and say so plainly, because that is the truth: a mixer
            deposit breaks the on-chain link. We can surface{" "}
            <strong>low-confidence candidate withdrawals</strong> as leads for an
            investigator to pursue, but we will not present a guess as a destination. That
            honesty matters — a fabricated &ldquo;this is where it went&rdquo; would fall
            apart the moment a court or an exchange looked at it.
          </p>
        ),
      },
      {
        q: "The funds reached an exchange. Is that good news?",
        a: (
          <p>
            It&rsquo;s the best realistic news. Exchanges hold real customer identity and
            can freeze balances. We identify the deposit address, tell you which exchange
            it belongs to, and generate the freeze request and subpoena-target paperwork
            aimed at that specific deposit. Speed matters enormously here.
          </p>
        ),
      },
      {
        q: "How confident are the results? Could you be wrong?",
        a: (
          <>
            <p>
              Every finding carries an explicit confidence level, and we are deliberately
              conservative:
            </p>
            <ul>
              <li>
                <strong>High</strong> — cryptographic or protocol-level certainty (a bridge
                message confirming source and destination, an authoritative sanctions
                listing). Never assigned to a guess.
              </li>
              <li>
                <strong>Medium</strong> — a strong single-candidate value match.
              </li>
              <li>
                <strong>Low</strong> — a lead for human review. Where several paths are
                plausible we mark them ambiguous rather than picking one.
              </li>
            </ul>
            <p>
              The rule we don&rsquo;t break: <strong>we never invent a destination</strong>{" "}
              to fill a gap. If the trail ends, the report says the trail ends.
            </p>
          </>
        ),
      },
      {
        q: "What do I actually get at the end?",
        a: (
          <p>
            A plain-English summary of where your money is now and what&rsquo;s realistically
            recoverable; an interactive fund-flow graph; a transfers spreadsheet; an
            investigation brief; and, as part of a managed engagement, the recovery
            paperwork: exchange freeze requests, subpoena targets, SAR/STR drafts and a
            court-admissible exhibit pack with signed hashes.
          </p>
        ),
      },
    ],
  },
  {
    cat: "Working with us",
    items: [
      {
        q: "Do you send the freeze letters and contact exchanges for me?",
        a: (
          <p>
            No — and that&rsquo;s deliberate. Recupero <em>drafts</em> them; a human always
            decides what gets sent. Nothing is auto-sent to an exchange, issuer or
            regulator on your behalf. You or your counsel review, adapt and send.
          </p>
        ),
      },
      {
        q: "Is this legal advice?",
        a: (
          <p>
            No. Recupero is investigative software, not a law firm, and nothing it produces
            is legal advice. The legal documents it generates are drafts for a qualified
            professional to review. See our <Link href="/terms">Terms</Link>.
          </p>
        ),
      },
      {
        q: "I'm a law firm / investigator working someone else's case. Can I use this?",
        a: (
          <p>
            Yes — that&rsquo;s a core use case. Organizations, team members with roles, an
            audit log and a programmatic API are all built in. Invite your team from the
            Members page.
          </p>
        ),
      },
      {
        q: "Who can see my case data?",
        a: (
          <p>
            Only your organization. Each org&rsquo;s data is isolated, access is scoped by
            role, and we don&rsquo;t sell data or use it for advertising. Details in our{" "}
            <Link href="/privacy">Privacy Policy</Link>.
          </p>
        ),
      },
      {
        q: "Should I report the theft to the police as well?",
        a: (
          <p>
            Yes — report it, and do it early. Exchanges and courts act on law-enforcement
            process far more readily than on a private request, so an official report
            materially improves your odds. Recupero&rsquo;s output is built to hand
            straight to investigators.
          </p>
        ),
      },
    ],
  },
];

export default function FaqPage() {
  return (
    <div className="legal-doc">
      <div className="doc-head">
        <span className="kicker">Answers</span>
        <h1>Frequently asked questions</h1>
        <p className="muted" style={{ margin: 0 }}>
          What we can and can&rsquo;t do, in plain language. If your question isn&rsquo;t
          here, <Link href="/contact">ask us</Link>.
        </p>
      </div>

      {GROUPS.map((g) => (
        <section key={g.cat}>
          <div className="faq-cat">{g.cat}</div>
          <div className="faq-list">
            {g.items.map((qa) => (
              <div className="faq-item" key={qa.q}>
                <h3>{qa.q}</h3>
                {qa.a}
              </div>
            ))}
          </div>
        </section>
      ))}

      <section className="panel stack" style={{ marginTop: 40 }}>
        <h3 style={{ margin: 0, fontSize: "1.05rem" }}>Still deciding?</h3>
        <p className="muted" style={{ margin: 0 }}>
          A trace will tell you which situation you&rsquo;re actually in — recoverable,
          trackable, or gone — far faster than deliberating will.
        </p>
        <div className="row">
          <Link href="/signup" className="cta primary" style={{ padding: "10px 20px", fontSize: 14 }}>
            Start a recovery
          </Link>
          <Link href="/academy" className="muted">
            Read the Academy →
          </Link>
        </div>
      </section>
    </div>
  );
}
