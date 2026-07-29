export const metadata = {
  title: "Terms of Service — Recupero",
  description:
    "The terms that govern your use of Recupero's tracing, screening and recovery-artifact platform.",
};

// NOTE FOR REVIEW: the product-behaviour sections here are accurate (what the
// service does and explicitly does NOT promise). The commercial/liability clauses
// marked [COUNSEL] are deliberately left as visible placeholders rather than
// invented text — unreviewed liability, indemnity, arbitration and governing-law
// language is worse than none. Have counsel complete those before launch.

const UPDATED = "29 July 2026";

export default function TermsPage() {
  return (
    <>
      <div className="section-head" style={{ textAlign: "left", margin: "0 0 32px" }}>
        <span className="kicker">Legal</span>
        <h1 style={{ fontSize: "2.2rem", fontWeight: 800, margin: "12px 0" }}>
          Terms of Service
        </h1>
        <p className="muted" style={{ margin: 0 }}>Last updated {UPDATED}</p>
      </div>

      <div className="stack" style={{ gap: 28, lineHeight: 1.7 }}>
        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>What Recupero is</h2>
          <p className="muted" style={{ margin: 0 }}>
            Recupero is investigative software. It reads public blockchain data to trace
            where funds moved, screens addresses against sanctions and risk data, and
            produces evidence and paperwork you or your counsel can act on.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>
            What Recupero is not — please read this one
          </h2>
          <ul className="muted" style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              <strong>We do not guarantee recovery.</strong> Most stolen crypto is never
              recovered. Nothing in the product or our marketing is a promise that your
              funds will be returned.
            </li>
            <li>
              <strong>We are not your lawyer</strong> and we do not provide legal advice.
              Freeze requests, subpoena packets and regulatory filings are drafts for a
              qualified professional to review, adapt and send.
            </li>
            <li>
              <strong>We do not provide financial or investment advice.</strong>
            </li>
            <li>
              <strong>We cannot freeze or seize funds.</strong> Only exchanges, issuers,
              courts and law enforcement can. We help you identify who to ask and give you
              the evidence to ask with.
            </li>
            <li>
              <strong>Attribution is evidence, not proof.</strong> Findings carry an
              explicit confidence level. Low- and medium-confidence findings are leads for
              human review. We never fabricate a destination to fill a gap.
            </li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Your responsibilities</h2>
          <ul className="muted" style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              Use the service lawfully, and only to investigate incidents you are entitled
              to investigate.
            </li>
            <li>
              Don&rsquo;t use it to harass, dox or surveil people, or to launder or conceal
              the proceeds of crime.
            </li>
            <li>Keep your credentials and API keys secure; you are responsible for activity under them.</li>
            <li>Provide accurate incident information — the quality of a trace depends on it.</li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Plans, quotas and billing</h2>
          <p className="muted" style={{ margin: 0 }}>
            Paid plans are billed in advance on a recurring basis and include a monthly
            trace allowance and feature set shown at checkout and on your billing page.
            Allowances reset each billing period and do not roll over.
            [COUNSEL: refunds, cancellation, proration, price-change notice.]
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Your data and ours</h2>
          <p className="muted" style={{ margin: 0 }}>
            You keep ownership of the case data you submit and the reports generated for
            you. You grant us the licence needed to process it in order to run the service.
            We retain ownership of the software, models and labels. See our{" "}
            <a href="/privacy">Privacy Policy</a>.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Availability</h2>
          <p className="muted" style={{ margin: 0 }}>
            The service depends on third-party blockchain, market-data and sanctions
            providers. It is provided on an &ldquo;as available&rdquo; basis and may be
            interrupted for maintenance or provider outages.
            [COUNSEL: uptime commitment / SLA, if any.]
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Legal terms to be completed</h2>
          <p className="muted" style={{ margin: 0 }}>
            [COUNSEL: warranty disclaimer, limitation of liability and cap, indemnity,
            dispute resolution / arbitration, governing law and venue, termination and
            suspension, changes to these terms, and the contracting entity&rsquo;s legal
            name and registered address.]
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Contact</h2>
          <p className="muted" style={{ margin: 0 }}>
            Questions about these terms? See our <a href="/contact">contact page</a>.
          </p>
        </section>
      </div>
    </>
  );
}
