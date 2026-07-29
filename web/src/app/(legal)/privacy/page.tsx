export const metadata = {
  title: "Privacy Policy — Recupero",
  description:
    "What Recupero collects when you trace stolen funds, why, how long we keep it, and who processes it.",
};

// NOTE FOR REVIEW: the FACTUAL sections below (what we collect, processors,
// retention) are written to match what the product actually does — the /v2 data
// model (users, organizations, investigations, usage_events, audit_log), the case
// artifacts the worker writes, and the third parties the engine actually calls.
// The items marked [CONFIRM] need a decision or a real value from you, and the
// whole document should be reviewed by counsel before launch.

const UPDATED = "29 July 2026";

export default function PrivacyPage() {
  return (
    <>
      <div className="section-head" style={{ textAlign: "left", margin: "0 0 32px" }}>
        <span className="kicker">Legal</span>
        <h1 style={{ fontSize: "2.2rem", fontWeight: 800, margin: "12px 0" }}>
          Privacy Policy
        </h1>
        <p className="muted" style={{ margin: 0 }}>Last updated {UPDATED}</p>
      </div>

      <div className="stack" style={{ gap: 28, lineHeight: 1.7 }}>
        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>In short</h2>
          <p className="muted" style={{ margin: 0 }}>
            To trace stolen funds we need two things: an account for you, and the
            blockchain addresses involved in your incident. Blockchain data is already
            public — we read it, we never publish anything about you, and we don&rsquo;t
            sell your data or use it for advertising.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>What we collect</h2>
          <ul className="muted" style={{ margin: 0, paddingLeft: 20 }}>
            <li>
              <strong>Account</strong> — your email address, a password (stored only as a
              memory-hard hash, never in plain text), your organization name, and the
              members you invite.
            </li>
            <li>
              <strong>Case data you submit</strong> — the wallet addresses, chain and
              incident time for each trace, plus any case reference you add.
            </li>
            <li>
              <strong>Trace output</strong> — the transfers, addresses, risk labels and
              reports our engine produces from public blockchain data for your case.
            </li>
            <li>
              <strong>Usage + security records</strong> — how many traces you run (for
              quota and billing), and an audit log of security-relevant actions such as
              sign-ins, API-key creation and membership changes.
            </li>
            <li>
              <strong>Billing</strong> — a customer identifier and subscription status from
              our payment processor. <strong>We never see or store your card details.</strong>
            </li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Who processes it</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            We use a small set of providers to run the service. Blockchain and pricing
            providers receive addresses and asset identifiers in order to answer queries;
            they do not receive your account details.
          </p>
          <ul className="muted" style={{ margin: 0, paddingLeft: 20 }}>
            <li>Cloud hosting and managed Postgres — to run the application and store your data</li>
            <li>Blockchain data providers — to read public on-chain history</li>
            <li>Market-data provider — for historical asset valuations</li>
            <li>Sanctions and attribution data providers — to screen addresses for risk</li>
            <li>Payment processor — subscriptions and invoicing</li>
            <li>Email provider — sign-in, verification and case notifications</li>
            <li>AI provider — to draft plain-English case summaries [CONFIRM: keep or disable]</li>
          </ul>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>How long we keep it</h2>
          <p className="muted" style={{ margin: 0 }}>
            Case data is retained according to your plan and then deleted automatically.
            Account and billing records are kept while your account is open and for as long
            as we are legally required to keep them afterwards. You can ask us to delete
            your account and case data at any time — see Contact.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Your choices</h2>
          <p className="muted" style={{ margin: 0 }}>
            You can access, correct, export or delete your data, and withdraw consent for
            optional processing, by contacting us. Depending on where you live you may have
            additional rights under laws such as the GDPR or the CCPA.
            [CONFIRM: which regimes you operate under, and your data-controller entity +
            registered address.]
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Security</h2>
          <p className="muted" style={{ margin: 0 }}>
            Data is encrypted in transit. Passwords are hashed with a memory-hard algorithm.
            API keys are stored only as hashes and shown once. Each organization&rsquo;s data
            is isolated, and access is scoped per organization and role.
          </p>
        </section>

        <section>
          <h2 style={{ fontSize: "1.2rem", marginBottom: 8 }}>Contact</h2>
          <p className="muted" style={{ margin: 0 }}>
            Questions about this policy, or a data request? See our{" "}
            <a href="/contact">contact page</a>.
          </p>
        </section>
      </div>
    </>
  );
}
