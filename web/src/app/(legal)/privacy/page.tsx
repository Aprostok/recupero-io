import Link from "next/link";

export const metadata = {
  title: "Privacy Policy — Recupero",
  description:
    "What Recupero collects when you trace stolen funds, why we collect it, who processes it, how long we keep it, and the rights you have over it.",
};

/*
 * REVIEW NOTES (source only — not rendered)
 *
 * The factual sections below were written against what the product ACTUALLY does:
 * the /v2 data model (users, organizations, memberships, org_api_keys,
 * investigations, usage_events, audit_log, user_tokens), the artifacts the worker
 * writes into a case, and the third parties the engine genuinely calls.
 *
 * Every remaining unknown is rendered as a visible <Tbd> chip rather than invented
 * text, because shipping a confident-but-wrong controller entity or jurisdiction is
 * worse than an obvious blank. Before launch: fill each chip, confirm the role
 * mailboxes exist, and have counsel review the whole document.
 */

const UPDATED = "29 July 2026";

function Tbd({ children }: { children: React.ReactNode }) {
  return <span className="tbd">{children}</span>;
}

const SECTIONS = [
  "Summary",
  "Who we are",
  "Information we collect",
  "How we use it",
  "Legal bases",
  "Service providers",
  "Blockchain data",
  "Retention",
  "Your rights",
  "Security",
  "International transfers",
  "Children",
  "Changes",
  "Contact",
];

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");

export default function PrivacyPage() {
  return (
    <div className="legal-doc">
      <div className="doc-head">
        <span className="kicker">Legal</span>
        <h1>Privacy Policy</h1>
        <p className="doc-meta">Last updated {UPDATED}</p>
      </div>

      <nav className="doc-toc" aria-label="Contents">
        <h4>Contents</h4>
        <ol>
          {SECTIONS.map((s) => (
            <li key={s}>
              <a href={`#${slug(s)}`}>{s}</a>
            </li>
          ))}
        </ol>
      </nav>

      <h2 id="summary">
        <span className="num">1</span>Summary
      </h2>
      <p>
        To trace stolen funds we need two things: an account for you, and the blockchain
        addresses involved in your incident. Blockchain transaction data is already public
        — we read and analyse it. We do not sell your personal information, we do not use
        it for advertising, and we never publish anything about you or your case.
      </p>
      <p>
        <strong>We never ask for your seed phrase, recovery phrase or private keys.</strong>{" "}
        Tracing does not require access to your wallet, and anyone who asks you for those
        is attempting fraud.
      </p>

      <h2 id="who-we-are">
        <span className="num">2</span>Who we are
      </h2>
      <p>
        Recupero provides investigative software for tracing and recovering stolen digital
        assets. The data controller responsible for the information described here is{" "}
        <Tbd>legal entity name</Tbd>, registered at <Tbd>registered address</Tbd>.
      </p>

      <h2 id="information-we-collect">
        <span className="num">3</span>Information we collect
      </h2>
      <h3>Information you give us</h3>
      <ul>
        <li>
          <strong>Account details</strong> — your email address, a password, and your name
          if you provide one. Passwords are stored only as a memory-hard cryptographic hash;
          we cannot read them.
        </li>
        <li>
          <strong>Organization details</strong> — your organization name and the email
          addresses of team members you invite, together with their roles.
        </li>
        <li>
          <strong>Case details</strong> — the wallet addresses, blockchain and approximate
          incident time you submit for each trace, plus any case reference or notes you add.
        </li>
      </ul>
      <h3>Information we generate</h3>
      <ul>
        <li>
          <strong>Trace results</strong> — the transfers, counterparty addresses, risk and
          sanctions labels, valuations and reports our engine derives from public blockchain
          data for your case.
        </li>
        <li>
          <strong>Usage records</strong> — the number of traces you run, used to enforce
          plan quotas and to bill accurately.
        </li>
        <li>
          <strong>Security records</strong> — an audit log of security-relevant events such
          as sign-ins, API-key creation and revocation, and membership changes.
        </li>
        <li>
          <strong>Technical logs</strong> — request metadata (time, endpoint, response
          status) needed to operate and secure the service.
        </li>
      </ul>
      <h3>Information from third parties</h3>
      <ul>
        <li>
          <strong>Billing status</strong> — a customer identifier, subscription state and
          invoice history from our payment processor.{" "}
          <strong>We never receive or store your full card details.</strong>
        </li>
      </ul>

      <h2 id="how-we-use-it">
        <span className="num">4</span>How we use it
      </h2>
      <ul>
        <li>To run traces and produce the reports and recovery paperwork you asked for.</li>
        <li>To create and secure your account and organization, and to authenticate you.</li>
        <li>To enforce plan quotas and rate limits, and to bill you correctly.</li>
        <li>To send transactional email: verification, password reset, invitations and case notifications.</li>
        <li>To detect, investigate and prevent abuse, fraud and security incidents.</li>
        <li>To comply with legal obligations and respond to lawful requests.</li>
      </ul>
      <p>
        We do not sell personal information, and we do not use your case data to train
        general-purpose models.
      </p>

      <h2 id="legal-bases">
        <span className="num">5</span>Legal bases
      </h2>
      <p>
        Where the GDPR or similar law applies, we rely on: <strong>contract</strong> — to
        provide the service you signed up for; <strong>legitimate interests</strong> — to
        secure the platform, prevent abuse and improve reliability;{" "}
        <strong>legal obligation</strong> — for tax, accounting and lawful requests; and{" "}
        <strong>consent</strong> — for anything optional, which you may withdraw at any
        time. <Tbd>confirm applicable regimes with counsel</Tbd>
      </p>

      <h2 id="service-providers">
        <span className="num">6</span>Service providers
      </h2>
      <p>
        We use a deliberately small set of providers to run the service. Blockchain,
        sanctions and market-data providers receive addresses and asset identifiers in order
        to answer a query — they do not receive your account details or case narrative.
      </p>
      <ul>
        <li><strong>Cloud hosting and managed database</strong> — running the application and storing your data</li>
        <li><strong>Blockchain data providers</strong> — reading public on-chain transaction history</li>
        <li><strong>Market-data provider</strong> — historical asset valuations</li>
        <li><strong>Sanctions and attribution providers</strong> — screening addresses against sanctions and risk data</li>
        <li><strong>Payment processor</strong> — subscriptions, invoicing and card handling</li>
        <li><strong>Email provider</strong> — transactional email</li>
        <li><strong>AI provider</strong> — generating plain-English case summaries from your trace results <Tbd>confirm: enabled or disabled</Tbd></li>
      </ul>

      <h2 id="blockchain-data">
        <span className="num">7</span>Blockchain data
      </h2>
      <p>
        Blockchain transactions are public and permanent by design. We read that public
        record; we do not and cannot alter or delete it. Note that an address you submit may
        itself be linkable to a person — including you. We treat the addresses you submit as
        confidential to your organization, but we cannot make the underlying chain data
        private.
      </p>

      <h2 id="retention">
        <span className="num">8</span>Retention
      </h2>
      <ul>
        <li>
          <strong>Case data and trace artifacts</strong> — retained for the retention window
          of your plan, then deleted automatically.
        </li>
        <li>
          <strong>Account and organization records</strong> — kept while your account is
          open.
        </li>
        <li>
          <strong>Billing and tax records</strong> — kept for the period the law requires
          after your account closes. <Tbd>retention period</Tbd>
        </li>
        <li>
          <strong>Security audit logs</strong> — kept as an integrity record for{" "}
          <Tbd>audit-log retention period</Tbd>.
        </li>
      </ul>

      <h2 id="your-rights">
        <span className="num">9</span>Your rights
      </h2>
      <p>
        Subject to your jurisdiction, you may have the right to access, correct, export or
        delete your personal information, to object to or restrict certain processing, and
        to withdraw consent. You can delete your case data from the product, or contact us
        to request deletion of your account and associated data. We will respond within the
        period required by applicable law.
      </p>
      <p>
        If you are in the EEA or UK you may also complain to your supervisory authority. If
        you are a California resident, we do not sell or share personal information as those
        terms are defined by the CCPA/CPRA, and we will not discriminate against you for
        exercising your rights.
      </p>

      <h2 id="security">
        <span className="num">10</span>Security
      </h2>
      <ul>
        <li>All traffic is encrypted in transit (TLS).</li>
        <li>Passwords are hashed with a memory-hard algorithm and are never stored or logged in plain text.</li>
        <li>API keys are stored only as hashes, shown once at creation, and can be revoked immediately.</li>
        <li>Each organization&rsquo;s data is isolated, and access is scoped per organization and per role.</li>
        <li>Sessions are re-validated against current membership, so removing a member revokes their access immediately.</li>
      </ul>
      <p>
        No system is perfectly secure. If you believe you have found a vulnerability, please
        report it to us at <a href="mailto:security@recupero.io">security@recupero.io</a>{" "}
        <Tbd>confirm mailbox exists</Tbd> and we will work with you in good faith.
      </p>

      <h2 id="international-transfers">
        <span className="num">11</span>International transfers
      </h2>
      <p>
        Our providers may process data in countries other than yours. Where required we rely
        on appropriate safeguards, such as the European Commission&rsquo;s standard
        contractual clauses. <Tbd>confirm hosting regions and safeguards</Tbd>
      </p>

      <h2 id="children">
        <span className="num">12</span>Children
      </h2>
      <p>
        The service is not intended for anyone under 18, and we do not knowingly collect
        information from children.
      </p>

      <h2 id="changes">
        <span className="num">13</span>Changes
      </h2>
      <p>
        We will update this policy as the service changes. The date at the top always
        reflects the current version, and we will notify account holders of material changes
        by email before they take effect.
      </p>

      <h2 id="contact">
        <span className="num">14</span>Contact
      </h2>
      <p>
        Privacy questions and data requests: see our <Link href="/contact">contact page</Link>
        , or email <a href="mailto:legal@recupero.io">legal@recupero.io</a>.
      </p>
    </div>
  );
}
