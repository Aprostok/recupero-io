import Link from "next/link";

export const metadata = {
  title: "Terms of Service — Recupero",
  description:
    "The terms governing your use of Recupero's tracing, screening and recovery-artifact platform — including what we explicitly do not promise.",
};

/*
 * REVIEW NOTES (source only — not rendered)
 *
 * Sections describing PRODUCT BEHAVIOUR are accurate and are the ones that matter
 * most for consumer protection: no recovery guarantee, not legal advice, we cannot
 * freeze funds, attribution is evidence not proof, nothing is auto-sent.
 *
 * Standard commercial clauses are drafted here in conventional form so the document
 * reads as a complete agreement, BUT every jurisdiction- or entity-specific value is
 * a visible <Tbd> chip. Do not launch without counsel completing those — in
 * particular the liability cap, dispute-resolution forum and governing law, which
 * are unenforceable or harmful if wrong.
 */

const UPDATED = "29 July 2026";

// Contingency rate on funds actually recovered. Mirrors what the engagement letter
// renders (reports/templates/engagement_letter.html.j2 → `contingency_pct`) and the
// figure quoted on /faq. The engagement letter is the binding instrument for a
// managed engagement; this section must not contradict it.
const DIAGNOSTIC_FEE = "US$999";  // flat first-run fee, same regardless of amount stolen
const FEE_RANGE = "10–15%";

function Tbd({ children }: { children: React.ReactNode }) {
  return <span className="tbd">{children}</span>;
}

const SECTIONS = [
  "Agreement",
  "What Recupero is",
  "What Recupero is not",
  "Eligibility and accounts",
  "Acceptable use",
  "Fees and payment",
  "Your data and ours",
  "Third-party data",
  "Availability and support",
  "Disclaimer of warranties",
  "Limitation of liability",
  "Indemnity",
  "Suspension and termination",
  "Dispute resolution",
  "Changes to these terms",
  "Contact",
];

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");

export default function TermsPage() {
  return (
    <div className="legal-doc">
      <div className="doc-head">
        <span className="kicker">Legal</span>
        <h1>Terms of Service</h1>
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

      <h2 id="agreement">
        <span className="num">1</span>Agreement
      </h2>
      <p>
        These Terms are an agreement between you (and, if you are using Recupero for an
        organization, that organization) and <Tbd>legal entity name</Tbd> (&ldquo;Recupero&rdquo;,
        &ldquo;we&rdquo;, &ldquo;us&rdquo;), registered at <Tbd>registered address</Tbd>. By
        creating an account or using the service you accept them. If you are accepting on
        behalf of an organization, you confirm you have authority to do so.
      </p>

      <h2 id="what-recupero-is">
        <span className="num">2</span>What Recupero is
      </h2>
      <p>
        Recupero is investigative software. It reads public blockchain data to trace where
        funds moved, screens addresses against sanctions and risk data, and produces
        evidence and draft paperwork that you — or your counsel, investigator or law
        enforcement — can act on.
      </p>

      <h2 id="what-recupero-is-not">
        <span className="num">3</span>What Recupero is not
      </h2>
      <p>Please read this section carefully. It is the most important one.</p>
      <ul>
        <li>
          <strong>We do not guarantee recovery.</strong> Most stolen crypto is never
          recovered. Nothing in the product, our marketing, or any output constitutes a
          promise, prediction or warranty that your funds will be returned in whole or in
          part.
        </li>
        <li>
          <strong>We are not your lawyer and this is not legal advice.</strong> Freeze
          requests, subpoena targets, regulatory filings and exhibit packs are{" "}
          <em>drafts</em> for a qualified professional to review, adapt and file. No
          attorney–client relationship is created by using Recupero.
        </li>
        <li>
          <strong>We do not provide financial, tax or investment advice.</strong>
        </li>
        <li>
          <strong>We cannot freeze, seize or return funds.</strong> Only exchanges, token
          issuers, courts and law enforcement can. We help you identify who to ask, and give
          you the evidence to ask with.
        </li>
        <li>
          <strong>We never take custody of your assets</strong> and will never ask for your
          seed phrase, recovery phrase or private keys.
        </li>
        <li>
          <strong>Attribution is evidence, not proof.</strong> Findings carry an explicit
          confidence level; low- and medium-confidence findings are investigative leads
          requiring human judgement. We do not fabricate a destination when the trail ends —
          but you must not treat any finding as a conclusive determination of identity or
          wrongdoing.
        </li>
        <li>
          <strong>Nothing is sent on your behalf.</strong> No letter, filing or request is
          transmitted to an exchange, issuer or regulator without a human deciding to send
          it.
        </li>
      </ul>

      <h2 id="eligibility-and-accounts">
        <span className="num">4</span>Eligibility and accounts
      </h2>
      <p>
        You must be at least 18 and legally able to enter this agreement. You are
        responsible for the accuracy of your account information, for keeping your
        credentials and API keys confidential, and for all activity under your account and
        your organization&rsquo;s members. Tell us promptly if you suspect unauthorised
        access.
      </p>

      <h2 id="acceptable-use">
        <span className="num">5</span>Acceptable use
      </h2>
      <p>You agree not to:</p>
      <ul>
        <li>Use the service unlawfully, or to investigate matters you have no legitimate interest in.</li>
        <li>Harass, stalk, dox or surveil any person, or attempt to unmask individuals for purposes unrelated to a genuine investigation.</li>
        <li>Use it to launder, conceal or move the proceeds of crime, or to evade sanctions.</li>
        <li>Present its output as a conclusive legal determination, or misrepresent a low-confidence lead as established fact.</li>
        <li>Resell, sublicense or white-label the service without our written agreement.</li>
        <li>Scrape, reverse-engineer, or circumvent rate limits, quotas or access controls.</li>
        <li>Upload malware, or attempt to disrupt or gain unauthorised access to the service or another organization&rsquo;s data.</li>
      </ul>

      <h2 id="fees-and-payment">
        <span className="num">6</span>Fees and payment
      </h2>
      <h3>How engagements are priced</h3>
      <p>
        Recupero is currently provided as a managed engagement rather than a self-serve
        subscription. Where we act on a case for you, fees have three components, set out in
        full in the engagement letter you sign:
      </p>
      <ul>
        <li>
          A <strong>flat diagnostic fee of {DIAGNOSTIC_FEE}</strong>, payable upfront and
          the same for every first case regardless of the amount stolen, covering the
          investigation and an assessment of what is realistically recoverable. It is
          non-refundable and is not credited against the engagement fee — the diagnostic and
          the engagement are distinct services with distinct deliverables.
        </li>
        <li>
          An <strong>engagement fee priced per case</strong> if you choose to proceed, quoted
          to you in writing before you commit, reflecting the scope of work the case
          requires. This becomes non-refundable once we begin sending compliance freeze
          letters on your behalf.
        </li>
        <li>
          A <strong>contingency fee of {FEE_RANGE} of any funds actually recovered</strong>{" "}
          through the engagement. &ldquo;Recovered&rdquo; means funds returned to you, or to
          a court-appointed custodian on your behalf, valued in USD equivalent at the time
          of return.
        </li>
      </ul>
      <p>
        If we introduce self-serve subscription plans in future, their price, allowances and
        billing terms will be shown at checkout before you subscribe. The contingency fee is
        invoiced within 14 days of a recovery event and is due within
        30 days of invoice. Recoveries occurring more than 12 months after the engagement
        date are not subject to the contingency fee. The diagnostic and the engagement are
        distinct services with distinct deliverables, and the diagnostic fee is not credited
        against the engagement fee.
      </p>
      <p>
        <strong>We never take custody of recovered funds.</strong> Recoveries are returned
        to you or to your custodian directly, and we invoice afterwards. Exact amounts,
        the applicable contingency percentage, and any case-specific terms are governed by
        your engagement letter, which prevails over this section if they differ.
      </p>

      <h2 id="your-data-and-ours">
        <span className="num">7</span>Your data and ours
      </h2>
      <p>
        You retain ownership of the case information you submit and of the reports generated
        for you. You grant us a limited licence to host, process and analyse that
        information solely to provide and secure the service. We retain all rights in the
        software, our label and attribution datasets, and the underlying methods. Our
        handling of personal information is described in our{" "}
        <Link href="/privacy">Privacy Policy</Link>.
      </p>

      <h2 id="third-party-data">
        <span className="num">8</span>Third-party data
      </h2>
      <p>
        The service depends on public blockchain data and on third-party blockchain,
        market-data, sanctions and attribution providers. That data can be incomplete,
        delayed or wrong, and provider coverage changes. We do not warrant the accuracy or
        completeness of third-party data, and a trace reflects only what was available when
        it ran.
      </p>

      <h2 id="availability-and-support">
        <span className="num">9</span>Availability and support
      </h2>
      <p>
        The service is provided on an &ldquo;as available&rdquo; basis and may be interrupted
        for maintenance, provider outages or events beyond our control. Support channels and
        any service-level commitment: <Tbd>support hours / SLA, if any</Tbd>.
      </p>

      <h2 id="disclaimer-of-warranties">
        <span className="num">10</span>Disclaimer of warranties
      </h2>
      <p>
        To the fullest extent permitted by law, the service is provided &ldquo;as is&rdquo;
        and &ldquo;as available&rdquo; without warranties of any kind, whether express,
        implied or statutory, including implied warranties of merchantability, fitness for a
        particular purpose, non-infringement, and any warranty as to the accuracy,
        completeness or investigative sufficiency of any output. Some jurisdictions do not
        allow certain exclusions, so parts of this section may not apply to you.
      </p>

      <h2 id="limitation-of-liability">
        <span className="num">11</span>Limitation of liability
      </h2>
      <p>
        To the fullest extent permitted by law, neither party is liable for indirect,
        incidental, special, consequential or punitive damages, or for lost profits, lost
        data, or — importantly —{" "}
        <strong>the value of digital assets that are not recovered</strong>, even if advised
        of the possibility.
      </p>
      <p>
        Our total aggregate liability arising out of or relating to these Terms is limited
        to <Tbd>liability cap — e.g. fees paid in the preceding 12 months</Tbd>. Nothing
        here limits liability that cannot lawfully be limited, including for fraud or death
        or personal injury caused by negligence.
      </p>

      <h2 id="indemnity">
        <span className="num">12</span>Indemnity
      </h2>
      <p>
        You will indemnify and hold us harmless against claims, losses and reasonable costs
        arising from your use of the service in breach of these Terms — in particular from
        your use of, reliance on, or onward distribution of trace output, including any
        filing, allegation or communication you make to a third party based on it.
      </p>

      <h2 id="suspension-and-termination">
        <span className="num">13</span>Suspension and termination
      </h2>
      <p>
        You may stop using the service and close your account at any time. We may suspend or
        terminate access if you materially breach these Terms, if required by law, or if your
        use threatens the security or integrity of the platform — with notice where
        practicable, immediately where necessary. On termination your right to use the
        service ends; data is handled per the retention rules in our{" "}
        <Link href="/privacy">Privacy Policy</Link>. Sections 3, 7 and 10–12 survive.
      </p>

      <h2 id="dispute-resolution">
        <span className="num">14</span>Dispute resolution
      </h2>
      <p>
        These Terms are governed by the laws of <Tbd>governing law</Tbd>, without regard to
        conflict-of-laws rules. Disputes will be resolved in{" "}
        <Tbd>courts / arbitration forum and seat</Tbd>. We encourage you to contact us first
        — most issues are resolved quickly without formal process.{" "}
        <Tbd>counsel: confirm whether arbitration and any class-action waiver are
        appropriate and enforceable in your target markets</Tbd>
      </p>

      <h2 id="changes-to-these-terms">
        <span className="num">15</span>Changes to these terms
      </h2>
      <p>
        We may update these Terms as the service evolves. The date above always reflects the
        current version. For material changes we will notify account holders by email before
        they take effect; continuing to use the service afterwards means you accept the
        updated Terms.
      </p>

      <h2 id="contact">
        <span className="num">16</span>Contact
      </h2>
      <p>
        Questions about these Terms: <Link href="/contact">contact us</Link> or email{" "}
        <a href="mailto:legal@recupero.io">legal@recupero.io</a>.
      </p>
    </div>
  );
}
