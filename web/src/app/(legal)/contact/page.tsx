import Link from "next/link";

export const metadata = {
  title: "Contact — Recupero",
  description:
    "Reach Recupero about an active theft, a case in progress, billing, or a privacy request.",
};

// NOTE FOR REVIEW: the addresses below are role addresses, not personal ones.
// [CONFIRM] each mailbox actually exists and is monitored before launch — a
// published address that bounces is worse than no address.
const SUPPORT_EMAIL = "support@recupero.io";
const LEGAL_EMAIL = "legal@recupero.io";

export default function ContactPage() {
  return (
    <>
      <div className="section-head" style={{ textAlign: "left", margin: "0 0 32px" }}>
        <span className="kicker">Contact</span>
        <h1 style={{ fontSize: "2.2rem", fontWeight: 800, margin: "12px 0" }}>
          Talk to us
        </h1>
        <p className="muted" style={{ margin: 0 }}>
          If funds are moving right now, speed matters more than a perfect email.
        </p>
      </div>

      <div className="stack" style={{ gap: 16 }}>
        <section className="panel stack">
          <h2 style={{ margin: 0, fontSize: "1.1rem" }}>An active theft</h2>
          <p className="muted" style={{ margin: 0 }}>
            Start the trace yourself — it runs immediately and you don&rsquo;t need to wait
            for us. Paste the drained address and we&rsquo;ll follow the funds.
          </p>
          <div className="row">
            <Link href="/signup" className="cta primary" style={{ padding: "10px 20px", fontSize: 14 }}>
              Start a recovery
            </Link>
            <Link href="/academy/first-hour-after-a-theft" className="muted">
              What to do in the first hour →
            </Link>
          </div>
        </section>

        <section className="panel stack">
          <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Support &amp; billing</h2>
          <p className="muted" style={{ margin: 0 }}>
            Questions about a case, your plan, or the API:{" "}
            <a href={`mailto:${SUPPORT_EMAIL}`}>{SUPPORT_EMAIL}</a>
          </p>
        </section>

        <section className="panel stack">
          <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Legal &amp; privacy</h2>
          <p className="muted" style={{ margin: 0 }}>
            Data requests, law-enforcement enquiries and anything about our{" "}
            <Link href="/terms">Terms</Link> or <Link href="/privacy">Privacy Policy</Link>:{" "}
            <a href={`mailto:${LEGAL_EMAIL}`}>{LEGAL_EMAIL}</a>
          </p>
        </section>

        <p className="muted" style={{ fontSize: 13, margin: 0 }}>
          Recupero is investigative software, not a law firm. We don&rsquo;t provide legal or
          financial advice, and we can&rsquo;t promise recovery — see our{" "}
          <Link href="/terms">Terms</Link>.
        </p>
      </div>
    </>
  );
}
