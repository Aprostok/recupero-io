import Link from "next/link";
import type { Metadata } from "next";
import { ARTICLES } from "@/content/academy";

export const metadata: Metadata = {
  title: "Academy — Recupero",
  description:
    "Field notes on how illicit crypto moves and how to protect yourself: tracing, demixing, screening, and recovery.",
};

export default function AcademyIndex() {
  return (
    <>
      <section className="section" style={{ paddingTop: 40 }}>
        <div className="section-head">
          <span className="kicker">Academy</span>
          <h2>Field notes from the recovery frontline</h2>
          <p>How illicit funds move — and how investigators, and everyday users, catch up.</p>
        </div>
        <div className="insight-grid">
          {ARTICLES.map((a, i) => (
            <Link className="insight-card glass" key={a.slug} href={`/academy/${a.slug}`}>
              <div className={`thumb ${["", "b", "c", ""][i % 4]}`} />
              <div className="body">
                <div className="meta">{a.meta}</div>
                <h4>{a.title}</h4>
                <p style={{ color: "var(--muted, #9aa6be)", fontSize: 14, margin: "6px 0 0" }}>
                  {a.dek}
                </p>
              </div>
            </Link>
          ))}
        </div>
      </section>
    </>
  );
}
