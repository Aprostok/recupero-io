import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ARTICLES, getArticle } from "@/content/academy";

export function generateStaticParams() {
  return ARTICLES.map((a) => ({ slug: a.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }): Metadata {
  const article = getArticle(params.slug);
  if (!article) return { title: "Academy — Recupero" };
  return { title: `${article.title} — Recupero Academy`, description: article.dek };
}

export default function ArticlePage({ params }: { params: { slug: string } }) {
  const article = getArticle(params.slug);
  if (!article) notFound();

  const more = ARTICLES.filter((a) => a.slug !== article.slug).slice(0, 2);

  return (
    <section className="section" style={{ paddingTop: 40, maxWidth: 760, margin: "0 auto" }}>
      <Link href="/academy" style={{ color: "var(--muted, #9aa6be)", fontSize: 14 }}>
        ← All articles
      </Link>

      <div style={{ marginTop: 20 }}>
        <div className="meta" style={{ letterSpacing: ".08em", fontSize: 12, opacity: 0.8 }}>
          {article.meta}
        </div>
        <h1 style={{ fontSize: "2.1rem", lineHeight: 1.15, margin: "10px 0 12px" }}>
          {article.title}
        </h1>
        <p className="lead" style={{ fontSize: "1.15rem" }}>
          {article.dek}
        </p>
      </div>

      <article style={{ marginTop: 24 }}>
        {article.sections.map((s) => (
          <div key={s.heading} style={{ marginBottom: 28 }}>
            <h2 style={{ fontSize: "1.35rem", margin: "0 0 10px" }}>{s.heading}</h2>
            {s.body.map((p, i) => (
              <p key={i} style={{ lineHeight: 1.7, margin: "0 0 12px" }}>
                {p}
              </p>
            ))}
          </div>
        ))}
      </article>

      <div className="cta-band glass" style={{ marginTop: 24 }}>
        <h2>Protect your wallet with Recupero</h2>
        <p>Screen an address before you send, or trace stolen funds to a freeze target.</p>
        <div className="cta-row">
          <Link href="/signup" className="cta primary">
            Get started
          </Link>
          <Link href="/academy" className="cta secondary">
            More articles
          </Link>
        </div>
      </div>

      {more.length > 0 && (
        <div className="insight-grid" style={{ marginTop: 32 }}>
          {more.map((a, i) => (
            <Link className="insight-card glass" key={a.slug} href={`/academy/${a.slug}`}>
              <div className={`thumb ${["", "b"][i % 2]}`} />
              <div className="body">
                <div className="meta">{a.meta}</div>
                <h4>{a.title}</h4>
              </div>
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}
