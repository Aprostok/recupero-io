"use client";

import { FormEvent, ReactNode, useRef, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError, api } from "@/lib/api";

interface Msg {
  role: "user" | "assistant";
  content: string;
}

const SUGGESTIONS = [
  "Is 0x… safe to send funds to?",
  "What does a “mixer” verdict mean?",
  "I think I was scammed — what should I do first?",
  "How do wallet-drainer scams work?",
];

// Minimal, dependency-free Markdown renderer for the subset the assistant emits
// (headings, **bold**, bullet/numbered lists, --- rules, paragraphs). Renders to
// real React nodes — never injects HTML — so it is XSS-safe by construction.
function renderInline(text: string, k: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*)/g).map((seg, i) =>
    /^\*\*[^*]+\*\*$/.test(seg) ? (
      <strong key={`${k}-${i}`}>{seg.slice(2, -2)}</strong>
    ) : (
      <span key={`${k}-${i}`}>{seg}</span>
    ),
  );
}

function renderMarkdown(md: string): ReactNode[] {
  const lines = md.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  let para: string[] = [];
  let k = 0;

  const flushPara = () => {
    if (para.length) {
      const key = `p${k++}`;
      blocks.push(
        <p key={key} style={{ margin: "0 0 8px" }}>
          {renderInline(para.join(" "), key)}
        </p>,
      );
      para = [];
    }
  };
  const flushList = () => {
    if (list) {
      const key = `l${k++}`;
      const items = list.items.map((it, i) => (
        <li key={`${key}-${i}`}>{renderInline(it, `${key}-${i}`)}</li>
      ));
      blocks.push(
        list.ordered ? (
          <ol key={key} style={{ margin: "4px 0 8px", paddingLeft: 20 }}>{items}</ol>
        ) : (
          <ul key={key} style={{ margin: "4px 0 8px", paddingLeft: 20 }}>{items}</ul>
        ),
      );
      list = null;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.trim() === "") {
      flushPara();
      flushList();
      continue;
    }
    if (/^---+$/.test(line.trim())) {
      flushPara();
      flushList();
      blocks.push(
        <hr key={`hr${k++}`} style={{ border: 0, borderTop: "1px solid var(--border)", margin: "8px 0" }} />,
      );
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushPara();
      flushList();
      const key = `h${k++}`;
      blocks.push(
        <div key={key} style={{ fontWeight: 700, fontSize: heading[1].length <= 2 ? "1.05em" : "1em", margin: "8px 0 2px" }}>
          {renderInline(heading[2], key)}
        </div>,
      );
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    if (bullet) {
      flushPara();
      if (!list || list.ordered) {
        flushList();
        list = { ordered: false, items: [] };
      }
      list.items.push(bullet[1]);
      continue;
    }
    const numbered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (numbered) {
      flushPara();
      if (!list || !list.ordered) {
        flushList();
        list = { ordered: true, items: [] };
      }
      list.items.push(numbered[1]);
      continue;
    }
    flushList();
    para.push(line);
  }
  flushPara();
  flushList();
  return blocks;
}

export default function AssistantPage() {
  const { token } = useAuth();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  async function send(text: string) {
    if (!token || !text.trim() || sending) return;
    setError(null);
    const next: Msg[] = [...messages, { role: "user", content: text.trim() }];
    setMessages(next);
    setInput("");
    setSending(true);
    try {
      const res = await api.assistantChat(token, next);
      setMessages([...next, { role: "assistant", content: res.reply }]);
    } catch (err) {
      // roll back the optimistic user turn on failure
      setMessages(messages);
      setInput(text);
      const detail = err instanceof ApiError ? err.detail : "request failed";
      setError(
        err instanceof ApiError && err.status === 503
          ? "The assistant isn’t enabled on this deployment yet."
          : detail,
      );
    } finally {
      setSending(false);
      requestAnimationFrame(() => {
        scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
      });
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    send(input);
  }

  return (
    <div className="stack" style={{ gap: 16 }}>
      <section className="panel" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
          <span
            aria-hidden
            style={{
              flex: "none",
              width: 38,
              height: 38,
              borderRadius: 11,
              display: "grid",
              placeItems: "center",
              color: "var(--emerald)",
              background: "rgba(47,214,160,.1)",
              border: "1px solid var(--emerald-line)",
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 5h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H9l-4 4v-4H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z" />
              <path d="M9 10h6M9 13h4" />
            </svg>
          </span>
          <div style={{ minWidth: 0 }}>
            <h3 style={{ margin: 0 }}>Recupero Assistant</h3>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Ask about wallet safety, screening verdicts, scams, or what to do after
              a theft. Mention an address and it’s screened live. Not financial or
              legal advice.
            </p>
          </div>
        </div>

        <div
          ref={scrollRef}
          style={{
            minHeight: 260,
            maxHeight: 460,
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: 10,
            padding: "4px 2px",
          }}
        >
          {messages.length === 0 ? (
            <div className="stack" style={{ gap: 8 }}>
              <span className="muted">Try asking:</span>
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  className="ghost"
                  style={{ textAlign: "left", justifyContent: "flex-start" }}
                  onClick={() => send(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          ) : (
            messages.map((m, i) => (
              <div
                key={i}
                style={{
                  alignSelf: m.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "80%",
                  padding: "10px 14px",
                  borderRadius: 14,
                  whiteSpace: m.role === "user" ? "pre-wrap" : "normal",
                  lineHeight: 1.5,
                  background:
                    m.role === "user"
                      ? "var(--accent)"
                      : "rgba(255,255,255,.06)",
                  color: m.role === "user" ? "#fff" : "var(--text)",
                  border:
                    m.role === "user" ? "none" : "1px solid var(--border)",
                }}
              >
                {m.role === "user" ? m.content : renderMarkdown(m.content)}
              </div>
            ))
          )}
          {sending && (
            <div
              className="typing"
              aria-label="Assistant is thinking"
              style={{ alignSelf: "flex-start", border: "1px solid var(--border)", borderRadius: 14, background: "rgba(255,255,255,.06)" }}
            >
              <i /><i /><i />
            </div>
          )}
        </div>

        {error && <div className="error">{error}</div>}

        <form className="row" onSubmit={onSubmit}>
          <input
            style={{ flex: 1, minWidth: 240 }}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about an address, a scam, or a screening verdict…"
            disabled={sending}
          />
          <button type="submit" disabled={sending || !input.trim()}>
            Send
          </button>
        </form>
      </section>
    </div>
  );
}
