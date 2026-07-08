/**
 * Recupero Academy — educational content on how illicit crypto moves and how to
 * protect yourself. Single source of truth for both the /academy pages and the
 * landing page's "Insights" section. Plain data, no runtime deps.
 */

export interface ArticleSection {
  heading: string;
  body: string[]; // paragraphs
}

export interface Article {
  slug: string;
  title: string;
  meta: string; // e.g. "TRACING · 6 MIN"
  category: string;
  dek: string; // one-line summary
  sections: ArticleSection[];
}

export const ARTICLES: Article[] = [
  {
    slug: "peel-chains",
    title: "How peel chains launder large thefts — and how to follow them",
    meta: "TRACING · 6 MIN",
    category: "Tracing",
    dek: "A thief who steals millions rarely moves it in one hop. The peel chain is the workhorse of laundering — and it leaves a followable trail.",
    sections: [
      {
        heading: "What a peel chain is",
        body: [
          "A peel chain is a long sequence of transactions where, at each step, a small amount is “peeled” off to a cash-out address (an exchange deposit, a swap, a payment) while the bulk of the funds moves on to a fresh wallet. Repeat this dozens or hundreds of times and a single large theft is dispersed into a fan of small, individually-unremarkable movements.",
          "The goal is to break the obvious one-to-one link between the theft and any single cash-out, and to exhaust an investigator who tries to follow every branch by hand.",
        ],
      },
      {
        heading: "Why the bulk flow is the signal",
        body: [
          "The defining feature of a peel chain is that the large remainder keeps moving. At every hop, one output is dramatically bigger than the others — that is the continuation of the chain. The small peels are the leaves.",
          "Recupero follows the largest-value leg at each hop rather than trying to enumerate every branch. That single rule cuts through most of the noise: the peels self-identify as terminal, and the trail of the principal amount stays intact across the whole chain.",
        ],
      },
      {
        heading: "Where peel chains end",
        body: [
          "Peel chains usually terminate at one of a few places: a centralized-exchange deposit address (a subpoena target), a bridge to another chain (the trail continues on the other side), or a mixer (where following becomes probabilistic).",
          "Reaching the endpoint is what turns a trace into an action — a freeze request to the exchange, a cross-chain continuation, or a demixing lead for investigator review.",
        ],
      },
    ],
  },
  {
    slug: "reading-a-mixer",
    title: "Reading a mixer: what withdrawal timing tells you",
    meta: "DEMIXING · 5 MIN",
    category: "Demixing",
    dek: "A mixer breaks the on-chain link between deposit and withdrawal. It does not, however, erase every clue.",
    sections: [
      {
        heading: "What a mixer actually does",
        body: [
          "A mixer (or “tumbler”) accepts deposits into a shared pool and lets users withdraw the same denomination later to a different address. Because many people deposit and withdraw the same fixed amount, there is no on-chain arrow saying “this withdrawal came from that deposit.”",
          "That is a genuine break in the trail. Anyone who claims to deterministically “de-mix” a well-used pool is overselling. What responsible analysis produces are leads — ranked candidates, not proof.",
        ],
      },
      {
        heading: "Signals that survive the mix",
        body: [
          "Timing and behavior leak information. A withdrawal minutes after a matching-denomination deposit, address reuse across deposit and withdrawal, a shared relayer, or a distinctive gas-payment pattern can all narrow the candidate set.",
          "Recupero surfaces these as low-confidence demixing leads — explicitly labeled as probabilistic and never followed automatically as if they were a confirmed hop. They are a starting point for a human investigator, not a verdict.",
        ],
      },
      {
        heading: "The honest posture",
        body: [
          "When funds enter a sanctioned or high-risk mixer, the correct forensic statement is often “funds entered the mixer and became unrecoverable through on-chain tracing alone,” not a fabricated downstream address. Overstating certainty here is how investigations get discredited in court.",
        ],
      },
    ],
  },
  {
    slug: "address-poisoning",
    title: "Sibling and shadow addresses in address-poisoning scams",
    meta: "SCREENING · 4 MIN",
    category: "Screening",
    dek: "One of the most effective scams doesn’t hack anything — it just tricks you into copying the wrong address.",
    sections: [
      {
        heading: "How the scam works",
        body: [
          "Address poisoning exploits a simple habit: people copy a recipient address from their transaction history instead of re-checking it in full. The attacker sends you a tiny (often zero-value) transfer from an address engineered to look like one you use — matching first and last characters — so it appears in your history.",
          "Later, when you copy “your” address from history, you copy the attacker’s look-alike, and your next payment goes to them.",
        ],
      },
      {
        heading: "Why it defeats a quick glance",
        body: [
          "Wallets abbreviate addresses as 0xAB12…9F4C. The look-alike is built to match exactly those visible characters. The middle — which nobody reads — is completely different. A five-second visual check passes.",
        ],
      },
      {
        heading: "How to defend against it",
        body: [
          "Never copy an address from transaction history. Copy it from the source (the invoice, the exchange, the counterparty’s verified channel) every time, and verify the full string or a large middle segment.",
          "Recupero flags spoofed look-alike addresses and airdrop-spam so a trace never follows a decoy, and Wallet Guard screens a recipient before you send — the same protection, applied at the moment it matters.",
        ],
      },
    ],
  },
  {
    slug: "first-hour-after-a-theft",
    title: "What to do in the first hour after a crypto theft",
    meta: "RECOVERY · 5 MIN",
    category: "Recovery",
    dek: "Speed matters. The steps you take in the first hour materially affect whether funds can be frozen before they cash out.",
    sections: [
      {
        heading: "Stop the bleeding",
        body: [
          "If a wallet is compromised, assume every asset in it and every wallet that shares its seed phrase is at risk. Move any remaining funds to a brand-new wallet created on a clean device. Revoke outstanding token approvals if you can still transact safely.",
        ],
      },
      {
        heading: "Preserve evidence",
        body: [
          "Record the transaction hashes of the theft, the addresses involved, and the approximate time. Screenshot everything. This is the raw material a trace and any later legal action are built from — do not rely on being able to reconstruct it later.",
        ],
      },
      {
        heading: "Trace and target the cash-out",
        body: [
          "Stolen funds are most freezable while they are still sitting at, or moving toward, a centralized exchange. A fast trace that reaches an exchange deposit address gives you a concrete freeze target and the evidence to support the request.",
          "This is the window where tooling matters most: the sooner the funds are followed to an endpoint, the sooner a freeze request or law-enforcement referral can go out — ideally before the attacker withdraws.",
        ],
      },
      {
        heading: "Get the right help",
        body: [
          "Report to law enforcement and, for a theft of any size, consult qualified counsel. On-chain tracing produces investigative leads and evidence; actual freezes and recovery run through exchanges, courts, and law enforcement.",
        ],
      },
    ],
  },
];

export function getArticle(slug: string): Article | undefined {
  return ARTICLES.find((a) => a.slug === slug);
}
