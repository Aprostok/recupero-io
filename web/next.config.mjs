/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The API base URL is read client-side from NEXT_PUBLIC_API_BASE_URL (see
  // src/lib/api.ts). Keeping the API on a separate origin means the frontend
  // can be served from a CDN/edge while the FastAPI service scales independently.
  poweredByHeader: false,
  // Emit a self-contained server bundle (.next/standalone) so the container image
  // ships only the traced runtime deps — see web/Dockerfile. Required for the
  // containerised deploy; harmless for `next start` in dev.
  output: "standalone",
  // The site this app REPLACES was a single-page brochure whose nav/footer
  // linked /services, /how-it-works, /faq, /contact, /portal, /submit-a-case,
  // /privacy and /terms (every URL served the same shell). Those links exist in
  // the wild — map them to their nearest equivalent here so nothing 404s after
  // the cutover. Permanent (308) so search engines transfer the old URLs.
  async redirects() {
    return [
      { source: "/services", destination: "/#platform", permanent: true },
      { source: "/how-it-works", destination: "/#how", permanent: true },
      { source: "/faq", destination: "/contact", permanent: true },
      { source: "/portal", destination: "/login", permanent: true },
      { source: "/client-portal", destination: "/login", permanent: true },
      { source: "/submit", destination: "/signup", permanent: true },
      { source: "/submit-a-case", destination: "/signup", permanent: true },
      { source: "/privacy-policy", destination: "/privacy", permanent: true },
      { source: "/terms-of-service", destination: "/terms", permanent: true },
    ];
  },
};

export default nextConfig;
