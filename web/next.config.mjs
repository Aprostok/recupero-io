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
};

export default nextConfig;
