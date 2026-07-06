/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The API base URL is read client-side from NEXT_PUBLIC_API_BASE_URL (see
  // src/lib/api.ts). Keeping the API on a separate origin means the frontend
  // can be served from a CDN/edge while the FastAPI service scales independently.
  poweredByHeader: false,
};

export default nextConfig;
