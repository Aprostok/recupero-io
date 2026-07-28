# Recupero customer web app (Next.js 14 App Router) — production image.
#
# The root Dockerfile builds the PYTHON services (recupero-api / -worker / -cron)
# and copies only `src/`, so the frontend was never built or shipped by any deploy
# config. This file is the web service's own image.
#
# Deploy (Railway): create a service pointing at this repo with
#   Root Directory = web        Dockerfile Path = Dockerfile
# and set NEXT_PUBLIC_API_BASE_URL to the API origin (baked in at BUILD time —
# it is a NEXT_PUBLIC_* var, so it must be a build arg, not just a runtime env).
# Vercel alternative: point a project at `web/` and set the same env var; no
# Dockerfile needed there.

# ---- deps ----
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---- build ----
FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* values are inlined into the client bundle at build time.
ARG NEXT_PUBLIC_API_BASE_URL="http://localhost:8000"
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---- runtime ----
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Run unprivileged.
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001
# `output: "standalone"` (web/next.config.mjs) emits a minimal server + only the
# traced node_modules it actually needs.
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=build --chown=nextjs:nodejs /app/public ./public
USER nextjs
# Railway/Heroku inject $PORT; Next's standalone server honours PORT + HOSTNAME.
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000
CMD ["node", "server.js"]
