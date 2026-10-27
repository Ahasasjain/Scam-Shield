# ScamShield API — production image (Node 20, pnpm workspace).
#
# Build from the REPO ROOT so the `workspace:*` link to @scamshield/shared
# resolves (building from server/ alone breaks the workspace protocol):
#   docker build -f server/Dockerfile -t scamshield-api .
#
# Run:
#   docker run -d -p 8787:8787 --env-file server/.env scamshield-api

FROM node:20-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY shared/package.json ./shared/package.json
COPY server/package.json ./server/package.json
RUN pnpm install --frozen-lockfile
COPY shared ./shared
COPY server ./server
RUN pnpm --filter @scamshield/server build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
# The bundle inlines @scamshield/shared. Everything else imported by the built
# dist/index.js is external: the four packages below plus dotenv and zod.
# Keep this list in sync with `external` in server/tsup.config.ts and the
# imports in dist/index.js.
#
# Do NOT copy server/package.json into this stage: it declares
# "@scamshield/shared": "workspace:*", which npm cannot resolve outside the
# pnpm workspace (EUNSUPPORTEDPROTOCOL). A minimal manifest is enough, and the
# direct deps are pinned to the versions resolved in pnpm-lock.yaml.
RUN echo '{"name":"scamshield-api","private":true,"type":"module"}' > package.json \
  && npm i --omit=dev --no-audit --no-fund \
    dotenv@16.6.1 \
    express@4.22.2 \
    express-rate-limit@7.5.1 \
    helmet@7.2.0 \
    pino@9.14.0 \
    zod@3.25.76
COPY --from=build /app/server/dist ./dist
# Drop privileges: nothing in this service needs root.
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app
EXPOSE 8787
# Shell form on purpose: ${PORT} expands at runtime, so the probe follows the
# port the platform injects (Render/Railway set PORT; local runs default 8787).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8787}/api/health" | grep -q '"ok":true'
CMD ["node", "dist/index.js"]
