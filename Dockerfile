# syntax=docker/dockerfile:1
# Hardened, minimal image for the CuraSecure portal.

# ---------- Stage 1: install production dependencies from the lockfile ----------
FROM node:20-alpine AS deps
WORKDIR /app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

# ---------- Stage 2: runtime ----------
FROM node:20-alpine
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="curasecure" \
      org.opencontainers.image.description="DevSecOps healthcare portal (fictional data)" \
      org.opencontainers.image.version="${APP_VERSION}"

# Patch OS packages and remove package managers that are not needed at runtime
# (smaller attack surface, fewer CVEs reported by the image scan)
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/lib/node_modules/corepack /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg

ENV NODE_ENV=production PORT=3000
WORKDIR /app
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
COPY --chown=root:root app/package.json app/server.js ./
COPY --chown=root:root app/src ./src
COPY --chown=root:root app/public ./public

# Files are owned by root and read-only for the app user; the app runs unprivileged
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "server.js"]
