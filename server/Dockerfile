# ── Build stage ──────────────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app

# Copy manifests first (better layer caching)
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

# ── Production stage ─────────────────────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

# Non-root user for least-privilege
RUN addgroup -S vault && adduser -S vault -G vault

# Copy installed deps + source
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=vault:vault . .

# Remove dev/test artifacts if any
RUN rm -rf *.bak tests/ __tests__/

# Create data directory for SQLite
RUN mkdir -p /data && chown vault:vault /data

USER vault

EXPOSE 4000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "index.js"]
