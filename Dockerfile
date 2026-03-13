# ── Stage 1: Install dependencies ──────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# ── Stage 2: Final image ────────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Create non-root user for security (principle of least privilege)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=deps /app/node_modules ./node_modules
COPY src ./src

# Don't run as root
USER appuser

EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

ENV NODE_ENV=production
CMD ["node", "src/index.js"]
