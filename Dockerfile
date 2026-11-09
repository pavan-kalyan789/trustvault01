# Multi-stage production build for TrustVault on Google Cloud Run
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production Runner
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/dist-server ./dist-server 2>/dev/null || true
COPY --from=builder /app/src ./src
COPY --from=builder /app/server.ts ./server.ts
COPY --from=builder /app/tsconfig.json ./tsconfig.json

# Create private storage directory with restricted permissions
RUN mkdir -p /app/vault_storage_private && chmod 700 /app/vault_storage_private

EXPOSE 3000

CMD ["npx", "tsx", "server.ts"]
