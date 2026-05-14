# ── Build stage ──────────────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

# Build args injected at build time by docker-compose
ARG VITE_API_URL=https://api.yourdomain.com/api
ARG VITE_WS_URL=wss://api.yourdomain.com/ws
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_WS_URL=$VITE_WS_URL

RUN npm run build

# ── Nginx stage ───────────────────────────────────────────────────────────
FROM nginx:1.27-alpine AS runner

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our hardened nginx config
COPY nginx.conf /etc/nginx/conf.d/vault-msg.conf

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Non-root nginx
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

USER nginx

ENV PORT=80

CMD ["/bin/sh", "-c", "envsubst '${PORT}' < /etc/nginx/conf.d/vault-msg.conf > /tmp/vault-msg.conf && mv /tmp/vault-msg.conf /etc/nginx/conf.d/vault-msg.conf && nginx -g 'daemon off;'"]
